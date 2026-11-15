package mtproto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

var testAdTag = bytes.Repeat([]byte{0xcd}, adTagSize)

// fakeMiddleProxy plays Telegram's side, deriving keys from the address it really sees.
// The wire format itself is checked against Telegram with TestLiveTelegram; this covers
// what a short real exchange can't, like large messages and quick acks.
type fakeMiddleProxy struct {
	t        *testing.T
	secret   []byte
	address  net.Destination
	accepted atomic.Int32
	requests chan fakeRequest
}

type fakeRequest struct {
	flags        uint32
	connectionID []byte
	client       []byte
	source       []byte
	extra        []byte
	message      []byte
}

func startFakeMiddleProxy(t *testing.T, dc int) *fakeMiddleProxy {
	t.Helper()

	secret := make([]byte, 128)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	address, err := net.ParseDestination("tcp:" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeMiddleProxy{t: t, secret: secret, address: address, requests: make(chan fakeRequest, 8)}

	middleProxies.lock.Lock()
	middleProxies.secret = secret
	middleProxies.proxies = map[int][]net.Destination{dc: {address}}
	middleProxies.nextUpdate = time.Now().Add(time.Hour)
	middleProxies.lock.Unlock()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			fake.accepted.Add(1)
			go fake.serve(conn)
		}
	}()
	return fake
}

func (f *fakeMiddleProxy) serve(conn net.Conn) {
	defer conn.Close()

	nonceFrame := make([]byte, 48)
	if _, err := io.ReadFull(conn, nonceFrame); err != nil {
		return
	}
	clientNonce := nonceFrame[24:40]
	timestamp := nonceFrame[20:24]
	serverNonce := bytes.Repeat([]byte{0x5a}, 16)

	answer := binary.LittleEndian.AppendUint32(nil, rpcNonce)
	answer = append(answer, f.secret[:4]...)
	answer = binary.LittleEndian.AppendUint32(answer, rpcCryptoAES)
	answer = append(answer, timestamp...)
	answer = append(answer, serverNonce...)
	if _, err := conn.Write(appendRPCFrame(nil, rpcFirstSequence, answer)[:rpcNonceAnswer]); err != nil {
		return
	}

	remote := conn.RemoteAddr().(*net.TCPAddr)
	local := conn.LocalAddr().(*net.TCPAddr)
	block := func(purpose string) (cipher.Block, []byte) {
		key, iv := middleKeys(middlePrekey(serverNonce, clientNonce, timestamp, reversedIP(local.IP), uint16(remote.Port), purpose, reversedIP(remote.IP), uint16(local.Port), f.secret))
		b, err := aes.NewCipher(key)
		common.Must(err)
		return b, iv
	}
	clientBlock, clientIV := block("CLIENT")
	serverBlock, serverIV := block("SERVER")

	m := &middleConn{
		conn:          conn,
		decrypt:       cipher.NewCBCDecrypter(clientBlock, clientIV),
		encrypt:       cipher.NewCBCEncrypter(serverBlock, serverIV),
		writeSequence: rpcFirstSequence + 1,
		readSequence:  rpcFirstSequence + 1,
	}

	// With wrong keys this decrypts to garbage, and like the real thing we just hang up.
	handshake, err := m.readFrame()
	if err != nil || binary.LittleEndian.Uint32(handshake) != rpcHandshake {
		return
	}
	if err := m.writeFrame(handshake); err != nil {
		return
	}

	for {
		frame, err := m.readFrame()
		if err != nil {
			return
		}
		request := fakeRequest{
			flags:        binary.LittleEndian.Uint32(frame[4:]),
			connectionID: slices.Clone(frame[8:16]),
			client:       slices.Clone(frame[16:36]),
			source:       slices.Clone(frame[36:56]),
			extra:        slices.Clone(frame[56:84]),
			message:      slices.Clone(frame[84:]),
		}
		if binary.LittleEndian.Uint32(frame) != rpcProxyRequest {
			f.t.Errorf("unexpected request type %#x", binary.LittleEndian.Uint32(frame))
			return
		}
		f.requests <- request

		if request.flags&rpcFlagQuickAck != 0 {
			ack := binary.LittleEndian.AppendUint32(nil, rpcSimpleAck)
			ack = append(ack, request.connectionID...)
			ack = append(ack, 0xa1, 0xa2, 0xa3, 0xa4)
			if err := m.writeFrame(ack); err != nil {
				return
			}
		}
		answer := binary.LittleEndian.AppendUint32(nil, rpcProxyAnswer)
		answer = binary.LittleEndian.AppendUint32(answer, 0)
		answer = append(answer, request.connectionID...)
		if err := m.writeFrame(answer, request.message); err != nil {
			return
		}
	}
}

type fakeHandler struct {
	outbound.Handler
	tag        string
	configType string
}

func (h *fakeHandler) Tag() string { return h.tag }
func (h *fakeHandler) ProxySettings() *serial.TypedMessage {
	return &serial.TypedMessage{Type: h.configType}
}

func (h *fakeHandler) Dial(_ context.Context, dest net.Destination) (stat.Connection, error) {
	return net.Dial("tcp", dest.NetAddr())
}

type fakeOutbounds struct {
	outbound.Manager
	handler *fakeHandler
}

func (o *fakeOutbounds) GetDefaultHandler() outbound.Handler { return o.handler }
func (o *fakeOutbounds) GetHandler(string) outbound.Handler  { return o.handler }

type fakeRouter struct{ routing.Router }

func (fakeRouter) PickRoute(routing.Context) (routing.Route, error) { return nil, common.ErrNoClue }

// countingPolicy turns on the same per-user stats the node's config does.
type countingPolicy struct{ policy.DefaultManager }

func (countingPolicy) ForLevel(uint32) policy.Session {
	session := policy.SessionDefault()
	session.Stats.UserUplink = true
	session.Stats.UserDownlink = true
	session.Stats.UserOnline = true
	return session
}

func startTaggedProxy(t *testing.T, configType string, publicIP net.IP, more ...func(*Server)) (*Server, *testDispatcher, string, chan []byte) {
	t.Helper()

	manager, err := stats.NewManager(context.Background(), &stats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return startProxy(t, map[string][]byte{"7": testSecret}, func(server *Server) {
		server.policyManager = countingPolicy{}
		server.adTag = testAdTag
		server.publicIP = publicIP
		server.router = fakeRouter{}
		server.outbounds = &fakeOutbounds{handler: &fakeHandler{tag: "direct", configType: configType}}
		server.stats = manager
		for _, apply := range more {
			apply(server)
		}
	})
}

var (
	loopbackIP = net.ParseAddress("127.0.0.1").IP()
	ownSecret  = bytes.Repeat([]byte{0x44}, secretSize)
	ownAdTag   = bytes.Repeat([]byte{0xee}, adTagSize)
)

func addUserWithOwnTag(server *Server) {
	user := &protocol.MemoryUser{Email: "8", Account: &MemoryAccount{Secret: ownSecret, AdTag: ownAdTag}}
	common.Must(server.AddUser(context.Background(), user))
}

func TestMiddleProxyUserTagOverridesInboundTag(t *testing.T) {
	fake := startFakeMiddleProxy(t, 2)
	_, _, address, _ := startTaggedProxy(t, freedomConfigType, loopbackIP, addUserWithOwnTag)

	for _, c := range []struct {
		name        string
		secret, tag []byte
	}{
		{"user without a tag gets the inbound's", testSecret, testAdTag},
		{"user with a tag gets their own", ownSecret, ownAdTag},
	} {
		t.Run(c.name, func(t *testing.T) {
			client, err := dialClient(t, dial(t, address), c.secret, testDomain, 2)
			if err != nil {
				t.Fatal(err)
			}
			client.sendMessage(t, bytes.Repeat([]byte{1}, 40), 0, false)
			request := <-fake.requests
			if !bytes.Equal(request.extra[9:25], c.tag) {
				t.Errorf("Telegram got the tag %x, want %x", request.extra[9:25], c.tag)
			}
		})
	}
}

func TestOnlyUsersWithATagUseMiddleProxies(t *testing.T) {
	fake := startFakeMiddleProxy(t, 2)
	_, dispatcher, address, _ := startTaggedProxy(t, freedomConfigType, loopbackIP, addUserWithOwnTag, func(server *Server) {
		server.adTag = nil
	})

	if _, err := dialClient(t, dial(t, address), testSecret, testDomain, 2); err != nil {
		t.Fatal(err)
	}
	<-dispatcher.dests
	if fake.accepted.Load() != 0 {
		t.Error("a user with no tag went through a middle proxy")
	}

	client, err := dialClient(t, dial(t, address), ownSecret, testDomain, 2)
	if err != nil {
		t.Fatal(err)
	}
	client.sendMessage(t, bytes.Repeat([]byte{1}, 40), 0, false)
	<-fake.requests
	if len(dispatcher.dests) != 0 {
		t.Error("a user with a tag also went down the direct path")
	}
}

func TestAccountAdTag(t *testing.T) {
	secret := hex.EncodeToString(testSecret)
	if _, err := (&Account{Secret: secret, AdTag: "not-hex"}).AsAccount(); err == nil {
		t.Error("a malformed tag was accepted")
	}
	account, err := (&Account{Secret: secret, AdTag: hex.EncodeToString(ownAdTag)}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(account.(*MemoryAccount).AdTag, ownAdTag) {
		t.Error("tag decoded wrongly")
	}
	empty, err := (&Account{Secret: secret}).AsAccount()
	if err != nil || empty.(*MemoryAccount).AdTag != nil {
		t.Errorf("no tag should stay nil: %v", err)
	}
}

func (c *testClient) sendMessage(t *testing.T, message []byte, padding int, quickAck bool) {
	t.Helper()
	size := uint32(len(message) + padding)
	if quickAck {
		size |= rpcFlagQuickAck
	}
	framed := binary.LittleEndian.AppendUint32(nil, size)
	framed = append(framed, message...)
	framed = append(framed, make([]byte, padding)...)
	if err := c.send(framed); err != nil {
		t.Fatal(err)
	}
}

func (c *testClient) receiveMessage(t *testing.T) []byte {
	t.Helper()
	head, err := c.receive(4)
	if err != nil {
		t.Fatal(err)
	}
	size := binary.LittleEndian.Uint32(head)
	body, err := c.receive(int(size))
	if err != nil {
		t.Fatal(err)
	}
	return body[:size-size%4] // what's past a multiple of 4 is padding
}

func TestMiddleProxyRelay(t *testing.T) {
	fake := startFakeMiddleProxy(t, -4)
	server, dispatcher, address, _ := startTaggedProxy(t, freedomConfigType, loopbackIP)

	conn := dial(t, address)
	client, err := dialClient(t, conn, testSecret, testDomain, -4)
	if err != nil {
		t.Fatal(err)
	}

	// Crosses TLS records and CBC blocks in both directions, and carries client padding.
	large := make([]byte, 100_000)
	if _, err := rand.Read(large); err != nil {
		t.Fatal(err)
	}
	client.sendMessage(t, large, 3, false)
	request := <-fake.requests
	if !bytes.Equal(request.message, large) {
		t.Fatalf("Telegram got %d bytes that don't match, padding was not removed", len(request.message))
	}
	if got := client.receiveMessage(t); !bytes.Equal(got, large) {
		t.Fatal("the client got a different message back")
	}

	want := uint32(rpcFlagMagic | rpcFlagExtMode2 | rpcFlagIntermediate | rpcFlagHasAdTag | rpcFlagPad)
	if request.flags != want {
		t.Errorf("flags are %#x, want %#x", request.flags, want)
	}
	if !bytes.Equal(request.extra[8:9], []byte{adTagSize}) || !bytes.Equal(request.extra[9:25], testAdTag) {
		t.Errorf("the ad tag didn't reach Telegram: %x", request.extra)
	}
	if binary.LittleEndian.Uint32(request.extra) != 24 || binary.LittleEndian.Uint32(request.extra[4:]) != rpcProxyTag {
		t.Errorf("malformed extra section: %x", request.extra)
	}
	clientAddress := conn.LocalAddr().(*net.TCPAddr)
	wantClient := appendIPPort(nil, net.TCPDestination(net.IPAddress(clientAddress.IP), net.Port(clientAddress.Port)))
	if !bytes.Equal(request.client, wantClient) {
		t.Errorf("Telegram sees the client as %x, want %x", request.client, wantClient)
	}

	// An unencrypted MTProto message is flagged as such, and quick acks come back raw.
	unencrypted := append(make([]byte, 8), bytes.Repeat([]byte{7}, 32)...)
	client.sendMessage(t, unencrypted, 0, true)
	request = <-fake.requests
	if request.flags&rpcFlagNotEncrypted == 0 || request.flags&rpcFlagQuickAck == 0 {
		t.Errorf("flags %#x should mark this unencrypted with a quick ack", request.flags)
	}
	ack, err := client.receive(4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ack, []byte{0xa1, 0xa2, 0xa3, 0xa4}) {
		t.Errorf("quick ack came back as %x", ack)
	}
	if got := client.receiveMessage(t); !bytes.Equal(got, unencrypted) {
		t.Fatal("the second message came back wrong")
	}

	if len(dispatcher.dests) != 0 {
		t.Error("a tagged connection also went down the direct path")
	}
	if fake.accepted.Load() != 1 {
		t.Errorf("%d middle proxy connections, want 1", fake.accepted.Load())
	}

	// This path skips the dispatcher, so limits depend on these being counted here.
	sum := int64(len(large) + len(unencrypted))
	for _, name := range []string{"uplink", "downlink"} {
		counter := server.stats.GetCounter("user>>>7>>>traffic>>>" + name)
		if counter == nil || counter.Value() != sum {
			t.Errorf("%s counted %v, want %d", name, counter, sum)
		}
	}
	// Xray's online map ignores loopback addresses, so this only shows the path registered it.
	if server.stats.GetOnlineMap("user>>>7>>>online") == nil {
		t.Error("the user isn't tracked as online")
	}
}

func TestMiddleProxyRefusalFallsBackToDirect(t *testing.T) {
	fake := startFakeMiddleProxy(t, 2)
	// Not what the proxy sees, so the keys won't match.
	_, dispatcher, address, _ := startTaggedProxy(t, freedomConfigType, net.ParseAddress("192.0.2.1").IP())

	client, err := dialClient(t, dial(t, address), testSecret, testDomain, 2)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{9}, 1000)
	if err := client.send(payload); err != nil {
		t.Fatal(err)
	}
	if got, err := client.receive(len(payload)); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("the user lost their connection instead of falling back: %v", err)
	}
	if dest := <-dispatcher.dests; dest.Address.String() != "149.154.167.51" {
		t.Errorf("fell back to %s", dest)
	}
	if user := <-dispatcher.users; user == nil || user.Email != "7" {
		t.Error("the fallback lost track of the user, so usage wouldn't be counted")
	}

	// Clients shouldn't each wait for the middle proxy to fail while it's down.
	if _, err := dialClient(t, dial(t, address), testSecret, testDomain, 2); err != nil {
		t.Fatal(err)
	}
	<-dispatcher.dests
	if fake.accepted.Load() != 1 {
		t.Errorf("tried the failing middle proxy %d times, want 1", fake.accepted.Load())
	}
}

func TestMiddleProxyPrivateAddressNeedsPublicIP(t *testing.T) {
	fake := startFakeMiddleProxy(t, 2)
	// With no publicIp the local address is used, and 127.0.0.1 can't be what Telegram sees.
	_, dispatcher, address, _ := startTaggedProxy(t, freedomConfigType, nil)

	if _, err := dialClient(t, dial(t, address), testSecret, testDomain, 2); err != nil {
		t.Fatal(err)
	}
	<-dispatcher.dests
	if fake.accepted.Load() != 0 && len(fake.requests) != 0 {
		t.Error("sent requests with a source address Telegram can't see")
	}
}

func TestMiddleProxyRespectsRouting(t *testing.T) {
	t.Run("proxied outbound stays on routing", func(t *testing.T) {
		fake := startFakeMiddleProxy(t, 2)
		server, dispatcher, address, _ := startTaggedProxy(t, "xray.proxy.vless.outbound.Config", loopbackIP)

		if _, err := dialClient(t, dial(t, address), testSecret, testDomain, 2); err != nil {
			t.Fatal(err)
		}
		<-dispatcher.dests
		if fake.accepted.Load() != 0 {
			t.Error("tried a middle proxy on an outbound that can't reach one")
		}
		// One user's rule mustn't turn off the sponsored channel for everyone else.
		if server.middleSkipUntil.Load() != 0 {
			t.Error("a route choice started the failure cooldown")
		}
	})

	t.Run("blocked route refuses", func(t *testing.T) {
		fake := startFakeMiddleProxy(t, 2)
		_, dispatcher, address, _ := startTaggedProxy(t, blackholeConfigType, loopbackIP)

		client, err := dialClient(t, dial(t, address), testSecret, testDomain, 2)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.receive(1); err == nil {
			t.Error("a blocked connection stayed open")
		}
		if len(dispatcher.dests) != 0 || fake.accepted.Load() != 0 {
			t.Error("a blocked connection reached Telegram")
		}
	})
}

// Checks the key material against telemt's published expected value.
func TestMiddlePrekeyMatchesKnownVector(t *testing.T) {
	prekey := middlePrekey(
		bytes.Repeat([]byte{0x11}, 16),
		bytes.Repeat([]byte{0x22}, 16),
		binary.LittleEndian.AppendUint32(nil, 0x44332211),
		[]byte{149, 154, 175, 50},
		0x1f90,
		"CLIENT",
		[]byte{10, 0, 0, 1},
		0x22b8,
		bytes.Repeat([]byte{0x55}, 128),
	)
	sum := sha256.Sum256(prekey)
	if got := hex.EncodeToString(sum[:]); got != "934f5facdafd65a44d5c2df90d2f35ddc81faaaeb337949dfeef817c8a7c1e00" {
		t.Errorf("prekey hash is %s", got)
	}
}

func TestParseMiddleConfig(t *testing.T) {
	parsed := parseMiddleConfig(`# force_probability 10 10
default 2;
proxy_for 1 149.154.175.50:8888;
proxy_for -2 149.154.161.184:8888;
proxy_for 203 91.105.192.110:443;
proxy_for 203 91.105.192.111:443;
proxy_for bad line;
`)
	if len(parsed) != 3 || len(parsed[203]) != 2 || parsed[-2][0].NetAddr() != "149.154.161.184:8888" || parsed[203][0].Port != 443 {
		t.Errorf("parsed %+v", parsed)
	}
}

func TestMiddleLookupFallsBackToDefaultDC(t *testing.T) {
	address := net.TCPDestination(net.ParseAddress("192.0.2.2"), net.Port(8888))
	media := net.TCPDestination(net.ParseAddress("192.0.2.3"), net.Port(8888))
	directory := &middleDirectory{
		secret:     []byte("secret"),
		proxies:    map[int][]net.Destination{2: {address}, -2: {media}},
		nextUpdate: time.Now().Add(time.Hour),
	}
	if _, proxy, ok := directory.lookup(10002); !ok || proxy != address {
		t.Errorf("an unknown DC got %v", proxy)
	}
	if _, proxy, ok := directory.lookup(-10002); !ok || proxy != media {
		t.Errorf("an unknown media DC got %v", proxy)
	}
	empty := &middleDirectory{nextUpdate: time.Now().Add(time.Hour)}
	if _, _, ok := empty.lookup(2); ok {
		t.Error("a list that hasn't loaded yet offered a proxy")
	}
}
