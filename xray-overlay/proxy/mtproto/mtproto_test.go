package mtproto

import (
	"bufio"
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

const testDomain = "www.example.com"

var testSecret = bytes.Repeat([]byte{0xab}, secretSize)

// testClient follows what Telegram's clients do (TDLib's TlsInit and ObfuscatedTransport).
type testClient struct {
	conn    net.Conn
	reader  *bufio.Reader
	secret  []byte
	encrypt cipher.Stream
	decrypt cipher.Stream
	left    int
}

func buildClientHello(t testing.TB, secret []byte, domain string, at time.Time) []byte {
	t.Helper()

	extension := []byte{0, 0}
	sni := append([]byte{0}, byte(len(domain)>>8), byte(len(domain)))
	sni = append(sni, domain...)
	list := append([]byte{byte(len(sni) >> 8), byte(len(sni))}, sni...)
	extension = append(extension, byte(len(list)>>8), byte(len(list)))
	extension = append(extension, list...)
	padding := make([]byte, 180)
	extension = append(extension, 0x00, 0x15, byte(len(padding)>>8), byte(len(padding)))
	extension = append(extension, padding...)

	body := []byte{3, 3}
	body = append(body, make([]byte, randomSize)...)
	sessionID := make([]byte, 32)
	if _, err := rand.Read(sessionID); err != nil {
		t.Fatal(err)
	}
	body = append(body, 32)
	body = append(body, sessionID...)
	body = append(body, 0, 6, 0x0a, 0x0a, 0x13, 0x01, 0x13, 0x02) // starts with GREASE, like Chrome
	body = append(body, 1, 0)
	body = append(body, byte(len(extension)>>8), byte(len(extension)))
	body = append(body, extension...)

	record := appendRecordHeader(nil, recordHandshake, 4+len(body))
	record[2] = 1 // the outer hello record says TLS 1.0, like real clients
	record = append(record, 1, 0, byte(len(body)>>8), byte(len(body)))
	record = append(record, body...)

	mac := hmac.New(sha256.New, secret)
	mac.Write(record)
	random := mac.Sum(nil)
	timestamp := binary.LittleEndian.Uint32(random[digestSize:]) ^ uint32(at.Unix())
	binary.LittleEndian.PutUint32(random[digestSize:], timestamp)
	copy(record[randomOffset:], random)
	return record
}

// readServerReply mirrors TDLib's check: exact prefixes, then an HMAC over all of it.
func readServerReply(reader *bufio.Reader, secret, clientRandom []byte) error {
	var reply []byte
	for _, prefix := range [][]byte{{0x16, 3, 3}, {0x14, 3, 3, 0, 1, 1, 0x17, 3, 3}} {
		head := make([]byte, len(prefix)+2)
		if _, err := io.ReadFull(reader, head); err != nil {
			return fmt.Errorf("reading reply: %w", err)
		}
		if !bytes.Equal(head[:len(prefix)], prefix) {
			return fmt.Errorf("bad reply prefix %x", head)
		}
		payload := make([]byte, binary.BigEndian.Uint16(head[len(prefix):]))
		if _, err := io.ReadFull(reader, payload); err != nil {
			return fmt.Errorf("reading reply payload: %w", err)
		}
		reply = append(append(reply, head...), payload...)
	}

	got := bytes.Clone(reply[randomOffset : randomOffset+randomSize])
	clear(reply[randomOffset : randomOffset+randomSize])
	mac := hmac.New(sha256.New, secret)
	mac.Write(clientRandom)
	mac.Write(reply)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return fmt.Errorf("response hash mismatch")
	}
	return nil
}

func dialClient(t testing.TB, conn net.Conn, secret []byte, domain string, dc int16) (*testClient, error) {
	t.Helper()

	hello := buildClientHello(t, secret, domain, time.Now())
	if _, err := conn.Write(hello); err != nil {
		return nil, err
	}
	client := &testClient{conn: conn, reader: bufio.NewReader(conn), secret: secret}
	if err := readServerReply(client.reader, secret, hello[randomOffset:randomOffset+randomSize]); err != nil {
		return nil, err
	}

	var frame [frameSize]byte
	for {
		if _, err := rand.Read(frame[:]); err != nil {
			return nil, err
		}
		if isValidFrameStart(frame[:8]) {
			break
		}
	}
	copy(frame[frameTagStart:], []byte{0xdd, 0xdd, 0xdd, 0xdd})
	binary.LittleEndian.PutUint16(frame[frameDCStart:], uint16(dc))

	client.encrypt = newStream(mixSecret(frame[frameKeyStart:frameIVStart], secret), frame[frameIVStart:frameTagStart])
	key, iv := reversedKeyMaterial(&frame)
	client.decrypt = newStream(mixSecret(key, secret), iv)

	var encrypted [frameSize]byte
	client.encrypt.XORKeyStream(encrypted[:], frame[:])
	copy(frame[frameTagStart:], encrypted[frameTagStart:])

	first := []byte{0x14, 3, 3, 0, 1, 1} // the client's ChangeCipherSpec comes first
	first = appendRecordHeader(first, recordAppData, frameSize)
	first = append(first, frame[:]...)
	if _, err := conn.Write(first); err != nil {
		return nil, err
	}
	return client, nil
}

func (c *testClient) send(payload []byte) error {
	encrypted := make([]byte, len(payload))
	c.encrypt.XORKeyStream(encrypted, payload)
	// Split it to prove record boundaries don't matter to the relay.
	for len(encrypted) > 0 {
		size := min(len(encrypted), 2878)
		out := appendRecordHeader(nil, recordAppData, size)
		if _, err := c.conn.Write(append(out, encrypted[:size]...)); err != nil {
			return err
		}
		encrypted = encrypted[size:]
	}
	return nil
}

func (c *testClient) receive(size int) ([]byte, error) {
	out := make([]byte, size)
	records := &recordReader{r: c.reader, left: c.left}
	if _, err := io.ReadFull(records, out); err != nil {
		return nil, err
	}
	c.left = records.left
	c.decrypt.XORKeyStream(out, out)
	return out, nil
}

// fakeDC plays Telegram: it validates the frame, then echoes everything back.
func fakeDC(t testing.TB, link *transport.Link, gotDC chan<- int) {
	t.Helper()

	reader := &buf.BufferedReader{Reader: link.Reader}
	var frame [frameSize]byte
	if _, err := io.ReadFull(reader, frame[:]); err != nil {
		return
	}
	decrypt := newStream(frame[frameKeyStart:frameIVStart], frame[frameIVStart:frameTagStart])
	key, iv := reversedKeyMaterial(&frame)
	encrypt := newStream(key, iv)

	var plain [frameSize]byte
	decrypt.XORKeyStream(plain[:], frame[:])
	if !isProtocolTag(plain[frameTagStart:frameDCStart]) {
		t.Errorf("DC got a bad protocol tag %x", plain[frameTagStart:frameDCStart])
		return
	}
	gotDC <- int(int16(binary.LittleEndian.Uint16(plain[frameDCStart:])))

	data := make([]byte, buf.Size) // a buf.Buffer holds no more than this
	for {
		n, err := reader.Read(data)
		if n > 0 {
			decrypt.XORKeyStream(data[:n], data[:n])
			encrypt.XORKeyStream(data[:n], data[:n])
			b := buf.New()
			common.Must2(b.Write(data[:n]))
			if link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}) != nil {
				return
			}
		}
		if err != nil {
			common.Close(link.Writer)
			return
		}
	}
}

type testDispatcher struct {
	t     testing.TB
	dests chan net.Destination
	users chan *protocol.MemoryUser
	dcs   chan int
}

func (d *testDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *testDispatcher) Start() error      { return nil }
func (d *testDispatcher) Close() error      { return nil }
func (d *testDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return nil
}

func (d *testDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	d.dests <- dest
	d.users <- session.InboundFromContext(ctx).User
	upReader, upWriter := pipe.New(pipe.WithSizeLimit(64 * 1024))
	downReader, downWriter := pipe.New(pipe.WithSizeLimit(64 * 1024))
	go fakeDC(d.t, &transport.Link{Reader: upReader, Writer: downWriter}, d.dcs)
	return &transport.Link{Reader: downReader, Writer: upWriter}, nil
}

// startProxy runs a Server on a real socket, with fronting pointed at a real echo socket.
func startProxy(t *testing.T, secrets map[string][]byte, configure ...func(*Server)) (*Server, *testDispatcher, string, chan []byte) {
	t.Helper()

	frontListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { frontListener.Close() })
	fronted := make(chan []byte, 8)
	go func() {
		for {
			conn, err := frontListener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// The replay and whatever follows it can arrive as separate reads.
				var got []byte
				data := make([]byte, 64*1024)
				for {
					conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
					n, err := conn.Read(data)
					got = append(got, data[:n]...)
					if err != nil {
						break
					}
				}
				fronted <- got
				conn.Write([]byte("real website"))
			}()
		}
	}()

	target, err := net.ParseDestination("tcp:" + frontListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		policyManager: policy.DefaultManager{},
		domain:        testDomain,
		target:        target,
		users:         make(map[string]*protocol.MemoryUser),
	}
	for email, secret := range secrets {
		user := &protocol.MemoryUser{Email: email, Account: &MemoryAccount{Secret: secret}}
		if err := server.AddUser(context.Background(), user); err != nil {
			t.Fatal(err)
		}
	}
	for _, apply := range configure {
		apply(server)
	}

	dispatcher := &testDispatcher{
		t:     t,
		dests: make(chan net.Destination, 8),
		users: make(chan *protocol.MemoryUser, 8),
		dcs:   make(chan int, 8),
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
					Source: net.DestinationFromAddr(conn.RemoteAddr()),
				})
				server.Process(ctx, net.Network_TCP, conn.(stat.Connection), dispatcher)
			}()
		}
	}()
	return server, dispatcher, listener.Addr().String(), fronted
}

func dial(t *testing.T, address string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn
}

func TestRelayThroughProxy(t *testing.T) {
	other := bytes.Repeat([]byte{0x11}, secretSize)
	_, dispatcher, address, _ := startProxy(t, map[string][]byte{"7": testSecret, "8": other})

	client, err := dialClient(t, dial(t, address), testSecret, testDomain, -4)
	if err != nil {
		t.Fatal(err)
	}

	// Larger than a TLS record and a Xray buffer, so both boundaries get crossed.
	payload := make([]byte, 100_000)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	if err := client.send(payload); err != nil {
		t.Fatal(err)
	}
	echoed, err := client.receive(len(payload))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatal("payload changed on its way through the proxy")
	}

	if dest := <-dispatcher.dests; dest.Address.String() != "149.154.167.91" || dest.Port != 443 {
		t.Errorf("media DC 4 was sent to %s", dest)
	}
	if user := <-dispatcher.users; user == nil || user.Email != "7" {
		t.Errorf("traffic would be counted against the wrong user: %+v", user)
	}
	if dc := <-dispatcher.dcs; dc != -4 {
		t.Errorf("the media sign was lost, Telegram saw DC %d", dc)
	}
}

func TestStrangersReachTheRealWebsite(t *testing.T) {
	wrongSecret := bytes.Repeat([]byte{0x22}, secretSize)
	cases := map[string][]byte{
		"plain HTTP":   []byte("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"),
		"wrong secret": buildClientHello(t, wrongSecret, testDomain, time.Now()),
		"wrong domain": buildClientHello(t, testSecret, "other.example.com", time.Now()),
		"old hello":    buildClientHello(t, testSecret, testDomain, time.Now().Add(-maxClockSkew-time.Minute)),
		"future hello": buildClientHello(t, testSecret, testDomain, time.Now().Add(maxClockSkew+time.Minute)),
		"broken hello": {recordHandshake, 3, 1, 0, 2, 1, 0},
	}
	for name, probe := range cases {
		t.Run(name, func(t *testing.T) {
			_, dispatcher, address, fronted := startProxy(t, map[string][]byte{"7": testSecret})
			conn := dial(t, address)
			if _, err := conn.Write(probe); err != nil {
				t.Fatal(err)
			}
			answer := make([]byte, 64)
			n, err := conn.Read(answer)
			if err != nil || string(answer[:n]) != "real website" {
				t.Fatalf("probe got %q, %v", answer[:n], err)
			}
			if got := <-fronted; !bytes.Equal(got, probe) {
				t.Errorf("the website got %q instead of the probe's own bytes", got)
			}
			if len(dispatcher.dests) != 0 {
				t.Error("a stranger reached Telegram")
			}
		})
	}
}

func TestReplayedHelloReachesTheRealWebsite(t *testing.T) {
	_, _, address, fronted := startProxy(t, map[string][]byte{"7": testSecret})
	hello := buildClientHello(t, testSecret, testDomain, time.Now())

	first := dial(t, address)
	if _, err := first.Write(hello); err != nil {
		t.Fatal(err)
	}
	if err := readServerReply(bufio.NewReader(first), testSecret, hello[randomOffset:randomOffset+randomSize]); err != nil {
		t.Fatalf("the first hello should be accepted: %v", err)
	}

	replay := dial(t, address)
	if _, err := replay.Write(hello); err != nil {
		t.Fatal(err)
	}
	if got := <-fronted; !bytes.Equal(got, hello) {
		t.Errorf("the replay wasn't fronted, website got %d bytes", len(got))
	}
}

func TestUsersChangeWhileRunning(t *testing.T) {
	server, _, address, fronted := startProxy(t, nil)
	ctx := context.Background()
	hello := buildClientHello(t, testSecret, testDomain, time.Now())

	unknown := dial(t, address)
	if _, err := unknown.Write(hello); err != nil {
		t.Fatal(err)
	}
	<-fronted

	user := &protocol.MemoryUser{Email: "7", Account: &MemoryAccount{Secret: testSecret}}
	if err := server.AddUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	if server.AddUser(ctx, user) == nil {
		t.Error("the same user was added twice")
	}
	if server.GetUsersCount(ctx) != 1 || server.GetUser(ctx, "7") == nil || len(server.GetUsers(ctx)) != 1 {
		t.Error("the added user is missing")
	}
	if _, err := dialClient(t, dial(t, address), testSecret, testDomain, 2); err != nil {
		t.Fatalf("a user added live was refused: %v", err)
	}

	if err := server.RemoveUser(ctx, "7"); err != nil {
		t.Fatal(err)
	}
	if server.RemoveUser(ctx, "7") == nil {
		t.Error("the same user was removed twice")
	}
	removed := dial(t, address)
	if _, err := removed.Write(buildClientHello(t, testSecret, testDomain, time.Now())); err != nil {
		t.Fatal(err)
	}
	<-fronted
}

func TestDCDestination(t *testing.T) {
	cases := []struct {
		dc, sent int
		address  string
	}{
		{1, 1, "149.154.175.50"},
		{-2, -2, "149.154.167.51"},
		{203, 203, "91.105.192.100"},
		{-203, -203, "91.105.192.100"},
		{0, 2, "149.154.167.51"},
		{10002, 2, "149.154.167.51"},
		{-10002, -2, "149.154.167.51"},
	}
	for _, c := range cases {
		dest, sent := dcDestination(c.dc)
		if sent != c.sent || dest.Address.String() != c.address {
			t.Errorf("DC %d: got %d at %s", c.dc, sent, dest.Address)
		}
	}
}

func TestParseClientHelloNeverPanics(t *testing.T) {
	hello := buildClientHello(t, testSecret, testDomain, time.Now())
	if parsed := parseClientHello(hello); parsed == nil || parsed.sni != testDomain || parsed.cipherSuite != 0x1301 {
		t.Fatalf("a valid hello parsed as %+v", parsed)
	}
	for i := range hello {
		parseClientHello(hello[:i])
		corrupted := bytes.Clone(hello)
		corrupted[i] ^= 0xff
		parseClientHello(corrupted)
	}
}

func TestAccountRejectsBadSecrets(t *testing.T) {
	for _, secret := range []string{"", "abc", "zz" + hex.EncodeToString(testSecret)[2:], hex.EncodeToString(testSecret) + "00"} {
		if _, err := (&Account{Secret: secret}).AsAccount(); err == nil {
			t.Errorf("secret %q was accepted", secret)
		}
	}
	account, err := (&Account{Secret: hex.EncodeToString(testSecret)}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(account.(*MemoryAccount).Secret, testSecret) {
		t.Error("secret decoded wrongly")
	}
}

// BenchmarkAuthenticate measures a stranger's cost, the worst case: no secret matches.
func BenchmarkAuthenticate(b *testing.B) {
	for _, count := range []int{100, 1_000, 10_000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			server := &Server{users: make(map[string]*protocol.MemoryUser, count), domain: testDomain}
			for i := range count {
				secret := make([]byte, secretSize)
				rand.Read(secret)
				email := fmt.Sprint(i)
				server.users[email] = &protocol.MemoryUser{Email: email, Account: &MemoryAccount{Secret: secret}}
			}
			hello := parseClientHello(buildClientHello(b, bytes.Repeat([]byte{0x33}, secretSize), testDomain, time.Now()))
			now := time.Now()
			b.ResetTimer()
			for b.Loop() {
				server.authenticate(hello, now)
			}
		})
	}
}

// TestLiveTelegram checks a deployed proxy against Telegram itself, without an
// account: it asks for an auth key (req_pq_multi) and expects Telegram's resPQ.
//
//	MTPROTO_ADDRESS=1.2.3.4:443 MTPROTO_LINK_SECRET=ee... go test -run TestLiveTelegram -v ./proxy/mtproto
func TestLiveTelegram(t *testing.T) {
	address, linkSecret := os.Getenv("MTPROTO_ADDRESS"), os.Getenv("MTPROTO_LINK_SECRET")
	if address == "" || linkSecret == "" {
		t.Skip("set MTPROTO_ADDRESS and MTPROTO_LINK_SECRET to run")
	}
	raw, err := hex.DecodeString(linkSecret)
	if err != nil || len(raw) <= 1+secretSize || raw[0] != 0xee {
		t.Fatalf("expected an ee-prefixed hex secret, got %q", linkSecret)
	}

	// Every data centre in dcAddresses, plus the media path, so a moved address shows up here.
	for _, dc := range []int16{1, 2, 3, 4, 5, 203, -2} {
		t.Run(fmt.Sprintf("dc%d", dc), func(t *testing.T) {
			conn := dial(t, address)
			client, err := dialClient(t, conn, raw[1:1+secretSize], string(raw[1+secretSize:]), dc)
			if err != nil {
				t.Fatal(err)
			}

			nonce := make([]byte, 16)
			if _, err := rand.Read(nonce); err != nil {
				t.Fatal(err)
			}
			message := make([]byte, 20, 40)
			binary.LittleEndian.PutUint64(message[8:], uint64(time.Now().Unix())<<32)
			binary.LittleEndian.PutUint32(message[16:], 20)
			message = binary.LittleEndian.AppendUint32(message, 0xbe7e8ef1) // req_pq_multi
			message = append(message, nonce...)
			packet := binary.LittleEndian.AppendUint32(nil, uint32(len(message)))
			if err := client.send(append(packet, message...)); err != nil {
				t.Fatal(err)
			}

			head, err := client.receive(4)
			if err != nil {
				t.Fatalf("no answer from Telegram: %v", err)
			}
			size := binary.LittleEndian.Uint32(head)
			if size < 40 || size > 4096 {
				t.Fatalf("Telegram answered with a %d byte packet", size)
			}
			answer, err := client.receive(int(size))
			if err != nil {
				t.Fatal(err)
			}
			if got := binary.LittleEndian.Uint32(answer[20:]); got != 0x05162463 {
				t.Fatalf("expected resPQ, got constructor %#x", got)
			}
			if !bytes.Equal(answer[24:40], nonce) {
				t.Fatal("Telegram didn't echo our nonce")
			}
			t.Logf("resPQ from Telegram through the proxy (%d bytes)", size)
		})
	}
}
