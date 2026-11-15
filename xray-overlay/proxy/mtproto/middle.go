package mtproto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"hash/crc32"
	"io"
	mathrand "math/rand/v2"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	feature_stats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Sponsored channels only work through Telegram's middle proxies, which read the
// ad tag. Their handshake keys include the source IP and port they see, so only an
// outbound whose socket opens on this node can reach them. Anything else, or any
// failure, falls back to the direct path: users stay connected, without the channel.
const (
	rpcNonce         = 0x7acb87aa
	rpcHandshake     = 0x7682eef5
	rpcProxyRequest  = 0x36cef1ee
	rpcProxyAnswer   = 0x4403da0d
	rpcSimpleAck     = 0x3bac409b
	rpcCloseExt      = 0x5eb634a2
	rpcProxyTag      = 0xdb1e26ae
	rpcCryptoAES     = 1
	rpcFirstSequence = -2

	rpcFlagNotEncrypted = 0x2
	rpcFlagHasAdTag     = 0x8
	rpcFlagMagic        = 0x1000
	rpcFlagExtMode2     = 0x20000
	rpcFlagPad          = 0x8000000
	rpcFlagIntermediate = 0x20000000
	rpcFlagQuickAck     = 0x80000000

	rpcFrameOverhead = 12 // length, sequence, CRC
	rpcMaxFrame      = 1 << 24
	rpcBlockSize     = aes.BlockSize
	rpcNonceAnswer   = rpcFrameOverhead + 32
	adTagSize        = 16

	middleConfigURL = "https://core.telegram.org/getProxyConfig"
	middleSecretURL = "https://core.telegram.org/getProxySecret"

	middleUpdateEvery  = time.Hour
	middleRetryEvery   = time.Minute
	middleConnectLimit = 3 * time.Second
	// How long an inbound skips middle proxies after one fails, so that clients
	// don't each wait out a timeout while they're unreachable.
	middleCooldown = time.Minute

	freedomConfigType   = "xray.proxy.freedom.Config"
	blackholeConfigType = "xray.proxy.blackhole.Config"
)

var (
	rpcPadding = []byte{4, 0, 0, 0}
	rpcPID     = []byte("IPIPPRPDTIME")
	proxyFor   = regexp.MustCompile(`proxy_for\s+(-?\d+)\s+([0-9.]+):(\d+)\s*;`)
)

// middleProxies is Telegram's published list, shared by every tagged inbound.
var middleProxies = &middleDirectory{}

type middleDirectory struct {
	lock       sync.RWMutex
	secret     []byte
	proxies    map[int][]net.Destination
	nextUpdate time.Time
	updating   atomic.Bool
}

// lookup finds a middle proxy for a DC, keeping the sign that marks media DCs.
func (d *middleDirectory) lookup(dc int) (secret []byte, proxy net.Destination, ok bool) {
	d.updateIfDue()

	d.lock.RLock()
	defer d.lock.RUnlock()
	candidates := d.proxies[dc]
	if len(candidates) == 0 {
		if dc < 0 {
			candidates = d.proxies[-defaultDC]
		} else {
			candidates = d.proxies[defaultDC]
		}
	}
	if d.secret == nil || len(candidates) == 0 {
		return nil, net.Destination{}, false
	}
	return d.secret, candidates[mathrand.IntN(len(candidates))], true
}

func (d *middleDirectory) updateIfDue() {
	d.lock.RLock()
	due := time.Now().After(d.nextUpdate)
	d.lock.RUnlock()
	if !due || !d.updating.CompareAndSwap(false, true) {
		return
	}

	go func() {
		defer d.updating.Store(false)
		secret, proxies, err := fetchMiddleDirectory()

		d.lock.Lock()
		defer d.lock.Unlock()
		if err != nil {
			errors.LogWarningInner(context.Background(), err, "mtproto: failed to update the middle proxy list")
			d.nextUpdate = time.Now().Add(middleRetryEvery)
			return
		}
		d.secret, d.proxies = secret, proxies
		d.nextUpdate = time.Now().Add(middleUpdateEvery)
	}()
}

func fetchMiddleDirectory() ([]byte, map[int][]net.Destination, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	get := func(url string) ([]byte, error) {
		response, err := client.Get(url)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, errors.New("unexpected status ", response.StatusCode, " from ", url)
		}
		return io.ReadAll(io.LimitReader(response.Body, 1<<20))
	}

	config, err := get(middleConfigURL)
	if err != nil {
		return nil, nil, err
	}
	proxies := parseMiddleConfig(string(config))
	if len(proxies) == 0 {
		return nil, nil, errors.New("no middle proxies in the published config")
	}
	secret, err := get(middleSecretURL)
	if err != nil {
		return nil, nil, err
	}
	if len(secret) < 32 {
		return nil, nil, errors.New("the published middle proxy secret is too short")
	}
	return secret, proxies, nil
}

// shortcut: IPv4 only, like the direct path. Add getProxyConfigV6 for IPv6-only nodes.
func parseMiddleConfig(config string) map[int][]net.Destination {
	proxies := make(map[int][]net.Destination)
	for _, match := range proxyFor.FindAllStringSubmatch(config, -1) {
		dc, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		port, err := net.PortFromString(match[3])
		if err != nil {
			continue
		}
		proxies[dc] = append(proxies[dc], net.TCPDestination(net.ParseAddress(match[2]), port))
	}
	return proxies
}

// middlePrekey is the material both ends derive keys from. The IPs and ports are the
// ones each end sees, which is why a wrong publicIp or a proxied outbound gets refused.
func middlePrekey(serverNonce, clientNonce, timestamp, serverIP []byte, clientPort uint16, purpose string, clientIP []byte, serverPort uint16, secret []byte) []byte {
	prekey := slices.Concat(serverNonce, clientNonce, timestamp, serverIP)
	prekey = binary.LittleEndian.AppendUint16(prekey, clientPort)
	prekey = append(prekey, purpose...)
	prekey = append(prekey, clientIP...)
	prekey = binary.LittleEndian.AppendUint16(prekey, serverPort)
	return slices.Concat(prekey, secret, serverNonce, clientNonce)
}

func middleKeys(prekey []byte) (key, iv []byte) {
	first := md5.Sum(prekey[1:])
	second := sha1.Sum(prekey)
	third := md5.Sum(prekey[2:])
	return slices.Concat(first[:12], second[:]), third[:]
}

func reversedIP(ip net.IP) []byte {
	reversed := slices.Clone([]byte(ip.To4()))
	slices.Reverse(reversed)
	return reversed
}

// appendRPCFrame adds one frame: length, sequence, payload, CRC, then filler up to a block.
func appendRPCFrame(out []byte, sequence int32, payload ...[]byte) []byte {
	start := len(out)
	size := rpcFrameOverhead
	for _, part := range payload {
		size += len(part)
	}
	out = binary.LittleEndian.AppendUint32(out, uint32(size))
	out = binary.LittleEndian.AppendUint32(out, uint32(sequence))
	for _, part := range payload {
		out = append(out, part...)
	}
	out = binary.LittleEndian.AppendUint32(out, crc32.ChecksumIEEE(out[start:]))
	for (len(out)-start)%rpcBlockSize != 0 {
		out = append(out, rpcPadding...)
	}
	return out
}

// middleConn is one client's connection to a middle proxy, after the handshake.
type middleConn struct {
	conn          net.Conn
	encrypt       cipher.BlockMode
	decrypt       cipher.BlockMode
	flags         uint32
	requestHeader []byte
	writeSequence int32
	readSequence  int32
	out           []byte
	in            []byte
	plain         []byte
}

// openMiddleConn runs the handshake over a socket whose real source address is known.
func openMiddleConn(conn net.Conn, secret []byte, serverIP net.IP, serverPort uint16, sourceIP net.IP, sourcePort uint16) (*middleConn, error) {
	clientNonce := make([]byte, 16)
	if _, err := rand.Read(clientNonce); err != nil {
		return nil, errors.New("mtproto: failed to generate a nonce").Base(err)
	}
	timestamp := binary.LittleEndian.AppendUint32(nil, uint32(time.Now().Unix()))

	nonce := binary.LittleEndian.AppendUint32(nil, rpcNonce)
	nonce = append(nonce, secret[:4]...)
	nonce = binary.LittleEndian.AppendUint32(nonce, rpcCryptoAES)
	nonce = append(nonce, timestamp...)
	nonce = append(nonce, clientNonce...)
	if _, err := conn.Write(appendRPCFrame(nil, rpcFirstSequence, nonce)); err != nil {
		return nil, errors.New("mtproto: failed to send nonce").Base(err)
	}

	// Unlike every other frame, the nonce answer has no filler after it.
	answer := make([]byte, rpcNonceAnswer)
	if _, err := io.ReadFull(conn, answer); err != nil {
		return nil, errors.New("mtproto: no nonce answer").Base(err)
	}
	if binary.LittleEndian.Uint32(answer) != rpcNonceAnswer ||
		binary.LittleEndian.Uint32(answer[8:]) != rpcNonce ||
		!slices.Equal(answer[12:16], secret[:4]) ||
		binary.LittleEndian.Uint32(answer[16:]) != rpcCryptoAES ||
		binary.LittleEndian.Uint32(answer[rpcNonceAnswer-4:]) != crc32.ChecksumIEEE(answer[:rpcNonceAnswer-4]) {
		return nil, errors.New("mtproto: unexpected nonce answer")
	}
	serverNonce := answer[24:40]

	keysFor := func(purpose string) (cipher.Block, []byte, error) {
		key, iv := middleKeys(middlePrekey(serverNonce, clientNonce, timestamp, reversedIP(serverIP), sourcePort, purpose, reversedIP(sourceIP), serverPort, secret))
		block, err := aes.NewCipher(key)
		return block, iv, err
	}
	encryptBlock, encryptIV, err := keysFor("CLIENT")
	if err != nil {
		return nil, err
	}
	decryptBlock, decryptIV, err := keysFor("SERVER")
	if err != nil {
		return nil, err
	}

	m := &middleConn{
		conn:          conn,
		encrypt:       cipher.NewCBCEncrypter(encryptBlock, encryptIV),
		decrypt:       cipher.NewCBCDecrypter(decryptBlock, decryptIV),
		writeSequence: rpcFirstSequence + 1,
		readSequence:  rpcFirstSequence + 1,
	}

	handshake := binary.LittleEndian.AppendUint32(nil, rpcHandshake)
	handshake = binary.LittleEndian.AppendUint32(handshake, 0)
	handshake = append(handshake, rpcPID...)
	handshake = append(handshake, rpcPID...)
	if err := m.writeFrame(handshake); err != nil {
		return nil, errors.New("mtproto: failed to send handshake").Base(err)
	}
	reply, err := m.readFrame()
	if err != nil {
		return nil, errors.New("mtproto: handshake refused, is publicIp right?").Base(err)
	}
	if len(reply) != 32 || binary.LittleEndian.Uint32(reply) != rpcHandshake || !slices.Equal(reply[20:32], rpcPID) {
		return nil, errors.New("mtproto: unexpected handshake answer")
	}
	return m, nil
}

func (m *middleConn) writeFrame(payload ...[]byte) error {
	m.out = appendRPCFrame(m.out[:0], m.writeSequence, payload...)
	m.writeSequence++
	m.encrypt.CryptBlocks(m.out, m.out)
	_, err := m.conn.Write(m.out)
	return err
}

// fill decrypts whole blocks until n plain bytes are ready. Frames always end on a
// block boundary, so this never waits for more than the current frame.
func (m *middleConn) fill(n int) error {
	if len(m.plain) >= n {
		return nil
	}
	want := (n - len(m.plain) + rpcBlockSize - 1) / rpcBlockSize * rpcBlockSize
	m.in = slices.Grow(m.in[:0], want)[:want]
	if _, err := io.ReadFull(m.conn, m.in); err != nil {
		return err
	}
	m.decrypt.CryptBlocks(m.in, m.in)
	m.plain = append(m.plain, m.in...)
	return nil
}

// readFrame returns the next payload, which stays valid until the next call.
func (m *middleConn) readFrame() ([]byte, error) {
	for {
		if err := m.fill(4); err != nil {
			return nil, err
		}
		if !slices.Equal(m.plain[:4], rpcPadding) {
			break
		}
		m.plain = m.plain[4:]
	}

	size := int(binary.LittleEndian.Uint32(m.plain))
	if size < rpcFrameOverhead || size > rpcMaxFrame || size%4 != 0 {
		return nil, errors.New("mtproto: bad middle proxy frame size ", size)
	}
	if err := m.fill(size); err != nil {
		return nil, err
	}
	frame := m.plain[:size]
	m.plain = m.plain[size:]

	if int32(binary.LittleEndian.Uint32(frame[4:])) != m.readSequence {
		return nil, errors.New("mtproto: middle proxy frame out of sequence")
	}
	m.readSequence++
	if binary.LittleEndian.Uint32(frame[size-4:]) != crc32.ChecksumIEEE(frame[:size-4]) {
		return nil, errors.New("mtproto: bad middle proxy frame checksum")
	}
	return frame[8 : size-4], nil
}

// prepareRequests builds what stays the same in every request of this connection.
func (m *middleConn) prepareRequests(tag, adTag []byte, client, source net.Destination) error {
	connectionID := make([]byte, 8)
	if _, err := rand.Read(connectionID); err != nil {
		return errors.New("mtproto: failed to generate a connection ID").Base(err)
	}

	m.flags = rpcFlagMagic | rpcFlagExtMode2 | rpcFlagIntermediate | rpcFlagHasAdTag
	if tag[0] == 0xdd {
		m.flags |= rpcFlagPad
	}

	header := appendIPPort(connectionID, client)
	header = appendIPPort(header, source)
	header = binary.LittleEndian.AppendUint32(header, 4+1+adTagSize+3) // tag type, length, tag, alignment
	header = binary.LittleEndian.AppendUint32(header, rpcProxyTag)
	header = append(header, adTagSize)
	header = append(header, adTag...)
	m.requestHeader = append(header, 0, 0, 0)
	return nil
}

func appendIPPort(out []byte, address net.Destination) []byte {
	var ip net.IP
	if address.Address != nil && address.Address.Family().IsIP() {
		ip = address.Address.IP()
	}
	if v4 := ip.To4(); v4 != nil {
		out = append(out, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff)
		out = append(out, v4...)
	} else if len(ip) == 16 {
		out = append(out, ip...)
	} else {
		out = append(out, make([]byte, 16)...)
	}
	return binary.LittleEndian.AppendUint32(out, uint32(address.Port))
}

func (m *middleConn) sendMessage(message []byte, quickAck bool) error {
	flags := m.flags
	if quickAck {
		flags |= rpcFlagQuickAck
	}
	if len(message) >= 8 && binary.LittleEndian.Uint64(message) == 0 {
		flags |= rpcFlagNotEncrypted
	}
	head := binary.LittleEndian.AppendUint32(nil, rpcProxyRequest)
	head = binary.LittleEndian.AppendUint32(head, flags)
	return m.writeFrame(head, m.requestHeader, message)
}

type middleRoute int

const (
	middleRouteDirect middleRoute = iota
	middleRouteBlocked
	middleRouteElsewhere
)

// routeMiddleProxy asks Xray's router where this connection goes. For a direct
// outbound it returns the outbound's own socket, with its sendThrough and sockopt.
func (s *Server) routeMiddleProxy(ctx context.Context, proxy net.Destination) (stat.Connection, string, middleRoute, error) {
	outboundContext := session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: proxy, OriginalTarget: proxy}})

	handler := s.outbounds.GetDefaultHandler()
	if route, err := s.router.PickRoute(routing_session.AsRoutingContext(outboundContext)); err == nil {
		if picked := s.outbounds.GetHandler(route.GetOutboundTag()); picked != nil {
			handler = picked
		}
	}
	if handler == nil {
		return nil, "", middleRouteElsewhere, nil
	}

	switch handler.ProxySettings().GetType() {
	case blackholeConfigType:
		return nil, handler.Tag(), middleRouteBlocked, nil
	case freedomConfigType:
	default:
		return nil, handler.Tag(), middleRouteElsewhere, nil
	}

	dialer, ok := handler.(interface {
		Dial(context.Context, net.Destination) (stat.Connection, error)
	})
	if !ok {
		return nil, handler.Tag(), middleRouteElsewhere, nil
	}

	dialContext, cancel := context.WithTimeout(outboundContext, middleConnectLimit)
	defer cancel()
	conn, err := dialer.Dial(dialContext, proxy)
	if err != nil {
		return nil, handler.Tag(), middleRouteDirect, errors.New("mtproto: failed to reach middle proxy ", proxy).Base(err)
	}
	return conn, handler.Tag(), middleRouteDirect, nil
}

// sourceAddress is the IP and port a middle proxy will see for this socket. A
// dialerProxy chain has no real socket here, so it ends up refused like other chains.
func (s *Server) sourceAddress(conn net.Conn) (net.IP, uint16, error) {
	local, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok || local.Port == 0 {
		return nil, 0, errors.New("mtproto: this outbound has no socket on this node")
	}
	if s.publicIP != nil {
		return s.publicIP, uint16(local.Port), nil
	}
	ip := local.IP.To4()
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || (ip[0] == 100 && ip[1]&0xc0 == 64) {
		return nil, 0, errors.New("mtproto: this node's address ", local.IP, " is private, so set publicIp on the inbound")
	}
	return ip, uint16(local.Port), nil
}

// relayThroughMiddleProxy returns handled=false when the caller should use the
// direct path instead. Nothing has been read from the client's stream by then.
func (s *Server) relayThroughMiddleProxy(ctx context.Context, conn stat.Connection, records io.Reader, clientDecrypt, clientEncrypt cipher.Stream, tag, adTag []byte, requestedDC int, user *protocol.MemoryUser) (handled bool, err error) {
	// Abridged framing isn't parsed here, and fake TLS clients don't use it.
	if tag[0] == 0xef || time.Now().Unix() < s.middleSkipUntil.Load() {
		return false, nil
	}
	if requestedDC == 0 {
		requestedDC = defaultDC
	}
	secret, proxy, ok := middleProxies.lookup(requestedDC)
	if !ok {
		return false, nil
	}

	fail := func(err error) (bool, error) {
		s.middleSkipUntil.Store(time.Now().Add(middleCooldown).Unix())
		errors.LogWarningInner(ctx, err, "mtproto: using the direct path for ", middleCooldown, ", so the sponsored channel won't show")
		return false, nil
	}

	remote, detour, route, err := s.routeMiddleProxy(ctx, proxy)
	switch {
	case route == middleRouteBlocked:
		return true, errors.New("mtproto: blocked by routing, outbound [", detour, "]")
	case route == middleRouteElsewhere:
		errors.LogInfo(ctx, "mtproto: outbound [", detour, "] doesn't leave from this node, so the sponsored channel won't show")
		return false, nil
	case err != nil:
		return fail(err)
	}
	defer remote.Close()

	sourceIP, sourcePort, err := s.sourceAddress(remote)
	if err != nil {
		return fail(err)
	}
	if err := remote.SetDeadline(time.Now().Add(middleConnectLimit)); err != nil {
		return fail(err)
	}
	middle, err := openMiddleConn(remote, secret, proxy.Address.IP(), uint16(proxy.Port), sourceIP, sourcePort)
	if err != nil {
		return fail(err)
	}
	if err := remote.SetDeadline(time.Time{}); err != nil {
		return fail(err)
	}

	inbound := session.InboundFromContext(ctx)
	source := net.TCPDestination(net.IPAddress(sourceIP), net.Port(sourcePort))
	if err := middle.prepareRequests(tag, adTag, inbound.Source, source); err != nil {
		return fail(err)
	}

	log.Record(&log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     proxy,
		Status: log.AccessAccepted,
		Detour: inbound.Tag + " >> " + detour + " (middle proxy)",
		Email:  user.Email,
	})

	sessionPolicy := s.policyManager.ForLevel(user.Level)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	// Going around the dispatcher means counting usage here, or limits would stop working.
	var uplink, downlink feature_stats.Counter
	if sessionPolicy.Stats.UserUplink {
		uplink, _ = s.stats.GetOrRegisterCounter("user>>>" + user.Email + ">>>traffic>>>uplink")
	}
	if sessionPolicy.Stats.UserDownlink {
		downlink, _ = s.stats.GetOrRegisterCounter("user>>>" + user.Email + ">>>traffic>>>downlink")
	}
	if sessionPolicy.Stats.UserOnline {
		if online, _ := s.stats.GetOrRegisterOnlineMap("user>>>" + user.Email + ">>>online"); online != nil {
			ip := inbound.Source.Address.String()
			online.AddIP(ip)
			context.AfterFunc(ctx, func() { online.RemoveIP(ip) })
		}
	}

	stream := cipher.StreamReader{S: clientDecrypt, R: records}
	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		var head [4]byte
		var message []byte
		for {
			if _, err := io.ReadFull(stream, head[:]); err != nil {
				return err
			}
			size := binary.LittleEndian.Uint32(head[:])
			quickAck := size&rpcFlagQuickAck != 0
			size &^= rpcFlagQuickAck
			if size > rpcMaxFrame {
				return errors.New("mtproto: client message too large: ", size)
			}
			message = slices.Grow(message[:0], int(size))[:size]
			if _, err := io.ReadFull(stream, message); err != nil {
				return err
			}
			// Anything past a multiple of 4 is the padding of the secure transport.
			payload := message[:size-size%4]
			if len(payload) == 0 {
				continue
			}
			if err := middle.sendMessage(payload, quickAck); err != nil {
				return err
			}
			if uplink != nil {
				uplink.Add(int64(len(payload)))
			}
			timer.Update()
		}
	}

	writer := &relayWriter{dst: conn, encrypt: clientEncrypt}
	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		var framed []byte
		for {
			payload, err := middle.readFrame()
			if err != nil {
				return err
			}
			if len(payload) < 4 {
				continue
			}
			switch binary.LittleEndian.Uint32(payload) {
			case rpcProxyAnswer:
				if len(payload) < 16 {
					return errors.New("mtproto: short middle proxy answer")
				}
				data := payload[16:]
				framed = appendClientMessage(framed[:0], data, tag)
				if err := writer.writePayload(framed); err != nil {
					return err
				}
				if downlink != nil {
					downlink.Add(int64(len(data)))
				}
			case rpcSimpleAck:
				if len(payload) < 16 {
					return errors.New("mtproto: short middle proxy ack")
				}
				framed = append(framed[:0], payload[12:16]...)
				if err := writer.writePayload(framed); err != nil {
					return err
				}
			case rpcCloseExt:
				return errors.New("mtproto: closed by the middle proxy")
			}
			timer.Update()
		}
	}

	if err := task.Run(ctx, requestDone, responseDone); err != nil {
		return true, errors.New("mtproto: connection ends").Base(err)
	}
	return true, nil
}

// appendClientMessage frames a message the way the client's transport expects it.
func appendClientMessage(out, data, tag []byte) []byte {
	padding := 0
	if tag[0] == 0xdd {
		padding = mathrand.IntN(4)
	}
	out = binary.LittleEndian.AppendUint32(out, uint32(len(data)+padding))
	out = append(out, data...)
	for range padding {
		out = append(out, byte(mathrand.IntN(256)))
	}
	return out
}
