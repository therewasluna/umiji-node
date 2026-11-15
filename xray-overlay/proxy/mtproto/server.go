// Package mtproto is a Telegram MTProxy inbound (fake TLS "ee" secrets only). It goes
// through Xray's normal routing to Telegram's data centres, or, for an inbound with an
// ad tag, to Telegram's middle proxies (middle.go).
package mtproto

import (
	"bufio"
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/app/iplimit"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	feature_stats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// maxClockSkew is the allowance Telegram's own proxy gives client clocks.
const maxClockSkew = 10 * time.Minute

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

// Server is an inbound connection handler for the MTProxy protocol.
type Server struct {
	policyManager policy.Manager
	domain        string
	target        net.Destination
	replay        replayCache

	usersLock sync.RWMutex
	users     map[string]*protocol.MemoryUser

	// The inbound's sponsored channel, for users without their own. May be nil.
	adTag           []byte
	publicIP        net.IP
	router          routing.Router
	outbounds       outbound.Manager
	stats           feature_stats.Manager
	middleSkipUntil atomic.Int64
}

// NewServer creates an MTProxy inbound handler.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	if config.Domain == "" {
		return nil, errors.New("mtproto: domain is required")
	}

	target := net.TCPDestination(net.ParseAddress(config.Domain), net.Port(443))
	if config.Target != "" {
		parsed, err := net.ParseDestination("tcp:" + config.Target)
		if err != nil {
			return nil, errors.New("mtproto: invalid target ", config.Target).Base(err)
		}
		target = parsed
	}

	server := &Server{
		policyManager: core.MustFromContext(ctx).GetFeature(policy.ManagerType()).(policy.Manager),
		domain:        config.Domain,
		target:        target,
		users:         make(map[string]*protocol.MemoryUser, len(config.Users)),
	}

	adTag, err := parseAdTag(config.AdTag)
	if err != nil {
		return nil, err
	}
	server.adTag = adTag
	anyTag := adTag != nil

	for _, user := range config.Users {
		memoryUser, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("mtproto: failed to get user").Base(err)
		}
		if err := server.AddUser(ctx, memoryUser); err != nil {
			return nil, err
		}
		anyTag = anyTag || memoryUser.Account.(*MemoryAccount).AdTag != nil
	}

	if config.PublicIp != "" {
		address := net.ParseAddress(config.PublicIp)
		if !address.Family().IsIPv4() {
			return nil, errors.New("mtproto: publicIp must be an IPv4 address")
		}
		server.publicIP = address.IP()
	}

	// Users with their own tag can arrive at any time, so these are always needed.
	if err := core.RequireFeatures(ctx, func(router routing.Router, outbounds outbound.Manager, stats feature_stats.Manager) error {
		server.router, server.outbounds, server.stats = router, outbounds, stats
		return nil
	}); err != nil {
		return nil, errors.New("mtproto: failed to get features").Base(err)
	}
	if anyTag {
		middleProxies.updateIfDue()
	}
	return server, nil
}

// AddUser implements proxy.UserManager.AddUser().
func (s *Server) AddUser(_ context.Context, user *protocol.MemoryUser) error {
	if _, ok := user.Account.(*MemoryAccount); !ok {
		return errors.New("mtproto: not an mtproto account: ", user.Email)
	}

	s.usersLock.Lock()
	defer s.usersLock.Unlock()
	if _, exists := s.users[user.Email]; exists {
		return errors.New("mtproto: user already exists: ", user.Email)
	}
	s.users[user.Email] = user
	return nil
}

// RemoveUser implements proxy.UserManager.RemoveUser().
func (s *Server) RemoveUser(_ context.Context, email string) error {
	s.usersLock.Lock()
	defer s.usersLock.Unlock()
	if _, exists := s.users[email]; !exists {
		return errors.New("mtproto: user not found: ", email)
	}
	delete(s.users, email)
	return nil
}

// GetUser implements proxy.UserManager.GetUser().
func (s *Server) GetUser(_ context.Context, email string) *protocol.MemoryUser {
	s.usersLock.RLock()
	defer s.usersLock.RUnlock()
	return s.users[email]
}

// GetUsers implements proxy.UserManager.GetUsers().
func (s *Server) GetUsers(context.Context) []*protocol.MemoryUser {
	s.usersLock.RLock()
	defer s.usersLock.RUnlock()
	users := make([]*protocol.MemoryUser, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user)
	}
	return users
}

// GetUsersCount implements proxy.UserManager.GetUsersCount().
func (s *Server) GetUsersCount(context.Context) int64 {
	s.usersLock.RLock()
	defer s.usersLock.RUnlock()
	return int64(len(s.users))
}

// Network implements proxy.Inbound.Network().
func (s *Server) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

// authenticate finds the user whose secret signed this hello.
//
// shortcut: the hello carries no user hint, so this tries every secret, about
// 1µs each (see BenchmarkAuthenticate). Remember the last user per source IP if
// inbounds with tens of thousands of users make handshakes slow.
func (s *Server) authenticate(hello *clientHello, now time.Time) (*protocol.MemoryUser, *MemoryAccount) {
	if hello == nil || !strings.EqualFold(hello.sni, s.domain) {
		return nil, nil
	}

	zeroed := hello.zeroedRecord()
	var digest [sha256.Size]byte

	s.usersLock.RLock()
	defer s.usersLock.RUnlock()
	for _, user := range s.users {
		account := user.Account.(*MemoryAccount)
		mac := hmac.New(sha256.New, account.Secret)
		mac.Write(zeroed)
		sum := mac.Sum(digest[:0])
		if subtle.ConstantTimeCompare(sum[:digestSize], hello.random[:digestSize]) != 1 {
			continue
		}
		timestamp := binary.LittleEndian.Uint32(sum[digestSize:]) ^ binary.LittleEndian.Uint32(hello.random[digestSize:])
		if skew := now.Sub(time.Unix(int64(timestamp), 0)); skew > maxClockSkew || skew < -maxClockSkew {
			return nil, nil
		}
		return user, account
	}
	return nil, nil
}

// Process implements proxy.Inbound.Process().
func (s *Server) Process(ctx context.Context, _ net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	handshakeTimeout := s.policyManager.ForLevel(0).Timeouts.Handshake
	if err := conn.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return errors.New("mtproto: unable to set read deadline").Base(err)
	}

	reader := bufio.NewReader(conn)
	record, err := readHelloRecord(reader)
	if len(record) == 0 && errors.Cause(err) == io.EOF {
		return nil
	}

	now := time.Now()
	hello := parseClientHello(record)
	user, account := s.authenticate(hello, now)
	// A replayed hello is an active probe, so it gets the same answer as any stranger.
	if user == nil || !s.replay.firstSeen(hello.random, now) {
		log.Record(&log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     "",
			Status: log.AccessRejected,
			Reason: errors.New("mtproto: not an authenticated client"),
		})
		return s.front(ctx, conn, reader, record)
	}

	reply, err := buildServerHello(hello, account.Secret)
	if err != nil {
		return err
	}
	if _, err := conn.Write(reply); err != nil {
		return errors.New("mtproto: failed to send server hello").Base(err)
	}

	records := &recordReader{r: reader}
	var frame [frameSize]byte
	if _, err := io.ReadFull(records, frame[:]); err != nil {
		return errors.New("mtproto: failed to read obfuscated frame").Base(err)
	}
	clientDecrypt, clientEncrypt, tag, requestedDC, err := openClientFrame(&frame, account.Secret)
	if err != nil {
		return err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return errors.New("mtproto: unable to clear read deadline").Base(err)
	}

	inbound := session.InboundFromContext(ctx)
	inbound.Name = "mtproto"
	inbound.User = user
	inbound.CanSpliceCopy = 3 // every byte is re-encrypted, so the kernel can't copy them
	// Here rather than only in the dispatcher: the middle-proxy path never reaches it.
	if err := iplimit.Admit(ctx, s.stats); err != nil {
		return err
	}

	adTag := account.AdTag
	if adTag == nil {
		adTag = s.adTag
	}
	if adTag != nil {
		handled, err := s.relayThroughMiddleProxy(ctx, conn, records, clientDecrypt, clientEncrypt, tag, adTag, requestedDC, user)
		if handled {
			return err
		}
	}

	destination, dc := dcDestination(requestedDC)
	wire, dcEncrypt, dcDecrypt, err := newDCFrame(tag, dc)
	if err != nil {
		return err
	}

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     destination,
		Status: log.AccessAccepted,
		Email:  user.Email,
	})
	errors.LogInfo(ctx, "mtproto: tunnelling to DC ", dc)

	sessionPolicy := s.policyManager.ForLevel(user.Level)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)
	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)

	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		return errors.New("mtproto: failed to dispatch to ", destination).Base(err)
	}

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		opening := buf.New()
		common.Must2(opening.Write(wire[:]))
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{opening}); err != nil {
			return errors.New("mtproto: failed to open DC stream").Base(err)
		}
		upstream := buf.NewReader(&relayReader{src: records, decrypt: clientDecrypt, encrypt: dcEncrypt})
		if err := buf.Copy(upstream, link.Writer, buf.UpdateActivity(timer)); err != nil {
			return errors.New("mtproto: failed to transfer request").Base(err)
		}
		return nil
	}

	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		downstream := &relayWriter{dst: conn, decrypt: dcDecrypt, encrypt: clientEncrypt}
		if err := buf.Copy(link.Reader, downstream, buf.UpdateActivity(timer)); err != nil {
			return errors.New("mtproto: failed to write response").Base(err)
		}
		return nil
	}

	if err := task.Run(ctx, task.OnSuccess(requestDone, task.Close(link.Writer)), responseDone); err != nil {
		common.Must(common.Interrupt(link.Reader))
		common.Must(common.Interrupt(link.Writer))
		return errors.New("mtproto: connection ends").Base(err)
	}
	return nil
}

// front makes this port behave exactly like the website it claims to be: anything
// that isn't an authenticated client is relayed there, bytes already read included.
func (s *Server) front(ctx context.Context, conn stat.Connection, reader io.Reader, consumed []byte) error {
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return errors.New("mtproto: unable to clear read deadline").Base(err)
	}

	upstream, err := internet.DialSystem(ctx, s.target, nil)
	if err != nil {
		return errors.New("mtproto: failed to reach fronting target ", s.target).Base(err)
	}
	defer upstream.Close()

	sessionPolicy := s.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	upstreamWriter := buf.NewWriter(upstream)
	clientWriter := buf.NewWriter(conn)

	request := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		if _, err := upstream.Write(consumed); err != nil {
			return errors.New("mtproto: failed to replay to fronting target").Base(err)
		}
		return buf.Copy(buf.NewReader(reader), upstreamWriter, buf.UpdateActivity(timer))
	}
	response := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(buf.NewReader(upstream), clientWriter, buf.UpdateActivity(timer))
	}

	if err := task.Run(ctx, task.OnSuccess(request, task.Close(upstreamWriter)), task.OnSuccess(response, task.Close(clientWriter))); err != nil {
		return errors.New("mtproto: fronting ends").Base(err).AtInfo()
	}
	return nil
}

// relayReader carries the client's stream re-encrypted for Telegram.
type relayReader struct {
	src              io.Reader
	decrypt, encrypt cipher.Stream
}

func (r *relayReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	r.decrypt.XORKeyStream(p[:n], p[:n])
	r.encrypt.XORKeyStream(p[:n], p[:n])
	return n, err
}

// relayWriter carries Telegram's stream to the client, re-encrypted and in TLS records.
type relayWriter struct {
	dst              io.Writer
	decrypt, encrypt cipher.Stream
	out              []byte
}

func (w *relayWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		payload := b.Bytes()
		w.decrypt.XORKeyStream(payload, payload)
		if err := w.writePayload(payload); err != nil {
			return err
		}
	}
	return nil
}

// writePayload encrypts plain bytes for the client and sends them in TLS records.
func (w *relayWriter) writePayload(payload []byte) error {
	w.encrypt.XORKeyStream(payload, payload)
	for len(payload) > 0 {
		size := min(len(payload), maxRecordPayload)
		w.out = appendRecordHeader(w.out[:0], recordAppData, size)
		w.out = append(w.out, payload[:size]...)
		if _, err := w.dst.Write(w.out); err != nil {
			return err
		}
		payload = payload[size:]
	}
	return nil
}

// replayCache remembers accepted hellos for as long as their timestamp stays
// valid. Only authenticated hellos get here, so strangers can't fill it.
type replayCache struct {
	lock    sync.Mutex
	expires map[[randomSize]byte]time.Time
	sweepAt time.Time
}

func (c *replayCache) firstSeen(random [randomSize]byte, now time.Time) bool {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.expires == nil {
		c.expires = make(map[[randomSize]byte]time.Time)
	}
	if now.After(c.sweepAt) {
		for seen, expiry := range c.expires {
			if now.After(expiry) {
				delete(c.expires, seen)
			}
		}
		c.sweepAt = now.Add(maxClockSkew)
	}
	if _, seen := c.expires[random]; seen {
		return false
	}
	c.expires[random] = now.Add(2 * maxClockSkew)
	return true
}
