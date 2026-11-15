package iplimit

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

type fakeConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *fakeConn) Close() error {
	c.closed.Store(true)
	return nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newLimiter() (*Limiter, *clock) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	l := New()
	l.now = c.now
	return l, c
}

// connect opens one connection for email from ip. Cancel the context to end it.
func connect(l *Limiter, email, ip string, conn net.Conn) (context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(context.Background())
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress(ip), 40000),
		User:   &protocol.MemoryUser{Email: email},
		Conn:   conn,
	})
	if err := l.Admit(ctx, nil); err != nil {
		cancel()
		return nil, err
	}
	return cancel, nil
}

func liveIPs(l *Limiter, email string) int {
	l.mu.RLock()
	u := l.users[email]
	l.mu.RUnlock()
	if u == nil {
		return 0
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.live)
}

// Releases run in context.AfterFunc goroutines.
func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

func TestUnlimitedUserIsNotTracked(t *testing.T) {
	l, _ := newLimiter()
	for i := 0; i < 5; i++ {
		if _, err := connect(l, "free", fmt.Sprintf("10.0.0.%d", i), nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(l.users) != 0 {
		t.Fatal("a user without a limit was tracked")
	}
}

func TestRefusesNewIPWhenFull(t *testing.T) {
	l, _ := newLimiter()
	l.Sync([]*Entry{{Email: "u", Limit: 1}})

	endA, err := connect(l, "u", "1.1.1.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	endA2, err := connect(l, "u", "1.1.1.1", nil)
	if err != nil {
		t.Fatal("a second connection from the same IP was refused:", err)
	}
	if _, err := connect(l, "u", "2.2.2.2", nil); err == nil {
		t.Fatal("a second IP got in with a limit of 1")
	}

	endA()
	if _, err := connect(l, "u", "2.2.2.2", nil); err == nil {
		t.Fatal("the slot was freed while 1.1.1.1 still had a connection")
	}
	endA2()
	eventually(t, func() bool { return liveIPs(l, "u") == 0 })
	if _, err := connect(l, "u", "2.2.2.2", nil); err != nil {
		t.Fatal("the slot was not freed after 1.1.1.1 left:", err)
	}
}

func TestLoopbackIsNotCounted(t *testing.T) {
	l, _ := newLimiter()
	l.Sync([]*Entry{{Email: "u", Limit: 1}})
	for _, ip := range []string{"127.0.0.1", "::1", "1.1.1.1"} {
		if _, err := connect(l, "u", ip, nil); err != nil {
			t.Fatal(ip, err)
		}
	}
}

func TestConcurrentNewIPsNeverExceedLimit(t *testing.T) {
	l, _ := newLimiter()
	l.Sync([]*Entry{{Email: "u", Limit: 2}})

	var admitted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := connect(l, "u", fmt.Sprintf("10.0.%d.1", i), nil); err == nil {
				admitted.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if n := admitted.Load(); n != 2 {
		t.Fatalf("%d IPs got in with a limit of 2", n)
	}
}

func TestOtherNodesIPsTakeSlots(t *testing.T) {
	l, _ := newLimiter()
	l.Sync([]*Entry{{Email: "u", Limit: 1, Ips: []string{"9.9.9.9"}}})

	if _, err := connect(l, "u", "1.1.1.1", nil); err == nil {
		t.Fatal("got in while another node holds the only slot")
	}
	if _, err := connect(l, "u", "9.9.9.9", nil); err != nil {
		t.Fatal("the IP holding the slot on another node was refused here:", err)
	}
}

func TestStaleListFallsBackToThisNode(t *testing.T) {
	l, c := newLimiter()
	l.Sync([]*Entry{{Email: "u", Limit: 1, Ips: []string{"9.9.9.9"}}})

	c.t = c.t.Add(admittedTTL + time.Second)
	if _, err := connect(l, "u", "1.1.1.1", nil); err != nil {
		t.Fatal("an expired cross-node list still blocked:", err)
	}
	if _, err := connect(l, "u", "2.2.2.2", nil); err == nil {
		t.Fatal("this node's own limit stopped working once the list expired")
	}
}

func TestSyncClosesNewestOverflow(t *testing.T) {
	l, c := newLimiter()
	l.Sync([]*Entry{{Email: "u", Limit: 2}})

	older, newer := &fakeConn{}, &fakeConn{}
	if _, err := connect(l, "u", "1.1.1.1", older); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(time.Second)
	if _, err := connect(l, "u", "2.2.2.2", newer); err != nil {
		t.Fatal(err)
	}

	// Another node got the user first: one slot left here, for the older IP.
	l.Sync([]*Entry{{Email: "u", Limit: 2, Ips: []string{"9.9.9.9"}}})
	if older.closed.Load() || !newer.closed.Load() {
		t.Fatalf("older closed=%v newer closed=%v, want only the newer one closed",
			older.closed.Load(), newer.closed.Load())
	}
	if _, err := connect(l, "u", "2.2.2.2", nil); err == nil {
		t.Fatal("a kicked IP opened a new connection")
	}
	if _, err := connect(l, "u", "1.1.1.1", nil); err != nil {
		t.Fatal("the IP that kept its slot was refused:", err)
	}
}

func TestPanelListKeepsItsIPs(t *testing.T) {
	l, _ := newLimiter()
	l.Sync([]*Entry{{Email: "u", Limit: 1}})

	conn := &fakeConn{}
	if _, err := connect(l, "u", "1.1.1.1", conn); err != nil {
		t.Fatal(err)
	}
	l.Sync([]*Entry{{Email: "u", Limit: 1, Ips: []string{"1.1.1.1"}}})
	if conn.closed.Load() {
		t.Fatal("closed the IP the panel admitted")
	}
}

func TestDroppedUserLosesLimit(t *testing.T) {
	l, _ := newLimiter()
	l.Sync([]*Entry{{Email: "u", Limit: 1}})
	end, err := connect(l, "u", "1.1.1.1", nil)
	if err != nil {
		t.Fatal(err)
	}

	l.Sync(nil)
	if _, err := connect(l, "u", "2.2.2.2", nil); err != nil {
		t.Fatal("still limited after the panel dropped the limit:", err)
	}

	end()
	eventually(t, func() bool { return liveIPs(l, "u") == 0 })
	l.Sync(nil)
	if len(l.users) != 0 {
		t.Fatal("a dropped user with no IPs left was kept")
	}
}

func TestIPv6CountsByPrefix(t *testing.T) {
	l, _ := newLimiter()
	l.Sync([]*Entry{{Email: "u", Limit: 1}})

	// A phone's temporary address rotates inside its /64 while old connections stay open.
	if _, err := connect(l, "u", "2001:db8:1:2::a", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := connect(l, "u", "2001:db8:1:2:ffff::b", nil); err != nil {
		t.Fatal("a new address in the same /64 was refused:", err)
	}
	if _, err := connect(l, "u", "2001:db8:1:3::a", nil); err == nil {
		t.Fatal("another /64 got in with a limit of 1")
	}
}

func TestPanelListMatchesIPv6Prefix(t *testing.T) {
	for _, listed := range []string{"[2001:db8:1:2::a]", "2001:db8:1:2::/64", "2001:0db8:0001:0002::/64"} {
		l, _ := newLimiter()
		l.Sync([]*Entry{{Email: "u", Limit: 1, Ips: []string{listed}}})
		if _, err := connect(l, "u", "2001:db8:1:2::77", nil); err != nil {
			t.Fatalf("listed %s, the same /64 was refused: %v", listed, err)
		}
		if _, err := connect(l, "u", "1.1.1.1", nil); err == nil {
			t.Fatalf("listed %s, another IP got in with a limit of 1", listed)
		}
	}
}
