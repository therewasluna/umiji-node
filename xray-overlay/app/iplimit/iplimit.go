// Package iplimit caps how many IPs can use one user at the same time.
//
// Each node counts its own live IPs per user. The panel adds the IPs it saw on every node
// (SyncOperation), so a user's slots are shared across nodes. If the panel stops syncing,
// its list expires and each node keeps enforcing on its own IPs, so a failure only loosens
// the limit. Users without a limit are never tracked.
package iplimit

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/stats"
)

// How long the panel's list counts after a sync. The panel syncs every 30 seconds.
const admittedTTL = 2 * time.Minute

type ipState struct {
	refs   int
	since  time.Time
	conns  map[net.Conn]int
	kicked bool // over the limit after a sync: no new connections until its old ones end
}

type user struct {
	mu       sync.Mutex
	limit    int // 0 once the panel drops the user; the entry goes when its IPs do
	live     map[string]*ipState
	admitted map[string]bool
	until    time.Time
}

type Limiter struct {
	mu    sync.RWMutex
	users map[string]*user
	now   func() time.Time
}

func New() *Limiter {
	return &Limiter{users: map[string]*user{}, now: time.Now}
}

var global = New()

// Admit counts the connection in ctx against its user's limit until ctx ends, or refuses it.
func Admit(ctx context.Context, sm stats.Manager) error {
	return global.Admit(ctx, sm)
}

func (l *Limiter) Admit(ctx context.Context, sm stats.Manager) error {
	in := session.InboundFromContext(ctx)
	if in == nil || in.User == nil || in.User.Email == "" || in.Source.Address == nil {
		return nil
	}
	email := in.User.Email

	l.mu.RLock()
	u := l.users[email]
	l.mu.RUnlock()
	if u == nil {
		return nil
	}

	addr := in.Source.Address
	if addr.Family().IsIP() && addr.IP().IsLoopback() {
		return nil
	}
	ip := slotKey(addr)
	now := l.now()

	u.mu.Lock()
	e := u.live[ip]
	if e == nil {
		if u.limit == 0 {
			u.mu.Unlock()
			return nil
		}
		if !u.allows(ip, now) {
			used, limit := u.used(now), u.limit
			u.mu.Unlock()
			return errors.New("iplimit: ", email, " already uses ", used, " of ", limit, " IPs, refusing ", addr)
		}
		e = &ipState{since: now, conns: map[net.Conn]int{}}
		u.live[ip] = e
	} else if e.kicked {
		u.mu.Unlock()
		return errors.New("iplimit: ", email, " is over its limit, refusing ", addr)
	}
	e.refs++
	conn := in.Conn
	first := false
	if conn != nil {
		first = e.conns[conn] == 0
		e.conns[conn]++
	}
	u.mu.Unlock()
	if first {
		closeWhenDead(conn)
	}

	// The panel reads IPs from the stats online list, which the node only turns on with
	// CAP_NET_ADMIN, so limited users are reported here either way. Refcounts stay balanced
	// if the dispatcher adds the same IP too.
	var online stats.OnlineMap
	if sm != nil {
		if online, _ = sm.GetOrRegisterOnlineMap("user>>>" + email + ">>>online"); online != nil {
			online.AddIP(addr.String())
		}
	}

	context.AfterFunc(ctx, func() {
		if online != nil {
			online.RemoveIP(addr.String())
		}
		u.release(ip, conn)
	})
	return nil
}

var v6Slot = net.CIDRMask(64, 128)

// slotKey is what holds a slot: an IPv4 address, or an IPv6 /64. A phone's temporary IPv6
// addresses rotate inside its /64, and a home network gets one /64, like one IPv4 behind NAT.
func slotKey(a net.Address) string {
	if !a.Family().IsIP() {
		return a.String()
	}
	if a.Family().IsIPv4() {
		return a.IP().String()
	}
	return (&net.IPNet{IP: a.IP().Mask(v6Slot), Mask: v6Slot}).String()
}

// parseSlot reads one of the panel's IPs: an address as the online list shows it, or a /64.
func parseSlot(s string) string {
	s, _, _ = strings.Cut(s, "/")
	return slotKey(net.ParseAddress(s))
}

func (u *user) release(ip string, conn net.Conn) {
	u.mu.Lock()
	defer u.mu.Unlock()
	e := u.live[ip]
	if e == nil {
		return
	}
	if conn != nil {
		e.conns[conn]--
		if e.conns[conn] <= 0 {
			delete(e.conns, conn)
		}
	}
	e.refs--
	if e.refs <= 0 {
		delete(u.live, ip)
	}
}

func (u *user) fresh(now time.Time) bool {
	return now.Before(u.until)
}

// used counts the IPs holding slots: the panel's list while fresh, plus this node's live IPs
// the list doesn't have.
func (u *user) used(now time.Time) int {
	if !u.fresh(now) {
		return len(u.live)
	}
	n := len(u.admitted)
	for ip := range u.live {
		if !u.admitted[ip] {
			n++
		}
	}
	return n
}

func (u *user) allows(ip string, now time.Time) bool {
	if u.fresh(now) && u.admitted[ip] {
		return true
	}
	return u.used(now) < u.limit
}

// overflow marks live IPs the panel's list doesn't have, newest first, until the user fits
// its limit again, and returns their connections to close.
func (u *user) overflow() []net.Conn {
	var extra []string
	for ip, e := range u.live {
		e.kicked = false
		if !u.admitted[ip] {
			extra = append(extra, ip)
		}
	}
	free := max(u.limit-len(u.admitted), 0)
	if len(extra) <= free {
		return nil
	}
	sort.Slice(extra, func(i, j int) bool {
		return u.live[extra[i]].since.Before(u.live[extra[j]].since)
	})
	var conns []net.Conn
	for _, ip := range extra[free:] {
		e := u.live[ip]
		e.kicked = true
		for c := range e.conns {
			conns = append(conns, c)
		}
	}
	return conns
}

// Sync replaces every user's limit and cross-node list, and closes connections that no longer fit.
func (l *Limiter) Sync(entries []*Entry) {
	now := l.now()
	var kick []net.Conn

	l.mu.Lock()
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if entry.GetEmail() == "" || entry.GetLimit() == 0 {
			continue
		}
		seen[entry.Email] = true
		u := l.users[entry.Email]
		if u == nil {
			u = &user{live: map[string]*ipState{}}
			l.users[entry.Email] = u
		}
		admitted := make(map[string]bool, len(entry.Ips))
		for _, ip := range entry.Ips {
			admitted[parseSlot(ip)] = true
		}
		u.mu.Lock()
		u.limit = int(entry.Limit)
		u.admitted = admitted
		u.until = now.Add(admittedTTL)
		kick = append(kick, u.overflow()...)
		u.mu.Unlock()
	}
	for email, u := range l.users {
		if seen[email] {
			continue
		}
		u.mu.Lock()
		u.limit = 0
		u.admitted = nil
		if len(u.live) == 0 {
			delete(l.users, email)
		}
		u.mu.Unlock()
	}
	l.mu.Unlock()

	for _, c := range kick {
		c.Close()
	}
	if len(kick) > 0 {
		errors.LogInfo(context.Background(), "iplimit: closed ", len(kick), " connections over their user's limit")
	}
}

// ApplyInbound makes SyncOperation an AlterInbound operation. The inbound is only the
// way in: limits are per user, across every inbound.
func (op *SyncOperation) ApplyInbound(context.Context, inbound.Handler) error {
	global.Sync(op.GetUsers())
	return nil
}
