package iplimit

import (
	"crypto/tls"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/sys/unix"
)

// sockopts reads keepalive on/idle and the user timeout (ms) off the server side's socket.
func sockopts(t *testing.T, tc *net.TCPConn) (on, idle, userMs int) {
	t.Helper()
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	raw.Control(func(fd uintptr) {
		on, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_KEEPALIVE)
		idle, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPIDLE)
		userMs, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT)
	})
	return
}

func tcpPair(t *testing.T) *net.TCPConn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	// The core's listener turns keepalive off; start from the same place.
	server.(*net.TCPConn).SetKeepAlive(false)
	return server.(*net.TCPConn)
}

func TestLimitedUsersSocketsCloseWhenDead(t *testing.T) {
	l, _ := newLimiter()
	l.Sync([]*Entry{{Email: "u", Limit: 1}})

	sock := tcpPair(t)
	// What a REALITY/TLS inbound with stats hands the dispatcher.
	wrapped := &stat.CounterConnection{Connection: tls.Server(sock, &tls.Config{})}
	if _, err := connect(l, "u", "1.1.1.1", wrapped); err != nil {
		t.Fatal(err)
	}
	on, idle, userMs := sockopts(t, sock)
	if on != 1 || idle != int(keepAliveIdle.Seconds()) || userMs != int(userTimeout.Milliseconds()) {
		t.Fatalf("keepalive=%d idle=%ds user timeout=%dms", on, idle, userMs)
	}
}

func TestUnlimitedUsersSocketsAreUntouched(t *testing.T) {
	l, _ := newLimiter()
	sock := tcpPair(t)
	if _, err := connect(l, "free", "1.1.1.1", sock); err != nil {
		t.Fatal(err)
	}
	if on, _, userMs := sockopts(t, sock); on != 0 || userMs != 0 {
		t.Fatalf("an unlimited user's socket was changed: keepalive=%d user timeout=%dms", on, userMs)
	}
}
