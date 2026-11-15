package iplimit

import (
	"time"

	"github.com/xtls/xray-core/common/net"
	"golang.org/x/sys/unix"
)

// Keepalive alone waits out retransmissions (about 15 minutes) when data is in flight.
func setUserTimeout(tc *net.TCPConn, d time.Duration) {
	raw, err := tc.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(d.Milliseconds()))
	})
}
