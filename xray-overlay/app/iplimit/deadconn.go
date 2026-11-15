package iplimit

import (
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// A spliced (Vision) connection has no idle timer (CopyRawConnIfExist sets it to 24 hours),
// and the core leaves TCP keepalive off on inbound sockets. A device that drops off a network
// without closing its connections would then hold its slot for minutes to hours. Limited users'
// sockets get keepalive and a user timeout, so the kernel closes dead ones in about a minute.
const (
	keepAliveIdle     = 30 * time.Second
	keepAliveInterval = 10 * time.Second
	keepAliveCount    = 3
	userTimeout       = 60 * time.Second
)

// tcpSocket digs the kernel socket out of the stats, TLS/REALITY, PROXY protocol and mask
// wrappers, or returns nil (WebSocket, gRPC, XHTTP: their idle timer still works).
func tcpSocket(c net.Conn) *net.TCPConn {
	for range 8 {
		switch v := c.(type) {
		case *net.TCPConn:
			return v
		case *stat.CounterConnection:
			c = v.Connection
		case interface{ NetConn() net.Conn }:
			c = v.NetConn()
		case interface{ Raw() net.Conn }:
			c = v.Raw()
		case interface{ RawConn() net.Conn }:
			c = v.RawConn()
		default:
			return nil
		}
	}
	return nil
}

func closeWhenDead(c net.Conn) {
	tc := tcpSocket(c)
	if tc == nil {
		return
	}
	_ = tc.SetKeepAliveConfig(net.KeepAliveConfig{
		Enable:   true,
		Idle:     keepAliveIdle,
		Interval: keepAliveInterval,
		Count:    keepAliveCount,
	})
	setUserTimeout(tc, userTimeout)
}
