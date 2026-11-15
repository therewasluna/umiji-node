//go:build !linux

package iplimit

import (
	"time"

	"github.com/xtls/xray-core/common/net"
)

func setUserTimeout(*net.TCPConn, time.Duration) {}
