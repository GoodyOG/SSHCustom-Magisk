//go:build !linux

package main

import "net"

func setTCPTimeouts(tc *net.TCPConn, userTimeoutS, idleS, intvlS, cnt int) {
	// TCP keepalive tuning is Linux-only; no-op on other platforms.
	_ = tc
	_ = userTimeoutS
	_ = idleS
	_ = intvlS
	_ = cnt
}
