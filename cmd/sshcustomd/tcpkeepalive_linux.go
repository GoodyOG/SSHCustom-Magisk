//go:build linux

package main

import (
	"net"
	"syscall"
)

const (
	tcpUserTimeout = 18 // TCP_USER_TIMEOUT — max time unACKed data (ms)
	tcpKeepIdle    = 4  // TCP_KEEPIDLE  — idle before probes (s)
	tcpKeepIntvl   = 5  // TCP_KEEPINTVL — interval between probes (s)
	tcpKeepCnt     = 6  // TCP_KEEPCNT   — unanswered probes before dead
)

func setTCPTimeouts(tc *net.TCPConn, userTimeoutS, idleS, intvlS, cnt int) {
	raw, err := tc.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeout, userTimeoutS*1000)
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepIdle, idleS)
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepIntvl, intvlS)
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepCnt, cnt)
	})
}
