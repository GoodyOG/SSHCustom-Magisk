//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

const soIPTransparent = 19

// listenTransparentTCP creates a TCP listener with IP_TRANSPARENT using
// raw syscalls. Avoids net.ListenConfig.Control which can be unreliable
// on some Android kernel versions.
func listenTransparentTCP(ctx context.Context, addr string) (net.Listener, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("tproxy socket: %w", err)
	}

	// IP_TRANSPARENT: accept packets with non-local destinations
	if err := syscall.SetsockoptInt(fd, syscall.SOL_IP, soIPTransparent, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("tproxy IP_TRANSPARENT: %w", err)
	}

	// SO_REUSEADDR: allow quick restarts
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("tproxy SO_REUSEADDR: %w", err)
	}

	// Bind
	sa := &syscall.SockaddrInet4{Port: tcpAddr.Port}
	copy(sa.Addr[:], tcpAddr.IP.To4())
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("tproxy bind: %w", err)
	}

	// Listen
	if err := syscall.Listen(fd, 128); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("tproxy listen: %w", err)
	}

	// Wrap as net.Listener
	f := os.NewFile(uintptr(fd), "tcp-tproxy")
	defer f.Close()
	return net.FileListener(f)
}

// setTransparent sets IP_TRANSPARENT sockopt on a file descriptor.
func setTransparent(fd int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_IP, soIPTransparent, 1)
}

// tproxyDst returns the original destination from a TPROXY-accepted TCP
// connection. TPROXY preserves the destination so LocalAddr() holds it.
func tproxyDst(conn *net.TCPConn) (string, error) {
	addr := conn.LocalAddr()
	if addr == nil {
		return "", errors.New("no local address on tproxy socket")
	}
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return "", fmt.Errorf("unexpected addr type: %T", addr)
	}
	return net.JoinHostPort(tcpAddr.IP.String(), fmt.Sprintf("%d", tcpAddr.Port)), nil
}

// udpTproxyConn wraps a UDP socket with IP_TRANSPARENT + IP_RECVORIGDSTADDR.
type udpTproxyConn struct {
	conn *net.UDPConn
}

// listenTransparentUDP creates a UDP listener with IP_TRANSPARENT +
// IP_RECVORIGDSTADDR for receiving TPROXY-captured UDP packets.
func listenTransparentUDP(ctx context.Context, addr string) (*udpTproxyConn, error) {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	var conn *net.UDPConn
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var ctrlErr error
			c.Control(func(fd uintptr) {
				if ctrlErr = setTransparent(int(fd)); ctrlErr != nil {
					return
				}
				if ctrlErr = setRecvOrigDst(int(fd)); ctrlErr != nil {
					return
				}
				if ctrlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); ctrlErr != nil {
					return
				}
			})
			return ctrlErr
		},
	}
	pc, err := lc.ListenPacket(ctx, "udp", uaddr.String())
	if err != nil {
		return nil, err
	}
	conn = pc.(*net.UDPConn)
	return &udpTproxyConn{conn: conn}, nil
}

// setRecvOrigDst enables IP_RECVORIGDSTADDR (20) on Linux 2.6.29+.
func setRecvOrigDst(fd int) error {
	const ipRecvOrigDstAddr = 20
	return syscall.SetsockoptInt(fd, syscall.SOL_IP, ipRecvOrigDstAddr, 1)
}

func (l *udpTproxyConn) Close() error {
	return l.conn.Close()
}

// recvFrom reads a datagram and extracts original destination from ancillary data.
func (l *udpTproxyConn) recvFrom() ([]byte, *net.UDPAddr, *net.UDPAddr, error) {
	buf := make([]byte, 65535)
	oob := make([]byte, 1024)

	n, oobn, _, src, err := l.conn.ReadMsgUDP(buf, oob)
	if err != nil {
		return nil, nil, nil, err
	}

	dst := parseOrigDstUDP(oob[:oobn])
	if dst == nil {
		return nil, nil, nil, errors.New("no original destination in ancillary data")
	}

	return buf[:n], src, dst, nil
}

// parseOrigDstUDP extracts the original destination IPv4 address from
// IP_RECVORIGDSTADDR ancillary data (sockaddr_in).
func parseOrigDstUDP(oob []byte) *net.UDPAddr {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	for _, msg := range msgs {
		if msg.Header.Level == syscall.SOL_IP && msg.Header.Type == 20 {
			if len(msg.Data) < 8 {
				continue
			}
			port := int(msg.Data[2])<<8 | int(msg.Data[3])
			ip := net.IPv4(msg.Data[4], msg.Data[5], msg.Data[6], msg.Data[7])
			return &net.UDPAddr{IP: ip, Port: port}
		}
	}
	return nil
}
