//go:build !linux

package main

import (
	"context"
	"errors"
	"net"
)

func listenTransparentTCP(ctx context.Context, addr string) (net.Listener, error) {
	return nil, errors.New("TPROXY only supported on linux")
}

func listenTransparentUDP(ctx context.Context, addr string) (*udpTproxyConn, error) {
	return nil, errors.New("TPROXY UDP only supported on linux")
}

func setTransparent(fd int) error {
	return errors.New("IP_TRANSPARENT not supported")
}

type udpTproxyConn struct {
	conn *net.UDPConn
}

func (l *udpTproxyConn) Close() error {
	return nil
}

func (l *udpTproxyConn) recvFrom() ([]byte, *net.UDPAddr, *net.UDPAddr, error) {
	return nil, nil, nil, errors.New("not supported")
}
