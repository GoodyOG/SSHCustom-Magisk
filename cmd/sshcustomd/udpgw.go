package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

const (
	udpgwAddrTypeIPv4 = 1
	udpgwHeaderSize   = 7
	udpgwMaxPayload   = 65507
)

// BadVPN UDPGW wire helpers.

// packUDPGW builds a UDPGW frame: [2B BE:data_len][1B:type=1][4B:IP][2B:port][payload]
func packUDPGW(ip net.IP, port int, payload []byte) []byte {
	dataLen := udpgwHeaderSize + len(payload)
	frame := make([]byte, 2+dataLen)
	binary.BigEndian.PutUint16(frame[0:2], uint16(dataLen))
	frame[2] = udpgwAddrTypeIPv4
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero
	}
	copy(frame[3:7], ip4)
	binary.BigEndian.PutUint16(frame[7:9], uint16(port))
	copy(frame[9:], payload)
	return frame
}

// readUDPGWFrame reads and unpacks a UDPGW response frame.
// Returns: sourceIP, sourcePort, payload, error
func readUDPGWFrame(r io.Reader) (net.IP, int, []byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, 0, nil, err
	}
	dataLen := int(binary.BigEndian.Uint16(hdr))
	if dataLen < udpgwHeaderSize || dataLen > udpgwHeaderSize+udpgwMaxPayload {
		return nil, 0, nil, fmt.Errorf("invalid udpgw data length: %d", dataLen)
	}
	frame := make([]byte, dataLen)
	if _, err := io.ReadFull(r, frame); err != nil {
		return nil, 0, nil, err
	}
	if frame[0] != udpgwAddrTypeIPv4 {
		return nil, 0, nil, fmt.Errorf("unsupported udpgw addr type: %d", frame[0])
	}
	srcIP := net.IPv4(frame[1], frame[2], frame[3], frame[4])
	srcPort := int(binary.BigEndian.Uint16(frame[5:7]))
	return srcIP, srcPort, frame[7:], nil
}

// udpgwTunnel manages a persistent SSH channel to BadVPN UDPGW on the server.
type udpgwTunnel struct {
	mu       sync.Mutex
	conn     net.Conn
	cur      func() *tunClient
	port     int
	ctx      context.Context
	cancel   context.CancelFunc
	dead     bool
	respCh   map[string]chan []byte
	respMu   sync.Mutex
}

func newUDPGWTunnel(ctx context.Context, curClient func() *tunClient, udpgwPort int) *udpgwTunnel {
	tctx, cancel := context.WithCancel(ctx)
	t := &udpgwTunnel{
		cur:    curClient,
		port:   udpgwPort,
		ctx:    tctx,
		cancel: cancel,
		respCh: make(map[string]chan []byte),
	}
	return t
}

// dial ensures the tunnel is connected, reconnecting if necessary.
func (t *udpgwTunnel) dial() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn != nil && !t.dead {
		return nil
	}

	cl := t.cur()
	if cl == nil || cl.IsDead() {
		return fmt.Errorf("ssh client unavailable")
	}

	target := fmt.Sprintf("127.0.0.1:%d", t.port)
	conn, err := cl.DialTCP(t.ctx, "tcp", target)
	if err != nil {
		return fmt.Errorf("udpgw dial: %w", err)
	}

	t.conn = conn
	t.dead = false
	go t.readLoop()
	log.Printf("[udpgw] connected to %s", target)
	return nil
}

func (t *udpgwTunnel) readLoop() {
	defer func() {
		t.mu.Lock()
		if t.conn != nil {
			t.conn.Close()
			t.conn = nil
		}
		t.dead = true
		t.mu.Unlock()
	}()

	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		srcIP, srcPort, payload, err := readUDPGWFrame(t.conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("[udpgw] read: %v", err)
			}
			return
		}

		key := fmt.Sprintf("%s:%d", srcIP.String(), srcPort)
		t.respMu.Lock()
		ch, ok := t.respCh[key]
		t.respMu.Unlock()

		if ok {
			select {
			case ch <- payload:
			default:
			}
		}
	}
}

// Send forwards a UDP datagram to the specified target.
func (t *udpgwTunnel) Send(targetIP net.IP, targetPort int, payload []byte) error {
	if err := t.dial(); err != nil {
		return err
	}

	t.mu.Lock()
	conn := t.conn
	t.mu.Unlock()

	if conn == nil {
		return fmt.Errorf("udpgw tunnel dead")
	}

	frame := packUDPGW(targetIP, targetPort, payload)
	_, err := conn.Write(frame)
	return err
}

// ResponseChan returns a channel that receives UDP responses for the given key.
func (t *udpgwTunnel) ResponseChan(key string) chan []byte {
	ch := make(chan []byte, 16)
	t.respMu.Lock()
	t.respCh[key] = ch
	t.respMu.Unlock()
	return ch
}

// ReleaseResponse removes a response channel.
func (t *udpgwTunnel) ReleaseResponse(key string) {
	t.respMu.Lock()
	delete(t.respCh, key)
	t.respMu.Unlock()
}

func (t *udpgwTunnel) Close() {
	t.cancel()
	t.mu.Lock()
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
	t.mu.Unlock()
}

const udpgwFlowTimeout = 30 * time.Second
