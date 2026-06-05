package main

// engine.go — the lean single-connection SSH engine, ported from
// sshcustom-vpnchain. One SSH connection carries every proxied stream via
// on-demand direct-tcpip channels (RFC 4254 multiplexing). Local listeners
// (SOCKS5, transparent REDIRECT, DNS-through-tunnel) and the iptables rules
// are brought up ONCE on first connect and KEPT UP across transparent SSH
// reconnects — a brief SSH drop stalls apps ~1s with no traffic leak
// (fail-closed), exactly like a VpnService whose tun stays up.
//
// This replaces the old multi-connection SSHPool: no pool, no per-connection
// snapshot bookkeeping, no retained buffer pool. That is what keeps idle RAM
// near ~13 MB and working RAM ~30–40 MB.

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"

	xssh "golang.org/x/crypto/ssh"
)

// dnsForwardPort is the loopback UDP port the DNS-through-tunnel forwarder
// listens on. iptables redirects device UDP:53 here (skipping uid 0). Matches
// vpnchain's fixed 5353.
const dnsForwardPort = 5353

// dnsUpstream is the DNS server queried (as TCP) through the SSH tunnel.
const dnsUpstream = "8.8.8.8:53"

// tunClient wraps a single authenticated SSH client with an in-flight
// connection counter and a keepalive goroutine that detects a dead carrier
// link (so Wait() returns promptly and the loop reconnects).
type tunClient struct {
	ssh    *xssh.Client
	ctx    context.Context
	cancel context.CancelFunc
	active int32
}

func newTunClient(parent context.Context, sc *xssh.Client, keepaliveSec int) *tunClient {
	ctx, cancel := context.WithCancel(parent)
	c := &tunClient{ssh: sc, ctx: ctx, cancel: cancel}
	go c.keepAlive(keepaliveSec)
	return c
}

// keepAlive sends SSH keepalives and force-closes the connection after a few
// consecutive misses, which makes Wait() return and triggers a reconnect.
func (c *tunClient) keepAlive(sec int) {
	if sec <= 0 {
		sec = 15
	}
	t := time.NewTicker(time.Duration(sec) * time.Second)
	defer t.Stop()
	missed := 0
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			_, _, err := c.ssh.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				missed++
				if missed >= 3 {
					_ = c.ssh.Close()
					return
				}
			} else {
				missed = 0
			}
		}
	}
}

// DialTCP opens an on-demand direct-tcpip channel to addr through the SSH
// server. The server resolves hostnames, so addr may be host:port or ip:port.
func (c *tunClient) DialTCP(ctx context.Context, network, addr string) (net.Conn, error) {
	return c.ssh.DialContext(ctx, network, addr)
}

func (c *tunClient) add()        { atomic.AddInt32(&c.active, 1) }
func (c *tunClient) remove()     { atomic.AddInt32(&c.active, -1) }
func (c *tunClient) Active() int { return int(atomic.LoadInt32(&c.active)) }
func (c *tunClient) Close()      { c.cancel(); _ = c.ssh.Close() }
func (c *tunClient) Wait() error { return c.ssh.Wait() }

// tunnelLoop is the connection manager: connect → bring listeners + iptables
// up once → wait for the client to die → reconnect (keeping routing up).
func tunnelLoop(ctx context.Context, getCfg func() Config, sp Profile, st *State, clientPtr *atomic.Pointer[tunClient]) {
	const (
		baseDelay = 1 * time.Second
		maxDelay  = 30 * time.Second
	)
	curClient := func() *tunClient { return clientPtr.Load() }

	var (
		listenerCancel context.CancelFunc
		iptablesUp     bool
	)
	teardown := func() {
		if listenerCancel != nil {
			listenerCancel()
			listenerCancel = nil
		}
		if iptablesUp {
			_ = cleanupTransparentRules(getCfg())
			iptablesUp = false
		}
		clientPtr.Store(nil)
	}
	defer teardown()

	var delay time.Duration
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}

		cfg := getCfg()
		ri := routeInfo()
		st.set(func() {
			st.NetworkOnline = ri.Online
			st.DefaultRoute = ri.Raw
			st.Interface = ri.Iface
			st.Gateway = ri.Gw
			st.SourceIP = ri.Src
		})
		if !ri.Online {
			st.set(func() {
				st.State = "PAUSED_NO_NETWORK"
				st.Connected = false
				st.SSHAuthenticated = false
				st.TransportReady = false
				st.PoolHealthy = 0
				st.LastEvent = "network offline; reconnect paused"
			})
			delay = 5 * time.Second
			continue
		}

		st.set(func() {
			st.State = "CONNECTING_SSH"
			st.LastEvent = "opening transport and authenticating SSH"
			st.LastError = ""
		})
		log.Printf("[tunnel] connecting %s:%d mode=%s", sp.SSH.Host, sp.SSH.Port, sp.Transport.Mode)

		client, res, err := attemptSSHAuth(ctx, cfg, sp)
		if err != nil {
			st.set(func() {
				st.State = "RETRY_BACKOFF"
				st.Connected = false
				st.SSHAuthenticated = false
				st.TransportReady = false
				st.PoolHealthy = 0
				st.LastError = err.Error()
				st.LastEvent = "SSH auth failed; retrying"
				st.RemoteBanner = res.Banner
				st.HTTPStatuses = res.Statuses
				st.ResolvedDial = res.ResolvedDial
				st.ResolverMethod = res.ResolverMethod
				st.ResolvedIPs = res.ResolvedIPs
			})
			log.Printf("[tunnel] connect failed: %v", err)
			// Keep routing rules up indefinitely while reconnecting — tearing
			// them down would silently expose traffic to the raw carrier.
			// A user who loses signal for >15 min should stay fail-closed, not
			// suddenly have unprotected traffic. Rules are only cleaned on an
			// explicit stop/shutdown.
			delay = nextDelay(delay, baseDelay, maxDelay)
			continue
		}

		delay = baseDelay
		keepaliveSec := secondsDefault(cfg.Performance.KeepAliveSec, 15)
		tc := newTunClient(ctx, client, keepaliveSec)
		clientPtr.Store(tc)
		st.set(func() {
			st.State = "CONNECTED"
			st.Connected = true
			st.SSHAuthenticated = true
			st.TransportReady = true
			st.LastError = ""
			st.LastEvent = "SSH connected; SOCKS5 + transparent TCP + DNS-through-tunnel active"
			st.RemoteBanner = res.Banner
			st.HTTPStatuses = res.Statuses
			st.ResolvedDial = res.ResolvedDial
			st.ResolverMethod = res.ResolverMethod
			st.ResolvedIPs = res.ResolvedIPs
			st.PoolSize = 1
			st.PoolHealthy = 1
			st.PoolReconnecting = 0
			st.PoolStreams = 0
		})
		log.Printf("[tunnel] connected: banner=%q statuses=%v", res.Banner, res.Statuses)

		// Bring listeners + iptables up exactly once. They keep running and
		// pick up the new client (via curClient) across reconnects.
		if listenerCancel == nil {
			lctx, lcancel := context.WithCancel(ctx)
			listenerCancel = lcancel
			startListeners(lctx, cfg, curClient, st)
			time.Sleep(150 * time.Millisecond)
			if cfg.TransparentProxy.Enabled {
				if err := applyTransparentRules(cfg, res.ResolvedIPs); err != nil {
					log.Printf("[tunnel] iptables apply failed: %v", err)
					st.set(func() {
						st.TransparentApplied = false
						st.LastError = "iptables apply failed: " + err.Error()
					})
				} else {
					iptablesUp = true
					st.set(func() {
						st.TransparentApplied = true
						st.HotspotRunning = cfg.Hotspot.Enabled && cfg.Hotspot.TCP
					})
				}
			}
		}

		// Wait for this client to die, refreshing live stats meanwhile.
		healthTicker := time.NewTicker(2 * time.Second)
		waitDone := make(chan error, 1)
		go func() { waitDone <- tc.Wait() }()
	wait:
		for {
			select {
			case <-ctx.Done():
				healthTicker.Stop()
				tc.Close()
				clientPtr.Store(nil)
				return
			case <-waitDone:
				break wait
			case <-healthTicker.C:
				ri := routeInfo()
				streams := tc.Active()
				st.set(func() {
					st.PoolStreams = streams
					st.NetworkOnline = ri.Online
					st.DefaultRoute = ri.Raw
					st.Interface = ri.Iface
					st.Gateway = ri.Gw
					st.SourceIP = ri.Src
				})
			}
		}
		healthTicker.Stop()

		tc.Close()
		clientPtr.Store(nil)
		st.set(func() {
			st.State = "RECONNECTING"
			st.Connected = false
			st.SSHAuthenticated = false
			st.TransportReady = false
			st.PoolHealthy = 0
			st.PoolReconnecting = 1
			st.PoolStreams = 0
			st.LastEvent = "SSH connection lost; reconnecting (routing kept up)"
		})
		log.Printf("[tunnel] connection lost — reconnecting (routing kept up)")
		delay = baseDelay
	}
}

func nextDelay(cur, base, max time.Duration) time.Duration {
	if cur <= 0 {
		return base
	}
	cur *= 2
	if cur > max {
		return max
	}
	return cur
}

// startListeners brings up SOCKS5 + transparent (REDIRECT) + DNS forwarder,
// all bound to the CURRENT SSH client via curClient so they survive reconnects.
func startListeners(ctx context.Context, cfg Config, curClient func() *tunClient, st *State) {
	if cfg.LocalProxy.SocksEnabled {
		go serveSOCKS(ctx, cfg, curClient, st)
	}
	if cfg.TransparentProxy.Enabled {
		go serveTransparent(ctx, cfg, curClient, st)
	}
	// DNS-through-tunnel: iptables redirects device UDP:53 → 127.0.0.1:5353,
	// where we proxy each query as TCP DNS through the SSH tunnel. This is what
	// fixes "no internet" in Chrome/YouTube on bug-host networks.
	go func() {
		if err := dnsForwardLoop(ctx, fmt.Sprintf("127.0.0.1:%d", dnsForwardPort), dnsUpstream, curClient); err != nil {
			log.Printf("[dns-forward] %v", err)
		}
	}()
}

func serveSOCKS(ctx context.Context, cfg Config, curClient func() *tunClient, st *State) {
	addr := socksAddr(cfg)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[socks5] listen %s: %v", addr, err)
		st.set(func() { st.SocksRunning = false; st.LastError = "SOCKS5 listen failed: " + err.Error() })
		return
	}
	st.set(func() { st.SocksRunning = true; st.SocksAddr = addr })
	log.Printf("[socks5] listening on %s", addr)
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				st.set(func() { st.SocksRunning = false })
				return
			default:
				st.set(func() { st.SocksRunning = false })
				return
			}
		}
		go handleSOCKSClient(ctx, c, cfg, curClient)
	}
}

func handleSOCKSClient(ctx context.Context, c net.Conn, cfg Config, curClient func() *tunClient) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	target, err := socks5Handshake(c)
	if err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	tuneTCPConn(c, cfg, false)
	cl := curClient()
	if cl == nil {
		_ = socks5Reply(c, 0x04) // host unreachable (reconnecting; fail-closed)
		return
	}
	remote, err := cl.DialTCP(ctx, "tcp", target)
	if err != nil {
		logTunnelOpenError("[socks5]", target, err)
		_ = socks5Reply(c, 0x05)
		return
	}
	defer remote.Close()
	cl.add()
	defer cl.remove()
	_ = socks5Reply(c, 0x00)
	bufSize := cfg.Performance.BufferSize
	if bufSize <= 0 {
		bufSize = 128 * 1024
	}
	pipeBoth(c, remote, bufSize, streamIdleTimeout(cfg))
}

func serveTransparent(ctx context.Context, cfg Config, curClient func() *tunClient, st *State) {
	addr := transparentAddr(cfg)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[transparent] listen %s: %v", addr, err)
		st.set(func() { st.TransparentRunning = false; st.LastError = "transparent listen failed: " + err.Error() })
		return
	}
	st.set(func() { st.TransparentRunning = true; st.TransparentAddr = addr })
	log.Printf("[transparent] listening on %s", addr)
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			st.set(func() { st.TransparentRunning = false })
			return
		}
		go handleTransparentClient(ctx, c, cfg, curClient)
	}
}

func handleTransparentClient(ctx context.Context, c net.Conn, cfg Config, curClient func() *tunClient) {
	defer c.Close()
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	target, err := originalDst(tcp)
	if err != nil {
		return
	}
	if isLocalOrBlockedTarget(target, cfg) {
		return
	}
	tuneTCPConn(c, cfg, false)
	cl := curClient()
	if cl == nil {
		return // reconnecting — drop (fail-closed)
	}
	remote, err := cl.DialTCP(ctx, "tcp", target)
	if err != nil {
		logTunnelOpenError("[transparent]", target, err)
		return
	}
	defer remote.Close()
	cl.add()
	defer cl.remove()
	bufSize := cfg.Performance.BufferSize
	if bufSize <= 0 {
		bufSize = 128 * 1024
	}
	pipeBoth(c, remote, bufSize, streamIdleTimeout(cfg))
}

// dnsForwardLoop runs a UDP listener that proxies DNS queries as TCP DNS
// (RFC 1035 §4.2.2: 2-byte length prefix + payload) through the SSH tunnel.
func dnsForwardLoop(ctx context.Context, listenAddr, upstream string, curClient func() *tunClient) error {
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("resolve udp: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	log.Printf("[dns-forward] listening on %s, upstream=%s (via SSH)", listenAddr, upstream)
	go func() { <-ctx.Done(); _ = conn.Close() }()
	defer conn.Close()

	buf := make([]byte, 1500)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return fmt.Errorf("read udp: %w", err)
		}
		if n < 12 {
			continue
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go forwardOneDNSQuery(ctx, conn, src, query, upstream, curClient)
	}
}

func forwardOneDNSQuery(ctx context.Context, listener *net.UDPConn, src *net.UDPAddr, query []byte, upstream string, curClient func() *tunClient) {
	c := curClient()
	// If the tunnel is momentarily reconnecting, wait up to 2s before giving
	// up. The resolver will retry in ~5s, but a brief wait avoids dropping
	// queries that arrive right at the reconnect boundary.
	if c == nil {
		for i := 0; i < 4 && c == nil; i++ {
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
			c = curClient()
		}
	}
	if c == nil {
		return // tunnel still down — drop; resolver will retry
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tcp, err := c.DialTCP(dialCtx, "tcp", upstream)
	if err != nil {
		return
	}
	defer tcp.Close()
	_ = tcp.SetDeadline(time.Now().Add(5 * time.Second))

	// RFC 1035 §4.2.2: TCP DNS is a 2-byte length prefix + payload
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	if _, err := tcp.Write(frame); err != nil {
		return
	}
	var lenHdr [2]byte
	if _, err := io.ReadFull(tcp, lenHdr[:]); err != nil {
		return
	}
	respLen := int(binary.BigEndian.Uint16(lenHdr[:]))
	// Sanity check: DNS messages must be between 12 bytes (header only) and 65535
	if respLen < 12 || respLen > 65535 {
		return
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(tcp, resp); err != nil {
		return
	}
	_, _ = listener.WriteToUDP(resp, src)
}

// measureLatency opens a TCP connection to target through the SSH tunnel and
// returns the connect time in milliseconds. Used by the Home "latency" card.
func measureLatency(ctx context.Context, cl *tunClient, target string) (int64, error) {
	if cl == nil {
		return 0, fmt.Errorf("tunnel not connected")
	}
	dialCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := cl.DialTCP(dialCtx, "tcp", target)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return time.Since(start).Milliseconds(), nil
}
