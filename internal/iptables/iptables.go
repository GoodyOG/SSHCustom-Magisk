// Package iptables installs and removes the SSHCustom transparent-proxy
// chains using REDIRECT (nat table) and the leak-prevention side-effects that
// make a TCP-only SSH tunnel behave correctly on modern Android ROMs
// (HyperOS 3 / MIUI / OneUI / ColorOS).
//
// # Design notes
//
// Every exec.Command call for iptables uses "-w 100" as its first two
// arguments. On Android 11+ iptables serialises access via /run/xtables.lock;
// without -w, concurrent or rapid-fire calls fail silently and rules are never
// installed. vpnchain's ssh.iptables uses "iptables -w 100" on every call for
// the same reason — this is the single most important correctness requirement.
//
// We install two chains in the nat table:
//
//   - SSHC_OUTPUT  hooked into nat OUTPUT,  for traffic from this device.
//   - SSHC_PREROUTING  hooked into nat PREROUTING per hotspot interface,
//     for traffic from tethered clients.
//
// Each chain RETURNs traffic destined to private/loopback/link-local CIDRs,
// the daemon's own bypass IPs (resolved SSH endpoint addresses), and the
// daemon's own listener ports. Anything else hits a final
// REDIRECT --to-ports <transparent_tcp_port>, which the kernel rewrites
// in-place; the daemon then reads the original destination via the
// SO_ORIGINAL_DST socket option.
//
// # DNS-through-tunnel (the real no-internet fix)
//
// We redirect device UDP:53 to our local DNS forwarder (127.0.0.1:5353),
// which proxies each query as TCP DNS through the SSH tunnel to 8.8.8.8.
// This is what makes Android's captive-portal NetworkMonitor probe succeed:
// the probe resolves its target, reaches it through the tunnel, gets a 204,
// and marks the network validated. captive_portal_mode=0 alone is NOT enough
// on HyperOS 3 / Android 16 — the OS still fires the probe. The DNS tunnel +
// captive_portal_server=localhost together make the probe hit our forwarder
// (which goes through the tunnel to a real 204 endpoint), clearing the tag
// without any disruptive data toggle. This is exactly vpnchain's approach.
//
// # Leak prevention (always applied with the redirect rules)
//
//   - QUIC (UDP/443 and UDP/80): DROPped so browsers fall back to TCP.
//     DROP not REJECT — vpnchain's own code documents that ipt_REJECT is
//     not reliably available on Android kernels.
//   - IPv6: disabled system-wide (REDIRECT is IPv4-only).
//
// # Bypass IPs
//
// The daemon passes in the resolved SSH endpoint IPs at apply time.
// Each becomes a -d <ip> RETURN rule so the SSH carrier connection itself
// is never caught by the REDIRECT and looped back.
//
// # uid-0 RETURN rule
//
// SSHC_OUTPUT skips uid 0 so the daemon's own connections (SSH tunnel,
// DNS lookups) are not redirected through themselves.
//
// # Cleanup is idempotent
//
// Apply() always runs the internal rule cleanup first; Cleanup() ignores
// errors from non-existent chains/rules.
package iptables

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config is the subset of daemon config needed to install rules.
type Config struct {
	ChainsPrefix   string
	TCPPort        int
	APIPort        int
	SocksPort      int
	DNSForwardPort int // local UDP DNS-through-tunnel forwarder port (0 = disabled)
	Hotspot        bool
	HotspotIfaces  []string
}

// DefaultPrefix is used when ChainsPrefix is empty.
const DefaultPrefix = "SSHC"

// DefaultHotspotIfaces covers Wi-Fi hotspot, MediaTek AP, USB tethering,
// CDC-NCM, and Bluetooth PAN — the tether interfaces on modern Android.
var DefaultHotspotIfaces = []string{"wlan+", "swlan+", "ap+", "rndis+", "ncm+", "bt-pan+"}

var privateCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"224.0.0.0/4",
	"240.0.0.0/4",
}

// allLegacyChains lists every chain name ever created across all SSHCustom
// versions so Cleanup() removes orphans from older installs too.
func allLegacyChains(prefix string) []string {
	return []string{
		prefix + "_OUTPUT",
		prefix + "_PREROUTING",
		prefix + "_PROXY",
		prefix + "_DNS",
		prefix + "_HOTSPOT",
		prefix + "_HOTSPOT_DNS",
	}
}

// ipt runs a single iptables command with the -w 100 lock-wait flag.
// -w 100 tells iptables to wait up to 100 seconds to acquire the xtables lock.
// Without it, concurrent calls on Android 11+ silently fail and rules are
// never installed — the single most important correctness detail in this file.
func ipt(args ...string) *exec.Cmd {
	return exec.Command("iptables", append([]string{"-w", "100"}, args...)...)
}

// Apply installs the REDIRECT chains, DNS-through-tunnel, QUIC block, IPv6
// disable, TCP tuning, and captive-portal bypass. bypassIPs are the resolved
// SSH endpoint IPs that must not be caught by the REDIRECT rule.
func Apply(cfg Config, bypassIPs []string) error {
	prefix := cfg.ChainsPrefix
	if prefix == "" {
		prefix = DefaultPrefix
	}
	port := cfg.TCPPort
	if port <= 0 {
		port = 10810
	}
	outChain := prefix + "_OUTPUT"
	preChain := prefix + "_PREROUTING"

	var errs []string
	run := func(args ...string) {
		if b, err := ipt(args...).CombinedOutput(); err != nil {
			errs = append(errs, fmt.Sprintf("iptables %s: %v %s",
				strings.Join(args, " "), err, strings.TrimSpace(string(b))))
		}
	}

	// Pre-pass: tear down any existing rules from a prior run or a crash.
	// This must not touch IPv6/captive-portal state so we don't flap them.
	cleanupRules(cfg)

	for _, ch := range []string{outChain, preChain} {
		run("-t", "nat", "-N", ch)
		run("-t", "nat", "-F", ch)
	}

	addBypasses := func(ch string, isOutput bool) {
		// uid owner match only works on OUTPUT (not on PREROUTING where no uid
		// is yet assigned to the packet).
		if isOutput {
			run("-t", "nat", "-A", ch, "-m", "owner", "--uid-owner", "0", "-j", "RETURN")
		}
		for _, cidr := range privateCIDRs {
			run("-t", "nat", "-A", ch, "-d", cidr, "-j", "RETURN")
		}
		for _, ip := range bypassIPs {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			run("-t", "nat", "-A", ch, "-d", ip, "-j", "RETURN")
		}
		// Exempt the daemon's own listener ports so it can accept connections.
		// Port 5353 is the DNS-through-tunnel forwarder — exempt it so the
		// forwarder's own TCP upstream connections are never REDIRECT-looped.
		// NOTE: Port 80 removed - it was blocking all HTTP traffic to Google/etc.
		// The localhost captive server doesn't need exemption since probes use
		// uid 0 which already has a RETURN rule.
		for _, p := range []int{cfg.APIPort, cfg.SocksPort, cfg.TCPPort, cfg.DNSForwardPort} {
			if p > 0 {
				run("-t", "nat", "-A", ch, "-p", "tcp", "--dport", strconv.Itoa(p), "-j", "RETURN")
			}
		}
		run("-t", "nat", "-A", ch, "-p", "tcp", "-j", "REDIRECT", "--to-ports", strconv.Itoa(port))
	}
	addBypasses(outChain, true)
	addBypasses(preChain, false)

	// Hook at position 1 so we run before any other module's rules.
	run("-t", "nat", "-I", "OUTPUT", "1", "-p", "tcp", "-j", outChain)

	if cfg.Hotspot {
		ifaces := cfg.HotspotIfaces
		if len(ifaces) == 0 {
			ifaces = DefaultHotspotIfaces
		}
		for _, iface := range ifaces {
			if strings.TrimSpace(iface) == "" {
				continue
			}
			run("-t", "nat", "-I", "PREROUTING", "1", "-i", iface, "-p", "tcp", "-j", preChain)
		}
		_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
		_ = ipt("-I", "FORWARD", "-j", "ACCEPT").Run()
	}

	// Leak prevention + captive-portal: best-effort, never fail Apply().
	// Order matters: DNS forward first (probe needs it), then QUIC block
	// (forces TCP), then IPv6 off, then TCP buffer tuning, then captive portal.
	setupDNSForward(prefix, cfg.DNSForwardPort)
	blockQUIC()
	disableIPv6()
	tuneTCP()
	disableCaptivePortal()

	var fatal []string
	for _, e := range errs {
		if strings.Contains(e, "No chain/target/match") ||
			strings.Contains(e, "does a matching rule exist") ||
			strings.Contains(e, "Chain already exists") {
			continue
		}
		// Log every non-fatal warning so on-device debugging doesn't require
		// reading raw iptables output. Errors here do NOT fail Apply().
		fmt.Printf("[iptables] warn: %s\n", e)
		fatal = append(fatal, e)
	}
	if len(fatal) > 0 {
		return errors.New(strings.Join(fatal, "; "))
	}
	return nil
}

// Cleanup removes all SSHC chains, re-enables IPv6, and restores captive-portal.
func Cleanup(cfg Config) error {
	cleanupRules(cfg)
	enableIPv6()
	restoreCaptivePortal()
	return nil
}

// cleanupRules tears down only the iptables state. Does NOT touch IPv6 sysctls
// or captive-portal settings — Apply() calls this as a pre-pass and must not
// flap those device-wide toggles.
func cleanupRules(cfg Config) {
	prefix := cfg.ChainsPrefix
	if prefix == "" {
		prefix = DefaultPrefix
	}
	chains := allLegacyChains(prefix)
	ifaces := cfg.HotspotIfaces
	if len(ifaces) == 0 {
		ifaces = DefaultHotspotIfaces
	}

	// Phase 1: detach all hook shapes we have ever used (handles rolling upgrades).
	for _, ch := range chains {
		_ = ipt("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", ch).Run()
		_ = ipt("-t", "nat", "-D", "OUTPUT", "-j", ch).Run()
		_ = ipt("-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", ch).Run()
		_ = ipt("-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-j", ch).Run()
		_ = ipt("-t", "nat", "-D", "PREROUTING", "-j", ch).Run()
		for _, iface := range ifaces {
			if strings.TrimSpace(iface) == "" {
				continue
			}
			_ = ipt("-t", "nat", "-D", "PREROUTING", "-i", iface, "-p", "tcp", "-j", ch).Run()
			_ = ipt("-t", "nat", "-D", "PREROUTING", "-i", iface, "-j", ch).Run()
		}
	}
	// Phase 2: flush then delete (must follow phase 1 — can't delete a
	// chain that is still referenced by a hook).
	for _, ch := range chains {
		_ = ipt("-t", "nat", "-F", ch).Run()
		_ = ipt("-t", "nat", "-X", ch).Run()
	}
	_ = ipt("-D", "FORWARD", "-j", "ACCEPT").Run()
	unblockQUIC()
}

// setupDNSForward redirects device UDP:53 to 127.0.0.1:<port> (our DNS
// forwarder) so every DNS query rides the SSH tunnel as TCP DNS to 8.8.8.8.
//
// Why this is essential: Android's NetworkMonitor fires a captive-portal probe
// even when captive_portal_mode=0 on HyperOS 3 / Android 16. The probe needs
// to resolve its target and reach a 204 endpoint. With the DNS tunnel active,
// the probe resolves through the tunnel (uid 0 bypasses the DNS redirect so
// the daemon's own dnsx still uses carrier DNS), reaches the 204 endpoint
// through the tunnel, and Android marks the network validated — no "no
// internet" tag without any data toggle. This is exactly vpnchain's design.
//
// uid 0 is excluded so the daemon's own DNS lookups go direct to carrier DNS.
//
// We always delete-then-insert (not check-then-insert) to avoid stacking
// duplicate DNAT rules if the daemon restarts or Apply() is called twice.
func setupDNSForward(prefix string, port int) {
	if port <= 0 {
		return
	}
	chain := prefix + "_DNS"
	// DNAT to loopback for locally-generated packets requires route_localnet=1.
	shRun("sysctl -w net.ipv4.conf.all.route_localnet=1 2>/dev/null || echo 1 > /proc/sys/net/ipv4/conf/all/route_localnet")
	
	// Check if chain already exists before creating (avoids error spam in logs)
	if ipt("-t", "nat", "-L", chain, "-n").Run() != nil {
		_ = ipt("-t", "nat", "-N", chain).Run()
	}
	_ = ipt("-t", "nat", "-F", chain).Run()
	
	// uid 0 (daemon + root shell) goes direct; everyone else is redirected.
	_ = ipt("-t", "nat", "-A", chain, "-m", "owner", "--uid-owner", "0", "-j", "RETURN").Run()
	_ = ipt("-t", "nat", "-A", chain, "-p", "udp", "--dport", "53",
		"-j", "DNAT", "--to-destination", fmt.Sprintf("127.0.0.1:%d", port)).Run()
	// Delete-then-insert: avoids stacking duplicate rules if Apply() is
	// called more than once (daemon restart, watchdog, etc.).
	_ = ipt("-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", chain).Run()
	_ = ipt("-t", "nat", "-I", "OUTPUT", "1", "-p", "udp", "--dport", "53", "-j", chain).Run()
}

// blockQUIC drops outbound UDP/443 and UDP/80. REDIRECT only catches TCP, so
// without this QUIC traffic escapes the tunnel entirely. DROP (not REJECT) is
// used because ipt_REJECT is not reliably available on Android kernels —
// vpnchain's own source documents this. DROP causes apps to wait for timeout
// before falling back to TCP; on a fast Android kernel this is typically 1-3s
// which is acceptable and identical to vpnchain's behaviour.
func blockQUIC() {
	for _, port := range []string{"443", "80"} {
		if ipt("-t", "filter", "-C", "OUTPUT", "-p", "udp", "--dport", port, "-j", "DROP").Run() != nil {
			_ = ipt("-t", "filter", "-A", "OUTPUT", "-p", "udp", "--dport", port, "-j", "DROP").Run()
		}
	}
}

func unblockQUIC() {
	// Remove all variants (DROP and any REJECT from prior builds).
	for _, port := range []string{"443", "80"} {
		for i := 0; i < 4; i++ {
			if ipt("-t", "filter", "-D", "OUTPUT", "-p", "udp", "--dport", port, "-j", "DROP").Run() != nil {
				break
			}
		}
		for i := 0; i < 4; i++ {
			if ipt("-t", "filter", "-D", "OUTPUT", "-p", "udp", "--dport", port, "-j", "REJECT", "--reject-with", "icmp-port-unreachable").Run() != nil {
				break
			}
		}
	}
}

// shellPATH mirrors the PATH used by vpnchain's shell scripts so that
// settings, ndc, sysctl, and ip all resolve correctly when called from the
// daemon (which is launched with a minimal nohup environment).
const shellPATH = "/system/bin:/system/xbin:/vendor/bin:/data/adb/magisk:/data/adb/ksu/bin:/data/adb/ap/bin"

// shRun executes a shell command with a full Android PATH. Best-effort.
func shRun(cmdline string) {
	_ = exec.Command("/system/bin/sh", "-c", "export PATH="+shellPATH+":$PATH; "+cmdline).Run()
}

// disableIPv6 turns off IPv6 system-wide so no traffic leaks past the
// IPv4-only REDIRECT path. Also enables ip_forward (needed for hotspot).
func disableIPv6() {
	shRun(`sysctl -w net.ipv4.ip_forward=1 2>/dev/null || echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -w net.ipv6.conf.all.disable_ipv6=1 2>/dev/null || echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sysctl -w net.ipv6.conf.default.disable_ipv6=1 2>/dev/null || echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6`)
}

func enableIPv6() {
	shRun(`sysctl -w net.ipv6.conf.all.disable_ipv6=0 2>/dev/null || echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sysctl -w net.ipv6.conf.default.disable_ipv6=0 2>/dev/null || echo 0 > /proc/sys/net/ipv6/conf/default/disable_ipv6`)
}

// disableCaptivePortal sets the captive-portal settings to use Google's real
// probe URLs that go through the SSH tunnel. This is the correct approach for
// zero bug-host networks where the probe needs to reach the actual endpoint.
//
// Strategy change from localhost to real URLs:
//   - localhost 204 server works on BUG-HOST networks (carrier injects responses)
//   - Real Google URLs work on ZERO-BUG-HOST networks (clean carrier, no injection)
//   - The probe goes through the tunnel → reaches real Google → gets 204 → validated
//
// We use connectivitycheck.gstatic.com for HTTP and www.google.com for HTTPS
// because these are Android's default probe targets. The DNS tunnel ensures
// these domains resolve correctly, and the transparent proxy rules catch the
// probe traffic and route it through the SSH tunnel.
//
// captive_portal_mode=0 disables the captive portal LOGIN page but does NOT
// disable the validation probe itself. captive_portal_detection_enabled=0
// would fully disable probes but we want them to succeed through the tunnel.
//
// A non-disruptive reevaluate is fired once per session as a safety net in
// case Android already cached a stale "no internet" verdict before this ran.
func disableCaptivePortal() {
	shRun(`settings put global captive_portal_mode 0
settings put global captive_portal_use_https 0
settings delete global captive_portal_server 2>/dev/null || true
settings put global captive_portal_http_url "http://connectivitycheck.gstatic.com/generate_204"
settings put global captive_portal_https_url "https://www.google.com/generate_204"
ndc resolver clearnetdns 2>/dev/null || true`)
	kickRevalidation()
}

func restoreCaptivePortal() {
	resetRevalidation()
	shRun(`settings put global captive_portal_mode 1
settings put global captive_portal_use_https 1
settings delete global captive_portal_server 2>/dev/null || true
settings delete global captive_portal_http_url 2>/dev/null || true
settings delete global captive_portal_https_url 2>/dev/null || true`)
}

var (
	revalidateMu   sync.Mutex
	revalidateDone bool
)

// kickRevalidation fires "cmd connectivity reevaluate <netId>" once per
// tunnel session to clear any stale "no internet" verdict that Android
// cached before the DNS tunnel and captive-portal settings took effect.
// Non-disruptive: does NOT toggle mobile data or drop the SSH carrier.
// Runs at most once per session; re-arms on Cleanup().
//
// Updated strategy: Use Android's built-in reevaluate command which triggers
// a fresh NetworkMonitor probe WITHOUT toggling radio or disconnecting. This
// is much cleaner than the old data toggle approach and doesn't cause the
// brief connectivity loss that users find annoying.
func kickRevalidation() {
	revalidateMu.Lock()
	already := revalidateDone
	revalidateDone = true
	revalidateMu.Unlock()
	if already {
		return
	}
	go func() {
		// 5s delay: let iptables rules, settings, and DNS forwarder fully stabilize
		// so the probe has the best chance of succeeding on first attempt.
		time.Sleep(5 * time.Second)
		
		// Try multiple methods in order of preference:
		// 1. Specific network ID (most reliable)
		// 2. All networks (fallback for older Android)
		// 3. Broadcast intent (last resort)
		shRun(`NETID=$(dumpsys connectivity 2>/dev/null | grep -oE "network=[0-9]+" | tail -1 | cut -d= -f2)
if [ -n "$NETID" ]; then
  cmd connectivity reevaluate "$NETID" 2>/dev/null || \
  cmd connectivity reevaluate 2>/dev/null || \
  am broadcast -a android.net.conn.CONNECTIVITY_CHANGE 2>/dev/null
else
  cmd connectivity reevaluate 2>/dev/null || \
  am broadcast -a android.net.conn.CONNECTIVITY_CHANGE 2>/dev/null
fi`)
	}()
}

func resetRevalidation() {
	revalidateMu.Lock()
	revalidateDone = false
	revalidateMu.Unlock()
}

// tuneTCP raises kernel TCP socket-buffer ceilings so the single tunnel socket
// can reach full throughput on high-latency mobile links (measured 382 KB/s →
// 3.3 MB/s on a Poco F6 / 5G / 153ms RTT). Called from Apply() so the buffers
// are set before any proxied connection opens its first socket. Note: the SSH
// carrier socket itself was already created before Apply() runs, but new
// sockets (proxied app connections) benefit immediately. For the carrier socket
// itself, see the speed_boost call in sshcustom.sh which runs BEFORE the daemon
// starts. The larger ceilings are harmless (the kernel auto-tunes within them).
func tuneTCP() {
	shRun(`sysctl -w net.core.rmem_max=67108864 2>/dev/null || echo 67108864 > /proc/sys/net/core/rmem_max
sysctl -w net.core.wmem_max=67108864 2>/dev/null || echo 67108864 > /proc/sys/net/core/wmem_max
sysctl -w net.ipv4.tcp_rmem="4096 87380 67108864" 2>/dev/null || echo "4096 87380 67108864" > /proc/sys/net/ipv4/tcp_rmem
sysctl -w net.ipv4.tcp_wmem="4096 65536 67108864" 2>/dev/null || echo "4096 65536 67108864" > /proc/sys/net/ipv4/tcp_wmem`)
}
