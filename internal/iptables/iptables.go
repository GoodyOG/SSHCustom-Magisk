// Package iptables installs and removes the SSHCustom transparent-proxy rules
// using TPROXY in the mangle table.
//
// # Why TPROXY instead of REDIRECT
//
// REDIRECT (nat table) does not work on modern Android ROMs (HyperOS 3, newer
// MIUI, OneUI 6+, ColorOS 14+) because these ROMs use UID-based fwmark policy
// routing that bypasses the nat OUTPUT chain entirely. App traffic never hits
// our REDIRECT rule.
//
// TPROXY (mangle table) works because mangle OUTPUT fires BEFORE policy routing
// decisions. We mark packets in mangle OUTPUT → kernel re-routes them via our
// custom ip rule/table → packets arrive at lo → re-enter PREROUTING → TPROXY
// intercepts them and delivers to our listener with the original destination
// preserved.
//
// # How it works
//
// 1. ip route add local default dev lo table 100
// 2. ip rule add fwmark 0x1 table 100 pref 100
// 3. mangle PREROUTING: -p tcp -m socket --transparent -j MARK --set-mark 0x1 (DIVERT fast-path)
// 4. mangle PREROUTING: -p tcp -j TPROXY --on-port 10810 --tproxy-mark 0x1
// 5. mangle OUTPUT: bypass uid-0, bypass private CIDRs, bypass SSH endpoint IPs
// 6. mangle OUTPUT: -p tcp -j MARK --set-mark 0x1 (triggers re-route to lo)
//
// The Go listener uses IP_TRANSPARENT socket option to accept connections
// destined for arbitrary IPs. conn.LocalAddr() gives the original destination.
package iptables

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Config is the subset of daemon config needed to install rules.
type Config struct {
	ChainsPrefix  string
	TCPPort       int
	APIPort       int
	SocksPort     int
	DNSPort       int
	Hotspot       bool
	HotspotDNS    bool
	HotspotIfaces []string
}

// Default chain prefix when none is configured.
const DefaultPrefix = "SSHC"

// TPROXY routing constants
const (
	tproxyMark  = "0x1/0x1" // fwmark for marked packets
	tproxyTable = "100"     // custom routing table ID
	tproxyPref  = "100"     // ip rule preference (priority)
)

// Default hotspot interface globs covering most modern Android tether modes.
var DefaultHotspotIfaces = []string{"wlan+", "swlan+", "ap+", "rndis+", "ncm+", "bt-pan+"}

// privateCIDRs is the set of address ranges we always bypass.
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

// run executes an iptables command with -w 5 (wait for lock) and retry logic.
func run(args ...string) error {
	fullArgs := append([]string{"-w", "5"}, args...)
	var lastErr error
	var lastOut []byte
	for attempt := 0; attempt < 3; attempt++ {
		b, err := exec.Command("iptables", fullArgs...).CombinedOutput()
		if err == nil {
			return nil
		}
		lastErr = err
		lastOut = b
		if !strings.Contains(string(b), "xtables.lock") {
			break
		}
		time.Sleep(time.Duration(attempt+1) * time.Second)
	}
	return fmt.Errorf("iptables %s: %v %s", strings.Join(args, " "), lastErr, strings.TrimSpace(string(lastOut)))
}

// runIgnore executes an iptables command, ignoring errors (for cleanup).
func runIgnore(args ...string) {
	fullArgs := append([]string{"-w", "5"}, args...)
	_ = exec.Command("iptables", fullArgs...).Run()
}

// run6 executes an ip6tables command with -w 5 (wait for lock) and retry logic.
func run6(args ...string) error {
	fullArgs := append([]string{"-w", "5"}, args...)
	var lastErr error
	var lastOut []byte
	for attempt := 0; attempt < 3; attempt++ {
		b, err := exec.Command("ip6tables", fullArgs...).CombinedOutput()
		if err == nil {
			return nil
		}
		lastErr = err
		lastOut = b
		if !strings.Contains(string(b), "xtables.lock") {
			break
		}
		time.Sleep(time.Duration(attempt+1) * time.Second)
	}
	return fmt.Errorf("ip6tables %s: %v %s", strings.Join(args, " "), lastErr, strings.TrimSpace(string(lastOut)))
}

// run6Ignore executes an ip6tables command, ignoring errors (for cleanup).
func run6Ignore(args ...string) {
	fullArgs := append([]string{"-w", "5"}, args...)
	_ = exec.Command("ip6tables", fullArgs...).Run()
}

// ipCmd executes an ip command.
func ipCmd(args ...string) error {
	b, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %v %s", strings.Join(args, " "), err, strings.TrimSpace(string(b)))
	}
	return nil
}

// Apply installs TPROXY rules in the mangle table with ip rule/route for
// policy routing. bypassIPs are the SSH endpoint IPs that must not be proxied.
func Apply(cfg Config, bypassIPs []string) error {
	prefix := cfg.ChainsPrefix
	if prefix == "" {
		prefix = DefaultPrefix
	}
	port := cfg.TCPPort
	if port <= 0 {
		port = 10810
	}
	portStr := strconv.Itoa(port)

	// Chain names
	divertChain := prefix + "_DIVERT"
	preChain := prefix + "_PREROUTING"
	outChain := prefix + "_OUTPUT"

	// Always clean first
	_ = Cleanup(cfg)

	var errs []string
	must := func(err error) {
		if err != nil {
			errs = append(errs, err.Error())
		}
	}

	// Step 1: Policy routing - route marked packets to loopback
	must(ipCmd("route", "add", "local", "default", "dev", "lo", "table", tproxyTable))
	must(ipCmd("rule", "add", "fwmark", tproxyMark, "table", tproxyTable, "pref", tproxyPref))

	// Step 2: Enable IP forwarding (needed for hotspot/PREROUTING)
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

	// Step 3: Create chains
	for _, ch := range []string{divertChain, preChain, outChain} {
		must(run("-t", "mangle", "-N", ch))
	}

	// Step 4: DIVERT chain - fast-path for established connections
	// Packets that already have a transparent socket get marked and accepted
	// without traversing the full TPROXY rule again.
	must(run("-t", "mangle", "-A", divertChain, "-j", "MARK", "--set-mark", tproxyMark))
	must(run("-t", "mangle", "-A", divertChain, "-j", "ACCEPT"))

	// Step 5: PREROUTING chain
	// 5a: Established transparent connections → DIVERT (fast-path)
	must(run("-t", "mangle", "-A", preChain, "-p", "tcp", "-m", "socket", "--transparent", "-j", divertChain))
	// 5b: Bypass private/local destinations
	for _, cidr := range privateCIDRs {
		must(run("-t", "mangle", "-A", preChain, "-d", cidr, "-j", "RETURN"))
	}
	// 5c: Bypass SSH endpoint IPs
	for _, ip := range bypassIPs {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			must(run("-t", "mangle", "-A", preChain, "-d", ip, "-j", "RETURN"))
		}
	}
	// 5d: Bypass our own ports
	for _, p := range []int{cfg.APIPort, cfg.SocksPort, cfg.TCPPort} {
		if p > 0 {
			must(run("-t", "mangle", "-A", preChain, "-p", "tcp", "--dport", strconv.Itoa(p), "-j", "RETURN"))
		}
	}
	// 5e: TPROXY all remaining TCP
	must(run("-t", "mangle", "-A", preChain, "-p", "tcp", "-j", "TPROXY",
		"--on-port", portStr, "--tproxy-mark", tproxyMark))

	// Step 6: OUTPUT chain (local device traffic)
	// 6a: Bypass daemon's own traffic (uid 0 = root, where sshcustomd runs)
	must(run("-t", "mangle", "-A", outChain, "-m", "owner", "--uid-owner", "0", "-j", "RETURN"))
	// 6b: Bypass private/local destinations
	for _, cidr := range privateCIDRs {
		must(run("-t", "mangle", "-A", outChain, "-d", cidr, "-j", "RETURN"))
	}
	// 6c: Bypass SSH endpoint IPs
	for _, ip := range bypassIPs {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			must(run("-t", "mangle", "-A", outChain, "-d", ip, "-j", "RETURN"))
		}
	}
	// 6d: Bypass our own ports
	for _, p := range []int{cfg.APIPort, cfg.SocksPort, cfg.TCPPort} {
		if p > 0 {
			must(run("-t", "mangle", "-A", outChain, "-p", "tcp", "--dport", strconv.Itoa(p), "-j", "RETURN"))
		}
	}
	// 6e: MARK all remaining TCP → triggers re-route via ip rule → enters PREROUTING → TPROXY
	must(run("-t", "mangle", "-A", outChain, "-p", "tcp", "-j", "MARK", "--set-mark", tproxyMark))

	// Step 7: Hook chains into PREROUTING and OUTPUT
	must(run("-t", "mangle", "-I", "PREROUTING", "1", "-j", preChain))
	must(run("-t", "mangle", "-I", "OUTPUT", "1", "-j", outChain))

	// Step 8: Hotspot - hook PREROUTING for tethered interfaces too
	if cfg.Hotspot {
		ifaces := cfg.HotspotIfaces
		if len(ifaces) == 0 {
			ifaces = DefaultHotspotIfaces
		}
		for _, iface := range ifaces {
			if strings.TrimSpace(iface) != "" {
				// Already covered by the global PREROUTING jump above
				// But ensure FORWARD accepts for tethered traffic
				runIgnore("-I", "FORWARD", "-i", iface, "-j", "ACCEPT")
				runIgnore("-I", "FORWARD", "-o", iface, "-j", "ACCEPT")
			}
		}
		runIgnore("-I", "FORWARD", "-j", "ACCEPT")
	}

	// Step 9: IPv6 blocking - force apps to use IPv4 (Happy Eyeballs fallback)
	v6block := prefix + "_V6BLOCK"
	run6Ignore("-t", "mangle", "-D", "OUTPUT", "-j", v6block)
	run6Ignore("-t", "mangle", "-F", v6block)
	run6Ignore("-t", "mangle", "-X", v6block)
	must(run6("-t", "mangle", "-N", v6block))
	must(run6("-t", "mangle", "-A", v6block, "-o", "lo", "-j", "RETURN"))
	must(run6("-t", "mangle", "-A", v6block, "-d", "::1/128", "-j", "RETURN"))
	must(run6("-t", "mangle", "-A", v6block, "-d", "fe80::/10", "-j", "RETURN"))
	must(run6("-t", "mangle", "-A", v6block, "-m", "owner", "--uid-owner", "0", "-j", "RETURN"))
	must(run6("-t", "mangle", "-A", v6block, "-p", "tcp", "-j", "DROP"))
	must(run6("-t", "mangle", "-A", v6block, "-p", "udp", "-j", "DROP"))
	must(run6("-t", "mangle", "-I", "OUTPUT", "1", "-j", v6block))

	// Step 10: DNS redirect - intercept port 53 and redirect to local DNS forwarder
	if cfg.DNSPort > 0 {
		dnsChain := prefix + "_DNS"
		dnsPortStr := strconv.Itoa(cfg.DNSPort)
		// Clean any leftover DNS chain first
		runIgnore("-t", "nat", "-D", "OUTPUT", "-j", dnsChain)
		runIgnore("-t", "nat", "-F", dnsChain)
		runIgnore("-t", "nat", "-X", dnsChain)
		must(run("-t", "nat", "-N", dnsChain))
		must(run("-t", "nat", "-A", dnsChain, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", dnsPortStr))
		must(run("-t", "nat", "-A", dnsChain, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", dnsPortStr))
		must(run("-t", "nat", "-I", "OUTPUT", "1", "-j", dnsChain))

		// Hotspot DNS sharing
		if cfg.HotspotDNS {
			ifaces := cfg.HotspotIfaces
			if len(ifaces) == 0 {
				ifaces = DefaultHotspotIfaces
			}
			for _, iface := range ifaces {
				if strings.TrimSpace(iface) != "" {
					must(run("-t", "nat", "-I", "PREROUTING", "1", "-i", iface, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", dnsPortStr))
					must(run("-t", "nat", "-I", "PREROUTING", "1", "-i", iface, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", dnsPortStr))
				}
			}
		}
	}

	// Filter fatal errors
	var fatal []string
	for _, e := range errs {
		// Ignore "already exists" errors from ip rule/route (idempotent)
		if strings.Contains(e, "File exists") ||
			strings.Contains(e, "No chain/target/match") ||
			strings.Contains(e, "Chain already exists") {
			continue
		}
		fatal = append(fatal, e)
	}
	if len(fatal) > 0 {
		log.Printf("tproxy apply had %d errors (first: %s)", len(fatal), fatal[0])
		return errors.New(strings.Join(fatal, "; "))
	}
	return nil
}

// Cleanup removes all SSHCustom TPROXY rules, chains, ip rules, and ip routes.
func Cleanup(cfg Config) error {
	prefix := cfg.ChainsPrefix
	if prefix == "" {
		prefix = DefaultPrefix
	}

	divertChain := prefix + "_DIVERT"
	preChain := prefix + "_PREROUTING"
	outChain := prefix + "_OUTPUT"

	// Also clean legacy nat-based chains from older versions
	legacyChains := []string{
		prefix + "_OUTPUT",
		prefix + "_PREROUTING",
		prefix + "_PROXY",
		prefix + "_DNS",
		prefix + "_HOTSPOT",
		prefix + "_HOTSPOT_DNS",
	}

	// Phase 1: Remove jumps from built-in chains (mangle)
	runIgnore("-t", "mangle", "-D", "PREROUTING", "-j", preChain)
	runIgnore("-t", "mangle", "-D", "OUTPUT", "-j", outChain)

	// Phase 2: Flush and delete mangle chains
	for _, ch := range []string{divertChain, preChain, outChain} {
		runIgnore("-t", "mangle", "-F", ch)
		runIgnore("-t", "mangle", "-X", ch)
	}

	// Phase 3: Clean legacy nat chains
	for _, ch := range legacyChains {
		runIgnore("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", ch)
		runIgnore("-t", "nat", "-D", "OUTPUT", "-j", ch)
		runIgnore("-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-j", ch)
		runIgnore("-t", "nat", "-D", "PREROUTING", "-j", ch)
		ifaces := cfg.HotspotIfaces
		if len(ifaces) == 0 {
			ifaces = DefaultHotspotIfaces
		}
		for _, iface := range ifaces {
			if strings.TrimSpace(iface) != "" {
				runIgnore("-t", "nat", "-D", "PREROUTING", "-i", iface, "-p", "tcp", "-j", ch)
			}
		}
		runIgnore("-t", "nat", "-F", ch)
		runIgnore("-t", "nat", "-X", ch)
	}

	// Phase 4: Remove ip rule and ip route
	_ = exec.Command("ip", "rule", "del", "fwmark", tproxyMark, "table", tproxyTable, "pref", tproxyPref).Run()
	_ = exec.Command("ip", "route", "del", "local", "default", "dev", "lo", "table", tproxyTable).Run()

	// Phase 5: Remove FORWARD rules
	runIgnore("-D", "FORWARD", "-j", "ACCEPT")
	ifaces := cfg.HotspotIfaces
	if len(ifaces) == 0 {
		ifaces = DefaultHotspotIfaces
	}
	for _, iface := range ifaces {
		if strings.TrimSpace(iface) != "" {
			runIgnore("-D", "FORWARD", "-i", iface, "-j", "ACCEPT")
			runIgnore("-D", "FORWARD", "-o", iface, "-j", "ACCEPT")
		}
	}

	// Phase 6: Remove IPv6 V6BLOCK chain
	v6block := prefix + "_V6BLOCK"
	run6Ignore("-t", "mangle", "-D", "OUTPUT", "-j", v6block)
	run6Ignore("-t", "mangle", "-F", v6block)
	run6Ignore("-t", "mangle", "-X", v6block)

	// Phase 7: Remove DNS nat chain and hotspot PREROUTING rules
	dnsChain := prefix + "_DNS"
	runIgnore("-t", "nat", "-D", "OUTPUT", "-j", dnsChain)
	runIgnore("-t", "nat", "-F", dnsChain)
	runIgnore("-t", "nat", "-X", dnsChain)
	// Remove hotspot DNS PREROUTING rules (all possible ports)
	for _, iface := range ifaces {
		if strings.TrimSpace(iface) != "" {
			runIgnore("-t", "nat", "-D", "PREROUTING", "-i", iface, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "10811")
			runIgnore("-t", "nat", "-D", "PREROUTING", "-i", iface, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", "10811")
		}
	}

	return nil
}
