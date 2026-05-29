package main

import (
	"reflect"
	"testing"
)

// Smoke tests for the pure functions that still live in package main. Once
// the connection-manager / SSHPool / transport layer gets pulled into its
// own package these will move alongside it. Until then, this file at least
// fences in the most-touched helpers against accidental regressions.

func TestNormalizeMode(t *testing.T) {
	cases := map[string]string{
		"":                    "",
		"   ":                 "",
		"direct":              "direct",
		"  Direct  ":          "direct",
		"ssh":                 "direct",
		"ssh+pl":              "direct",
		"http_proxy":          "http_proxy",
		"ssh+http":            "http_proxy",
		"ssh+pl+http":         "http_proxy",
		"tls_sni":             "tls_sni",
		"sni":                 "tls_sni",
		"ssh+sni":             "tls_sni",
		"http_proxy_tls_sni":  "http_proxy_tls_sni",
		"ssh+http+sni":        "http_proxy_tls_sni",
		"ssh+pl+http+sni":     "http_proxy_tls_sni",
		"unknown":             "",
	}
	for in, want := range cases {
		if got := normalizeMode(in); got != want {
			t.Errorf("normalizeMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeDNSMode(t *testing.T) {
	cases := map[string]string{
		"":           "device",
		"system":     "device",
		"DEVICE":     "device",
		"default":    "device",
		"google":     "google",
		"cloudflare": "cloudflare",
		"custom":     "custom",
		"garbage":    "device",
	}
	for in, want := range cases {
		if got := normalizeDNSMode(in); got != want {
			t.Errorf("normalizeDNSMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"":                  "",
		"   ":               "",
		"My Profile":        "my-profile",
		"---hyphens---":     "hyphens",
		"Special!Chars@123": "special-chars-123",
		"already-slug":      "already-slug",
	}
	for in, want := range cases {
		if got := slugify(in); got != want {
			t.Errorf("slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractHTTPStatuses(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []int
	}{
		{"none", "no http here", nil},
		{"single", "HTTP/1.1 200 OK\r\n", []int{200}},
		{"multiple", "HTTP/1.1 302 Found\r\n\r\nHTTP/1.1 200 OK\r\n", []int{302, 200}},
		{"non-status text ignored", "Server: nginx\r\nHTTP/1.1 101 Switching Protocols\r\n", []int{101}},
		{"malformed status word skipped", "HTTP/1.1 abc OK\r\nHTTP/1.1 200 OK\r\n", []int{200}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractHTTPStatuses(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("extractHTTPStatuses(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestAllowedStatuses(t *testing.T) {
	cases := []struct {
		name    string
		got     []int
		allowed []int
		want    bool
	}{
		{"empty got", nil, []int{200}, true},
		{"empty allowed treated as any", []int{200}, nil, true},
		{"all in allowed", []int{200, 302}, []int{200, 302, 101}, true},
		{"one not allowed fails", []int{200, 500}, []int{200, 302}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := allowedStatuses(c.got, c.allowed); got != c.want {
				t.Errorf("allowedStatuses(%v, %v) = %v, want %v", c.got, c.allowed, got, c.want)
			}
		})
	}
}

func TestExtractSSHBanner(t *testing.T) {
	cases := map[string]string{
		"":                                       "",
		"no banner here":                         "",
		"SSH-2.0-OpenSSH_8.4\r\n":                "SSH-2.0-OpenSSH_8.4",
		"HTTP/1.1 200 OK\r\nSSH-2.0-dropbear\n":  "SSH-2.0-dropbear",
	}
	for in, want := range cases {
		if got := extractSSHBanner(in); got != want {
			t.Errorf("extractSSHBanner(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUniqueProfileID(t *testing.T) {
	pf := &ProfilesFile{
		Profiles: []Profile{{ID: "main"}, {ID: "main-2"}},
	}
	// First-time fresh slug returns as-is.
	if got := uniqueProfileID(pf, "fresh"); got != "fresh" {
		t.Errorf("uniqueProfileID fresh = %q, want %q", got, "fresh")
	}
	// Existing slug gets a suffix beyond what's already taken.
	if got := uniqueProfileID(pf, "main"); got != "main-3" {
		t.Errorf("uniqueProfileID collision = %q, want %q", got, "main-3")
	}
}

func TestBuildTransportSetsTLSPort443When80OnTLSChain(t *testing.T) {
	// Regression test for the SNI-on-port-80 bug: a profile that selected
	// the http_proxy_tls_sni chain with proxy port 80 used to time out the
	// TLS handshake. buildTransport must auto-upgrade port 80 to 443 in
	// that case.
	ssh := SSH{Host: "example.com", Port: 80}
	hp := &HTTPProxyCfg{Host: "example.com", Port: 80, ConnectMethod: "socket"}
	tc := buildTransport("http_proxy_tls_sni", PayloadCfg{}, hp, nil, ssh)
	if tc.HTTPProxy == nil {
		t.Fatal("expected HTTPProxy in tls_sni mode")
	}
	if tc.HTTPProxy.Port != 443 {
		t.Errorf("expected proxy port auto-upgraded to 443, got %d", tc.HTTPProxy.Port)
	}
}

func TestFilterAAAA(t *testing.T) {
	// Construct a minimal DNS response with 1 A record and 1 AAAA record.
	// DNS header (12 bytes): ID=0x1234, QR=1 (response), QDCOUNT=1, ANCOUNT=2
	header := []byte{
		0x12, 0x34, // ID
		0x81, 0x80, // Flags: QR=1, RD=1, RA=1
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x02, // ANCOUNT = 2
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
	}
	// Question: example.com A IN
	question := []byte{
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // null terminator
		0x00, 0x01, // QTYPE = A
		0x00, 0x01, // QCLASS = IN
	}
	// Answer 1: A record (type 1), compressed name pointer to offset 12
	aRecord := []byte{
		0xC0, 0x0C, // compression pointer to question name
		0x00, 0x01, // TYPE = A (1)
		0x00, 0x01, // CLASS = IN
		0x00, 0x00, 0x00, 0x3C, // TTL = 60
		0x00, 0x04, // RDLENGTH = 4
		0x01, 0x02, 0x03, 0x04, // RDATA = 1.2.3.4
	}
	// Answer 2: AAAA record (type 28), compressed name pointer
	aaaaRecord := []byte{
		0xC0, 0x0C, // compression pointer
		0x00, 0x1C, // TYPE = AAAA (28)
		0x00, 0x01, // CLASS = IN
		0x00, 0x00, 0x00, 0x3C, // TTL = 60
		0x00, 0x10, // RDLENGTH = 16
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 2001:db8::1
	}
	msg := append(header, question...)
	msg = append(msg, aRecord...)
	msg = append(msg, aaaaRecord...)

	filtered := filterAAAA(msg)

	// Verify ANCOUNT is now 1
	if filtered[6] != 0x00 || filtered[7] != 0x01 {
		t.Errorf("expected ANCOUNT=1, got %d", int(filtered[6])<<8|int(filtered[7]))
	}
	// Verify the A record is preserved (check RDATA 1.2.3.4 is in the output)
	found := false
	for i := 0; i+3 < len(filtered); i++ {
		if filtered[i] == 1 && filtered[i+1] == 2 && filtered[i+2] == 3 && filtered[i+3] == 4 {
			found = true
			break
		}
	}
	if !found {
		t.Error("A record RDATA 1.2.3.4 not found in filtered response")
	}
	// Verify the AAAA RDATA is NOT in the output
	for i := 0; i+15 < len(filtered); i++ {
		if filtered[i] == 0x20 && filtered[i+1] == 0x01 && filtered[i+2] == 0x0d && filtered[i+3] == 0xb8 {
			t.Error("AAAA record RDATA still present in filtered response")
			break
		}
	}
	// Verify short messages pass through unchanged
	short := []byte{0x01, 0x02}
	if got := filterAAAA(short); len(got) != 2 {
		t.Errorf("expected short message passthrough, got len=%d", len(got))
	}
	// Verify message with no AAAA passes through unchanged
	noAAAA := append(header[:6], 0x00, 0x01) // ANCOUNT=1
	noAAAA = append(noAAAA, header[8:]...)   // rest of header
	noAAAA = append(noAAAA, question...)
	noAAAA = append(noAAAA, aRecord...)
	if got := filterAAAA(noAAAA); len(got) != len(noAAAA) {
		t.Errorf("expected no-AAAA message unchanged, got different length: %d vs %d", len(got), len(noAAAA))
	}
}
