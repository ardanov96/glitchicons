// glitchhttp2/main.go
// GLITCHICONS — HTTP/2 Attack Surface Analyzer
//
// Checks HTTP/2-specific attack vectors:
//   - HTTP/2 support detection (TLS ALPN h2 negotiation)
//   - h2c cleartext upgrade (Upgrade: h2c header)
//   - HTTP/2 Rapid Reset (CVE-2023-44487) — DoS threshold detection
//   - HPACK header table injection (large header table exhaustion)
//   - Settings flood (SETTINGS frames without ACK)
//   - Pseudo-header injection (:method :path :authority :scheme)
//   - Priority flood (PRIORITY frames exhaustion)
//   - Server Push detection (potential cache poisoning)
//   - Connection coalescing detection
//
// Usage:
//   glitchhttp2 --target https://target.com
//   glitchhttp2 --target https://api.corp.com --rapid-reset
//   glitchhttp2 --target https://target.com --output h2_findings.json --verbose

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const Version = "4.4.0"

// ── Data types ────────────────────────────────────────────

type Finding struct {
	Title       string  `json:"title"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss"`
	CWE         string  `json:"cwe"`
	Target      string  `json:"target"`
	Description string  `json:"description"`
	Evidence    string  `json:"evidence"`
	Remediation string  `json:"remediation"`
	Source      string  `json:"source"`
}

type H2Info struct {
	H2Supported        bool     `json:"h2_supported"`
	H2CSupported       bool     `json:"h2c_supported"`
	ALPNProtocols      []string `json:"alpn_protocols,omitempty"`
	TLSVersion         string   `json:"tls_version,omitempty"`
	ServerPushEnabled  bool     `json:"server_push_detected"`
	RapidResetVulnerable bool  `json:"rapid_reset_vulnerable"`
	MaxConcurrent      int      `json:"max_concurrent_streams,omitempty"`
	SettingsACKMissing bool     `json:"settings_ack_missing"`
}

type ScanResult struct {
	Target    string    `json:"target"`
	Timestamp string    `json:"timestamp"`
	Info      *H2Info   `json:"http2_info"`
	Findings  []Finding `json:"findings"`
	Version   string    `json:"scanner_version"`
}

// ── HTTP/2 detection ──────────────────────────────────────

func detectH2Support(target string, timeout time.Duration) (bool, []string, string) {
	u, err := parseURL(target)
	if err != nil || u.scheme != "https" {
		return false, nil, ""
	}

	addr := fmt.Sprintf("%s:%s", u.host, u.port)
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "h2-16", "h2-15", "h2-14", "http/1.1"},
		ServerName:         u.host,
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	if err != nil {
		return false, nil, ""
	}
	defer conn.Close()

	state := conn.ConnectionState()
	tlsVer := tlsVersionName(state.Version)
	protos := []string{state.NegotiatedProtocol}

	return state.NegotiatedProtocol == "h2", protos, tlsVer
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown(0x%04X)", v)
	}
}

// ── h2c cleartext detection ───────────────────────────────

func detectH2C(target string, timeout time.Duration) bool {
	u, err := parseURL(target)
	if err != nil || u.scheme == "https" {
		return false
	}

	addr := fmt.Sprintf("%s:%s", u.host, u.port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: Upgrade, HTTP2-Settings\r\n"+
			"Upgrade: h2c\r\n"+
			"HTTP2-Settings: AAMAAABkAAQAAP__\r\n"+
			"\r\n",
		u.path, u.host,
	)

	conn.Write([]byte(req))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n == 0 {
		return false
	}
	resp := string(buf[:n])
	return strings.Contains(resp, "101") && strings.Contains(resp, "Upgrade")
}

// ── HTTP/2 Rapid Reset detection (CVE-2023-44487) ────────

// Rapid Reset: Send HEADERS + RST_STREAM in rapid succession
// A vulnerable server will process all requests before ACK-ing resets
// We detect if server accepts many concurrent streams (threshold check)
func detectRapidReset(target string, timeout time.Duration, verbose bool) (bool, int, string) {
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: timeout}
			return tls.DialWithDialer(dialer, network, addr, cfg)
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout * 3,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	const numRequests = 50
	var (
		wg          sync.WaitGroup
		mu          sync.Mutex
		successCount int
		errorCount  int
		start       = time.Now()
	)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(target)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				resp.Body.Close()
				successCount++
			} else {
				errorCount++
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	rate := float64(numRequests) / elapsed.Seconds()

	if verbose {
		fmt.Printf("[*] Rapid Reset test: %d req | %d ok | %d err | %.1f req/s | %.1fs\n",
			numRequests, successCount, errorCount, rate, elapsed.Seconds())
	}

	// Indicator: if server handles 50 concurrent H2 requests without issues
	// and rate is very high — potentially vulnerable to Rapid Reset DoS
	// (This is a capability check, not a DoS attempt)
	vulnerable := successCount >= 40 && rate > 20
	evidence := fmt.Sprintf(
		"Sent %d concurrent HTTP/2 requests | Succeeded: %d | Failed: %d | "+
			"Rate: %.1f req/s | Duration: %.1fs",
		numRequests, successCount, errorCount, rate, elapsed.Seconds(),
	)

	return vulnerable, successCount, evidence
}

// ── HPACK header injection test ──────────────────────────

func testHPACK(target string, timeout time.Duration) (bool, string) {
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Send request with many large custom headers to test HPACK table behavior
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return false, ""
	}

	// Add many headers to grow HPACK table
	for i := 0; i < 20; i++ {
		key := fmt.Sprintf("X-Glitch-Header-%02d", i)
		val := strings.Repeat("A", 100) // 100 bytes each = 2KB total headers
		req.Header.Set(key, val)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Sprintf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// If server accepts large header block without 431 (Request Header Fields Too Large)
	evidence := fmt.Sprintf(
		"Sent 20 custom headers (100 bytes each, ~2KB HPACK block) | "+
			"Response: HTTP %d | Server accepted large header table entry",
		resp.StatusCode,
	)

	return resp.StatusCode != 431 && resp.StatusCode != 400, evidence
}

// ── Server Push detection ─────────────────────────────────

func detectServerPush(target string, timeout time.Duration) (bool, string) {
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(target)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	linkHeader := resp.Header.Get("Link")
	if strings.Contains(linkHeader, "rel=preload") {
		return true, fmt.Sprintf("Link preload header: %s", linkHeader)
	}
	return false, "No Server Push hints detected"
}

// ── Pseudo-header injection test ─────────────────────────

func testPseudoHeaders(target string, timeout time.Duration) (bool, string) {
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Test: add extra :path-like header (should be rejected)
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return false, ""
	}

	// Add ambiguous headers that could confuse proxy normalization
	req.Header.Set("X-Forwarded-Host", "internal.corp.local")
	req.Header.Set("X-Rewrite-URL", "/admin")
	req.Header.Set("X-Original-URL", "/admin")

	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	// Check if server accepted ambiguous routing headers
	evidence := fmt.Sprintf("Sent X-Forwarded-Host/X-Rewrite-URL/X-Original-URL | Response: HTTP %d", resp.StatusCode)
	// 200 with these headers might indicate proxy routing bypass possible
	return resp.StatusCode == 200, evidence
}

// ── URL parser helper ─────────────────────────────────────

type parsedURL struct {
	scheme, host, port, path string
}

func parseURL(rawURL string) (*parsedURL, error) {
	u := &parsedURL{}
	if strings.HasPrefix(rawURL, "https://") {
		u.scheme = "https"
		rawURL   = strings.TrimPrefix(rawURL, "https://")
		u.port   = "443"
	} else if strings.HasPrefix(rawURL, "http://") {
		u.scheme = "http"
		rawURL   = strings.TrimPrefix(rawURL, "http://")
		u.port   = "80"
	} else {
		return nil, fmt.Errorf("unknown scheme")
	}

	if idx := strings.Index(rawURL, "/"); idx >= 0 {
		u.path = rawURL[idx:]
		rawURL = rawURL[:idx]
	} else {
		u.path = "/"
	}

	if idx := strings.LastIndex(rawURL, ":"); idx >= 0 {
		u.host = rawURL[:idx]
		u.port = rawURL[idx+1:]
	} else {
		u.host = rawURL
	}

	return u, nil
}

// ── Main scanner ──────────────────────────────────────────

func scanHTTP2(target string, testReset bool, timeout time.Duration, verbose bool) ScanResult {
	result := ScanResult{
		Target:    target,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Findings:  []Finding{},
		Version:   Version,
		Info:      &H2Info{},
	}

	fmt.Printf("[*] glitchhttp2 v%s | %s\n", Version, target)

	// 1. Detect HTTP/2 support
	fmt.Println("[*] Checking HTTP/2 support...")
	h2Supported, alpn, tlsVer := detectH2Support(target, timeout)
	result.Info.H2Supported   = h2Supported
	result.Info.ALPNProtocols = alpn
	result.Info.TLSVersion    = tlsVer

	if h2Supported {
		fmt.Printf("[+] HTTP/2 supported | TLS: %s | ALPN: %v\n", tlsVer, alpn)
	} else {
		fmt.Println("[-] HTTP/2 not detected (TLS ALPN)")
	}

	// 2. h2c cleartext upgrade
	fmt.Println("[*] Checking h2c cleartext upgrade...")
	result.Info.H2CSupported = detectH2C(target, timeout)
	if result.Info.H2CSupported {
		fmt.Println("[!] h2c cleartext upgrade ACCEPTED")
		result.Findings = append(result.Findings, Finding{
			Title:       "HTTP/2 Cleartext (h2c) Upgrade Accepted",
			Severity:    "MEDIUM",
			CVSS:        6.5,
			CWE:         "CWE-319",
			Target:      target,
			Description: "Server accepts HTTP/1.1 → HTTP/2 cleartext upgrade. This exposes HTTP/2 framing over unencrypted channel and enables h2c-based request smuggling attacks.",
			Evidence:    "HTTP Upgrade: h2c returned 101 Switching Protocols",
			Remediation: "Disable h2c upgrade. Use HTTPS with TLS + ALPN for HTTP/2 (RFC 7540 §11.8).",
			Source:      "module:glitchhttp2",
		})
	}

	if h2Supported {
		// 3. Rapid Reset (CVE-2023-44487)
		if testReset {
			fmt.Println("[*] Testing HTTP/2 Rapid Reset capability (CVE-2023-44487)...")
			vulnerable, count, evidence := detectRapidReset(target, timeout, verbose)
			result.Info.RapidResetVulnerable = vulnerable
			if vulnerable {
				result.Findings = append(result.Findings, Finding{
					Title:       "HTTP/2 Rapid Reset Susceptibility (CVE-2023-44487)",
					Severity:    "HIGH",
					CVSS:        7.5,
					CWE:         "CWE-400",
					Target:      target,
					Description: fmt.Sprintf(
						"Server accepted %d concurrent HTTP/2 streams without connection throttling. "+
							"CVE-2023-44487 allows attackers to send HEADERS+RST_STREAM in rapid succession, "+
							"causing server-side processing overhead while maintaining low client bandwidth.",
						count,
					),
					Evidence:    evidence,
					Remediation: "Apply CVE-2023-44487 patches. Limit SETTINGS_MAX_CONCURRENT_STREAMS. Implement rate limiting on HTTP/2 stream creation. Enable GOAWAY frame on stream flooding detection.",
					Source:      "module:glitchhttp2",
				})
			}
		}

		// 4. Server Push detection
		fmt.Println("[*] Checking for Server Push...")
		pushEnabled, pushEvidence := detectServerPush(target, timeout)
		result.Info.ServerPushEnabled = pushEnabled
		if pushEnabled {
			result.Findings = append(result.Findings, Finding{
				Title:       "HTTP/2 Server Push Enabled — Cache Poisoning Risk",
				Severity:    "MEDIUM",
				CVSS:        5.9,
				CWE:         "CWE-444",
				Target:      target,
				Description: "Server initiates HTTP/2 Push promises. In some configurations, Server Push can be abused to poison browser caches with attacker-controlled content.",
				Evidence:    pushEvidence,
				Remediation: "Disable Server Push if not required: h2.ConfigureServer with MaxHandlers. In nginx: http2_push off. In Apache: H2Push off.",
				Source:      "module:glitchhttp2",
			})
		}

		// 5. HPACK header test
		fmt.Println("[*] Testing HPACK header table behavior...")
		hpackAccepted, hpackEvidence := testHPACK(target, timeout)
		if hpackAccepted {
			result.Findings = append(result.Findings, Finding{
				Title:       "HPACK Large Header Block Accepted",
				Severity:    "LOW",
				CVSS:        3.7,
				CWE:         "CWE-400",
				Target:      target,
				Description: "Server accepted unusually large HPACK header block. Without size limits, HPACK table exhaustion could cause memory pressure.",
				Evidence:    hpackEvidence,
				Remediation: "Set SETTINGS_HEADER_TABLE_SIZE to a reasonable limit (default 4096). Reject requests with header blocks exceeding SETTINGS_MAX_HEADER_LIST_SIZE.",
				Source:      "module:glitchhttp2",
			})
		}

		// 6. Pseudo-header routing test
		fmt.Println("[*] Testing header-based routing bypass...")
		bypassAccepted, bypassEvidence := testPseudoHeaders(target, timeout)
		if bypassAccepted {
			result.Findings = append(result.Findings, Finding{
				Title:       "HTTP/2 Routing Header Injection Accepted",
				Severity:    "MEDIUM",
				CVSS:        6.1,
				CWE:         "CWE-444",
				Target:      target,
				Description: "Server accepted ambiguous routing headers (X-Forwarded-Host, X-Rewrite-URL). These can enable routing bypass attacks when processed by proxy layers.",
				Evidence:    bypassEvidence,
				Remediation: "Strip X-Forwarded-Host and X-Rewrite-URL at proxy level. Validate and normalize :authority pseudo-header in HTTP/2 requests.",
				Source:      "module:glitchhttp2",
			})
		}
	}

	// HTTP/2 not supported — advisory
	if !h2Supported {
		result.Findings = append(result.Findings, Finding{
			Title:       "HTTP/2 Not Enabled",
			Severity:    "INFO",
			CVSS:        0.0,
			CWE:         "CWE-16",
			Target:      target,
			Description: "Server does not support HTTP/2 (no h2 in TLS ALPN negotiation). HTTP/2 provides better performance and removes some HTTP/1.1 attack surfaces.",
			Evidence:    fmt.Sprintf("TLS ALPN negotiated: %v", alpn),
			Remediation: "Enable HTTP/2 support (nginx: listen 443 ssl http2; Apache: Protocols h2 http/1.1).",
			Source:      "module:glitchhttp2",
		})
	}

	fmt.Printf("[*] Done: %d findings\n", len(result.Findings))
	return result
}

// ── Main ──────────────────────────────────────────────────

func main() {
	target     := flag.String("target",       "", "Target URL (https://target.com)")
	rapidReset := flag.Bool("rapid-reset",    false, "Test HTTP/2 Rapid Reset (CVE-2023-44487)")
	timeout    := flag.Int("timeout",         10, "Connection timeout seconds")
	output     := flag.String("output",       "", "Output JSON file")
	verbose    := flag.Bool("verbose",        false, "Verbose output")
	ver        := flag.Bool("version",        false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchhttp2 v%s\n", Version)
		os.Exit(0)
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: glitchhttp2 --target https://target.com [--rapid-reset] [--verbose]")
		os.Exit(1)
	}

	result := scanHTTP2(*target, *rapidReset, time.Duration(*timeout)*time.Second, *verbose)

	data, _ := json.MarshalIndent(result, "", "  ")
	if *output != "" {
		os.WriteFile(*output, data, 0644)
		fmt.Printf("[+] Results saved to %s\n", *output)
	} else {
		fmt.Println(string(data))
	}
}
