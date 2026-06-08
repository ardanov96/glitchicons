// glitchids/main.go
// GLITCHICONS — IDS/IPS Evasion Tester
//
// Tests whether network security controls detect or block scan traffic.
// Compares results between normal and evasion-mode scans to identify
// IDS/IPS gaps.
//
// Evasion Techniques:
//   slow      — Ultra-slow scan (configurable delay per probe)
//   fragment  — Send HTTP requests in small TCP fragments
//   decoy     — Mix real probes with fake decoy IPs
//   jitter    — Random timing between probes
//   rotate    — Rotate User-Agent and headers per request
//   ttl       — Low TTL values (may confuse IDS reassembly)
//   all       — Apply all evasion techniques simultaneously
//
// Usage:
//   glitchids --target https://target.com --technique slow --delay 5000
//   glitchids --target 10.0.0.1 --technique decoy --decoys 192.168.1.1,10.0.0.5
//   glitchids --target https://api.corp.com --technique rotate --requests 50
//   glitchids --target https://target.com --technique all --output ids_findings.json
//   glitchids --version

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const Version = "4.5.0"

// ── User-Agent pool ───────────────────────────────────────

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
	"curl/8.5.0",
	"python-requests/2.31.0",
	"Go-http-client/1.1",
	"Wget/1.21.4 (linux-gnu)",
	"Jakarta Commons-HttpClient/3.1",
	"Microsoft-WNS/10.0",
	"Dalvik/2.1.0 (Linux; U; Android 13; Pixel 7 Build/TQ3A.230901.001)",
}

var headerSets = []map[string]string{
	{"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5"},
	{"Accept": "application/json, text/plain, */*", "X-Requested-With": "XMLHttpRequest"},
	{"Accept": "*/*", "Cache-Control": "no-cache"},
	{"Accept": "text/html", "Accept-Encoding": "gzip, deflate, br"},
	{"Accept": "application/json", "Content-Type": "application/json"},
}

// ── Data types ────────────────────────────────────────────

type ProbeResult struct {
	URL          string  `json:"url"`
	StatusCode   int     `json:"status_code"`
	ResponseMS   int64   `json:"response_ms"`
	Blocked      bool    `json:"blocked"`
	Technique    string  `json:"technique"`
	UserAgent    string  `json:"user_agent,omitempty"`
}

type EvasionResult struct {
	Target       string        `json:"target"`
	Technique    string        `json:"technique"`
	Timestamp    string        `json:"timestamp"`
	Normal       []ProbeResult `json:"normal_probes"`
	Evaded       []ProbeResult `json:"evasion_probes"`
	BlockedNormal int          `json:"blocked_normal"`
	BlockedEvaded int          `json:"blocked_evaded"`
	EvasionRate  float64       `json:"evasion_rate_pct"`
	IDSDetecting bool          `json:"ids_detecting"`
	Findings     []Finding     `json:"findings"`
	Version      string        `json:"scanner_version"`
}

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

// ── Random helpers ────────────────────────────────────────

func randInt(max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

func randUA() string {
	return userAgents[randInt(len(userAgents))]
}

func randHeaders() map[string]string {
	return headerSets[randInt(len(headerSets))]
}

func randIP() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		randInt(254)+1, randInt(254)+1,
		randInt(254)+1, randInt(254)+1)
}

func randDelay(baseMS, jitterMS int) time.Duration {
	if jitterMS == 0 {
		return time.Duration(baseMS) * time.Millisecond
	}
	j := randInt(jitterMS)
	return time.Duration(baseMS+j) * time.Millisecond
}

// ── HTTP probing ──────────────────────────────────────────

func normalProbe(url string, timeout time.Duration) ProbeResult {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()
	resp, err := client.Get(url)
	elapsed := time.Since(start).Milliseconds()

	result := ProbeResult{
		URL:        url,
		ResponseMS: elapsed,
		Technique:  "normal",
	}

	if err != nil {
		result.Blocked = true
		return result
	}
	defer resp.Body.Close()
	result.StatusCode = resp.StatusCode
	result.Blocked = resp.StatusCode == 403 || resp.StatusCode == 429 || resp.StatusCode == 503
	return result
}

// ── Evasion techniques ────────────────────────────────────

// 1. Slow scan — large delay between probes
func slowProbe(url string, delayMS int, timeout time.Duration) ProbeResult {
	time.Sleep(time.Duration(delayMS) * time.Millisecond)
	result := normalProbe(url, timeout)
	result.Technique = fmt.Sprintf("slow(%dms)", delayMS)
	return result
}

// 2. Rotate User-Agent per request
func rotateProbe(url string, timeout time.Duration) ProbeResult {
	ua := randUA()
	hdrs := randHeaders()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ProbeResult{URL: url, Blocked: true, Technique: "rotate"}
	}
	req.Header.Set("User-Agent", ua)
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	// Add random X-Forwarded-For
	req.Header.Set("X-Forwarded-For", randIP())

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()

	result := ProbeResult{
		URL: url, ResponseMS: elapsed,
		Technique: "rotate", UserAgent: ua,
	}
	if err != nil {
		result.Blocked = true
		return result
	}
	defer resp.Body.Close()
	result.StatusCode = resp.StatusCode
	result.Blocked = resp.StatusCode == 403 || resp.StatusCode == 429
	return result
}

// 3. Jitter — random timing between requests
func jitterProbe(url string, baseMS, jitterMS int, timeout time.Duration) ProbeResult {
	delay := randDelay(baseMS, jitterMS)
	time.Sleep(delay)
	result := normalProbe(url, timeout)
	result.Technique = fmt.Sprintf("jitter(%v)", delay)
	return result
}

// 4. Fragmented TCP delivery — send HTTP in small chunks
func fragmentProbe(target string, chunkSize int, timeout time.Duration) ProbeResult {
	result := ProbeResult{
		URL:       target,
		Technique: fmt.Sprintf("fragment(%db)", chunkSize),
	}

	// Parse target to get host and path
	host, port, path, useTLS := parseTarget(target)
	addr := fmt.Sprintf("%s:%s", host, port)

	var conn net.Conn
	var err error
	start := time.Now()

	if useTLS {
		conn, err = tls.DialWithDialer(
			&net.Dialer{Timeout: timeout},
			"tcp", addr,
			&tls.Config{InsecureSkipVerify: true, ServerName: host},
		)
	} else {
		conn, err = net.DialTimeout("tcp", addr, timeout)
	}

	if err != nil {
		result.Blocked = true
		return result
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Build HTTP request
	httpReq := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n",
		path, host, randUA(),
	)

	// Send in small fragments with delay between each
	reqBytes := []byte(httpReq)
	for i := 0; i < len(reqBytes); i += chunkSize {
		end := i + chunkSize
		if end > len(reqBytes) {
			end = len(reqBytes)
		}
		conn.Write(reqBytes[i:end])
		time.Sleep(10 * time.Millisecond) // Small delay between fragments
	}

	// Read response
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	elapsed := time.Since(start).Milliseconds()
	result.ResponseMS = elapsed

	if err != nil {
		result.Blocked = true
		return result
	}

	var code int
	fmt.Sscanf(statusLine, "HTTP/1.1 %d", &code)
	if code == 0 {
		fmt.Sscanf(statusLine, "HTTP/1.0 %d", &code)
	}
	result.StatusCode = code
	result.Blocked = code == 403 || code == 429 || code == 503
	return result
}

// 5. Decoy scan — mix probes with fake source IPs
func decoyProbe(url string, decoys []string, timeout time.Duration) ProbeResult {
	// Send decoy probes first (with fake IPs via X-Forwarded-For)
	for _, decoy := range decoys {
		req, err := http.NewRequest("GET", url, nil)
		if err == nil {
			req.Header.Set("X-Forwarded-For", decoy)
			req.Header.Set("User-Agent", randUA())
			client := &http.Client{
				Timeout: timeout / 2,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
				CheckRedirect: func(r *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Real probe after decoys
	result := normalProbe(url, timeout)
	result.Technique = fmt.Sprintf("decoy(%d)", len(decoys))
	return result
}

// ── Port scan evasion ─────────────────────────────────────

func slowPortScan(host string, ports []int, delayMS int, timeout time.Duration, verbose bool) map[int]bool {
	results := make(map[int]bool)
	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err == nil {
			conn.Close()
			results[port] = true
			if verbose {
				fmt.Printf("[+] Open: %d\n", port)
			}
		}
		time.Sleep(time.Duration(delayMS) * time.Millisecond)
	}
	return results
}

// ── Main scanner ──────────────────────────────────────────

func parseTarget(target string) (host, port, path string, useTLS bool) {
	useTLS = strings.HasPrefix(target, "https://")
	target = strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	if useTLS {
		port = "443"
	} else {
		port = "80"
	}
	if idx := strings.Index(target, "/"); idx >= 0 {
		path = target[idx:]
		target = target[:idx]
	} else {
		path = "/"
	}
	if idx := strings.LastIndex(target, ":"); idx >= 0 {
		host = target[:idx]
		port = target[idx+1:]
	} else {
		host = target
	}
	return
}

func runEvasion(target, technique string, requests, delayMS, jitterMS, chunkSize int, decoys []string, timeout time.Duration, verbose bool) EvasionResult {
	result := EvasionResult{
		Target:    target,
		Technique: technique,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Findings:  []Finding{},
		Version:   Version,
	}

	fmt.Printf("[*] glitchids v%s | %s | technique=%s | requests=%d\n",
		Version, target, technique, requests)

	var blockedNormal int64
	var blockedEvaded int64

	// Run normal probes (baseline)
	fmt.Printf("[*] Running %d baseline probes...\n", requests/2)
	for i := 0; i < requests/2; i++ {
		r := normalProbe(target, timeout)
		result.Normal = append(result.Normal, r)
		if r.Blocked {
			atomic.AddInt64(&blockedNormal, 1)
		}
	}

	// Run evasion probes
	fmt.Printf("[*] Running %d evasion probes (technique: %s)...\n", requests/2, technique)
	for i := 0; i < requests/2; i++ {
		var r ProbeResult
		switch technique {
		case "slow":
			r = slowProbe(target, delayMS, timeout)
		case "rotate":
			r = rotateProbe(target, timeout)
		case "jitter":
			r = jitterProbe(target, delayMS, jitterMS, timeout)
		case "fragment":
			r = fragmentProbe(target, chunkSize, timeout)
		case "decoy":
			r = decoyProbe(target, decoys, timeout)
		case "all":
			// Combine all techniques
			time.Sleep(randDelay(delayMS, jitterMS))
			r = rotateProbe(target, timeout)
			if !r.Blocked && i%3 == 0 {
				r = fragmentProbe(target, chunkSize, timeout)
			}
		default:
			r = normalProbe(target, timeout)
		}

		result.Evaded = append(result.Evaded, r)
		if r.Blocked {
			atomic.AddInt64(&blockedEvaded, 1)
		}
		if verbose {
			status := "OK"
			if r.Blocked {
				status = "BLOCKED"
			}
			fmt.Printf("[%s] %s | %dms | UA=%s\n",
				status, r.Technique, r.ResponseMS,
				truncate(r.UserAgent, 40))
		}
	}

	result.BlockedNormal = int(blockedNormal)
	result.BlockedEvaded = int(blockedEvaded)

	// Calculate evasion rate
	if blockedNormal > 0 {
		evaded := blockedNormal - blockedEvaded
		if evaded < 0 {
			evaded = 0
		}
		result.EvasionRate = float64(evaded) / float64(blockedNormal) * 100
		result.IDSDetecting = blockedNormal > 0
	}

	fmt.Printf("[*] Normal blocked: %d/%d | Evasion blocked: %d/%d | Evasion rate: %.1f%%\n",
		blockedNormal, requests/2, blockedEvaded, requests/2, result.EvasionRate)

	// Generate findings
	if result.IDSDetecting && result.EvasionRate > 50 {
		result.Findings = append(result.Findings, Finding{
			Title:    fmt.Sprintf("IDS/WAF Bypass via %s Technique (%.0f%% Evasion Rate)", technique, result.EvasionRate),
			Severity: "HIGH",
			CVSS:     7.5,
			CWE:      "CWE-693",
			Target:   target,
			Description: fmt.Sprintf(
				"IDS/WAF detected %d/%d normal requests but only %d/%d evasion requests. "+
					"%.0f%% evasion rate with technique: %s.",
				blockedNormal, requests/2, blockedEvaded, requests/2,
				result.EvasionRate, technique,
			),
			Evidence: fmt.Sprintf(
				"Normal: %d/%d blocked\nEvasion: %d/%d blocked\nRate: %.1f%%\nTechnique: %s",
				blockedNormal, requests/2, blockedEvaded, requests/2,
				result.EvasionRate, technique,
			),
			Remediation: "Update IDS/WAF signatures to detect evasion variants. " +
				"Use behavioral analysis (not just signature-based). " +
				"Normalize requests before inspection. " +
				"Enable slow HTTP attack detection.",
			Source: "module:glitchids",
		})
	} else if !result.IDSDetecting {
		result.Findings = append(result.Findings, Finding{
			Title:    "No IDS/WAF Rate Limiting Detected",
			Severity: "MEDIUM",
			CVSS:     5.3,
			CWE:      "CWE-770",
			Target:   target,
			Description: fmt.Sprintf("No requests were blocked during %d probe attempts. Server may lack rate limiting or IDS protection.", requests),
			Evidence:    fmt.Sprintf("Requests: %d | Blocked: 0 | Rate: unrestricted", requests),
			Remediation: "Implement rate limiting. Deploy WAF with behavioral analysis. Enable slow HTTP attack protection.",
			Source:      "module:glitchids",
		})
	}

	return result
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ── Main ──────────────────────────────────────────────────

func main() {
	target    := flag.String("target",    "", "Target URL or host (required)")
	technique := flag.String("technique", "rotate", "Evasion technique: slow|rotate|jitter|fragment|decoy|all")
	requests  := flag.Int("requests",    20,   "Total probe requests (split normal/evasion)")
	delayMS   := flag.Int("delay",       2000, "Delay in ms (slow/jitter mode)")
	jitterMS  := flag.Int("jitter",      1000, "Jitter max ms (jitter mode)")
	chunkSize := flag.Int("chunk",       8,    "TCP fragment chunk bytes (fragment mode)")
	decoyList := flag.String("decoys",   "",   "Decoy IPs comma-separated (decoy mode)")
	timeout   := flag.Int("timeout",     10,   "Request timeout seconds")
	output    := flag.String("output",   "",   "Output JSON file")
	verbose   := flag.Bool("verbose",    false, "Verbose output")
	ver       := flag.Bool("version",    false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchids v%s\n", Version)
		os.Exit(0)
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: glitchids --target https://target.com [--technique rotate|slow|jitter|fragment|decoy|all]")
		os.Exit(1)
	}

	validTechs := map[string]bool{
		"slow": true, "rotate": true, "jitter": true,
		"fragment": true, "decoy": true, "all": true,
	}
	if !validTechs[*technique] {
		fmt.Fprintf(os.Stderr, "Invalid technique: %s\n", *technique)
		os.Exit(1)
	}

	var decoys []string
	if *decoyList != "" {
		decoys = strings.Split(*decoyList, ",")
	} else {
		// Auto-generate random decoys
		for i := 0; i < 5; i++ {
			decoys = append(decoys, randIP())
		}
	}

	tOut   := time.Duration(*timeout) * time.Second
	result := runEvasion(*target, *technique, *requests, *delayMS, *jitterMS, *chunkSize, decoys, tOut, *verbose)

	data, _ := json.MarshalIndent(result, "", "  ")
	if *output != "" {
		os.WriteFile(*output, data, 0644)
		fmt.Printf("[+] Results saved to %s\n", *output)
	} else {
		fmt.Println(string(data))
	}
}
