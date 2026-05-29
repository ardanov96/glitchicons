// glitchfuzz — HTTP Directory + Parameter Fuzzer
// Part of the Glitchicons security research platform
//
// Features:
//   - Directory/path brute force (like ffuf/gobuster but integrated)
//   - Parameter discovery (find hidden GET/POST params)
//   - Virtual host brute force
//   - Recursive directory scanning
//   - Filter by status code, response size, word count
//   - Rate limiting + delay support
//   - Standard Glitchicons JSON output
//
// Modes:
//   dir   — brute force directories/files
//   param — discover hidden parameters
//   vhost — enumerate virtual hosts
//
// Usage:
//   glitchfuzz dir   --url https://target.com --wordlist common.txt
//   glitchfuzz param --url https://target.com/api/user --wordlist params.txt
//   glitchfuzz vhost --url https://target.com --wordlist subdomains.txt
//
// Author: ardanov96

package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ── Output schema ─────────────────────────────────────────

type FuzzResult struct {
	Word       string `json:"word"`
	URL        string `json:"url"`
	Status     int    `json:"status"`
	Length     int    `json:"length"`
	Words      int    `json:"words"`
	Lines      int    `json:"lines"`
	DurationMS int64  `json:"duration_ms"`
	Redirect   string `json:"redirect,omitempty"`
}

type Finding struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss"`
	CWE         string  `json:"cwe"`
	Target      string  `json:"target"`
	Description string  `json:"description"`
	Evidence    string  `json:"evidence"`
	Remediation string  `json:"remediation"`
	Timestamp   string  `json:"timestamp"`
}

type Stats struct {
	Mode         string  `json:"mode"`
	WordlistSize int     `json:"wordlist_size"`
	Requests     int64   `json:"requests"`
	Hits         int     `json:"hits"`
	DurationMS   int64   `json:"duration_ms"`
	ReqPerSec    float64 `json:"req_per_sec"`
	Concurrency  int     `json:"concurrency"`
}

type Output struct {
	Tool     string       `json:"tool"`
	Version  string       `json:"version"`
	Target   string       `json:"target"`
	Mode     string       `json:"mode"`
	Started  string       `json:"started"`
	Finished string       `json:"finished"`
	Results  []FuzzResult `json:"results"`
	Findings []Finding    `json:"findings"`
	Stats    Stats        `json:"stats"`
	ExitCode int          `json:"exit_code"`
}

// ── Interesting status codes ──────────────────────────────

var interestingStatuses = map[int]struct {
	severity string
	cvss     float64
	cwe      string
	title    string
}{
	200: {"INFO",   3.1, "CWE-200", "Accessible path discovered"},
	201: {"LOW",    3.5, "CWE-200", "Resource creation endpoint found"},
	204: {"INFO",   2.0, "CWE-200", "No-content endpoint found"},
	301: {"INFO",   2.0, "CWE-200", "Redirect discovered"},
	302: {"INFO",   2.0, "CWE-200", "Redirect discovered"},
	401: {"MEDIUM", 5.3, "CWE-200", "Authentication-protected endpoint found"},
	403: {"MEDIUM", 5.3, "CWE-284", "Forbidden endpoint found (may be bypassable)"},
	405: {"LOW",    3.1, "CWE-200", "Method not allowed — endpoint exists"},
	500: {"MEDIUM", 5.5, "CWE-200", "Server error — potential information disclosure"},
}

// ── Built-in wordlists (minimal, embedded) ────────────────

var builtinDirWordlist = []string{
	"admin", "api", "backup", "config", "dashboard", "data", "db",
	"debug", "dev", "docs", "download", "env", "files", "health",
	"hidden", "info", "internal", "js", "login", "logs", "manage",
	"metrics", "monitor", "old", "private", "robots.txt", "secret",
	"server-status", "setup", "static", "status", "swagger", "test",
	"tmp", "upload", "user", "v1", "v2", "wp-admin", ".env",
	".git", ".htaccess", "sitemap.xml", "web.config", "phpinfo.php",
}

var builtinParamWordlist = []string{
	"id", "user", "username", "email", "token", "key", "api_key",
	"apikey", "secret", "password", "pass", "debug", "admin",
	"test", "cmd", "exec", "file", "path", "url", "redirect",
	"return", "next", "callback", "ref", "page", "limit", "offset",
	"sort", "order", "filter", "search", "q", "query", "format",
	"type", "action", "method", "lang", "locale", "version",
}

// ── Wordlist loader ───────────────────────────────────────

func loadWordlist(path string, builtin []string) ([]string, error) {
	if path == "" {
		return builtin, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open wordlist %s: %w", path, err)
	}
	defer f.Close()

	var words []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)
		}
	}
	return words, scanner.Err()
}

// ── HTTP client ───────────────────────────────────────────

func newClient(timeoutSec int, followRedirects bool) *http.Client {
	client := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        1000,
			MaxIdleConnsPerHost: 1000,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  true,
		},
	}
	if !followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}

// ── Response analyzer ─────────────────────────────────────

func analyzeResponse(resp *http.Response, body string) (words, lines int) {
	fields := strings.Fields(body)
	words = len(fields)
	lines = strings.Count(body, "\n") + 1
	return
}

// ── Fuzz request ──────────────────────────────────────────

func fuzzRequest(
	client *http.Client,
	method, targetURL string,
	headers map[string]string,
) (status, length, words, lines int, redirect string, durMS int64, err error) {
	start := time.Now()

	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Glitchicons/1.0 (glitchfuzz)")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	durMS = time.Since(start).Milliseconds()
	if err != nil {
		return
	}
	defer resp.Body.Close()

	buf := make([]byte, 65536)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	status = resp.StatusCode
	length = n
	words, lines = analyzeResponse(resp, body)
	redirect = resp.Header.Get("Location")
	return
}

// ── Filter checker ────────────────────────────────────────

type Filter struct {
	ExcludeStatus []int
	ExcludeSize   int
	MinStatus     int
	MaxStatus     int
}

func (f *Filter) ShouldShow(status, size int) bool {
	for _, s := range f.ExcludeStatus {
		if status == s {
			return false
		}
	}
	if f.ExcludeSize > 0 && size == f.ExcludeSize {
		return false
	}
	if _, ok := interestingStatuses[status]; !ok {
		return false
	}
	return true
}

// ── Dir fuzzer ────────────────────────────────────────────

func fuzzDir(
	client *http.Client,
	baseURL string,
	words []string,
	concurrency int,
	delayMS int,
	filter *Filter,
	verbose bool,
	headers map[string]string,
) []FuzzResult {
	baseURL = strings.TrimRight(baseURL, "/")

	wordCh := make(chan string, len(words))
	for _, w := range words {
		wordCh <- w
	}
	close(wordCh)

	resultCh := make(chan FuzzResult, len(words))
	var wg sync.WaitGroup
	var reqCount int64

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range wordCh {
				targetURL := fmt.Sprintf("%s/%s", baseURL, word)
				status, length, words_, lines, redirect, durMS, err := fuzzRequest(
					client, "GET", targetURL, headers,
				)
				atomic.AddInt64(&reqCount, 1)
				if err != nil {
					continue
				}
				if filter.ShouldShow(status, length) {
					r := FuzzResult{
						Word: word, URL: targetURL,
						Status: status, Length: length,
						Words: words_, Lines: lines,
						DurationMS: durMS, Redirect: redirect,
					}
					resultCh <- r
					if verbose {
						fmt.Fprintf(os.Stderr,
							"[glitchfuzz] %d  %-40s  len=%-6d  %dms\n",
							status, targetURL, length, durMS)
					}
				}
				if delayMS > 0 {
					time.Sleep(time.Duration(delayMS) * time.Millisecond)
				}
			}
		}()
	}

	wg.Wait()
	close(resultCh)

	var results []FuzzResult
	for r := range resultCh {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Status < results[j].Status
	})
	return results
}

// ── Param fuzzer ──────────────────────────────────────────

func fuzzParam(
	client *http.Client,
	baseURL string,
	words []string,
	concurrency int,
	delayMS int,
	filter *Filter,
	verbose bool,
	headers map[string]string,
) []FuzzResult {
	// First request baseline
	_, baseLen, _, _, _, _, _ := fuzzRequest(client, "GET", baseURL, headers)

	wordCh := make(chan string, len(words))
	for _, w := range words {
		wordCh <- w
	}
	close(wordCh)

	resultCh := make(chan FuzzResult, len(words))
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range wordCh {
				targetURL := fmt.Sprintf("%s?%s=GLITCHFUZZ", baseURL, word)
				status, length, words_, lines, redirect, durMS, err := fuzzRequest(
					client, "GET", targetURL, headers,
				)
				if err != nil {
					continue
				}
				// Show if response differs from baseline
				sizeDiff := length - baseLen
				if sizeDiff < 0 {
					sizeDiff = -sizeDiff
				}
				if sizeDiff > 50 || status != 200 {
					if filter.ShouldShow(status, length) || sizeDiff > 100 {
						r := FuzzResult{
							Word: word, URL: targetURL,
							Status: status, Length: length,
							Words: words_, Lines: lines,
							DurationMS: durMS, Redirect: redirect,
						}
						resultCh <- r
						if verbose {
							fmt.Fprintf(os.Stderr,
								"[glitchfuzz] PARAM %s  status=%d  len=%d (diff %+d)\n",
								word, status, length, sizeDiff)
						}
					}
				}
				if delayMS > 0 {
					time.Sleep(time.Duration(delayMS) * time.Millisecond)
				}
			}
		}()
	}

	wg.Wait()
	close(resultCh)

	var results []FuzzResult
	for r := range resultCh {
		results = append(results, r)
	}
	return results
}

// ── Vhost fuzzer ──────────────────────────────────────────

func fuzzVhost(
	client *http.Client,
	baseURL, baseDomain string,
	words []string,
	concurrency int,
	delayMS int,
	verbose bool,
	headers map[string]string,
) []FuzzResult {
	// Baseline with original host
	_, baseLen, _, _, _, _, _ := fuzzRequest(client, "GET", baseURL, headers)

	wordCh := make(chan string, len(words))
	for _, w := range words {
		wordCh <- w
	}
	close(wordCh)

	resultCh := make(chan FuzzResult, len(words))
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range wordCh {
				vhostHeaders := make(map[string]string)
				for k, v := range headers {
					vhostHeaders[k] = v
				}
				vhost := fmt.Sprintf("%s.%s", word, baseDomain)
				vhostHeaders["Host"] = vhost

				status, length, words_, lines, redirect, durMS, err := fuzzRequest(
					client, "GET", baseURL, vhostHeaders,
				)
				if err != nil {
					continue
				}
				sizeDiff := length - baseLen
				if sizeDiff < 0 {
					sizeDiff = -sizeDiff
				}
				if sizeDiff > 100 {
					r := FuzzResult{
						Word: vhost, URL: baseURL,
						Status: status, Length: length,
						Words: words_, Lines: lines,
						DurationMS: durMS, Redirect: redirect,
					}
					resultCh <- r
					if verbose {
						fmt.Fprintf(os.Stderr,
							"[glitchfuzz] VHOST %s  status=%d  len=%d\n",
							vhost, status, length)
					}
				}
				if delayMS > 0 {
					time.Sleep(time.Duration(delayMS) * time.Millisecond)
				}
			}
		}()
	}

	wg.Wait()
	close(resultCh)

	var results []FuzzResult
	for r := range resultCh {
		results = append(results, r)
	}
	return results
}

// ── Finding generator ─────────────────────────────────────

func generateFindings(results []FuzzResult, mode, target string) []Finding {
	var findings []Finding
	for i, r := range results {
		info, ok := interestingStatuses[r.Status]
		if !ok {
			continue
		}
		// Only generate findings for meaningful statuses
		if r.Status == 200 || r.Status == 403 || r.Status == 401 || r.Status >= 500 {
			findings = append(findings, Finding{
				ID:       fmt.Sprintf("FUZZ-%03d", i+1),
				Title:    fmt.Sprintf("%s: %s", info.title, r.Word),
				Severity: info.severity,
				CVSS:     info.cvss,
				CWE:      info.cwe,
				Target:   r.URL,
				Description: fmt.Sprintf(
					"[%s mode] '%s' returned HTTP %d (size: %d bytes). "+
						"Discovered via wordlist fuzzing.",
					mode, r.Word, r.Status, r.Length,
				),
				Evidence: fmt.Sprintf(
					"URL: %s\nHTTP %d | Size: %d | Words: %d | %dms",
					r.URL, r.Status, r.Length, r.Words, r.DurationMS,
				),
				Remediation: "Review if this endpoint should be publicly accessible. " +
					"Implement authentication if sensitive. " +
					"Return 404 instead of 403 to avoid confirming endpoint existence.",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
		}
	}
	return findings
}

// ── Main ──────────────────────────────────────────────────

func main() {
	// Sub-commands
	dirCmd   := flag.NewFlagSet("dir",   flag.ExitOnError)
	paramCmd := flag.NewFlagSet("param", flag.ExitOnError)
	vhostCmd := flag.NewFlagSet("vhost", flag.ExitOnError)

	// Shared flags helper
	addSharedFlags := func(fs *flag.FlagSet) (
		url_, wordlist, token, output *string,
		concurrency, timeout, delay *int,
		verbose *bool,
	) {
		url_        = fs.String("url",         "", "Target URL (required)")
		wordlist     = fs.String("wordlist",    "", "Wordlist file (uses builtin if empty)")
		token        = fs.String("token",       "", "Bearer token")
		output       = fs.String("output",      "json", "Output: json|text")
		concurrency  = fs.Int("concurrency",    100,   "Concurrent goroutines")
		timeout      = fs.Int("timeout",        5,     "Request timeout seconds")
		delay        = fs.Int("delay",          0,     "Delay between requests (ms)")
		verbose      = fs.Bool("verbose",       false, "Print each result to stderr")
		return
	}

	dirURL, dirWordlist, dirToken, dirOutput, dirConc, dirTimeout, dirDelay, dirVerbose := addSharedFlags(dirCmd)
	paramURL, paramWordlist, paramToken, paramOutput, paramConc, paramTimeout, paramDelay, paramVerbose := addSharedFlags(paramCmd)
	vhostURL, vhostWordlist, vhostToken, vhostOutput, vhostConc, vhostTimeout, vhostDelay, vhostVerbose := addSharedFlags(vhostCmd)
	vhostDomain := vhostCmd.String("domain", "", "Base domain for vhost fuzzing")

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: glitchfuzz <dir|param|vhost> [flags]")
		fmt.Fprintln(os.Stderr, "       glitchfuzz --version")
		os.Exit(1)
	}

	if os.Args[1] == "--version" || os.Args[1] == "version" {
		fmt.Println("glitchfuzz 1.0.0")
		os.Exit(0)
	}

	mode := os.Args[1]
	var (
		targetURL   string
		wordlistPath string
		token        string
		outputFmt    string
		concurrency  int
		timeoutSec   int
		delayMS      int
		verbose      bool
	)

	switch mode {
	case "dir":
		dirCmd.Parse(os.Args[2:])
		targetURL, wordlistPath, token = *dirURL, *dirWordlist, *dirToken
		outputFmt, concurrency, timeoutSec = *dirOutput, *dirConc, *dirTimeout
		delayMS, verbose = *dirDelay, *dirVerbose
	case "param":
		paramCmd.Parse(os.Args[2:])
		targetURL, wordlistPath, token = *paramURL, *paramWordlist, *paramToken
		outputFmt, concurrency, timeoutSec = *paramOutput, *paramConc, *paramTimeout
		delayMS, verbose = *paramDelay, *paramVerbose
	case "vhost":
		vhostCmd.Parse(os.Args[2:])
		targetURL, wordlistPath, token = *vhostURL, *vhostWordlist, *vhostToken
		outputFmt, concurrency, timeoutSec = *vhostOutput, *vhostConc, *vhostTimeout
		delayMS, verbose = *vhostDelay, *vhostVerbose
	default:
		fmt.Fprintf(os.Stderr, "Unknown mode: %s\n", mode)
		os.Exit(1)
	}

	if targetURL == "" {
		fmt.Fprintln(os.Stderr, "Error: --url is required")
		os.Exit(1)
	}

	headers := map[string]string{}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}

	// Load wordlist
	var builtinList []string
	if mode == "param" {
		builtinList = builtinParamWordlist
	} else {
		builtinList = builtinDirWordlist
	}
	words, err := loadWordlist(wordlistPath, builtinList)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	client := newClient(timeoutSec, false)
	filter := &Filter{ExcludeStatus: []int{404}}

	started := time.Now()
	if verbose || outputFmt == "text" {
		fmt.Fprintf(os.Stderr, "[glitchfuzz] Mode    : %s\n", mode)
		fmt.Fprintf(os.Stderr, "[glitchfuzz] Target  : %s\n", targetURL)
		fmt.Fprintf(os.Stderr, "[glitchfuzz] Words   : %d\n", len(words))
		fmt.Fprintf(os.Stderr, "[glitchfuzz] Threads : %d\n", concurrency)
	}

	var results []FuzzResult
	switch mode {
	case "dir":
		results = fuzzDir(client, targetURL, words, concurrency, delayMS, filter, verbose, headers)
	case "param":
		results = fuzzParam(client, targetURL, words, concurrency, delayMS, filter, verbose, headers)
	case "vhost":
		domain := *vhostDomain
		if domain == "" {
			// Extract domain from URL
			parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(targetURL, "https://"), "http://"), "/")
			domain = parts[0]
		}
		results = fuzzVhost(client, targetURL, domain, words, concurrency, delayMS, verbose, headers)
	}

	finished := time.Now()
	duration := finished.Sub(started).Milliseconds()

	var reqCount int64 = int64(len(words))
	var rps float64
	if duration > 0 {
		rps = float64(reqCount) / (float64(duration) / 1000.0)
	}

	findings := generateFindings(results, mode, targetURL)

	output := Output{
		Tool:     "glitchfuzz",
		Version:  "1.0.0",
		Target:   targetURL,
		Mode:     mode,
		Started:  started.UTC().Format(time.RFC3339),
		Finished: finished.UTC().Format(time.RFC3339),
		Results:  results,
		Findings: findings,
		Stats: Stats{
			Mode:         mode,
			WordlistSize: len(words),
			Requests:     reqCount,
			Hits:         len(results),
			DurationMS:   duration,
			ReqPerSec:    rps,
			Concurrency:  concurrency,
		},
		ExitCode: 0,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(output)
}
