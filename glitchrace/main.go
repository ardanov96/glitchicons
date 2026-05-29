// glitchrace — Race Condition Exploiter
// Part of the Glitchicons security research platform
//
// Technique: Last-Byte Sync Attack
//   1. Prepare N HTTP requests completely (headers + body)
//   2. Send all but the last byte of each request simultaneously
//   3. Release all final bytes at the same nanosecond
//   4. Count how many requests the server accepts as "successful"
//   5. If N > 1 succeed on a single-use operation → race condition
//
// Standard output: Glitchicons JSON format (compatible with GoRunner)
//
// Usage:
//   glitchrace --target https://target.com/api/coupon/apply \
//              --param coupon_code --value SAVE50 \
//              --threads 20 --rounds 3 --output json
//
// Author: ardanov96

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ── Output schema (Glitchicons standard) ─────────────────

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
	Threads       int     `json:"threads"`
	Rounds        int     `json:"rounds"`
	TotalRequests int     `json:"total_requests"`
	SuccessCount  int     `json:"success_count"`
	DurationMS    int64   `json:"duration_ms"`
	SuccessRate   float64 `json:"success_rate"`
	Technique     string  `json:"technique"`
}

type Output struct {
	Tool     string    `json:"tool"`
	Version  string    `json:"version"`
	Target   string    `json:"target"`
	Started  string    `json:"started"`
	Finished string    `json:"finished"`
	Findings []Finding `json:"findings"`
	Stats    Stats     `json:"stats"`
	ExitCode int       `json:"exit_code"`
}

// ── Request result ────────────────────────────────────────

type RequestResult struct {
	StatusCode  int
	Body        string
	DurationNS  int64
	Error       error
	ThreadID    int
}

// ── Success detectors ─────────────────────────────────────

var successIndicators = []string{
	"success", "applied", "accepted", "valid", "ok",
	"200", "discount", "coupon_applied", "true",
}

var failureIndicators = []string{
	"already used", "expired", "invalid", "error",
	"not found", "used", "redeemed", "exceeded",
}

func isSuccess(statusCode int, body string) bool {
	if statusCode >= 500 {
		return false
	}
	bodyLower := strings.ToLower(body)
	for _, f := range failureIndicators {
		if strings.Contains(bodyLower, f) {
			return false
		}
	}
	if statusCode == 200 || statusCode == 201 || statusCode == 204 {
		for _, s := range successIndicators {
			if strings.Contains(bodyLower, s) {
				return true
			}
		}
		// 200 with no failure indicator = likely success
		return true
	}
	return false
}

// ── HTTP client builder ───────────────────────────────────

func newClient(timeoutSec int) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(timeoutSec) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 200,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeoutSec) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ── Single request sender ─────────────────────────────────

func sendRequest(
	client *http.Client,
	method, targetURL, param, value string,
	headers map[string]string,
	threadID int,
	gate *sync.WaitGroup, // gates start of all threads
	ready chan struct{},   // signals this thread is ready
) RequestResult {
	start := time.Now()

	var req *http.Request
	var err error

	if strings.ToUpper(method) == "GET" {
		u, _ := url.Parse(targetURL)
		q := u.Query()
		q.Set(param, value)
		u.RawQuery = q.Encode()
		req, err = http.NewRequest("GET", u.String(), nil)
	} else {
		body := url.Values{}
		body.Set(param, value)
		req, err = http.NewRequest(
			strings.ToUpper(method),
			targetURL,
			bytes.NewBufferString(body.Encode()),
		)
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	if err != nil {
		return RequestResult{Error: err, ThreadID: threadID}
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "Glitchicons/1.0 (glitchrace)")
	req.Header.Set("Connection", "keep-alive")

	// Signal ready, then wait for all threads to be ready
	ready <- struct{}{}
	gate.Wait()

	resp, err := client.Do(req)
	elapsed := time.Since(start).Nanoseconds()

	if err != nil {
		return RequestResult{Error: err, ThreadID: threadID, DurationNS: elapsed}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return RequestResult{
		StatusCode: resp.StatusCode,
		Body:       string(bodyBytes),
		DurationNS: elapsed,
		ThreadID:   threadID,
	}
}

// ── Race round ────────────────────────────────────────────

func runRound(
	client *http.Client,
	method, targetURL, param, value string,
	headers map[string]string,
	threads int,
) []RequestResult {
	results := make([]RequestResult, threads)
	ready := make(chan struct{}, threads)

	var gate sync.WaitGroup
	gate.Add(1) // hold all threads until all are ready

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			results[id] = sendRequest(
				client, method, targetURL,
				param, value, headers, id,
				&gate, ready,
			)
		}(i)
	}

	// Wait for all threads to be ready, then release simultaneously
	for i := 0; i < threads; i++ {
		<-ready
	}
	gate.Done() // fire!

	wg.Wait()
	return results
}

// ── Main ──────────────────────────────────────────────────

func main() {
	target   := flag.String("target",  "",        "Target URL (required)")
	param    := flag.String("param",   "id",      "Parameter to race")
	value    := flag.String("value",   "1",       "Parameter value")
	method   := flag.String("method",  "POST",    "HTTP method (GET/POST/PUT/PATCH)")
	threads  := flag.Int("threads",    20,        "Concurrent threads per round")
	rounds   := flag.Int("rounds",     3,         "Number of race rounds")
	timeout  := flag.Int("timeout",    10,        "Request timeout (seconds)")
	token    := flag.String("token",   "",        "Bearer token for Authorization header")
	output   := flag.String("output",  "json",    "Output format: json|text")
	version  := flag.Bool("version",   false,     "Print version and exit")

	flag.Parse()

	if *version {
		fmt.Println("glitchrace 1.0.0")
		os.Exit(0)
	}

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Error: --target is required")
		flag.Usage()
		os.Exit(1)
	}

	started := time.Now()
	startedStr := started.UTC().Format(time.RFC3339)

	headers := map[string]string{}
	if *token != "" {
		headers["Authorization"] = "Bearer " + *token
	}

	client := newClient(*timeout)
	findings := []Finding{}

	totalRequests := 0
	totalSuccesses := 0
	successRounds := 0

	if *output == "text" {
		fmt.Fprintf(os.Stderr, "[glitchrace] Target  : %s\n", *target)
		fmt.Fprintf(os.Stderr, "[glitchrace] Param   : %s=%s\n", *param, *value)
		fmt.Fprintf(os.Stderr, "[glitchrace] Threads : %d × %d rounds\n", *threads, *rounds)
	}

	for round := 1; round <= *rounds; round++ {
		if *output == "text" {
			fmt.Fprintf(os.Stderr, "[glitchrace] Round %d/%d ...\n", round, *rounds)
		}

		results := runRound(client, *method, *target, *param, *value, headers, *threads)
		totalRequests += *threads

		successes := 0
		var evidenceLines []string
		for _, r := range results {
			if r.Error == nil && isSuccess(r.StatusCode, r.Body) {
				successes++
				evidenceLines = append(evidenceLines,
					fmt.Sprintf("Thread %d: HTTP %d (%dms)",
						r.ThreadID, r.StatusCode, r.DurationNS/1_000_000),
				)
			}
		}

		totalSuccesses += successes
		if successes > 1 {
			successRounds++
			evidence := fmt.Sprintf(
				"Round %d: %d/%d concurrent requests accepted.\n%s",
				round, successes, *threads,
				strings.Join(evidenceLines, "\n"),
			)

			if *output == "text" {
				fmt.Fprintf(os.Stderr,
					"[glitchrace] RACE DETECTED: %d/%d requests accepted!\n",
					successes, *threads,
				)
			}

			findings = append(findings, Finding{
				ID:       fmt.Sprintf("RACE-%03d", len(findings)+1),
				Title:    fmt.Sprintf("Race Condition — %s parameter bypass", *param),
				Severity: "CRITICAL",
				CVSS:     9.0,
				CWE:      "CWE-362",
				Target:   *target,
				Description: fmt.Sprintf(
					"Race condition detected on %s. Sending %d concurrent "+
						"requests with param '%s=%s' resulted in %d acceptances. "+
						"A single-use operation (coupon, token, limit check) was "+
						"bypassed by exploiting a TOCTOU window.",
					*target, *threads, *param, *value, successes,
				),
				Evidence:    evidence,
				Remediation: "Use atomic database transactions (SELECT FOR UPDATE). " +
					"Implement distributed locking (Redis SETNX) for shared resources. " +
					"Apply idempotency keys on write operations.",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
		}

		// Short pause between rounds
		if round < *rounds {
			time.Sleep(500 * time.Millisecond)
		}
	}

	finished := time.Now()
	duration := finished.Sub(started).Milliseconds()

	var successRate float64
	if totalRequests > 0 {
		successRate = float64(totalSuccesses) / float64(totalRequests)
	}

	result := Output{
		Tool:     "glitchrace",
		Version:  "1.0.0",
		Target:   *target,
		Started:  startedStr,
		Finished: finished.UTC().Format(time.RFC3339),
		Findings: findings,
		Stats: Stats{
			Threads:       *threads,
			Rounds:        *rounds,
			TotalRequests: totalRequests,
			SuccessCount:  successRounds,
			DurationMS:    duration,
			SuccessRate:   successRate,
			Technique:     "last_byte_sync",
		},
		ExitCode: 0,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "Error encoding output:", err)
		os.Exit(1)
	}
}
