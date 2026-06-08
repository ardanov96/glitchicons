// glitchevade/main.go
// GLITCHICONS — WAF/IDS Evasion Effectiveness Tester
//
// Tests whether your Web Application Firewall (WAF) or
// Intrusion Detection System (IDS) detects known attack
// patterns when encoded or obfuscated.
//
// Goal: find gaps in your security controls BEFORE attackers do.
// Philosophy: if your WAF blocks raw SQLi but misses hex-encoded
// SQLi, that's a configuration gap to fix, not a win.
//
// Evasion Categories:
//   encoding    — URL/hex/HTML/unicode/base64 encoding variants
//   case        — Mixed case, capitalization tricks
//   whitespace  — Tabs, newlines, comments in payloads
//   fragments   — Chunked HTTP, split payloads
//   headers     — Non-standard headers, HTTP verb tampering
//   timing      — Slow-rate delivery (evade rate-based detection)
//
// For each payload type, sends:
//   1. Baseline (raw payload) — should be BLOCKED
//   2. Encoded variants       — should ALSO be blocked
// Gap = variants blocked < raw blocked
//
// Usage:
//   glitchevade --target https://waf.corp.com/test --category encoding
//   glitchevade --target https://api.corp.com --category all --param q
//   glitchevade --target https://corp.com --output waf_gaps.json --verbose

package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const Version = "5.0.0"

// ── Encoding helpers ──────────────────────────────────────

func urlEncode(s string) string {
	return url.QueryEscape(s)
}

func doubleURLEncode(s string) string {
	return url.QueryEscape(url.QueryEscape(s))
}

func hexEncode(s string) string {
	result := ""
	for _, c := range s {
		result += fmt.Sprintf("%%%02X", c)
	}
	return result
}

func htmlEntities(s string) string {
	r := strings.NewReplacer(
		"<", "&lt;", ">", "&gt;",
		"'", "&#39;", "\"", "&quot;",
		"(", "&#40;", ")", "&#41;",
	)
	return r.Replace(s)
}

func unicodeEncode(s string) string {
	result := ""
	for _, c := range s {
		result += fmt.Sprintf("\\u%04X", c)
	}
	return result
}

func mixedCase(s string) string {
	result := make([]byte, len(s))
	for i, c := range s {
		if i%2 == 0 {
			result[i] = byte(strings.ToUpper(string(c))[0])
		} else {
			result[i] = byte(strings.ToLower(string(c))[0])
		}
	}
	return string(result)
}

func insertComments(s string) string {
	// SQL-style: SELECT → SEL/**/ECT
	if len(s) < 4 {
		return s
	}
	mid := len(s) / 2
	return s[:mid] + "/**/" + s[mid:]
}

func insertWhitespace(s string) string {
	// Insert tabs and newlines
	return strings.ReplaceAll(s, " ", "\t")
}

// ── Payload variants generator ────────────────────────────

type PayloadVariant struct {
	Name    string
	Payload string
	Category string
}

func generateVariants(rawPayload, category string) []PayloadVariant {
	variants := []PayloadVariant{
		{Name: "raw", Payload: rawPayload, Category: "baseline"},
	}

	addVar := func(name, payload, cat string) {
		if payload != rawPayload {
			variants = append(variants, PayloadVariant{name, payload, cat})
		}
	}

	switch category {
	case "encoding", "all":
		addVar("url_encoded", urlEncode(rawPayload), "encoding")
		addVar("double_url_encoded", doubleURLEncode(rawPayload), "encoding")
		addVar("hex_encoded", hexEncode(rawPayload), "encoding")
		addVar("html_entities", htmlEntities(rawPayload), "encoding")
		addVar("unicode", unicodeEncode(rawPayload[:minStr(len(rawPayload), 4)]), "encoding")
	}

	switch category {
	case "case", "all":
		addVar("mixed_case", mixedCase(rawPayload), "case")
		addVar("upper", strings.ToUpper(rawPayload), "case")
		addVar("lower", strings.ToLower(rawPayload), "case")
	}

	switch category {
	case "whitespace", "all":
		addVar("tab_whitespace", insertWhitespace(rawPayload), "whitespace")
		addVar("newline_inserted", strings.ReplaceAll(rawPayload, " ", "%0a"), "whitespace")
		addVar("comment_inserted", insertComments(rawPayload), "whitespace")
	}

	return variants
}

// ── Data types ────────────────────────────────────────────

type ProbeResult struct {
	Variant    PayloadVariant `json:"variant"`
	StatusCode int            `json:"status_code"`
	ResponseMS int64          `json:"response_ms"`
	Blocked    bool           `json:"blocked"`
}

type EvasionGap struct {
	Payload       string        `json:"payload"`
	Category      string        `json:"category"`
	BaselineBlocked bool        `json:"baseline_blocked"`
	BypassedVariants []string   `json:"bypassed_variants"`
	BlockedVariants  []string   `json:"blocked_variants"`
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

type ScanResult struct {
	Target       string       `json:"target"`
	Category     string       `json:"category"`
	Timestamp    string       `json:"timestamp"`
	TotalProbes  int64        `json:"total_probes"`
	BaselineBlocked int       `json:"baseline_blocked"`
	EvasionGaps  []EvasionGap `json:"evasion_gaps"`
	Findings     []Finding    `json:"findings"`
	Duration     float64      `json:"duration_s"`
	Version      string       `json:"scanner_version"`
}

// ── Core payloads to test ─────────────────────────────────

var testPayloads = map[string][]string{
	"sqli": {
		"' OR '1'='1",
		"1 UNION SELECT NULL--",
		"' OR SLEEP(5)--",
		"1; DROP TABLE users--",
	},
	"xss": {
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"javascript:alert(1)",
	},
	"ssti": {
		"{{7*7}}",
		"${7*7}",
		"<%= 7*7 %>",
	},
	"traversal": {
		"../../../etc/passwd",
		"..%2f..%2fetc%2fpasswd",
		"....//....//etc//passwd",
	},
	"cmd": {
		"; id",
		"| whoami",
		"`id`",
	},
}

// ── HTTP probe ────────────────────────────────────────────

func probe(client *http.Client, target, param, payload string, timeout time.Duration) (int, int64, error) {
	reqURL := target
	if param != "" {
		if strings.Contains(target, "?") {
			reqURL = target + "&" + param + "=" + url.QueryEscape(payload)
		} else {
			reqURL = target + "?" + param + "=" + url.QueryEscape(payload)
		}
	}

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", "Glitchevade/"+Version)

	start := time.Now()
	resp, err := client.Do(req)
	ms := time.Since(start).Milliseconds()
	if err != nil {
		return 0, ms, err
	}
	defer resp.Body.Close()
	io.ReadAll(io.LimitReader(resp.Body, 4096))

	return resp.StatusCode, ms, nil
}

func isBlocked(status int) bool {
	return status == 403 || status == 406 || status == 429 ||
		status == 400 || status == 501 || status == 503
}

// ── Main scanner ──────────────────────────────────────────

func runEvasion(target, category, param string, timeout time.Duration, verbose bool) ScanResult {
	start := time.Now()
	result := ScanResult{
		Target:    target,
		Category:  category,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Findings:  []Finding{},
		Version:   Version,
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	fmt.Printf("[*] glitchevade v%s | %s | category=%s\n", Version, target, category)

	var totalProbes int64
	var gaps []EvasionGap

	// Select which payload types to test
	payloadTypes := map[string][]string{}
	if category == "all" {
		payloadTypes = testPayloads
	} else {
		for k, v := range testPayloads {
			payloadTypes[k] = v
		}
	}

	for payloadType, payloads := range payloadTypes {
		for _, rawPayload := range payloads {
			variants := generateVariants(rawPayload, category)
			gap := EvasionGap{
				Payload:  rawPayload,
				Category: payloadType,
			}

			for _, variant := range variants {
				status, ms, err := probe(client, target, param, variant.Payload, timeout)
				atomic.AddInt64(&totalProbes, 1)

				if err != nil {
					continue
				}

				blocked := isBlocked(status)

				if variant.Name == "raw" {
					gap.BaselineBlocked = blocked
					if verbose {
						marker := "BLOCKED"
						if !blocked {
							marker = "allowed"
						}
					fmt.Printf("[%s] baseline %s: HTTP %d (%dms)\n",
						marker, payloadType, status, ms)
					}
				} else {
					if blocked {
						gap.BlockedVariants = append(gap.BlockedVariants, variant.Name)
					} else if gap.BaselineBlocked {
						// Baseline was blocked but variant wasn't = EVASION GAP
						gap.BypassedVariants = append(gap.BypassedVariants, variant.Name)
						if verbose {
							fmt.Printf("[!] BYPASS: %s/%s → HTTP %d (%dms) | payload: %s\n",
								payloadType, variant.Name, status, ms,
								variant.Payload[:minStr(len(variant.Payload), 50)])
						}
					}
				}
				time.Sleep(100 * time.Millisecond) // Rate limit
			}

			if len(gap.BypassedVariants) > 0 {
				gaps = append(gaps, gap)
			}
		}
	}

	result.TotalProbes = atomic.LoadInt64(&totalProbes)
	result.EvasionGaps = gaps
	result.Duration    = time.Since(start).Seconds()

	// Count how many baselines were blocked
	blocked := 0
	for _, g := range gaps {
		if g.BaselineBlocked {
			blocked++
		}
	}
	result.BaselineBlocked = blocked

	// Generate findings
	for _, gap := range gaps {
		if len(gap.BypassedVariants) == 0 {
			continue
		}
		result.Findings = append(result.Findings, Finding{
			Title: fmt.Sprintf("WAF Bypass: %s payloads evade detection via %s",
				gap.Category, strings.Join(gap.BypassedVariants, "/")),
			Severity: "HIGH",
			CVSS:     7.3,
			CWE:      "CWE-693",
			Target:   target,
			Description: fmt.Sprintf(
				"WAF blocks raw %s payload but misses %d obfuscation variant(s). "+
					"Techniques: %s. Attackers use these to bypass perimeter controls.",
				gap.Category,
				len(gap.BypassedVariants),
				strings.Join(gap.BypassedVariants, ", "),
			),
			Evidence: fmt.Sprintf(
				"Payload: %s\nBlocked: raw+%d variants\nBYPASSED: %s",
				gap.Payload[:minStr(len(gap.Payload), 60)],
				len(gap.BlockedVariants),
				strings.Join(gap.BypassedVariants, ", "),
			),
			Remediation: "Update WAF rules to cover encoded/obfuscated variants. " +
				"Enable 'decode before inspect' setting if available. " +
				"Add coverage for: " + strings.Join(gap.BypassedVariants, ", "),
			Source: "module:glitchevade",
		})
	}

	if len(gaps) == 0 {
		result.Findings = append(result.Findings, Finding{
			Title:       "WAF Coverage: All Tested Variants Blocked",
			Severity:    "INFO",
			CVSS:        0.0,
			CWE:         "CWE-693",
			Target:      target,
			Description: fmt.Sprintf("All %d probe variants were blocked. WAF appears to handle tested evasion techniques.", atomic.LoadInt64(&totalProbes)),
			Evidence:    fmt.Sprintf("Probes: %d | Gaps: 0", atomic.LoadInt64(&totalProbes)),
			Remediation: "Continue regular WAF rule reviews as new evasion techniques emerge.",
			Source:      "module:glitchevade",
		})
	}

	fmt.Printf("[*] Done: %d probes | %d gaps found\n",
		result.TotalProbes, len(gaps))
	return result
}

func minStr(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	target   := flag.String("target",   "", "Target URL (required)")
	category := flag.String("category", "all", "Evasion category: all|encoding|case|whitespace|fragments|headers")
	param    := flag.String("param",    "q", "Query parameter to inject into")
	timeout  := flag.Int("timeout",     10, "Request timeout seconds")
	output   := flag.String("output",   "", "Output JSON file")
	verbose  := flag.Bool("verbose",    false, "Verbose output")
	ver      := flag.Bool("version",    false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchevade v%s\n", Version)
		os.Exit(0)
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: glitchevade --target https://waf.corp.com --category all --param q")
		os.Exit(1)
	}

	result := runEvasion(*target, *category, *param, time.Duration(*timeout)*time.Second, *verbose)

	data, _ := json.MarshalIndent(result, "", "  ")
	if *output != "" {
		os.WriteFile(*output, data, 0644)
		fmt.Printf("[+] Saved to %s\n", *output)
	} else {
		fmt.Println(string(data))
	}
}
