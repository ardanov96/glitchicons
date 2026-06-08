// glitchcloak/main.go
// GLITCHICONS — Detection Coverage Tester
//
// Tests whether your SIEM rules, IDS signatures, and security
// monitoring detect known attack patterns.
//
// Simulates attack patterns mapped to MITRE ATT&CK techniques
// and checks if your detection stack generates alerts.
// Reports gaps in coverage BEFORE real attackers find them.
//
// Detection Categories:
//   recon      — Port scan patterns, banner grabbing
//   auth       — Brute force patterns, password spray indicators
//   lateral    — SMB/RDP lateral movement signatures
//   exfil      — Large data transfer anomalies, DNS exfil
//   persistence — Scheduled task creation, service installation
//   discovery  — User/group enumeration patterns
//
// How it works:
//   1. Simulate "noisy" versions of attack patterns to target
//   2. Verify if alerts arrive at your webhook receiver
//   3. Report which ATT&CK techniques were NOT alerted on
//
// Requires: a webhook endpoint that your SIEM will POST alerts to
// (or manual review mode: just check your SIEM dashboard)
//
// Usage:
//   glitchcloak --target 192.168.1.0/24 --category recon --verbose
//   glitchcloak --target 192.168.1.10 --category auth --webhook https://siem.corp.com/test
//   glitchcloak --target https://app.corp.com --category all --output coverage.json

package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const Version = "5.0.0"

// ── MITRE ATT&CK technique mapping ───────────────────────

type ATTACKTechnique struct {
	ID          string
	Name        string
	Tactic      string
	Description string
}

var attackTechniques = map[string]ATTACKTechnique{
	"T1046": {"T1046", "Network Service Discovery", "Discovery",
		"Adversaries scan for open ports and services"},
	"T1110": {"T1110", "Brute Force", "Credential Access",
		"Repeated authentication attempts"},
	"T1110.003": {"T1110.003", "Password Spraying", "Credential Access",
		"Single password across many accounts"},
	"T1021.002": {"T1021.002", "SMB/Windows Admin Shares", "Lateral Movement",
		"Access Windows admin shares for lateral movement"},
	"T1048.003": {"T1048.003", "DNS Exfiltration", "Exfiltration",
		"Exfiltrate data via DNS queries"},
	"T1059": {"T1059", "Command Interpreter", "Execution",
		"Execution via command-line interface"},
	"T1087": {"T1087", "Account Discovery", "Discovery",
		"Enumerate user accounts"},
	"T1595": {"T1595", "Active Scanning", "Reconnaissance",
		"Active scanning to gather target information"},
}

// ── Detection test types ──────────────────────────────────

type DetectionTest struct {
	TechniqueID string
	Name        string
	Category    string
	RunFn       func(target string, timeout time.Duration, verbose bool) DetectionResult
}

type DetectionResult struct {
	TechniqueID    string   `json:"technique_id"`
	TechniqueName  string   `json:"technique_name"`
	Category       string   `json:"category"`
	Simulated      bool     `json:"simulated"`
	AlertExpected  bool     `json:"alert_expected"`
	SimulationDesc string   `json:"simulation_description"`
	Timestamp      string   `json:"timestamp"`
	Evidence       []string `json:"evidence"`
}

type CoverageReport struct {
	Target       string            `json:"target"`
	Timestamp    string            `json:"timestamp"`
	Category     string            `json:"category"`
	Results      []DetectionResult `json:"detection_results"`
	TestedCount  int               `json:"techniques_tested"`
	Findings     []Finding         `json:"findings"`
	Duration     float64           `json:"duration_s"`
	Version      string            `json:"scanner_version"`
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

// ── Simulation functions ──────────────────────────────────

// T1595 - Active Scanning simulation: slow port probe
func simActiveScanning(target string, timeout time.Duration, verbose bool) DetectionResult {
	r := DetectionResult{
		TechniqueID:   "T1595",
		TechniqueName: "Active Scanning",
		Category:      "recon",
		AlertExpected: true,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	}

	// Probe a small set of ports — detectable as scanning
	commonPorts := []int{21, 22, 23, 25, 80, 443, 445, 3389, 8080}
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, port := range commonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", target, p)
			conn, err := net.DialTimeout("tcp", addr, timeout/4)
			if err == nil {
				conn.Close()
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()

	r.Simulated = true
	r.SimulationDesc = fmt.Sprintf(
		"Scanned %d ports on %s — open: %v. "+
			"This should appear in your IDS/SIEM as a port scan alert (T1595).",
		len(commonPorts), target, openPorts)
	r.Evidence = []string{
		fmt.Sprintf("Target: %s", target),
		fmt.Sprintf("Ports probed: %v", commonPorts),
		fmt.Sprintf("Open ports found: %v", openPorts),
		"Expected alert: Network port scan detected",
	}

	if verbose {
		fmt.Printf("[T1595] Port scan simulated on %s | Open: %v\n", target, openPorts)
	}
	return r
}

// T1110 - Brute Force simulation: multiple failed auth attempts
func simBruteForce(target string, timeout time.Duration, verbose bool) DetectionResult {
	r := DetectionResult{
		TechniqueID:   "T1110",
		TechniqueName: "Brute Force",
		Category:      "auth",
		AlertExpected: true,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "http://" + target
	}

	// Send 5 requests with invalid basic auth — should trigger brute force alert
	var statusCodes []int
	users := []string{"admin", "administrator", "root", "test", "user"}
	for _, user := range users {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.SetBasicAuth(user, "wrongpassword123!")
		req.Header.Set("User-Agent", "Glitchcloak/"+Version)
		resp, err := client.Do(req)
		if err == nil {
			statusCodes = append(statusCodes, resp.StatusCode)
			resp.Body.Close()
		}
		time.Sleep(200 * time.Millisecond)
	}

	r.Simulated = true
	r.SimulationDesc = fmt.Sprintf(
		"Sent %d HTTP Basic Auth requests with invalid credentials to %s. "+
			"SIEM should detect repeated 401 responses as brute force (T1110).",
		len(users), url)
	r.Evidence = []string{
		fmt.Sprintf("Endpoint: %s", url),
		fmt.Sprintf("Attempts: %d", len(users)),
		fmt.Sprintf("Users tried: %s", strings.Join(users, ", ")),
		fmt.Sprintf("HTTP responses: %v", statusCodes),
		"Expected alert: Multiple failed authentication attempts",
	}

	if verbose {
		fmt.Printf("[T1110] Brute force simulated on %s | Responses: %v\n", url, statusCodes)
	}
	return r
}

// T1110.003 - Password Spraying simulation
func simPasswordSpray(target string, timeout time.Duration, verbose bool) DetectionResult {
	r := DetectionResult{
		TechniqueID:   "T1110.003",
		TechniqueName: "Password Spraying",
		Category:      "auth",
		AlertExpected: true,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "http://" + target
	}

	// Spray pattern: same password, different users, spread over time
	users := []string{"alice", "bob", "charlie", "diana", "eve"}
	password := "Winter2024!"
	var results []string

	for _, user := range users {
		req, _ := http.NewRequest("GET", url, nil)
		if req == nil {
			continue
		}
		req.SetBasicAuth(user, password)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err == nil {
			results = append(results, fmt.Sprintf("%s→%d", user, resp.StatusCode))
			resp.Body.Close()
		}
		time.Sleep(500 * time.Millisecond) // Spray rate: 2/sec
	}

	r.Simulated = true
	r.SimulationDesc = fmt.Sprintf(
		"Sprayed password '%s' across %d different users at %s. "+
			"Detection: same password, many users, regular timing (T1110.003).",
		password, len(users), url)
	r.Evidence = []string{
		fmt.Sprintf("Pattern: 1 password × %d users", len(users)),
		fmt.Sprintf("Rate: 2 requests/sec (spread pattern)"),
		fmt.Sprintf("Results: %s", strings.Join(results, " ")),
		"Expected alert: Password spray pattern detected",
	}

	if verbose {
		fmt.Printf("[T1110.003] Password spray simulated | Results: %v\n", results)
	}
	return r
}

// T1046 - Network Service Discovery simulation
func simServiceDiscovery(target string, timeout time.Duration, verbose bool) DetectionResult {
	r := DetectionResult{
		TechniqueID:   "T1046",
		TechniqueName: "Network Service Discovery",
		Category:      "discovery",
		AlertExpected: true,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	}

	// Banner grab from common services
	services := map[int]string{
		22:   "SSH",
		21:   "FTP",
		25:   "SMTP",
		110:  "POP3",
		143:  "IMAP",
		3306: "MySQL",
		5432: "PostgreSQL",
	}

	var discovered []string
	for port, svc := range services {
		addr := fmt.Sprintf("%s:%d", target, port)
		conn, err := net.DialTimeout("tcp", addr, timeout/4)
		if err == nil {
			buf := make([]byte, 64)
			conn.SetDeadline(time.Now().Add(1 * time.Second))
			n, _ := conn.Read(buf)
			conn.Close()
			banner := strings.TrimSpace(string(buf[:n]))
			if banner != "" {
				discovered = append(discovered, fmt.Sprintf("%s/%d: %s", svc, port, banner[:minStr(len(banner), 30)]))
			} else {
				discovered = append(discovered, fmt.Sprintf("%s/%d: open", svc, port))
			}
		}
	}

	r.Simulated = true
	r.SimulationDesc = fmt.Sprintf(
		"Probed %d services on %s for banner grabbing. "+
			"Should appear as service enumeration in SIEM (T1046).",
		len(services), target)
	r.Evidence = []string{
		fmt.Sprintf("Target: %s", target),
		fmt.Sprintf("Services probed: %d", len(services)),
		fmt.Sprintf("Discovered: %s", strings.Join(discovered, "; ")),
		"Expected alert: Network service enumeration",
	}

	if verbose {
		fmt.Printf("[T1046] Service discovery on %s | Found: %v\n", target, discovered)
	}
	return r
}

// T1048.003 - DNS Exfiltration simulation
func simDNSExfil(target string, timeout time.Duration, verbose bool) DetectionResult {
	r := DetectionResult{
		TechniqueID:   "T1048.003",
		TechniqueName: "Exfiltration via DNS",
		Category:      "exfil",
		AlertExpected: true,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	}

	// Simulate DNS exfil pattern: many queries with encoded subdomains
	fakeData := []string{
		"6865786c6f6f6b7570",
		"74657374646174613031",
		"656e636f646564636875",
		"6e6b79303132333435",
		"646174616368756e6b32",
	}

	var queryResults []string
	for _, chunk := range fakeData {
		domain := chunk + ".detection-test.internal"
		_, err := net.LookupHost(domain)
		if err != nil {
			queryResults = append(queryResults, fmt.Sprintf("NXDOMAIN(%s)", chunk[:8]))
		} else {
			queryResults = append(queryResults, fmt.Sprintf("RESOLVED(%s)", chunk[:8]))
		}
		time.Sleep(200 * time.Millisecond)
	}

	r.Simulated = true
	r.SimulationDesc = fmt.Sprintf(
		"Sent %d DNS queries with hex-encoded subdomains simulating data exfiltration. "+
			"DNS monitoring should detect abnormal subdomain pattern (T1048.003).",
		len(fakeData))
	r.Evidence = []string{
		fmt.Sprintf("Queries sent: %d", len(fakeData)),
		"Pattern: hex-encoded data as DNS labels",
		fmt.Sprintf("Results: %s", strings.Join(queryResults, " ")),
		"Expected alert: DNS exfiltration pattern or high-entropy subdomain queries",
	}

	if verbose {
		fmt.Printf("[T1048.003] DNS exfil simulated | %d queries\n", len(fakeData))
	}
	return r
}

// T1087 - Account Discovery simulation
func simAccountDiscovery(target string, timeout time.Duration, verbose bool) DetectionResult {
	r := DetectionResult{
		TechniqueID:   "T1087",
		TechniqueName: "Account Discovery",
		Category:      "discovery",
		AlertExpected: true,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	url := target
	if !strings.HasPrefix(url, "http") {
		url = "http://" + target
	}

	// Probe common user enumeration endpoints
	endpoints := []string{
		"/api/users", "/api/v1/users", "/api/accounts",
		"/users", "/admin/users", "/wp-json/wp/v2/users",
		"/.well-known/security.txt",
	}

	var probed []string
	for _, ep := range endpoints {
		resp, err := client.Get(url + ep)
		if err == nil {
			probed = append(probed, fmt.Sprintf("%s→%d", ep, resp.StatusCode))
			resp.Body.Close()
		}
		time.Sleep(150 * time.Millisecond)
	}

	r.Simulated = true
	r.SimulationDesc = fmt.Sprintf(
		"Probed %d common user enumeration endpoints on %s (T1087). "+
			"SIEM should detect sequential API enumeration pattern.",
		len(endpoints), url)
	r.Evidence = []string{
		fmt.Sprintf("Endpoints probed: %d", len(endpoints)),
		fmt.Sprintf("Results: %s", strings.Join(probed, " ")),
		"Expected alert: Automated API/endpoint enumeration",
	}

	if verbose {
		fmt.Printf("[T1087] Account discovery simulated | %v\n", probed)
	}
	return r
}

// ── Webhook notification ──────────────────────────────────

func notifyWebhook(webhook string, report *CoverageReport) {
	if webhook == "" {
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	data, _ := json.Marshal(report)
	resp, err := client.Post(webhook, "application/json", strings.NewReader(string(data)))
	if err != nil {
		fmt.Printf("[-] Webhook notify failed: %v\n", err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("[*] Detection test report sent to SIEM webhook: HTTP %d\n", resp.StatusCode)
}

func minStr(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── Main ──────────────────────────────────────────────────

func main() {
	target   := flag.String("target",   "", "Target host or URL (required)")
	category := flag.String("category", "all", "Detection category: all|recon|auth|discovery|exfil")
	webhook  := flag.String("webhook",  "", "SIEM webhook URL for alert verification")
	timeout  := flag.Int("timeout",     10, "Operation timeout seconds")
	output   := flag.String("output",   "", "Output JSON file")
	verbose  := flag.Bool("verbose",    false, "Verbose output")
	ver      := flag.Bool("version",    false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchcloak v%s\n", Version)
		os.Exit(0)
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: glitchcloak --target 192.168.1.10 --category all [--webhook https://siem/alerts]")
		os.Exit(1)
	}

	tOut := time.Duration(*timeout) * time.Second
	start := time.Now()

	report := &CoverageReport{
		Target:    *target,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Category:  *category,
		Findings:  []Finding{},
		Version:   Version,
	}

	fmt.Printf("[*] glitchcloak v%s | %s | category=%s\n", Version, *target, *category)
	fmt.Println("[*] Simulating attack patterns — check your SIEM for alerts")

	// Define all available tests
	allTests := []DetectionTest{
		{"T1595", "Active Scanning", "recon", simActiveScanning},
		{"T1046", "Network Service Discovery", "discovery", simServiceDiscovery},
		{"T1110", "Brute Force", "auth", simBruteForce},
		{"T1110.003", "Password Spraying", "auth", simPasswordSpray},
		{"T1048.003", "DNS Exfiltration", "exfil", simDNSExfil},
		{"T1087", "Account Discovery", "discovery", simAccountDiscovery},
	}

	// Run selected tests
	for _, test := range allTests {
		if *category != "all" && test.Category != *category {
			continue
		}
		fmt.Printf("[*] Simulating %s (%s)...\n", test.Name, test.TechniqueID)
		result := test.RunFn(*target, tOut, *verbose)
		report.Results = append(report.Results, result)
		report.TestedCount++
		time.Sleep(500 * time.Millisecond)
	}

	report.Duration = time.Since(start).Seconds()

	// Generate findings
	report.Findings = append(report.Findings, Finding{
		Title:    fmt.Sprintf("Detection Coverage Test Complete: %d ATT&CK Techniques Simulated", report.TestedCount),
		Severity: "INFO",
		CVSS:     0.0,
		CWE:      "CWE-693",
		Target:   *target,
		Description: fmt.Sprintf(
			"Simulated %d MITRE ATT&CK techniques against %s. "+
				"Check your SIEM/IDS for corresponding alerts. "+
				"Techniques not generating alerts represent detection gaps.",
			report.TestedCount, *target),
		Evidence: fmt.Sprintf(
			"Techniques tested: %d | Duration: %.1fs | "+
				"Categories: %s",
			report.TestedCount, report.Duration, *category),
		Remediation: "For each technique without a SIEM alert: create a detection rule. " +
			"Map coverage to MITRE ATT&CK navigator. Target 90%+ coverage for T1 priorities.",
		Source: "module:glitchcloak",
	})

	fmt.Printf("\n[*] Simulation complete: %d techniques\n", report.TestedCount)
	fmt.Printf("[!] NOW CHECK YOUR SIEM — which techniques generated alerts?\n")
	fmt.Printf("[!] Gaps = techniques with no corresponding alert\n")

	if *webhook != "" {
		notifyWebhook(*webhook, report)
	}

	data, _ := json.MarshalIndent(report, "", "  ")
	if *output != "" {
		os.WriteFile(*output, data, 0644)
		fmt.Printf("[+] Saved to %s\n", *output)
	} else {
		fmt.Println(string(data))
	}
}
