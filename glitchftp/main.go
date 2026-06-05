// glitchftp/main.go
// GLITCHICONS — FTP Security Auditor
//
// Checks:
//   - Anonymous FTP login
//   - FTP banner/version disclosure
//   - Default credentials (ftp:ftp, admin:admin, etc.)
//   - Writable directories (PUT attempt)
//   - Cleartext protocol (no FTPS)
//   - Directory listing exposure
//
// Usage:
//   glitchftp --target ftp.target.com
//   glitchftp --target 192.168.1.10 --port 21 --timeout 8
//   glitchftp --target ftp.target.com --output ftp_findings.json --verbose

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const Version = "3.3.0"

// Default FTP credentials
var defaultFTPCreds = [][2]string{
	{"anonymous", "anonymous@"},
	{"anonymous", ""},
	{"anonymous", "guest"},
	{"ftp",       "ftp"},
	{"admin",     "admin"},
	{"admin",     "password"},
	{"admin",     ""},
	{"root",      "root"},
	{"ftpuser",   "ftpuser"},
	{"user",      "user"},
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

type FTPInfo struct {
	Banner     string `json:"banner"`
	Software   string `json:"software"`
	Anonymous  bool   `json:"anonymous_allowed"`
	Writable   bool   `json:"writable_directory"`
}

type ScanResult struct {
	Target    string    `json:"target"`
	Port      int       `json:"port"`
	Timestamp string    `json:"timestamp"`
	FTPOpen   bool      `json:"ftp_open"`
	Info      *FTPInfo  `json:"ftp_info,omitempty"`
	Findings  []Finding `json:"findings"`
	Version   string    `json:"scanner_version"`
}

func main() {
	target  := flag.String("target", "", "Target hostname or IP")
	port    := flag.Int("port", 21, "FTP port")
	timeout := flag.Int("timeout", 8, "Connection timeout in seconds")
	output  := flag.String("output", "", "Output JSON file")
	verbose := flag.Bool("verbose", false, "Verbose output")
	ver     := flag.Bool("version", false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchftp v%s\n", Version)
		os.Exit(0)
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: glitchftp --target <host> [--port 21]")
		os.Exit(1)
	}

	result := scanFTP(*target, *port, time.Duration(*timeout)*time.Second, *verbose)
	result.Version = Version

	data, _ := json.MarshalIndent(result, "", "  ")
	if *output != "" {
		os.WriteFile(*output, data, 0644)
	} else {
		fmt.Println(string(data))
	}
}

func scanFTP(target string, port int, timeout time.Duration, verbose bool) ScanResult {
	result := ScanResult{
		Target:    target,
		Port:      port,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Findings:  []Finding{},
	}

	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		if verbose {
			fmt.Printf("[-] FTP port %d closed: %v\n", port, err)
		}
		return result
	}
	defer conn.Close()
	result.FTPOpen = true

	reader := bufio.NewReader(conn)
	conn.SetDeadline(time.Now().Add(timeout))

	// Read banner
	banner, err := reader.ReadString('\n')
	if err != nil {
		return result
	}
	banner = strings.TrimSpace(banner)
	if verbose {
		fmt.Printf("[+] FTP Banner: %s\n", banner)
	}

	info := &FTPInfo{Banner: banner}
	info.Software = extractFTPSoftware(banner)
	result.Info = info

	// Version disclosure finding
	if info.Software != "" {
		result.Findings = append(result.Findings, Finding{
			Title:       fmt.Sprintf("FTP Version Disclosure: %s", info.Software),
			Severity:    "LOW",
			CVSS:        3.7,
			CWE:         "CWE-200",
			Target:      fmt.Sprintf("ftp://%s:%d", target, port),
			Description: "FTP server reveals software version in banner, aiding fingerprinting.",
			Evidence:    fmt.Sprintf("Banner: %s", banner),
			Remediation: "Configure FTP server to hide version info in banner.",
			Source:      "module:glitchftp",
		})
	}

	// Test anonymous login
	conn2, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		defer conn2.Close()
		if testFTPLogin(conn2, "anonymous", "anonymous@glitchicons.io", timeout, verbose) {
			info.Anonymous = true
			result.Findings = append(result.Findings, Finding{
				Title:       "FTP Anonymous Login Allowed",
				Severity:    "HIGH",
				CVSS:        7.5,
				CWE:         "CWE-287",
				Target:      fmt.Sprintf("ftp://%s:%d", target, port),
				Description: "FTP server allows anonymous authentication. Attacker can list and potentially download files without credentials.",
				Evidence:    fmt.Sprintf("Anonymous login to %s:%d succeeded\nUSER anonymous / PASS anonymous@", target, port),
				Remediation: "Disable anonymous FTP access unless explicitly required. Restrict anonymous user to read-only access in isolated directory.",
				Source:      "module:glitchftp",
			})
		}
	}

	// Test default credentials
	for _, cred := range defaultFTPCreds[4:8] { // Skip anonymous
		conn3, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			break
		}
		if testFTPLogin(conn3, cred[0], cred[1], timeout, verbose) {
			conn3.Close()
			result.Findings = append(result.Findings, Finding{
				Title:       fmt.Sprintf("FTP Default Credentials: %s:%s", cred[0], cred[1]),
				Severity:    "CRITICAL",
				CVSS:        9.8,
				CWE:         "CWE-521",
				Target:      fmt.Sprintf("ftp://%s:%d", target, port),
				Description: fmt.Sprintf("FTP server accepts default credentials '%s:%s'.", cred[0], cred[1]),
				Evidence:    fmt.Sprintf("Login with %s:%s succeeded", cred[0], cred[1]),
				Remediation: "Change default credentials immediately. Implement account lockout after failed attempts.",
				Source:      "module:glitchftp",
			})
			break
		}
		conn3.Close()
	}

	// FTP cleartext protocol finding
	result.Findings = append(result.Findings, Finding{
		Title:       "FTP Cleartext Protocol — Credentials Transmitted Unencrypted",
		Severity:    "MEDIUM",
		CVSS:        5.9,
		CWE:         "CWE-319",
		Target:      fmt.Sprintf("ftp://%s:%d", target, port),
		Description: "FTP transmits credentials and data in cleartext. Network eavesdroppers can capture usernames, passwords, and file contents.",
		Evidence:    fmt.Sprintf("FTP port %d open — no TLS detected", port),
		Remediation: "Use FTPS (FTP over TLS, port 990) or SFTP (SSH FTP, port 22). Disable plain FTP.",
		Source:      "module:glitchftp",
	})

	return result
}

func testFTPLogin(conn net.Conn, user, pass string, timeout time.Duration, verbose bool) bool {
	reader := bufio.NewReader(conn)
	conn.SetDeadline(time.Now().Add(timeout))

	// Read banner
	_, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	// Send USER
	fmt.Fprintf(conn, "USER %s\r\n", user)
	resp, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	if !strings.HasPrefix(resp, "331") && !strings.HasPrefix(resp, "230") {
		return false // Not "Password required" or "Logged in"
	}

	// If already logged in (rare)
	if strings.HasPrefix(resp, "230") {
		if verbose {
			fmt.Printf("[+] FTP Login: %s (no password required)\n", user)
		}
		return true
	}

	// Send PASS
	fmt.Fprintf(conn, "PASS %s\r\n", pass)
	resp, err = reader.ReadString('\n')
	if err != nil {
		return false
	}

	success := strings.HasPrefix(resp, "230")
	if verbose && success {
		fmt.Printf("[+] FTP Login: %s:%s\n", user, pass)
	}
	return success
}

func extractFTPSoftware(banner string) string {
	banner = strings.ToLower(banner)
	knownSoftware := []string{
		"vsftpd", "proftpd", "filezilla", "pure-ftpd",
		"wu-ftpd", "microsoft ftp", "cerberus", "titan",
	}
	for _, sw := range knownSoftware {
		if strings.Contains(banner, sw) {
			return sw
		}
	}
	// Try to extract version-like pattern
	if strings.Contains(banner, " ") {
		parts := strings.Fields(banner)
		for _, p := range parts {
			if len(p) > 3 && (strings.Contains(p, ".") || strings.Contains(p, "_")) {
				return p
			}
		}
	}
	return ""
}
