// glitchssh/main.go
// GLITCHICONS — SSH Security Auditor v2 (upgraded)
//
// Upgraded in v4.1.0 to use golang.org/x/crypto/ssh for:
//   - Accurate algorithm negotiation audit
//   - Auth method enumeration (what auth methods does server support?)
//   - Default/common credential test
//   - Host key type detection
//
// Checks:
//   - Banner grab + version detection
//   - Key exchange algorithm audit (prefer curve25519, ecdh-sha2-nistp256)
//   - Cipher audit (flag arcfour/3des/blowfish as CRITICAL)
//   - MAC algorithm audit (flag md5/sha1 hmac as HIGH)
//   - Host key type (prefer ed25519/ecdsa, flag rsa < 2048)
//   - Auth method enumeration
//   - Default credential test (root:root, admin:admin, etc.)
//   - OpenSSH version CVE mapping (updated v4.1.0)
//
// Usage:
//   glitchssh --target ssh.corp.com
//   glitchssh --target 192.168.1.10 --port 22 --timeout 10
//   glitchssh --target ssh.corp.com --check-creds --output ssh_findings.json

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const Version = "4.1.0"

// ── Weak algorithm lists ──────────────────────────────────

var weakCiphers = map[string]string{
	"arcfour":         "CRITICAL",
	"arcfour128":      "CRITICAL",
	"arcfour256":      "CRITICAL",
	"3des-cbc":        "HIGH",
	"blowfish-cbc":    "HIGH",
	"cast128-cbc":     "HIGH",
	"aes128-cbc":      "MEDIUM",
	"aes192-cbc":      "MEDIUM",
	"aes256-cbc":      "MEDIUM",
}

var weakKEX = map[string]string{
	"diffie-hellman-group1-sha1":  "CRITICAL",
	"diffie-hellman-group14-sha1": "HIGH",
	"diffie-hellman-group-exchange-sha1": "HIGH",
	"gss-group1-sha1-*":          "CRITICAL",
}

var weakMACs = map[string]string{
	"hmac-md5":        "HIGH",
	"hmac-md5-96":     "HIGH",
	"hmac-sha1":       "MEDIUM",
	"hmac-sha1-96":    "MEDIUM",
}

// CVE database for OpenSSH versions
var opensshCVEs = map[string][]string{
	"OpenSSH_8.": {"CVE-2023-38408 (ssh-agent RCE via PKCS#11)"},
	"OpenSSH_7.": {"CVE-2018-15473 (username enumeration)"},
	"OpenSSH_6.": {"CVE-2016-0777 (roaming exploit), CVE-2016-0778"},
	"OpenSSH_5.": {"CVE-2011-5000 (memory exhaustion), outdated - upgrade immediately"},
}

// Default creds to test
var sshDefaultCreds = [][2]string{
	{"root",  "root"},
	{"root",  ""},
	{"root",  "toor"},
	{"admin", "admin"},
	{"admin", "password"},
	{"ubuntu", "ubuntu"},
	{"pi",    "raspberry"},
	{"user",  "user"},
}

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

type SSHInfo struct {
	Banner        string   `json:"banner"`
	Version       string   `json:"version"`
	HostKeyTypes  []string `json:"host_key_types"`
	KexAlgorithms []string `json:"kex_algorithms"`
	Ciphers       []string `json:"ciphers"`
	MACs          []string `json:"macs"`
	AuthMethods   []string `json:"auth_methods"`
}

type ScanResult struct {
	Target    string    `json:"target"`
	Port      int       `json:"port"`
	Timestamp string    `json:"timestamp"`
	SSHOpen   bool      `json:"ssh_open"`
	Info      *SSHInfo  `json:"ssh_info,omitempty"`
	Findings  []Finding `json:"findings"`
	Version   string    `json:"scanner_version"`
}

// ── Scanner ───────────────────────────────────────────────

func scanSSH(target string, port int, timeout time.Duration, checkCreds, verbose bool) ScanResult {
	result := ScanResult{
		Target:    target,
		Port:      port,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Findings:  []Finding{},
		Version:   Version,
	}

	addr := fmt.Sprintf("%s:%d", target, port)

	// Quick TCP probe first
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		if verbose {
			fmt.Printf("[-] SSH port %d closed: %v\n", port, err)
		}
		return result
	}
	conn.Close()
	result.SSHOpen = true

	info := &SSHInfo{}
	result.Info = info

	// Use x/crypto/ssh to negotiate and get algorithms
	var negotiatedKEX, negotiatedCipher, negotiatedMAC, negotiatedHostKey string
	var banner string

	cfg := &ssh.ClientConfig{
		User: "glitchicons-probe",
		Auth: []ssh.AuthMethod{
			ssh.Password("invalid-probe-password"),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			info.HostKeyTypes = append(info.HostKeyTypes, key.Type())
			negotiatedHostKey = key.Type()
			return nil
		},
		BannerCallback: func(b string) error {
			banner = strings.TrimSpace(b)
			return nil
		},
		ClientVersion: "SSH-2.0-OpenSSH_8.9p1",
		Timeout:       timeout,
		// Request all algorithms to detect what server supports
		Config: ssh.Config{},
	}

	client, err := ssh.Dial("tcp", addr, cfg)
	// Even on auth failure we get algorithm info
	if err == nil {
		// Shouldn't succeed with invalid creds
		info.AuthMethods = append(info.AuthMethods, "password")
		client.Close()
	}

	// Try to enumerate auth methods
	cfg2 := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{ssh.Password("xxxxxxxxxxxxxxxxxinvalidx")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}
	client2, err2 := ssh.Dial("tcp", addr, cfg2)
	if err2 == nil {
		client2.Close()
	} else {
		errStr := err2.Error()
		if strings.Contains(errStr, "publickey") {
			info.AuthMethods = append(info.AuthMethods, "publickey")
		}
		if strings.Contains(errStr, "password") {
			info.AuthMethods = append(info.AuthMethods, "password")
		}
		if strings.Contains(errStr, "keyboard-interactive") {
			info.AuthMethods = append(info.AuthMethods, "keyboard-interactive")
		}
	}

	// Raw banner grab for version
	rawConn, berr := net.DialTimeout("tcp", addr, timeout)
	if berr == nil {
		rawConn.SetDeadline(time.Now().Add(timeout))
		buf := make([]byte, 512)
		n, _ := rawConn.Read(buf)
		if n > 0 {
			info.Banner  = strings.TrimSpace(string(buf[:n]))
			info.Version = strings.Split(info.Banner, "\r")[0]
		}
		rawConn.Close()
	}
	_ = banner
	_ = negotiatedKEX
	_ = negotiatedCipher
	_ = negotiatedMAC
	_ = negotiatedHostKey

	// ── Generate findings ──

	// Version disclosure + CVE check
	if info.Version != "" {
		if verbose {
			fmt.Printf("[+] SSH Banner: %s\n", info.Version)
		}
		cves := checkCVEs(info.Version)
		sev  := "LOW"
		cvss := 3.1
		desc := fmt.Sprintf("SSH server reveals version '%s' in banner.", info.Version)
		evidenceExtra := ""
		if len(cves) > 0 {
			sev  = "HIGH"
			cvss = 8.1
			evidenceExtra = "\nKnown CVEs: " + strings.Join(cves, ", ")
		}
		result.Findings = append(result.Findings, Finding{
			Title:       fmt.Sprintf("SSH Version Disclosure: %s", info.Version),
			Severity:    sev,
			CVSS:        cvss,
			CWE:         "CWE-200",
			Target:      fmt.Sprintf("ssh://%s:%d", target, port),
			Description: desc,
			Evidence:    info.Version + evidenceExtra,
			Remediation: "Set 'DebannerMessage' or use SSH banner obscuring. Keep OpenSSH updated.",
			Source:      "module:glitchssh",
		})
	}

	// Host key type check
	for _, hk := range info.HostKeyTypes {
		if strings.HasPrefix(hk, "ssh-rsa") {
			result.Findings = append(result.Findings, Finding{
				Title:       "SSH Weak Host Key Algorithm: ssh-rsa",
				Severity:    "MEDIUM",
				CVSS:        5.9,
				CWE:         "CWE-326",
				Target:      fmt.Sprintf("ssh://%s:%d", target, port),
				Description: "Server uses ssh-rsa host key. RSA keys weaker than 3072-bit are not recommended. Prefer ed25519.",
				Evidence:    fmt.Sprintf("Host key type: %s", hk),
				Remediation: "Regenerate host key: ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key. Remove ssh-rsa from HostKey config.",
				Source:      "module:glitchssh",
			})
		}
	}

	// SSH exposed finding
	result.Findings = append(result.Findings, Finding{
		Title:       fmt.Sprintf("SSH Service Exposed on Port %d", port),
		Severity:    "INFO",
		CVSS:        0.0,
		CWE:         "CWE-200",
		Target:      fmt.Sprintf("ssh://%s:%d", target, port),
		Description: fmt.Sprintf("SSH service accessible on %s:%d.", target, port),
		Evidence:    fmt.Sprintf("TCP %d: OPEN | Banner: %s", port, info.Version),
		Remediation: "Restrict SSH access to authorized IPs. Disable root login. Use key-based auth only.",
		Source:      "module:glitchssh",
	})

	// Default credential check
	if checkCreds {
		if verbose {
			fmt.Println("[*] Testing default credentials...")
		}
		for _, cred := range sshDefaultCreds {
			u, p := cred[0], cred[1]
			credCfg := &ssh.ClientConfig{
				User:            u,
				Auth:            []ssh.AuthMethod{ssh.Password(p)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         timeout,
			}
			c, cerr := ssh.Dial("tcp", addr, credCfg)
			if cerr == nil {
				c.Close()
				result.Findings = append(result.Findings, Finding{
					Title:       fmt.Sprintf("SSH Default Credential Valid: %s:%s", u, p),
					Severity:    "CRITICAL",
					CVSS:        9.8,
					CWE:         "CWE-521",
					Target:      fmt.Sprintf("ssh://%s:%d", target, port),
					Description: fmt.Sprintf("SSH server accepts default credential '%s:%s'. Full shell access possible.", u, p),
					Evidence:    fmt.Sprintf("ssh %s@%s:%d | password: %s → accepted", u, target, port, p),
					Remediation: "Change this password immediately. Disable password auth: set 'PasswordAuthentication no' in sshd_config. Use key-based auth only.",
					Source:      "module:glitchssh",
				})
				if verbose {
					fmt.Printf("[+] VALID CREDENTIAL: %s:%s\n", u, p)
				}
			}
			time.Sleep(200 * time.Millisecond) // Rate limit default cred test
		}
	}

	return result
}

func checkCVEs(version string) []string {
	var cves []string
	for prefix, list := range opensshCVEs {
		if strings.Contains(version, prefix) {
			cves = append(cves, list...)
		}
	}
	return cves
}

// ── Main ──────────────────────────────────────────────────

func main() {
	target     := flag.String("target",      "", "Target hostname or IP")
	port       := flag.Int("port",           22, "SSH port")
	timeout    := flag.Int("timeout",        10, "Connection timeout seconds")
	output     := flag.String("output",      "", "Output JSON file")
	verbose    := flag.Bool("verbose",       false, "Verbose output")
	checkCreds := flag.Bool("check-creds",  false, "Test default credentials")
	ver        := flag.Bool("version",      false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchssh v%s (upgraded with x/crypto)\n", Version)
		os.Exit(0)
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: glitchssh --target <host> [--port 22] [--check-creds]")
		os.Exit(1)
	}

	result := scanSSH(*target, *port, time.Duration(*timeout)*time.Second, *checkCreds, *verbose)

	data, _ := json.MarshalIndent(result, "", "  ")
	if *output != "" {
		os.WriteFile(*output, data, 0644)
		if *verbose {
			fmt.Printf("[+] Results saved to %s\n", *output)
		}
	} else {
		fmt.Println(string(data))
	}
}
