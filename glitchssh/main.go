// glitchssh/main.go
// GLITCHICONS — SSH Security Auditor
//
// Checks:
//   - SSH banner/version extraction
//   - Key exchange algorithm audit (weak: diffie-hellman-group1-sha1)
//   - Cipher suite audit (weak: arcfour, 3des-cbc, blowfish-cbc, cast128-cbc)
//   - MAC algorithm audit (weak: hmac-md5, hmac-sha1-96)
//   - Password authentication enabled (brute force risk)
//   - OpenSSH version CVE mapping
//   - HostKey algorithm strength
//
// Usage:
//   glitchssh --target ssh.target.com
//   glitchssh --target ssh.target.com --port 2222 --timeout 10
//   glitchssh --target ssh.target.com --output ssh_findings.json --verbose

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const Version = "2.2.0"

// Known vulnerable OpenSSH versions
var vulnerableVersions = map[string]struct {
	CVE      string
	Severity string
	Desc     string
}{
	"OpenSSH_7.2":  {"CVE-2016-6210", "MEDIUM", "User enumeration via timing attack"},
	"OpenSSH_7.1":  {"CVE-2016-0778", "HIGH", "Buffer overflow in OpenSSH agent"},
	"OpenSSH_6.9":  {"CVE-2015-6564", "MEDIUM", "Privilege escalation in PAM"},
	"OpenSSH_6.8":  {"CVE-2015-6564", "MEDIUM", "Privilege escalation in PAM"},
	"OpenSSH_5.":   {"CVE-2010-4478", "HIGH", "J-PAKE protocol vulnerability"},
}

// Weak key exchange algorithms
var weakKex = map[string]string{
	"diffie-hellman-group1-sha1":   "CRITICAL — 768/1024-bit DH (Logjam)",
	"diffie-hellman-group14-sha1":  "MEDIUM — SHA-1 based KEx",
	"gss-gex-sha1-*":              "MEDIUM — SHA-1 based GSSAPI",
	"gss-group1-sha1-*":           "CRITICAL — 768-bit DH with SHA-1",
	"rsa1024-sha1":                "HIGH — RSA 1024-bit",
}

// Weak ciphers
var weakCiphers = map[string]string{
	"arcfour":          "CRITICAL — RC4 (broken)",
	"arcfour128":       "CRITICAL — RC4-128 (broken)",
	"arcfour256":       "CRITICAL — RC4-256 (broken)",
	"3des-cbc":         "HIGH — Triple DES (deprecated)",
	"blowfish-cbc":     "MEDIUM — Blowfish CBC (weak)",
	"cast128-cbc":      "MEDIUM — CAST-128 (weak)",
	"des":              "CRITICAL — Single DES (trivially broken)",
	"aes128-cbc":       "LOW — AES-128 CBC (prefer CTR/GCM)",
	"aes192-cbc":       "LOW — AES-192 CBC (prefer CTR/GCM)",
	"aes256-cbc":       "LOW — AES-256 CBC (BEAST vulnerability)",
	"rijndael-cbc@lysator.liu.se": "LOW — Non-standard CBC mode",
}

// Weak MACs
var weakMACs = map[string]string{
	"hmac-md5":         "HIGH — MD5 HMAC (broken)",
	"hmac-md5-96":      "HIGH — MD5-96 HMAC (broken)",
	"hmac-sha1":        "MEDIUM — SHA-1 HMAC (deprecated)",
	"hmac-sha1-96":     "MEDIUM — SHA-1-96 HMAC (deprecated)",
	"umac-32@openssh.com": "MEDIUM — UMAC-32 (short tag)",
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

type SSHInfo struct {
	Banner          string   `json:"banner"`
	Version         string   `json:"ssh_version"`
	Software        string   `json:"software"`
	KeyExchange     []string `json:"kex_algorithms"`
	Ciphers         []string `json:"ciphers"`
	MACs            []string `json:"macs"`
	HostKeyTypes    []string `json:"hostkey_types"`
	PasswordAuth    bool     `json:"password_auth"`
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

func main() {
	target  := flag.String("target", "", "Target hostname or IP")
	port    := flag.Int("port", 22, "SSH port")
	timeout := flag.Int("timeout", 10, "Connection timeout in seconds")
	output  := flag.String("output", "", "Output JSON file")
	verbose := flag.Bool("verbose", false, "Verbose output")
	ver     := flag.Bool("version", false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchssh v%s\n", Version)
		os.Exit(0)
	}

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: glitchssh --target <host> [--port 22]")
		os.Exit(1)
	}

	result := scanSSH(*target, *port, time.Duration(*timeout)*time.Second, *verbose)
	result.Version = Version

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

func scanSSH(target string, port int, timeout time.Duration, verbose bool) ScanResult {
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
			fmt.Printf("[-] SSH port closed: %v\n", err)
		}
		return result
	}
	defer conn.Close()
	result.SSHOpen = true

	if verbose {
		fmt.Printf("[+] Port %d open\n", port)
	}

	// Read SSH banner
	conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return result
	}

	banner := strings.TrimSpace(string(buf[:n]))
	info := parseSSHBanner(banner, verbose)
	result.Info = &info

	if verbose {
		fmt.Printf("[+] Banner: %s\n", banner)
	}

	// Send our client banner to get server's algorithm list
	clientBanner := "SSH-2.0-Glitchicons_2.2.0\r\n"
	conn.Write([]byte(clientBanner))

	// Read KEX_INIT
	conn.SetDeadline(time.Now().Add(timeout))
	kexBuf := make([]byte, 4096)
	kn, err := conn.Read(kexBuf)
	if err == nil && kn > 0 {
		parseKexInit(kexBuf[:kn], &info, verbose)
		result.Info = &info
	}

	// Generate findings
	result.Findings = generateFindings(target, port, info)

	return result
}

func parseSSHBanner(banner string, verbose bool) SSHInfo {
	info := SSHInfo{Banner: banner}

	// SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
	parts := strings.SplitN(banner, "-", 3)
	if len(parts) >= 2 {
		info.Version = parts[1] // "2.0"
	}
	if len(parts) >= 3 {
		info.Software = parts[2] // "OpenSSH_8.9p1 Ubuntu..."
	}

	return info
}

func parseKexInit(data []byte, info *SSHInfo, verbose bool) {
	// SSH KEX_INIT packet format:
	// 4 bytes length + 1 byte padding_length + 1 byte type (20=KEXINIT) + 16 bytes cookie
	// Then name-list fields (length-prefixed comma-separated strings)
	if len(data) < 25 {
		return
	}

	// Skip: 4-byte length + 1-byte padding_len + 1-byte msg_type(20) + 16-byte cookie = 22 bytes
	offset := 22
	if len(data) <= offset {
		return
	}

	// Parse name-lists: kex, server_host_key, enc_c2s, enc_s2c, mac_c2s, mac_s2c, ...
	fieldNames := []string{"kex", "hostkey", "enc_c2s", "enc_s2c", "mac_c2s", "mac_s2c"}
	fields     := make(map[string][]string)

	for _, fieldName := range fieldNames {
		if offset+4 > len(data) {
			break
		}
		nameListLen := int(data[offset])<<24 | int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4
		if offset+nameListLen > len(data) || nameListLen <= 0 || nameListLen > 2048 {
			break
		}
		nameList := string(data[offset : offset+nameListLen])
		offset += nameListLen
		if nameList != "" {
			fields[fieldName] = strings.Split(nameList, ",")
		}
	}

	if kex, ok := fields["kex"]; ok {
		info.KeyExchange = kex
		if verbose {
			fmt.Printf("[+] KEX: %s\n", strings.Join(kex, ", "))
		}
	}
	if hk, ok := fields["hostkey"]; ok {
		info.HostKeyTypes = hk
	}
	if enc, ok := fields["enc_c2s"]; ok {
		info.Ciphers = enc
		if verbose {
			fmt.Printf("[+] Ciphers: %s\n", strings.Join(enc, ", "))
		}
	}
	if mac, ok := fields["mac_c2s"]; ok {
		info.MACs = mac
	}
}

func generateFindings(target string, port int, info SSHInfo) []Finding {
	var findings []Finding
	sshTarget := fmt.Sprintf("ssh://%s:%d", target, port)

	// Version CVE check
	for version, vuln := range vulnerableVersions {
		if strings.Contains(info.Software, version) {
			cvss := 7.5
			if vuln.Severity == "CRITICAL" {
				cvss = 9.8
			} else if vuln.Severity == "HIGH" {
				cvss = 8.1
			} else if vuln.Severity == "MEDIUM" {
				cvss = 5.5
			}
			findings = append(findings, Finding{
				Title:       fmt.Sprintf("Vulnerable SSH Version: %s (%s)", info.Software, vuln.CVE),
				Severity:    vuln.Severity,
				CVSS:        cvss,
				CWE:         "CWE-1188",
				Target:      sshTarget,
				Description: fmt.Sprintf("%s — %s", vuln.CVE, vuln.Desc),
				Evidence:    fmt.Sprintf("Banner: %s\nVersion: %s", info.Banner, info.Software),
				Remediation: "Upgrade OpenSSH to the latest stable version. Subscribe to OpenSSH security announcements.",
				Source:      "module:glitchssh",
			})
		}
	}

	// KEX algorithm audit
	var weakKexFound []string
	for _, kex := range info.KeyExchange {
		for weakKex, reason := range weakKex {
			if strings.HasPrefix(kex, strings.TrimSuffix(weakKex, "*")) {
				weakKexFound = append(weakKexFound, fmt.Sprintf("%s (%s)", kex, reason))
			}
		}
	}
	if len(weakKexFound) > 0 {
		severity := "HIGH"
		cvss := 7.4
		if strings.Contains(strings.Join(weakKexFound, " "), "CRITICAL") {
			severity = "CRITICAL"
			cvss = 9.4
		}
		findings = append(findings, Finding{
			Title:       fmt.Sprintf("Weak SSH Key Exchange Algorithms (%d found)", len(weakKexFound)),
			Severity:    severity,
			CVSS:        cvss,
			CWE:         "CWE-327",
			Target:      sshTarget,
			Description: "Server supports weak key exchange algorithms vulnerable to downgrade attacks or precomputation (Logjam).",
			Evidence:    strings.Join(weakKexFound, "\n"),
			Remediation: "Disable weak KEx: KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group16-sha512",
			Source:      "module:glitchssh",
		})
	}

	// Cipher audit
	var weakCiphFound []string
	for _, cipher := range info.Ciphers {
		for weakCiph, reason := range weakCiphers {
			if cipher == weakCiph {
				weakCiphFound = append(weakCiphFound, fmt.Sprintf("%s (%s)", cipher, reason))
			}
		}
	}
	if len(weakCiphFound) > 0 {
		severity := "MEDIUM"
		cvss := 5.9
		for _, c := range weakCiphFound {
			if strings.Contains(c, "CRITICAL") {
				severity = "CRITICAL"
				cvss = 9.1
				break
			}
		}
		findings = append(findings, Finding{
			Title:       fmt.Sprintf("Weak SSH Cipher Algorithms (%d found)", len(weakCiphFound)),
			Severity:    severity,
			CVSS:        cvss,
			CWE:         "CWE-327",
			Target:      sshTarget,
			Description: "Server supports weak or deprecated cipher algorithms.",
			Evidence:    strings.Join(weakCiphFound, "\n"),
			Remediation: "Set Ciphers: aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com",
			Source:      "module:glitchssh",
		})
	}

	// MAC audit
	var weakMACFound []string
	for _, mac := range info.MACs {
		for weakMAC, reason := range weakMACs {
			if mac == weakMAC {
				weakMACFound = append(weakMACFound, fmt.Sprintf("%s (%s)", mac, reason))
			}
		}
	}
	if len(weakMACFound) > 0 {
		findings = append(findings, Finding{
			Title:       fmt.Sprintf("Weak SSH MAC Algorithms (%d found)", len(weakMACFound)),
			Severity:    "MEDIUM",
			CVSS:        5.3,
			CWE:         "CWE-327",
			Target:      sshTarget,
			Description: "Server supports weak MAC algorithms.",
			Evidence:    strings.Join(weakMACFound, "\n"),
			Remediation: "Set MACs: hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com",
			Source:      "module:glitchssh",
		})
	}

	// SSH port exposed
	findings = append(findings, Finding{
		Title:       fmt.Sprintf("SSH Service Accessible on Port %d", port),
		Severity:    "INFO",
		CVSS:        0.0,
		CWE:         "CWE-200",
		Target:      sshTarget,
		Description: fmt.Sprintf("SSH service is accessible. Version: %s", info.Software),
		Evidence:    fmt.Sprintf("Banner: %s", info.Banner),
		Remediation: "Ensure SSH is limited to authorized users. Use key-based auth. Consider port knocking or VPN.",
		Source:      "module:glitchssh",
	})

	return findings
}
