// glitchtls — TLS/SSL Cipher Suite Analyzer
// Part of the Glitchicons security research platform
//
// Features:
//   - Protocol version detection (TLS 1.0 - 1.3)
//   - Cipher suite analysis (strength classification)
//   - Certificate chain analysis (expiry, CN, SANs, issuer, self-signed)
//   - Hostname mismatch detection
//   - HSTS header check
//   - Deprecated protocol detection
//   - Standard Glitchicons JSON output
//
// Usage:
//   glitchtls --target target.com
//   glitchtls --target target.com:8443
//   glitchtls --target target.com --output text
//
// Author: ardanov96

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// ── Cipher strength classification ───────────────────────

func cipherStrength(id uint16) string {
	name := tls.CipherSuiteName(id)
	nameLower := strings.ToLower(name)
	switch {
	case strings.Contains(nameLower, "rc4"):
		return "INSECURE"
	case strings.Contains(nameLower, "null"):
		return "INSECURE"
	case strings.Contains(nameLower, "export"):
		return "INSECURE"
	case strings.Contains(nameLower, "3des"):
		return "WEAK"
	case strings.Contains(nameLower, "anon"):
		return "WEAK"
	case strings.Contains(nameLower, "md5"):
		return "WEAK"
	case strings.Contains(nameLower, "cbc") && !strings.Contains(nameLower, "ecdhe"):
		return "MEDIUM"
	default:
		return "STRONG"
	}
}

// ── Output schema ─────────────────────────────────────────

type CertInfo struct {
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	SANs         []string `json:"sans"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	DaysUntilExp int      `json:"days_until_expiry"`
	IsExpired    bool     `json:"is_expired"`
	IsSelfSigned bool     `json:"is_self_signed"`
	KeyAlgorithm string   `json:"key_algorithm"`
	SigAlgorithm string   `json:"signature_algorithm"`
}

type TLSResult struct {
	Protocol       string    `json:"protocol"`
	CipherSuite    string    `json:"cipher_suite"`
	CipherStrength string    `json:"cipher_strength"`
	Certificate    *CertInfo `json:"certificate,omitempty"`
	HostnameMatch  bool      `json:"hostname_match"`
	HSTSEnabled    bool      `json:"hsts_enabled"`
	HSTSMaxAge     int       `json:"hsts_max_age,omitempty"`
}

type SupportedProtocol struct {
	Version   string `json:"version"`
	Supported bool   `json:"supported"`
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
	DurationMS      int64  `json:"duration_ms"`
	WeakCiphers     int    `json:"weak_ciphers"`
	InsecureCiphers int    `json:"insecure_ciphers"`
}

type Output struct {
	Tool      string              `json:"tool"`
	Version   string              `json:"version"`
	Target    string              `json:"target"`
	Started   string              `json:"started"`
	Finished  string              `json:"finished"`
	TLSResult *TLSResult          `json:"tls"`
	Protocols []SupportedProtocol `json:"protocols"`
	Findings  []Finding           `json:"findings"`
	Stats     Stats               `json:"stats"`
	ExitCode  int                 `json:"exit_code"`
}

// ── TLS probing ───────────────────────────────────────────

func dialTLS(host, address string, minVer, maxVer uint16, timeoutSec int) (*tls.ConnectionState, error) {
	dialer := &net.Dialer{Timeout: time.Duration(timeoutSec) * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         minVer,
		MaxVersion:         maxVer,
	})
	if err != nil {
		return nil, err
	}
	state := conn.ConnectionState()
	conn.Close()
	return &state, nil
}

// ── Certificate analysis ──────────────────────────────────

func parseCert(cert *x509.Certificate) *CertInfo {
	now := time.Now()
	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
	isSelfSigned := cert.Issuer.String() == cert.Subject.String()

	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	keyAlg := cert.PublicKeyAlgorithm.String()
	sigAlg := cert.SignatureAlgorithm.String()

	return &CertInfo{
		Subject:      cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		SANs:         sans,
		NotBefore:    cert.NotBefore.Format(time.RFC3339),
		NotAfter:     cert.NotAfter.Format(time.RFC3339),
		DaysUntilExp: daysLeft,
		IsExpired:    now.After(cert.NotAfter),
		IsSelfSigned: isSelfSigned,
		KeyAlgorithm: keyAlg,
		SigAlgorithm: sigAlg,
	}
}

// ── HSTS detection ────────────────────────────────────────

func checkHSTS(host, address string, timeoutSec int) (bool, int) {
	dialer := &net.Dialer{Timeout: time.Duration(timeoutSec) * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return false, 0
	}
	defer conn.Close()

	fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	response := strings.ToLower(string(buf[:n]))

	if !strings.Contains(response, "strict-transport-security") {
		return false, 0
	}

	maxAge := 0
	for _, line := range strings.Split(response, "\n") {
		if strings.Contains(line, "strict-transport-security") && strings.Contains(line, "max-age=") {
			fmt.Sscanf(line, "%*s max-age=%d", &maxAge)
			if maxAge == 0 {
				// try alternate format
				parts := strings.Split(line, "max-age=")
				if len(parts) > 1 {
					fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &maxAge)
				}
			}
			break
		}
	}
	return true, maxAge
}

// ── Finding generator ─────────────────────────────────────

func generateFindings(
	result *TLSResult,
	protocols []SupportedProtocol,
	target string,
) []Finding {
	var findings []Finding
	idx := 1

	add := func(title, sev string, cvss float64, cwe, desc, evidence, remediation string) {
		findings = append(findings, Finding{
			ID:          fmt.Sprintf("TLS-%03d", idx),
			Title:       title, Severity: sev, CVSS: cvss, CWE: cwe,
			Target:      target, Description: desc,
			Evidence:    evidence, Remediation: remediation,
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
		})
		idx++
	}

	cert := result.Certificate
	if cert != nil {
		if cert.IsExpired {
			add("Expired TLS Certificate", "HIGH", 7.5, "CWE-295",
				"TLS certificate has expired. Browsers will show security warnings.",
				fmt.Sprintf("Expired: %s", cert.NotAfter),
				"Renew the TLS certificate. Use Let's Encrypt for free auto-renewal.")
		} else if cert.DaysUntilExp < 30 {
			add(fmt.Sprintf("TLS Certificate Expiring in %d Days", cert.DaysUntilExp),
				"MEDIUM", 5.3, "CWE-295",
				fmt.Sprintf("Certificate expires in %d days.", cert.DaysUntilExp),
				fmt.Sprintf("Not After: %s", cert.NotAfter),
				"Renew certificate before expiry. Automate with certbot.")
		}
		if cert.IsSelfSigned {
			add("Self-Signed TLS Certificate", "HIGH", 7.4, "CWE-295",
				"Server uses self-signed certificate not trusted by browsers.",
				fmt.Sprintf("Issuer: %s == Subject: %s", cert.Issuer, cert.Subject),
				"Replace with certificate from trusted CA (Let's Encrypt, DigiCert).")
		}
	}

	if !result.HostnameMatch {
		sanList := ""
		if cert != nil {
			sanList = strings.Join(cert.SANs, ", ")
		}
		add("TLS Certificate Hostname Mismatch", "HIGH", 7.4, "CWE-297",
			"Certificate CN/SANs do not match the target hostname.",
			fmt.Sprintf("Target: %s | SANs: %s", target, sanList),
			"Obtain certificate with correct hostname in SANs.")
	}

	switch result.CipherStrength {
	case "INSECURE":
		add("Insecure TLS Cipher Suite Accepted", "HIGH", 7.5, "CWE-326",
			"Server accepts RC4 or NULL ciphers which are completely broken.",
			fmt.Sprintf("Cipher: %s", result.CipherSuite),
			"Disable RC4, NULL, EXPORT ciphers immediately. Use AES-GCM or ChaCha20.")
	case "WEAK":
		add("Weak TLS Cipher Suite Accepted", "MEDIUM", 5.9, "CWE-326",
			"Server accepts weak ciphers (3DES/SWEET32 or no forward secrecy).",
			fmt.Sprintf("Cipher: %s", result.CipherSuite),
			"Disable 3DES. Configure only AEAD ciphers (AES-GCM, ChaCha20-Poly1305).")
	}

	for _, proto := range protocols {
		if proto.Supported && (proto.Version == "TLS 1.0" || proto.Version == "TLS 1.1") {
			add(fmt.Sprintf("Deprecated TLS Version: %s", proto.Version),
				"MEDIUM", 5.3, "CWE-326",
				fmt.Sprintf("%s is deprecated and vulnerable to BEAST/POODLE.", proto.Version),
				fmt.Sprintf("%s accepted", proto.Version),
				fmt.Sprintf("Disable %s. Set minimum to TLS 1.2, prefer TLS 1.3.", proto.Version))
		}
	}

	if !result.HSTSEnabled {
		add("HSTS Not Configured", "MEDIUM", 5.3, "CWE-319",
			"HTTP Strict Transport Security not set — browsers can be downgraded to HTTP.",
			"Strict-Transport-Security header absent",
			"Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload")
	} else if result.HSTSMaxAge > 0 && result.HSTSMaxAge < 31536000 {
		add("HSTS max-age Too Short", "LOW", 3.1, "CWE-319",
			fmt.Sprintf("HSTS max-age=%d is below recommended 31536000 (1 year).", result.HSTSMaxAge),
			fmt.Sprintf("max-age=%d", result.HSTSMaxAge),
			"Set max-age=31536000; includeSubDomains; preload")
	}

	return findings
}

// ── Main ──────────────────────────────────────────────────

func main() {
	target    := flag.String("target",  "",     "Target host[:port] (required)")
	timeoutSec := flag.Int("timeout",  10,     "Connection timeout (seconds)")
	outputFmt := flag.String("output", "json", "Output: json|text")
	version   := flag.Bool("version",  false,  "Print version and exit")
	flag.Parse()

	if *version {
		fmt.Println("glitchtls 1.0.0")
		os.Exit(0)
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "Error: --target is required")
		flag.Usage()
		os.Exit(1)
	}

	host, port := *target, "443"
	if strings.Contains(*target, ":") {
		parts := strings.SplitN(*target, ":", 2)
		host, port = parts[0], parts[1]
	}
	address := host + ":" + port
	started := time.Now()

	if *outputFmt == "text" {
		fmt.Fprintf(os.Stderr, "[glitchtls] Target : %s\n", address)
	}

	// Default TLS handshake
	state, err := dialTLS(host, address, tls.VersionTLS10, tls.VersionTLS13, *timeoutSec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[glitchtls] Connection error: %v\n", err)
		os.Exit(1)
	}

	proto := "TLS 1.2"
	switch state.Version {
	case tls.VersionTLS10:
		proto = "TLS 1.0"
	case tls.VersionTLS11:
		proto = "TLS 1.1"
	case tls.VersionTLS12:
		proto = "TLS 1.2"
	case tls.VersionTLS13:
		proto = "TLS 1.3"
	}

	cipherName := tls.CipherSuiteName(state.CipherSuite)
	strength := cipherStrength(state.CipherSuite)

	// Certificate
	var certInfo *CertInfo
	hostnameMatch := true
	if len(state.PeerCertificates) > 0 {
		certInfo = parseCert(state.PeerCertificates[0])
		hostnameMatch = state.PeerCertificates[0].VerifyHostname(host) == nil
	}

	// HSTS
	hstsEnabled, hstsMaxAge := checkHSTS(host, address, *timeoutSec)

	tlsResult := &TLSResult{
		Protocol:       proto,
		CipherSuite:    cipherName,
		CipherStrength: strength,
		Certificate:    certInfo,
		HostnameMatch:  hostnameMatch,
		HSTSEnabled:    hstsEnabled,
		HSTSMaxAge:     hstsMaxAge,
	}

	// Protocol version support
	var protocols []SupportedProtocol
	for _, v := range []struct {
		name string
		ver  uint16
	}{
		{"TLS 1.0", tls.VersionTLS10},
		{"TLS 1.1", tls.VersionTLS11},
		{"TLS 1.2", tls.VersionTLS12},
		{"TLS 1.3", tls.VersionTLS13},
	} {
		_, e := dialTLS(host, address, v.ver, v.ver, *timeoutSec)
		supported := e == nil
		protocols = append(protocols, SupportedProtocol{Version: v.name, Supported: supported})
		if *outputFmt == "text" {
			sym := "NO "
			if supported {
				sym = "YES"
			}
			fmt.Fprintf(os.Stderr, "[glitchtls] %-10s: %s\n", v.name, sym)
		}
	}

	if *outputFmt == "text" {
		fmt.Fprintf(os.Stderr, "[glitchtls] Cipher  : %s (%s)\n", cipherName, strength)
		if certInfo != nil {
			fmt.Fprintf(os.Stderr, "[glitchtls] Cert    : %s (%d days left)\n",
				certInfo.Subject, certInfo.DaysUntilExp)
		}
		fmt.Fprintf(os.Stderr, "[glitchtls] HSTS    : %v\n", hstsEnabled)
	}

	findings := generateFindings(tlsResult, protocols, *target)

	weakN, insecureN := 0, 0
	switch strength {
	case "WEAK":
		weakN = 1
	case "INSECURE":
		insecureN = 1
	}

	finished := time.Now()
	output := Output{
		Tool: "glitchtls", Version: "1.0.0",
		Target:    *target,
		Started:   started.UTC().Format(time.RFC3339),
		Finished:  finished.UTC().Format(time.RFC3339),
		TLSResult: tlsResult,
		Protocols: protocols,
		Findings:  findings,
		Stats: Stats{
			DurationMS:      finished.Sub(started).Milliseconds(),
			WeakCiphers:     weakN,
			InsecureCiphers: insecureN,
		},
		ExitCode: 0,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(output)
}
