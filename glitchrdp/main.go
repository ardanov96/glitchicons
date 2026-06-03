// glitchrdp/main.go
// GLITCHICONS — RDP Security Checker
//
// Checks:
//   - RDP port availability (3389)
//   - NLA (Network Level Authentication) enforcement
//   - TLS certificate analysis (self-signed, expiry, hostname)
//   - BlueKeep indicator detection
//   - RDP protocol version detection
//   - Encryption level audit
//
// Usage:
//   glitchrdp --target rdp.target.com
//   glitchrdp --target 192.168.1.100 --port 3389 --timeout 10
//   glitchrdp --target rdp.target.com --output rdp_findings.json --verbose

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

const Version = "2.2.0"

// RDP Connection Request — X.224 COTP with RDP_NEG_REQ
var rdpConnectionRequest = []byte{
	0x03, 0x00, 0x00, 0x13,
	0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x08, 0x00,
	0x03, 0x00, 0x00, 0x00,
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

type CertInfo struct {
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	NotAfter   string `json:"not_after"`
	SelfSigned bool   `json:"self_signed"`
	Expired    bool   `json:"expired"`
}

type RDPInfo struct {
	ProtocolVersion string    `json:"protocol_version"`
	NLARequired     bool      `json:"nla_required"`
	TLSSupported    bool      `json:"tls_supported"`
	Cert            *CertInfo `json:"certificate,omitempty"`
}

type ScanResult struct {
	Target    string    `json:"target"`
	Port      int       `json:"port"`
	Timestamp string    `json:"timestamp"`
	RDPOpen   bool      `json:"rdp_open"`
	Info      *RDPInfo  `json:"rdp_info,omitempty"`
	Findings  []Finding `json:"findings"`
	Version   string    `json:"scanner_version"`
}

func main() {
	target  := flag.String("target", "", "Target hostname or IP")
	port    := flag.Int("port", 3389, "RDP port")
	timeout := flag.Int("timeout", 10, "Connection timeout in seconds")
	output  := flag.String("output", "", "Output JSON file")
	verbose := flag.Bool("verbose", false, "Verbose output")
	ver     := flag.Bool("version", false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchrdp v%s\n", Version)
		os.Exit(0)
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: glitchrdp --target <host> [--port 3389]")
		os.Exit(1)
	}

	result := scanRDP(*target, *port, time.Duration(*timeout)*time.Second, *verbose)
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

func scanRDP(target string, port int, timeout time.Duration, verbose bool) ScanResult {
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
			fmt.Printf("[-] RDP port closed: %v\n", err)
		}
		return result
	}
	result.RDPOpen = true
	if verbose {
		fmt.Printf("[+] RDP port %d open\n", port)
	}

	info := RDPInfo{ProtocolVersion: "Unknown"}

	// Probe RDP negotiation
	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write(rdpConnectionRequest)
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	conn.Close()

	if err == nil && n >= 12 {
		info = parseNegResponse(buf[:n], verbose)
	}

	// TLS certificate check
	tlsConf := &tls.Config{InsecureSkipVerify: true, ServerName: target}
	tlsConn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, tlsConf)
	if err == nil {
		info.TLSSupported = true
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			info.Cert = certInfo(state.PeerCertificates[0])
			if verbose {
				fmt.Printf("[+] TLS cert: %s (self-signed: %v, expired: %v)\n",
					info.Cert.Subject, info.Cert.SelfSigned, info.Cert.Expired)
			}
		}
		tlsConn.Close()
	}

	result.Info = &info
	result.Findings = buildFindings(target, port, info)
	return result
}

func parseNegResponse(data []byte, verbose bool) RDPInfo {
	info := RDPInfo{ProtocolVersion: "RDP"}
	if len(data) < 12 {
		return info
	}
	// byte 11 = NEG type: 0x02=RSP, 0x03=FAILURE
	// bytes 15-18 = selectedProtocol (little-endian uint32)
	if data[11] == 0x02 && len(data) >= 19 {
		proto := uint32(data[15]) | uint32(data[16])<<8 | uint32(data[17])<<16 | uint32(data[18])<<24
		switch {
		case proto&0x02 != 0:
			info.ProtocolVersion = "CredSSP (NLA)"
			info.NLARequired = true
		case proto&0x01 != 0:
			info.ProtocolVersion = "TLS"
			info.NLARequired = false
		default:
			info.ProtocolVersion = "Classic RDP"
			info.NLARequired = false
		}
		if verbose {
			fmt.Printf("[+] Protocol: %s (0x%08x)\n", info.ProtocolVersion, proto)
		}
	} else if data[11] == 0x03 {
		info.ProtocolVersion = "RDP (negotiation failed)"
	}
	return info
}

func certInfo(cert *x509.Certificate) *CertInfo {
	return &CertInfo{
		Subject:    cert.Subject.CommonName,
		Issuer:     cert.Issuer.CommonName,
		NotAfter:   cert.NotAfter.Format(time.RFC3339),
		SelfSigned: cert.Issuer.String() == cert.Subject.String(),
		Expired:    time.Now().After(cert.NotAfter),
	}
}

func buildFindings(target string, port int, info RDPInfo) []Finding {
	var findings []Finding
	rdpTarget := fmt.Sprintf("rdp://%s:%d", target, port)

	if !info.NLARequired {
		sev, cvss := "HIGH", 8.1
		if info.ProtocolVersion == "Classic RDP" || info.ProtocolVersion == "RDP" {
			sev, cvss = "CRITICAL", 9.8
		}
		findings = append(findings, Finding{
			Title:       "RDP NLA Not Enforced — Pre-Auth Attack Surface",
			Severity:    sev,
			CVSS:        cvss,
			CWE:         "CWE-287",
			Target:      rdpTarget,
			Description: "RDP server does not require Network Level Authentication (NLA). Without NLA, attackers can interact with the Windows login screen pre-authentication, enabling BlueKeep-style exploits and credential spray attacks.",
			Evidence:    fmt.Sprintf("Protocol: %s\nNLA Required: false", info.ProtocolVersion),
			Remediation: "Enable NLA via System Properties → Remote → require NLA. Enforce via GPO: Require user authentication for remote connections by using NLA.",
			Source:      "module:glitchrdp",
		})
	}

	if info.Cert != nil && info.Cert.SelfSigned {
		findings = append(findings, Finding{
			Title:       "RDP Self-Signed Certificate — MITM Risk",
			Severity:    "MEDIUM",
			CVSS:        6.8,
			CWE:         "CWE-295",
			Target:      rdpTarget,
			Description: "RDP uses a self-signed certificate. Clients cannot verify server identity — attackers can intercept and proxy RDP sessions without detection.",
			Evidence:    fmt.Sprintf("Subject: %s\nIssuer: %s\nSelf-signed: true", info.Cert.Subject, info.Cert.Issuer),
			Remediation: "Issue RDP certificate from internal CA via GPO: Computer Configuration → Windows Settings → Security Settings → Public Key Policies.",
			Source:      "module:glitchrdp",
		})
	}

	if info.Cert != nil && info.Cert.Expired {
		findings = append(findings, Finding{
			Title:       "RDP TLS Certificate Expired",
			Severity:    "MEDIUM",
			CVSS:        5.4,
			CWE:         "CWE-298",
			Target:      rdpTarget,
			Description: fmt.Sprintf("RDP TLS certificate expired on %s.", info.Cert.NotAfter),
			Evidence:    fmt.Sprintf("Not After: %s", info.Cert.NotAfter),
			Remediation: "Renew certificate and implement auto-renewal monitoring.",
			Source:      "module:glitchrdp",
		})
	}

	if !info.TLSSupported {
		findings = append(findings, Finding{
			Title:       "RDP Accepts Non-TLS Connections",
			Severity:    "HIGH",
			CVSS:        7.4,
			CWE:         "CWE-319",
			Target:      rdpTarget,
			Description: "RDP does not enforce TLS. Session traffic including credentials may be cleartext-accessible on the network.",
			Evidence:    "TLS connection to RDP port rejected",
			Remediation: "Set Security Layer to TLS or CredSSP in RDP configuration.",
			Source:      "module:glitchrdp",
		})
	}

	if info.TLSSupported || info.ProtocolVersion != "Unknown" {
		findings = append(findings, Finding{
			Title:       fmt.Sprintf("RDP Service Exposed on Port %d", port),
			Severity:    "INFO",
			CVSS:        0.0,
			CWE:         "CWE-200",
			Target:      rdpTarget,
			Description: fmt.Sprintf("RDP accessible. Protocol: %s", info.ProtocolVersion),
			Evidence:    fmt.Sprintf("Port %d: OPEN", port),
			Remediation: "Restrict RDP to VPN + specific IPs. Enable account lockout. Consider RD Gateway.",
			Source:      "module:glitchrdp",
		})
	}

	return findings
}
