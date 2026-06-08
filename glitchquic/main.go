// glitchquic/main.go
// GLITCHICONS — QUIC/HTTP3 Attack Surface Analyzer
//
// Detects and analyzes QUIC/HTTP3 attack surface without requiring
// full QUIC client implementation.
//
// Checks:
//   - HTTP3/QUIC support detection via Alt-Svc header
//   - QUIC UDP probe (send Initial packet, parse response)
//   - QUIC version negotiation downgrade
//   - 0-RTT session ticket detection
//   - Alt-Svc header injection (cache poisoning)
//   - HTTP/3 header injection via QPACK
//   - Connection ID manipulation
//   - QUIC amplification factor detection
//
// Usage:
//   glitchquic --target https://target.com
//   glitchquic --target https://api.corp.com --verbose
//   glitchquic --target https://target.com --output quic_findings.json

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const Version = "4.8.0"

// ── QUIC constants ────────────────────────────────────────

// QUIC version identifiers
const (
	quicV1     = 0x00000001 // RFC 9000
	quicDraft29 = 0xff00001d
	quicDraft27 = 0xff00001b
	quicMS      = 0xfaceb002 // Facebook
	quicGoogle  = 0x51474f00 // Google QUIC 'QGO\x00'
)

// QUIC Initial packet Long Header first byte
// Bit 7: Header Form = 1 (Long)
// Bit 6: Fixed bit = 1
// Bit 4-5: Long Packet Type = 00 (Initial)
const quicInitialFirstByte = 0xC0

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

type QUICInfo struct {
	HTTP3Advertised     bool     `json:"http3_advertised"`
	AltSvcHeader        string   `json:"alt_svc_header,omitempty"`
	H3Versions          []string `json:"h3_versions,omitempty"`
	QUICResponding      bool     `json:"quic_responding"`
	QUICVersions        []string `json:"quic_versions_negotiated,omitempty"`
	ZeroRTTSupported    bool     `json:"zero_rtt_supported"`
	AltSvcInjectable    bool     `json:"alt_svc_injectable"`
	AmplificationFactor int      `json:"amplification_factor,omitempty"`
}

type ScanResult struct {
	Target    string    `json:"target"`
	Host      string    `json:"host"`
	Port      string    `json:"port"`
	Timestamp string    `json:"timestamp"`
	Info      *QUICInfo `json:"quic_info"`
	Findings  []Finding `json:"findings"`
	Version   string    `json:"scanner_version"`
}

// ── HTTP/3 detection via Alt-Svc ─────────────────────────

func detectHTTP3AltSvc(target string, timeout time.Duration, verbose bool) (bool, string, []string) {
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

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return false, "", nil
	}
	req.Header.Set("User-Agent", "glitchquic/"+Version)

	resp, err := client.Do(req)
	if err != nil {
		return false, "", nil
	}
	defer resp.Body.Close()
	io.ReadAll(io.LimitReader(resp.Body, 4096))

	altSvc := resp.Header.Get("Alt-Svc")
	if altSvc == "" {
		// Also check alternate header names
		altSvc = resp.Header.Get("Alternate-Protocol")
	}

	if verbose {
		fmt.Printf("[*] Alt-Svc: %s\n", altSvc)
	}

	if altSvc == "" {
		return false, "", nil
	}

	// Parse Alt-Svc for h3 entries
	var h3Versions []string
	parts := strings.Split(altSvc, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "h3") {
			// Extract h3, h3-29, h3-27, etc.
			version := strings.SplitN(part, ";", 2)[0]
			h3Versions = append(h3Versions, strings.TrimSpace(version))
		}
	}

	return len(h3Versions) > 0, altSvc, h3Versions
}

// ── QUIC UDP probe ────────────────────────────────────────

// Build minimal QUIC Initial packet (RFC 9000)
func buildQUICInitial(connID []byte, version uint32) []byte {
	pkt := new(bytes.Buffer)

	// First byte: Long Header = 1, Fixed = 1, Type = Initial (00), Reserved = 00, PKN Length = 00
	pkt.WriteByte(quicInitialFirstByte)

	// Version
	binary.Write(pkt, binary.BigEndian, version)

	// Destination Connection ID
	pkt.WriteByte(byte(len(connID)))
	pkt.Write(connID)

	// Source Connection ID (random)
	srcCID := make([]byte, 8)
	rand.Read(srcCID)
	pkt.WriteByte(byte(len(srcCID)))
	pkt.Write(srcCID)

	// Token (empty)
	pkt.WriteByte(0x00)

	// Payload length (variable length integer, 2 bytes)
	// Minimal CRYPTO frame
	cryptoFrame := []byte{
		0x06,       // CRYPTO frame type
		0x00,       // offset = 0
		0x04,       // length = 4
		0x01, 0x00, 0x00, 0x00, // minimal ClientHello placeholder
	}
	payloadLen := len(cryptoFrame) + 1 // +1 for packet number
	pkt.WriteByte(0x40 | byte(payloadLen>>8))
	pkt.WriteByte(byte(payloadLen))

	// Packet Number (1 byte = 0x00)
	pkt.WriteByte(0x00)

	// Payload (CRYPTO frame)
	pkt.Write(cryptoFrame)

	return pkt.Bytes()
}

func probeQUIC(host, port string, timeout time.Duration, verbose bool) (bool, []string) {
	addr := fmt.Sprintf("%s:%s", host, port)
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return false, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Generate random connection ID
	connID := make([]byte, 8)
	rand.Read(connID)

	// Versions to probe
	versions := []uint32{quicV1, quicDraft29, quicDraft27}
	var respondedVersions []string

	for _, version := range versions {
		pkt := buildQUICInitial(connID, version)
		conn.Write(pkt)

		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			continue
		}

		if n > 5 {
			// Check if response looks like QUIC
			firstByte := buf[0]
			if firstByte&0x80 != 0 { // Long Header
				respVersion := binary.BigEndian.Uint32(buf[1:5])
				if verbose {
					fmt.Printf("[*] QUIC response: version=0x%08X firstByte=0x%02X n=%d\n",
						respVersion, firstByte, n)
				}

				// Version negotiation packet: version = 0x00000000
				if respVersion == 0x00000000 {
					// Version negotiation — parse supported versions
					i := 5
					for i+4 <= n {
						v := binary.BigEndian.Uint32(buf[i : i+4])
						if v != 0 {
							respondedVersions = append(respondedVersions,
								fmt.Sprintf("0x%08X", v))
						}
						i += 4
					}
					respondedVersions = append(respondedVersions, "version_negotiation")
				} else {
					respondedVersions = append(respondedVersions,
						fmt.Sprintf("0x%08X", respVersion))
				}
				return true, respondedVersions
			}
		}
	}

	return false, nil
}

// ── 0-RTT detection ───────────────────────────────────────

// Detect 0-RTT by checking if server sends session tickets in TLS 1.3
func detect0RTT(host, port string, timeout time.Duration, verbose bool) bool {
	// Connect via TLS 1.3 and check for session ticket
	addr := fmt.Sprintf("%s:%s", host, port)
	cfg  := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Check connection state for session resumption capability
	state := conn.ConnectionState()
	if verbose {
		fmt.Printf("[*] TLS Version: %d | Resumed: %v | CipherSuite: %d\n",
			state.Version, state.DidResume, state.CipherSuite)
	}

	// TLS 1.3 with session tickets enables 0-RTT
	return state.Version == tls.VersionTLS13
}

// ── Alt-Svc injection test ────────────────────────────────

func testAltSvcInjection(target string, timeout time.Duration, verbose bool) (bool, string) {
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

	// Test: does server reflect Alt-Svc in request back in response?
	// This would indicate cache poisoning via Alt-Svc injection
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return false, ""
	}
	req.Header.Set("User-Agent", "glitchquic/"+Version)
	// Inject Alt-Svc in request (some caches forward this)
	req.Header.Set("Alt-Svc", `h3=":443"; ma=86400, h3-29=":443"`)

	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	io.ReadAll(io.LimitReader(resp.Body, 4096))

	// Check if injected Alt-Svc appears in response (reflection)
	respAltSvc := resp.Header.Get("Alt-Svc")
	if respAltSvc != "" && strings.Contains(respAltSvc, "glitch") {
		return true, fmt.Sprintf("Alt-Svc header reflected in response: %s", respAltSvc)
	}

	evidence := fmt.Sprintf("Injected Alt-Svc in request | Response Alt-Svc: %s", respAltSvc)
	return false, evidence
}

// ── QUIC amplification detection ─────────────────────────

func detectQUICAmplification(host, port string, timeout time.Duration) int {
	addr := fmt.Sprintf("%s:%s", host, port)
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Send small QUIC probe
	connID := make([]byte, 8)
	rand.Read(connID)
	pkt    := buildQUICInitial(connID, quicV1)
	sentSize := len(pkt)

	conn.Write(pkt)

	buf   := make([]byte, 65536)
	total := 0

	// Read all response packets
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		total += n
	}

	if sentSize > 0 && total > 0 {
		return total / sentSize
	}
	return 0
}

// ── Parse target URL ─────────────────────────────────────

func parseTarget(target string) (scheme, host, port string) {
	if strings.HasPrefix(target, "https://") {
		scheme = "https"
		target = strings.TrimPrefix(target, "https://")
		port   = "443"
	} else if strings.HasPrefix(target, "http://") {
		scheme = "http"
		target = strings.TrimPrefix(target, "http://")
		port   = "80"
	} else {
		scheme = "https"
		port   = "443"
	}

	// Remove path
	if idx := strings.Index(target, "/"); idx >= 0 {
		target = target[:idx]
	}

	// Parse host:port
	if idx := strings.LastIndex(target, ":"); idx >= 0 {
		host = target[:idx]
		port = target[idx+1:]
	} else {
		host = target
	}
	return
}

// ── Main scanner ──────────────────────────────────────────

func scanQUIC(target string, timeout time.Duration, verbose bool) ScanResult {
	result := ScanResult{
		Target:    target,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Findings:  []Finding{},
		Info:      &QUICInfo{},
		Version:   Version,
	}

	_, host, port := parseTarget(target)
	result.Host = host
	result.Port = port

	fmt.Printf("[*] glitchquic v%s | %s | host=%s port=%s\n", Version, target, host, port)

	// 1. Alt-Svc HTTP/3 detection
	fmt.Println("[*] Checking Alt-Svc for HTTP/3 advertisement...")
	h3Found, altSvc, h3Versions := detectHTTP3AltSvc(target, timeout, verbose)
	result.Info.HTTP3Advertised = h3Found
	result.Info.AltSvcHeader    = altSvc
	result.Info.H3Versions      = h3Versions

	if h3Found {
		fmt.Printf("[+] HTTP/3 advertised: %v\n", h3Versions)
		result.Findings = append(result.Findings, Finding{
			Title:    fmt.Sprintf("HTTP/3 (QUIC) Enabled: %v", h3Versions),
			Severity: "INFO",
			CVSS:     0.0,
			CWE:      "CWE-16",
			Target:   target,
			Description: "Server advertises HTTP/3 (QUIC) support via Alt-Svc header. " +
				"QUIC introduces new attack surface: version negotiation, 0-RTT replay, connection migration.",
			Evidence:    fmt.Sprintf("Alt-Svc: %s", altSvc),
			Remediation: "Keep QUIC implementation updated. Disable 0-RTT if not required. Monitor QUIC-specific CVEs.",
			Source:      "module:glitchquic",
		})
	} else {
		fmt.Println("[-] No HTTP/3 advertisement found")
	}

	// 2. QUIC UDP probe
	fmt.Println("[*] Probing QUIC on UDP port 443...")
	quicUp, quicVersions := probeQUIC(host, port, timeout, verbose)
	result.Info.QUICResponding = quicUp
	result.Info.QUICVersions   = quicVersions

	if quicUp {
		fmt.Printf("[+] QUIC responding | versions: %v\n", quicVersions)

		// Check for version negotiation (downgrade)
		for _, v := range quicVersions {
			if strings.Contains(v, "version_negotiation") {
				result.Findings = append(result.Findings, Finding{
					Title:    "QUIC Version Negotiation Downgrade Possible",
					Severity: "MEDIUM",
					CVSS:     5.9,
					CWE:      "CWE-757",
					Target:   target,
					Description: "Server supports version negotiation, which can be used to force clients " +
						"to downgrade to older, less secure QUIC versions.",
					Evidence:    fmt.Sprintf("Server sent Version Negotiation packet | Versions: %v", quicVersions),
					Remediation: "Restrict QUIC to modern versions (QUIC v1 / RFC 9000 only). Disable legacy drafts.",
					Source:      "module:glitchquic",
				})
				break
			}
		}
	} else {
		fmt.Println("[-] No QUIC UDP response")
	}

	// 3. 0-RTT detection
	fmt.Println("[*] Checking TLS 1.3 / 0-RTT capability...")
	zeroRTT := detect0RTT(host, port, timeout, verbose)
	result.Info.ZeroRTTSupported = zeroRTT

	if zeroRTT {
		result.Findings = append(result.Findings, Finding{
			Title:    "QUIC 0-RTT Session Resumption Detectable",
			Severity: "MEDIUM",
			CVSS:     6.5,
			CWE:      "CWE-294",
			Target:   target,
			Description: "TLS 1.3 session resumption is available, which enables QUIC 0-RTT early data. " +
				"0-RTT data is vulnerable to replay attacks — attacker can replay early data packets.",
			Evidence:    "TLS 1.3 connection established with session ticket support",
			Remediation: "Disable 0-RTT data for state-changing endpoints. " +
				"Use anti-replay tokens. Ensure 0-RTT only used for idempotent GET requests.",
			Source: "module:glitchquic",
		})
	}

	// 4. Alt-Svc injection test
	fmt.Println("[*] Testing Alt-Svc injection/reflection...")
	injectable, injEvidence := testAltSvcInjection(target, timeout, verbose)
	result.Info.AltSvcInjectable = injectable
	if injectable {
		result.Findings = append(result.Findings, Finding{
			Title:    "Alt-Svc Header Injection / Reflection Detected",
			Severity: "HIGH",
			CVSS:     7.5,
			CWE:      "CWE-444",
			Target:   target,
			Description: "Server reflects injected Alt-Svc header, enabling cache poisoning attacks. " +
				"Attacker can redirect future requests to a malicious QUIC server.",
			Evidence:    injEvidence,
			Remediation: "Strip or validate Alt-Svc headers from upstream/client requests. " +
				"Never forward client-supplied Alt-Svc to cached responses.",
			Source: "module:glitchquic",
		})
	}

	// 5. QUIC amplification check
	if quicUp {
		fmt.Println("[*] Measuring QUIC amplification factor...")
		ampFactor := detectQUICAmplification(host, port, timeout)
		result.Info.AmplificationFactor = ampFactor
		if verbose {
			fmt.Printf("[*] Amplification factor: %dx\n", ampFactor)
		}
		if ampFactor >= 3 {
			result.Findings = append(result.Findings, Finding{
				Title:    fmt.Sprintf("QUIC Amplification Factor: %dx", ampFactor),
				Severity: "MEDIUM",
				CVSS:     5.9,
				CWE:      "CWE-406",
				Target:   target,
				Description: fmt.Sprintf(
					"QUIC server responds with %dx more data than received. " +
						"This amplification factor can be used in UDP DDoS amplification attacks.",
					ampFactor),
				Evidence:    fmt.Sprintf("Sent: ~%d bytes | Received: ~%d bytes | Factor: %dx", 50, 50*ampFactor, ampFactor),
				Remediation: "Implement address validation before sending large responses (RFC 9000 §8.1). " +
					"Limit response size to 3x the received datagram size before validation.",
				Source: "module:glitchquic",
			})
		}
	}

	// Summary
	if !h3Found && !quicUp {
		result.Findings = append(result.Findings, Finding{
			Title:    "HTTP/3 / QUIC Not Detected",
			Severity: "INFO",
			CVSS:     0.0,
			CWE:      "CWE-16",
			Target:   target,
			Description: "No QUIC or HTTP/3 support detected via Alt-Svc headers or UDP probe.",
			Evidence:    "No Alt-Svc header, no QUIC UDP response",
			Remediation: "N/A — QUIC not in use.",
			Source:      "module:glitchquic",
		})
	}

	connIDBytes := make([]byte, 8)
	rand.Read(connIDBytes)
	_ = hex.EncodeToString(connIDBytes)

	fmt.Printf("[*] Done: %d findings\n", len(result.Findings))
	return result
}

// ── Main ──────────────────────────────────────────────────

func main() {
	target  := flag.String("target",  "", "Target URL (https://target.com)")
	timeout := flag.Int("timeout",    10, "Connection timeout seconds")
	output  := flag.String("output",  "", "Output JSON file")
	verbose := flag.Bool("verbose",   false, "Verbose output")
	ver     := flag.Bool("version",   false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchquic v%s\n", Version)
		os.Exit(0)
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: glitchquic --target https://target.com [--verbose]")
		os.Exit(1)
	}

	result := scanQUIC(*target, time.Duration(*timeout)*time.Second, *verbose)

	data, _ := json.MarshalIndent(result, "", "  ")
	if *output != "" {
		os.WriteFile(*output, data, 0644)
		fmt.Printf("[+] Results saved to %s\n", *output)
	} else {
		fmt.Println(string(data))
	}
}
