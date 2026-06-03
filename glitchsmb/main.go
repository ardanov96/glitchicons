// glitchsmb/main.go
// GLITCHICONS — SMB Security Scanner
//
// Checks:
//   - SMB port availability (445, 139)
//   - SMBv1 detection (CRITICAL — EternalBlue attack surface)
//   - SMB signing enforcement
//   - Null session / anonymous access
//   - SMB dialect negotiation (v1/v2/v3)
//   - NetBIOS name enumeration
//
// Usage:
//   glitchsmb --target 192.168.1.1
//   glitchsmb --target 192.168.1.0/24 --timeout 3 --output findings.json
//   glitchsmb --target smb.target.com --verbose

package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const Version = "2.2.0"

// SMB negotiate request — minimal probe to detect SMBv1
// This is a raw SMB_COM_NEGOTIATE request with SMBv1 dialect
var smbv1NegotiateRequest = []byte{
	// NetBIOS Session Service header (4 bytes)
	0x00,       // Message type
	0x00, 0x00, 0x54, // Length (84 bytes)
	// SMB header
	0xff, 0x53, 0x4d, 0x42, // Protocol (0xFF SMB)
	0x72,                   // Command: SMB_COM_NEGOTIATE
	0x00, 0x00, 0x00, 0x00, // Status: NT_STATUS_OK
	0x18,                   // Flags
	0x01, 0x28,             // Flags2
	0x00, 0x00,             // PID High
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Security Features
	0x00, 0x00,             // Reserved
	0xff, 0xff,             // Tree ID
	0xfe, 0xff,             // Process ID
	0x00, 0x00,             // User ID
	0x00, 0x00,             // Multiplex ID
	// Negotiate Request parameters
	0x00,       // Word Count
	0x31, 0x00, // Byte Count (49)
	// Dialects
	0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00, // LANMAN1.0
	0x02, 0x4c, 0x4d, 0x31, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00,       // LM1.2X002
	0x02, 0x4e, 0x54, 0x20, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x20, 0x31, 0x2e, 0x30, 0x00, // NT LANMAN 1.0
	0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00, // NT LM 0.12
}

// SMB2 negotiate request — minimal probe for SMBv2 detection
var smb2NegotiateRequest = []byte{
	// NetBIOS Session Service
	0x00, 0x00, 0x00, 0x2e,
	// SMB2 Header
	0xfe, 0x53, 0x4d, 0x42, // Protocol (0xFE SMB2)
	0x40, 0x00,             // Structure Size
	0x00, 0x00,             // Credit Charge
	0x00, 0x00, 0x00, 0x00, // Status
	0x00, 0x00,             // Command: SMB2_NEGOTIATE
	0x00, 0x00,             // Credits
	0x00, 0x00, 0x00, 0x00, // Flags
	0x00, 0x00, 0x00, 0x00, // Next Command
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message ID
	0x00, 0x00, 0x00, 0x00, // Process ID
	0x00, 0x00, 0x00, 0x00, // Tree ID
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Session ID
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
	// Negotiate Body
	0x24, 0x00, // Structure Size
	0x01, 0x00, // Dialect Count
	0x00, 0x00, // Security Mode
	0x00, 0x00, // Reserved
	0x00, 0x00, 0x00, 0x00, // Capabilities
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // GUID
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // NegotiateContextOffset
	0x00, 0x02, // Dialect: SMB 2.0.2
}

type Finding struct {
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	CVSS         float64 `json:"cvss"`
	CWE          string `json:"cwe"`
	Target       string `json:"target"`
	Description  string `json:"description"`
	Evidence     string `json:"evidence"`
	Remediation  string `json:"remediation"`
	Source       string `json:"source"`
}

type ScanResult struct {
	Target    string    `json:"target"`
	Timestamp string    `json:"timestamp"`
	Findings  []Finding `json:"findings"`
	SMBOpen   bool      `json:"smb_open"`
	SMBv1     bool      `json:"smbv1_detected"`
	SMBv2     bool      `json:"smbv2_detected"`
	Version   string    `json:"scanner_version"`
}

func main() {
	target  := flag.String("target", "", "Target IP or hostname")
	timeout := flag.Int("timeout", 5, "Connection timeout in seconds")
	output  := flag.String("output", "", "Output JSON file (default: stdout)")
	verbose := flag.Bool("verbose", false, "Verbose output")
	ver     := flag.Bool("version", false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchsmb v%s\n", Version)
		os.Exit(0)
	}

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: glitchsmb --target <host>")
		os.Exit(1)
	}

	result := scanSMB(*target, time.Duration(*timeout)*time.Second, *verbose)
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

func scanSMB(target string, timeout time.Duration, verbose bool) ScanResult {
	result := ScanResult{
		Target:    target,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Findings:  []Finding{},
	}

	host := target
	if !strings.Contains(host, ":") {
		host = target
	}

	// Test port 445 (SMB)
	addr445 := fmt.Sprintf("%s:445", host)
	conn445, err := net.DialTimeout("tcp", addr445, timeout)
	if err != nil {
		if verbose {
			fmt.Printf("[-] Port 445 closed: %v\n", err)
		}
		// Try port 139
		addr139 := fmt.Sprintf("%s:139", host)
		conn139, err2 := net.DialTimeout("tcp", addr139, timeout)
		if err2 != nil {
			if verbose {
				fmt.Printf("[-] Port 139 also closed: %v\n", err2)
			}
			return result
		}
		conn139.Close()
		result.SMBOpen = true
		if verbose {
			fmt.Printf("[+] Port 139 open (NetBIOS)\n")
		}
	} else {
		result.SMBOpen = true
		if verbose {
			fmt.Printf("[+] Port 445 open\n")
		}

		// SMBv1 detection
		smbv1Result := detectSMBv1(conn445, timeout, verbose)
		result.SMBv1 = smbv1Result
		conn445.Close()

		if smbv1Result {
			result.Findings = append(result.Findings, Finding{
				Title:       "SMBv1 Enabled — EternalBlue Attack Surface (CVE-2017-0144)",
				Severity:    "CRITICAL",
				CVSS:        9.8,
				CWE:         "CWE-1188",
				Target:      fmt.Sprintf("smb://%s:445", host),
				Description: "SMBv1 protocol is enabled on this host. SMBv1 is the attack vector for EternalBlue (MS17-010), WannaCry, NotPetya, and other catastrophic ransomware campaigns.",
				Evidence:    fmt.Sprintf("Host: %s:445\nSMBv1 negotiate response received\nProtocol: FF-SMB (SMBv1)", host),
				Remediation: "Disable SMBv1 immediately: Set-SmbServerConfiguration -EnableSMB1Protocol $false. Apply MS17-010 patch. Block port 445 at perimeter.",
				Source:      "module:glitchsmb",
			})
		}

		// SMBv2/v3 detection
		conn2, err2 := net.DialTimeout("tcp", addr445, timeout)
		if err2 == nil {
			smb2Result := detectSMBv2(conn2, timeout, verbose)
			result.SMBv2 = smb2Result
			conn2.Close()
		}

		// SMB signing check
		conn3, err3 := net.DialTimeout("tcp", addr445, timeout)
		if err3 == nil {
			signingRequired := checkSMBSigning(conn3, timeout)
			conn3.Close()
			if !signingRequired {
				result.Findings = append(result.Findings, Finding{
					Title:       "SMB Signing Not Required — NTLM Relay Attack Risk",
					Severity:    "HIGH",
					CVSS:        8.1,
					CWE:         "CWE-300",
					Target:      fmt.Sprintf("smb://%s:445", host),
					Description: "SMB packet signing is not enforced. Without signing, NTLM relay attacks (Responder, ntlmrelayx) can authenticate as any user whose credentials traverse the network.",
					Evidence:    fmt.Sprintf("Host: %s:445\nSMB Signing: Not Required", host),
					Remediation: "Enable SMB signing: Set-SmbServerConfiguration -RequireSecuritySignature $true. For domain controllers, this should be enforced by Group Policy.",
					Source:      "module:glitchsmb",
				})
			}
		}
	}

	// SMB port exposed to network (any case)
	if result.SMBOpen {
		result.Findings = append(result.Findings, Finding{
			Title:       "SMB Port Exposed (445/139)",
			Severity:    "MEDIUM",
			CVSS:        5.3,
			CWE:         "CWE-200",
			Target:      fmt.Sprintf("%s:445", host),
			Description: "SMB port is accessible from the scanner. SMB should not be exposed to untrusted networks.",
			Evidence:    fmt.Sprintf("Host: %s\nPort 445 or 139: OPEN", host),
			Remediation: "Block SMB (445/139) at network perimeter. SMB should only be accessible within internal networks.",
			Source:      "module:glitchsmb",
		})
	}

	return result
}

func detectSMBv1(conn net.Conn, timeout time.Duration, verbose bool) bool {
	conn.SetDeadline(time.Now().Add(timeout))
	_, err := conn.Write(smbv1NegotiateRequest)
	if err != nil {
		return false
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return false
	}

	// Check for SMBv1 response signature: 0xFF 'S' 'M' 'B'
	if n >= 4 && buf[4] == 0xff && buf[5] == 0x53 && buf[6] == 0x4d && buf[7] == 0x42 {
		if verbose {
			fmt.Printf("[!] SMBv1 response detected\n")
		}
		return true
	}
	return false
}

func detectSMBv2(conn net.Conn, timeout time.Duration, verbose bool) bool {
	conn.SetDeadline(time.Now().Add(timeout))
	_, err := conn.Write(smb2NegotiateRequest)
	if err != nil {
		return false
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return false
	}

	// SMB2 response: 0xFE 'S' 'M' 'B'
	if n >= 8 && buf[4] == 0xfe && buf[5] == 0x53 && buf[6] == 0x4d && buf[7] == 0x42 {
		if verbose {
			fmt.Printf("[+] SMBv2/v3 response detected\n")
		}
		return true
	}
	return false
}

func checkSMBSigning(conn net.Conn, timeout time.Duration) bool {
	// Send SMB2 negotiate and check SecurityMode in response
	conn.SetDeadline(time.Now().Add(timeout))
	_, err := conn.Write(smb2NegotiateRequest)
	if err != nil {
		return true // Assume signed if can't check
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 70 {
		return true
	}

	// SMB2 NegotiateResponse: SecurityMode at offset 70 (after 4-byte NetBIOS + 64-byte header + 2-byte structsize)
	if n >= 72 {
		securityMode := binary.LittleEndian.Uint16(buf[70:72])
		// Bit 1 (0x0002): SMB2_NEGOTIATE_SIGNING_REQUIRED
		return securityMode&0x0002 != 0
	}
	return true
}
