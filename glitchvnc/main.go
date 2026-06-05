// glitchvnc/main.go
// GLITCHICONS — VNC Security Checker
//
// Checks:
//   - VNC port availability (5900, 5901)
//   - No-auth VNC detection (security type 1 = None)
//   - VNC version fingerprinting (RFB protocol version)
//   - Security type enumeration
//   - Weak authentication detection
//
// Usage:
//   glitchvnc --target vnc.target.com
//   glitchvnc --target 192.168.1.100 --port 5900 --timeout 5
//   glitchvnc --target vnc.target.com --output vnc_findings.json --verbose

package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const Version = "3.3.0"

// RFB protocol versions
const (
	rfbVersion33  = "RFB 003.003"
	rfbVersion37  = "RFB 003.007"
	rfbVersion38  = "RFB 003.008"
)

// VNC security types
const (
	secNone        = 1   // No authentication
	secVNCAuth     = 2   // VNC password authentication
	secRA2         = 5   // RA2
	secRA2NE       = 6   // RA2NE
	secTight       = 16  // TightVNC
	secUltra       = 17  // UltraVNC
	secTLS         = 18  // TLS
	secVeNCrypt    = 19  // VeNCrypt
	secGtkVncSASL  = 20  // GTK-VNC SASL
	secMS_Logon    = 113 // MS-Logon II
)

var securityTypeNames = map[int]string{
	secNone:    "None (No Authentication!)",
	secVNCAuth: "VNC Authentication (password)",
	secRA2:     "RA2",
	secRA2NE:   "RA2NE",
	secTight:   "TightVNC",
	secUltra:   "UltraVNC",
	secTLS:     "TLS",
	secVeNCrypt: "VeNCrypt",
	secGtkVncSASL: "GTK-VNC SASL",
	secMS_Logon: "MS-Logon II",
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

type VNCInfo struct {
	RFBVersion     string `json:"rfb_version"`
	SecurityTypes  []int  `json:"security_types"`
	NoAuth         bool   `json:"no_auth"`
	SecurityNames  []string `json:"security_type_names"`
}

type ScanResult struct {
	Target    string    `json:"target"`
	Port      int       `json:"port"`
	Timestamp string    `json:"timestamp"`
	VNCOpen   bool      `json:"vnc_open"`
	Info      *VNCInfo  `json:"vnc_info,omitempty"`
	Findings  []Finding `json:"findings"`
	Version   string    `json:"scanner_version"`
}

func main() {
	target  := flag.String("target", "", "Target hostname or IP")
	port    := flag.Int("port", 5900, "VNC port")
	timeout := flag.Int("timeout", 8, "Connection timeout in seconds")
	output  := flag.String("output", "", "Output JSON file")
	verbose := flag.Bool("verbose", false, "Verbose output")
	ver     := flag.Bool("version", false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchvnc v%s\n", Version)
		os.Exit(0)
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: glitchvnc --target <host> [--port 5900]")
		os.Exit(1)
	}

	result := scanVNC(*target, *port, time.Duration(*timeout)*time.Second, *verbose)
	result.Version = Version

	data, _ := json.MarshalIndent(result, "", "  ")
	if *output != "" {
		os.WriteFile(*output, data, 0644)
	} else {
		fmt.Println(string(data))
	}
}

func scanVNC(target string, port int, timeout time.Duration, verbose bool) ScanResult {
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
			fmt.Printf("[-] VNC port %d closed: %v\n", port, err)
		}
		// Try 5901
		if port == 5900 {
			conn2, err2 := net.DialTimeout("tcp", fmt.Sprintf("%s:5901", target), timeout)
			if err2 == nil {
				conn2.Close()
				result.Findings = append(result.Findings, Finding{
					Title:    "VNC Detected on Port 5901",
					Severity: "INFO",
					CVSS:     0.0,
					CWE:      "CWE-200",
					Target:   fmt.Sprintf("vnc://%s:5901", target),
					Description: "VNC port 5901 open (display :1).",
					Evidence: "TCP 5901: OPEN",
					Remediation: "Secure VNC with strong password and restrict access to authorized IPs.",
					Source: "module:glitchvnc",
				})
			}
		}
		return result
	}
	defer conn.Close()
	result.VNCOpen = true

	conn.SetDeadline(time.Now().Add(timeout))

	// Read RFB version from server
	serverVersion := make([]byte, 12)
	n, err := conn.Read(serverVersion)
	if err != nil || n < 12 {
		return result
	}

	versionStr := strings.TrimSpace(string(serverVersion[:n]))
	if verbose {
		fmt.Printf("[+] VNC Version: %s\n", versionStr)
	}

	info := &VNCInfo{RFBVersion: versionStr}
	result.Info = info

	// Send client version (use same or lower)
	clientVersion := "RFB 003.008\n"
	if strings.Contains(versionStr, "003.003") {
		clientVersion = "RFB 003.003\n"
	}
	conn.Write([]byte(clientVersion))

	// Read security types
	secBuf := make([]byte, 256)
	conn.SetDeadline(time.Now().Add(timeout))
	sn, err := conn.Read(secBuf)
	if err != nil || sn < 1 {
		return result
	}

	secTypes, noAuth := parseSecurityTypes(secBuf[:sn], versionStr, verbose)
	info.SecurityTypes = secTypes
	info.NoAuth = noAuth

	// Build security type names
	for _, t := range secTypes {
		name, ok := securityTypeNames[t]
		if !ok {
			name = fmt.Sprintf("Unknown(%d)", t)
		}
		info.SecurityNames = append(info.SecurityNames, name)
	}

	// No-auth finding
	if noAuth {
		result.Findings = append(result.Findings, Finding{
			Title:       "VNC No Authentication Required — Unauthenticated Access",
			Severity:    "CRITICAL",
			CVSS:        9.8,
			CWE:         "CWE-306",
			Target:      fmt.Sprintf("vnc://%s:%d", target, port),
			Description: "VNC server accepts connections without any authentication (Security Type 1: None). Anyone on the network can access the desktop.",
			Evidence: fmt.Sprintf(
				"RFB Version: %s\nSecurity Type 1 (None) offered\nNo credentials required",
				versionStr),
			Remediation: "Enable VNC password authentication immediately. Use VNC over SSH tunnel or VPN. Consider replacing with more secure remote access solution.",
			Source:      "module:glitchvnc",
		})
	}

	// Old RFB version
	majorMinor := extractRFBVersion(versionStr)
	major, minor := majorMinor[0], majorMinor[1]
	if major <= 3 && minor <= 7 {
		result.Findings = append(result.Findings, Finding{
			Title:       fmt.Sprintf("Outdated VNC Protocol: %s", versionStr),
			Severity:    "MEDIUM",
			CVSS:        5.9,
			CWE:         "CWE-1188",
			Target:      fmt.Sprintf("vnc://%s:%d", target, port),
			Description: fmt.Sprintf("VNC uses outdated RFB protocol version %s. Older versions have weaker security features.", versionStr),
			Evidence:    fmt.Sprintf("Server announced: %s", versionStr),
			Remediation: "Upgrade VNC server to support RFB 3.8+. Use TigerVNC or TightVNC with TLS support.",
			Source:      "module:glitchvnc",
		})
	}

	// VNC exposed
	result.Findings = append(result.Findings, Finding{
		Title:       fmt.Sprintf("VNC Service Exposed on Port %d", port),
		Severity:    "MEDIUM",
		CVSS:        6.5,
		CWE:         "CWE-200",
		Target:      fmt.Sprintf("vnc://%s:%d", target, port),
		Description: "VNC provides full graphical desktop access. Exposure to untrusted networks is high risk.",
		Evidence: fmt.Sprintf(
			"Port %d: OPEN\nVersion: %s\nSecurity types: %v",
			port, versionStr, info.SecurityNames),
		Remediation: "Restrict VNC to localhost only. Use SSH tunnel: ssh -L 5900:localhost:5900 user@host. Implement IP allowlisting.",
		Source:      "module:glitchvnc",
	})

	return result
}

func parseSecurityTypes(data []byte, version string, verbose bool) ([]int, bool) {
	var types []int
	noAuth := false

	if len(data) < 1 {
		return types, false
	}

	// RFB 3.3: server sends 4-byte security type
	if strings.Contains(version, "003.003") {
		if len(data) >= 4 {
			secType := int(binary.BigEndian.Uint32(data[0:4]))
			types = append(types, secType)
			noAuth = secType == secNone
		}
		return types, noAuth
	}

	// RFB 3.7+: server sends count + list of types
	count := int(data[0])
	if count == 0 {
		// Server rejected — check error message
		return types, false
	}

	for i := 1; i <= count && i < len(data); i++ {
		t := int(data[i])
		types = append(types, t)
		if t == secNone {
			noAuth = true
		}
		if verbose {
			name := securityTypeNames[t]
			if name == "" {
				name = strconv.Itoa(t)
			}
			fmt.Printf("[+] Security type: %s (%d)\n", name, t)
		}
	}

	return types, noAuth
}

func extractRFBVersion(versionStr string) [2]int {
	// "RFB 003.008" → [3, 8]
	parts := strings.Split(strings.TrimPrefix(versionStr, "RFB "), ".")
	if len(parts) < 2 {
		return [2]int{3, 8}
	}
	major, _ := strconv.Atoi(strings.TrimLeft(parts[0], "0"))
	minor, _ := strconv.Atoi(strings.TrimLeft(parts[1], "0"))
	if major == 0 {
		major = 3
	}
	return [2]int{major, minor}
}
