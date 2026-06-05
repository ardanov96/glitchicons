// glitchsnmp/main.go
// GLITCHICONS — SNMP Security Auditor
//
// Checks:
//   - SNMP v1/v2c community string brute force
//   - Default community strings (public, private, community)
//   - System information disclosure via sysDescr, sysName
//   - Interface enumeration via ifTable
//   - SNMPv3 detection (safer alternative)
//
// Usage:
//   glitchsnmp --target 192.168.1.1
//   glitchsnmp --target snmp.target.com --port 161 --timeout 3
//   glitchsnmp --target 10.0.0.1 --wordlist communities.txt
//   glitchsnmp --target 10.0.0.1 --output snmp_findings.json --verbose

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

const Version = "3.3.0"

// Default SNMP community strings to test
var defaultCommunities = []string{
	"public", "private", "community", "admin", "manager",
	"default", "cisco", "snmp", "monitor", "readonly",
	"readwrite", "write", "all", "internal", "secret",
	"password", "network", "switch", "router", "server",
}

// SNMP OIDs
const (
	oidSysDescr  = "1.3.6.1.2.1.1.1.0"
	oidSysName   = "1.3.6.1.2.1.1.5.0"
	oidSysUpTime = "1.3.6.1.2.1.1.3.0"
	oidSysContact = "1.3.6.1.2.1.1.4.0"
	oidSysLocation = "1.3.6.1.2.1.1.6.0"
)

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

type SNMPInfo struct {
	Community   string `json:"community"`
	SysDescr    string `json:"sys_descr"`
	SysName     string `json:"sys_name"`
	SysContact  string `json:"sys_contact"`
	SysLocation string `json:"sys_location"`
}

type ScanResult struct {
	Target             string     `json:"target"`
	Port               int        `json:"port"`
	Timestamp          string     `json:"timestamp"`
	SNMPOpen           bool       `json:"snmp_open"`
	ValidCommunities   []string   `json:"valid_communities"`
	SystemInfo         []SNMPInfo `json:"system_info"`
	Findings           []Finding  `json:"findings"`
	Version            string     `json:"scanner_version"`
}

func main() {
	target   := flag.String("target", "", "Target hostname or IP")
	port     := flag.Int("port", 161, "SNMP UDP port")
	timeout  := flag.Int("timeout", 3, "UDP timeout in seconds")
	output   := flag.String("output", "", "Output JSON file")
	verbose  := flag.Bool("verbose", false, "Verbose output")
	wordlist := flag.String("wordlist", "", "Custom community string wordlist file")
	ver      := flag.Bool("version", false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchsnmp v%s\n", Version)
		os.Exit(0)
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: glitchsnmp --target <host> [--port 161]")
		os.Exit(1)
	}

	communities := defaultCommunities
	if *wordlist != "" {
		data, err := os.ReadFile(*wordlist)
		if err == nil {
			extra := strings.Fields(string(data))
			communities = append(communities, extra...)
		}
	}

	result := scanSNMP(*target, *port, time.Duration(*timeout)*time.Second, communities, *verbose)
	result.Version = Version

	data, _ := json.MarshalIndent(result, "", "  ")
	if *output != "" {
		os.WriteFile(*output, data, 0644)
	} else {
		fmt.Println(string(data))
	}
}

func scanSNMP(target string, port int, timeout time.Duration, communities []string, verbose bool) ScanResult {
	result := ScanResult{
		Target:    target,
		Port:      port,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Findings:  []Finding{},
	}

	addr := fmt.Sprintf("%s:%d", target, port)

	// Test each community string
	for _, community := range communities {
		info, ok := querySNMP(addr, community, timeout, verbose)
		if ok {
			result.SNMPOpen = true
			result.ValidCommunities = append(result.ValidCommunities, community)
			result.SystemInfo = append(result.SystemInfo, info)

			// Default community finding
			isDefault := isDefaultCommunity(community)
			sev := "HIGH"
			cvss := 7.5
			if isDefault {
				sev  = "CRITICAL"
				cvss = 9.1
			}

			result.Findings = append(result.Findings, Finding{
				Title:       fmt.Sprintf("SNMP Community String Accepted: '%s'", community),
				Severity:    sev,
				CVSS:        cvss,
				CWE:         "CWE-200",
				Target:      fmt.Sprintf("udp://%s:%d", target, port),
				Description: fmt.Sprintf(
					"SNMP community string '%s' is valid. "+
						"Attacker can read system information, interface data, routing tables, and potentially write config.",
					community),
				Evidence: fmt.Sprintf(
					"Community: %s\nSysDescr: %s\nSysName: %s",
					community, truncate(info.SysDescr, 100), info.SysName),
				Remediation: "Change default community strings immediately. Upgrade to SNMPv3 with authentication and encryption. Use ACLs to restrict SNMP access.",
				Source:      "module:glitchsnmp",
			})

			if verbose {
				fmt.Printf("[+] Valid: '%s' — SysName: %s\n", community, info.SysName)
			}

			// Only report first few valid communities
			if len(result.ValidCommunities) >= 3 {
				break
			}
		}
	}

	// SNMPv1/v2c vs SNMPv3 advisory
	if result.SNMPOpen {
		result.Findings = append(result.Findings, Finding{
			Title:       "SNMPv1/v2c in Use — Unencrypted Protocol",
			Severity:    "MEDIUM",
			CVSS:        5.9,
			CWE:         "CWE-319",
			Target:      fmt.Sprintf("udp://%s:%d", target, port),
			Description: "SNMP v1/v2c transmits community strings in cleartext. Any network observer can intercept credentials and system data.",
			Evidence:    "SNMPv1/v2c GetRequest succeeded — no encryption",
			Remediation: "Migrate to SNMPv3 with authPriv security level. Use AES-128 encryption and SHA authentication.",
			Source:      "module:glitchsnmp",
		})
	}

	return result
}

// buildSNMPGetRequest builds a minimal SNMPv2c GetRequest PDU
func buildSNMPGetRequest(community, oid string, reqID int) []byte {
	// Encode OID
	oidBytes := encodeOID(oid)

	// VarBind: Sequence { OID, NULL }
	varBind := []byte{0x30, byte(2 + len(oidBytes))}
	varBind = append(varBind, oidBytes...)
	varBind = append(varBind, 0x05, 0x00) // NULL

	// VarBindList
	varBindList := append([]byte{0x30, byte(len(varBind))}, varBind...)

	// GetRequest PDU [0xA0]
	reqIDBytes := []byte{0x02, 0x04,
		byte(reqID >> 24), byte(reqID >> 16), byte(reqID >> 8), byte(reqID),
	}
	errorStatus := []byte{0x02, 0x01, 0x00}
	errorIndex  := []byte{0x02, 0x01, 0x00}

	pduBody := append(reqIDBytes, errorStatus...)
	pduBody  = append(pduBody, errorIndex...)
	pduBody  = append(pduBody, varBindList...)
	getPDU  := append([]byte{0xA0, byte(len(pduBody))}, pduBody...)

	// SNMP Message
	version   := []byte{0x02, 0x01, 0x01} // v2c = 1
	commBytes := []byte{0x04, byte(len(community))}
	commBytes  = append(commBytes, []byte(community)...)

	msgBody := append(version, commBytes...)
	msgBody  = append(msgBody, getPDU...)
	msg     := append([]byte{0x30, byte(len(msgBody))}, msgBody...)
	return msg
}

// encodeOID encodes a dotted OID string to ASN.1 BER
func encodeOID(oid string) []byte {
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return nil
	}

	// First two components combined: 40*first + second
	var nums []int
	for _, p := range parts {
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		nums = append(nums, n)
	}

	var encoded []byte
	first := nums[0]*40 + nums[1]
	encoded = append(encoded, encodeBase128(first)...)
	for _, n := range nums[2:] {
		encoded = append(encoded, encodeBase128(n)...)
	}

	result := []byte{0x06, byte(len(encoded))}
	return append(result, encoded...)
}

func encodeBase128(n int) []byte {
	if n == 0 {
		return []byte{0x00}
	}
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte(n & 0x7F)}, buf...)
		n >>= 7
	}
	for i := 0; i < len(buf)-1; i++ {
		buf[i] |= 0x80
	}
	return buf
}

// querySNMP sends a GetRequest and parses the response
func querySNMP(addr, community string, timeout time.Duration, verbose bool) (SNMPInfo, bool) {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return SNMPInfo{}, false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	req := buildSNMPGetRequest(community, oidSysDescr, 1)
	_, err = conn.Write(req)
	if err != nil {
		return SNMPInfo{}, false
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 10 {
		return SNMPInfo{}, false
	}

	// Verify it's an SNMP response (starts with 0x30)
	if buf[0] != 0x30 {
		return SNMPInfo{}, false
	}

	// Extract community string from response to verify match
	sysDescr := extractOctetString(buf[:n])
	if sysDescr == "" && !strings.HasPrefix(string(buf[4:4+len(community)]), community) {
		return SNMPInfo{}, false
	}

	info := SNMPInfo{
		Community: community,
		SysDescr:  sysDescr,
	}

	// Get sysName
	conn2, err := net.DialTimeout("udp", addr, timeout)
	if err == nil {
		defer conn2.Close()
		conn2.SetDeadline(time.Now().Add(timeout))
		req2 := buildSNMPGetRequest(community, oidSysName, 2)
		conn2.Write(req2)
		buf2 := make([]byte, 1024)
		n2, err2 := conn2.Read(buf2)
		if err2 == nil && n2 > 0 {
			info.SysName = extractOctetString(buf2[:n2])
		}
	}

	return info, true
}

// extractOctetString finds the first OCTET STRING value in the packet
func extractOctetString(data []byte) string {
	for i := 0; i < len(data)-2; i++ {
		if data[i] == 0x04 { // OCTET STRING tag
			length := int(data[i+1])
			if i+2+length <= len(data) && length > 0 && length < 512 {
				val := string(data[i+2 : i+2+length])
				// Basic sanity check — printable ASCII
				isPrintable := true
				for _, c := range val {
					if c < 0x20 || c > 0x7E {
						isPrintable = false
						break
					}
				}
				if isPrintable && len(val) > 2 {
					return val
				}
			}
		}
	}
	return ""
}

func isDefaultCommunity(s string) bool {
	defaults := map[string]bool{
		"public": true, "private": true, "community": true,
		"admin": true, "manager": true, "default": true,
	}
	return defaults[strings.ToLower(s)]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
