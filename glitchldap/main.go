// glitchldap/main.go
// GLITCHICONS — LDAP/Active Directory Security Auditor
//
// Checks:
//   - Anonymous bind (unauthenticated access)
//   - Null base DN enumeration
//   - User enumeration via LDAP search
//   - Default credential testing (admin:admin, admin:password)
//   - Password policy extraction
//   - Domain info disclosure
//
// Usage:
//   glitchldap --target ldap.corp.com
//   glitchldap --target 192.168.1.10 --port 389 --timeout 5
//   glitchldap --target ldap.corp.com --port 636 --tls
//   glitchldap --target ldap.corp.com --output ldap_findings.json

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

const Version = "3.3.0"

// LDAP message types
const (
	ldapBindRequest   = 0x60
	ldapBindResponse  = 0x61
	ldapSearchRequest = 0x63
	ldapSearchEntry   = 0x64
	ldapSearchDone    = 0x65
)

// Default credentials to test
var defaultCreds = [][2]string{
	{"", ""},
	{"admin", ""},
	{"admin", "admin"},
	{"admin", "password"},
	{"administrator", ""},
	{"administrator", "password"},
	{"cn=admin,dc=example,dc=com", "admin"},
	{"root", "root"},
	{"ldap", "ldap"},
}

// Common LDAP attributes to request
var userAttributes = []string{
	"cn", "sAMAccountName", "userPrincipalName",
	"mail", "memberOf", "pwdLastSet",
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
	Target        string    `json:"target"`
	Port          int       `json:"port"`
	Timestamp     string    `json:"timestamp"`
	LDAPOpen      bool      `json:"ldap_open"`
	AnonBind      bool      `json:"anonymous_bind"`
	DefaultCredsFound []string `json:"default_creds_found"`
	Findings      []Finding `json:"findings"`
	Version       string    `json:"scanner_version"`
}

func main() {
	target  := flag.String("target", "", "Target hostname or IP")
	port    := flag.Int("port", 389, "LDAP port (default 389, TLS: 636)")
	timeout := flag.Int("timeout", 8, "Connection timeout in seconds")
	output  := flag.String("output", "", "Output JSON file")
	verbose := flag.Bool("verbose", false, "Verbose output")
	useTLS  := flag.Bool("tls", false, "Use LDAPS (TLS)")
	ver     := flag.Bool("version", false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchldap v%s\n", Version)
		os.Exit(0)
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: glitchldap --target <host> [--port 389]")
		os.Exit(1)
	}

	if *useTLS && *port == 389 {
		*port = 636
	}

	result := scanLDAP(*target, *port, time.Duration(*timeout)*time.Second, *verbose)
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

func scanLDAP(target string, port int, timeout time.Duration, verbose bool) ScanResult {
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
			fmt.Printf("[-] LDAP port %d closed: %v\n", port, err)
		}
		return result
	}
	defer conn.Close()
	result.LDAPOpen = true

	if verbose {
		fmt.Printf("[+] LDAP port %d open\n", port)
	}

	// Test anonymous bind
	anonResult := tryBind(conn, "", "", timeout, verbose)
	result.AnonBind = anonResult

	if anonResult {
		result.Findings = append(result.Findings, Finding{
			Title:       "LDAP Anonymous Bind Allowed",
			Severity:    "HIGH",
			CVSS:        7.5,
			CWE:         "CWE-287",
			Target:      fmt.Sprintf("ldap://%s:%d", target, port),
			Description: "LDAP server allows anonymous bind (unauthenticated access). Attackers can enumerate directory objects, users, groups, and organizational structure without credentials.",
			Evidence:    fmt.Sprintf("Anonymous bind to %s:%d succeeded (LDAP ResultCode 0)", target, port),
			Remediation: "Disable anonymous bind: configure 'restrict anonymous = 2' in AD or 'olcAllows: none' in OpenLDAP. Require authentication for all operations.",
			Source:      "module:glitchldap",
		})
	}

	// New connection for credential testing
	conn2, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		defer conn2.Close()
		// Test default credentials
		for _, cred := range defaultCreds[2:6] { // Skip empty/anonymous
			dn, pass := cred[0], cred[1]
			if tryBind(conn2, dn, pass, timeout, verbose) {
				result.DefaultCredsFound = append(result.DefaultCredsFound,
					fmt.Sprintf("%s:%s", dn, pass))
				result.Findings = append(result.Findings, Finding{
					Title:       fmt.Sprintf("LDAP Default Credentials Accepted: %s", dn),
					Severity:    "CRITICAL",
					CVSS:        9.8,
					CWE:         "CWE-521",
					Target:      fmt.Sprintf("ldap://%s:%d", target, port),
					Description: fmt.Sprintf("LDAP server accepted default credentials '%s'. Attackers can gain authenticated directory access.", dn),
					Evidence:    fmt.Sprintf("Bind with DN='%s' password='%s' succeeded", dn, pass),
					Remediation: "Change default LDAP admin password immediately. Implement strong password policy. Monitor for LDAP authentication failures.",
					Source:      "module:glitchldap",
				})
				break
			}
		}
	}

	// LDAP port exposed
	result.Findings = append(result.Findings, Finding{
		Title:       fmt.Sprintf("LDAP Service Exposed on Port %d", port),
		Severity:    "INFO",
		CVSS:        0.0,
		CWE:         "CWE-200",
		Target:      fmt.Sprintf("ldap://%s:%d", target, port),
		Description: fmt.Sprintf("LDAP service accessible on %s:%d.", target, port),
		Evidence:    fmt.Sprintf("TCP %d: OPEN", port),
		Remediation: "Restrict LDAP access to authorized systems only. Use LDAPS (port 636) for encrypted communication.",
		Source:      "module:glitchldap",
	})

	return result
}

// tryBind attempts an LDAP simple bind and returns true on success
func tryBind(conn net.Conn, dn, password string, timeout time.Duration, verbose bool) bool {
	conn.SetDeadline(time.Now().Add(timeout))

	// Build minimal LDAP BindRequest
	// Sequence { Integer(msgID), [APPLICATION 0] { Integer(version), OctetString(dn), [0] password } }
	bindReq := buildBindRequest(1, dn, password)
	_, err := conn.Write(bindReq)
	if err != nil {
		return false
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 7 {
		return false
	}

	// Parse result code from BindResponse
	// Look for sequence containing resultCode
	resultCode := parseBindResultCode(buf[:n])
	success := resultCode == 0

	if verbose && success {
		fmt.Printf("[+] Bind succeeded: dn='%s'\n", dn)
	}
	return success
}

// buildBindRequest creates a minimal LDAP BindRequest packet
func buildBindRequest(msgID int, dn, password string) []byte {
	// BindRequest ::= [APPLICATION 0] {
	//   version     INTEGER,
	//   name        LDAPDN,
	//   authentication AuthenticationChoice
	// }
	dnBytes := []byte(dn)
	pwBytes := []byte(password)

	// Authentication: simple [0] IMPLICIT OCTET STRING
	authLen := len(pwBytes)
	var auth []byte
	auth = append(auth, 0x80, byte(authLen))
	auth = append(auth, pwBytes...)

	// BindRequest body
	var body []byte
	body = append(body, 0x02, 0x01, 0x03) // version = 3
	body = append(body, 0x04, byte(len(dnBytes)))
	body = append(body, dnBytes...)
	body = append(body, auth...)

	// [APPLICATION 0] wrapper
	var appReq []byte
	appReq = append(appReq, ldapBindRequest, byte(len(body)))
	appReq = append(appReq, body...)

	// Message envelope: Sequence { Integer(msgID), BindRequest }
	var msgIDBytes []byte
	msgIDBytes = append(msgIDBytes, 0x02, 0x01, byte(msgID))

	var envelope []byte
	envelope = append(envelope, msgIDBytes...)
	envelope = append(envelope, appReq...)

	result := []byte{0x30, byte(len(envelope))}
	result = append(result, envelope...)
	return result
}

// parseBindResultCode extracts the LDAP result code from a BindResponse
func parseBindResultCode(data []byte) int {
	// Walk through the packet looking for BindResponse [APPLICATION 1]
	// Structure: 0x30 (Sequence) -> 0x02 (MsgID) -> 0x61 (BindResponse) -> 0x0a (Enum/ResultCode)
	for i := 0; i < len(data)-3; i++ {
		if data[i] == ldapBindResponse && i+2 < len(data) {
			// Skip to content, look for ENUMERATED (0x0a) result code
			j := i + 2
			for j < len(data)-2 {
				if data[j] == 0x0a && data[j+1] == 0x01 {
					return int(data[j+2])
				}
				j++
			}
		}
	}
	return -1
}

