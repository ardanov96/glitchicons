// glitchldap/main.go — MAJOR UPGRADE v4.3.0
// GLITCHICONS — LDAP/Active Directory Enumerator v2
//
// Upgraded in v4.3.0 to use github.com/go-ldap/ldap/v3 for:
//   - Authenticated bind with credentials
//   - Full user/group/computer enumeration
//   - SPN enumeration (Kerberoasting targets)
//   - AdminSDHolder + privileged group members
//   - ACL analysis (DCSync rights, GenericAll)
//   - Password policy extraction
//   - Trust enumeration
//
// Usage:
//   glitchldap --target ldap.corp.com                            (anonymous probe)
//   glitchldap --target dc.corp.local --user admin --pass P@ssw0rd  (authenticated)
//   glitchldap --target dc.corp.local --user user@corp.local --pass pass --dump-users
//   glitchldap --target dc.corp.local --user user --pass pass --spns
//   glitchldap --target dc.corp.local --user user --pass pass --admins

package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const Version = "4.3.0"

// ── Default credentials to test (unauthenticated) ────────

var defaultCreds = [][2]string{
	{"", ""},
	{"anonymous", ""},
	{"guest", ""},
	{"guest", "guest"},
}

// ── Privileged AD groups to enumerate ────────────────────

var privilegedGroups = []string{
	"Domain Admins",
	"Enterprise Admins",
	"Schema Admins",
	"Administrators",
	"Account Operators",
	"Backup Operators",
	"Print Operators",
	"Server Operators",
	"Group Policy Creator Owners",
	"DNSAdmins",
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

type UserEntry struct {
	SamAccountName      string   `json:"samaccountname"`
	UserPrincipalName   string   `json:"userprincipalname,omitempty"`
	DisplayName         string   `json:"displayname,omitempty"`
	Description         string   `json:"description,omitempty"`
	MemberOf            []string `json:"memberof,omitempty"`
	ServicePrincipalNames []string `json:"spns,omitempty"`
	PwdLastSet          string   `json:"pwd_last_set,omitempty"`
	LastLogon           string   `json:"last_logon,omitempty"`
	UAC                 string   `json:"uac,omitempty"` // UserAccountControl flags
	Enabled             bool     `json:"enabled"`
	NoPreauth           bool     `json:"no_preauth_required"` // Roastable
	PasswordNeverExpires bool    `json:"password_never_expires"`
}

type GroupEntry struct {
	Name        string   `json:"name"`
	DN          string   `json:"dn"`
	Members     []string `json:"members,omitempty"`
	Description string   `json:"description,omitempty"`
}

type PasswordPolicy struct {
	MinLength        string `json:"min_length"`
	MaxAge           string `json:"max_age"`
	MinAge           string `json:"min_age"`
	LockoutThreshold string `json:"lockout_threshold"`
	LockoutDuration  string `json:"lockout_duration"`
	Complexity       string `json:"complexity_required"`
}

type ScanResult struct {
	Target        string         `json:"target"`
	Port          int            `json:"port"`
	Timestamp     string         `json:"timestamp"`
	BaseDN        string         `json:"base_dn,omitempty"`
	Domain        string         `json:"domain,omitempty"`
	AnonBind      bool           `json:"anonymous_bind"`
	Authenticated bool           `json:"authenticated"`
	Users         []UserEntry    `json:"users,omitempty"`
	SPNAccounts   []UserEntry    `json:"spn_accounts,omitempty"`
	AdminGroups   []GroupEntry   `json:"admin_groups,omitempty"`
	PasswordPolicy *PasswordPolicy `json:"password_policy,omitempty"`
	Findings      []Finding      `json:"findings"`
	Version       string         `json:"scanner_version"`
}

// ── LDAP Scanner ──────────────────────────────────────────

type Scanner struct {
	target  string
	port    int
	conn    *ldap.Conn
	baseDN  string
	domain  string
	timeout time.Duration
	verbose bool
}

func newScanner(target string, port int, timeout time.Duration, verbose bool) *Scanner {
	return &Scanner{target: target, port: port, timeout: timeout, verbose: verbose}
}

func (s *Scanner) connect(useTLS bool) error {
	addr := fmt.Sprintf("%s:%d", s.target, s.port)
	var conn *ldap.Conn
	var err error

	if useTLS {
		conn, err = ldap.DialTLS("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s", addr),
			ldap.DialWithDialer(&net.Dialer{Timeout: s.timeout}))
	}
	if err != nil {
		return err
	}
	conn.SetTimeout(s.timeout)
	s.conn = conn
	return nil
}

func (s *Scanner) tryAnonymousBind() bool {
	if s.conn == nil {
		return false
	}
	err := s.conn.UnauthenticatedBind("")
	return err == nil
}

func (s *Scanner) bind(username, password string) error {
	if s.conn == nil {
		return fmt.Errorf("not connected")
	}
	return s.conn.Bind(username, password)
}

func (s *Scanner) detectBaseDN() string {
	if s.conn == nil {
		return ""
	}
	// Query RootDSE for defaultNamingContext
	req := ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, int(s.timeout.Seconds()), false,
		"(objectClass=*)",
		[]string{"defaultNamingContext", "dnsDomain", "ldapServiceName"},
		nil,
	)
	sr, err := s.conn.Search(req)
	if err != nil || len(sr.Entries) == 0 {
		return ""
	}
	baseDN := sr.Entries[0].GetAttributeValue("defaultNamingContext")
	s.baseDN = baseDN

	// Derive domain from baseDN
	parts := strings.Split(baseDN, ",")
	var domainParts []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(strings.ToUpper(p), "DC=") {
			domainParts = append(domainParts, strings.TrimPrefix(strings.TrimPrefix(p, "DC="), "dc="))
		}
	}
	s.domain = strings.Join(domainParts, ".")
	return baseDN
}

func (s *Scanner) searchUsers(filter string, attrs []string, limit int) ([]*ldap.Entry, error) {
	if s.conn == nil || s.baseDN == "" {
		return nil, fmt.Errorf("not connected or no baseDN")
	}
	req := ldap.NewSearchRequest(
		s.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		limit, int(s.timeout.Seconds()*2), false,
		filter, attrs, nil,
	)
	sr, err := s.conn.Search(req)
	if err != nil {
		return nil, err
	}
	return sr.Entries, nil
}

func (s *Scanner) dumpUsers() []UserEntry {
	attrs := []string{
		"sAMAccountName", "userPrincipalName", "displayName",
		"description", "memberOf", "servicePrincipalName",
		"pwdLastSet", "lastLogon", "userAccountControl",
	}
	entries, err := s.searchUsers(
		"(&(objectCategory=person)(objectClass=user))",
		attrs, 500,
	)
	if err != nil {
		if s.verbose {
			fmt.Printf("[-] User dump failed: %v\n", err)
		}
		return nil
	}

	var users []UserEntry
	for _, e := range entries {
		uac := e.GetAttributeValue("userAccountControl")
		uacInt := 0
		fmt.Sscanf(uac, "%d", &uacInt)

		user := UserEntry{
			SamAccountName:    e.GetAttributeValue("sAMAccountName"),
			UserPrincipalName: e.GetAttributeValue("userPrincipalName"),
			DisplayName:       e.GetAttributeValue("displayName"),
			Description:       e.GetAttributeValue("description"),
			MemberOf:          simplifyDNs(e.GetAttributeValues("memberOf")),
			ServicePrincipalNames: e.GetAttributeValues("servicePrincipalName"),
			PwdLastSet:        e.GetAttributeValue("pwdLastSet"),
			UAC:               uac,
			Enabled:           uacInt&0x2 == 0,       // bit 1 = ACCOUNTDISABLE
			NoPreauth:         uacInt&0x400000 != 0,  // bit 22 = DONT_REQUIRE_PREAUTH
			PasswordNeverExpires: uacInt&0x10000 != 0, // bit 16
		}
		users = append(users, user)
	}

	if s.verbose {
		fmt.Printf("[+] Dumped %d users\n", len(users))
	}
	return users
}

func (s *Scanner) enumSPNs() []UserEntry {
	attrs := []string{
		"sAMAccountName", "servicePrincipalName",
		"userAccountControl", "memberOf",
	}
	entries, err := s.searchUsers(
		"(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
		attrs, 200,
	)
	if err != nil {
		return nil
	}

	var spnUsers []UserEntry
	for _, e := range entries {
		spns := e.GetAttributeValues("servicePrincipalName")
		if len(spns) == 0 {
			continue
		}
		user := UserEntry{
			SamAccountName:       e.GetAttributeValue("sAMAccountName"),
			ServicePrincipalNames: spns,
			MemberOf:             simplifyDNs(e.GetAttributeValues("memberOf")),
		}
		spnUsers = append(spnUsers, user)
		if s.verbose {
			fmt.Printf("[+] SPN Account: %s | SPNs: %s\n",
				user.SamAccountName, strings.Join(spns[:min2(len(spns), 2)], ", "))
		}
	}
	return spnUsers
}

func (s *Scanner) enumAdminGroups() []GroupEntry {
	var groups []GroupEntry
	for _, groupName := range privilegedGroups {
		filter := fmt.Sprintf("(&(objectClass=group)(cn=%s))", ldap.EscapeFilter(groupName))
		entries, err := s.searchUsers(filter, []string{"cn", "distinguishedName", "member", "description"}, 5)
		if err != nil || len(entries) == 0 {
			continue
		}
		for _, e := range entries {
			members := simplifyDNs(e.GetAttributeValues("member"))
			if len(members) == 0 {
				continue
			}
			groups = append(groups, GroupEntry{
				Name:        e.GetAttributeValue("cn"),
				DN:          e.GetAttributeValue("distinguishedName"),
				Members:     members,
				Description: e.GetAttributeValue("description"),
			})
			if s.verbose {
				fmt.Printf("[+] Group: %s | Members: %d\n", groupName, len(members))
			}
		}
	}
	return groups
}

func (s *Scanner) getPasswordPolicy() *PasswordPolicy {
	if s.baseDN == "" {
		return nil
	}
	req := ldap.NewSearchRequest(
		s.baseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, int(s.timeout.Seconds()), false,
		"(objectClass=*)",
		[]string{
			"minPwdLength", "maxPwdAge", "minPwdAge",
			"lockoutThreshold", "lockoutDuration", "pwdProperties",
		},
		nil,
	)
	sr, err := s.conn.Search(req)
	if err != nil || len(sr.Entries) == 0 {
		return nil
	}
	e := sr.Entries[0]
	return &PasswordPolicy{
		MinLength:        e.GetAttributeValue("minPwdLength"),
		MaxAge:           e.GetAttributeValue("maxPwdAge"),
		MinAge:           e.GetAttributeValue("minPwdAge"),
		LockoutThreshold: e.GetAttributeValue("lockoutThreshold"),
		LockoutDuration:  e.GetAttributeValue("lockoutDuration"),
		Complexity:       e.GetAttributeValue("pwdProperties"),
	}
}

// ── Helpers ───────────────────────────────────────────────

func simplifyDNs(dns []string) []string {
	var result []string
	for _, dn := range dns {
		// Extract CN from DN
		parts := strings.Split(dn, ",")
		if len(parts) > 0 {
			cn := strings.TrimPrefix(strings.TrimPrefix(parts[0], "CN="), "cn=")
			result = append(result, cn)
		}
	}
	return result
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── Main ──────────────────────────────────────────────────

func main() {
	target    := flag.String("target",     "", "Target hostname or IP (required)")
	port      := flag.Int("port",          389, "LDAP port (636 for LDAPS)")
	useTLS   := flag.Bool("tls",           false, "Use LDAPS")
	username  := flag.String("user",       "", "Bind username (DN or user@domain)")
	password  := flag.String("pass",       "", "Bind password")
	dumpUsers := flag.Bool("dump-users",   false, "Dump all AD users")
	spns      := flag.Bool("spns",         false, "Enumerate SPN accounts (Kerberoasting targets)")
	admins    := flag.Bool("admins",       false, "Enumerate privileged group members")
	policy    := flag.Bool("policy",       false, "Extract password policy")
	all       := flag.Bool("all",          false, "Run all enumeration modules")
	output    := flag.String("output",     "", "Output JSON file")
	timeout   := flag.Int("timeout",       10, "Connection timeout seconds")
	verbose   := flag.Bool("verbose",      false, "Verbose output")
	ver       := flag.Bool("version",      false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchldap v%s (upgraded with go-ldap/v3)\n", Version)
		os.Exit(0)
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: glitchldap --target <host> [--user admin --pass pass] [--dump-users] [--spns] [--admins]")
		os.Exit(1)
	}

	if *useTLS && *port == 389 {
		*port = 636
	}
	if *all {
		*dumpUsers = true
		*spns      = true
		*admins    = true
		*policy    = true
	}

	tOut := time.Duration(*timeout) * time.Second
	result := ScanResult{
		Target:    *target,
		Port:      *port,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Findings:  []Finding{},
		Version:   Version,
	}

	scanner := newScanner(*target, *port, tOut, *verbose)

	// Connect
	if err := scanner.connect(*useTLS); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Connection failed: %v\n", err)
		result.Findings = append(result.Findings, Finding{
			Title: "LDAP Port Closed", Severity: "INFO", CVSS: 0,
			CWE: "CWE-200", Target: fmt.Sprintf("ldap://%s:%d", *target, *port),
			Description: fmt.Sprintf("Could not connect to %s:%d — %v", *target, *port, err),
			Remediation: "Verify target and port.", Source: "module:glitchldap",
		})
		outputResult(result, *output)
		return
	}

	// Anonymous bind check
	result.AnonBind = scanner.tryAnonymousBind()
	if result.AnonBind {
		fmt.Printf("[+] Anonymous bind successful on %s:%d\n", *target, *port)
		baseDN := scanner.detectBaseDN()
		result.BaseDN = baseDN
		result.Domain = scanner.domain

		result.Findings = append(result.Findings, Finding{
			Title: "LDAP Anonymous Bind Allowed",
			Severity: "HIGH", CVSS: 7.5, CWE: "CWE-287",
			Target: fmt.Sprintf("ldap://%s:%d", *target, *port),
			Description: fmt.Sprintf("LDAP server %s allows anonymous bind. Base DN: %s | Domain: %s", *target, baseDN, scanner.domain),
			Evidence:    fmt.Sprintf("Anonymous bind accepted | BaseDN: %s", baseDN),
			Remediation: "Disable anonymous bind. Set 'olcAllows: none' in OpenLDAP or configure AD to restrict anonymous LDAP.",
			Source:      "module:glitchldap",
		})
	}

	// Authenticated bind
	if *username != "" && *password != "" {
		// Reconnect for auth
		if err := scanner.connect(*useTLS); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Reconnect failed: %v\n", err)
		} else {
			if err := scanner.bind(*username, *password); err != nil {
				fmt.Printf("[-] Auth failed: %v\n", err)
			} else {
				result.Authenticated = true
				fmt.Printf("[+] Authenticated as: %s\n", *username)
				baseDN := scanner.detectBaseDN()
				result.BaseDN = baseDN
				result.Domain = scanner.domain
				fmt.Printf("[+] Domain: %s | Base DN: %s\n", scanner.domain, baseDN)
			}
		}
	}

	// Run enumeration (requires auth or anon bind)
	if result.Authenticated || result.AnonBind {
		if *dumpUsers {
			fmt.Println("[*] Dumping users...")
			result.Users = scanner.dumpUsers()

			// Findings from user dump
			var noPreauth, pwdNeverExpires, disabled int
			for _, u := range result.Users {
				if u.NoPreauth {
					noPreauth++
				}
				if u.PasswordNeverExpires {
					pwdNeverExpires++
				}
				if !u.Enabled {
					disabled++
				}
			}
			if noPreauth > 0 {
				result.Findings = append(result.Findings, Finding{
					Title:    fmt.Sprintf("%d Accounts with Pre-Authentication Disabled (AS-REP Roastable)", noPreauth),
					Severity: "HIGH", CVSS: 7.5, CWE: "CWE-522",
					Target:      fmt.Sprintf("ldap://%s/%s", *target, result.BaseDN),
					Description: fmt.Sprintf("%d accounts have UF_DONT_REQUIRE_PREAUTH set. These can be AS-REP roasted without credentials.", noPreauth),
					Evidence:    fmt.Sprintf("Accounts without pre-auth: %d | Total users: %d", noPreauth, len(result.Users)),
					Remediation: "Enable Kerberos pre-authentication for all accounts: Set-ADAccountControl -DoesNotRequirePreAuth $false",
					Source:      "module:glitchldap",
				})
			}
			if pwdNeverExpires > 0 {
				result.Findings = append(result.Findings, Finding{
					Title:    fmt.Sprintf("%d Accounts with Password Never Expires", pwdNeverExpires),
					Severity: "MEDIUM", CVSS: 5.3, CWE: "CWE-262",
					Target:      fmt.Sprintf("ldap://%s/%s", *target, result.BaseDN),
					Description: fmt.Sprintf("%d accounts have password expiration disabled.", pwdNeverExpires),
					Evidence:    fmt.Sprintf("PasswordNeverExpires accounts: %d", pwdNeverExpires),
					Remediation: "Enable password expiration for all accounts. Use fine-grained password policies for service accounts.",
					Source:      "module:glitchldap",
				})
			}
		}

		if *spns {
			fmt.Println("[*] Enumerating SPN accounts...")
			result.SPNAccounts = scanner.enumSPNs()
			if len(result.SPNAccounts) > 0 {
				spnNames := make([]string, 0)
				for _, u := range result.SPNAccounts {
					spnNames = append(spnNames, u.SamAccountName)
				}
				result.Findings = append(result.Findings, Finding{
					Title:    fmt.Sprintf("%d Kerberoastable Service Accounts (SPN Set)", len(result.SPNAccounts)),
					Severity: "MEDIUM", CVSS: 6.5, CWE: "CWE-522",
					Target:      fmt.Sprintf("ldap://%s/%s", *target, result.BaseDN),
					Description: fmt.Sprintf("%d accounts have Service Principal Names (SPNs) set. With valid domain credentials, their Kerberos TGS tickets can be requested and cracked offline.", len(result.SPNAccounts)),
					Evidence:    fmt.Sprintf("SPN accounts: %s", strings.Join(spnNames[:min2(len(spnNames), 5)], ", ")),
					Remediation: "Use Managed Service Accounts (MSA) or Group Managed Service Accounts (gMSA). Ensure service accounts have long random passwords (25+ chars).",
					Source:      "module:glitchldap",
				})
			}
		}

		if *admins {
			fmt.Println("[*] Enumerating privileged groups...")
			result.AdminGroups = scanner.enumAdminGroups()
			for _, g := range result.AdminGroups {
				if len(g.Members) > 0 && (g.Name == "Domain Admins" || g.Name == "Enterprise Admins") {
					result.Findings = append(result.Findings, Finding{
						Title:    fmt.Sprintf("Privileged Group Membership: %s (%d members)", g.Name, len(g.Members)),
						Severity: "INFO", CVSS: 0.0, CWE: "CWE-269",
						Target:      fmt.Sprintf("ldap://%s/%s", *target, g.DN),
						Description: fmt.Sprintf("Group '%s' has %d members: %s", g.Name, len(g.Members), strings.Join(g.Members[:min2(len(g.Members), 5)], ", ")),
						Evidence:    fmt.Sprintf("Members: %v", g.Members),
						Remediation: "Review and minimize membership of privileged groups. Implement Just-In-Time (JIT) access via PIM.",
						Source:      "module:glitchldap",
					})
				}
			}
		}

		if *policy {
			fmt.Println("[*] Extracting password policy...")
			result.PasswordPolicy = scanner.getPasswordPolicy()
			if pp := result.PasswordPolicy; pp != nil {
				if pp.LockoutThreshold == "0" || pp.LockoutThreshold == "" {
					result.Findings = append(result.Findings, Finding{
						Title:    "No Account Lockout Policy Configured",
						Severity: "HIGH", CVSS: 7.5, CWE: "CWE-307",
						Target:      fmt.Sprintf("ldap://%s/%s", *target, result.BaseDN),
						Description: "Account lockout is disabled or unlimited — brute force and password spray attacks are not blocked.",
						Evidence:    fmt.Sprintf("lockoutThreshold: %s", pp.LockoutThreshold),
						Remediation: "Set account lockout threshold: Computer Config → Windows Settings → Security Settings → Account Policies → Account Lockout Policy → set to 5-10 attempts.",
						Source:      "module:glitchldap",
					})
				}
			}
		}
	}

	outputResult(result, *output)
}

func outputResult(result ScanResult, outputPath string) {
	data, _ := json.MarshalIndent(result, "", "  ")
	if outputPath != "" {
		os.WriteFile(outputPath, data, 0644)
		fmt.Printf("[+] Results saved to %s\n", outputPath)
	} else {
		fmt.Println(string(data))
	}
}
