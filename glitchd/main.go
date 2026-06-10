// glitchd/main.go
// GLITCHICONS — Unified Go Binary Dispatcher
//
// Single entry point that routes scan requests to the correct
// Go binary. Provides a unified HTTP API over all 37 binaries.
//
// API:
//   GET  /version           — version info + available binaries
//   GET  /health            — health check
//   GET  /binaries          — list all binaries with capabilities
//   POST /scan/:binary      — run binary synchronously
//   POST /scan/:binary/async — run async (returns job ID hint)
//   GET  /capabilities      — full capability matrix by category
//
// Usage:
//   glitchd --port 7332 --bin-dir ./bin --timeout 60
//   glitchd --version

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

const Version = "5.5.0"

// ── Binary capability registry ────────────────────────────
// Updated: v4.0.0 (14) → v5.5.0 (37 binaries)

type BinaryInfo struct {
	Name        string   `json:"name"`
	Protocol    string   `json:"protocol"`
	Description string   `json:"description"`
	Flags       []string `json:"supported_flags"`
	DefaultPort int      `json:"default_port,omitempty"`
	Category    string   `json:"category"`
	Tier        string   `json:"tier"`
	Since       string   `json:"since"`
}

var BinaryRegistry = map[string]BinaryInfo{

	// ── Tier 1 — Foundation ───────────────────────────────
	"glitchrace": {
		Name: "glitchrace", Protocol: "HTTP",
		Description: "Race condition detection (nanosecond precision)",
		Flags:       []string{"--url", "--concurrency", "--timeout", "--output"},
		Category: "exploit", Tier: "1", Since: "v1.0",
	},
	"glitchscan": {
		Name: "glitchscan", Protocol: "TCP",
		Description: "High-speed port scanner (10k+ ports/sec)",
		Flags:       []string{"--target", "--ports", "--timeout", "--output"},
		Category: "recon", Tier: "1", Since: "v1.0",
	},
	"glitchfuzz": {
		Name: "glitchfuzz", Protocol: "HTTP",
		Description: "High-throughput HTTP parameter fuzzer",
		Flags:       []string{"--url", "--method", "--data", "--timeout", "--output"},
		Category: "fuzz", Tier: "1", Since: "v1.0",
	},
	"glitchfuzz2": {
		Name: "glitchfuzz2", Protocol: "HTTP",
		Description: "Mutation-based fuzzer — body/header/cookie/path/json",
		Flags:       []string{"body", "header", "cookie", "path", "json"},
		Category: "fuzz", Tier: "1", Since: "v1.0",
	},
	"glitchdns": {
		Name: "glitchdns", Protocol: "DNS",
		Description: "DNS brute force and enumeration (100k+ queries/sec)",
		Flags:       []string{"--target", "--wordlist", "--timeout", "--output"},
		Category: "recon", Tier: "1", Since: "v1.0",
	},
	"glitchtls": {
		Name: "glitchtls", Protocol: "TLS",
		Description: "TLS/SSL certificate and cipher suite audit",
		Flags:       []string{"--target", "--port", "--timeout", "--output"},
		DefaultPort: 443, Category: "protocol", Tier: "1", Since: "v1.0",
	},
	"glitchproxy": {
		Name: "glitchproxy", Protocol: "HTTP",
		Description: "Intercepting proxy with finding injection",
		Flags:       []string{"--port", "--upstream", "--output"},
		Category: "proxy", Tier: "1", Since: "v1.0",
	},

	// ── Tier 2 — Protocol Depth ───────────────────────────
	"glitchsmb": {
		Name: "glitchsmb", Protocol: "SMB",
		Description: "SMBv2/v3 negotiate, signing, null session, pass-the-hash",
		Flags:       []string{"--target", "--port", "--hash", "--timeout", "--output"},
		DefaultPort: 445, Category: "protocol", Tier: "2", Since: "v2.2",
	},
	"glitchssh": {
		Name: "glitchssh", Protocol: "SSH",
		Description: "SSH algorithm audit, auth method enum, default cred test",
		Flags:       []string{"--target", "--port", "--check-creds", "--timeout", "--output"},
		DefaultPort: 22, Category: "protocol", Tier: "2", Since: "v2.2",
	},
	"glitchrdp": {
		Name: "glitchrdp", Protocol: "RDP",
		Description: "RDP NLA enforcement and TLS certificate analysis",
		Flags:       []string{"--target", "--port", "--timeout", "--output"},
		DefaultPort: 3389, Category: "protocol", Tier: "2", Since: "v2.2",
	},
	"glitchldap": {
		Name: "glitchldap", Protocol: "LDAP",
		Description: "Authenticated AD enumeration — users/SPNs/groups/policy",
		Flags:       []string{"--target", "--port", "--user", "--pass", "--dump-users", "--spns", "--admins", "--output"},
		DefaultPort: 389, Category: "protocol", Tier: "2", Since: "v3.3",
	},
	"glitchsnmp": {
		Name: "glitchsnmp", Protocol: "SNMP/UDP",
		Description: "SNMP community string brute force",
		Flags:       []string{"--target", "--port", "--wordlist", "--timeout", "--output"},
		DefaultPort: 161, Category: "protocol", Tier: "2", Since: "v3.3",
	},
	"glitchftp": {
		Name: "glitchftp", Protocol: "FTP",
		Description: "FTP anonymous login and default credential test",
		Flags:       []string{"--target", "--port", "--timeout", "--output"},
		DefaultPort: 21, Category: "protocol", Tier: "2", Since: "v3.3",
	},
	"glitchvnc": {
		Name: "glitchvnc", Protocol: "VNC/RFB",
		Description: "VNC no-auth detection and RFB version fingerprint",
		Flags:       []string{"--target", "--port", "--timeout", "--output"},
		DefaultPort: 5900, Category: "protocol", Tier: "2", Since: "v3.3",
	},
	"glitchwmi": {
		Name: "glitchwmi", Protocol: "DCOM/RPC",
		Description: "DCOM/RPC port 135, OXID resolver, WMI interface detection",
		Flags:       []string{"--target", "--timeout", "--output"},
		DefaultPort: 135, Category: "protocol", Tier: "2", Since: "v4.2",
	},

	// ── Tier 3 — Offensive Operations ────────────────────
	"glitchagent": {
		Name: "glitchagent", Protocol: "HTTP",
		Description: "HTTP scan daemon — job queue, goroutine worker pool, webhook",
		Flags:       []string{"--port", "--workers", "--bin-dir", "--webhook"},
		DefaultPort: 7331, Category: "infrastructure", Tier: "3", Since: "v4.0",
	},
	"glitchbrute": {
		Name: "glitchbrute", Protocol: "Multi",
		Description: "Unified credential attacker — SSH/FTP/HTTP Basic/HTTP Form/LDAP",
		Flags:       []string{"--target", "--protocol", "--users", "--passwords", "--combo", "--rate", "--output"},
		Category: "credentials", Tier: "3", Since: "v4.1",
	},
	"glitchkerberos": {
		Name: "glitchkerberos", Protocol: "Kerberos/UDP",
		Description: "User enum, AS-REP roasting (hashcat $krb5asrep$23), password spray",
		Flags:       []string{"--dc", "--domain", "--mode", "--users", "--password", "--output"},
		DefaultPort: 88, Category: "active_directory", Tier: "3", Since: "v4.3",
	},
	"glitchdesync": {
		Name: "glitchdesync", Protocol: "HTTP",
		Description: "HTTP request smuggling — CL.TE / TE.CL / TE.TE (6 variants) / h2c",
		Flags:       []string{"--target", "--method", "--timeout", "--output"},
		Category: "exploit", Tier: "3", Since: "v4.4",
	},
	"glitchhttp2": {
		Name: "glitchhttp2", Protocol: "HTTP/2",
		Description: "Rapid Reset CVE-2023-44487, HPACK, h2c upgrade, Server Push",
		Flags:       []string{"--target", "--timeout", "--output"},
		DefaultPort: 443, Category: "exploit", Tier: "3", Since: "v4.4",
	},
	"glitchrelay": {
		Name: "glitchrelay", Protocol: "NTLM/HTTP",
		Description: "NTLM relay + HTTP capture → hashcat -m 5600 (NTLMv2)",
		Flags:       []string{"--target", "--mode", "--port", "--output"},
		DefaultPort: 8080, Category: "credentials", Tier: "3", Since: "v4.5",
	},
	"glitchids": {
		Name: "glitchids", Protocol: "HTTP",
		Description: "IDS/IPS evasion effectiveness tester — slow/rotate/jitter/fragment/decoy",
		Flags:       []string{"--target", "--technique", "--url", "--output"},
		Category: "evasion", Tier: "3", Since: "v4.5",
	},
	"glitchexploit": {
		Name: "glitchexploit", Protocol: "Multi",
		Description: "9 CVE verifiers — Log4Shell/Spring4Shell/Zerologon/BlueKeep/CitrixBleed/PAN-OS/more",
		Flags:       []string{"--target", "--cve", "--list", "--output"},
		Category: "cve", Tier: "3", Since: "v4.6",
	},
	"glitchpcap": {
		Name: "glitchpcap", Protocol: "TCP/UDP",
		Description: "Passive capture — JA3 fingerprinting (no libpcap), HTTP creds, DNS anomaly",
		Flags:       []string{"--mode", "--interface", "--output"},
		Category: "passive", Tier: "3", Since: "v4.7",
	},
	"glitchwatcher": {
		Name: "glitchwatcher", Protocol: "HTTP/TLS",
		Description: "Asset monitoring — 7 change types: status/cert/port/content/headers. Webhook alerts.",
		Flags:       []string{"--config", "--state", "--interval", "--webhook", "--once", "--output"},
		Category: "monitoring", Tier: "3", Since: "v4.7",
	},
	"glitchfuzz3": {
		Name: "glitchfuzz3", Protocol: "HTTP",
		Description: "Coverage-guided fuzzer — corpus, grammar engine, OpenAPI seeding, 6 mutation strategies",
		Flags:       []string{"--url", "--mode", "--param", "--grammar", "--corpus", "--openapi", "--output"},
		Category: "fuzz", Tier: "3", Since: "v4.8",
	},
	"glitchquic": {
		Name: "glitchquic", Protocol: "QUIC/UDP",
		Description: "QUIC version negotiation, 0-RTT detection, Alt-Svc h3, amplification factor",
		Flags:       []string{"--target", "--port", "--check-altsvc", "--output"},
		DefaultPort: 443, Category: "protocol", Tier: "3", Since: "v4.8",
	},
	"glitchimplant": {
		Name: "glitchimplant", Protocol: "HTTPS",
		Description: "Authorized post-access agent — HMAC engagement token required",
		Flags:       []string{"--token", "--secret", "--server", "--ops", "--dry-run", "--self-delete"},
		Category: "red_team", Tier: "3", Since: "v4.9",
	},
	"glitchpivot": {
		Name: "glitchpivot", Protocol: "TCP/UDP",
		Description: "Network pivoting — SOCKS5 proxy, TCP forwarder, reverse tunnel, DNS tunnel",
		Flags:       []string{"socks5", "forward", "reverse", "dns-tunnel", "--port", "--remote", "--server"},
		Category: "red_team", Tier: "3", Since: "v4.9",
	},

	// ── Tier 4 — Elite Assessment ─────────────────────────
	"glitchevade": {
		Name: "glitchevade", Protocol: "HTTP",
		Description: "WAF coverage tester — URL/hex/case/whitespace bypass variants, gap detection",
		Flags:       []string{"--target", "--category", "--param", "--timeout", "--output"},
		Category: "waf_testing", Tier: "4", Since: "v5.0",
	},
	"glitchcloak": {
		Name: "glitchcloak", Protocol: "TCP/UDP/HTTP",
		Description: "MITRE ATT&CK detection coverage simulator — T1595/T1046/T1110/T1048/T1087",
		Flags:       []string{"--target", "--category", "--webhook", "--output"},
		Category: "detection_testing", Tier: "4", Since: "v5.0",
	},
	"glitchsupply": {
		Name: "glitchsupply", Protocol: "HTTPS",
		Description: "Supply chain scanner — dependency confusion, typosquatting, integrity checks",
		Flags:       []string{"--path", "--ecosystem", "--output"},
		Category: "supply_chain", Tier: "4", Since: "v5.1",
	},
	"glitchcloud": {
		Name: "glitchcloud", Protocol: "HTTPS",
		Description: "Cloud misconfiguration scanner — AWS/Azure/GCP, 15 CIS controls, SigV4",
		Flags:       []string{"--cloud", "--region", "--subscription-id", "--project", "--output"},
		Category: "cloud", Tier: "4", Since: "v5.2",
	},
	"glitchiot": {
		Name: "glitchiot", Protocol: "Multi",
		Description: "IoT/ICS scanner — 24 device signatures, Telnet/MQTT/CoAP/Modbus/UPnP, CIDR scan",
		Flags:       []string{"--target", "--protocol", "--threads", "--timeout", "--output"},
		Category: "iot", Tier: "4", Since: "v5.3",
	},
	"glitchai": {
		Name: "glitchai", Protocol: "HTTPS",
		Description: "AI-assisted security — triage/payload/recon/summary/chat (Ollama/Groq/Anthropic/OpenAI)",
		Flags:       []string{"triage", "payload", "recon", "summary", "chat", "--provider", "--model", "--findings"},
		Category: "ai_assisted", Tier: "4", Since: "v5.4",
	},
	"glitchorchestrator": {
		Name: "glitchorchestrator", Protocol: "HTTP",
		Description: "Distributed scan orchestrator — multi-node, round-robin, MD5 dedup, dashboard :7330",
		Flags:       []string{"serve", "run", "status", "report", "init", "--config", "--port", "--output"},
		DefaultPort: 7330, Category: "distributed", Tier: "4", Since: "v5.5",
	},
}

// ── Request/response types ────────────────────────────────

type ScanRequest struct {
	Target  string   `json:"target"`
	Args    []string `json:"args,omitempty"`
	Timeout int      `json:"timeout_s,omitempty"`
}

type ScanResponse struct {
	Binary       string        `json:"binary"`
	Target       string        `json:"target"`
	StartedAt    string        `json:"started_at"`
	CompletedAt  string        `json:"completed_at"`
	DurationS    float64       `json:"duration_s"`
	FindingCount int           `json:"finding_count"`
	Findings     []interface{} `json:"findings"`
	Status       string        `json:"status"`
	Error        string        `json:"error,omitempty"`
}

type AsyncResponse struct {
	JobID   string `json:"job_id"`
	Binary  string `json:"binary"`
	Target  string `json:"target"`
	Message string `json:"message"`
}

// ── Dispatcher ────────────────────────────────────────────

type Dispatcher struct {
	binDir         string
	defaultTimeout int
	totalScans     int64
	startTime      time.Time
}

func newDispatcher(binDir string, timeout int) *Dispatcher {
	return &Dispatcher{
		binDir:         binDir,
		defaultTimeout: timeout,
		startTime:      time.Now(),
	}
}

func (d *Dispatcher) scan(binaryName, target string, args []string, timeout int) ScanResponse {
	atomic.AddInt64(&d.totalScans, 1)
	startedAt := time.Now()

	resp := ScanResponse{
		Binary:    binaryName,
		Target:    target,
		StartedAt: startedAt.UTC().Format(time.RFC3339),
		Findings:  []interface{}{},
	}

	binPath := filepath.Join(d.binDir, binaryName)
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}

	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		resp.Status = "error"
		resp.Error  = fmt.Sprintf("binary not found: %s", binPath)
		resp.CompletedAt = time.Now().UTC().Format(time.RFC3339)
		return resp
	}

	if timeout <= 0 {
		timeout = d.defaultTimeout
	}

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("glitchd_%d.json", time.Now().UnixNano()))
	defer os.Remove(tmpFile)

	cmdArgs := []string{"--target", target, "--output", tmpFile}
	cmdArgs  = append(cmdArgs, args...)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, cmdArgs...)
	_, err := cmd.CombinedOutput()

	completedAt := time.Now()
	resp.CompletedAt = completedAt.UTC().Format(time.RFC3339)
	resp.DurationS   = completedAt.Sub(startedAt).Seconds()

	if ctx.Err() == context.DeadlineExceeded {
		resp.Status = "timeout"
		resp.Error  = fmt.Sprintf("binary timed out after %ds", timeout)
		return resp
	}

	if data, ferr := os.ReadFile(tmpFile); ferr == nil {
		var raw map[string]interface{}
		if jerr := json.Unmarshal(data, &raw); jerr == nil {
			if findings, ok := raw["findings"]; ok {
				if arr, ok := findings.([]interface{}); ok {
					resp.Findings     = arr
					resp.FindingCount = len(arr)
				}
			}
		}
	}

	if err != nil {
		if _, isExit := err.(*exec.ExitError); !isExit {
			resp.Status = "error"
			resp.Error  = err.Error()
			return resp
		}
	}

	resp.Status = "completed"
	return resp
}

func (d *Dispatcher) binaryExists(name string) bool {
	p := filepath.Join(d.binDir, name)
	if runtime.GOOS == "windows" {
		p += ".exe"
	}
	_, err := os.Stat(p)
	return err == nil
}

// ── HTTP Handlers ─────────────────────────────────────────

func (d *Dispatcher) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	path    := strings.TrimPrefix(r.URL.Path, "/scan/")
	async   := strings.HasSuffix(path, "/async")
	binName := strings.TrimSuffix(path, "/async")

	if binName == "" {
		http.Error(w, "binary name required: /scan/<binary>", http.StatusBadRequest)
		return
	}
	if strings.Contains(binName, "/") || strings.Contains(binName, "..") {
		http.Error(w, "invalid binary name", http.StatusBadRequest)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Target == "" {
		http.Error(w, "target is required", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if async {
		resp := AsyncResponse{
			JobID:   fmt.Sprintf("sync-%d", time.Now().UnixNano()),
			Binary:  binName,
			Target:  req.Target,
			Message: "for full async job management use glitchagent on :7331",
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(resp)
		return
	}

	result := d.scan(binName, req.Target, req.Args, req.Timeout)
	if result.Status == "error" {
		w.WriteHeader(http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(result)
}

func (d *Dispatcher) handleBinaries(w http.ResponseWriter, r *http.Request) {
	available := []map[string]interface{}{}
	for name, info := range BinaryRegistry {
		entry := map[string]interface{}{
			"name":        info.Name,
			"protocol":    info.Protocol,
			"description": info.Description,
			"category":    info.Category,
			"tier":        info.Tier,
			"since":       info.Since,
			"installed":   d.binaryExists(name),
		}
		if info.DefaultPort > 0 {
			entry["default_port"] = info.DefaultPort
		}
		available = append(available, entry)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"binaries": available,
		"total":    len(available),
		"version":  Version,
	})
}

func (d *Dispatcher) handleHealth(w http.ResponseWriter, r *http.Request) {
	installed := 0
	for name := range BinaryRegistry {
		if d.binaryExists(name) {
			installed++
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":              "ok",
		"version":             Version,
		"uptime":              time.Since(d.startTime).Round(time.Second).String(),
		"total_scans":         atomic.LoadInt64(&d.totalScans),
		"goroutines":          runtime.NumGoroutine(),
		"binaries_registered": len(BinaryRegistry),
		"binaries_installed":  installed,
	})
}

func (d *Dispatcher) handleVersion(w http.ResponseWriter, r *http.Request) {
	installed := []string{}
	missing   := []string{}
	for name := range BinaryRegistry {
		if d.binaryExists(name) {
			installed = append(installed, name)
		} else {
			missing = append(missing, name)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"version":             Version,
		"platform":            fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		"go_version":          runtime.Version(),
		"binaries_registered": len(BinaryRegistry),
		"binaries_installed":  installed,
		"binaries_missing":    missing,
	})
}

func (d *Dispatcher) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	tiers := map[string][]BinaryInfo{}
	for _, info := range BinaryRegistry {
		key := "tier_" + info.Tier + "_" + info.Category
		tiers[key] = append(tiers[key], info)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"version":    Version,
		"total":      len(BinaryRegistry),
		"categories": tiers,
	})
}

// ── Main ──────────────────────────────────────────────────

func main() {
	port    := flag.Int("port",    7332,   "HTTP port to listen on")
	binDir  := flag.String("bin-dir", "./bin", "Directory containing Go binaries")
	timeout := flag.Int("timeout", 60,    "Default scan timeout in seconds")
	ver     := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchd v%s\n", Version)
		os.Exit(0)
	}

	d := newDispatcher(*binDir, *timeout)

	// Count installed binaries on startup
	installed := 0
	for name := range BinaryRegistry {
		if d.binaryExists(name) {
			installed++
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/version",      d.handleVersion)
	mux.HandleFunc("/health",       d.handleHealth)
	mux.HandleFunc("/binaries",     d.handleBinaries)
	mux.HandleFunc("/capabilities", d.handleCapabilities)
	mux.HandleFunc("/scan/",        d.handleScan)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: time.Duration(*timeout+30) * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("[glitchd] v%s listening on :%d | bin-dir=%s | registered=%d installed=%d",
		Version, *port, *binDir, len(BinaryRegistry), installed)

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("[glitchd] error: %v", err)
	}
}
