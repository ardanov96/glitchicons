// glitchd/main.go
// GLITCHICONS — Unified Go Binary Dispatcher
//
// Single entry point that routes scan requests to the correct
// Go binary. Replaces direct binary invocation with a unified
// HTTP API that Python can call consistently.
//
// API:
//   GET  /version           — version info + available binaries
//   GET  /health            — health check
//   GET  /binaries          — list available binaries with capabilities
//   POST /scan/:binary      — run binary synchronously (returns findings)
//   POST /scan/:binary/async — run binary asynchronously (returns job ID)
//   GET  /capabilities      — full capability matrix
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

const Version = "4.0.0"

// ── Binary capability registry ────────────────────────────

type BinaryInfo struct {
	Name        string   `json:"name"`
	Protocol    string   `json:"protocol"`
	Description string   `json:"description"`
	Flags       []string `json:"supported_flags"`
	DefaultPort int      `json:"default_port,omitempty"`
	Category    string   `json:"category"`
}

var BinaryRegistry = map[string]BinaryInfo{
	"glitchscan": {
		Name: "glitchscan", Protocol: "TCP",
		Description: "High-speed port scanner",
		Flags:       []string{"--target", "--ports", "--timeout", "--output"},
		Category:    "recon",
	},
	"glitchdns": {
		Name: "glitchdns", Protocol: "DNS",
		Description: "DNS brute force and enumeration",
		Flags:       []string{"--target", "--wordlist", "--timeout", "--output"},
		Category:    "recon",
	},
	"glitchtls": {
		Name: "glitchtls", Protocol: "TLS",
		Description: "TLS/SSL certificate and cipher audit",
		Flags:       []string{"--target", "--port", "--timeout", "--output"},
		DefaultPort: 443, Category: "protocol",
	},
	"glitchsmb": {
		Name: "glitchsmb", Protocol: "SMB",
		Description: "SMB version detection and signing audit",
		Flags:       []string{"--target", "--port", "--timeout", "--output"},
		DefaultPort: 445, Category: "protocol",
	},
	"glitchssh": {
		Name: "glitchssh", Protocol: "SSH",
		Description: "SSH algorithm and configuration audit",
		Flags:       []string{"--target", "--port", "--timeout", "--output"},
		DefaultPort: 22, Category: "protocol",
	},
	"glitchrdp": {
		Name: "glitchrdp", Protocol: "RDP",
		Description: "RDP NLA enforcement and TLS analysis",
		Flags:       []string{"--target", "--port", "--timeout", "--output"},
		DefaultPort: 3389, Category: "protocol",
	},
	"glitchldap": {
		Name: "glitchldap", Protocol: "LDAP",
		Description: "LDAP anonymous bind and credential testing",
		Flags:       []string{"--target", "--port", "--tls", "--timeout", "--output"},
		DefaultPort: 389, Category: "protocol",
	},
	"glitchsnmp": {
		Name: "glitchsnmp", Protocol: "SNMP/UDP",
		Description: "SNMP community string brute force",
		Flags:       []string{"--target", "--port", "--wordlist", "--timeout", "--output"},
		DefaultPort: 161, Category: "protocol",
	},
	"glitchftp": {
		Name: "glitchftp", Protocol: "FTP",
		Description: "FTP anonymous login and default credential test",
		Flags:       []string{"--target", "--port", "--timeout", "--output"},
		DefaultPort: 21, Category: "protocol",
	},
	"glitchvnc": {
		Name: "glitchvnc", Protocol: "VNC/RFB",
		Description: "VNC no-auth detection and version fingerprint",
		Flags:       []string{"--target", "--port", "--timeout", "--output"},
		DefaultPort: 5900, Category: "protocol",
	},
	"glitchfuzz": {
		Name: "glitchfuzz", Protocol: "HTTP",
		Description: "High-throughput HTTP parameter fuzzer",
		Flags:       []string{"--url", "--method", "--data", "--timeout", "--output"},
		Category:    "fuzz",
	},
	"glitchfuzz2": {
		Name: "glitchfuzz2", Protocol: "HTTP",
		Description: "Mutation-based fuzzer with 5 attack modes",
		Flags:       []string{"body", "header", "cookie", "path", "json"},
		Category:    "fuzz",
	},
	"glitchrace": {
		Name: "glitchrace", Protocol: "HTTP",
		Description: "Race condition detection (nanosecond precision)",
		Flags:       []string{"--url", "--concurrency", "--timeout", "--output"},
		Category:    "exploit",
	},
	"glitchproxy": {
		Name: "glitchproxy", Protocol: "HTTP",
		Description: "Intercepting proxy with finding injection",
		Flags:       []string{"--port", "--upstream", "--output"},
		Category:    "proxy",
	},
}

// ── Request/response types ────────────────────────────────

type ScanRequest struct {
	Target  string   `json:"target"`
	Args    []string `json:"args,omitempty"`
	Timeout int      `json:"timeout_s,omitempty"`
}

type ScanResponse struct {
	Binary      string        `json:"binary"`
	Target      string        `json:"target"`
	StartedAt   string        `json:"started_at"`
	CompletedAt string        `json:"completed_at"`
	DurationS   float64       `json:"duration_s"`
	FindingCount int          `json:"finding_count"`
	Findings    []interface{} `json:"findings"`
	Status      string        `json:"status"`
	Error       string        `json:"error,omitempty"`
}

type AsyncResponse struct {
	JobID   string `json:"job_id"`
	Binary  string `json:"binary"`
	Target  string `json:"target"`
	Message string `json:"message"`
}

// ── Dispatcher ────────────────────────────────────────────

type Dispatcher struct {
	binDir      string
	defaultTimeout int
	totalScans  int64
	startTime   time.Time
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

	// Parse output file
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
		_, isExit := err.(*exec.ExitError)
		if !isExit {
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

	// Extract binary name from path: /scan/:binary or /scan/:binary/async
	path    := strings.TrimPrefix(r.URL.Path, "/scan/")
	async   := strings.HasSuffix(path, "/async")
	binName := strings.TrimSuffix(path, "/async")

	if binName == "" {
		http.Error(w, "binary name required: /scan/<binary>", http.StatusBadRequest)
		return
	}

	// Validate binary name (security: no path traversal)
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
		// Return immediately with job ID hint (full async via glitchagent)
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

	// Synchronous scan
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
	})
}

func (d *Dispatcher) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "ok",
		"version":     Version,
		"uptime":      time.Since(d.startTime).Round(time.Second).String(),
		"total_scans": atomic.LoadInt64(&d.totalScans),
		"goroutines":  runtime.NumGoroutine(),
	})
}

func (d *Dispatcher) handleVersion(w http.ResponseWriter, r *http.Request) {
	installed := []string{}
	for name := range BinaryRegistry {
		if d.binaryExists(name) {
			installed = append(installed, name)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"version":             Version,
		"platform":            fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		"go_version":          runtime.Version(),
		"binaries_installed":  installed,
		"binaries_registered": len(BinaryRegistry),
	})
}

func (d *Dispatcher) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	categories := map[string][]BinaryInfo{}
	for _, info := range BinaryRegistry {
		categories[info.Category] = append(categories[info.Category], info)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"version":    Version,
		"categories": categories,
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

	log.Printf("[glitchd] v%s listening on :%d | bin-dir=%s | timeout=%ds",
		Version, *port, *binDir, *timeout)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("[glitchd] error: %v", err)
	}
}
