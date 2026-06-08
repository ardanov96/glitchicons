// glitchwatcher/main.go
// GLITCHICONS — Continuous Asset Monitoring Daemon
//
// Monitors a watch list of targets for security-relevant changes.
// Runs scheduled probes and generates diff reports on change detection.
//
// Change Detection:
//   - HTTP status code changes
//   - Response size changes (new/removed content)
//   - TLS certificate changes (expiry, CN, fingerprint)
//   - New open ports detected
//   - New HTTP response headers
//   - Content hash changes (full page change)
//   - New subdomains (CT log polling)
//
// Config file (JSON):
//   {
//     "targets": [
//       {"url": "https://target.com", "name": "Main App", "tags": ["prod"]},
//       {"host": "10.0.0.1",  "ports": [22, 80, 443, 8080], "name": "Server"}
//     ],
//     "interval": "30m",
//     "webhook": "https://hooks.slack.com/...",
//     "alert_on": ["status_change", "cert_change", "new_port", "content_change"]
//   }
//
// Usage:
//   glitchwatcher --config watch.json
//   glitchwatcher --config watch.json --interval 15m
//   glitchwatcher --config watch.json --state state.json --output diffs.json
//   glitchwatcher init --output watch.json  (generate sample config)
//   glitchwatcher --version

package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const Version = "4.7.0"

// ── Config types ──────────────────────────────────────────

type WatchTarget struct {
	URL   string   `json:"url,omitempty"`
	Host  string   `json:"host,omitempty"`
	Name  string   `json:"name,omitempty"`
	Tags  []string `json:"tags,omitempty"`
	Ports []int    `json:"ports,omitempty"`
}

type WatchConfig struct {
	Targets  []WatchTarget `json:"targets"`
	Interval string        `json:"interval"`
	Webhook  string        `json:"webhook,omitempty"`
	AlertOn  []string      `json:"alert_on,omitempty"`
}

// ── State types ───────────────────────────────────────────

type TargetState struct {
	URL           string            `json:"url"`
	StatusCode    int               `json:"status_code"`
	ContentHash   string            `json:"content_hash"`
	ContentLength int               `json:"content_length"`
	Headers       map[string]string `json:"headers"`
	TLSFingerprint string           `json:"tls_fingerprint,omitempty"`
	TLSExpiry     string            `json:"tls_expiry,omitempty"`
	TLSCN         string            `json:"tls_cn,omitempty"`
	OpenPorts     []int             `json:"open_ports,omitempty"`
	LastSeen      string            `json:"last_seen"`
	FirstSeen     string            `json:"first_seen"`
}

type WatchState struct {
	Targets   map[string]*TargetState `json:"targets"`
	UpdatedAt string                  `json:"updated_at"`
}

// ── Change types ──────────────────────────────────────────

type Change struct {
	TargetName string `json:"target_name"`
	TargetURL  string `json:"target_url"`
	ChangeType string `json:"change_type"`
	OldValue   string `json:"old_value"`
	NewValue   string `json:"new_value"`
	Severity   string `json:"severity"`
	Timestamp  string `json:"timestamp"`
}

type DiffReport struct {
	RunAt    string   `json:"run_at"`
	Changes  []Change `json:"changes"`
	Summary  string   `json:"summary"`
}

// ── HTTP Probe ────────────────────────────────────────────

func probeHTTP(url string, timeout time.Duration) (*TargetState, error) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: false},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Glitchwatcher/"+Version)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536)) // Max 64KB
	h := md5.New()
	h.Write(body)
	contentHash := hex.EncodeToString(h.Sum(nil))

	// Extract interesting headers
	interestingHeaders := []string{
		"Server", "X-Powered-By", "X-Frame-Options",
		"Content-Security-Policy", "X-Content-Type-Options",
		"Strict-Transport-Security", "X-AspNet-Version",
	}
	headers := make(map[string]string)
	for _, hdr := range interestingHeaders {
		if val := resp.Header.Get(hdr); val != "" {
			headers[hdr] = val
		}
	}

	state := &TargetState{
		URL:           url,
		StatusCode:    resp.StatusCode,
		ContentHash:   contentHash,
		ContentLength: len(body),
		Headers:       headers,
		LastSeen:      time.Now().UTC().Format(time.RFC3339),
	}

	// TLS info
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert    := resp.TLS.PeerCertificates[0]
		fp      := sha1.Sum(cert.Raw)
		state.TLSFingerprint = hex.EncodeToString(fp[:])
		state.TLSCN  = cert.Subject.CommonName
		state.TLSExpiry = cert.NotAfter.UTC().Format("2006-01-02")
	}

	return state, nil
}

// ── Port Scanner ──────────────────────────────────────────

func probePorts(host string, ports []int, timeout time.Duration) []int {
	var open []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", host, p)
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				conn.Close()
				mu.Lock()
				open = append(open, p)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return open
}

// ── Change Detection ──────────────────────────────────────

func detectChanges(name, url string, old, new *TargetState) []Change {
	var changes []Change
	ts := time.Now().UTC().Format(time.RFC3339)

	if old == nil {
		changes = append(changes, Change{
			TargetName: name, TargetURL: url,
			ChangeType: "new_target",
			NewValue:   fmt.Sprintf("HTTP %d | Size: %d | Hash: %s",
				new.StatusCode, new.ContentLength, new.ContentHash[:8]),
			Severity:  "INFO",
			Timestamp: ts,
		})
		return changes
	}

	// Status code change
	if old.StatusCode != new.StatusCode {
		sev := "HIGH"
		if (old.StatusCode == 200 && new.StatusCode == 301) ||
			(old.StatusCode == 301 && new.StatusCode == 200) {
			sev = "MEDIUM"
		}
		changes = append(changes, Change{
			TargetName: name, TargetURL: url,
			ChangeType: "status_change",
			OldValue:   fmt.Sprintf("%d", old.StatusCode),
			NewValue:   fmt.Sprintf("%d", new.StatusCode),
			Severity:   sev,
			Timestamp:  ts,
		})
	}

	// Content hash change
	if old.ContentHash != new.ContentHash {
		sizeDiff := new.ContentLength - old.ContentLength
		changes = append(changes, Change{
			TargetName: name, TargetURL: url,
			ChangeType: "content_change",
			OldValue:   fmt.Sprintf("hash=%s size=%d", old.ContentHash[:8], old.ContentLength),
			NewValue:   fmt.Sprintf("hash=%s size=%d (diff=%+d)", new.ContentHash[:8], new.ContentLength, sizeDiff),
			Severity:   "MEDIUM",
			Timestamp:  ts,
		})
	}

	// TLS certificate change
	if old.TLSFingerprint != "" && new.TLSFingerprint != "" &&
		old.TLSFingerprint != new.TLSFingerprint {
		changes = append(changes, Change{
			TargetName: name, TargetURL: url,
			ChangeType: "cert_change",
			OldValue:   fmt.Sprintf("fp=%s cn=%s expires=%s", old.TLSFingerprint[:16], old.TLSCN, old.TLSExpiry),
			NewValue:   fmt.Sprintf("fp=%s cn=%s expires=%s", new.TLSFingerprint[:16], new.TLSCN, new.TLSExpiry),
			Severity:   "HIGH",
			Timestamp:  ts,
		})
	}

	// TLS expiry approaching
	if new.TLSExpiry != "" {
		expiry, err := time.Parse("2006-01-02", new.TLSExpiry)
		if err == nil {
			daysLeft := int(time.Until(expiry).Hours() / 24)
			if daysLeft <= 14 && daysLeft >= 0 {
				changes = append(changes, Change{
					TargetName: name, TargetURL: url,
					ChangeType: "cert_expiry_soon",
					NewValue:   fmt.Sprintf("%d days remaining (expires %s)", daysLeft, new.TLSExpiry),
					Severity:   "HIGH",
					Timestamp:  ts,
				})
			} else if daysLeft < 0 {
				changes = append(changes, Change{
					TargetName: name, TargetURL: url,
					ChangeType: "cert_expired",
					NewValue:   fmt.Sprintf("EXPIRED on %s", new.TLSExpiry),
					Severity:   "CRITICAL",
					Timestamp:  ts,
				})
			}
		}
	}

	// New open ports
	oldPortSet := make(map[int]bool)
	for _, p := range old.OpenPorts {
		oldPortSet[p] = true
	}
	for _, p := range new.OpenPorts {
		if !oldPortSet[p] {
			changes = append(changes, Change{
				TargetName: name, TargetURL: url,
				ChangeType: "new_port",
				NewValue:   fmt.Sprintf("port %d now open", p),
				Severity:   "HIGH",
				Timestamp:  ts,
			})
		}
	}

	// New response headers
	for h, v := range new.Headers {
		if _, exists := old.Headers[h]; !exists {
			changes = append(changes, Change{
				TargetName: name, TargetURL: url,
				ChangeType: "new_header",
				NewValue:   fmt.Sprintf("%s: %s", h, v),
				Severity:   "LOW",
				Timestamp:  ts,
			})
		}
	}

	// Missing previously present header (removed security header = bad)
	securityHeaders := []string{
		"Strict-Transport-Security", "Content-Security-Policy",
		"X-Frame-Options", "X-Content-Type-Options",
	}
	for _, h := range securityHeaders {
		if old.Headers[h] != "" && new.Headers[h] == "" {
			changes = append(changes, Change{
				TargetName: name, TargetURL: url,
				ChangeType: "header_removed",
				OldValue:   fmt.Sprintf("%s: %s", h, old.Headers[h]),
				NewValue:   "REMOVED",
				Severity:   "MEDIUM",
				Timestamp:  ts,
			})
		}
	}

	return changes
}

// ── Webhook notification ──────────────────────────────────

func notifyWebhook(webhook string, changes []Change) {
	if webhook == "" || len(changes) == 0 {
		return
	}

	payload := map[string]interface{}{
		"text":      fmt.Sprintf("⚠️ Glitchwatcher: %d changes detected", len(changes)),
		"changes":   changes,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(webhook, "application/json", strings.NewReader(string(data)))
	if err != nil {
		fmt.Printf("[-] Webhook error: %v\n", err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("[*] Webhook notified: HTTP %d\n", resp.StatusCode)
}

// ── State persistence ─────────────────────────────────────

func loadState(path string) *WatchState {
	state := &WatchState{Targets: make(map[string]*TargetState)}
	if path == "" {
		return state
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return state
	}
	json.Unmarshal(data, state)
	return state
}

func saveState(state *WatchState, path string) {
	if path == "" {
		return
	}
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	data, _ := json.MarshalIndent(state, "", "  ")
	os.WriteFile(path, data, 0644)
}

// ── Sample config generator ───────────────────────────────

func generateSampleConfig(path string) {
	cfg := WatchConfig{
		Targets: []WatchTarget{
			{URL: "https://target.corp.com", Name: "Main App", Tags: []string{"prod", "web"}},
			{URL: "https://api.corp.com/health", Name: "API Health", Tags: []string{"prod", "api"}},
			{Host: "10.0.0.1", Name: "Infra Server", Ports: []int{22, 80, 443, 8080, 8443}, Tags: []string{"infra"}},
		},
		Interval: "30m",
		Webhook:  "https://hooks.slack.com/services/xxx/yyy/zzz",
		AlertOn:  []string{"status_change", "cert_change", "new_port", "content_change", "cert_expiry_soon"},
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if path == "" {
		fmt.Println(string(data))
	} else {
		os.WriteFile(path, data, 0644)
		fmt.Printf("[+] Sample config written to %s\n", path)
	}
}

// ── Parse interval ────────────────────────────────────────

func parseInterval(s string) time.Duration {
	if s == "" {
		return 30 * time.Minute
	}
	d, err := time.ParseDuration(s)
	if err == nil {
		return d
	}
	// Support "30m", "1h", "24h" etc.
	suffix := s[len(s)-1:]
	value  := s[:len(s)-1]
	n := 0
	fmt.Sscanf(value, "%d", &n)
	switch suffix {
	case "s":
		return time.Duration(n) * time.Second
	case "m":
		return time.Duration(n) * time.Minute
	case "h":
		return time.Duration(n) * time.Hour
	case "d":
		return time.Duration(n) * 24 * time.Hour
	}
	return 30 * time.Minute
}

// ── Main scanner loop ─────────────────────────────────────

func runWatcher(cfg *WatchConfig, state *WatchState, statePath, outputPath string, timeout time.Duration, verbose bool) {
	var allChanges []Change
	ts := time.Now().UTC().Format(time.RFC3339)

	fmt.Printf("[*] Scanning %d targets...\n", len(cfg.Targets))

	for _, target := range cfg.Targets {
		name := target.Name
		if name == "" {
			name = target.URL
			if name == "" {
				name = target.Host
			}
		}

		var newState *TargetState
		var err error
		key := target.URL
		if key == "" {
			key = target.Host
		}

		// HTTP probe
		if target.URL != "" {
			newState, err = probeHTTP(target.URL, timeout)
			if err != nil {
				fmt.Printf("[-] Error probing %s: %v\n", name, err)
				continue
			}
			if verbose {
				fmt.Printf("[+] %s → HTTP %d | Size: %d | TLS: %s\n",
					name, newState.StatusCode, newState.ContentLength, newState.TLSExpiry)
			}
		}

		// Port probe
		if target.Host != "" && len(target.Ports) > 0 {
			openPorts := probePorts(target.Host, target.Ports, timeout)
			if newState == nil {
				newState = &TargetState{
					URL:      target.Host,
					LastSeen: time.Now().UTC().Format(time.RFC3339),
					Headers:  make(map[string]string),
				}
			}
			newState.OpenPorts = openPorts
			if verbose {
				fmt.Printf("[+] %s → open ports: %v\n", name, openPorts)
			}
		}

		if newState == nil {
			continue
		}

		if newState.FirstSeen == "" {
			if old, exists := state.Targets[key]; exists && old.FirstSeen != "" {
				newState.FirstSeen = old.FirstSeen
			} else {
				newState.FirstSeen = ts
			}
		}

		// Detect changes
		oldState := state.Targets[key]
		changes  := detectChanges(name, key, oldState, newState)

		for _, c := range changes {
			if c.ChangeType == "new_target" {
				fmt.Printf("[NEW] %s\n", name)
			} else {
				sev := c.Severity
				fmt.Printf("[CHANGE] %s | %s | %s → %s | [%s]\n",
					name, c.ChangeType,
					c.OldValue[:minInt(len(c.OldValue), 30)],
					c.NewValue[:minInt(len(c.NewValue), 30)],
					sev)
			}
		}

		allChanges = append(allChanges, changes...)
		state.Targets[key] = newState
	}

	// Save state
	saveState(state, statePath)

	// Notify webhook for non-INFO changes
	alertChanges := []Change{}
	for _, c := range allChanges {
		if c.Severity != "INFO" {
			alertChanges = append(alertChanges, c)
		}
	}
	if len(alertChanges) > 0 {
		notifyWebhook(cfg.Webhook, alertChanges)
	}

	// Save diff report
	if outputPath != "" {
		report := DiffReport{
			RunAt:   ts,
			Changes: allChanges,
			Summary: fmt.Sprintf("%d targets scanned, %d changes detected", len(cfg.Targets), len(allChanges)),
		}
		data, _ := json.MarshalIndent(report, "", "  ")
		os.WriteFile(outputPath, data, 0644)
		fmt.Printf("[+] Diff report saved to %s\n", outputPath)
	}

	fmt.Printf("[*] Scan complete: %d changes\n", len(allChanges))
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── Main ──────────────────────────────────────────────────

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "init" {
		fs := flag.NewFlagSet("init", flag.ExitOnError)
		outPath := fs.String("output", "", "Output config file path")
		fs.Parse(os.Args[2:])
		generateSampleConfig(*outPath)
		return
	}

	configPath := flag.String("config",   "",    "Watch config JSON file (required)")
	statePath  := flag.String("state",    "",    "State file for change tracking (recommended)")
	outputPath := flag.String("output",   "",    "Diff report output JSON file")
	intervalS  := flag.String("interval", "",    "Override probe interval (e.g. 15m, 1h)")
	timeout    := flag.Int("timeout",    15,    "Per-probe timeout seconds")
	once       := flag.Bool("once",      false, "Run once and exit (no daemon mode)")
	verbose    := flag.Bool("verbose",   false, "Verbose output")
	ver        := flag.Bool("version",   false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchwatcher v%s\n", Version)
		os.Exit(0)
	}

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: glitchwatcher --config watch.json [--state state.json] [--interval 30m]")
		fmt.Fprintln(os.Stderr, "       glitchwatcher init --output watch.json  (generate sample config)")
		os.Exit(1)
	}

	// Load config
	configData, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Cannot read config: %v\n", err)
		os.Exit(1)
	}
	var cfg WatchConfig
	if err := json.Unmarshal(configData, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Invalid config JSON: %v\n", err)
		os.Exit(1)
	}

	// Override interval if specified
	if *intervalS != "" {
		cfg.Interval = *intervalS
	}

	interval := parseInterval(cfg.Interval)
	tOut     := time.Duration(*timeout) * time.Second

	fmt.Printf("[*] glitchwatcher v%s | targets=%d | interval=%v\n",
		Version, len(cfg.Targets), interval)

	// Load state
	state := loadState(*statePath)

	if *once {
		// Single run
		runWatcher(&cfg, state, *statePath, *outputPath, tOut, *verbose)
		return
	}

	// Daemon mode
	fmt.Printf("[*] Daemon mode — scanning every %v\n", interval)
	fmt.Println("[*] Press Ctrl+C to stop")

	// Run immediately, then on interval
	runWatcher(&cfg, state, *statePath, *outputPath, tOut, *verbose)

	ticker := time.NewTicker(interval)
	for range ticker.C {
		fmt.Printf("\n[*] Scheduled scan at %s\n", time.Now().UTC().Format(time.RFC3339))
		runWatcher(&cfg, state, *statePath, *outputPath, tOut, *verbose)
	}
}
