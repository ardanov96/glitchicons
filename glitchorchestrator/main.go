// glitchorchestrator/main.go
// GLITCHICONS — Distributed Scan Orchestrator
//
// Central controller that distributes scan jobs across multiple
// glitchagent nodes, aggregates findings, and generates unified reports.
//
// Architecture:
//   Orchestrator (this binary, port 7330)
//     ├── Node registry + health monitor
//     ├── Job queue + round-robin distributor
//     ├── Finding aggregator + deduplicator
//     └── HTTP dashboard + REST API
//
//   Worker Nodes (glitchagent instances, port 7331)
//     ├── POST /jobs   — receive scan job
//     ├── GET  /jobs/:id/results — return findings
//     └── GET  /health — health check
//
// Commands:
//   serve   — Start orchestrator daemon + dashboard (default)
//   run     — Execute scan plan from config file, then exit
//   status  — Check health of all registered nodes
//   report  — Aggregate + print all collected findings
//
// Config file (JSON):
//   {
//     "nodes": [
//       {"name": "node1", "url": "http://10.0.0.1:7331"},
//       {"name": "node2", "url": "http://10.0.0.2:7331"}
//     ],
//     "targets": ["192.168.1.1", "192.168.1.10", "https://app.corp.com"],
//     "scan_plan": ["glitchscan", "glitchssh", "glitchsmb", "glitchhttp2"],
//     "concurrency": 4,
//     "timeout_s": 60
//   }
//
// Usage:
//   glitchorchestrator serve  --config plan.json --port 7330
//   glitchorchestrator run    --config plan.json --output findings.json
//   glitchorchestrator status --config plan.json
//   glitchorchestrator init   --output plan.json
//   glitchorchestrator --version

package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const Version = "5.5.0"

// ── Config types ──────────────────────────────────────────

type NodeConfig struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type OrchestratorConfig struct {
	Nodes       []NodeConfig `json:"nodes"`
	Targets     []string     `json:"targets"`
	ScanPlan    []string     `json:"scan_plan"`
	Concurrency int          `json:"concurrency"`
	TimeoutS    int          `json:"timeout_s"`
	Webhook     string       `json:"webhook,omitempty"`
}

// ── Node registry ─────────────────────────────────────────

type NodeStatus struct {
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Healthy     bool      `json:"healthy"`
	ActiveJobs  int       `json:"active_jobs"`
	TotalJobs   int64     `json:"total_jobs_sent"`
	LastSeen    time.Time `json:"last_seen"`
	GoRoutines  int       `json:"goroutines,omitempty"`
	Uptime      string    `json:"uptime,omitempty"`
	Version     string    `json:"version,omitempty"`
}

type Node struct {
	mu     sync.RWMutex
	Status NodeStatus
	client *http.Client
}

func newNode(cfg NodeConfig) *Node {
	return &Node{
		Status: NodeStatus{
			Name: cfg.Name,
			URL:  cfg.URL,
		},
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *Node) checkHealth() bool {
	resp, err := n.client.Get(n.Status.URL + "/health")
	if err != nil {
		n.mu.Lock()
		n.Status.Healthy = false
		n.mu.Unlock()
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var health map[string]interface{}
	json.Unmarshal(body, &health)

	n.mu.Lock()
	n.Status.Healthy  = resp.StatusCode == 200
	n.Status.LastSeen = time.Now()
	if v, ok := health["version"].(string); ok {
		n.Status.Version = v
	}
	if u, ok := health["uptime"].(string); ok {
		n.Status.Uptime = u
	}
	if g, ok := health["goroutines"].(float64); ok {
		n.Status.GoRoutines = int(g)
	}
	n.mu.Unlock()
	return n.Status.Healthy
}

func (n *Node) submitJob(binary, target string, timeoutS int) (string, error) {
	type JobReq struct {
		Binary  string `json:"binary"`
		Target  string `json:"target"`
		Timeout int    `json:"timeout_s"`
	}
	req := JobReq{Binary: binary, Target: target, Timeout: timeoutS}
	body, _ := json.Marshal(req)

	resp, err := n.client.Post(
		n.Status.URL+"/jobs",
		"application/json",
		strings.NewReader(string(body)),
	)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	jobID, _ := result["id"].(string)
	if jobID == "" {
		return "", fmt.Errorf("no job ID returned")
	}

	atomic.AddInt64(&n.Status.TotalJobs, 1)
	return jobID, nil
}

func (n *Node) pollJobResult(jobID string, maxWait time.Duration) ([]Finding, error) {
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		// Check status
		resp, err := n.client.Get(n.Status.URL + "/jobs/" + jobID)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var status map[string]interface{}
		json.Unmarshal(body, &status)

		jobStatus, _ := status["status"].(string)
		switch jobStatus {
		case "completed":
			// Fetch results
			rResp, err := n.client.Get(n.Status.URL + "/jobs/" + jobID + "/results")
			if err != nil {
				return nil, err
			}
			defer rResp.Body.Close()
			rBody, _ := io.ReadAll(rResp.Body)

			var results JobResult
			json.Unmarshal(rBody, &results)
			return results.Findings, nil

		case "failed":
			errMsg, _ := status["error"].(string)
			return nil, fmt.Errorf("job failed: %s", errMsg)

		case "pending", "running":
			time.Sleep(3 * time.Second)
			continue
		}
		time.Sleep(2 * time.Second)
	}
	return nil, fmt.Errorf("job timed out after %v", maxWait)
}

// ── Finding types ─────────────────────────────────────────

type Finding struct {
	Title       string  `json:"title"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss"`
	CWE         string  `json:"cwe,omitempty"`
	Target      string  `json:"target"`
	Description string  `json:"description"`
	Evidence    string  `json:"evidence,omitempty"`
	Remediation string  `json:"remediation,omitempty"`
	Source      string  `json:"source,omitempty"`
	Node        string  `json:"scanned_by,omitempty"`
	Binary      string  `json:"binary,omitempty"`
	Timestamp   string  `json:"timestamp,omitempty"`
}

type JobResult struct {
	JobID    string    `json:"job_id"`
	Binary   string    `json:"binary"`
	Target   string    `json:"target"`
	Findings []Finding `json:"findings"`
}

// ── Finding aggregator ────────────────────────────────────

type Aggregator struct {
	mu       sync.Mutex
	findings []Finding
	seen     map[string]bool
}

func newAggregator() *Aggregator {
	return &Aggregator{seen: make(map[string]bool)}
}

func (a *Aggregator) Add(findings []Finding, nodeName, binary string) int {
	added := 0
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, f := range findings {
		// Dedup key: hash of title+target+severity
		key := md5hash(f.Title + "|" + f.Target + "|" + f.Severity)
		if a.seen[key] {
			continue
		}
		a.seen[key] = true
		f.Node   = nodeName
		f.Binary = binary
		f.Timestamp = time.Now().UTC().Format(time.RFC3339)
		a.findings = append(a.findings, f)
		added++
	}
	return added
}

func (a *Aggregator) All() []Finding {
	a.mu.Lock()
	defer a.mu.Unlock()
	cp := make([]Finding, len(a.findings))
	copy(cp, a.findings)
	return cp
}

func (a *Aggregator) Summary() map[string]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	for _, f := range a.findings {
		s[strings.ToUpper(f.Severity)]++
	}
	return s
}

func md5hash(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// ── Job distributor ───────────────────────────────────────

type Job struct {
	Binary  string
	Target  string
	Timeout int
}

type Orchestrator struct {
	cfg      *OrchestratorConfig
	nodes    []*Node
	aggr     *Aggregator
	jobCount int64
	startTime time.Time
	mu       sync.RWMutex
}

func newOrchestrator(cfg *OrchestratorConfig) *Orchestrator {
	o := &Orchestrator{
		cfg:       cfg,
		aggr:      newAggregator(),
		startTime: time.Now(),
	}
	for _, nc := range cfg.Nodes {
		o.nodes = append(o.nodes, newNode(nc))
	}
	return o
}

func (o *Orchestrator) healthyNodes() []*Node {
	var healthy []*Node
	for _, n := range o.nodes {
		n.mu.RLock()
		if n.Status.Healthy {
			healthy = append(healthy, n)
		}
		n.mu.RUnlock()
	}
	return healthy
}

func (o *Orchestrator) pickNode(idx int) *Node {
	healthy := o.healthyNodes()
	if len(healthy) == 0 {
		// Fallback: try all nodes
		return o.nodes[idx%len(o.nodes)]
	}
	return healthy[idx%len(healthy)]
}

func (o *Orchestrator) startHealthMonitor() {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		// Initial check
		for _, n := range o.nodes {
			n.checkHealth()
		}
		for range ticker.C {
			for _, n := range o.nodes {
				go n.checkHealth()
			}
		}
	}()
}

func (o *Orchestrator) runScanPlan(verbose bool) {
	// Generate all jobs: binary × target
	var jobs []Job
	for _, target := range o.cfg.Targets {
		for _, binary := range o.cfg.ScanPlan {
			jobs = append(jobs, Job{Binary: binary, Target: target, Timeout: o.cfg.TimeoutS})
		}
	}

	timeout := o.cfg.TimeoutS
	if timeout <= 0 {
		timeout = 60
	}
	concurrency := o.cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 4
	}

	fmt.Printf("[*] Scan plan: %d jobs (%d targets × %d binaries) | concurrency=%d\n",
		len(jobs), len(o.cfg.Targets), len(o.cfg.ScanPlan), concurrency)

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var jobIdx int64

	for i, job := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(j Job, idx int) {
			defer wg.Done()
			defer func() { <-sem }()

			nodeIdx := int(atomic.AddInt64(&jobIdx, 1)) - 1
			node    := o.pickNode(nodeIdx)

			if verbose {
				fmt.Printf("[→] %s on %s via %s\n", j.Binary, j.Target, node.Status.Name)
			}

			jobID, err := node.submitJob(j.Binary, j.Target, j.Timeout)
			if err != nil {
				fmt.Printf("[-] Submit failed (%s/%s): %v\n", j.Binary, j.Target, err)
				return
			}

			maxWait := time.Duration(j.Timeout+30) * time.Second
			findings, err := node.pollJobResult(jobID, maxWait)
			if err != nil {
				if verbose {
					fmt.Printf("[-] Poll failed (%s/%s): %v\n", j.Binary, j.Target, err)
				}
				return
			}

			added := o.aggr.Add(findings, node.Status.Name, j.Binary)
			atomic.AddInt64(&o.jobCount, 1)

			if added > 0 || verbose {
				fmt.Printf("[✓] %s → %s | +%d findings (node: %s)\n",
					j.Binary, j.Target, added, node.Status.Name)
			}
		}(job, i)
	}
	wg.Wait()

	// Summary
	summary := o.aggr.Summary()
	total   := 0
	for _, v := range summary {
		total += v
	}
	fmt.Printf("\n[*] Scan complete: %d jobs | %d findings (CRIT:%d HIGH:%d MED:%d LOW:%d)\n",
		atomic.LoadInt64(&o.jobCount),
		total,
		summary["CRITICAL"], summary["HIGH"],
		summary["MEDIUM"], summary["LOW"])
}

// ── HTTP Dashboard ────────────────────────────────────────

func (o *Orchestrator) startDashboard(port int) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", o.handleDashboardHTML)
	mux.HandleFunc("/status", o.handleStatus)
	mux.HandleFunc("/findings", o.handleFindings)
	mux.HandleFunc("/run", o.handleRun)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"version": Version,
			"uptime":  time.Since(o.startTime).Round(time.Second).String(),
			"nodes":   len(o.nodes),
			"jobs":    atomic.LoadInt64(&o.jobCount),
		})
	})

	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("[*] Dashboard: http://localhost%s\n", addr)
	fmt.Printf("[*] Endpoints: /status /findings /run /health\n")
	http.ListenAndServe(addr, mux)
}

func (o *Orchestrator) handleStatus(w http.ResponseWriter, r *http.Request) {
	statuses := []NodeStatus{}
	for _, n := range o.nodes {
		n.mu.RLock()
		statuses = append(statuses, n.Status)
		n.mu.RUnlock()
	}
	summary := o.aggr.Summary()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"orchestrator_version": Version,
		"uptime":               time.Since(o.startTime).Round(time.Second).String(),
		"nodes":                statuses,
		"jobs_dispatched":      atomic.LoadInt64(&o.jobCount),
		"findings":             summary,
	})
}

func (o *Orchestrator) handleFindings(w http.ResponseWriter, r *http.Request) {
	findings := o.aggr.All()
	// Sort by CVSS descending
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].CVSS > findings[j].CVSS
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":    len(findings),
		"summary":  o.aggr.Summary(),
		"findings": findings,
	})
}

func (o *Orchestrator) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	go o.runScanPlan(true)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "scan_started",
		"message": "Scan plan dispatched to nodes. Poll /findings for results.",
	})
}

func (o *Orchestrator) handleDashboardHTML(w http.ResponseWriter, r *http.Request) {
	summary := o.aggr.Summary()
	total   := 0
	for _, v := range summary {
		total += v
	}

	healthyCount := 0
	for _, n := range o.nodes {
		n.mu.RLock()
		if n.Status.Healthy {
			healthyCount++
		}
		n.mu.RUnlock()
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <title>GLITCHICONS Orchestrator v%s</title>
  <meta http-equiv="refresh" content="10">
  <style>
    body { background:#0a0010; color:#e0e0e0; font-family:'Courier New',monospace; padding:2rem; }
    h1   { color:#A855F7; letter-spacing:.2em; }
    .stat { display:inline-block; background:#1a0030; border:1px solid #6B00FF;
            padding:.5rem 1.5rem; margin:.5rem; border-radius:4px; }
    .stat-num { font-size:2rem; color:#BF00FF; display:block; }
    .stat-lbl { font-size:.7rem; color:#888; }
    .crit { color:#FF0040; } .high { color:#FF6B00; }
    .med  { color:#FFB300; } .info { color:#00E5FF; }
    table { border-collapse:collapse; width:100%; margin-top:1rem; }
    th,td { padding:.4rem .8rem; border:1px solid #2a0050; text-align:left; font-size:.8rem; }
    th    { background:#1a0030; color:#A855F7; }
    tr:hover { background:#1a0020; }
    .btn { background:#6B00FF; color:white; border:none; padding:.5rem 1.5rem;
           cursor:pointer; font-family:monospace; font-size:.9rem; border-radius:3px; }
    .btn:hover { background:#BF00FF; }
    .tag-healthy { color:#30D158; } .tag-down { color:#FF0040; }
  </style>
</head>
<body>
<h1>⬡ GLITCHICONS ORCHESTRATOR v%s</h1>
<p style="color:#666">Auto-refresh: 10s | Uptime: %s | <a href="/findings" style="color:#A855F7">Raw JSON</a></p>

<div class="stat"><span class="stat-num">%d</span><span class="stat-lbl">NODES</span></div>
<div class="stat"><span class="stat-num tag-healthy">%d</span><span class="stat-lbl">HEALTHY</span></div>
<div class="stat"><span class="stat-num">%d</span><span class="stat-lbl">JOBS DONE</span></div>
<div class="stat"><span class="stat-num">%d</span><span class="stat-lbl">TOTAL FINDINGS</span></div>
<div class="stat"><span class="stat-num crit">%d</span><span class="stat-lbl">CRITICAL</span></div>
<div class="stat"><span class="stat-num high">%d</span><span class="stat-lbl">HIGH</span></div>
<div class="stat"><span class="stat-num med">%d</span><span class="stat-lbl">MEDIUM</span></div>

<br><br>
<button class="btn" onclick="fetch('/run',{method:'POST'}).then(()=>location.reload())">▶ RUN SCAN PLAN</button>

<h2 style="color:#A855F7;margin-top:2rem">NODES</h2>
<table>
  <tr><th>NAME</th><th>URL</th><th>STATUS</th><th>JOBS SENT</th><th>VERSION</th><th>UPTIME</th></tr>`,
		Version, Version,
		time.Since(o.startTime).Round(time.Second),
		len(o.nodes), healthyCount,
		atomic.LoadInt64(&o.jobCount), total,
		summary["CRITICAL"], summary["HIGH"], summary["MEDIUM"],
	)

	for _, n := range o.nodes {
		n.mu.RLock()
		s := n.Status
		n.mu.RUnlock()
		statusTag := `<span class="tag-healthy">● ONLINE</span>`
		if !s.Healthy {
			statusTag = `<span class="tag-down">● OFFLINE</span>`
		}
		html += fmt.Sprintf(
			`<tr><td>%s</td><td><a href="%s/health" style="color:#A855F7">%s</a></td><td>%s</td><td>%d</td><td>%s</td><td>%s</td></tr>`,
			s.Name, s.URL, s.URL, statusTag, s.TotalJobs, s.Version, s.Uptime)
	}

	html += `</table>
<p style="color:#444;margin-top:3rem;font-size:.7rem">GLITCHICONS ORCHESTRATOR — AUTHORIZED USE ONLY</p>
</body></html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// ── Sample config generator ───────────────────────────────

func generateSampleConfig(path string) {
	cfg := OrchestratorConfig{
		Nodes: []NodeConfig{
			{Name: "node1", URL: "http://10.0.0.1:7331"},
			{Name: "node2", URL: "http://10.0.0.2:7331"},
			{Name: "local", URL: "http://127.0.0.1:7331"},
		},
		Targets: []string{
			"192.168.1.1",
			"192.168.1.10",
			"https://app.corp.com",
		},
		ScanPlan:    []string{"glitchscan", "glitchssh", "glitchsmb", "glitchtls"},
		Concurrency: 4,
		TimeoutS:    60,
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if path == "" || path == "-" {
		fmt.Println(string(data))
	} else {
		os.WriteFile(path, data, 0644)
		fmt.Printf("[+] Sample config written to %s\n", path)
	}
}

// ── Status command ────────────────────────────────────────

func cmdStatus(nodes []*Node) {
	fmt.Printf("%-15s %-35s %-8s %-6s %s\n", "NAME", "URL", "STATUS", "JOBS", "VERSION")
	fmt.Println(strings.Repeat("─", 75))
	for _, n := range nodes {
		n.checkHealth()
		n.mu.RLock()
		s := n.Status
		n.mu.RUnlock()
		status := "● ONLINE"
		if !s.Healthy {
			status = "✗ OFFLINE"
		}
		fmt.Printf("%-15s %-35s %-8s %-6d %s\n",
			s.Name, s.URL, status, s.TotalJobs, s.Version)
	}
}

// ── Main ──────────────────────────────────────────────────

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "init" {
		fs := flag.NewFlagSet("init", flag.ExitOnError)
		out := fs.String("output", "", "Output config file")
		fs.Parse(os.Args[2:])
		generateSampleConfig(*out)
		return
	}

	if len(os.Args) >= 2 && (os.Args[1] == "--version" || os.Args[1] == "-version") {
		fmt.Printf("glitchorchestrator v%s\n", Version)
		os.Exit(0)
	}

	// Parse command + flags
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd  = args[0]
		args = args[1:]
	}

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	configF  := fs.String("config",  "", "Orchestrator config JSON file (required)")
	port     := fs.Int("port",       7330, "Dashboard HTTP port")
	outputF  := fs.String("output",  "", "Output findings JSON (run mode)")
	verbose  := fs.Bool("verbose",   false, "Verbose output")
	fs.Parse(args)

	if *configF == "" && cmd != "init" {
		fmt.Fprintln(os.Stderr, "Usage: glitchorchestrator [serve|run|status|report] --config plan.json")
		fmt.Fprintln(os.Stderr, "       glitchorchestrator init --output plan.json")
		os.Exit(1)
	}

	// Load config
	var cfg OrchestratorConfig
	if *configF != "" {
		data, err := os.ReadFile(*configF)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Cannot read config: %v\n", err)
			os.Exit(1)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Invalid config JSON: %v\n", err)
			os.Exit(1)
		}
	}

	if len(cfg.Nodes) == 0 && cmd != "init" {
		fmt.Fprintln(os.Stderr, "[-] No nodes configured. Add glitchagent instances to config.")
		os.Exit(1)
	}

	o := newOrchestrator(&cfg)

	switch cmd {
	case "serve":
		fmt.Printf("[*] glitchorchestrator v%s | %d nodes | %d targets\n",
			Version, len(cfg.Nodes), len(cfg.Targets))
		o.startHealthMonitor()
		o.startDashboard(*port)

	case "run":
		fmt.Printf("[*] glitchorchestrator v%s | mode=run\n", Version)
		// Check node health first
		healthy := 0
		for _, n := range o.nodes {
			if n.checkHealth() {
				healthy++
			}
		}
		fmt.Printf("[*] Nodes: %d/%d healthy\n", healthy, len(o.nodes))
		if healthy == 0 {
			fmt.Fprintln(os.Stderr, "[-] No healthy nodes available. Start glitchagent on configured nodes.")
			os.Exit(1)
		}
		o.runScanPlan(*verbose)

		// Save output
		findings := o.aggr.All()
		sort.Slice(findings, func(i, j int) bool {
			return findings[i].CVSS > findings[j].CVSS
		})
		out := map[string]interface{}{
			"timestamp":  time.Now().UTC().Format(time.RFC3339),
			"nodes_used": len(cfg.Nodes),
			"targets":    len(cfg.Targets),
			"summary":    o.aggr.Summary(),
			"findings":   findings,
			"scanner_version": Version,
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		if *outputF != "" {
			os.WriteFile(*outputF, data, 0644)
			fmt.Printf("[+] Findings saved to %s\n", *outputF)
		} else {
			fmt.Println(string(data))
		}

	case "status":
		fmt.Printf("[*] glitchorchestrator v%s | node health check\n", Version)
		cmdStatus(o.nodes)

	case "report":
		findings := o.aggr.All()
		summary  := o.aggr.Summary()
		fmt.Printf("FINDINGS REPORT — %d total\n", len(findings))
		fmt.Printf("CRITICAL:%d HIGH:%d MEDIUM:%d LOW:%d\n\n",
			summary["CRITICAL"], summary["HIGH"], summary["MEDIUM"], summary["LOW"])
		for i, f := range findings {
			fmt.Printf("[%d] [%s] %s\n    Target: %s | Node: %s | Binary: %s\n\n",
				i+1, f.Severity, f.Title, f.Target, f.Node, f.Binary)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		fmt.Fprintln(os.Stderr, "Commands: serve | run | status | report | init")
		os.Exit(1)
	}
}
