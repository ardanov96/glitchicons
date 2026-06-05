// glitchagent/main.go
// GLITCHICONS — Persistent Scan Agent Daemon
//
// HTTP daemon that receives scan jobs from Python orchestrator,
// executes Go binaries concurrently via goroutine worker pool,
// and delivers results via webhook or polling.
//
// Architecture:
//   Python → POST /jobs → Job Queue → Worker Pool → Go Binary
//                                                        ↓
//   Python ← GET /jobs/:id/results  ←  Result Store ←──┘
//
// API:
//   POST   /jobs              — submit scan job
//   GET    /jobs/:id          — get job status
//   GET    /jobs/:id/results  — get findings JSON
//   DELETE /jobs/:id          — cancel job
//   GET    /jobs              — list all jobs
//   GET    /health            — health check
//   GET    /metrics           — runtime metrics
//
// Usage:
//   glitchagent --port 7331 --workers 20 --bin-dir ./bin
//   glitchagent --port 7331 --webhook https://hooks.slack.com/xxx
//   glitchagent --version

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
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const Version = "4.0.0"

// ── Job status constants ──────────────────────────────────

const (
	StatusPending   = "pending"
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
)

// ── Data types ────────────────────────────────────────────

type JobRequest struct {
	Binary  string            `json:"binary"`          // e.g. "glitchsmb"
	Target  string            `json:"target"`          // host or URL
	Args    []string          `json:"args,omitempty"`  // extra flags
	Meta    map[string]string `json:"meta,omitempty"`  // engagement metadata
	Timeout int               `json:"timeout_s,omitempty"` // seconds, default 120
}

type Job struct {
	ID          string            `json:"id"`
	Binary      string            `json:"binary"`
	Target      string            `json:"target"`
	Args        []string          `json:"args"`
	Meta        map[string]string `json:"meta"`
	Status      string            `json:"status"`
	CreatedAt   time.Time         `json:"created_at"`
	StartedAt   *time.Time        `json:"started_at,omitempty"`
	CompletedAt *time.Time        `json:"completed_at,omitempty"`
	DurationS   float64           `json:"duration_s,omitempty"`
	Error       string            `json:"error,omitempty"`
	Timeout     int               `json:"timeout_s"`
	FindingCount int              `json:"finding_count"`
	cancel      context.CancelFunc
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

type JobResult struct {
	JobID    string    `json:"job_id"`
	Binary   string    `json:"binary"`
	Target   string    `json:"target"`
	Findings []Finding `json:"findings"`
	RawOutput string   `json:"raw_output,omitempty"`
}

type HealthResponse struct {
	Status    string    `json:"status"`
	Version   string    `json:"version"`
	Uptime    string    `json:"uptime"`
	Workers   int       `json:"workers"`
	QueueSize int       `json:"queue_size"`
	Jobs      JobStats  `json:"jobs"`
}

type JobStats struct {
	Total     int `json:"total"`
	Pending   int `json:"pending"`
	Running   int `json:"running"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
}

type MetricsResponse struct {
	Version     string   `json:"version"`
	Uptime      string   `json:"uptime"`
	Workers     int      `json:"workers_total"`
	ActiveJobs  int      `json:"workers_active"`
	GoRoutines  int      `json:"goroutines"`
	Jobs        JobStats `json:"jobs"`
	BinsAvailable []string `json:"binaries_available"`
}

// ── Agent ─────────────────────────────────────────────────

type Agent struct {
	mu       sync.RWMutex
	jobs     map[string]*Job
	results  map[string]*JobResult
	queue    chan *Job
	workers  int
	binDir   string
	webhook  string
	startTime time.Time
	activeWorkers int
	activeMu sync.Mutex
}

func newAgent(workers int, binDir, webhook string) *Agent {
	return &Agent{
		jobs:      make(map[string]*Job),
		results:   make(map[string]*JobResult),
		queue:     make(chan *Job, 500),
		workers:   workers,
		binDir:    binDir,
		webhook:   webhook,
		startTime: time.Now(),
	}
}

func (a *Agent) start() {
	for i := 0; i < a.workers; i++ {
		go a.worker(i)
	}
	log.Printf("[agent] started %d workers | bin-dir=%s", a.workers, a.binDir)
}

func (a *Agent) worker(id int) {
	for job := range a.queue {
		a.activeMu.Lock()
		a.activeWorkers++
		a.activeMu.Unlock()

		a.executeJob(job)

		a.activeMu.Lock()
		a.activeWorkers--
		a.activeMu.Unlock()
	}
}

func (a *Agent) submitJob(req JobRequest) *Job {
	id    := generateID()
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 120
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	job := &Job{
		ID:        id,
		Binary:    req.Binary,
		Target:    req.Target,
		Args:      req.Args,
		Meta:      req.Meta,
		Status:    StatusPending,
		CreatedAt: time.Now(),
		Timeout:   timeout,
		cancel:    cancel,
	}
	_ = ctx // stored in cancel func

	a.mu.Lock()
	a.jobs[id] = job
	a.mu.Unlock()

	a.queue <- job
	log.Printf("[agent] job queued: %s binary=%s target=%s", id[:8], req.Binary, req.Target)
	return job
}

func (a *Agent) executeJob(job *Job) {
	now := time.Now()
	job.StartedAt = &now
	job.Status    = StatusRunning

	binPath := filepath.Join(a.binDir, job.Binary)
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}

	// Build args: binary --target <target> --output <tmpfile> [extra args]
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("glitch_%s.json", job.ID))
	defer os.Remove(tmpFile)

	args := []string{
		"--target", job.Target,
		"--output", tmpFile,
	}
	args = append(args, job.Args...)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(job.Timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, args...)
	out, err := cmd.CombinedOutput()

	completedAt := time.Now()
	job.CompletedAt = &completedAt
	job.DurationS   = completedAt.Sub(*job.StartedAt).Seconds()

	if ctx.Err() == context.DeadlineExceeded {
		job.Status = StatusFailed
		job.Error  = fmt.Sprintf("timeout after %ds", job.Timeout)
		log.Printf("[agent] job timeout: %s", job.ID[:8])
		return
	}

	if err != nil && !isExitError(err) {
		job.Status = StatusFailed
		job.Error  = fmt.Sprintf("exec error: %v", err)
		log.Printf("[agent] job failed: %s — %v", job.ID[:8], err)
		return
	}

	// Parse results from output file
	result := &JobResult{
		JobID:  job.ID,
		Binary: job.Binary,
		Target: job.Target,
	}

	if data, ferr := os.ReadFile(tmpFile); ferr == nil {
		var parsed map[string]interface{}
		if jerr := json.Unmarshal(data, &parsed); jerr == nil {
			result.Findings = extractFindings(parsed)
			result.RawOutput = string(data)
		}
	} else if len(out) > 0 {
		// Fallback: try parsing stdout directly
		var parsed map[string]interface{}
		if jerr := json.Unmarshal(out, &parsed); jerr == nil {
			result.Findings = extractFindings(parsed)
		}
		result.RawOutput = string(out)
	}

	job.FindingCount = len(result.Findings)
	job.Status = StatusCompleted

	a.mu.Lock()
	a.results[job.ID] = result
	a.mu.Unlock()

	log.Printf("[agent] job done: %s | findings=%d duration=%.1fs",
		job.ID[:8], job.FindingCount, job.DurationS)

	// Fire webhook if configured
	if a.webhook != "" {
		go a.fireWebhook(job, result)
	}
}

func (a *Agent) cancelJob(id string) bool {
	a.mu.RLock()
	job, ok := a.jobs[id]
	a.mu.RUnlock()
	if !ok {
		return false
	}
	if job.cancel != nil {
		job.cancel()
	}
	job.Status = StatusCancelled
	return true
}

func (a *Agent) stats() JobStats {
	a.mu.RLock()
	defer a.mu.RUnlock()
	s := JobStats{Total: len(a.jobs)}
	for _, j := range a.jobs {
		switch j.Status {
		case StatusPending:
			s.Pending++
		case StatusRunning:
			s.Running++
		case StatusCompleted:
			s.Completed++
		case StatusFailed:
			s.Failed++
		}
	}
	return s
}

func (a *Agent) availableBinaries() []string {
	bins := []string{}
	entries, err := os.ReadDir(a.binDir)
	if err != nil {
		return bins
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "glitch") {
			name = strings.TrimSuffix(name, ".exe")
			bins = append(bins, name)
		}
	}
	return bins
}

func (a *Agent) fireWebhook(job *Job, result *JobResult) {
	payload := map[string]interface{}{
		"event":        "scan_completed",
		"job_id":       job.ID,
		"binary":       job.Binary,
		"target":       job.Target,
		"status":       job.Status,
		"finding_count": job.FindingCount,
		"duration_s":   job.DurationS,
		"timestamp":    job.CompletedAt.UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(a.webhook, "application/json",
		strings.NewReader(string(data)))
	if err != nil {
		log.Printf("[webhook] error: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("[webhook] fired: job=%s status=%d", job.ID[:8], resp.StatusCode)
}

// ── HTTP Handlers ─────────────────────────────────────────

func (a *Agent) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req JobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Binary == "" || req.Target == "" {
		http.Error(w, "binary and target are required", http.StatusBadRequest)
		return
	}
	job := a.submitJob(req)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(job)
}

func (a *Agent) handleJobStatus(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/jobs/")
	id  = strings.Split(id, "/")[0]

	a.mu.RLock()
	job, ok := a.jobs[id]
	a.mu.RUnlock()

	if !ok {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}

	if r.Method == http.MethodDelete {
		a.cancelJob(id)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(job)
}

func (a *Agent) handleJobResults(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/jobs/")
	id  = strings.TrimSuffix(id, "/results")

	a.mu.RLock()
	result, ok := a.results[id]
	a.mu.RUnlock()

	if !ok {
		http.Error(w, "results not ready or job not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (a *Agent) handleListJobs(w http.ResponseWriter, r *http.Request) {
	// Check if this is a specific job path
	path := strings.TrimPrefix(r.URL.Path, "/jobs/")
	if path != "" && path != "/" {
		if strings.HasSuffix(r.URL.Path, "/results") {
			a.handleJobResults(w, r)
		} else {
			a.handleJobStatus(w, r)
		}
		return
	}

	a.mu.RLock()
	jobs := make([]*Job, 0, len(a.jobs))
	for _, j := range a.jobs {
		jobs = append(jobs, j)
	}
	a.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"jobs":  jobs,
		"count": len(jobs),
	})
}

func (a *Agent) handleHealth(w http.ResponseWriter, r *http.Request) {
	a.activeMu.Lock()
	active := a.activeWorkers
	a.activeMu.Unlock()

	resp := HealthResponse{
		Status:    "ok",
		Version:   Version,
		Uptime:    time.Since(a.startTime).Round(time.Second).String(),
		Workers:   a.workers,
		QueueSize: len(a.queue),
		Jobs:      a.stats(),
	}
	_ = active
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (a *Agent) handleMetrics(w http.ResponseWriter, r *http.Request) {
	a.activeMu.Lock()
	active := a.activeWorkers
	a.activeMu.Unlock()

	resp := MetricsResponse{
		Version:       Version,
		Uptime:        time.Since(a.startTime).Round(time.Second).String(),
		Workers:       a.workers,
		ActiveJobs:    active,
		GoRoutines:    runtime.NumGoroutine(),
		Jobs:          a.stats(),
		BinsAvailable: a.availableBinaries(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ── Helpers ───────────────────────────────────────────────

func generateID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
}

func isExitError(err error) bool {
	_, ok := err.(*exec.ExitError)
	return ok
}

func extractFindings(data map[string]interface{}) []Finding {
	findings := []Finding{}
	raw, ok := data["findings"]
	if !ok {
		return findings
	}
	items, ok := raw.([]interface{})
	if !ok {
		return findings
	}
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		f := Finding{
			Title:       strField(m, "title"),
			Severity:    strField(m, "severity"),
			CVSS:        floatField(m, "cvss"),
			CWE:         strField(m, "cwe"),
			Target:      strField(m, "target"),
			Description: strField(m, "description"),
			Evidence:    strField(m, "evidence"),
			Remediation: strField(m, "remediation"),
			Source:      strField(m, "source"),
		}
		if f.Title != "" && f.Severity != "" {
			findings = append(findings, f)
		}
	}
	return findings
}

func strField(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func floatField(m map[string]interface{}, key string) float64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	f, _ := v.(float64)
	return f
}

// ── Main ──────────────────────────────────────────────────

func main() {
	port    := flag.Int("port",    7331, "HTTP port to listen on")
	workers := flag.Int("workers", 20,   "Number of concurrent worker goroutines")
	binDir  := flag.String("bin-dir", "./bin", "Directory containing Go binaries")
	webhook := flag.String("webhook", "",  "Webhook URL for job completion events")
	ver     := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchagent v%s\n", Version)
		os.Exit(0)
	}

	agent := newAgent(*workers, *binDir, *webhook)
	agent.start()

	mux := http.NewServeMux()
	mux.HandleFunc("/jobs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			agent.handleSubmit(w, r)
		} else {
			agent.handleListJobs(w, r)
		}
	})
	mux.HandleFunc("/jobs/", agent.handleListJobs)
	mux.HandleFunc("/health",  agent.handleHealth)
	mux.HandleFunc("/metrics", agent.handleMetrics)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		log.Printf("[agent] shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	log.Printf("[agent] glitchagent v%s listening on :%d | workers=%d",
		Version, *port, *workers)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("[agent] server error: %v", err)
	}
	log.Printf("[agent] stopped.")
}
