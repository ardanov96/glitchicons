// glitchscan — Port + Service Scanner
// Part of the Glitchicons security research platform
//
// Features:
//   - TCP connect scan (no raw sockets needed, works on Windows)
//   - Concurrent scanning via goroutine pool (10k+ ports/sec)
//   - Banner grabbing for open ports
//   - Service fingerprinting (HTTP, HTTPS, SSH, FTP, SMTP, etc.)
//   - Standard Glitchicons JSON output
//
// Usage:
//   glitchscan --target 192.168.1.1
//   glitchscan --target target.com --ports 1-1024
//   glitchscan --target target.com --ports 80,443,8080,8443 --timeout 2
//
// Author: ardanov96

package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── Output schema ─────────────────────────────────────────

type PortResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Version  string `json:"version,omitempty"`
	Banner   string `json:"banner,omitempty"`
}

type Finding struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss"`
	CWE         string  `json:"cwe"`
	Target      string  `json:"target"`
	Description string  `json:"description"`
	Evidence    string  `json:"evidence"`
	Remediation string  `json:"remediation"`
	Timestamp   string  `json:"timestamp"`
}

type Stats struct {
	PortsScanned int   `json:"ports_scanned"`
	OpenPorts    int   `json:"open_ports"`
	DurationMS   int64 `json:"duration_ms"`
	Concurrency  int   `json:"concurrency"`
}

type Output struct {
	Tool      string       `json:"tool"`
	Version   string       `json:"version"`
	Target    string       `json:"target"`
	Started   string       `json:"started"`
	Finished  string       `json:"finished"`
	OpenPorts []PortResult `json:"open_ports"`
	Findings  []Finding    `json:"findings"`
	Stats     Stats        `json:"stats"`
	ExitCode  int          `json:"exit_code"`
}

// ── Service fingerprints ──────────────────────────────────

var commonPorts = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	111:   "rpcbind",
	135:   "msrpc",
	139:   "netbios",
	143:   "imap",
	443:   "https",
	445:   "smb",
	993:   "imaps",
	995:   "pop3s",
	1433:  "mssql",
	1521:  "oracle",
	2181:  "zookeeper",
	3306:  "mysql",
	3389:  "rdp",
	4444:  "metasploit",
	5432:  "postgresql",
	5601:  "kibana",
	5900:  "vnc",
	6379:  "redis",
	6443:  "kubernetes",
	8080:  "http-alt",
	8443:  "https-alt",
	8888:  "jupyter",
	9000:  "sonarqube",
	9090:  "prometheus",
	9200:  "elasticsearch",
	9300:  "elasticsearch-cluster",
	27017: "mongodb",
}

// Ports that warrant a security finding
var sensitiveServices = map[string]struct {
	severity    string
	cvss        float64
	cwe         string
	description string
}{
	"telnet":        {"HIGH", 7.5, "CWE-319", "Telnet transmits data (including credentials) in cleartext."},
	"ftp":           {"MEDIUM", 5.3, "CWE-319", "FTP transmits credentials in cleartext."},
	"vnc":           {"HIGH", 7.5, "CWE-284", "VNC remote desktop exposed to network."},
	"rdp":           {"HIGH", 7.5, "CWE-284", "RDP exposed — BluEKeep and related vulnerabilities."},
	"smb":           {"HIGH", 8.1, "CWE-284", "SMB exposed — EternalBlue and related vulnerabilities."},
	"redis":         {"CRITICAL", 9.8, "CWE-284", "Redis exposed without auth — full data access + RCE."},
	"mongodb":       {"CRITICAL", 9.8, "CWE-284", "MongoDB exposed — unauthenticated database access."},
	"elasticsearch": {"CRITICAL", 9.8, "CWE-284", "Elasticsearch exposed — unauthenticated data access."},
	"kibana":        {"HIGH", 7.5, "CWE-284", "Kibana dashboard exposed — data visualization access."},
	"jupyter":       {"CRITICAL", 9.8, "CWE-284", "Jupyter notebook exposed — arbitrary code execution."},
	"metasploit":    {"CRITICAL", 10.0, "CWE-284", "Metasploit listener detected — active attack tool exposed."},
	"zookeeper":     {"HIGH", 7.5, "CWE-284", "ZooKeeper exposed — cluster configuration access."},
	"kubernetes":    {"CRITICAL", 9.8, "CWE-284", "Kubernetes API server exposed."},
	"prometheus":    {"MEDIUM", 5.3, "CWE-200", "Prometheus metrics exposed — internal system information."},
}

// ── Port range parser ─────────────────────────────────────

func parsePorts(spec string) []int {
	var ports []int
	seen := map[int]bool{}

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil || start > end {
				continue
			}
			for p := start; p <= end && p <= 65535; p++ {
				if !seen[p] {
					ports = append(ports, p)
					seen[p] = true
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err == nil && p > 0 && p <= 65535 && !seen[p] {
				ports = append(ports, p)
				seen[p] = true
			}
		}
	}
	return ports
}

// ── Banner grabber ────────────────────────────────────────

func grabBanner(host string, port int, timeoutSec int) string {
	conn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", host, port),
		time.Duration(timeoutSec)*time.Second,
	)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))

	// For HTTP/S, send a quick HEAD request
	service := commonPorts[port]
	if service == "http" || service == "http-alt" {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	} else if service == "https" || service == "https-alt" {
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		})
		if err := tlsConn.Handshake(); err == nil {
			cert := tlsConn.ConnectionState()
			if len(cert.PeerCertificates) > 0 {
				return fmt.Sprintf("TLS CN=%s", cert.PeerCertificates[0].Subject.CommonName)
			}
		}
		return "TLS"
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024), 1024)
	if scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) > 100 {
			line = line[:100]
		}
		return line
	}
	return ""
}

// ── HTTP title grabber ────────────────────────────────────

func getHTTPTitle(host string, port int, tls_ bool, timeoutSec int) string {
	scheme := "http"
	if tls_ {
		scheme = "https"
	}
	client := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(fmt.Sprintf("%s://%s:%d/", scheme, host, port))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	return fmt.Sprintf("HTTP %d", resp.StatusCode)
}

// ── Port scanner ──────────────────────────────────────────

func scanPort(host string, port int, timeoutSec int) (bool, string) {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, time.Duration(timeoutSec)*time.Second)
	if err != nil {
		return false, ""
	}
	conn.Close()

	banner := grabBanner(host, port, timeoutSec)
	return true, banner
}

// ── Main ──────────────────────────────────────────────────

func main() {
	target      := flag.String("target",      "",           "Target host or IP (required)")
	portsFlag   := flag.String("ports",       "1-1024",     "Port range: 1-1024 or 80,443,8080")
	concurrency := flag.Int("concurrency",    500,          "Concurrent goroutines")
	timeoutSec  := flag.Int("timeout",        2,            "Connection timeout (seconds)")
	outputFmt   := flag.String("output",      "json",       "Output format: json|text")
	versionFlag := flag.Bool("version",       false,        "Print version and exit")

	flag.Parse()

	if *versionFlag {
		fmt.Println("glitchscan 1.0.0")
		os.Exit(0)
	}

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Error: --target is required")
		flag.Usage()
		os.Exit(1)
	}

	// Resolve host
	host := *target
	addrs, err := net.LookupHost(host)
	if err == nil && len(addrs) > 0 {
		host = addrs[0]
	}

	ports := parsePorts(*portsFlag)
	if len(ports) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no valid ports specified")
		os.Exit(1)
	}

	started := time.Now()

	if *outputFmt == "text" {
		fmt.Fprintf(os.Stderr, "[glitchscan] Target : %s (%s)\n", *target, host)
		fmt.Fprintf(os.Stderr, "[glitchscan] Ports  : %d to scan\n", len(ports))
	}

	// Worker pool
	portCh := make(chan int, len(ports))
	for _, p := range ports {
		portCh <- p
	}
	close(portCh)

	type scanResult struct {
		port   int
		open   bool
		banner string
	}

	resultCh := make(chan scanResult, len(ports))
	var wg sync.WaitGroup

	workers := *concurrency
	if workers > len(ports) {
		workers = len(ports)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portCh {
				open, banner := scanPort(*target, port, *timeoutSec)
				resultCh <- scanResult{port, open, banner}
			}
		}()
	}

	wg.Wait()
	close(resultCh)

	// Collect open ports
	var openPorts []PortResult
	for r := range resultCh {
		if !r.open {
			continue
		}
		service := commonPorts[r.port]
		if service == "" {
			service = "unknown"
		}

		pr := PortResult{
			Port:     r.port,
			Protocol: "tcp",
			State:    "open",
			Service:  service,
			Banner:   r.banner,
		}

		// Enrich HTTP ports
		if service == "http" || service == "http-alt" {
			pr.Version = getHTTPTitle(*target, r.port, false, *timeoutSec)
		} else if service == "https" || service == "https-alt" {
			pr.Version = getHTTPTitle(*target, r.port, true, *timeoutSec)
		}

		openPorts = append(openPorts, pr)

		if *outputFmt == "text" {
			fmt.Fprintf(os.Stderr, "[glitchscan] OPEN   : %d/tcp (%s) %s\n",
				r.port, service, r.banner)
		}
	}

	// Sort by port number
	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})

	// Generate findings for sensitive services
	var findings []Finding
	for _, pr := range openPorts {
		if svc, ok := sensitiveServices[pr.Service]; ok {
			findings = append(findings, Finding{
				ID:          fmt.Sprintf("SCAN-%03d", len(findings)+1),
				Title:       fmt.Sprintf("Exposed Service: %s on port %d", strings.ToUpper(pr.Service), pr.Port),
				Severity:    svc.severity,
				CVSS:        svc.cvss,
				CWE:         svc.cwe,
				Target:      fmt.Sprintf("%s:%d", *target, pr.Port),
				Description: svc.description,
				Evidence:    fmt.Sprintf("Port %d/tcp open, service: %s, banner: %s", pr.Port, pr.Service, pr.Banner),
				Remediation: fmt.Sprintf("Restrict access to port %d via firewall rules. "+
					"Allow only trusted IPs. Consider disabling %s if not required.",
					pr.Port, pr.Service),
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
		}
	}

	finished := time.Now()
	duration := finished.Sub(started).Milliseconds()

	result := Output{
		Tool:      "glitchscan",
		Version:   "1.0.0",
		Target:    *target,
		Started:   started.UTC().Format(time.RFC3339),
		Finished:  finished.UTC().Format(time.RFC3339),
		OpenPorts: openPorts,
		Findings:  findings,
		Stats: Stats{
			PortsScanned: len(ports),
			OpenPorts:    len(openPorts),
			DurationMS:   duration,
			Concurrency:  workers,
		},
		ExitCode: 0,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "Error encoding output:", err)
		os.Exit(1)
	}
}
