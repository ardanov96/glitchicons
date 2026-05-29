// glitchproxy — Intercepting HTTP/HTTPS Proxy
// Part of the Glitchicons security research platform
//
// Features:
//   - HTTP + HTTPS (CONNECT) proxy
//   - TLS MITM for HTTPS traffic inspection
//   - Request/response logging to JSON
//   - Passive analysis: detect interesting headers, cookies, tokens
//   - Auto-detect auth tokens, API keys, sensitive data in traffic
//   - Finding generation from intercepted traffic
//   - Standard Glitchicons JSON output (saved on exit)
//
// Usage:
//   glitchproxy --port 8080
//   glitchproxy --port 8080 --output ./findings/proxy
//   # Configure browser/tool to use localhost:8080 as HTTP proxy
//
// Author: ardanov96

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ── Intercepted request/response ─────────────────────────

type InterceptedRequest struct {
	ID          int64             `json:"id"`
	Timestamp   string            `json:"timestamp"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Host        string            `json:"host"`
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers"`
	BodySnippet string            `json:"body_snippet,omitempty"`
	IsTLS       bool              `json:"is_tls"`
	StatusCode  int               `json:"status_code,omitempty"`
	RespHeaders map[string]string `json:"response_headers,omitempty"`
	RespSnippet string            `json:"response_snippet,omitempty"`
	DurationMS  int64             `json:"duration_ms"`
	Flags       []string          `json:"flags,omitempty"`
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

type Output struct {
	Tool         string               `json:"tool"`
	Version      string               `json:"version"`
	ListenAddr   string               `json:"listen_addr"`
	Started      string               `json:"started"`
	Finished     string               `json:"finished"`
	Requests     []InterceptedRequest `json:"requests"`
	Findings     []Finding            `json:"findings"`
	TotalReqs    int64                `json:"total_requests"`
	ExitCode     int                  `json:"exit_code"`
}

// ── Sensitive pattern detectors ───────────────────────────

var sensitiveHeaderPatterns = []string{
	"authorization", "x-api-key", "x-auth-token", "x-access-token",
	"api-key", "apikey", "bearer", "cookie", "x-csrf-token",
	"x-session-id", "x-user-id", "x-admin",
}

var sensitiveBodyPatterns = []string{
	"password", "passwd", "secret", "api_key", "apikey",
	"access_token", "refresh_token", "private_key",
	"credit_card", "ssn", "cvv",
}

var missingSecurityHeaders = []string{
	"x-frame-options", "x-content-type-options",
	"content-security-policy", "x-xss-protection",
	"strict-transport-security",
}

func detectFlags(req *http.Request, body string) []string {
	var flags []string
	// Auth in headers
	for _, h := range sensitiveHeaderPatterns {
		if req.Header.Get(h) != "" {
			flags = append(flags, fmt.Sprintf("auth-header:%s", h))
		}
	}
	// Sensitive data in body
	bodyLower := strings.ToLower(body)
	for _, p := range sensitiveBodyPatterns {
		if strings.Contains(bodyLower, p) {
			flags = append(flags, fmt.Sprintf("sensitive-body:%s", p))
			break
		}
	}
	return flags
}

func detectRespFlags(resp *http.Response) []string {
	var flags []string
	for _, h := range missingSecurityHeaders {
		if resp.Header.Get(h) == "" {
			flags = append(flags, fmt.Sprintf("missing-header:%s", h))
		}
	}
	return flags
}

// ── CA certificate generator ──────────────────────────────

type ProxyCA struct {
	cert    *x509.Certificate
	key     *rsa.PrivateKey
	tlsCert tls.Certificate
}

func generateCA() (*ProxyCA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Glitchicons Proxy CA",
			Organization: []string{"Glitchicons"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &ProxyCA{cert: cert, key: key, tlsCert: tlsCert}, nil
}

func (ca *ProxyCA) generateHostCert(host string) (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{host},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}, nil
}

// ── Proxy server ──────────────────────────────────────────

type Proxy struct {
	ca         *ProxyCA
	mu         sync.Mutex
	requests   []InterceptedRequest
	findings   []Finding
	reqCounter int64
	verbose    bool
}

func newProxy(ca *ProxyCA, verbose bool) *Proxy {
	return &Proxy{ca: ca, verbose: verbose}
}

func (p *Proxy) addRequest(r InterceptedRequest) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests = append(p.requests, r)
	p.generateFindings(r)
}

func (p *Proxy) generateFindings(r InterceptedRequest) {
	// Auth over HTTP (not HTTPS)
	if !r.IsTLS {
		for _, flag := range r.Flags {
			if strings.HasPrefix(flag, "auth-header:") {
				p.findings = append(p.findings, Finding{
					ID:       fmt.Sprintf("PROXY-%03d", len(p.findings)+1),
					Title:    "Authentication Token Sent Over HTTP",
					Severity: "HIGH",
					CVSS:     7.5,
					CWE:      "CWE-319",
					Target:   r.URL,
					Description: "Authentication credentials transmitted in cleartext over HTTP.",
					Evidence:    fmt.Sprintf("URL: %s | Header: %s", r.URL, flag),
					Remediation: "Enforce HTTPS. Never send auth tokens over plaintext HTTP.",
					Timestamp:   r.Timestamp,
				})
				break
			}
		}
	}

	// Missing security headers in response
	var missingList []string
	for _, flag := range r.Flags {
		if strings.HasPrefix(flag, "missing-header:") {
			missingList = append(missingList, strings.TrimPrefix(flag, "missing-header:"))
		}
	}
	if len(missingList) >= 3 {
		p.findings = append(p.findings, Finding{
			ID:       fmt.Sprintf("PROXY-%03d", len(p.findings)+1),
			Title:    "Missing Security Headers",
			Severity: "LOW",
			CVSS:     3.1,
			CWE:      "CWE-693",
			Target:   r.URL,
			Description: fmt.Sprintf("Response missing %d security headers: %s",
				len(missingList), strings.Join(missingList, ", ")),
			Evidence:    fmt.Sprintf("URL: %s | Missing: %s", r.URL, strings.Join(missingList, ", ")),
			Remediation: "Add security headers: X-Frame-Options, X-Content-Type-Options, CSP, HSTS.",
			Timestamp:   r.Timestamp,
		})
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleTunnel(w, r)
	} else {
		p.handleHTTP(w, r, false)
	}
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request, isTLS bool) {
	id := atomic.AddInt64(&p.reqCounter, 1)
	start := time.Now()

	// Capture request body snippet
	bodySnippet := ""
	if r.Body != nil {
		buf := make([]byte, 512)
		n, _ := r.Body.Read(buf)
		bodySnippet = string(buf[:n])
		r.Body = io.NopCloser(strings.NewReader(bodySnippet))
	}

	flags := detectFlags(r, bodySnippet)

	// Forward request
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	resp, err := transport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Capture response
	respBody := make([]byte, 512)
	n, _ := resp.Body.Read(respBody)
	respSnippet := string(respBody[:n])

	respFlags := detectRespFlags(resp)
	flags = append(flags, respFlags...)

	// Copy response to client
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, strings.NewReader(respSnippet))
	io.Copy(w, resp.Body)

	// Build intercepted request record
	headers := map[string]string{}
	for k := range r.Header {
		headers[k] = r.Header.Get(k)
	}
	respHeaders := map[string]string{}
	for k := range resp.Header {
		respHeaders[k] = resp.Header.Get(k)
	}

	url := r.URL.String()
	if !strings.HasPrefix(url, "http") {
		scheme := "http"
		if isTLS {
			scheme = "https"
		}
		url = fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.RequestURI())
	}

	intercepted := InterceptedRequest{
		ID:          id,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Method:      r.Method,
		URL:         url,
		Host:        r.Host,
		Path:        r.URL.Path,
		Headers:     headers,
		BodySnippet: bodySnippet[:min(len(bodySnippet), 200)],
		IsTLS:       isTLS,
		StatusCode:  resp.StatusCode,
		RespHeaders: respHeaders,
		RespSnippet: respSnippet[:min(len(respSnippet), 200)],
		DurationMS:  time.Since(start).Milliseconds(),
		Flags:       flags,
	}

	if p.verbose {
		fmt.Fprintf(os.Stderr, "[glitchproxy] %s %s %d\n",
			r.Method, url, resp.StatusCode)
	}

	p.addRequest(intercepted)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (p *Proxy) handleTunnel(w http.ResponseWriter, r *http.Request) {
	// CONNECT method — establish tunnel for HTTPS
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	host := strings.Split(r.Host, ":")[0]
	tlsCfg, err := p.ca.generateHostCert(host)
	if err != nil {
		io.Copy(clientConn, destConn)
		io.Copy(destConn, clientConn)
		return
	}

	// Wrap client connection in TLS
	tlsClientConn := tls.Server(clientConn, tlsCfg)
	if err := tlsClientConn.Handshake(); err != nil {
		return
	}
	defer tlsClientConn.Close()

	// Create fake HTTPS server to intercept
	fakeServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL.Host = r.Host
		req.URL.Scheme = "https"
		p.handleHTTP(w, req, true)
	})}

	// Serve single HTTPS request
	http2Conn := &singleConnListener{conn: tlsClientConn}
	fakeServer.Serve(http2Conn)
}

// singleConnListener serves exactly one connection
type singleConnListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() {
		c = l.conn
		l.done = make(chan struct{})
	})
	if c != nil {
		return c, nil
	}
	// Block until done
	if l.done != nil {
		<-l.done
	}
	return nil, fmt.Errorf("listener closed")
}

func (l *singleConnListener) Close() error {
	if l.done != nil {
		close(l.done)
	}
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// ── Main ──────────────────────────────────────────────────

func main() {
	port      := flag.Int("port",    8080,    "Proxy listen port")
	outputDir := flag.String("output", "./findings/proxy", "Output directory")
	verbose   := flag.Bool("verbose", false,  "Print each request")
	version   := flag.Bool("version", false,  "Print version and exit")
	flag.Parse()

	if *version {
		fmt.Println("glitchproxy 1.0.0")
		os.Exit(0)
	}

	started := time.Now()
	listenAddr := fmt.Sprintf(":%d", *port)

	// Generate CA
	ca, err := generateCA()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating CA: %v\n", err)
		os.Exit(1)
	}

	proxy := newProxy(ca, *verbose)

	server := &http.Server{
		Addr:    listenAddr,
		Handler: proxy,
	}

	fmt.Fprintf(os.Stderr, "[glitchproxy] Listening on %s\n", listenAddr)
	fmt.Fprintf(os.Stderr, "[glitchproxy] Configure proxy: localhost%s\n", listenAddr)
	fmt.Fprintf(os.Stderr, "[glitchproxy] Press Ctrl+C to stop and save findings\n")

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "[glitchproxy] Error: %v\n", err)
		}
	}()

	<-sigCh
	server.Close()

	// Save findings
	_ = os.MkdirAll(*outputDir, 0755)
	output := Output{
		Tool:       "glitchproxy",
		Version:    "1.0.0",
		ListenAddr: listenAddr,
		Started:    started.UTC().Format(time.RFC3339),
		Finished:   time.Now().UTC().Format(time.RFC3339),
		Requests:   proxy.requests,
		Findings:   proxy.findings,
		TotalReqs:  proxy.reqCounter,
		ExitCode:   0,
	}

	outFile := filepath.Join(*outputDir,
		fmt.Sprintf("proxy_%s.json", time.Now().Format("20060102_150405")))

	data, _ := json.MarshalIndent(output, "", "  ")
	os.WriteFile(outFile, data, 0644)

	fmt.Fprintf(os.Stderr, "\n[glitchproxy] Captured %d requests, %d findings\n",
		proxy.reqCounter, len(proxy.findings))
	fmt.Fprintf(os.Stderr, "[glitchproxy] Saved: %s\n", outFile)

	// Also print JSON to stdout
	_ = json.NewEncoder(os.Stdout)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(output)
}

// suppress unused import warning for httputil
var _ = httputil.DumpRequest
var _ = bufio.NewReader
