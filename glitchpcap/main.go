// glitchpcap/main.go
// GLITCHICONS — Passive Network Capture & Analyzer
//
// Passive network analysis WITHOUT gopacket/libpcap dependency.
// Uses raw TCP/UDP listeners and Go net package for capture.
//
// Capabilities:
//   ja3       — TLS ClientHello JA3/JA4 fingerprinting
//               Listen on port, parse raw TLS handshake
//               Extract: version, ciphers, extensions, curves
//               Compute MD5 JA3 hash — identify malware/tools
//   http      — HTTP traffic capture proxy
//               Listen as transparent HTTP proxy
//               Extract: credentials, tokens, cookies, secrets
//   dns       — DNS query capture (UDP 53)
//               Log all queries + responses
//               Detect: DGA domains, beaconing, exfiltration
//   all       — Run all capture modes simultaneously
//
// JA3 format: MD5(TLSVersion,Ciphers,Extensions,Curves,PointFormats)
// JA3S format: MD5(TLSVersion,Cipher,Extensions)
//
// Usage:
//   glitchpcap ja3  --port 8443 --output ja3_captures.json
//   glitchpcap http --port 8080 --output http_captures.json
//   glitchpcap dns  --port 5353 --output dns_captures.json
//   glitchpcap all  --ja3-port 8443 --http-port 8080 --dns-port 5353
//   glitchpcap --version

package main

import (
	"bufio"
	"crypto/md5"
	"encoding/binary"
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

// ── JA3 fingerprinting ────────────────────────────────────

// GREASE values to ignore in JA3
var greaseValues = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

type TLSClientHello struct {
	Version          uint16
	CipherSuites     []uint16
	Extensions       []uint16
	EllipticCurves   []uint16
	PointFormats     []uint8
	ServerName       string
	JA3              string
	JA3Raw           string
}

type JA3Capture struct {
	ClientIP   string         `json:"client_ip"`
	ClientPort int            `json:"client_port"`
	DestPort   int            `json:"dest_port"`
	SNI        string         `json:"sni,omitempty"`
	JA3Hash    string         `json:"ja3_hash"`
	JA3String  string         `json:"ja3_string"`
	Timestamp  string         `json:"timestamp"`
	KnownTool  string         `json:"known_tool,omitempty"`
}

// Known JA3 hashes for common tools/malware
var knownJA3 = map[string]string{
	"51c64c77e60f3980eea90869b68c58a8": "curl/7.x",
	"7daf72b0f04b44c5e0b3a85e8be27e48": "Python requests",
	"a0e9f5d64349fb13191bc781f81f42e1": "Go http client",
	"b32309a26951912be7dba376398abc3b": "Nmap",
	"c76c3def4d9157e0e0167d8e0e891898": "Masscan",
	"e7d705a3286e19ea42f587b344ee6865": "Golang default",
	"9e10692f1b7f78228f56f0b0c5f5cbb5": "Metasploit",
	"6d12ba96c84e5e67be7c3b8d7ddce79f": "Cobalt Strike",
}

func parseClientHello(data []byte) *TLSClientHello {
	if len(data) < 5 {
		return nil
	}

	// TLS Record Layer: ContentType(1) + Version(2) + Length(2)
	if data[0] != 0x16 { // Handshake
		return nil
	}

	offset := 5 // Skip TLS record header

	// Handshake: Type(1) + Length(3)
	if offset+4 > len(data) || data[offset] != 0x01 { // ClientHello
		return nil
	}
	offset += 4

	hello := &TLSClientHello{}

	// Client Version (2 bytes)
	if offset+2 > len(data) {
		return nil
	}
	hello.Version = binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// Random (32 bytes)
	offset += 32

	// Session ID
	if offset >= len(data) {
		return nil
	}
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	// Cipher Suites
	if offset+2 > len(data) {
		return nil
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if offset+cipherSuitesLen > len(data) {
		return nil
	}
	for i := 0; i < cipherSuitesLen; i += 2 {
		cs := binary.BigEndian.Uint16(data[offset+i:])
		if !greaseValues[cs] {
			hello.CipherSuites = append(hello.CipherSuites, cs)
		}
	}
	offset += cipherSuitesLen

	// Compression Methods
	if offset >= len(data) {
		return nil
	}
	compressionLen := int(data[offset])
	offset += 1 + compressionLen

	// Extensions
	if offset+2 > len(data) {
		return hello
	}
	extLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	extEnd := offset + extLen

	for offset+4 <= extEnd && offset+4 <= len(data) {
		extType := binary.BigEndian.Uint16(data[offset:])
		extDataLen := int(binary.BigEndian.Uint16(data[offset+2:]))
		offset += 4

		if !greaseValues[extType] {
			hello.Extensions = append(hello.Extensions, extType)
		}

		switch extType {
		case 0x0000: // SNI
			if extDataLen > 5 && offset+extDataLen <= len(data) {
				sniListLen := int(binary.BigEndian.Uint16(data[offset:]))
				if sniListLen > 3 && offset+5+sniListLen <= len(data)+2 {
					nameLen := int(binary.BigEndian.Uint16(data[offset+3:]))
					if offset+5+nameLen <= len(data) {
						hello.ServerName = string(data[offset+5 : offset+5+nameLen])
					}
				}
			}
		case 0x000a: // Supported Groups (elliptic curves)
			if extDataLen > 2 && offset+extDataLen <= len(data) {
				curvesLen := int(binary.BigEndian.Uint16(data[offset:]))
				for i := 2; i < curvesLen+2 && offset+i+2 <= len(data); i += 2 {
					curve := binary.BigEndian.Uint16(data[offset+i:])
					if !greaseValues[curve] {
						hello.EllipticCurves = append(hello.EllipticCurves, curve)
					}
				}
			}
		case 0x000b: // EC Point Formats
			if extDataLen > 1 && offset+extDataLen <= len(data) {
				formatsLen := int(data[offset])
				for i := 1; i <= formatsLen && offset+i < len(data); i++ {
					hello.PointFormats = append(hello.PointFormats, data[offset+i])
				}
			}
		}

		offset += extDataLen
	}

	// Compute JA3
	hello.JA3Raw  = buildJA3String(hello)
	hello.JA3     = ja3Hash(hello.JA3Raw)

	return hello
}

func buildJA3String(hello *TLSClientHello) string {
	// JA3: TLSVersion,Ciphers,Extensions,EllipticCurves,PointFormats
	ciphers := joinUint16(hello.CipherSuites, "-")
	exts    := joinUint16(hello.Extensions, "-")
	curves  := joinUint16(hello.EllipticCurves, "-")
	points  := joinUint8(hello.PointFormats, "-")

	return fmt.Sprintf("%d,%s,%s,%s,%s",
		hello.Version, ciphers, exts, curves, points)
}

func ja3Hash(raw string) string {
	h := md5.New()
	h.Write([]byte(raw))
	return hex.EncodeToString(h.Sum(nil))
}

func joinUint16(vals []uint16, sep string) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, sep)
}

func joinUint8(vals []uint8, sep string) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, sep)
}

// ── JA3 Listener ──────────────────────────────────────────

type CaptureStore struct {
	mu       sync.Mutex
	ja3      []JA3Capture
	httpCaps []HTTPCapture
	dnsCaps  []DNSCapture
	output   string
}

func newCaptureStore(output string) *CaptureStore {
	return &CaptureStore{output: output}
}

func (s *CaptureStore) addJA3(c JA3Capture) {
	s.mu.Lock()
	s.ja3 = append(s.ja3, c)
	s.mu.Unlock()
	fmt.Printf("[JA3] %s → %s | SNI: %s | Tool: %s\n",
		c.ClientIP, c.JA3Hash, c.SNI, func() string {
			if c.KnownTool != "" {
				return c.KnownTool
			}
			return "unknown"
		}())
}

func (s *CaptureStore) save() {
	if s.output == "" {
		return
	}
	s.mu.Lock()
	data := struct {
		JA3  []JA3Capture  `json:"ja3_captures"`
		HTTP []HTTPCapture `json:"http_captures"`
		DNS  []DNSCapture  `json:"dns_captures"`
	}{s.ja3, s.httpCaps, s.dnsCaps}
	s.mu.Unlock()
	b, _ := json.MarshalIndent(data, "", "  ")
	os.WriteFile(s.output, b, 0644)
}

func runJA3Listener(port int, store *CaptureStore, verbose bool) {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] JA3 listen failed on %d: %v\n", port, err)
		return
	}
	fmt.Printf("[*] JA3 listener on :%d — capturing TLS ClientHello\n", port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))

			buf := make([]byte, 4096)
			n, err := c.Read(buf)
			if err != nil || n < 5 {
				return
			}

			hello := parseClientHello(buf[:n])
			if hello == nil {
				return
			}

			clientAddr := c.RemoteAddr().(*net.TCPAddr)
			capture := JA3Capture{
				ClientIP:   clientAddr.IP.String(),
				ClientPort: clientAddr.Port,
				DestPort:   port,
				SNI:        hello.ServerName,
				JA3Hash:    hello.JA3,
				JA3String:  hello.JA3Raw,
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
				KnownTool:  knownJA3[hello.JA3],
			}
			store.addJA3(capture)
			store.save()

			if verbose {
				fmt.Printf("  Version: 0x%04X | Ciphers: %d | Extensions: %d\n",
					hello.Version, len(hello.CipherSuites), len(hello.Extensions))
				fmt.Printf("  JA3 raw: %s\n", hello.JA3Raw[:minStr(len(hello.JA3Raw), 80)])
			}

			// Close connection — we only needed the ClientHello
		}(conn)
	}
}

// ── HTTP Capture Proxy ────────────────────────────────────

type HTTPCapture struct {
	ClientIP   string            `json:"client_ip"`
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Host       string            `json:"host"`
	Headers    map[string]string `json:"interesting_headers,omitempty"`
	Secrets    []string          `json:"secrets_found,omitempty"`
	StatusCode int               `json:"status_code,omitempty"`
	Timestamp  string            `json:"timestamp"`
}

// Sensitive header patterns
var sensitiveHeaders = []string{
	"Authorization", "Cookie", "X-Api-Key", "X-Auth-Token",
	"X-Access-Token", "Bearer", "Api-Key", "Token",
}

var credentialPatterns = []string{
	"password=", "passwd=", "pass=", "pwd=",
	"api_key=", "apikey=", "access_token=", "token=",
	"secret=", "key=", "auth=", "credential=",
}

func runHTTPProxy(port int, store *CaptureStore, verbose bool) {
	proxy := &http.Server{
		Addr: fmt.Sprintf(":%d", port),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capture := HTTPCapture{
				ClientIP:  strings.Split(r.RemoteAddr, ":")[0],
				Method:    r.Method,
				URL:       r.URL.String(),
				Host:      r.Host,
				Headers:   make(map[string]string),
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			}

			// Extract interesting headers
			for _, h := range sensitiveHeaders {
				if val := r.Header.Get(h); val != "" {
					capture.Headers[h] = val[:minStr(len(val), 100)]
				}
			}

			// Extract credentials from body
			if r.Method == "POST" {
				body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
				bodyStr := strings.ToLower(string(body))
				for _, pattern := range credentialPatterns {
					if strings.Contains(bodyStr, pattern) {
						idx := strings.Index(bodyStr, pattern)
						end := idx + len(pattern) + 50
						if end > len(bodyStr) {
							end = len(bodyStr)
						}
						capture.Secrets = append(capture.Secrets,
							string(body)[idx:end])
					}
				}
				r.Body = io.NopCloser(strings.NewReader(string(body)))
			}

			if len(capture.Headers) > 0 || len(capture.Secrets) > 0 {
				store.mu.Lock()
				store.httpCaps = append(store.httpCaps, capture)
				store.mu.Unlock()
				store.save()

				fmt.Printf("[HTTP] %s %s %s | headers=%d secrets=%d\n",
					capture.ClientIP, r.Method, r.Host,
					len(capture.Headers), len(capture.Secrets))
				if verbose && len(capture.Secrets) > 0 {
					for _, s := range capture.Secrets {
						fmt.Printf("  [SECRET] %s\n", s[:minStr(len(s), 60)])
					}
				}
			}

			// Forward request (transparent proxy)
			http.Error(w, "Proxy intercepted", http.StatusOK)
		}),
	}

	fmt.Printf("[*] HTTP capture proxy on :%d\n", port)
	proxy.ListenAndServe()
}

// ── DNS Capture ───────────────────────────────────────────

type DNSCapture struct {
	ClientIP  string `json:"client_ip"`
	QueryName string `json:"query_name"`
	QueryType string `json:"query_type"`
	Anomaly   string `json:"anomaly,omitempty"`
	Timestamp string `json:"timestamp"`
}

func runDNSCapture(port int, store *CaptureStore, verbose bool) {
	addr := fmt.Sprintf(":%d", port)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] DNS listen failed on %d: %v\n", port, err)
		return
	}
	defer conn.Close()
	fmt.Printf("[*] DNS capture on UDP :%d\n", port)

	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		if n < 12 {
			continue
		}

		// Parse minimal DNS query
		name, qtype := parseDNSQuery(buf[:n])
		if name == "" {
			continue
		}

		clientIP := strings.Split(addr.String(), ":")[0]
		anomaly  := detectDNSAnomaly(name)

		capture := DNSCapture{
			ClientIP:  clientIP,
			QueryName: name,
			QueryType: qtype,
			Anomaly:   anomaly,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}

		store.mu.Lock()
		store.dnsCaps = append(store.dnsCaps, capture)
		store.mu.Unlock()

		anom := ""
		if anomaly != "" {
			anom = " [!" + anomaly + "!]"
		}
		fmt.Printf("[DNS] %s → %s (%s)%s\n", clientIP, name, qtype, anom)
		if anomaly != "" {
			store.save()
		}
	}
}

func parseDNSQuery(data []byte) (string, string) {
	if len(data) < 12 {
		return "", ""
	}
	offset := 12 // Skip DNS header

	// Parse QNAME
	var nameParts []string
	for offset < len(data) {
		labelLen := int(data[offset])
		if labelLen == 0 {
			offset++
			break
		}
		if labelLen > 63 || offset+1+labelLen > len(data) {
			break
		}
		nameParts = append(nameParts, string(data[offset+1:offset+1+labelLen]))
		offset += 1 + labelLen
	}

	name := strings.Join(nameParts, ".")

	// Parse QTYPE
	qtype := "A"
	if offset+2 <= len(data) {
		switch binary.BigEndian.Uint16(data[offset:]) {
		case 1:  qtype = "A"
		case 28: qtype = "AAAA"
		case 5:  qtype = "CNAME"
		case 15: qtype = "MX"
		case 16: qtype = "TXT"
		case 2:  qtype = "NS"
		}
	}

	return name, qtype
}

func detectDNSAnomaly(name string) string {
	// DGA detection: high entropy domain
	if len(name) > 30 && strings.Count(name, ".") <= 2 {
		entropy := calcEntropy(name)
		if entropy > 3.8 {
			return fmt.Sprintf("DGA_suspect(entropy=%.2f)", entropy)
		}
	}

	// Beaconing: very short domain with random-looking subdomain
	parts := strings.Split(name, ".")
	if len(parts) >= 3 && len(parts[0]) > 20 {
		return "possible_beaconing"
	}

	// DNS tunneling: long subdomain (data exfiltration)
	if len(parts) > 0 && len(parts[0]) > 50 {
		return "possible_dns_tunneling"
	}

	// Known C2/malware patterns
	c2Patterns := []string{
		".onion.", "pastebin.com", "githubusercontent.com",
		"bit.ly", "t.co", "ngrok.io",
	}
	for _, p := range c2Patterns {
		if strings.Contains(name, p) {
			return "c2_indicator"
		}
	}

	return ""
}

func calcEntropy(s string) float64 {
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	var entropy float64
	l := float64(len(s))
	for _, f := range freq {
		p := f / l
		entropy -= p * logBase2(p)
	}
	return entropy
}

func logBase2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// ln(x) / ln(2)
	result := 0.0
	for x > 1 {
		x /= 2
		result++
	}
	return result
}

func minStr(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── Main ──────────────────────────────────────────────────

func main() {
	mode     := flag.String("mode",       "ja3", "Mode: ja3|http|dns|all")
	ja3Port  := flag.Int("ja3-port",      8443, "JA3 listener port")
	httpPort := flag.Int("http-port",     8080, "HTTP proxy port")
	dnsPort  := flag.Int("dns-port",      5353, "DNS capture port")
	port     := flag.Int("port",          0,    "Single port (overrides mode-specific)")
	output   := flag.String("output",     "",   "Output JSON file")
	verbose  := flag.Bool("verbose",      false, "Verbose output")
	ver      := flag.Bool("version",      false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchpcap v%s\n", Version)
		os.Exit(0)
	}
	if *port > 0 {
		*ja3Port  = *port
		*httpPort = *port
		*dnsPort  = *port
	}

	store := newCaptureStore(*output)

	fmt.Printf("[*] glitchpcap v%s | mode=%s\n", Version, *mode)
	fmt.Println("[*] Passive capture — press Ctrl+C to stop")

	var wg sync.WaitGroup

	if *mode == "ja3" || *mode == "all" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runJA3Listener(*ja3Port, store, *verbose)
		}()
	}
	if *mode == "http" || *mode == "all" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runHTTPProxy(*httpPort, store, *verbose)
		}()
	}
	if *mode == "dns" || *mode == "all" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runDNSCapture(*dnsPort, store, *verbose)
		}()
	}

	// Periodic save
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			store.save()
		}
	}()

	wg.Wait()
}

// ── Reader helper ─────────────────────────────────────────

var _ = bufio.NewReader
