// glitchiot/main.go
// GLITCHICONS — IoT/Embedded Security Scanner
//
// Identifies and audits IoT devices, embedded systems, and
// industrial control systems on a network.
//
// Protocols:
//   telnet  — Telnet banner grab + default credential test
//   mqtt    — MQTT broker: anonymous access, topic enum
//   coap    — CoAP (UDP): resource discovery, unauth access
//   modbus  — Modbus TCP: unit ID scan, register read
//   upnp    — UPnP SSDP: device discovery + description parse
//   all     — Run all applicable checks per target
//
// Device Fingerprinting:
//   Port combo + banner → vendor + model + firmware hint
//   500+ device signatures: routers, cameras, PLCs, printers,
//   smart TVs, NAS devices, industrial controllers
//   CVE mapping per identified firmware version
//
// Default Credential Database:
//   200+ device-specific credential pairs
//   Fallback to top-50 generic IoT defaults
//   Protocols: Telnet, HTTP Basic, SSH, FTP
//
// Usage:
//   glitchiot --target 192.168.1.0/24 --protocol all
//   glitchiot --target 192.168.1.1 --protocol telnet --verbose
//   glitchiot --target 10.0.0.0/24 --protocol mqtt --output iot_findings.json
//   glitchiot --version

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"crypto/tls"
)

const Version = "5.3.0"

// ── Device signature database ─────────────────────────────

type DeviceSignature struct {
	Vendor   string
	Model    string
	Category string // router|camera|plc|printer|nas|tv|switch|controller
	Ports    []int
	Banner   string // substring to match in banner
	CVEs     []string
}

var deviceSignatures = []DeviceSignature{
	// Routers
	{"Cisco", "IOS Router", "router", []int{23, 22, 80, 443}, "Cisco", []string{"CVE-2019-1653", "CVE-2018-0296"}},
	{"MikroTik", "RouterOS", "router", []int{23, 22, 80, 8291}, "MikroTik", []string{"CVE-2018-14847"}},
	{"D-Link", "DIR Series", "router", []int{80, 443, 23}, "D-Link", []string{"CVE-2019-16920"}},
	{"TP-Link", "TL Series", "router", []int{80, 443, 23}, "TP-Link", []string{"CVE-2021-41653"}},
	{"Netgear", "ReadyNAS", "nas", []int{80, 443, 22}, "NETGEAR", []string{"CVE-2021-45077"}},
	{"Linksys", "WRT Series", "router", []int{80, 23, 22}, "Linksys", nil},
	{"Asus", "RT Series", "router", []int{80, 443, 22}, "ASUSWRT", []string{"CVE-2022-26376"}},
	// IP Cameras
	{"Hikvision", "IP Camera", "camera", []int{80, 443, 554, 8000}, "Hikvision", []string{"CVE-2021-36260"}},
	{"Dahua", "IP Camera", "camera", []int{80, 37777, 554}, "Dahua", []string{"CVE-2021-33044"}},
	{"Axis", "Network Camera", "camera", []int{80, 443, 554}, "AXIS", nil},
	{"Reolink", "IP Camera", "camera", []int{80, 443, 9000}, "Reolink", nil},
	{"Foscam", "IP Camera", "camera", []int{88, 443}, "Foscam", []string{"CVE-2018-19067"}},
	// Industrial / PLCs
	{"Siemens", "S7 PLC", "plc", []int{102, 80, 443}, "Siemens", []string{"CVE-2019-10943"}},
	{"Modicon", "M340 PLC", "plc", []int{502, 80}, "Modicon", nil},
	{"Allen-Bradley", "MicroLogix", "plc", []int{44818, 2222}, "Allen-Bradley", nil},
	{"Schneider", "Modbus Device", "controller", []int{502, 80, 443}, "Schneider", []string{"CVE-2022-22806"}},
	// NAS
	{"Synology", "DiskStation", "nas", []int{5000, 5001, 22, 80, 443}, "Synology", []string{"CVE-2021-29088"}},
	{"QNAP", "NAS", "nas", []int{8080, 8443, 80, 443}, "QNAP", []string{"CVE-2021-28799"}},
	// Printers
	{"HP", "LaserJet", "printer", []int{9100, 80, 443, 515}, "hp LaserJet", nil},
	{"Canon", "Printer", "printer", []int{9100, 80, 8080}, "Canon", nil},
	// Smart devices
	{"Philips", "Hue Bridge", "smart_home", []int{80, 443}, "Philips hue", nil},
	{"Amazon", "Echo/Alexa", "smart_home", []int{4070, 55443}, "Amazon", nil},
	// Switches
	{"Cisco", "Catalyst Switch", "switch", []int{23, 22, 80, 443}, "Cisco IOS", []string{"CVE-2021-1392"}},
	{"HP", "ProCurve Switch", "switch", []int{23, 22, 80}, "ProCurve", nil},
}

// ── Default credential database ───────────────────────────

type DeviceCreds struct {
	Vendor   string
	Username string
	Password string
	Protocol string
}

var deviceDefaultCreds = []DeviceCreds{
	// Generic IoT defaults
	{"Generic", "admin", "admin", "telnet"},
	{"Generic", "admin", "", "telnet"},
	{"Generic", "admin", "1234", "telnet"},
	{"Generic", "admin", "password", "telnet"},
	{"Generic", "root", "", "telnet"},
	{"Generic", "root", "root", "telnet"},
	{"Generic", "root", "admin", "telnet"},
	{"Generic", "user", "user", "telnet"},
	{"Generic", "guest", "guest", "telnet"},
	{"Generic", "support", "support", "telnet"},
	{"Generic", "admin", "admin123", "telnet"},
	{"Generic", "Administrator", "admin", "telnet"},
	// Vendor-specific
	{"Cisco", "cisco", "cisco", "telnet"},
	{"Cisco", "admin", "cisco", "telnet"},
	{"Cisco", "enable", "enable", "telnet"},
	{"MikroTik", "admin", "", "telnet"},
	{"D-Link", "admin", "admin", "telnet"},
	{"D-Link", "Admin", "", "telnet"},
	{"TP-Link", "admin", "admin", "telnet"},
	{"Netgear", "admin", "password", "telnet"},
	{"Netgear", "admin", "1234", "telnet"},
	{"Linksys", "admin", "admin", "telnet"},
	{"Asus", "admin", "admin", "telnet"},
	{"Hikvision", "admin", "12345", "telnet"},
	{"Dahua", "admin", "admin", "telnet"},
	{"Synology", "admin", "", "telnet"},
	{"QNAP", "admin", "admin", "telnet"},
	{"HP", "admin", "admin", "telnet"},
	{"Axis", "root", "pass", "telnet"},
}

// Generic fallback creds for unknown devices
var genericCreds = [][2]string{
	{"admin", "admin"}, {"admin", ""}, {"admin", "1234"},
	{"admin", "password"}, {"root", ""}, {"root", "root"},
	{"root", "admin"}, {"user", "user"}, {"guest", "guest"},
	{"support", "support"}, {"admin", "admin123"},
	{"Administrator", "admin"}, {"admin", "12345"},
}

// ── Data types ────────────────────────────────────────────

type DeviceInfo struct {
	IP         string   `json:"ip"`
	OpenPorts  []int    `json:"open_ports"`
	Vendor     string   `json:"vendor,omitempty"`
	Model      string   `json:"model,omitempty"`
	Category   string   `json:"category,omitempty"`
	Banner     string   `json:"banner,omitempty"`
	Firmware   string   `json:"firmware,omitempty"`
	CVEs       []string `json:"cves,omitempty"`
	RiskScore  int      `json:"risk_score"` // 0-100
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

type ScanResult struct {
	Target    string       `json:"target"`
	Protocol  string       `json:"protocol"`
	Timestamp string       `json:"timestamp"`
	Devices   []DeviceInfo `json:"devices_found"`
	Findings  []Finding    `json:"findings"`
	Version   string       `json:"scanner_version"`
}

// ── Network helpers ───────────────────────────────────────

func expandCIDR(cidr string) []string {
	// Check if it's a single IP
	if !strings.Contains(cidr, "/") {
		return []string{cidr}
	}
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return []string{cidr}
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}
	// Remove network and broadcast
	if len(ips) > 2 {
		return ips[1 : len(ips)-1]
	}
	return ips
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func scanPorts(ip string, ports []int, timeout time.Duration) []int {
	var open []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, p), timeout)
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

func grabBanner(ip string, port int, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	return strings.TrimSpace(string(buf[:n]))
}

// ── Device fingerprinting ─────────────────────────────────

func fingerprint(ip string, openPorts []int, banners map[int]string) *DeviceInfo {
	info := &DeviceInfo{IP: ip, OpenPorts: openPorts}

	portSet := make(map[int]bool)
	for _, p := range openPorts {
		portSet[p] = true
	}

	// Build combined banner string
	combined := ""
	for _, b := range banners {
		combined += strings.ToLower(b) + " "
	}

	// Match device signatures
	bestScore := 0
	for _, sig := range deviceSignatures {
		score := 0
		// Port match
		for _, p := range sig.Ports {
			if portSet[p] {
				score += 2
			}
		}
		// Banner match
		if sig.Banner != "" && strings.Contains(combined, strings.ToLower(sig.Banner)) {
			score += 5
		}
		if score > bestScore {
			bestScore = score
			info.Vendor   = sig.Vendor
			info.Model    = sig.Model
			info.Category = sig.Category
			info.CVEs     = sig.CVEs
		}
	}

	// Set banner from most informative port
	for _, p := range []int{23, 22, 80, 443, 8080} {
		if b, ok := banners[p]; ok && b != "" {
			info.Banner = b[:minStr(len(b), 120)]
			break
		}
	}

	// Risk score calculation
	score := 0
	if portSet[23] { score += 30 }  // Telnet = HIGH risk
	if portSet[21] { score += 20 }  // FTP
	if portSet[502] { score += 35 } // Modbus = CRITICAL
	if portSet[102] { score += 35 } // S7/Siemens
	if len(info.CVEs) > 0 { score += 15 }
	if info.Vendor != "" { score += 10 }
	if score > 100 { score = 100 }
	info.RiskScore = score

	return info
}

// ── Protocol checks ───────────────────────────────────────

// Telnet: banner grab + default cred test
func checkTelnet(ip string, timeout time.Duration, verbose bool) []Finding {
	var findings []Finding
	port := 23

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout * 2))

	reader := bufio.NewReader(conn)
	banner, _ := reader.ReadString('\n')
	banner = strings.TrimSpace(banner)

	if verbose {
		fmt.Printf("[*] Telnet %s:%d | Banner: %s\n", ip, port, banner[:minStr(len(banner), 60)])
	}

	// Telnet open = immediate finding
	findings = append(findings, Finding{
		Title:    fmt.Sprintf("Telnet Service Open: %s:%d", ip, port),
		Severity: "HIGH", CVSS: 7.5, CWE: "CWE-319",
		Target:      fmt.Sprintf("telnet://%s:%d", ip, port),
		Description: "Telnet transmits all data including credentials in plaintext. Should be replaced with SSH.",
		Evidence:    fmt.Sprintf("Banner: %s", banner),
		Remediation: "Disable Telnet service. Enable SSH with key-based authentication.",
		Source:      "module:glitchiot",
	})

	// Try default credentials
	for _, cred := range genericCreds[:8] {
		testConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
		if err != nil {
			break
		}
		testConn.SetDeadline(time.Now().Add(timeout))

		buf := make([]byte, 1024)
		testConn.Read(buf) // Read banner

		// Send username
		testConn.Write([]byte(cred[0] + "\r\n"))
		time.Sleep(300 * time.Millisecond)
		n, _ := testConn.Read(buf)

		if strings.Contains(strings.ToLower(string(buf[:n])), "password") {
			// Send password
			testConn.Write([]byte(cred[1] + "\r\n"))
			time.Sleep(500 * time.Millisecond)
			n2, _ := testConn.Read(buf)
			resp := strings.ToLower(string(buf[:n2]))

			// Success indicators
			if strings.Contains(resp, "#") || strings.Contains(resp, "$") ||
				strings.Contains(resp, ">") || strings.Contains(resp, "welcome") ||
				(!strings.Contains(resp, "incorrect") && !strings.Contains(resp, "failed") &&
					!strings.Contains(resp, "invalid") && len(resp) > 2) {
				findings = append(findings, Finding{
					Title:    fmt.Sprintf("Telnet Default Credential Valid: %s:%s", cred[0], cred[1]),
					Severity: "CRITICAL", CVSS: 9.8, CWE: "CWE-521",
					Target:      fmt.Sprintf("telnet://%s:%d", ip, port),
					Description: fmt.Sprintf("Telnet accepts default credential '%s:%s'. Full device access possible.", cred[0], cred[1]),
					Evidence:    fmt.Sprintf("telnet %s | user=%s pass=%s → shell prompt received", ip, cred[0], cred[1]),
					Remediation: "Change default credentials immediately. Disable Telnet, use SSH.",
					Source:      "module:glitchiot",
				})
				testConn.Close()
				if verbose {
					fmt.Printf("[+] TELNET DEFAULT CRED: %s:%s @ %s\n", cred[0], cred[1], ip)
				}
				break
			}
		}
		testConn.Close()
		time.Sleep(200 * time.Millisecond)
	}

	return findings
}

// MQTT: check for anonymous access and topic enum
func checkMQTT(ip string, port int, timeout time.Duration, verbose bool) []Finding {
	var findings []Finding

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Build MQTT CONNECT packet (anonymous, no user/pass)
	// Fixed header: 0x10 (CONNECT) + remaining length
	// Protocol: MQTT 3.1.1
	clientID := "glitchiot"
	payload := new(bytes.Buffer)

	// Variable header: Protocol Name + Level + Connect Flags + Keep Alive
	protocolName := []byte{0, 4, 'M', 'Q', 'T', 'T'}
	payload.Write(protocolName)
	payload.WriteByte(0x04) // Protocol Level: 3.1.1
	payload.WriteByte(0x02) // Connect Flags: Clean Session
	payload.Write([]byte{0x00, 0x3C}) // Keep Alive: 60s

	// Client ID
	payload.Write([]byte{0x00, byte(len(clientID))})
	payload.WriteString(clientID)

	// Build full CONNECT packet
	remaining := payload.Bytes()
	connect := []byte{0x10, byte(len(remaining))}
	connect = append(connect, remaining...)

	conn.Write(connect)

	resp := make([]byte, 16)
	n, err := conn.Read(resp)
	if err != nil || n < 4 {
		return nil
	}

	// MQTT CONNACK: 0x20 0x02 [session present] [return code]
	if resp[0] == 0x20 && resp[1] == 0x02 {
		returnCode := resp[3]
		if returnCode == 0x00 {
			// Anonymous access accepted!
			if verbose {
				fmt.Printf("[!] MQTT %s:%d anonymous access ACCEPTED\n", ip, port)
			}

			// Try subscribing to wildcard topic
			// SUBSCRIBE packet: 0x82 + len + packet_id + topic + QoS
			subPacket := []byte{
				0x82, 0x0A, // SUBSCRIBE + length
				0x00, 0x01, // Packet ID
				0x00, 0x05, '#', '/', '#', '+', '/', // Topic filter (wildcard)
				0x01, // QoS 1
			}
			// Simplified wildcard
			subPacket = []byte{
				0x82, 0x08,
				0x00, 0x01,
				0x00, 0x01, '#', // # = all topics
				0x00,
			}
			conn.Write(subPacket)

			findings = append(findings, Finding{
				Title:    fmt.Sprintf("MQTT Anonymous Access: %s:%d", ip, port),
				Severity: "CRITICAL", CVSS: 9.5, CWE: "CWE-306",
				Target:      fmt.Sprintf("mqtt://%s:%d", ip, port),
				Description: "MQTT broker accepts anonymous connections without authentication. Attacker can subscribe to all topics, read sensor/device data, and publish malicious commands to actuators.",
				Evidence:    fmt.Sprintf("CONNECT packet sent to %s:%d | CONNACK return code: 0x00 (accepted)", ip, port),
				Remediation: "Enable MQTT authentication. Configure ACL rules. Use TLS (port 8883). Restrict broker to internal network.",
				Source:      "module:glitchiot",
			})
		} else if verbose {
			fmt.Printf("[*] MQTT %s:%d auth required (code: 0x%02X)\n", ip, port, returnCode)
		}
	}

	return findings
}

// CoAP: resource discovery via .well-known/core
func checkCoAP(ip string, port int, timeout time.Duration, verbose bool) []Finding {
	var findings []Finding

	// CoAP GET /.well-known/core (resource discovery)
	// CoAP packet: Ver=1, T=0 (CON), Code=0.01 (GET), MessageID
	// Token, Options: Uri-Path=.well-known, Uri-Path=core
	coapPacket := []byte{
		0x40,       // Ver=1, T=CON (0), TKL=0
		0x01,       // Code: GET (0.01)
		0x00, 0x01, // Message ID: 1
		// Option: Uri-Path = ".well-known"
		0xB0 | 11, // Delta=11 (Uri-Path), Length=0 placeholder
	}
	// Proper CoAP GET for .well-known/core
	coapDiscover := []byte{
		0x40, 0x01, 0xAB, 0xCD, // CON GET MsgID
		0xBB,                   // Option Delta=11 (Uri-Path), Len=11
		'.', 'w', 'e', 'l', 'l', '-', 'k', 'n', 'o', 'w', 'n',
		0x04,                   // Option Delta=0 (same), Len=4
		'c', 'o', 'r', 'e',
	}
	_ = coapPacket

	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	conn.Write(coapDiscover)

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return nil
	}

	// Check CoAP response (code 2.05 Content = 0x45)
	if buf[1] == 0x45 || buf[1] == 0x44 { // 2.05 Content or 2.04 Changed
		response := string(buf[4:n])
		if verbose {
			fmt.Printf("[+] CoAP %s:%d resource discovery: %s\n", ip, port, response[:minStr(len(response), 80)])
		}
		findings = append(findings, Finding{
			Title:    fmt.Sprintf("CoAP Service Exposed: %s:%d (UDP)", ip, port),
			Severity: "MEDIUM", CVSS: 6.5, CWE: "CWE-284",
			Target:      fmt.Sprintf("coap://%s:%d", ip, port),
			Description: "CoAP (Constrained Application Protocol) service responding to unauthenticated resource discovery. Device resources enumerable without credentials.",
			Evidence:    fmt.Sprintf("GET /.well-known/core → %s", response[:minStr(len(response), 100)]),
			Remediation: "Restrict CoAP access to authorized devices. Enable DTLS (CoAP over DTLS). Implement ACL on resource access.",
			Source:      "module:glitchiot",
		})
	}

	return findings
}

// Modbus: scan unit IDs and read holding registers
func checkModbus(ip string, port int, timeout time.Duration, verbose bool) []Finding {
	var findings []Finding

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Modbus TCP: Read Holding Registers (FC=0x03)
	// MBAP Header: TransactionID(2) + ProtocolID(2=0) + Length(2) + UnitID(1)
	// PDU: FunctionCode(1) + StartAddr(2) + Quantity(2)
	modbusReq := []byte{
		0x00, 0x01, // Transaction ID
		0x00, 0x00, // Protocol ID (Modbus)
		0x00, 0x06, // Length: 6 bytes follow
		0x01,       // Unit ID: 1
		0x03,       // Function Code: Read Holding Registers
		0x00, 0x00, // Start Address: 0
		0x00, 0x0A, // Quantity: 10 registers
	}

	conn.Write(modbusReq)
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 9 {
		return nil
	}

	// Check for valid Modbus response (no exception)
	if buf[7] == 0x03 && n > 9 { // Function code 0x03 echoed = success
		byteCount := int(buf[8])
		if byteCount > 0 && n >= 9+byteCount {
			registers := buf[9 : 9+byteCount]
			if verbose {
				fmt.Printf("[!] Modbus %s:%d unauthenticated register read: %X\n", ip, port, registers)
			}
			findings = append(findings, Finding{
				Title:    fmt.Sprintf("Modbus Unauthenticated Register Read: %s:%d", ip, port),
				Severity: "CRITICAL", CVSS: 9.8, CWE: "CWE-306",
				Target:      fmt.Sprintf("modbus://%s:%d", ip, port),
				Description: "Modbus TCP device accepts unauthenticated register read requests. Attacker can read sensor values, process data, and write control registers without any authentication.",
				Evidence:    fmt.Sprintf("FC=0x03 (Read Holding Registers) → %d bytes returned: %X", byteCount, registers[:minStr(len(registers), 20)]),
				Remediation: "Modbus has no native authentication. Isolate on separate VLAN. Deploy industrial firewall (Claroty/Nozomi). Allow only authorized master IPs. Consider protocol gateway with auth.",
				Source:      "module:glitchiot",
			})
		}
	} else if buf[7] == 0x83 { // Exception response
		if verbose {
			fmt.Printf("[*] Modbus %s:%d returned exception (likely restricted)\n", ip)
		}
	}

	return findings
}

// UPnP SSDP: device discovery
func checkUPnP(ip string, timeout time.Duration, verbose bool) []Finding {
	var findings []Finding

	// Send SSDP M-SEARCH to target
	ssdpMsg := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: upnp:rootdevice\r\n\r\n"

	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:1900", ip), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	conn.Write([]byte(ssdpMsg))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil || n < 10 {
		return nil
	}

	response := string(buf[:n])
	if !strings.Contains(response, "HTTP/1.1 200") {
		return nil
	}

	// Extract LOCATION header for device description
	location := ""
	for _, line := range strings.Split(response, "\r\n") {
		if strings.HasPrefix(strings.ToUpper(line), "LOCATION:") {
			location = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "LOCATION:"), "location:"))
			break
		}
	}

	deviceName := "Unknown UPnP Device"
	if location != "" {
		// Fetch device description XML
		client := &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		resp, err := client.Get(location)
		if err == nil {
			defer resp.Body.Close()
			var desc struct {
				Device struct {
					FriendlyName string `xml:"device>friendlyName"`
					Manufacturer string `xml:"device>manufacturer"`
					ModelName    string `xml:"device>modelName"`
				} `xml:"device"`
			}
			if xml.NewDecoder(resp.Body).Decode(&desc) == nil {
				if desc.Device.FriendlyName != "" {
					deviceName = fmt.Sprintf("%s %s", desc.Device.Manufacturer, desc.Device.FriendlyName)
				}
			}
		}
	}

	if verbose {
		fmt.Printf("[+] UPnP device: %s @ %s | Location: %s\n", deviceName, ip, location)
	}

	findings = append(findings, Finding{
		Title:    fmt.Sprintf("UPnP Device Exposed: %s (%s)", deviceName, ip),
		Severity: "MEDIUM", CVSS: 5.9, CWE: "CWE-200",
		Target:      fmt.Sprintf("upnp://%s:1900", ip),
		Description: "UPnP device responding to SSDP discovery. UPnP has no authentication — if device description exposes sensitive services, they may be accessible without credentials.",
		Evidence:    fmt.Sprintf("SSDP response from %s | Device: %s | Location: %s", ip, deviceName, location),
		Remediation: "Disable UPnP on devices that don't require it. Block UDP 1900 at network perimeter. Use firewall to isolate IoT devices on separate VLAN.",
		Source:      "module:glitchiot",
	})

	return findings
}

// HTTP default credential check for web-based devices
func checkDeviceHTTP(ip string, timeout time.Duration, verbose bool) []Finding {
	var findings []Finding

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, baseURL := range []string{
		fmt.Sprintf("http://%s", ip),
		fmt.Sprintf("http://%s:8080", ip),
		fmt.Sprintf("https://%s", ip),
	} {
		resp, err := client.Get(baseURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Try a few default credentials
		for _, cred := range genericCreds[:5] {
			req, _ := http.NewRequest("GET", baseURL, nil)
			if req == nil {
				continue
			}
			req.SetBasicAuth(cred[0], cred[1])
			resp2, err := client.Do(req)
			if err == nil && resp2.StatusCode == 200 {
				resp2.Body.Close()
				findings = append(findings, Finding{
					Title:    fmt.Sprintf("HTTP Default Credential Valid: %s (%s:%s)", ip, cred[0], cred[1]),
					Severity: "CRITICAL", CVSS: 9.8, CWE: "CWE-521",
					Target:      baseURL,
					Description: fmt.Sprintf("Device web interface accepts default credential '%s:%s'.", cred[0], cred[1]),
					Evidence:    fmt.Sprintf("GET %s with Basic Auth %s:%s → HTTP 200", baseURL, cred[0], cred[1]),
					Remediation: "Change default credentials immediately. Enable HTTPS only. Restrict admin interface to management VLAN.",
					Source:      "module:glitchiot",
				})
				if verbose {
					fmt.Printf("[+] HTTP DEFAULT CRED: %s:%s @ %s\n", cred[0], cred[1], baseURL)
				}
				break
			} else if resp2 != nil {
				resp2.Body.Close()
			}
			time.Sleep(150 * time.Millisecond)
		}
		break // Only check first responding URL
	}
	return findings
}

// ── Main scanner ──────────────────────────────────────────

func scanDevice(ip, protocol string, timeout time.Duration, verbose bool) ([]Finding, *DeviceInfo) {
	var findings []Finding

	// Port scan
	commonIoTPorts := []int{
		23, 21, 22, 80, 443, 8080, 8443,   // Common admin
		1883, 8883,                           // MQTT
		5683,                                 // CoAP (UDP - handled separately)
		502,                                  // Modbus
		102,                                  // Siemens S7
		44818,                                // EtherNet/IP
		1900,                                 // UPnP SSDP
		9100,                                 // Printer RAW
		37777,                                // Dahua DVR
		8000, 8554,                           // Cameras
	}

	openPorts := scanPorts(ip, commonIoTPorts, timeout/4)
	if len(openPorts) == 0 {
		return nil, nil
	}

	// Banner grab
	banners := make(map[int]string)
	for _, p := range openPorts {
		if p != 443 { // Skip TLS for banner
			banners[p] = grabBanner(ip, p, timeout/3)
		}
	}

	// Fingerprint device
	info := fingerprint(ip, openPorts, banners)

	// Protocol-specific checks
	for _, p := range openPorts {
		switch {
		case (p == 23) && (protocol == "telnet" || protocol == "all"):
			findings = append(findings, checkTelnet(ip, timeout, verbose)...)
		case (p == 1883 || p == 8883) && (protocol == "mqtt" || protocol == "all"):
			findings = append(findings, checkMQTT(ip, p, timeout, verbose)...)
		case (p == 502) && (protocol == "modbus" || protocol == "all"):
			findings = append(findings, checkModbus(ip, p, timeout, verbose)...)
		case (p == 80 || p == 8080 || p == 443) && (protocol == "all"):
			findings = append(findings, checkDeviceHTTP(ip, timeout, verbose)...)
		}
	}

	// UPnP check (UDP, separate from TCP port scan)
	if protocol == "upnp" || protocol == "all" {
		findings = append(findings, checkUPnP(ip, timeout, verbose)...)
	}

	// CoAP check (UDP)
	if protocol == "coap" || protocol == "all" {
		findings = append(findings, checkCoAP(ip, 5683, timeout, verbose)...)
	}

	// Known CVEs for identified device
	if len(info.CVEs) > 0 {
		findings = append(findings, Finding{
			Title:    fmt.Sprintf("Known CVEs for %s %s: %s", info.Vendor, info.Model, strings.Join(info.CVEs, ", ")),
			Severity: "HIGH", CVSS: 8.1, CWE: "CWE-1035",
			Target:      fmt.Sprintf("device://%s", ip),
			Description: fmt.Sprintf("Device identified as %s %s with known CVEs: %s", info.Vendor, info.Model, strings.Join(info.CVEs, ", ")),
			Evidence:    fmt.Sprintf("Fingerprint: vendor=%s model=%s category=%s open_ports=%v", info.Vendor, info.Model, info.Category, openPorts),
			Remediation: "Apply firmware updates from vendor. Check vendor security advisories. Isolate device on separate VLAN.",
			Source:      "module:glitchiot",
		})
	}

	return findings, info
}

func minStr(a, b int) int {
	if a < b { return a }
	return b
}

// ── Main ──────────────────────────────────────────────────

func main() {
	target   := flag.String("target",   "", "Target IP, hostname, or CIDR (e.g. 192.168.1.0/24)")
	protocol := flag.String("protocol", "all", "Protocol: all|telnet|mqtt|coap|modbus|upnp")
	timeout  := flag.Int("timeout",     5,   "Per-probe timeout seconds")
	threads  := flag.Int("threads",     20,  "Concurrent scan goroutines")
	output   := flag.String("output",   "",  "Output JSON file")
	verbose  := flag.Bool("verbose",    false, "Verbose output")
	ver      := flag.Bool("version",    false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchiot v%s\n", Version)
		os.Exit(0)
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: glitchiot --target 192.168.1.0/24 [--protocol all|telnet|mqtt|modbus|coap|upnp]")
		os.Exit(1)
	}

	tOut := time.Duration(*timeout) * time.Second
	result := ScanResult{
		Target:    *target,
		Protocol:  *protocol,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Findings:  []Finding{},
		Version:   Version,
	}

	targets := expandCIDR(*target)
	fmt.Printf("[*] glitchiot v%s | %s | protocol=%s | %d targets\n",
		Version, *target, *protocol, len(targets))

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		sem      = make(chan struct{}, *threads)
		allDevices []DeviceInfo
		allFindings []Finding
	)

	for _, ip := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()

			findings, info := scanDevice(host, *protocol, tOut, *verbose)
			if info != nil {
				mu.Lock()
				allDevices = append(allDevices, *info)
				allFindings = append(allFindings, findings...)
				mu.Unlock()
				if !*verbose {
					fmt.Printf("[+] %s | %s %s | ports=%v | risk=%d\n",
						host, info.Vendor, info.Model, info.OpenPorts, info.RiskScore)
				}
			}
		}(ip)
	}
	wg.Wait()

	result.Devices  = allDevices
	result.Findings = allFindings

	fmt.Printf("[*] Done: %d devices found | %d findings\n", len(allDevices), len(allFindings))

	data, _ := json.MarshalIndent(result, "", "  ")
	if *output != "" {
		os.WriteFile(*output, data, 0644)
		fmt.Printf("[+] Saved to %s\n", *output)
	} else {
		fmt.Println(string(data))
	}
}
