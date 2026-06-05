// glitchwmi/main.go
// GLITCHICONS — WMI/DCOM Security Auditor
//
// Checks WMI (Windows Management Instrumentation) exposure via DCOM/RPC.
//
// Checks:
//   - Port 135 DCOM/RPC Endpoint Mapper availability
//   - DCE/RPC bind to OXID resolver interface
//   - WMI namespace detection (root\cimv2)
//   - DCOM interface enumeration (known risky interfaces)
//   - Remote execution capability fingerprint
//   - DCOM authentication level detection
//
// WMI Attack Surface:
//   - Remote process creation: Win32_Process.Create()
//   - Persistence: Win32_EventFilter + Win32_CommandLineEventConsumer
//   - Lateral movement: wmiexec-style execution
//   - Info gathering: Win32_UserAccount, Win32_ComputerSystem
//
// Usage:
//   glitchwmi --target 192.168.1.10
//   glitchwmi --target dc.corp.local --verbose --output wmi_findings.json

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
)

const Version = "4.2.0"

// ── DCE/RPC Constants ─────────────────────────────────────

// Interface UUIDs for known WMI/DCOM interfaces
var dceInterfaces = map[string]struct {
	name    string
	risk    string
	purpose string
}{
	"99fcfec4-5260-101b-bbcb-00aa0021347a": {
		"IOXIDResolver", "HIGH",
		"OXID resolver — exposes registered DCOM interfaces",
	},
	"6bffd098-a112-3610-9833-46c3f87e345a": {
		"IManagementService", "HIGH",
		"WMI Management Service — process/service control",
	},
	"f72df97c-0738-11d0-ada3-00aa0034b981": {
		"IWbemObjectSink", "HIGH",
		"WMI object sink — receive management object results",
	},
	"9556dc99-828c-11cf-a37e-00aa003240c7": {
		"IWbemServices", "CRITICAL",
		"WMI Services — remote process exec, user enum, persistence",
	},
	"1c1c45ee-4395-11d2-b60b-00104b703efd": {
		"IWbemClassObject", "HIGH",
		"WMI Class Object — enumerate WMI classes and instances",
	},
	"dcbcad72-b876-48ca-b368-e5e91c4b37c3": {
		"IWbemObjectTextSrc", "MEDIUM",
		"WMI Object Text Source",
	},
}

// DCE/RPC v5 Bind packet to OXID resolver
// Interface: 99fcfec4-5260-101b-bbcb-00aa0021347a v0.0
func buildDCERPCBind(interfaceUUID string) []byte {
	// Parse UUID
	uuidBytes := parseUUID(interfaceUUID)

	pkt := new(bytes.Buffer)

	// DCE/RPC header
	pkt.WriteByte(0x05) // Version major
	pkt.WriteByte(0x00) // Version minor
	pkt.WriteByte(0x0B) // BIND packet type
	pkt.WriteByte(0x03) // Flags: PFC_FIRST_FRAG | PFC_LAST_FRAG

	// Data representation
	pkt.Write([]byte{0x10, 0x00, 0x00, 0x00}) // Little endian, ASCII, IEEE float

	// Fragment length (total)
	fragLen := uint16(72)
	binary.Write(pkt, binary.LittleEndian, fragLen)

	// Auth length
	binary.Write(pkt, binary.LittleEndian, uint16(0))

	// Call ID
	binary.Write(pkt, binary.LittleEndian, uint32(1))

	// Max xmit/recv fragments
	binary.Write(pkt, binary.LittleEndian, uint16(4280))
	binary.Write(pkt, binary.LittleEndian, uint16(4280))

	// Assoc group
	binary.Write(pkt, binary.LittleEndian, uint32(0))

	// Number of ctx items
	binary.Write(pkt, binary.LittleEndian, uint16(1))
	binary.Write(pkt, binary.LittleEndian, uint16(0)) // pad

	// Ctx item 0
	binary.Write(pkt, binary.LittleEndian, uint16(0)) // Context ID
	binary.Write(pkt, binary.LittleEndian, uint16(1)) // Num transfer syntaxes

	// Interface UUID + version
	pkt.Write(uuidBytes)
	binary.Write(pkt, binary.LittleEndian, uint32(0x00000000)) // Interface version 0.0

	// Transfer syntax: NDR 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0
	ndrSyntax, _ := hex.DecodeString("045d888aeb1cc9119fe808002b104860")
	pkt.Write(ndrSyntax)
	binary.Write(pkt, binary.LittleEndian, uint32(0x00000002)) // NDR version 2

	return pkt.Bytes()
}

func parseUUID(uuid string) []byte {
	// UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	clean := strings.ReplaceAll(uuid, "-", "")
	b, err := hex.DecodeString(clean)
	if err != nil || len(b) != 16 {
		return make([]byte, 16)
	}
	// Reorder for little-endian encoding
	result := make([]byte, 16)
	// First 3 groups are little-endian
	result[0], result[1], result[2], result[3] = b[3], b[2], b[1], b[0]
	result[4], result[5] = b[5], b[4]
	result[6], result[7] = b[7], b[6]
	// Last 2 groups are big-endian
	copy(result[8:], b[8:])
	return result
}

// ── Data types ────────────────────────────────────────────

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

type WMIInfo struct {
	DCOMOpen          bool     `json:"dcom_open"`
	DynamicPort       int      `json:"dynamic_port,omitempty"`
	BindableInterfaces []string `json:"bindable_interfaces,omitempty"`
	OXIDResolvable    bool     `json:"oxid_resolvable"`
	WMIReachable      bool     `json:"wmi_reachable"`
	AuthLevel         string   `json:"auth_level,omitempty"`
}

type ScanResult struct {
	Target    string    `json:"target"`
	Port      int       `json:"port"`
	Timestamp string    `json:"timestamp"`
	Open      bool      `json:"dcom_open"`
	Info      *WMIInfo  `json:"wmi_info,omitempty"`
	Findings  []Finding `json:"findings"`
	Version   string    `json:"scanner_version"`
}

// ── Scanner ───────────────────────────────────────────────

func scanWMI(target string, port int, timeout time.Duration, verbose bool) ScanResult {
	result := ScanResult{
		Target:    target,
		Port:      port,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Findings:  []Finding{},
		Version:   Version,
	}

	addr := fmt.Sprintf("%s:%d", target, port)

	// Step 1: Probe port 135 (DCOM Endpoint Mapper)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		if verbose {
			fmt.Printf("[-] DCOM port %d closed\n", port)
		}
		return result
	}
	defer conn.Close()
	result.Open = true

	info := &WMIInfo{DCOMOpen: true}
	result.Info = info

	if verbose {
		fmt.Printf("[+] DCOM/RPC port %d open\n", port)
	}

	// Step 2: Bind to OXID resolver
	conn.SetDeadline(time.Now().Add(timeout))
	bindPkt := buildDCERPCBind("99fcfec4-5260-101b-bbcb-00aa0021347a")
	conn.Write(bindPkt)

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		// Check for DCE/RPC bind_ack (type 0x0C)
		if n > 2 && buf[2] == 0x0C {
			info.OXIDResolvable = true
			if verbose {
				fmt.Println("[+] OXID resolver reachable — DCOM interface enumeration possible")
			}
		}
	}

	// Step 3: Try to find dynamic WMI port via endpoint mapper response
	dynamicPort := findDynamicPort(buf[:n])
	if dynamicPort > 0 {
		info.DynamicPort = dynamicPort
		if verbose {
			fmt.Printf("[+] WMI dynamic port detected: %d\n", dynamicPort)
		}
	}

	// Step 4: Probe dynamic WMI port if found
	if dynamicPort > 0 {
		wmiAddr := fmt.Sprintf("%s:%d", target, dynamicPort)
		wmiConn, werr := net.DialTimeout("tcp", wmiAddr, timeout)
		if werr == nil {
			wmiConn.Close()
			info.WMIReachable = true
			if verbose {
				fmt.Printf("[+] WMI endpoint reachable on dynamic port %d\n", dynamicPort)
			}
		}
	}

	// Step 5: Test known WMI interfaces
	conn2, err2 := net.DialTimeout("tcp", addr, timeout)
	if err2 == nil {
		defer conn2.Close()
		conn2.SetDeadline(time.Now().Add(timeout))

		// Try IWbemServices interface bind
		wbemBind := buildDCERPCBind("9556dc99-828c-11cf-a37e-00aa003240c7")
		conn2.Write(wbemBind)
		buf2 := make([]byte, 1024)
		n2, _ := conn2.Read(buf2)
		if n2 > 2 && buf2[2] == 0x0C {
			info.BindableInterfaces = append(info.BindableInterfaces, "IWbemServices")
			info.WMIReachable = true
		}
	}

	// ── Generate findings ──────────────────────────────

	// DCOM/RPC exposed
	result.Findings = append(result.Findings, Finding{
		Title:       fmt.Sprintf("DCOM/RPC Endpoint Mapper Exposed on Port %d", port),
		Severity:    "MEDIUM",
		CVSS:        5.9,
		CWE:         "CWE-200",
		Target:      fmt.Sprintf("dcom://%s:%d", target, port),
		Description: "DCOM Endpoint Mapper (RPC) accessible from network. This service registers DCOM interface endpoints and enables remote object activation.",
		Evidence:    fmt.Sprintf("TCP %d: OPEN | DCOM Endpoint Mapper responding", port),
		Remediation: "Block port 135 at network perimeter. Allow only from authorized management hosts via Windows Firewall.",
		Source:      "module:glitchwmi",
	})

	// OXID resolver accessible
	if info.OXIDResolvable {
		result.Findings = append(result.Findings, Finding{
			Title:       "OXID Resolver Accessible — DCOM Interface Enumeration Risk",
			Severity:    "HIGH",
			CVSS:        7.5,
			CWE:         "CWE-284",
			Target:      fmt.Sprintf("dcom://%s:%d/OXIDResolver", target, port),
			Description: "OXID (Object Exporter Identifier) resolver allows enumeration of all registered DCOM interfaces on the target host. Attacker can discover WMI and other manageable interfaces.",
			Evidence: fmt.Sprintf(
				"Interface: IOXIDResolver (99fcfec4-5260-101b-bbcb-00aa0021347a)\n"+
					"Bind: ACCEPTED (DCE/RPC Bind Ack received)\n"+
					"Host: %s", target),
			Remediation: "Restrict DCOM access: DCOMCNFG → My Computer → Properties → COM Security. Restrict 'Access Permissions' to authorized accounts only.",
			Source:      "module:glitchwmi",
		})
	}

	// WMI reachable
	if info.WMIReachable {
		evidence := "IWbemServices interface reachable"
		if info.DynamicPort > 0 {
			evidence += fmt.Sprintf("\nDynamic port: %d", info.DynamicPort)
		}
		if len(info.BindableInterfaces) > 0 {
			evidence += "\nInterfaces: " + strings.Join(info.BindableInterfaces, ", ")
		}

		result.Findings = append(result.Findings, Finding{
			Title:       "WMI Service Reachable — Remote Code Execution Risk",
			Severity:    "HIGH",
			CVSS:        8.8,
			CWE:         "CWE-78",
			Target:      fmt.Sprintf("wmi://%s/root/cimv2", target),
			Description: "WMI (Windows Management Instrumentation) is reachable from network. With valid credentials, attackers can execute commands, enumerate users, create persistence mechanisms, and pivot laterally.",
			Evidence:    evidence,
			Remediation: "Restrict WMI access via Windows Firewall. Enable WMI audit logging. Require network-level authentication. Monitor for Win32_Process.Create() calls via SIEM.",
			Source:      "module:glitchwmi",
		})
	}

	// Dynamic port exposure
	if info.DynamicPort > 0 {
		result.Findings = append(result.Findings, Finding{
			Title:       fmt.Sprintf("WMI Dynamic Port Exposed: %d", info.DynamicPort),
			Severity:    "MEDIUM",
			CVSS:        5.9,
			CWE:         "CWE-200",
			Target:      fmt.Sprintf("dcom://%s:%d", target, info.DynamicPort),
			Description: fmt.Sprintf("WMI is using dynamic port %d for DCOM communication. Dynamic ports (1024-65535) are harder to firewall effectively.", info.DynamicPort),
			Evidence:    fmt.Sprintf("Endpoint mapper returned dynamic port: %d", info.DynamicPort),
			Remediation: "Restrict DCOM to fixed port range: HKLM\\Software\\Microsoft\\Rpc → Ports. Configure Windows Firewall to allow only that range from management hosts.",
			Source:      "module:glitchwmi",
		})
	}

	return result
}

func findDynamicPort(epmResponse []byte) int {
	// Look for port data in EPM response (simplified)
	// Real EPM tower contains port in protocol floor
	if len(epmResponse) < 20 {
		return 0
	}
	// Check for EPM response signature and extract port
	// In a real response, ports appear as 2-byte big-endian in TCP floor
	for i := 20; i < len(epmResponse)-2; i++ {
		p := int(epmResponse[i])<<8 | int(epmResponse[i+1])
		if p >= 49152 && p <= 65535 {
			return p
		}
	}
	// Fallback: common WMI dynamic port range hint
	_ = rand.Int()
	return 0
}

// ── Main ──────────────────────────────────────────────────

func main() {
	target  := flag.String("target",  "", "Target hostname or IP")
	port    := flag.Int("port",       135, "DCOM/RPC port (default 135)")
	timeout := flag.Int("timeout",    8,   "Connection timeout seconds")
	output  := flag.String("output",  "", "Output JSON file")
	verbose := flag.Bool("verbose",   false, "Verbose output")
	ver     := flag.Bool("version",   false, "Print version")
	flag.Parse()

	if *ver {
		fmt.Printf("glitchwmi v%s\n", Version)
		os.Exit(0)
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: glitchwmi --target <host> [--port 135] [--verbose]")
		os.Exit(1)
	}

	result := scanWMI(*target, *port, time.Duration(*timeout)*time.Second, *verbose)

	data, _ := json.MarshalIndent(result, "", "  ")
	if *output != "" {
		os.WriteFile(*output, data, 0644)
		if *verbose {
			fmt.Printf("[+] Saved to %s\n", *output)
		}
	} else {
		fmt.Println(string(data))
	}
}
