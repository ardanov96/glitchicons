# Changelog

All notable changes to Glitchicons are documented here.

Format: `[Version] — Release Name — Date`

---

## [v5.5.0] — Distributed Orchestrator — Jun 2026

### Added
- `glitchorchestrator` — central controller for multi-node distributed scanning
  - Commands: `serve` / `run` / `status` / `report` / `init`
  - Round-robin job distribution across glitchagent nodes
  - MD5 deduplication: hash(title+target+severity) prevents duplicate findings
  - Dark-themed HTTP dashboard at `:7330` with 10s auto-refresh
  - Graceful fallback when nodes go offline
  - `--ai-triage` flag: auto-pipes findings to `glitchai` after scan completes
  - Verified: 12 jobs (3 targets × 4 binaries), 7 findings aggregated

### Go Binaries
- Total: **37** (was 36)

---

## [v5.4.0] — AI-Assisted Security Testing — Jun 2026

### Added
- `glitchai` — multi-provider AI security engine (stdlib only, no SDK)
  - Providers: **Ollama** (local, free, no account) · **Groq** (free cloud, email only) · Anthropic · OpenAI
  - Mode `triage`: rank findings by exploitability, detect attack chains, 30-min attack plan
  - Mode `payload`: context-aware payloads from app fingerprint (not generic wordlists)
  - Mode `recon`: synthesize scan data into attack surface map + next actions
  - Mode `summary`: LLM-written executive summary for client reports
  - Mode `chat`: interactive multi-turn AI security assistant with findings context
  - Verified working: llama3.2 via Ollama local

### Go Binaries
- Total: **36** (was 35)

---

## [v5.3.0] — IoT/Embedded Security — Jun 2026

### Added
- `glitchiot` — IoT/ICS device scanner with protocol coverage
  - 24 device signatures: Cisco, MikroTik, Hikvision, Dahua, Siemens, Synology, QNAP, HP, Axis, more
  - Protocol checks: Telnet (banner + default creds), MQTT (anonymous CONNECT probe), CoAP (UDP resource discovery), Modbus TCP (unauthenticated register read), UPnP SSDP (device discovery + XML parse)
  - HTTP default credential check (5 generic IoT pairs)
  - Risk scoring 0–100 per device (Telnet=+30, Modbus=+35, CVE=+15)
  - CIDR expansion for full subnet scanning
  - CVE mapping per identified device signature
  - Concurrent scanning with goroutine pool (`--threads`)

### Go Binaries
- Total: **35** (was 34)

---

## [v5.2.0] — Cloud Security Posture — Jun 2026

### Added
- `glitchcloud` — cloud misconfiguration scanner (stdlib only, no SDK)
  - AWS SigV4 signing implemented from scratch (no aws-sdk-go)
  - 15 CIS Benchmark controls across AWS / Azure / GCP
  - AWS checks: S3 public access (CIS 2.1.5), EC2 0.0.0.0/0 SGs (CIS 4.1/4.2), IAM root MFA (CIS 1.5), IAM root access keys (CIS 1.4), IAM password policy (CIS 1.8–1.11), RDS publicly accessible (CIS 2.3.2), CloudTrail disabled (CIS 3.1)
  - Azure checks: storage anonymous blob access (CIS Azure 3.7), NSG any/any rules (CIS Azure 6.2)
  - GCP checks: allUsers ACL (CIS GCP 5.1), primitive roles Owner/Editor (CIS GCP 1.4)
  - Read-only — requires own cloud credentials

### Go Binaries
- Total: **34** (was 33)

---

## [v5.1.0] — Supply Chain Security — Jun 2026

### Added
- `glitchsupply` — dependency supply chain scanner
  - Dependency confusion: checks if internal package names exist on public registries (CRITICAL if found)
  - Typosquatting: 4 pattern checks (char substitution, insertion, omission, hyphen swap) against 44 popular npm/pip packages
  - Suspicious name patterns: `-test`, `-debug`, `-dev`, common malicious suffixes
  - go.sum integrity: HIGH finding if go.sum missing alongside go.mod
  - Ecosystems: npm (`package.json`), pip (`requirements.txt`), go (`go.mod`)
  - Live registry verification: npm registry API + PyPI API

### Go Binaries
- Total: **33** (was 32)

---

## [v5.0.0] — Advanced Evasion Testing — Jun 2026

### Added — v5.x Elite Assessment Tier begins

- `glitchevade` — WAF coverage effectiveness tester
  - For each payload type (SQLi/XSS/SSTI/traversal/cmd): raw → encoded variants
  - Evasion categories: URL encoding, double-URL, hex, HTML entities, unicode, mixed case, tab whitespace, SQL comments
  - Gap detection: variant passes when baseline was blocked = WAF config gap
  - Rate-limited (100ms) — safe for production WAF testing
  - HIGH finding per bypass variant discovered

- `glitchcloak` — SIEM/IDS detection coverage tester
  - 6 MITRE ATT&CK technique simulations:
    - T1595 Active Scanning, T1046 Service Discovery
    - T1110 Brute Force, T1110.003 Password Spray
    - T1048.003 DNS Exfiltration, T1087 Account Discovery
  - `--webhook` flag for SIEM correlation testing
  - Post-run: check your SIEM for which techniques generated alerts

### Go Binaries
- Total: **32** (was 30)

---

## [v4.9.0] — Red Team Agent — Jun 2026

### Added — v4.x Go Offensive Tier complete

- `glitchimplant` — authorized post-access agent
  - HMAC-SHA256 engagement token required (gen-token subcommand)
  - Token format: `base64(json_payload).base64(hmac_sig)` — verifies signature + scope + expiry
  - Operations: `discover` (credential file search), `env` (sensitive env extraction), `scan` (internal network), `procs` (process enumeration)
  - Credential patterns: `.env`, `id_rsa`, `*.pem`, `*.pfx`, `*.key`, `service-account*.json`
  - HTTPS beacon to `glitchagent :7331/agent/report`
  - Self-destruct on token expiry (`--self-delete`)

- `glitchpivot` — network pivoting daemon
  - Mode `socks5`: full RFC 1928 SOCKS5 proxy (IPv4/domain/IPv6, bidirectional relay)
  - Mode `forward`: TCP port forwarder with concurrent connections
  - Mode `reverse`: auto-reconnect reverse tunnel (target → attacker)
  - Mode `dns-tunnel`: hex-encoded data as DNS subdomain queries

### Go Binaries
- Total: **30** (was 28)

---

## [v4.8.0] — Fuzzing v3 + QUIC — Jun 2026

### Added
- `glitchfuzz3` — coverage-guided HTTP fuzzer (major upgrade over glitchfuzz2)
  - Corpus Manager: JSON persistence, MD5 dedup, load/save from directory
  - Grammar Engine: JSON template expansion (`{{sqli}}` `{{xss}}` `{{ssti}}` `{{traversal}}`)
  - OpenAPI seeding: parse paths + parameters from OpenAPI spec
  - 6 mutation strategies: BitFlip, Boundary, SQLi, XSS, SSTI, Traversal, TypeChange
  - Response clustering: status + size bucket (±100 bytes)
  - Time-based detection: response 5x+ baseline = interesting
  - Baseline measurement before fuzzing starts

- `glitchquic` — QUIC/HTTP3 attack surface analyzer
  - QUIC Version Negotiation: send fake version (0x0a0a0a0a), parse VN response
  - Supported version extraction from VN packet
  - Amplification factor measurement
  - Alt-Svc h3 detection via HTTP/1.1 response header
  - 0-RTT capability detection via TLS session resumption
  - HTTP header injection test (X-Forwarded-Host bypass)

### Go Binaries
- Total: **28** (was 26)

---

## [v4.7.0] — Passive Intelligence — Jun 2026

### Added
- `glitchpcap` — passive network capture (no gopacket/libpcap dependency)
  - Mode `ja3`: raw TLS ClientHello parsing, GREASE skip, JA3 MD5 hash, SNI extraction, 12 known tool fingerprints (curl/Metasploit/CobaltStrike)
  - Mode `http`: credential extraction proxy, 16 regex patterns
  - Mode `dns`: UDP port 53, DGA entropy detection, beaconing analysis, DNS tunneling indicators

- `glitchwatcher` — continuous asset monitoring daemon
  - 7 change detection types: status code, content hash, TLS cert fingerprint, cert expiry, new open port, new header, header removed
  - Webhook notifications on change
  - JSON state persistence between runs
  - `--once` flag for CI/CD pipeline integration
  - `init` subcommand generates sample config

### Go Binaries
- Total: **26** (was 24)

---

## [v4.6.0] — CVE Exploit Verifier — Jun 2026

### Added
- `glitchexploit` — 9 CVE verifiers (verify-not-exploit philosophy)
  - Log4Shell (CVE-2021-44228, CVSS 10.0): JNDI payload in 5 headers, timing detection
  - Spring4Shell (CVE-2022-22965, CVSS 9.8): classLoader probe
  - Zerologon (CVE-2020-1472, CVSS 10.0): SMB2 negotiate + dialect check
  - BlueKeep (CVE-2019-0708, CVSS 9.8): RDP TPKT + X.224 + NLA negotiation
  - CitrixBleed (CVE-2023-4966, CVSS 9.4): Range header + session token detection
  - PAN-OS (CVE-2024-3400, CVSS 10.0): GlobalProtect SESSID path traversal
  - H2Reset (CVE-2023-44487, CVSS 7.5): server version fingerprint
  - DirtyPipe (CVE-2022-0847, CVSS 7.8): SSH banner kernel version
  - BaronSamedit (CVE-2021-3156, CVSS 7.8): SSH banner OS detection
  - `--list` flag, confidence levels: high/medium/low/unknown

### Go Binaries
- Total: **24** (was 22)

---

## [v4.5.0] — Network Attack Engine — Jun 2026

### Added
- `glitchrelay` — NTLM relay + capture
  - HTTP NTLM challenge-response server (Type1→Type2→Type3 flow)
  - NTLMv2 hash extraction → hashcat `-m 5600` format
  - HTTP→SMB relay framework
  - `buildNTLMChallenge`, `decodeUTF16LE` pure Go implementation

- `glitchids` — IDS/IPS evasion effectiveness tester
  - 5 techniques: slow, rotate, jitter, fragment, decoy, all
  - 12 User-Agent pool, 5 header rotation sets, random X-Forwarded-For
  - Fragment mode: TCP chunked delivery (`--chunk` bytes)
  - Evasion rate calculation: (blocked_normal - blocked_evaded) / blocked_normal

### Go Binaries
- Total: **22** (was 20)

---

## [v4.4.0] — HTTP Deep Attack Layer — Jun 2026

### Added
- `glitchdesync` — HTTP request smuggling detector
  - Raw `net.Conn` HTTP (bypasses Go's stdlib header normalization)
  - CL.TE timing detection (>4s + 3× size ratio = CRITICAL 9.8)
  - TE.CL timing detection
  - TE.TE 6 obfuscation variants (tab/space/x-chunked/identity/chunk-ext)
  - h2c cleartext upgrade detection

- `glitchhttp2` — HTTP/2 attack surface
  - TLS ALPN negotiation detection
  - h2c cleartext upgrade (MEDIUM 6.5)
  - Rapid Reset CVE-2023-44487 capability check
  - Server Push via `Link: rel=preload` header
  - HPACK large header exhaustion (LOW 3.7)
  - Pseudo-header routing bypass

### Go Binaries
- Total: **20** (was 18)

---

## [v4.3.0] — Active Directory Attack Suite — Jun 2026

### Added
- `glitchkerberos` — Kerberos attack suite (pure Go, no Impacket)
  - 3 modes: `enum` / `asrep` / `spray`
  - Pure Go DER/ASN.1 encoding for AS-REQ packets
  - KDC error code parsing (6=not exist, 18=disabled, 25=pre-auth required, 37=expired)
  - AS-REP cipher extraction → hashcat `$krb5asrep$23` format
  - Password spray with lockout awareness (200ms/attempt)
  - UDP port 88

### Changed
- `glitchldap` — major upgrade
  - `go-ldap/v3` dependency
  - `--dump-users`: UAC analysis (noPreauth, pwdNeverExpires)
  - `--spns`: Kerberoastable service account enumeration
  - `--admins`: 10 privileged group membership check
  - `--policy`: password lockout policy extraction

### Go Binaries
- Total: **18** (was 16)

---

## [v4.2.0] — SMB/Windows Depth — Jun 2026

### Added
- `glitchsmb` — major upgrade to SMBv2/v3
  - SMBv2/v3 negotiate (dialects 2.0.2 through 3.1.1)
  - Signing enforcement audit (relay risk assessment)
  - Null session probe
  - Named pipe enumeration (`\srvsvc` `\samr` `\lsarpc`)
  - Pass-the-hash: NTLM Type1→Challenge→Type3 flow, `--hash LM:NT` flag

- `glitchwmi` — WMI/DCOM attack surface
  - DCOM/RPC port 135 probe
  - DCE/RPC bind packets
  - OXID resolver probe
  - IWbemServices interface detection
  - Dynamic WMI port detection

### Go Binaries
- Total: **16** (was 14)

---

## [v4.1.0] — Credential Attack Engine — Jun 2026

### Added
- `glitchbrute` — unified credential attacker
  - 5 protocols: SSH (`x/crypto`), FTP (raw TCP), HTTP Basic, HTTP Form (success/fail string), LDAP (BER BindRequest)
  - Goroutine worker pool with configurable concurrency
  - Token bucket rate limiter
  - Lockout detector: backoff after N consecutive failures
  - Combo file mode (`user:pass` format)
  - Built-in wordlists for quick testing

### Changed
- `glitchssh` — upgraded with `x/crypto/ssh`
  - Algorithm enumeration (KEX/cipher/MAC weakness detection)
  - Auth method enumeration
  - Host key type detection (ssh-rsa → MEDIUM finding)
  - OpenSSH CVE mapping (versions 6.x/7.x/8.x)
  - `--check-creds` flag

### Go Binaries
- Total: **14** (was 13)

---

## [v4.0.0] — Infrastructure Foundation — Jun 2026

### Added — Go Offensive Tier begins

- `glitchagent` — HTTP scan daemon
  - Goroutine worker pool (20 workers)
  - `POST /jobs` → `GET /jobs/:id/results` async pattern
  - Webhook on job completion
  - Graceful shutdown handling
  - Listens on `:7331`

- `glitchd` — unified binary dispatcher
  - Single API over all registered Go binaries
  - `GET /version` `/health` `/binaries` `/capabilities`
  - `POST /scan/:binary` — synchronous scan dispatch
  - Binary registry (14 → 36 in v5.5.0)
  - Listens on `:7332`

### Go Binaries
- Total: **13** (was 7, Tier 2 added in v2.x–v3.x)

---

## [v3.5.0] — Python Foundation Peak — 2025–2026

### Highlights (Python layer complete)
- AI Reporter: LLM-written executive summaries (Anthropic · OpenAI · Ollama)
- Compliance mapper: OWASP Top 10 2021 · PCI DSS v4.0 · ISO 27001:2022 · CIS Benchmarks
- CI/CD integrations: SARIF · GitHub Check Runs · GitLab DAST · DefectDojo · Jira
- Cloud Native v2: AWS IAM · Terraform · Azure AD · GCP IAM
- Collaboration: finding assignment, SLA tracking, audit log
- Plugin marketplace: PyPI-based community extensions
- Multi-target orchestrator with asyncio concurrency
- Full test suite: **1757 tests · 0 failures**

---

## [v3.x] — Protocol Tier II — 2025

### Added (Go Tier 2 — Protocol Depth)
- `glitchsmb` (v1) — SMB service detection
- `glitchssh` (v1) — SSH algorithm audit
- `glitchrdp` — RDP NLA enforcement check
- `glitchldap` (v1) — LDAP service probe
- `glitchsnmp` — SNMP community string brute
- `glitchftp` — FTP anonymous login
- `glitchvnc` — VNC no-auth detection

### Go Binaries
- Total: **13** (T1: 7, T2: 6)

---

## [v2.x] — Intelligence & Auth Expansion — 2025

### Highlights
- LLM Intelligence v2: framework detection, nuclei template generation
- LLM Mutator: adaptive payload mutation loop
- False Positive Reducer: 4-step LLM verification pipeline
- Threat Intelligence: CVE/EPSS, Shodan, Certificate Transparency
- Auth Expansion: SAML bypass, PKCE/SSO testing, JWT analysis, MFA bypass
- GraphQL advanced: subscription abuse, batch DoS
- WebSocket advanced: binary frames, prototype pollution

---

## [v1.x] — Go Foundation Tier + Core Platform — 2025

### Added (Go Tier 1 — Foundation)
- `glitchrace` — race condition detection (nanosecond precision)
- `glitchscan` — TCP port scanner (10k+ ports/sec)
- `glitchfuzz` — HTTP parameter fuzzer
- `glitchfuzz2` — mutation-based fuzzer
- `glitchdns` — DNS brute force (100k+ queries/sec)
- `glitchtls` — TLS/SSL certificate audit
- `glitchproxy` — intercepting proxy

### Python core
- Web attack modules: XSS, SQLi, SSRF, SSTI, XXE, CORS
- WAF Evasion: 30+ bypass techniques
- HTML Reporter: dark-themed interactive dashboard
- Database: SQLAlchemy ORM (Target/Scan/Finding)
- Webhooks: HMAC-signed event delivery
- Scheduler: APScheduler recurring scans

### Go Binaries
- Total: **7** (Tier 1 complete)

---

## [v0.7.0] — Initial Release — 2025

### Foundation
- Core scanning engine
- Basic injection detection (XSS, SQLi)
- First Python test suite
- MIT License

---

*For full commit history: `git log --oneline`*
*For binary changelog: each binary has `--version` flag*
