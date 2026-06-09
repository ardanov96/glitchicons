<div align="center">

```
  ╔══════════════════════════════════════╗
  ║   ⬡  G L I T C H I C O N S         ║
  ║   Offensive Security Platform        ║
  ╚══════════════════════════════════════╝
```

**From recon to boardroom-ready report — powered by AI.**

[![Python](https://img.shields.io/badge/Python-3.12+-blue?style=flat-square)](https://python.org)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square)](https://golang.org)
[![Tests](https://img.shields.io/badge/Tests-1757%20passed-30D158?style=flat-square)](#)
[![Binaries](https://img.shields.io/badge/Go%20Binaries-37-64D2FF?style=flat-square)](#go-binaries)
[![Version](https://img.shields.io/badge/Version-v5.5.0-A855F7?style=flat-square)](#changelog)
[![License](https://img.shields.io/badge/License-MIT-white?style=flat-square)](LICENSE)

[Quick Start](#quick-start) · [Python Modules](#python-modules) · [Go Binaries](#go-binaries) · [Roadmap](#roadmap) · [Contributing](CONTRIBUTING.md)

</div>

---

## What is Glitchicons?

Glitchicons is a modular offensive security platform for professional penetration testers, red teams, and security engineers.

It combines a Python intelligence and orchestration layer with 37 high-performance Go binaries — covering the full engagement lifecycle from passive recon to AI-written client reports.

```
Recon → Exploit → Verify → Enrich → Report → Track → Remediate
  ↑                                                         |
  └──────────── AI feedback loop ───────────────────────────┘
```

---

## At a Glance

| Dimension | Status |
|-----------|--------|
| Python test suite | **1,757 tests · 0 failures** |
| Go binaries | **37 compiled across 4 tiers** |
| Protocols covered | Web, SMB, SSH, RDP, LDAP, SNMP, FTP, VNC, Kerberos, QUIC, MQTT, Modbus, CoAP |
| LLM providers | Ollama (local) · Anthropic · OpenAI · Groq |
| Cloud coverage | AWS · Azure · GCP · CIS Benchmark |
| Report formats | HTML · Markdown · SARIF · PDF-ready |
| CI/CD integrations | GitHub · GitLab · DefectDojo · Jira · Slack |
| Compliance frameworks | OWASP Top 10 2021 · PCI DSS v4.0 · ISO 27001:2022 · CIS Benchmarks |

---

## Quick Start

```bash
git clone https://github.com/ardanov96/glitchicons.git
cd glitchicons

python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -q --tb=short
# 1757 passed, 0 failures
```

---

## Python Modules

### Web & API Security

| Module | Description |
|--------|-------------|
| GraphQL Fuzzer | Introspection, batch attacks, field suggestion abuse |
| WebSocket Fuzzer | Framing attacks, message mutation, auth bypass |
| gRPC Fuzzer | Reflection-based enumeration, method fuzzing |
| CORS Checker | Origin validation, credential exposure |
| OpenAPI Parser | Endpoint extraction, parameter analysis |
| WAF Evasion | 30+ bypass techniques |
| JWT Analyzer | Algorithm confusion, key confusion, none alg |
| MFA Bypass | OTP brute, backup code enum, flow bypass |

### Intelligence & Enrichment

| Module | Description |
|--------|-------------|
| Threat Intelligence | CVE/EPSS lookup, Shodan recon, CT discovery |
| LLM Intelligence v2 | Framework detection, nuclei template generation |
| LLM Mutator | LLM-driven payload mutation loop |
| FP Reducer | LLM-verified finding validation |

### Platform & Reporting

| Module | Description |
|--------|-------------|
| AI Reporter | LLM-written exec summary, finding narratives, remediation roadmap |
| Compliance | OWASP Top 10 · PCI DSS v4.0 · ISO 27001 · CIS mapping |
| HTML Reporter | Dark-themed interactive HTML dashboard |
| CI/CD Native | SARIF export, GitHub Check Runs, GitLab DAST, DefectDojo |
| Database | SQLAlchemy ORM — Target, Scan, Finding persistence |
| Scheduler | APScheduler recurring scan jobs |
| Webhooks | HMAC-signed event delivery |
| Collaboration | Finding assignment, SLA tracking, audit log |
| Cloud Native v2 | AWS IAM / Terraform / Azure AD / GCP IAM analysis |

---

## Go Binaries

37 high-performance Go binaries across 4 tiers. Each accepts `--target`, `--output`, `--verbose`, `--version`.

### Tier 1 — Foundation (v1.x)

| Binary | Protocol | Description |
|--------|----------|-------------|
| `glitchrace` | HTTP | Race condition detection (nanosecond precision) |
| `glitchscan` | TCP | Port scanner (10k+ ports/sec) |
| `glitchfuzz` | HTTP | High-throughput HTTP fuzzer |
| `glitchfuzz2` | HTTP | Mutation fuzzer — body/header/cookie/path/json |
| `glitchdns` | DNS | DNS brute force (100k+ queries/sec) |
| `glitchtls` | TLS | Certificate analysis, cipher audit |
| `glitchproxy` | HTTP | Intercepting proxy with finding injection |

### Tier 2 — Protocol Depth (v2.x–v3.x)

| Binary | Protocol | Description |
|--------|----------|-------------|
| `glitchsmb` | SMB | SMBv2/v3 negotiate, signing, null session, pass-the-hash |
| `glitchssh` | SSH | Algorithm audit, auth enum, default cred test (x/crypto) |
| `glitchrdp` | RDP | NLA enforcement, TLS analysis |
| `glitchldap` | LDAP | Authenticated AD enum — users/SPNs/groups/policy |
| `glitchsnmp` | SNMP/UDP | Community string brute force |
| `glitchftp` | FTP | Anonymous login, default creds |
| `glitchvnc` | VNC/RFB | No-auth detection, version fingerprint |
| `glitchwmi` | DCOM/RPC | OXID resolver, WMI interface detection |

### Tier 3 — Offensive Operations (v4.x)

| Binary | Category | Description |
|--------|----------|-------------|
| `glitchagent` | Infrastructure | HTTP scan daemon — job queue, worker pool, webhook |
| `glitchd` | Infrastructure | Unified binary dispatcher API (:7332) |
| `glitchbrute` | Credentials | Unified attacker — SSH/FTP/HTTP/LDAP/form, rate limiter |
| `glitchkerberos` | Active Directory | User enum, AS-REP roasting → hashcat, password spray |
| `glitchdesync` | HTTP | Request smuggling — CL.TE/TE.CL/TE.TE/h2c (raw TCP) |
| `glitchhttp2` | HTTP/2 | Rapid Reset, HPACK, h2c, Server Push |
| `glitchrelay` | Network | NTLM relay + HTTP capture → hashcat -m 5600 |
| `glitchids` | Evasion | IDS/IPS effectiveness tester — 5 techniques |
| `glitchexploit` | CVE | 9 CVE verifiers — Log4Shell/Zerologon/BlueKeep/CitrixBleed/PAN-OS/more |
| `glitchpcap` | Passive Intel | JA3 fingerprinting (no libpcap), HTTP capture, DNS anomaly |
| `glitchwatcher` | Monitoring | Asset change detection — cert/port/content/headers + webhook |
| `glitchfuzz3` | Fuzzing | Coverage-guided — corpus, grammar, OpenAPI seed, 6 mutations |
| `glitchquic` | QUIC/HTTP3 | Version negotiation, 0-RTT, Alt-Svc, amplification |
| `glitchimplant` | Red Team | Authorized post-access agent (HMAC engagement token) |
| `glitchpivot` | Red Team | SOCKS5 proxy, TCP forwarder, reverse tunnel |

### Tier 4 — Elite Assessment (v5.x)

| Binary | Category | Description |
|--------|----------|-------------|
| `glitchevade` | WAF Testing | WAF coverage tester — encoding/case/whitespace bypass variants |
| `glitchcloak` | Detection | MITRE ATT&CK detection coverage simulator (6 techniques) |
| `glitchsupply` | Supply Chain | Dependency confusion, typosquatting, integrity — npm/pip/go |
| `glitchcloud` | Cloud | AWS/Azure/GCP misconfiguration scanner (15 CIS controls) |
| `glitchiot` | IoT/ICS | Device fingerprint, Telnet/MQTT/CoAP/Modbus/UPnP, CIDR scan |
| `glitchai` | AI-Assisted | triage/payload/recon/summary/chat — Ollama/Groq/Anthropic/OpenAI |
| `glitchorchestrator` | Distributed | Multi-node scan coordinator, dashboard :7330, MD5 dedup |

---

## Key Capabilities

### AI-Assisted Security Testing (Free)

```bash
# Install Ollama (local, free, no account)
# https://ollama.com/download
ollama pull llama3.2
ollama serve

# Triage findings with AI
glitchai triage --findings findings.json

# Generate context-aware payloads
glitchai payload --target https://app.corp.com --headers headers.txt

# Write executive summary
glitchai summary --findings all.json --engagement "Corp Q4 2025"

# Interactive assistant
glitchai chat --findings findings.json

# Or use Groq (free cloud, email signup only)
# https://console.groq.com
set GROQ_API_KEY=gsk_xxx
glitchai triage --findings findings.json --provider groq
```

### Distributed Scanning

```bash
# Start glitchagent on each node (port 7331)
glitchagent --port 7331 --bin-dir ./bin

# Configure orchestrator
glitchorchestrator init --output plan.json

# Run distributed scan plan
glitchorchestrator run --config plan.json --output findings.json

# Live dashboard
glitchorchestrator serve --config plan.json --port 7330
# http://localhost:7330
```

### Active Directory

```bash
# User enumeration (no credentials)
glitchkerberos enum --dc dc.corp.local --domain corp.local --users users.txt

# AS-REP roasting → hashcat format
glitchkerberos asrep --dc dc.corp.local --domain corp.local --users users.txt
# hashcat -m 18200 hashes.txt rockyou.txt

# Full AD dump (authenticated)
glitchldap --target dc.corp.local --user admin@corp.local --pass P@ss --all
```

### CVE Verification

```bash
# Verify 9 critical CVEs — non-destructive
glitchexploit --target https://app.corp.com --cve all --verbose
glitchexploit --target dc.corp.local --cve zerologon
glitchexploit --list
```

### Cloud Security Posture

```bash
# Read-only scan of your own cloud environment
export AWS_ACCESS_KEY_ID=xxx AWS_SECRET_ACCESS_KEY=yyy
glitchcloud --cloud aws --region ap-southeast-1 --output cloud_findings.json
# Checks: S3 public access, SG 0.0.0.0/0, IAM root MFA, CloudTrail, RDS
```

### IoT Network Scan

```bash
# Scan entire subnet for IoT devices
glitchiot --target 192.168.1.0/24 --protocol all --verbose
# Checks: Telnet default creds, MQTT anonymous, Modbus unauthenticated, CoAP, UPnP
```

### WAF Coverage Testing

```bash
# Find gaps in your WAF rule coverage
glitchevade --target https://waf.corp.com --category all --param q
# Tests: URL encoding, hex, mixed case, tab injection, SQL comments
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     Python Layer                             │
│  Intelligence · Orchestration · LLM · Reporting             │
│  Cloud · CI/CD · Auth · Business Logic · Platform           │
├──────────────────────────────────────────────────────────────┤
│                  Go Layer (37 binaries · 4 tiers)           │
│  T1: Network Speed    T3: Offensive Ops                      │
│  T2: Protocol Depth   T4: Elite Assessment                   │
├──────────────────────────────────────────────────────────────┤
│                  Integration Layer                           │
│  GitHub · GitLab · Jira · Slack · DefectDojo                │
│  SARIF · CIS · OWASP · PCI DSS · ISO 27001                  │
├──────────────────────────────────────────────────────────────┤
│              Distributed Layer (v5.5)                       │
│  glitchorchestrator → glitchagent nodes → Go binaries       │
└──────────────────────────────────────────────────────────────╝
```

---

## Roadmap — All Complete ✅

| Tier | Versions | Binaries | Status |
|------|----------|----------|--------|
| Python Foundation | v0.7–v3.5 | — | ✅ Complete |
| Go Offensive Tier | v4.0–v4.9 | 30 | ✅ Complete |
| Elite Assessment | v5.0–v5.5 | 7 | ✅ Complete |

### v5.x Elite Tier — Complete

| Version | Module | Highlights |
|---------|--------|------------|
| v5.0 | glitchevade + glitchcloak | WAF bypass coverage · MITRE ATT&CK SIEM simulator |
| v5.1 | glitchsupply | Dependency confusion · typosquatting · npm/pip/go |
| v5.2 | glitchcloud | AWS SigV4 from scratch · 15 CIS controls · Azure · GCP |
| v5.3 | glitchiot | 24 device signatures · MQTT/Modbus/CoAP/UPnP · CIDR scan |
| v5.4 | glitchai | Ollama/Groq/Anthropic/OpenAI · triage/payload/recon/summary/chat |
| v5.5 | glitchorchestrator | Multi-node distributed scan · dashboard · MD5 dedup |

---

## Ethical Use

Glitchicons is built for **authorized security testing only**.

You are responsible for ensuring you have explicit written permission before running any scan, test, or assessment against any system. Unauthorized use is illegal.

Tools requiring explicit authorization: `glitchimplant` (signed engagement token), `glitchcloud` (requires your own cloud credentials), all credential testing tools.

The maintainers are not responsible for misuse.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup guide, PR requirements, module templates, and Go binary contribution guide.

**Ranks:** RECRUIT → OPERATIVE → COMMANDER → WARLORD

---

<div align="center">

Built by [ardanov96](https://github.com/ardanov96) · MIT License

*Where others probe, we siege. — ARDATRON*

</div>
