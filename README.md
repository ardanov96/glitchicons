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
[![Binaries](https://img.shields.io/badge/Go%20Binaries-34-64D2FF?style=flat-square)](#go-binaries)
[![Version](https://img.shields.io/badge/Version-v5.2.0-A855F7?style=flat-square)](#changelog)
[![License](https://img.shields.io/badge/License-MIT-white?style=flat-square)](LICENSE)

[Quick Start](#quick-start) · [Python Modules](#python-modules) · [Go Binaries](#go-binaries) · [Roadmap](#roadmap) · [Contributing](CONTRIBUTING.md)

</div>

---

## What is Glitchicons?

Glitchicons is a modular offensive security platform for professional penetration testers, red teams, and security engineers.

It combines a Python intelligence and orchestration layer with 34 high-performance Go binaries — covering the full engagement lifecycle from passive recon to AI-written client reports.

```
Recon → Exploit → Verify → Enrich → Report → Track → Remediate
  ↑                                                         |
  └──────────── AI feedback loop ───────────────────────────┘
```

**Not another scanner.** Glitchicons is an orchestration platform. It connects tools, enriches findings with threat intelligence, adapts payloads using LLMs, tracks remediation progress, and generates reports that go directly to clients.

---

## At a Glance

| Dimension | Status |
|-----------|--------|
| Python test suite | **1,757 tests · 0 failures** |
| Go binaries | **34 compiled** |
| Protocols covered | Web, SMB, SSH, RDP, LDAP, SNMP, FTP, VNC, Kerberos, QUIC |
| LLM providers | Anthropic Claude · OpenAI · Ollama (local) |
| Cloud coverage | AWS · Azure · GCP · Kubernetes · Terraform |
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

34 high-performance Go binaries. Each accepts `--target`, `--output`, `--verbose`, `--version`.

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
| `glitchsmb` | SMB | SMBv2/v3 negotiate, signing audit, null session, pass-the-hash |
| `glitchssh` | SSH | Algorithm audit, auth method enum, default cred test |
| `glitchrdp` | RDP | NLA enforcement, TLS analysis |
| `glitchldap` | LDAP | Authenticated AD enumeration, SPN/user/group dump |
| `glitchsnmp` | SNMP/UDP | Community string brute force |
| `glitchftp` | FTP | Anonymous login, default creds |
| `glitchvnc` | VNC/RFB | No-auth detection, version fingerprint |

### Tier 3 — Offensive Operations (v4.x)

| Binary | Category | Description |
|--------|----------|-------------|
| `glitchagent` | Infrastructure | HTTP scan daemon — job queue, worker pool, webhook |
| `glitchd` | Infrastructure | Unified binary dispatcher API |
| `glitchbrute` | Credentials | Unified credential attacker — SSH/FTP/HTTP/LDAP/form |
| `glitchwmi` | Windows | DCOM/RPC, OXID resolver, WMI interface detection |
| `glitchkerberos` | Active Directory | User enum, AS-REP roasting, password spray |
| `glitchdesync` | HTTP | Request smuggling — CL.TE/TE.CL/TE.TE/h2c |
| `glitchhttp2` | HTTP/2 | Rapid Reset, HPACK, h2c, Server Push |
| `glitchrelay` | Network | NTLM relay + HTTP capture (hashcat -m 5600) |
| `glitchids` | Evasion | IDS/IPS effectiveness tester — 5 techniques |
| `glitchexploit` | CVE | 9 CVE verifiers — Log4Shell/Spring4Shell/Zerologon/BlueKeep/CitrixBleed/PAN-OS/H2Reset/DirtyPipe/BaronSamedit |
| `glitchpcap` | Passive Intel | JA3 fingerprinting, HTTP capture, DNS anomaly detection |
| `glitchwatcher` | Monitoring | Asset change detection daemon — cert/port/content/headers |
| `glitchfuzz3` | Fuzzing | Coverage-guided fuzzer — corpus, grammar, OpenAPI seed |
| `glitchquic` | QUIC/HTTP3 | Version negotiation, 0-RTT, Alt-Svc, amplification |
| `glitchimplant` | Red Team | Authorized post-access agent (engagement token required) |
| `glitchpivot` | Red Team | SOCKS5 proxy, TCP forwarder, reverse tunnel |

### Tier 4 — Elite Assessment (v5.x)

| Binary | Category | Description |
|--------|----------|-------------|
| `glitchevade` | WAF Testing | WAF bypass coverage — encoding/case/whitespace variants |
| `glitchcloak` | Detection | MITRE ATT&CK detection coverage simulator |
| `glitchsupply` | Supply Chain | Dependency confusion, typosquatting, integrity checks |
| `glitchcloud` | Cloud | AWS/Azure/GCP misconfiguration scanner (CIS Benchmark) |

---

## Key Capabilities

### AI Report Generation

```python
from modules.report.ai_reporter import PentestReportGenerator

gen = PentestReportGenerator(provider="anthropic", api_key="sk-ant-...")
report = gen.generate(
    findings=findings_list,
    target="https://target.com",
    engagement_name="Target Corp — Web Application Pentest Q4 2025",
)
# Dark-themed HTML + Markdown with exec summary, per-finding narratives,
# remediation roadmap, and compliance mapping
```

### CVE Verification

```bash
# Verify 9 critical CVEs — does not exploit, only confirms vulnerability
glitchexploit --target https://app.corp.com --cve all
glitchexploit --target dc.corp.local --cve zerologon
glitchexploit --list  # show all supported CVEs with CVSS scores
```

### WAF Coverage Testing

```bash
# Find gaps in your WAF rule coverage
glitchevade --target https://waf.corp.com --category all --param q
# Tests: URL encoding, hex encoding, mixed case, tab injection, SQL comments
```

### Cloud Security Posture

```bash
# Read-only scan of your own cloud environment
export AWS_ACCESS_KEY_ID=xxx AWS_SECRET_ACCESS_KEY=yyy
glitchcloud --cloud aws --region us-east-1 --output findings.json
# Checks: S3 public access, SG 0.0.0.0/0, IAM root MFA, CloudTrail, RDS
```

### Supply Chain Security

```bash
# Scan your dependency tree for supply chain risks
glitchsupply --path . --ecosystem all --output supply_findings.json
# Checks: dependency confusion, typosquatting, suspicious packages, go.sum
```

### Asset Monitoring

```bash
# Generate config, then watch your assets for changes
glitchwatcher init --output watch.json
glitchwatcher --config watch.json --state state.json --interval 30m
# Detects: HTTP status change, cert expiry, new ports, content change
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     Python Layer                             │
│  Intelligence · Orchestration · LLM · Reporting             │
│  Cloud · CI/CD · Auth · Business Logic · Platform           │
├──────────────────────────────────────────────────────────────┤
│                      Go Layer (34 binaries)                  │
│  Tier 1: Network Speed    Tier 3: Offensive Operations       │
│  Tier 2: Protocol Depth   Tier 4: Elite Assessment           │
├──────────────────────────────────────────────────────────────┤
│               Integration Layer                              │
│  GitHub · GitLab · Jira · Slack · DefectDojo                │
│  SARIF · CIS · OWASP · PCI DSS · ISO 27001                  │
└──────────────────────────────────────────────────────────────┘
```

---

## Roadmap

### Completed

| Tier | Versions | Status |
|------|----------|--------|
| Foundation | v0.7–v3.5 | ✅ Complete — Python platform peak |
| Go Offensive Tier | v4.0–v4.9 | ✅ Complete — 30 binaries |
| Elite Assessment | v5.0–v5.2 | ✅ In progress — 4 more binaries |

### In Progress — v5.x Elite Tier

| Version | Focus | Status |
|---------|-------|--------|
| v5.0 | Advanced Evasion Testing | ✅ glitchevade + glitchcloak |
| v5.1 | Supply Chain Security | ✅ glitchsupply |
| v5.2 | Cloud Security Posture | ✅ glitchcloud |
| v5.3 | IoT/Embedded Security | 🔶 Planned |
| v5.4 | AI-Assisted Security Testing | 🔶 Planned |
| v5.5 | Distributed Orchestrator | 🔶 Planned |

---

## Ethical Use

Glitchicons is built for **authorized security testing only**.

You are responsible for ensuring you have explicit written permission before running any scan, test, or assessment against any system. Unauthorized use is illegal and strictly against the intended purpose of this project.

Tools requiring authorization include `glitchimplant` (signed engagement token with HMAC-SHA256 verification), `glitchcloud` (requires your own cloud credentials), and all credential testing tools.

The maintainers are not responsible for misuse.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup guide, PR requirements, module templates, and Go binary contribution guide.

---

<div align="center">

Built by [ardanov96](https://github.com/ardanov96) · MIT License

*Where others probe, we siege. — ARDATRON*

</div>
