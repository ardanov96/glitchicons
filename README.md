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
[![Binaries](https://img.shields.io/badge/Go%20Binaries-14-64D2FF?style=flat-square)](#go-binaries)
[![Version](https://img.shields.io/badge/Version-v3.5.0%20PEAK-A855F7?style=flat-square)](#changelog)
[![License](https://img.shields.io/badge/License-MIT-white?style=flat-square)](LICENSE)

[Quick Start](#quick-start) · [Modules](#modules) · [Go Binaries](#go-binaries) · [Roadmap](#roadmap) · [Contributing](CONTRIBUTING.md)

</div>

---

## What is Glitchicons?

Glitchicons is a modular offensive security platform built for professional penetration testers, bug bounty researchers, and red teams.

It combines a Python-based intelligence and attack layer with Go high-performance network binaries — covering the full engagement lifecycle from passive recon to AI-written client reports.

**Not another scanner.** Glitchicons is an orchestration platform. It connects tools, enriches findings with threat intelligence, adapts payloads using LLMs, tracks remediation, and generates reports that go directly to clients.

```
Recon → Exploit → Verify → Enrich → Report → Track → Repeat
  ↑                                                       |
  └──────────── AI feedback loop ─────────────────────────┘
```

---

## At a Glance

| Dimension | Status |
|-----------|--------|
| Python test suite | **1,757 tests · 0 failures** |
| Go binaries | **14 compiled** |
| Supported protocols | Web, SMB, SSH, RDP, LDAP, SNMP, FTP, VNC |
| LLM providers | Anthropic Claude · OpenAI · Ollama (local) |
| Cloud coverage | AWS · Azure · GCP · Kubernetes · Terraform |
| Report formats | HTML · Markdown · SARIF · PDF-ready |
| CI/CD integrations | GitHub · GitLab · DefectDojo · Jira · Slack |
| Compliance frameworks | OWASP Top 10 2021 · PCI DSS v4.0 · ISO 27001:2022 |

---

## Quick Start

```bash
# Clone
git clone https://github.com/ardanov96/glitchicons.git
cd glitchicons

# Python environment
python3 -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .\.venv\Scripts\Activate.ps1     # Windows PowerShell

# Install
pip install -e ".[dev]"

# Verify
pytest tests/ -q --tb=short
# Expected: 1757 passed, 0 failures

# Build Go binaries (optional — all standard library)
cd glitchsmb && go build -ldflags="-s -w" -o ../bin/glitchsmb . && cd ..
# Repeat for: glitchssh glitchrdp glitchldap glitchsnmp glitchftp glitchvnc
# and: glitchrace glitchscan glitchfuzz glitchdns glitchtls glitchproxy glitchfuzz2
```

---

## Modules

### Web & API Security

| Module | Location | Description |
|--------|----------|-------------|
| GraphQL Fuzzer | `modules/inject/graphql_fuzzer.py` | Introspection, batch attacks, field suggestion abuse |
| WebSocket Fuzzer | `modules/inject/websocket_fuzzer.py` | Framing attacks, message mutation, auth bypass |
| gRPC Fuzzer | `modules/inject/grpc_fuzzer.py` | Reflection-based enumeration, method fuzzing |
| CORS Checker | `modules/inject/cors_checker.py` | Origin validation, credential exposure |
| OpenAPI Parser | `modules/recon/openapi_parser.py` | Endpoint extraction, parameter analysis |
| WAF Evasion | `modules/intelligence/waf_evasion.py` | 30+ bypass techniques |

### Authentication & Identity

| Module | Location | Description |
|--------|----------|-------------|
| Auth Expansion | `modules/auth/` | SAML XSW, PKCE downgrade, SSO bypass |
| JWT Analyzer | `modules/inject/jwt_analyzer.py` | Algorithm confusion, key confusion, none alg |
| MFA Bypass | `modules/auth/mfa_bypass.py` | OTP brute, backup code enum, flow bypass |

### Intelligence & Enrichment

| Module | Location | Description |
|--------|----------|-------------|
| Threat Intelligence | `modules/intelligence/threat_intel.py` | CVE/EPSS lookup, Shodan recon, CT discovery |
| LLM Intelligence v2 | `modules/intelligence/llm_intelligence_v2.py` | Framework detection, nuclei template generation, payload library |
| LLM Mutator | `modules/intelligence/llm_mutator.py` | LLM-driven payload mutation loop |
| FP Reducer | `modules/intelligence/fp_reducer.py` | LLM-verified finding validation |

### Cloud Security

| Module | Location | Description |
|--------|----------|-------------|
| Cloud Security | `modules/cloud/cloud_security.py` | S3, Azure Blob, GCP Storage, CloudFront, IMDS SSRF |
| Cloud Native v2 | `modules/cloud/cloud_native_v2.py` | AWS IAM privesc paths, Terraform scanner, Azure AD audit, GCP IAM analysis |

### Mobile & CI/CD

| Module | Location | Description |
|--------|----------|-------------|
| Mobile API | `modules/mobile/mobile_api.py` | APK analysis, certificate pinning, mobile API attacks |
| CI/CD Security | `modules/cicd/cicd_security.py` | GitHub Actions audit, Dockerfile misconfig, K8s RBAC, secret scanning |

### Business Logic

| Module | Location | Description |
|--------|----------|-------------|
| Business Logic | `modules/business/business_logic.py` | Price manipulation, ATO chain, privilege escalation, workflow bypass |

### Platform

| Module | Location | Description |
|--------|----------|-------------|
| Database | `modules/core/database.py` | SQLAlchemy ORM — Target, Scan, Finding persistence |
| Scheduler | `modules/core/scheduler.py` | APScheduler-based recurring scan jobs |
| Webhooks | `modules/core/webhooks.py` | HMAC-signed event delivery (Slack, Teams, PagerDuty) |
| Collaboration | `modules/collab/collaboration.py` | Finding assignment, comments, SLA tracking, audit log |
| Plugin Marketplace | `modules/marketplace/plugin_marketplace.py` | Plugin registry, sandbox execution, community catalog |

### Reporting & Compliance

| Module | Location | Description |
|--------|----------|-------------|
| AI Reporter | `modules/report/ai_reporter.py` | LLM-written exec summary, finding narratives, remediation roadmap |
| Compliance | `modules/report/compliance.py` | OWASP Top 10 · PCI DSS v4.0 · ISO 27001 mapping |
| HTML Reporter | `modules/report/html_reporter.py` | Dark-themed interactive HTML dashboard |
| CI/CD Native | `modules/integrations/cicd_native.py` | SARIF export, GitHub Check Runs, GitLab DAST report, DefectDojo |

---

## Go Binaries

All Go binaries are in `bin/` after building. Each accepts `--target`, `--output`, `--verbose`, `--version`.

| Binary | Protocol | Key Capabilities |
|--------|----------|-----------------|
| `glitchrace` | HTTP | Race condition detection (nanosecond precision) |
| `glitchscan` | TCP | Port scanner (10k+ ports/sec) |
| `glitchfuzz` | HTTP | High-throughput HTTP fuzzer |
| `glitchfuzz2` | HTTP | Mutation fuzzer — body/header/cookie/path/json modes |
| `glitchdns` | DNS | DNS brute force (100k+ queries/sec) |
| `glitchtls` | TLS | Certificate analysis, cipher audit |
| `glitchproxy` | HTTP | Intercepting proxy with finding injection |
| `glitchsmb` | SMB | SMBv1 detection (EternalBlue), signing check |
| `glitchssh` | SSH | Algorithm audit — KEX/cipher/MAC weakness |
| `glitchrdp` | RDP | NLA enforcement, TLS cert analysis |
| `glitchldap` | LDAP | Anonymous bind, default credential test |
| `glitchsnmp` | SNMP | Community string brute force (20 defaults) |
| `glitchftp` | FTP | Anonymous login, default creds, cleartext detection |
| `glitchvnc` | VNC | No-auth detection, RFB version fingerprint |

```bash
# Quick usage examples
./bin/glitchsmb --target 192.168.1.10 --verbose
./bin/glitchssh --target ssh.target.com --output findings.json
./bin/glitchfuzz2 body --url https://api.target.com/search --data '{"q":"FUZZ"}'
./bin/glitchkerberos --target dc.corp.local --mode asrep  # coming in v4.3
```

---

## AI Report Generation

Generate a complete pentest report from findings in one command:

```python
from modules.report.ai_reporter import PentestReportGenerator

gen = PentestReportGenerator(
    provider="anthropic",              # or "openai" or "ollama"
    api_key="sk-ant-...",
    model="claude-3-5-haiku-20241022",
)

report = gen.generate(
    findings=findings_list,
    target="https://target.com",
    engagement_name="Target Corp — Web Application Pentest Q4 2025",
    tester="ardanov96",
    output_dir="./reports",
)

# Output: dark-themed HTML + Markdown with:
# - Executive summary (risk rating, key findings, next steps)
# - Per-finding: impact story, PoC steps, business risk, remediation
# - Remediation roadmap (P1/P2/P3 with effort + owner estimates)
```

Works offline without API key (template mode). With API key: full LLM-written narratives.

---

## Threat Intelligence

```python
from modules.intelligence.threat_intel import ThreatIntelScanner

scanner = ThreatIntelScanner(
    target="https://target.com",
    shodan_api_key="YOUR_KEY",   # optional
)

result = scanner.run(findings=existing_findings)
# Enriches findings with: CVE/EPSS scores, Shodan data, CT subdomains
```

---

## Compliance Mapping

```python
from modules.report.compliance import ComplianceReporter

reporter = ComplianceReporter(output_dir="./findings/compliance")
report   = reporter.generate(findings, target="target.com")

# Generates HTML + JSON compliance report:
# - OWASP Top 10 2021 (A01–A10 coverage)
# - PCI DSS v4.0 requirement mapping
# - ISO 27001:2022 Annex A control gaps
# - Overall compliance score (0–100)
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Python Layer                          │
│  Intelligence · Orchestration · LLM · Reporting         │
│  Cloud · CI/CD · Auth · Business Logic · Platform       │
├─────────────────────────────────────────────────────────┤
│                     Go Layer                            │
│  Network Speed · Protocol Depth · Binary Analysis       │
│  Race Conditions · High-concurrency · Static Binaries   │
├─────────────────────────────────────────────────────────┤
│              Integration Layer                          │
│  GitHub · GitLab · Jira · Slack · DefectDojo            │
│  SARIF · OWASP · PCI DSS · ISO 27001                   │
└─────────────────────────────────────────────────────────┘
```

---

## Roadmap

### Completed — v3.5.0 PEAK ✅

The original roadmap (v0.7.0–v3.5.0) is complete.

| Tier | Versions | Focus |
|------|----------|-------|
| Foundation | v0.7–v1.9 | Core modules, Go Phase 1 |
| Security Coverage | v2.0–v2.9 | Mobile, CI/CD, Threat Intel, LLM, Business Logic, Compliance |
| Platform | v3.0–v3.5 | Backend, Collaboration, CI/CD Native, Cloud v2, AI Reports |

### Next — v4.x Go Offensive Tier 🔶

| Version | Focus | Key Addition |
|---------|-------|-------------|
| v4.0 | Infrastructure | `glitchagent` daemon + `glitchd` gRPC |
| v4.1 | Credentials | `glitchbrute` — 10k attempts/sec, all protocols |
| v4.2 | SMB/Windows | `glitchsmb` upgrade + `glitchwmi` |
| v4.3 | Active Directory | `glitchkerberos` — AS-REP, Kerberoasting |
| v4.4 | HTTP Deep | `glitchdesync` + `glitchhttp2` |
| v4.5 | Network Attacks | `glitchrelay` (NTLM) + `glitchids` (evasion) |
| v4.6 | CVE Verification | `glitchexploit` — 9 critical CVEs |
| v4.7 | Passive Intel | `glitchpcap` + `glitchwatcher` |
| v4.8 | Fuzzing v3 | Coverage-guided + `glitchquic` (HTTP/3) |
| v4.9 | Red Team | `glitchimplant` + `glitchpivot` |

Go binaries: 14 → 29 · Go % of codebase: 7.8% → ~25%

### Long-term — v5.x Elite Tier 🔵

`v5.0` Advanced Evasion · `v5.1` Supply Chain · `v5.2` Cloud Attack Chains · `v5.3` IoT/ARM · `v5.4` AI Adaptation · `v5.5` Distributed Platform

Go binaries: 29 → 35+ · Go % of codebase: ~40%

---

## Installation Details

### Python Dependencies

```bash
pip install -e ".[dev]"

# Core: httpx rich sqlalchemy apscheduler
# Dev:  pytest ruff bandit
# Optional: fastapi uvicorn (web dashboard)
```

### Go Build (optional)

All Go binaries use standard library only — no `go mod download` needed for most.

```powershell
# Windows PowerShell
cd glitchsmb; go build -ldflags="-s -w" -o ..\bin\glitchsmb.exe .; cd ..
```

```bash
# Linux/macOS
cd glitchsmb && go build -ldflags="-s -w" -o ../bin/glitchsmb . && cd ..
```

### Database Setup (optional — for persistence)

```python
from modules.core.database import Database

# SQLite (development)
db = Database("sqlite:///glitchicons.db")
db.init()

# PostgreSQL (production)
db = Database("postgresql://user:pass@localhost/glitchicons")
db.init()
```

---

## Ethical Use

Glitchicons is built for **authorized security testing only**.

You are responsible for ensuring you have explicit written permission before running any scan or test against any system. Unauthorized use against systems you do not own or have written permission to test is illegal and strictly against the intended purpose of this project.

Go binaries like `glitchimplant` (coming in v4.9) require a signed engagement token and auto-expire — they cannot run without valid authorization proof.

The maintainers are not responsible for misuse.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup guide, PR requirements, module templates, and Go binary contribution guide.

**Contributor Ranks:**
```
RECRUIT    → First PR merged
OPERATIVE  → 5 PRs merged
COMMANDER  → 15 PRs merged + module ownership
WARLORD    → Core maintainer
```

---

## Security

Found a vulnerability in Glitchicons itself? See [SECURITY.md](SECURITY.md) for responsible disclosure.

Do not open public GitHub issues for security vulnerabilities.

---

<div align="center">

Built by [ardanov96](https://github.com/ardanov96) · MIT License

*Where others probe, we siege. — ARDATRON*

</div>
