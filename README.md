# GLITCHICONS ⬡

### Decepticons Siege Division — AI-Powered Security Research Platform

[![Status](https://img.shields.io/badge/status-stable-brightgreen?style=flat-square)](https://github.com/ardanov96/glitchicons)
[![Version](https://img.shields.io/badge/version-1.3.0-purple?style=flat-square)](https://github.com/ardanov96/glitchicons/releases)
[![PyPI](https://img.shields.io/badge/pip%20install-glitchicons-blueviolet?style=flat-square)](https://pypi.org/project/glitchicons)
[![License](https://img.shields.io/badge/license-MIT-blueviolet?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-purple?style=flat-square)](https://python.org)
[![Go](https://img.shields.io/badge/go-1.22%2B-cyan?style=flat-square)](https://go.dev)
[![CI](https://img.shields.io/github/actions/workflow/status/ardanov96/glitchicons/ci.yml?style=flat-square&label=CI)](https://github.com/ardanov96/glitchicons/actions)
[![Tests](https://img.shields.io/badge/tests-748%20passed-green?style=flat-square)](https://github.com/ardanov96/glitchicons/tree/main/tests)
[![Stars](https://img.shields.io/github/stars/ardanov96/glitchicons?style=flat-square&color=blueviolet)](https://github.com/ardanov96/glitchicons/stargazers)

> *Where others probe, we siege. Where others test, we break.*

---

## What is Glitchicons?

Glitchicons is an open-source **AI-powered security research platform** — a self-improving adaptive attacker that reads targets, evolves payloads, verifies findings, explains risk, bypasses WAFs, and integrates with your entire security workflow.

**748 Python tests. 6 Go binaries. 0 failures. pip install ready.**

```
Static scanner:    fixed payloads → fire → hope → manual report
Glitchicons 1.3:   read spec → build attack plan → probe →
                   LLM evolves payload → WAF bypass → confirm →
                   FP filter → CVSS explain → Jira ticket →
                   Slack alert → Burp export → SARIF upload →
                   port scan → DNS enum → TLS audit → proxy intercept
```

---

## Install

```bash
pip install glitchicons
pip install "glitchicons[grpc]"      # + gRPC fuzzer
pip install "glitchicons[websocket]" # + WebSocket fuzzer
pip install "glitchicons[all]"       # everything

glitchicons status   # check environment
```

### Go Binaries

```bash
# Build from source (Go 1.22+ required)
cd glitchrace && go build -o ../bin/glitchrace . && cd ..
cd glitchscan && go build -o ../bin/glitchscan . && cd ..
cd glitchfuzz && go build -o ../bin/glitchfuzz . && cd ..
cd glitchdns  && go build -o ../bin/glitchdns  . && cd ..
cd glitchtls  && go build -o ../bin/glitchtls  . && cd ..
cd glitchproxy && go build -o ../bin/glitchproxy . && cd ..
```

---

## Architecture

```
Target: Web App / API / Binary / Network / Protocol
                        ↓
 ┌──────────────────────────────────────────────────────────┐
 │                INTELLIGENCE LAYER                         │
 │   LLM Mutation · FP Reducer · CVSS Reason · WAF Evade    │
 └──────────────────────┬───────────────────────────────────┘
                        ↓
 ┌──────────────────────────────────────────────────────────┐
 │              PYTHON ATTACK SURFACE                        │
 │  OpenAPI · gRPC · GraphQL · WebSocket · CORS             │
 │  MFA · JWT · OAuth · XSS · SQLi · SSRF · SSTI            │
 │  IDOR · Race Condition · Subdomain Takeover              │
 └──────────────────────┬───────────────────────────────────┘
                        ↓
 ┌──────────────────────────────────────────────────────────┐
 │                GO BINARY LAYER                            │
 │  glitchrace  glitchscan  glitchfuzz                      │
 │  glitchdns   glitchtls   glitchproxy                     │
 └──────────────────────┬───────────────────────────────────┘
                        ↓
 ┌──────────────────────────────────────────────────────────┐
 │              STABLE PLATFORM                              │
 │  PyPI · Plugin System · Integrations · Go Arch           │
 └──────────────────────┬───────────────────────────────────┘
                        ↓
      Burp XML · Slack · Discord · Jira · SARIF · HTML Report
```

---

## Modules

### Python — 748 Tests

| Version | Module | Tests | Description |
|---|---|---|---|
| **v0.7.0** | GraphQL Fuzzer | 24 | 7 attacks: introspect, batch, alias, nested DoS |
| **v0.7.0** | WebSocket Fuzzer | 35 | 8 attacks: origin bypass, injection, replay |
| **v0.7.0** | CORS Checker | 39 | 9 checks, CVSS scoring, auto-dedup |
| **v0.7.0** | HTML Report | 31 | Self-contained dark theme dashboard |
| **v0.7.0** | Config System | 29 | YAML siege mode, env var interpolation |
| **v0.8.0** | OpenAPI Parser | 55 | Swagger 2.0 + OpenAPI 3.x auto attack plan |
| **v0.8.0** | gRPC Fuzzer | 49 | Reflection, injection, pure Python proto encoder |
| **v0.8.0** | Subdomain Takeover | 40 | 25+ cloud fingerprints, dead NS detection |
| **v0.8.0** | MFA Bypass | 55 | 10 techniques: OTP brute, skip, type juggling |
| **v0.9.0** | LLM Mutation Loop | 54 | Adaptive payload evolution, 3 LLM providers |
| **v0.9.0** | False Positive Reducer | 47 | 4-step pipeline, confidence 0.0–1.0 |
| **v0.9.0** | Severity Reasoning | 43 | Pure Python CVSS v3.1 + LLM narrative |
| **v0.9.0** | WAF Evasion Engine | 65 | 30+ techniques, 8 WAF fingerprints |
| **v1.0.0** | PyPI Package | 43 | `pip install glitchicons`, 15 CLI commands |
| **v1.0.0** | Integration Layer | 45 | Burp XML, Slack, Discord, Jira, SARIF 2.1.0 |
| **v1.0.0** | Go Integration Arch | 38 | Binary registry, runner, parser, health check |
| + others | JWT, OAuth, XSS, SQLi, SSRF, SSTI, XXE, IDOR, Race | — | Core web offensive modules |

### Go Binaries — 6 Tools

| Binary | Version | Description | Performance |
|---|---|---|---|
| **glitchrace** | 1.0.0 | Race condition exploiter — last-byte sync attack | 100x vs Python threads |
| **glitchscan** | 1.0.0 | Port + service scanner — banner grab, fingerprint | 10k+ ports/sec |
| **glitchfuzz** | 1.0.0 | HTTP fuzzer — dir, param, vhost modes | 50k+ req/sec |
| **glitchdns** | 1.0.0 | DNS brute force — wildcard detect, zone transfer | 100k+ queries/sec |
| **glitchtls** | 1.0.0 | TLS/SSL analyzer — cipher, cert, protocol, HSTS | new capability |
| **glitchproxy** | 1.0.0 | Intercepting HTTP/HTTPS proxy — MITM, logging | new capability |

---

## Quick Start

```bash
# Full engagement from config
glitchicons config init --domain target.com
glitchicons siege --config engagement.yaml

# Web offensive
glitchicons cors     https://target.com
glitchicons graphql  https://target.com/graphql
glitchicons openapi  --spec api.yaml --base-url https://api.target.com
glitchicons takeover --domain target.com
glitchicons mfa      --target https://target.com/auth/2fa
glitchicons grpc     --target grpc.target.com:443

# Intelligence
glitchicons mutate --url https://target.com/search --param q --payload "' OR '1'='1"
glitchicons verify --input ./findings/raw.json
glitchicons explain --input ./findings/raw.json --rescore
glitchicons evade "<script>alert(1)</script>" --waf Cloudflare --type xss

# Go tools
.\bin\glitchscan.exe  --target target.com --ports 1-1024
.\bin\glitchrace.exe  --target https://target.com/api/coupon --param code --value SAVE50
.\bin\glitchfuzz.exe  dir --url https://target.com
.\bin\glitchdns.exe   --domain target.com --mode brute --verbose
.\bin\glitchtls.exe   --target target.com --output text
.\bin\glitchproxy.exe --port 8080 --verbose
```

---

## Intelligence Layer

### LLM Mutation Loop
Turns Glitchicons from a static scanner into an adaptive attacker:

```
Round 1: "' OR '1'='1"            → 403 Forbidden
  LLM: "WAF detected. Try unicode encoding + comment injection."
Round 2: "%u0027/**/OR/**/1=1"    → 500 MySQL error
  LLM: "MySQL confirmed. Try time-based payload."
Round 3: "' AND SLEEP(3)--"       → 3.2s response → CONFIRMED
```

### False Positive Reducer
```
Input:   18 raw findings
Output:  CONFIRMED: 8 | LIKELY: 4 | UNCERTAIN: 3 | FP: 3

Pipeline: Static patterns → Fast path → LLM confidence → Re-probe
```

### Severity Reasoning
```python
reasoner = SeverityReasoner(provider="ollama")
enriched = reasoner.enrich_all(findings)
# Each finding gets:
#   cvss_vector, cvss_breakdown, narrative,
#   business_impact, executive_summary, remediation_priority
```

### WAF Evasion (30+ techniques)
```python
engine   = WAFEvasionEngine()
waf      = engine.fingerprint_waf(headers, body)  # "Cloudflare"
variants = engine.smart_bypass(payload, waf, "sqli")
engine.generate_wordlist(payloads, output_file="bypass.txt")
```

---

## Integrations

```python
from modules.integrations.integrations import (
    BurpExporter, SlackNotifier, DiscordNotifier,
    JiraIntegration, SARIFExporter,
)

# Burp Suite XML
BurpExporter().export(findings, "./burp.xml")

# Slack + Discord alerts
SlackNotifier(webhook_url=SLACK_URL).notify_critical(findings, "target.com")
DiscordNotifier(webhook_url=DISCORD_URL).notify_summary(findings, "target.com")

# Jira tickets
JiraIntegration(url=JIRA_URL, email=EMAIL, api_token=TOKEN) \
    .create_tickets(findings, project_key="SEC", min_severity="HIGH")

# GitHub Code Scanning
SARIFExporter().export(findings, "./results.sarif")
```

---

## Plugin System

```python
from glitchicons.plugin_system import GlitchiconPlugin, make_finding

class MyPlugin(GlitchiconPlugin):
    name = "my-check"
    version = "1.0.0"
    description = "Custom security check"
    tags = ["recon", "auth"]

    def run(self, target: str, **kwargs) -> list[dict]:
        return [make_finding(
            title="Found Something", severity="HIGH", cvss=7.5,
            cwe="CWE-200", description="...", evidence="...",
            remediation="...", target=target,
        )]

# Register in pyproject.toml:
# [project.entry-points."glitchicons.plugins"]
# my-check = "myplugin:MyPlugin"
```

---

## Proof of Concept

### Binary Fuzzing (AFL++)
```
Seeds generated : 60 (LLM-crafted JSON + HTTP + XML)
Runtime         : 5 minutes
Crashes found   : 726
CVSS            : 8.1 (HIGH)
```

### Live Web Engagement (B2B SaaS, 70K users)
```
Duration     : < 8 hours (unauthenticated)
Detection     : Zero — Tor routing, no WAF alerts triggered

CRITICAL (1) : No brute force protection (CVSS 9.1)
HIGH (4)     : Checkout webhook auth bypass, unauthenticated pricing API...
MEDIUM (7)   : Security headers, API key exposure, DMARC misconfiguration...
Total        : 12 findings
```

### glitchdns — Live Result
```
Target  : github.com
Words   : 81 subdomains
Found   : 13 in 1.2 seconds
Flagged : admin.github.com (MEDIUM — sensitive keyword)
```

### glitchtls — Live Result
```
Target  : github.com
TLS 1.3 : YES | TLS 1.2: YES | TLS 1.0/1.1: NO
Cipher  : TLS_AES_128_GCM_SHA256 (STRONG)
HSTS    : max-age=31536000 ✓
Cert    : 65 days remaining, ECDSA, Sectigo CA
Findings: 0 (github.com is well-configured)
```

---

## File Structure

```
glitchicons/
├── glitchicons/                  # PyPI package
│   ├── __init__.py               # Public API
│   ├── cli.py                    # 15 CLI commands
│   └── plugin_system.py          # Plugin ABC + Registry
│
├── modules/
│   ├── intelligence/             # v0.9.0
│   │   ├── llm_mutator.py
│   │   ├── fp_reducer.py
│   │   ├── severity_reasoner.py
│   │   └── waf_evasion.py
│   ├── integrations/             # v1.0.0
│   │   └── integrations.py
│   ├── go/                       # v1.0.0
│   │   └── go_runner.py
│   ├── auth/                     # mfa, jwt, oauth, session
│   ├── inject/                   # graphql, websocket, cors, grpc, xss...
│   ├── recon/                    # openapi, subdomain, recon engine
│   ├── config/                   # config loader, siege runner
│   ├── report/                   # html reporter
│   └── scanner/                  # nuclei wrapper
│
├── glitchrace/                   # v1.1.0 Go
├── glitchscan/                   # v1.1.0 Go
├── glitchfuzz/                   # v1.2.0 Go
├── glitchdns/                    # v1.2.0 Go
├── glitchtls/                    # v1.3.0 Go
├── glitchproxy/                  # v1.3.0 Go
│
├── bin/                          # Compiled binaries
├── tests/                        # 748 unit tests
└── pyproject.toml                # v1.0.0, PyPI ready
```

---

## Changelog

### v1.3.0 — Go Phase 3 (Final)
- ✅ **glitchtls** — TLS/SSL analyzer: cipher, cert, protocol, HSTS
- ✅ **glitchproxy** — Intercepting HTTP/HTTPS proxy with TLS MITM

### v1.2.0 — Go Phase 2
- ✅ **glitchfuzz** — HTTP directory/parameter/vhost fuzzer (50k+ req/sec)
- ✅ **glitchdns** — DNS brute force + zone transfer + wildcard detection

### v1.1.0 — Go Phase 1
- ✅ **glitchrace** — Race condition exploiter, last-byte sync, nanosecond precision
- ✅ **glitchscan** — Port + service scanner, banner grabbing, 10k+ ports/sec

### v1.0.0 — Stable Release
- ✅ PyPI package · Plugin system · Burp/Slack/Discord/Jira/SARIF · Go architecture

### v0.9.0 — Intelligence Layer
- ✅ LLM Mutation · FP Reducer · CVSS Reasoning · WAF Evasion — 209 tests

### v0.8.0 — API & Protocol
- ✅ OpenAPI · gRPC · Subdomain Takeover · MFA Bypass — 199 tests

### v0.7.0 — Foundation
- ✅ CI/CD · Docker · GraphQL · WebSocket · CORS · HTML Report — 209 tests

---

## Tech Stack

| Layer | Technology |
|---|---|
| Intelligence | Ollama + Qwen2.5-Coder (local) · Anthropic · OpenAI |
| Web Offensive | Python 3.10+ · httpx · Click · Rich |
| Go Binaries | Go 1.22 · goroutines · net/http · crypto/tls |
| CI/CD | GitHub Actions · Docker · ruff · bandit |
| Test Suite | pytest · 748 tests · 0 failures |
| DNS | dnspython · net.LookupHost |
| gRPC | grpcio · grpcio-reflection |
| Reporting | HTML · JSON · Markdown · Burp XML · SARIF 2.1.0 |
| Notifications | Slack Block Kit · Discord Embeds · Jira REST API v3 |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

Ranks: `RECRUIT` → `OPERATIVE` → `COMMANDER` → `WARLORD`

- 🐛 [Issues](https://github.com/ardanov96/glitchicons/issues)
- 💡 [Discussions](https://github.com/ardanov96/glitchicons/discussions)
- 📦 Build a plugin: implement `GlitchiconPlugin` + publish to PyPI as `glitchicons-<name>`

---

## Professional Services

→ **[glitchicons.io](https://ardanov96.github.io/GTCN/)** · ardanov96@gmail.com

---

## License

MIT License © 2026 GLITCHICONS

---

> *As MEGATRON forged the Constructicons from raw Cybertronian steel —*
> *ARDATRON forged GLITCHICONS from code, chaos, and conviction.*
> *Not to construct. To expose.*
