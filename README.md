# GLITCHICONS ⬡

### Decepticons Siege Division — AI-Powered Security Research Platform

[![Status](https://img.shields.io/badge/status-stable-brightgreen?style=flat-square)](https://github.com/ardanov96/glitchicons)
[![Version](https://img.shields.io/badge/version-2.0.0-purple?style=flat-square)](https://github.com/ardanov96/glitchicons/releases)
[![PyPI](https://img.shields.io/badge/pip%20install-glitchicons-blueviolet?style=flat-square)](https://pypi.org/project/glitchicons)
[![License](https://img.shields.io/badge/license-MIT-blueviolet?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-purple?style=flat-square)](https://python.org)
[![Go](https://img.shields.io/badge/go-1.22%2B-cyan?style=flat-square)](https://go.dev)
[![Tests](https://img.shields.io/badge/tests-1083%20passed-green?style=flat-square)](https://github.com/ardanov96/glitchicons/tree/main/tests)
[![CI](https://img.shields.io/github/actions/workflow/status/ardanov96/glitchicons/ci.yml?style=flat-square&label=CI)](https://github.com/ardanov96/glitchicons/actions)

> *Where others probe, we siege. Where others test, we break.*

---

## What is Glitchicons?

Glitchicons is an open-source **AI-powered security research platform** — a self-improving adaptive attacker that reads targets, evolves payloads, verifies findings, explains risk, bypasses WAFs, and integrates with your entire security workflow.

**1083 tests. 6 Go binaries. 0 failures. pip install ready.**

```
Static scanner:    fixed payloads → fire → hope → manual report
Glitchicons 2.0:   multi-target → parallel scan → LLM evolves payload →
                   WAF bypass → cloud audit → auth bypass (SAML/PKCE/SSO) →
                   FP filter → CVSS explain → PDF + HTML dashboard →
                   Jira ticket → Slack alert → Burp → SARIF →
                   real-time web dashboard → remediation tracker
```

---

## Install

```bash
pip install glitchicons
pip install "glitchicons[all]"       # + gRPC + WebSocket
pip install fastapi uvicorn          # + Web Dashboard

glitchicons status
glitchicons dashboard                # Start web UI at localhost:8888
```

### Go Binaries

```bash
cd glitchrace  && go build -o ../bin/glitchrace  . && cd ..
cd glitchscan  && go build -o ../bin/glitchscan  . && cd ..
cd glitchfuzz  && go build -o ../bin/glitchfuzz  . && cd ..
cd glitchdns   && go build -o ../bin/glitchdns   . && cd ..
cd glitchtls   && go build -o ../bin/glitchtls   . && cd ..
cd glitchproxy && go build -o ../bin/glitchproxy . && cd ..
```

---

## Quick Start

```bash
# Web Dashboard (new in v2.0.0)
glitchicons dashboard --port 8888
# Open browser: http://localhost:8888

# Multi-target scan (new in v2.0.0)
glitchicons siege --targets targets.txt --concurrency 3

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

# Intelligence layer
glitchicons mutate --url https://target.com/search --param q --payload "' OR '1'='1"
glitchicons verify --input ./findings/raw.json
glitchicons explain --input ./findings/raw.json --rescore
glitchicons evade "<script>alert(1)</script>" --waf Cloudflare

# Go binaries
.\bin\glitchrace.exe  --target https://target.com/api/coupon --param code --value SAVE50
.\bin\glitchscan.exe  --target target.com --ports 1-1024
.\bin\glitchfuzz.exe  dir --url https://target.com
.\bin\glitchdns.exe   --domain target.com --mode brute --verbose
.\bin\glitchtls.exe   --target target.com --output text
.\bin\glitchproxy.exe --port 8080 --verbose
```

---

## Module Overview

### Python — 1083 Tests

| Version | Module | Tests | Description |
|---|---|---|---|
| **v0.7.0** | GraphQL + WebSocket + CORS | 94 | 7+8+9 attack checks |
| **v0.7.0** | HTML Report + Config | 60 | Dark theme dashboard, YAML siege |
| **v0.8.0** | OpenAPI Parser | 55 | Swagger 2.0 + OpenAPI 3.x auto attack plan |
| **v0.8.0** | gRPC Fuzzer | 49 | Reflection, proto encoder, metadata escalation |
| **v0.8.0** | Subdomain Takeover | 40 | 25+ cloud fingerprints, dead NS |
| **v0.8.0** | MFA Bypass | 55 | 10 techniques including race condition |
| **v0.9.0** | LLM Mutation Loop | 54 | Adaptive payload evolution, 3 LLM providers |
| **v0.9.0** | False Positive Reducer | 47 | 4-step pipeline, confidence 0.0–1.0 |
| **v0.9.0** | Severity Reasoning | 43 | Pure Python CVSS v3.1 + LLM narrative |
| **v0.9.0** | WAF Evasion Engine | 65 | 30+ techniques, 8 WAF fingerprints |
| **v1.0.0** | PyPI + Plugin System | 43 | pip install, ABC plugin, PluginRegistry |
| **v1.0.0** | Integration Layer | 45 | Burp XML, Slack, Discord, Jira, SARIF 2.1.0 |
| **v1.0.0** | Go Integration Arch | 38 | Binary registry, runner, parser |
| **v1.5.0** | Cloud Security | 55 | S3, Azure Blob, GCP, IMDS metadata, CloudFront |
| **v1.6.0** | PDF Reporter | 18 | reportlab, cover + exec summary + per-finding |
| **v1.6.0** | Executive Dashboard | 15 | Self-contained HTML + Chart.js |
| **v1.6.0** | Remediation Tracker | 25 | Persistent JSON, 6 statuses, due dates |
| **v1.7.0** | GraphQL Subscription | 12 | Auth bypass, DoS, sensitive data leakage |
| **v1.7.0** | WebSocket Advanced | 13 | Binary frames, prototype pollution, auth bypass |
| **v1.7.0** | REST Parameter Pollution | 25 | HPP, mass assignment, type juggling, verb tamper |
| **v1.8.0** | SAML Bypass | 15 | XXE, unsigned, XSW, replay, NameID, role |
| **v1.8.0** | PKCE Bypass | 15 | Downgrade, optional, invalid method, CSRF |
| **v1.8.0** | SSO Tester | 18 | redirect_uri, discovery, logout, alg confusion |
| **v1.8.0** | API Key Auditor | 20 | Exposure, entropy, URL, scope (10 patterns) |
| **v1.9.0** | Async Engine | 30 | Token bucket, retry, cache, batch_get |
| **v1.9.0** | Scan Orchestrator | 35 | Priority, concurrency, dedup, timeout |
| **v2.0.0** | Multi-Target Orchestrator | 20 | Concurrent, tag filter, aggregation |
| **v2.0.0** | Web Dashboard | 19 | FastAPI, SSE, history, demo mode |
| + inject | XSS, SQLi, SSRF, SSTI, XXE, JWT, OAuth, IDOR, Race | — | Core web offensive |

### Go Binaries — 6 Tools

| Binary | Description | Performance |
|---|---|---|
| **glitchrace** | Race condition — last-byte sync, ns precision | 100x vs Python |
| **glitchscan** | Port scanner — banner grab, service fingerprint | 10k+ ports/sec |
| **glitchfuzz** | HTTP fuzzer — dir, param, vhost | 50k+ req/sec |
| **glitchdns** | DNS brute — wildcard detect, AXFR | 100k+ queries/sec |
| **glitchtls** | TLS analyzer — cipher, cert, HSTS | new capability |
| **glitchproxy** | Intercepting proxy — MITM, JSON log | new capability |

---

## Web Dashboard (v2.0.0)

```python
from modules.dashboard.dashboard import GlitchiconsDashboard
from modules.inject.cors_checker import CORSChecker
from modules.inject.graphql_fuzzer import GraphQLFuzzer

def my_scan(target, modules):
    findings = []
    if "cors" in modules:
        findings += CORSChecker(target=target).run()
    if "graphql" in modules:
        findings += GraphQLFuzzer(target=target).run()
    return findings

dash = GlitchiconsDashboard(port=8888, scan_fn=my_scan)
dash.run()
# → http://localhost:8888
```

---

## Multi-Target Scan (v2.0.0)

```python
import asyncio
from modules.core.multi_target import MultiTargetOrchestrator, Target
from modules.inject.cors_checker import CORSChecker

async def scan():
    mto = MultiTargetOrchestrator(concurrency=3)

    mto.add_targets_from_list([
        "https://target1.com",
        "https://target2.com",
        "https://target3.com",
    ], tags=["fintech"])

    mto.register_module(
        "cors",
        lambda url, **kw: CORSChecker(target=url, **kw).run(),
        timeout=60,
    )

    results = await mto.run(tags=["fintech"])
    mto.print_summary()
    # JSON report auto-saved to ./findings/multi/

asyncio.run(scan())
```

---

## Intelligence Layer

```python
from glitchicons import LLMMutator, FalsePositiveReducer, SeverityReasoner, WAFEvasionEngine

# Adaptive mutation
mutator = LLMMutator(provider="ollama", model="qwen2.5-coder:3b")
result  = mutator.mutate_and_test(
    target_url="https://target.com/search",
    param="q", base_payload="' OR '1'='1",
    attack_type="sqli", max_rounds=5,
)
# Round 1: ' OR '1'='1 → 403
# Round 2: %27/**/OR/**/1=1 → 500 MySQL
# Round 3: ' AND SLEEP(3)-- → 3.2s ✓ CONFIRMED

# FP reduction
verified = FalsePositiveReducer(provider="ollama").verify_all(raw_findings)

# CVSS + narrative
enriched = SeverityReasoner(provider="ollama", rescore=True).enrich_all(verified)

# WAF evasion
waf  = WAFEvasionEngine().fingerprint_waf(headers, body)  # "Cloudflare"
variants = WAFEvasionEngine().smart_bypass(payload, waf_type=waf)
```

---

## Cloud Security (v1.5.0)

```python
from modules.cloud.cloud_security import CloudSecurityScanner

scanner = CloudSecurityScanner(
    target="target.com",
    check_metadata=True,  # Also test IMDS endpoints
)
findings = scanner.run()
# Checks: S3 buckets, Azure Blob, GCP Storage, CloudFront, IMDS SSRF
```

---

## Auth Expansion (v1.8.0)

```python
from modules.auth.auth_expansion import (
    SAMLBypassTester, PKCEBypassTester, SSOTester, APIKeyAuditor
)

# SAML: XXE, unsigned assertion, signature wrapping, replay
SAMLBypassTester(target="https://sso.target.com/saml/acs").run()

# PKCE: downgrade, optional, invalid method, state CSRF
PKCEBypassTester(
    auth_endpoint="https://target.com/oauth/authorize",
    token_endpoint="https://target.com/oauth/token",
    client_id="app123",
).run()

# API Key: entropy, exposure, URL logging, scope
APIKeyAuditor(target="https://target.com", api_key=api_key).run()
```

---

## Performance Layer (v1.9.0)

```python
import asyncio
from modules.core.async_engine import AsyncEngine, RetryConfig
from modules.core.scan_orchestrator import ScanOrchestrator, ScanModule

async def fast_scan():
    # Async HTTP with rate limiting + retry
    async with AsyncEngine(rate_limit=100, concurrency=50,
                           retry_config=RetryConfig(max_retries=3)) as engine:
        responses = await engine.batch_get(url_list)

    # Concurrent module orchestration
    orch = ScanOrchestrator(target="https://target.com", concurrency=4)
    orch.add_module(ScanModule("cors",    cors_fn,    priority=1, timeout=60))
    orch.add_module(ScanModule("graphql", graphql_fn, priority=2, timeout=120))
    orch.add_module(ScanModule("cloud",   cloud_fn,   priority=3, timeout=180))
    results = await orch.run()
    orch.print_summary(results)
```

---

## Integrations

```python
from modules.integrations.integrations import (
    BurpExporter, SlackNotifier, JiraIntegration, SARIFExporter
)
from modules.report.pdf_reporter import PDFReporter
from modules.report.executive_dashboard import ExecutiveDashboard
from modules.report.remediation_tracker import RemediationTracker

# Export
BurpExporter().export(findings, "./burp.xml")
SARIFExporter().export(findings, "./results.sarif")

# Notify
SlackNotifier(webhook_url=SLACK_URL).notify_critical(findings, "target.com")
JiraIntegration(url=JIRA_URL, email=EMAIL, api_token=TOKEN) \
    .create_tickets(findings, project_key="SEC", min_severity="HIGH")

# Report
PDFReporter(findings=findings, target="target.com").generate()
ExecutiveDashboard(findings=findings, target="target.com").generate()

# Track remediation
tracker = RemediationTracker("engagement_2026", findings=findings)
tracker.load_or_init()
tracker.update("FIND-001", status="IN_PROGRESS", assignee="dev@target.com", due_days=7)
tracker.mark_fixed("FIND-002", note="Deployed in v2.4.1")
tracker.print_summary()
```

---

## Changelog

### v2.0.0 — Major Release
- ✅ **Web Dashboard** — FastAPI + SSE, real-time finding stream, scan history
- ✅ **Multi-Target Orchestrator** — concurrent scanning, tag filtering, aggregation

### v1.9.0 — Performance Layer
- ✅ **AsyncEngine** — token bucket rate limiter, exponential backoff, response cache
- ✅ **ScanOrchestrator** — priority groups, concurrency, finding deduplication

### v1.8.0 — Auth Expansion
- ✅ **SAML Bypass** — XXE, unsigned, signature wrapping, replay, NameID
- ✅ **PKCE Bypass** — downgrade, optional, invalid method, state CSRF
- ✅ **SSO Tester** — redirect_uri bypass, OIDC discovery, alg=none
- ✅ **API Key Auditor** — entropy check, 10 exposure patterns

### v1.7.0 — API Security Expansion
- ✅ **GraphQL Subscription** — auth bypass, DoS, sensitive data leakage
- ✅ **WebSocket Advanced** — binary frames, prototype pollution, auth bypass
- ✅ **REST Parameter Pollution** — HPP, mass assignment, type juggling, verb tamper

### v1.6.0 — Advanced Reporting
- ✅ **PDF Reporter** — cover page, exec summary, per-finding (reportlab)
- ✅ **Executive Dashboard** — HTML + Chart.js, expandable cards
- ✅ **Remediation Tracker** — 6 statuses, due dates, assignee, persistence

### v1.5.0 — Cloud Security
- ✅ **S3/Azure/GCP** — public bucket/container detection, wildcard
- ✅ **Cloud Metadata** — IMDS (AWS/Azure/GCP/DO), SSRF probe
- ✅ **CloudFront** — S3 origin bypass, missing security headers

### v1.4.0 — CI/CD + Docker
- ✅ GitHub Actions: Python tests (3 OS × 3 versions) + Go build (6 × 3 platforms)
- ✅ Multi-stage Dockerfile: go-builder + py-deps + runtime + Ollama

### v1.3.0 → v1.1.0 — Go Binaries
- ✅ glitchtls, glitchproxy, glitchfuzz, glitchdns, glitchrace, glitchscan

### v1.0.0 — Stable Release
- ✅ PyPI packaging · Plugin system · Burp/Slack/Discord/Jira/SARIF

### v0.9.0 → v0.7.0 — Foundation + Intelligence
- ✅ 648 tests across GraphQL, WebSocket, CORS, OpenAPI, gRPC, MFA, LLM, WAF, CVSS

---

## File Structure

```
glitchicons/
├── glitchicons/              # PyPI package v2.0.0
│   ├── __init__.py           # Public API, __version__ = "2.0.0"
│   ├── cli.py                # 15+ CLI commands
│   └── plugin_system.py      # GlitchiconPlugin ABC + Registry
├── modules/
│   ├── intelligence/         # LLM Mutation, FP Reducer, CVSS, WAF
│   ├── inject/               # GraphQL, WebSocket, CORS, gRPC, XSS, SQLi...
│   │   └── api_security.py   # GraphQL Sub, WebSocket Advanced, REST HPP
│   ├── auth/                 # MFA, JWT, OAuth, SAML, PKCE, SSO, APIKey
│   ├── recon/                # OpenAPI, Subdomain Takeover, Recon Engine
│   ├── cloud/                # S3, Azure, GCP, IMDS, CloudFront
│   ├── report/               # HTML, PDF, Executive Dashboard, Remediation
│   ├── integrations/         # Burp, Slack, Discord, Jira, SARIF
│   ├── core/                 # AsyncEngine, Orchestrator, MultiTarget
│   ├── dashboard/            # Web Dashboard (FastAPI + SSE)
│   ├── config/               # Config loader, Siege runner
│   └── go/                   # Go binary runner + registry
├── glitchrace/               # Go: race condition exploiter
├── glitchscan/               # Go: port + service scanner
├── glitchfuzz/               # Go: HTTP fuzzer
├── glitchdns/                # Go: DNS brute forcer
├── glitchtls/                # Go: TLS/SSL analyzer
├── glitchproxy/              # Go: intercepting proxy
├── bin/                      # Compiled Go binaries
├── tests/                    # 1083 unit tests
└── pyproject.toml            # v2.0.0, PyPI ready
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Intelligence | Ollama + Qwen2.5-Coder · Anthropic Claude API · OpenAI |
| Web Offensive | Python 3.10+ · httpx · asyncio · Click · Rich |
| Go Binaries | Go 1.22 · goroutines · crypto/tls · net/http |
| Web Dashboard | FastAPI · uvicorn · SSE · Chart.js |
| CI/CD | GitHub Actions · Docker multi-stage · ruff · bandit |
| Reporting | HTML · PDF (reportlab) · Burp XML · SARIF 2.1.0 |
| Notifications | Slack Block Kit · Discord Embeds · Jira REST API v3 |
| Test Suite | pytest · 1083 tests · 0 failures |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

Ranks: `RECRUIT` → `OPERATIVE` → `COMMANDER` → `WARLORD`

Build a plugin:
```python
from glitchicons.plugin_system import GlitchiconPlugin, make_finding

class MyPlugin(GlitchiconPlugin):
    name = "my-check"
    version = "1.0.0"
    tags = ["recon", "auth"]

    def run(self, target: str, **kwargs) -> list[dict]:
        return [make_finding(title="Found", severity="HIGH", cvss=7.5,
                             cwe="CWE-200", description="...", evidence="...",
                             remediation="...", target=target)]

# pyproject.toml:
# [project.entry-points."glitchicons.plugins"]
# my-check = "myplugin:MyPlugin"
```

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
