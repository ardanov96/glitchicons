# GLITCHICONS ⬡

### Decepticons Siege Division — AI-Powered Security Research Platform

[![Status](https://img.shields.io/badge/status-stable-brightgreen?style=flat-square)](https://github.com/ardanov96/glitchicons)
[![Version](https://img.shields.io/badge/version-1.0.0-purple?style=flat-square)](https://github.com/ardanov96/glitchicons/releases)
[![PyPI](https://img.shields.io/badge/pip%20install-glitchicons-blueviolet?style=flat-square)](https://pypi.org/project/glitchicons)
[![License](https://img.shields.io/badge/license-MIT-blueviolet?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-purple?style=flat-square)](https://python.org)
[![CI](https://img.shields.io/github/actions/workflow/status/ardanov96/glitchicons/ci.yml?style=flat-square&label=CI)](https://github.com/ardanov96/glitchicons/actions)
[![Tests](https://img.shields.io/badge/tests-748%20passed-green?style=flat-square)](https://github.com/ardanov96/glitchicons/tree/main/tests)
[![Stars](https://img.shields.io/github/stars/ardanov96/glitchicons?style=flat-square&color=blueviolet)](https://github.com/ardanov96/glitchicons/stargazers)

> *Where others probe, we siege. Where others test, we break.*

---

## What is Glitchicons?

Glitchicons is an open-source **AI-powered security research platform** — a self-improving adaptive attacker that reads targets, evolves payloads, verifies findings, explains risk, and integrates with your security workflow.

```
Static scanner:    fixed payloads → fire → hope → manual report
Glitchicons 1.0:   read spec → build attack plan → probe → LLM evolves payload →
                   WAF bypass → confirm → FP filter → CVSS explain → Jira ticket →
                   Slack alert → Burp export → SARIF upload
```

**748 unit tests. 0 failures. pip install ready.**

---

## Install

```bash
pip install glitchicons

# With optional extras
pip install "glitchicons[grpc]"      # gRPC fuzzer
pip install "glitchicons[websocket]" # WebSocket fuzzer
pip install "glitchicons[all]"       # everything

# Verify
glitchicons status
```

---

## Quick Start

```bash
# Full engagement from config file
glitchicons config init --domain target.com
# edit engagement.yaml
glitchicons siege --config engagement.yaml

# Individual modules
glitchicons cors     https://target.com --token eyJ...
glitchicons graphql  https://target.com/graphql
glitchicons openapi  --spec api.yaml --base-url https://api.target.com
glitchicons takeover --domain target.com
glitchicons mfa      --target https://target.com/auth/2fa
glitchicons grpc     --target grpc.target.com:443

# Intelligence layer
glitchicons mutate --url https://target.com/search --param q --payload "' OR '1'='1"
glitchicons verify --input ./findings/raw.json
glitchicons explain --input ./findings/raw.json --rescore
glitchicons evade "<script>alert(1)</script>" --waf Cloudflare --type xss
```

---

## Architecture

```
Target (web / binary / API / protocol)
              ↓
 ┌────────────────────────────────────────────────────────┐
 │              INTELLIGENCE LAYER v0.9.0                 │
 │  LLM Mutation · FP Reducer · CVSS Reasoner · WAF Evade │
 └────────────────────┬───────────────────────────────────┘
                      ↓
 ┌────────────────────────────────────────────────────────┐
 │           ATTACK SURFACE v0.8.0 + v0.7.0               │
 │  OpenAPI · gRPC · Subdomain · MFA · GraphQL ·          │
 │  WebSocket · CORS · XSS · SQLi · SSRF · JWT · IDOR     │
 └────────────────────┬───────────────────────────────────┘
                      ↓
 ┌────────────────────────────────────────────────────────┐
 │              STABLE PLATFORM v1.0.0                    │
 │  PyPI install · Plugin system · Integrations           │
 │  Go binary interface (glitchrace, glitchscan, ...)     │
 └────────────────────┬───────────────────────────────────┘
                      ↓
      Burp XML · Slack · Discord · Jira · SARIF
```

---

## Development Status

### v1.0.0 — Stable Release ✅ (Current)

| Module | Tests | Description |
|---|---|---|
| **PyPI Packaging** | 43 | `pip install glitchicons`, CLI entry point, public API |
| **Plugin System** | — | `GlitchiconPlugin` ABC, `PluginRegistry`, `make_finding()` |
| **Integration Layer** | 45 | Burp XML, Slack, Discord, Jira REST API, SARIF 2.1.0 |
| **Go Integration Arch** | 38 | Registry, Runner, Parser, Locator, HealthChecker |
| **Total v1.0.0** | **126** | 0 failures |

### v0.9.0 — Intelligence Layer ✅

| Module | Tests | Description |
|---|---|---|
| LLM Mutation Loop | 54 | Adaptive payload evolution, 3 LLM providers |
| False Positive Reducer | 47 | 4-step pipeline, confidence scoring |
| Severity Reasoning | 43 | Pure Python CVSS v3.1, LLM narrative, exec summary |
| WAF Evasion Engine | 65 | 30+ techniques, 8 WAF fingerprints |

### v0.8.0 — API & Protocol Expansion ✅

| Module | Tests | Description |
|---|---|---|
| OpenAPI Parser | 55 | Swagger 2.0 + OpenAPI 3.x auto attack plan |
| gRPC Fuzzer | 49 | Reflection, injection, pure Python proto encoder |
| Subdomain Takeover | 40 | 25+ cloud/SaaS fingerprints, dead NS |
| MFA Bypass Tester | 55 | 10 bypass techniques |

### v0.7.0 — Foundation ✅ | v0.6.0 — Web Offensive ✅ | Core ✅

GraphQL · WebSocket · CORS · HTML Report · JWT · OAuth · XSS · SQLi · SSRF · SSTI · IDOR · Race · AFL++ · Crash Triage

---

## Python API

```python
from glitchicons import (
    # Web offensive
    GraphQLFuzzer, WebSocketFuzzer, CORSChecker, GRPCFuzzer,
    # Recon
    OpenAPIParser, SubdomainTakeoverChecker,
    # Auth
    MFABypassTester, OTPGenerator,
    # Intelligence
    LLMMutator, FalsePositiveReducer, SeverityReasoner, CVSSCalculator,
    WAFEvasionEngine,
    # Report
    HTMLReporter,
)

# Auto attack plan from OpenAPI spec
parser = OpenAPIParser(base_url="https://api.target.com")
plan   = parser.parse_file("swagger.json")
print(f"{plan.total_endpoints} endpoints, {len(plan.findings)} static findings")

# Adaptive LLM mutation
mutator = LLMMutator(provider="ollama", model="qwen2.5-coder:3b")
result  = mutator.mutate_and_test(
    target_url="https://target.com/search",
    param="q", base_payload="' OR '1'='1",
    attack_type="sqli", max_rounds=5,
)

# Verify + reduce false positives
reducer  = FalsePositiveReducer(provider="ollama")
verified = reducer.verify_all(raw_findings)

# CVSS reasoning + narrative
reasoner = SeverityReasoner(provider="ollama", rescore=True)
enriched = reasoner.enrich_all(verified)

# WAF bypass variants
engine   = WAFEvasionEngine()
waf_type = engine.fingerprint_waf(resp_headers, resp_body)
variants = engine.smart_bypass(payload, waf_type, "sqli")
```

---

## Plugin System

```python
# Create a plugin
from glitchicons.plugin_system import GlitchiconPlugin, make_finding

class MyPlugin(GlitchiconPlugin):
    name        = "my-custom-check"
    version     = "1.0.0"
    description = "Custom security check"
    tags        = ["recon", "auth"]

    def run(self, target: str, **kwargs) -> list[dict]:
        # ... your logic
        return [make_finding(
            title="Found Something",
            severity="HIGH", cvss=7.5, cwe="CWE-200",
            description="...", evidence="...",
            remediation="...", target=target,
        )]

# Register in your pyproject.toml:
# [project.entry-points."glitchicons.plugins"]
# my-plugin = "myplugin:MyPlugin"

# Then use:
glitchicons plugins list
```

---

## Integrations

```python
from modules.integrations.integrations import (
    BurpExporter, SlackNotifier, DiscordNotifier,
    JiraIntegration, SARIFExporter,
)

# Burp Suite XML
BurpExporter().export(findings, "./findings/burp.xml")

# Slack alert for critical findings
slack = SlackNotifier(webhook_url=os.environ["SLACK_WEBHOOK"])
slack.notify_critical(findings, target="target.com")
slack.notify_summary(findings, target="target.com", duration="4h30m")

# Discord embed notifications
discord = DiscordNotifier(webhook_url=os.environ["DISCORD_WEBHOOK"])
discord.notify_critical(findings, target="target.com")

# Jira tickets for HIGH+ findings
jira = JiraIntegration(
    url="https://company.atlassian.net",
    email="security@company.com",
    api_token=os.environ["JIRA_TOKEN"],
)
tickets = jira.create_tickets(findings, project_key="SEC", min_severity="HIGH")

# SARIF for GitHub Code Scanning
SARIFExporter().export(findings, "./findings/results.sarif")
# Upload via: gh code-scanning upload-sarif --sarif findings/results.sarif
```

---

## Go Integration (v1.1.0+)

Go binaries plug into Glitchicons via a standard JSON interface:

```python
from modules.go.go_runner import GoRunner, GoHealthChecker

# Check what's installed
GoHealthChecker().print_status()

# Run a Go binary (once installed)
runner = GoRunner(timeout=120)
result = runner.run("glitchrace", [
    "--target", "https://target.com/api/checkout",
    "--param",  "coupon_code",
    "--threads", "100",
    "--output", "json",
])

for finding in result.findings:
    print(finding["severity"], finding["title"])
```

### Planned Go Modules

| Binary | Version | Description | Speedup |
|---|---|---|---|
| `glitchrace` | v1.1.0 | Race condition — ns precision | 100x |
| `glitchscan` | v1.1.0 | Port + service scanner | 20x |
| `glitchfuzz` | v1.2.0 | HTTP directory fuzzer | 25x |
| `glitchdns`  | v1.2.0 | DNS brute forcer | 20x |
| `glitchtls`  | v1.3.0 | TLS/SSL analyzer | new |
| `glitchproxy`| v1.3.0 | Intercepting HTTP proxy | new |

Install (when available):
```bash
go install github.com/ardanov96/glitchrace@latest
go install github.com/ardanov96/glitchscan@latest
```

---

## WAF Evasion

```python
from glitchicons import WAFEvasionEngine

engine = WAFEvasionEngine()

# 30+ encoding techniques
variants = engine.evade("' OR '1'='1", attack_type="sqli")

# WAF-specific smart bypass
waf  = engine.fingerprint_waf(response_headers, response_body)
# → "Cloudflare"
bypasses = engine.smart_bypass(payload, waf_type=waf, attack_type="sqli")

# Export wordlist for other tools
engine.generate_wordlist(
    base_payloads=["' OR '1'='1", "UNION SELECT NULL--"],
    attack_type="sqli",
    output_file="./wordlists/sqli_bypass.txt",
)
```

Techniques: URL(×3) · Unicode · HTML entity(×3) · Hex · Base64 · CHAR() ·
Case(×4) · Whitespace(×3) · Comment(×4) · Null byte(×2) · SQL concat(×2) ·
XSS wrappers(×4)

WAF fingerprints: Cloudflare · ModSecurity · Akamai · AWS WAF · Imperva · Sucuri · F5 BIG-IP · Barracuda

---

## Proof of Concept

### Binary Fuzzing (AFL++)

```
Seeds:          60 LLM-generated corpus files
Runtime:        5 minutes
Crashes found:  726
CVSS:           8.1 (HIGH)
```

### Live Web Engagement (B2B SaaS, 70K users)

```
Duration:       < 8 hours (unauthenticated)
Detection:      Zero (Tor routing, no WAF alerts)

CRITICAL (1):   No brute force protection — 2,353 attempts/60 min (CVSS 9.1)
HIGH (4):       Checkout webhook auth bypass · Unauthenticated pricing API · ...
MEDIUM (7):     Security headers · API key exposure · DMARC p=none · ...
Total:          12 findings
```

---

## File Structure

```
glitchicons/
├── glitchicons/                  # v1.0.0 installable package
│   ├── __init__.py               # Public API + __version__ = "1.0.0"
│   ├── cli.py                    # 15 CLI commands
│   └── plugin_system.py          # Plugin ABC + Registry + make_finding()
├── modules/
│   ├── intelligence/             # v0.9.0
│   │   ├── llm_mutator.py
│   │   ├── fp_reducer.py
│   │   ├── severity_reasoner.py
│   │   └── waf_evasion.py
│   ├── integrations/             # v1.0.0
│   │   └── integrations.py       # Burp, Slack, Discord, Jira, SARIF
│   ├── go/                       # v1.0.0
│   │   └── go_runner.py          # Go binary interface
│   ├── auth/
│   │   └── mfa_bypass.py         # v0.8.0
│   ├── inject/
│   │   └── grpc_fuzzer.py        # v0.8.0
│   ├── recon/
│   │   ├── openapi_parser.py     # v0.8.0
│   │   └── subdomain_takeover.py # v0.8.0
│   ├── config/
│   ├── report/
│   └── scanner/
├── tests/                        # 748 unit tests
└── pyproject.toml                # v1.0.0, PyPI ready
```

---

## Changelog

### v1.0.0 — Stable Release

- ✅ **pip install glitchicons** — PyPI ready, entry point, public API
- ✅ **Plugin System** — `GlitchiconPlugin` ABC, `PluginRegistry`, `make_finding()` schema
- ✅ **Integration Layer** — Burp XML · Slack · Discord · Jira REST API · SARIF 2.1.0
- ✅ **Go Integration Arch** — binary registry, subprocess runner, JSON schema, health checker
- ✅ **748 total tests**, 0 failures, 0 warnings

### v0.9.0 — Intelligence Layer

- ✅ LLM Mutation Loop · False Positive Reducer · Severity Reasoning · WAF Evasion — 209 tests

### v0.8.0 — API & Protocol Expansion

- ✅ OpenAPI Parser · gRPC Fuzzer · Subdomain Takeover · MFA Bypass — 199 tests

### v0.7.0–v0.6.0 — Foundation + Web Offensive

- ✅ 209 + 15 modules

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) · Ranks: `RECRUIT` → `OPERATIVE` → `COMMANDER` → `WARLORD`

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
