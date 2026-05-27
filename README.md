# GLITCHICONS ⬡

### Decepticons Siege Division — AI-Powered Security Research Platform

[![Status](https://img.shields.io/badge/status-active%20development-blueviolet?style=flat-square)](https://github.com/ardanov96/glitchicons)
[![Version](https://img.shields.io/badge/version-0.9.0-purple?style=flat-square)](https://github.com/ardanov96/glitchicons/releases)
[![License](https://img.shields.io/badge/license-MIT-blueviolet?style=flat-square)](https://github.com/ardanov96/glitchicons/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-purple?style=flat-square)](https://python.org)
[![CI](https://img.shields.io/github/actions/workflow/status/ardanov96/glitchicons/ci.yml?style=flat-square&label=CI)](https://github.com/ardanov96/glitchicons/actions)
[![Tests](https://img.shields.io/badge/tests-617%20passed-green?style=flat-square)](https://github.com/ardanov96/glitchicons/tree/main/tests)
[![Stars](https://img.shields.io/github/stars/ardanov96/glitchicons?style=flat-square&color=blueviolet)](https://github.com/ardanov96/glitchicons/stargazers)

> *Where others probe, we siege. Where others test, we break.*

---

## What is Glitchicons?

Glitchicons is an open-source **AI-powered security research platform** that combines large language model intelligence with adaptive fuzzing, web offensive testing, protocol analysis, brute force, and automated vulnerability reporting.

Unlike conventional scanners that rely on static signatures, Glitchicons **learns from each response** — using LLMs to evolve payloads, verify findings, explain severity, and bypass WAFs. The result is a self-improving attacker that gets smarter with every engagement.

```
Static scanner:   fixed payloads → fire → hope
Glitchicons v0.9: probe → observe → LLM evolves payload → probe → confirm →
                  FP reduce → CVSS explain → WAF bypass → report
```

Built in public. MIT licensed. Designed for security researchers, red teams, and bug bounty hunters.

---

## Architecture

```
Source Code / Binary / API / WebSocket / gRPC / Web Application
                         ↓
    ┌─────────────────────────────────────────────────┐
    │         INTELLIGENCE LAYER (v0.9.0)             │
    │  LLM Mutation Loop  │  False Positive Reducer   │
    │  Severity Reasoner  │  WAF Evasion Engine        │
    └──────────────────┬──────────────────────────────┘
                       ↓
    ┌──────────────────────────────────────────────────────────────────┐
    │  OpenAPI Parser   │  gRPC Fuzzer    │  Subdomain Takeover        │
    │  (auto attack     │  (proto encode) │  (25+ fingerprints)        │
    │   plan from spec) │                 │                            │
    └──────────────────────────────────────────────────────────────────┘
                       ↓
    ┌──────────────────────────────────────────────────────────────────┐
    │  GraphQL Fuzzer   │  WebSocket Fuzz │  CORS Checker              │
    │  MFA Bypass       │  JWT / OAuth    │  XSS / SQLi / SSRF         │
    │  SSTI / XXE       │  IDOR / Race    │  Price Manipulation        │
    └──────────────────────────────────────────────────────────────────┘
                       ↓
    ┌──────────────────────────────────────────────────────────────────┐
    │  AFL++ Fuzzer     │  Protocol Fuzz  │  Crash Triage (GDB+LLM)   │
    │  Coverage Map     │  RL Agent       │  Brute Force (CSRF-aware)  │
    └──────────────────────────────────────────────────────────────────┘
                       ↓
         HTML Report → JSON → Markdown → CVSS Scored → Bounty Ready
```

---

## Development Status

### v0.9.0 — Intelligence Layer ✅ (Current)

| Module | Tests | Description |
|---|---|---|
| **LLM Mutation Loop** | 54 | Adaptive payload evolution via LLM feedback |
| **False Positive Reducer** | 47 | LLM verifies findings before they enter report |
| **Severity Reasoning** | 43 | CVSS v3.1 calculator + LLM narrative + exec summary |
| **WAF Evasion Engine** | 65 | 30+ techniques: URL/unicode/hex/case/comment/XSS |
| **Total v0.9.0** | **209** | 0 failures |

### v0.8.0 — API & Protocol Expansion ✅

| Module | Tests | Description |
|---|---|---|
| OpenAPI Parser | 55 | Swagger 2.0 + OpenAPI 3.x auto attack plan |
| gRPC Fuzzer | 49 | Reflection, injection, proto encoder |
| Subdomain Takeover | 40 | 25+ cloud fingerprints, dead NS detection |
| MFA Bypass Tester | 55 | 10 attacks: OTP brute, skip, type juggling, race |

### v0.7.0 — Foundation ✅

| Module | Tests | Description |
|---|---|---|
| Config + CI/Docker | 29 | YAML siege mode, GitHub Actions, Docker |
| GraphQL + WebSocket + CORS | 98 | 24+ attack modules combined |
| HTML Report + Config | 31+29 | Dark theme dashboard, YAML engagement config |

### v0.6.0 — Web Offensive (15 modules) ✅

Recon · JWT · OAuth · Session · XSS · SQLi · SSRF · SSTI · XXE · IDOR · Price · Race · Nuclei

### Core (v0.2.0–v0.5.0) ✅

AFL++ · Crash triage · Protocol fuzzer · RL agent · CFG mapper · Brute force

---

## Quick Start

### Docker (Recommended)

```bash
git clone https://github.com/ardanov96/glitchicons.git && cd glitchicons
docker-compose up -d
docker-compose run --rm glitchicons status
```

### Linux/WSL2

```bash
git clone https://github.com/ardanov96/glitchicons.git && cd glitchicons
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install websocket-client grpcio grpcio-reflection dnspython
```

### Windows 11

```powershell
git clone https://github.com/ardanov96/glitchicons.git && cd glitchicons
python -m venv .venv && .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install websocket-client grpcio grpcio-reflection dnspython
```

---

## Usage

### Intelligence Layer (v0.9.0)

```python
# LLM Mutation Loop — adaptive payload evolution
from modules.intelligence.llm_mutator import LLMMutator

mutator = LLMMutator(provider="ollama", model="qwen2.5-coder:3b")
result = mutator.mutate_and_test(
    target_url="https://target.com/search",
    param="q",
    base_payload="' OR '1'='1",
    attack_type="sqli",
    max_rounds=5,
)
# result.successful_payload — evolved bypass payload

# False Positive Reducer — verify findings before reporting
from modules.intelligence.fp_reducer import FalsePositiveReducer

reducer = FalsePositiveReducer(provider="ollama")
verified = reducer.verify_all(raw_findings)
clean = [f for f in verified if f["verdict"] != "FALSE_POSITIVE"]

# Severity Reasoning — explain CVSS scores
from modules.intelligence.severity_reasoner import SeverityReasoner

reasoner = SeverityReasoner(provider="ollama", rescore=True)
enriched = reasoner.enrich_all(findings)
# Each finding now has: narrative, business_impact, executive_summary,
#                        cvss_vector, cvss_breakdown, remediation_priority

# WAF Evasion — bypass blocked payloads
from modules.intelligence.waf_evasion import WAFEvasionEngine

engine = WAFEvasionEngine()
# Detect WAF type
waf = engine.fingerprint_waf(response_headers, response_body)  # "Cloudflare"
# Generate bypass variants
variants = engine.smart_bypass("' OR '1'='1", waf_type=waf, attack_type="sqli")
# Generate evasion wordlist
engine.generate_wordlist(base_payloads, attack_type="sqli", output_file="./bypass.txt")
```

### Siege Mode

```bash
python3 glitchicons.py config init --domain target.com
python3 glitchicons.py siege --config engagement.yaml
```

### Module Commands

```bash
# v0.9.0 Intelligence
python3 glitchicons.py mutate --url https://t.com/search --param q --payload "' OR '1'='1"
python3 glitchicons.py verify  --input ./findings/raw.json
python3 glitchicons.py explain --input ./findings/raw.json --rescore
python3 glitchicons.py evade   --payload "<script>alert(1)</script>" --waf cloudflare

# v0.8.0 API/Protocol
python3 glitchicons.py openapi  --spec swagger.json --base-url https://api.target.com
python3 glitchicons.py grpc     --target grpc.target.com:443
python3 glitchicons.py takeover --domain target.com
python3 glitchicons.py mfa      --target https://target.com/auth/mfa

# v0.7.0 Web
python3 glitchicons.py graphql  https://target.com/graphql --introspect
python3 glitchicons.py websocket wss://target.com/ws --token eyJ...
python3 glitchicons.py cors     https://target.com

# Core
python3 glitchicons.py recon    target.com --mode passive
python3 glitchicons.py scan     https://target.com --profile deep
python3 glitchicons.py jwt      eyJhbGciOiJSUzI1NiJ9...
python3 glitchicons.py fuzz     ./target_binary
```

### Developer

```bash
pytest tests/ -v          # 617 unit tests
ruff check .              # lint
bandit -r . -x .venv,tests  # security scan on source
```

---

## New in v0.9.0 — Intelligence Layer

### LLM Mutation Loop

Transforms Glitchicons from static scanner to adaptive attacker:

```
Round 1: base payload → blocked (403)
  LLM: "Server blocked single quote. Try unicode encoding or comment injection."
Round 2: unicode variant → error message (MySQL syntax near...)
  LLM: "MySQL detected. Try time-based or UNION-based payloads."
Round 3: SLEEP(3) variant → 3.2s response time → CONFIRMED SQLi
```

Supports: SQLi · XSS · SSTI · SSRF · generic
Providers: Ollama (local) · Anthropic · OpenAI

### False Positive Reducer

Filters noise before findings enter the report:

```
Input:  18 raw findings
Output: CONFIRMED: 8 | LIKELY: 4 | UNCERTAIN: 3 | FALSE_POSITIVE: 3

Pipeline:
  Static analysis → strong evidence patterns matched?
  Fast path       → 2+ signals = CONFIRMED instantly
  LLM reasoning   → contextual analysis with confidence 0.0-1.0
  Re-probe        → optional confirmation payload to live target
```

### Severity Reasoning Engine

Full CVSS v3.1 calculator + LLM-powered explanations:

```
Input:  finding with title + evidence
Output:
  cvss_vector:          CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  cvss_breakdown:       {Attack Vector: Network, Complexity: Low, ...}
  narrative:            "This SQL injection vulnerability allows..."
  business_impact:      "This poses an immediate, existential risk..."
  executive_summary:    Non-technical one-paragraph for management
  remediation_priority: 95/100 (CVSS + exploitability + attack type)
  suggested_score:      LLM can challenge original score if wrong
```

### WAF Evasion Engine (30+ techniques)

```python
engine = WAFEvasionEngine()

# All techniques for SQLi
variants = engine.evade("' OR '1'='1", attack_type="sqli")
# → [EvasionVariant(technique="comment_inline", encoded="'/**/OR/**/...", rate=0.75),
#    EvasionVariant(technique="unicode",        encoded="%u0027...",      rate=0.70),
#    ...]

# WAF-specific smart bypass
waf = engine.fingerprint_waf(headers, body)  # "Cloudflare"
bypasses = engine.smart_bypass(payload, waf, "sqli")

# Export wordlist for other tools
engine.generate_wordlist(payloads, output_file="./wordlists/sqli_waf_bypass.txt")
```

Techniques: URL(×3) · Unicode · HTML entity(×3) · Hex · Base64 · CHAR() ·
Case(×4) · Whitespace(×3) · Comment(×4) · Null byte(×2) · SQL concat(×2) ·
XSS wrappers(×4)

WAF fingerprints: Cloudflare · ModSecurity · Akamai · AWS WAF · Imperva · Sucuri · F5 BIG-IP · Barracuda

---

## Tech Stack

| Layer | Technology | Status |
|---|---|---|
| Intelligence | LLM Mutation · FP Reducer · CVSS Engine · WAF Evasion | ✅ v0.9.0 |
| API/Protocol | OpenAPI · gRPC · Subdomain · MFA | ✅ v0.8.0 |
| Web Offensive | GraphQL · WebSocket · CORS · HTML Report | ✅ v0.7.0 |
| Injection | XSS · SQLi · SSRF · SSTI · XXE | ✅ v0.6.0 |
| Auth | JWT · OAuth · Session · MFA | ✅ Live |
| Fuzzing | AFL++ · Protocol · RL Agent · CFG | ✅ Live |
| LLM — Local | Ollama + Qwen2.5-Coder | ✅ Live |
| LLM — Cloud | Anthropic + OpenAI (optional) | ✅ Live |
| CI/CD | GitHub Actions · Docker | ✅ Live |
| Test Suite | pytest · 617 tests · 0 failures | ✅ Live |

---

## File Structure

```
glitchicons/
├── modules/
│   ├── intelligence/           # NEW v0.9.0
│   │   ├── llm_mutator.py      # Adaptive payload evolution
│   │   ├── fp_reducer.py       # False positive reduction
│   │   ├── severity_reasoner.py # CVSS + narrative + exec summary
│   │   └── waf_evasion.py      # 30+ encoding/bypass techniques
│   ├── auth/
│   │   ├── jwt_analyzer.py / oauth_tester.py / session_analyzer.py
│   │   └── mfa_bypass.py       # v0.8.0
│   ├── inject/
│   │   ├── xss / sqli / ssrf / ssti / xxe
│   │   ├── graphql_fuzzer.py / websocket_fuzzer.py / cors_checker.py
│   │   └── grpc_fuzzer.py      # v0.8.0
│   ├── recon/
│   │   ├── recon_engine.py / tech_fingerprint.py / cloud_assets.py
│   │   ├── openapi_parser.py   # v0.8.0
│   │   └── subdomain_takeover.py # v0.8.0
│   ├── config/
│   │   └── config_loader.py / siege_runner.py
│   ├── report/
│   │   └── html_reporter.py
│   └── scanner/
│       └── nuclei_wrapper.py
└── tests/                      # 617 unit tests
    ├── test_llm_mutator.py      # 54
    ├── test_fp_reducer.py       # 47
    ├── test_severity_reasoner.py # 43
    ├── test_waf_evasion.py      # 65
    ├── test_openapi_parser.py   # 55
    ├── test_grpc_fuzzer.py      # 49
    ├── test_subdomain_takeover.py # 40
    ├── test_mfa_bypass.py       # 55
    └── [7 more test files]
```

---

## Changelog

### v0.9.0 — Intelligence Layer

- ✅ **LLM Mutation Loop** — adaptive feedback loop, 5 attack types, 3 LLM providers, 54 tests
- ✅ **False Positive Reducer** — 4-step pipeline, confidence scoring, fast paths, 47 tests
- ✅ **Severity Reasoning** — pure Python CVSS v3.1 calculator, LLM narrative, exec summary, 43 tests
- ✅ **WAF Evasion Engine** — 30+ techniques, 8 WAF fingerprints, smart bypass, wordlist export, 65 tests
- ✅ **617 total tests**, 0 failures

### v0.8.0 — API & Protocol Expansion

- ✅ OpenAPI Parser · gRPC Fuzzer · Subdomain Takeover · MFA Bypass — 199 tests

### v0.7.0 — Foundation + Attack Surface Expansion

- ✅ CI/CD · Docker · Config · GraphQL · WebSocket · CORS · HTML Report — 209 tests

### v0.6.0 — Web Offensive Toolkit

- ✅ 15 modules: Recon · JWT · OAuth · XSS · SQLi · SSRF · SSTI · XXE · IDOR · Race

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) · Ranks: `RECRUIT` → `OPERATIVE` → `COMMANDER` → `WARLORD`

- 🐛 [Issues](https://github.com/ardanov96/glitchicons/issues) · 💡 [Discussions](https://github.com/ardanov96/glitchicons/discussions)

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
