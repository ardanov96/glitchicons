# GLITCHICONS ⬡

### Decepticons Siege Division — AI-Powered Security Research Platform

[![Status](https://img.shields.io/badge/status-active%20development-blueviolet?style=flat-square)](https://github.com/ardanov96/glitchicons)
[![Version](https://img.shields.io/badge/version-0.8.0-purple?style=flat-square)](https://github.com/ardanov96/glitchicons/releases)
[![License](https://img.shields.io/badge/license-MIT-blueviolet?style=flat-square)](https://github.com/ardanov96/glitchicons/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-purple?style=flat-square)](https://python.org)
[![Go](https://img.shields.io/badge/go-1.22%2B-cyan?style=flat-square)](https://go.dev)
[![CI](https://img.shields.io/github/actions/workflow/status/ardanov96/glitchicons/ci.yml?style=flat-square&label=CI)](https://github.com/ardanov96/glitchicons/actions)
[![Tests](https://img.shields.io/badge/tests-408%20passed-green?style=flat-square)](https://github.com/ardanov96/glitchicons/tree/main/tests)
[![Stars](https://img.shields.io/github/stars/ardanov96/glitchicons?style=flat-square&color=blueviolet)](https://github.com/ardanov96/glitchicons/stargazers)

> *Where others probe, we siege. Where others test, we break.*

---

## What is Glitchicons?

Glitchicons is an open-source **AI-powered security research platform** that combines large language model intelligence with adaptive fuzzing, web offensive testing, protocol analysis, brute force, and automated vulnerability reporting.

Unlike conventional scanners that rely on static signatures, Glitchicons **reads your target first** — using LLMs to understand structure and generate precision attacks across both binary and web attack surfaces. The result is faster discovery with less noise.

```
Conventional scanner:  static payloads → hope for hit
Glitchicons:           read target → understand context → targeted attack → finding → CVSS report
```

Built in public. MIT licensed. Designed for security researchers, red teams, and bug bounty hunters.

---

## Architecture

```
Source Code / Binary / Network Protocol / Web Application / WebSocket / gRPC
                         ↓
    ┌─────────────────────────────────────────┐
    │         GLITCHICONS SIEGE CORE          │
    │      LLM Orchestration + Brain Memory   │  ← Ollama / Claude API
    │      Config File System (YAML)          │  ← engagement_template.yaml
    └──────────────────┬──────────────────────┘
                       ↓
    ┌──────────────────────────────────────────────────────────────────┐
    │  Recon Engine    │  Nuclei Scanner  │  Subdomain Takeover        │
    │  (subfinder +    │  (12,958 tmpl)   │  (25+ fingerprints)        │
    │   httpx + katana)│                  │                            │
    └──────────────────────────────────────────────────────────────────┘
                       ↓
    ┌──────────────────────────────────────────────────────────────────┐
    │  OpenAPI Parser  │  JWT Analyzer    │  MFA Bypass Tester         │
    │  (auto attack    │  (alg confusion, │  (OTP brute, skip,         │
    │   plan from spec)│   weak secrets)  │   type juggling)           │
    └──────────────────────────────────────────────────────────────────┘
                       ↓
    ┌──────────────────────────────────────────────────────────────────┐
    │  XSS / SQLi      │  GraphQL Fuzzer  │  gRPC Fuzzer               │
    │  SSRF / SSTI     │  (introspect,    │  (reflection, injection,   │
    │  XXE / CORS      │   batch, DoS)    │   proto encoder)           │
    └──────────────────────────────────────────────────────────────────┘
                       ↓
    ┌──────────────────────────────────────────────────────────────────┐
    │  WebSocket Fuzzer│  IDOR Fuzzer     │  Race Condition            │
    │  (origin bypass, │  (sequential,    │  Price Manipulation        │
    │   msg injection) │   mass assign.)  │                            │
    └──────────────────────────────────────────────────────────────────┘
                       ↓
    ┌──────────────────────────────────────────────────────────────────┐
    │  Seed Generator  │  AFL++ Runner    │  Protocol Fuzzer           │
    │  (LLM-guided)    │  (300k/sec)      │  (HTTP/TLS/DNS)            │
    └──────────────────────────────────────────────────────────────────┘
                       ↓
    ┌──────────────────────────────────────────────────────────────────┐
    │  Crash Triage    │  Coverage Map    │  HTML Report Dashboard     │
    │  (GDB + LLM)     │  (gcov/LLVM)     │  (sortable, dark theme)    │
    └──────────────────────────────────────────────────────────────────┘
                       ↓
         CVE Report → Pentest Report (MD + JSON + HTML) → Bounty Ready
```

---

## Development Status

### Core Modules (Binary & Protocol)

| Module | Component | Status | Description |
|---|---|---|---|
| **0** | CLI (17 commands) | ✅ DONE | `seed` `fuzz` `protocol` `triage` `coverage` `brain` `siege` `map` `export` `status` `recon` `scan` `jwt` `idor` `graphql` `websocket` `cors` `openapi` `grpc` `takeover` `mfa` |
| **1** | LLM Seed Generator | ✅ DONE | Ollama + Qwen2.5-Coder → targeted corpus generation |
| **2** | AFL++ Runner | ✅ DONE | AI-seeded AFL++ · 726 crashes in 5 min (PoC) |
| **3** | Crash Triage | ✅ DONE | GDB + LLM classification → CVE-style report |
| **4** | Protocol Fuzzer | ✅ DONE | HTTP header/path/param/POST fuzzing |
| **5** | Coverage Map | ✅ DONE | gcov/LLVM visualization of code paths |
| **6** | RL Agent | ✅ DONE | Reinforcement learning for adaptive mutation |
| **7** | CFG Code Mapper | ✅ DONE | AST + control flow graph analysis |
| **8** | Auto Report Export | ✅ DONE | Internal/external pentest report with CVSS |
| **9** | Brute Force | ✅ DONE | CSRF-aware login brute force + lockout detection |
| **10** | Heavy Brute Force | ✅ DONE | Time-limited stress testing with rate analysis |

### Web Offensive Modules (v0.6.0)

| Category | Module | Status | Description |
|---|---|---|---|
| **recon/** | `recon_engine.py` | ✅ DONE | subfinder + httpx + nuclei + katana pipeline |
| **recon/** | `tech_fingerprint.py` | ✅ DONE | CMS, WAF, CDN, framework detection |
| **recon/** | `cloud_assets.py` | ✅ DONE | S3, Azure Blob, GCS bucket exposure |
| **auth/** | `jwt_analyzer.py` | ✅ DONE | Algorithm confusion, weak secrets, claim manipulation |
| **auth/** | `oauth_tester.py` | ✅ DONE | State parameter, redirect_uri bypass |
| **auth/** | `session_analyzer.py` | ✅ DONE | Fixation, cookie flags, entropy analysis |
| **inject/** | `xss_tester.py` | ✅ DONE | Reflected, stored, DOM-based XSS |
| **inject/** | `sqli_tester.py` | ✅ DONE | Error-based, time-based blind SQLi |
| **inject/** | `ssrf_tester.py` | ✅ DONE | Cloud metadata, localhost, blind SSRF |
| **inject/** | `ssti_tester.py` | ✅ DONE | Jinja2, Twig, Smarty, Freemarker detection |
| **inject/** | `xxe_tester.py` | ✅ DONE | File read, SSRF via XML, blind XXE |
| **business_logic/** | `idor_fuzzer.py` | ✅ DONE | Sequential ID, parameter, mass assignment |
| **business_logic/** | `price_manipulator.py` | ✅ DONE | Negative price, zero, overflow, discount abuse |
| **business_logic/** | `race_condition.py` | ✅ DONE | Concurrent threading, TOCTOU detection |
| **scanner/** | `nuclei_wrapper.py` | ✅ DONE | 5 scan profiles, 12,958 templates |

### v0.7.0 — Foundation + Attack Surface Expansion ✅

| Component | Tests | Description |
|---|---|---|
| GitHub Actions CI | — | Auto lint + test matrix + Docker build |
| Docker + docker-compose | — | Glitchicons + Ollama + Tor |
| Config File System | 29 | YAML engagement config + siege orchestrator |
| GraphQL Fuzzer | 24 | 7 attack modules: introspect, batch, alias, nested DoS |
| WebSocket Fuzzer | 35 | 8 attack modules: origin bypass, injection, replay |
| CORS Checker | 39 | 9 checks, CVSS 3.1–9.3, auto-dedup |
| HTML Report Dashboard | 31 | Self-contained HTML, sortable, canvas chart |

### v0.8.0 — API & Protocol Expansion ✅

| Component | Tests | Description |
|---|---|---|
| **OpenAPI Parser** | 55 | Swagger 2.0 + OpenAPI 3.x, auto attack plan, static analysis |
| **gRPC Fuzzer** | 49 | Reflection enum, injection, proto encoder, metadata injection |
| **Subdomain Takeover** | 40 | 25+ fingerprints: S3, GitHub, Heroku, Azure, Netlify, Vercel... |
| **MFA Bypass Tester** | 55 | OTP brute, skip, type juggling, race, remember-me abuse |
| **Total tests** | **408** | 0 failures |

---

## Quick Start

### Option A — Docker (Recommended)

```bash
git clone https://github.com/ardanov96/glitchicons.git
cd glitchicons
docker-compose up -d
docker-compose run --rm glitchicons status
```

### Option B — Linux/WSL2

```bash
sudo apt install afl++ gdb python3 python3-pip python3-venv tor proxychains4 golang-go -y
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
curl -fsSL https://ollama.com/install.sh | sh && ollama pull qwen2.5-coder:3b

git clone https://github.com/ardanov96/glitchicons.git && cd glitchicons
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install websocket-client grpcio grpcio-reflection dnspython
```

### Option C — Windows 11

```powershell
git clone https://github.com/ardanov96/glitchicons.git && cd glitchicons
python -m venv .venv && .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install websocket-client grpcio grpcio-reflection dnspython
```

---

## Usage

### Siege Mode — Full Engagement from Config

```bash
python3 glitchicons.py config init --domain target.com
# Edit engagement.yaml
python3 glitchicons.py siege --config engagement.yaml
```

### v0.8.0 New Commands

```bash
# OpenAPI/Swagger auto attack plan
python3 glitchicons.py openapi --spec swagger.json --base-url https://api.target.com
python3 glitchicons.py openapi --url https://api.target.com/swagger.json

# gRPC fuzzing
python3 glitchicons.py grpc --target grpc.target.com:443
python3 glitchicons.py grpc --target grpc.target.com:9090 --insecure --token eyJ...

# Subdomain takeover
python3 glitchicons.py takeover --domain target.com
python3 glitchicons.py takeover --domain target.com --wordlist wordlists/subdomains.txt

# MFA bypass
python3 glitchicons.py mfa --target https://target.com/auth/mfa
python3 glitchicons.py mfa --target https://target.com/2fa --session sess_abc --brute
```

### v0.7.0 Commands

```bash
python3 glitchicons.py graphql https://target.com/graphql --introspect --dos-test
python3 glitchicons.py websocket wss://target.com/ws --token eyJ...
python3 glitchicons.py cors https://target.com --token eyJ...
python3 glitchicons.py report --input ./findings --output ./findings/report.html
```

### Core Commands

```bash
python3 glitchicons.py recon target.com --mode passive
python3 glitchicons.py scan https://target.com --profile deep --severity high,critical
python3 glitchicons.py jwt eyJhbGciOiJSUzI1NiJ9...
python3 glitchicons.py idor https://target.com/api/user/{id}
python3 glitchicons.py fuzz ./target_binary
python3 glitchicons.py triage ./target_binary ./findings/crashes
```

### Developer

```bash
pytest tests/ -v                   # 408 unit tests
pytest tests/ -m unit -v           # unit tests only
ruff check .                       # lint
bandit -r . -x .venv,tests         # security scan on source
```

---

## Proof of Concept

### Binary Fuzzing (AFL++)

```
Seeds generated : 60 files (JSON + HTTP + XML via LLM)
AFL++ runtime   : 5 minutes
Total crashes   : 726
CVSS Score      : 8.1 (HIGH)
```

### Web Engagement — B2B Platform (70K users)

```
Duration     : < 8 hours (unauthenticated)
CRITICAL (1) : No brute force protection (CVSS 9.1) — 2,353 attempts/60 min
HIGH (4)     : Checkout webhook auth bypass, unauthenticated pricing API...
MEDIUM (7)   : Security headers, API key exposure, DMARC p=none...
Detection    : Zero — Tor routing, no WAF alerts triggered
```

---

## New in v0.8.0

### OpenAPI Parser + Attack Planner

Reads Swagger/OpenAPI spec and auto-generates a targeted attack plan:

```
From file  : glitchicons openapi --spec api.yaml --base-url https://api.target.com
From URL   : glitchicons openapi --url https://api.target.com/openapi.json

Attack matrix per endpoint:
  IDOR · SQLi · SSTI · XSS · AUTH_BYPASS · MASS_ASSIGN · BOLA · RATE_LIMIT

Static findings (no network):
  Unauthenticated sensitive endpoints · HTTP base URL · Sensitive GET params
  PII in response schemas · Missing global security policy
```

### gRPC Fuzzer

```
Attacks: Reflection enumeration · Auth bypass · Payload injection
         Metadata injection · Boolean/enum escalation · Deadline bypass
         Error info leakage · Large payload DoS

ProtoEncoder: pure Python — no .proto schema required
```

### Subdomain Takeover (25+ fingerprints)

```
AWS S3 (CRITICAL 9.8)  · Azure Blob (CRITICAL 9.5)  · GitHub Pages (HIGH 8.0)
Heroku (HIGH 8.0)      · Netlify (HIGH 8.0)          · Vercel (HIGH 8.0)
CloudFront · Elastic Beanstalk · Fastly · Shopify · Zendesk · Ghost
Tumblr · Surge.sh · Readme.io · HubSpot · UserVoice · WordPress.com
Domain Parking (generic) · Dead NS records (CRITICAL 9.8)
```

### MFA Bypass Tester (10 attacks)

```
Common PIN bypass  · OTP skip (empty/null/flag body)
Type juggling      · Backup code enumeration
Remember-me abuse  · OTP reuse detection
Race condition     · Long OTP truncation bug
Lockout check      · Full 000000-999999 brute force (--brute)
```

---

## Tech Stack

| Layer | Technology | Status |
|---|---|---|
| CLI | Python 3.10+ · Click · Rich | ✅ Live |
| CI/CD | GitHub Actions · ruff · bandit | ✅ Live |
| Containerization | Docker · docker-compose | ✅ Live |
| Test Suite | pytest · 408 tests · 0 failures | ✅ Live |
| Config System | YAML · dataclasses · env var interpolation | ✅ Live |
| Fuzzing Engine | AFL++ 4.09c | ✅ Live |
| Web Recon | subfinder · httpx · katana | ✅ Live |
| Web Scanner | nuclei · 12,958 templates | ✅ Live |
| Auth Testing | JWT · OAuth · Session · MFA bypass | ✅ Live |
| Injection | XSS · SQLi · SSRF · SSTI · XXE | ✅ Live |
| GraphQL | Introspection · batch · alias · nested DoS | ✅ Live |
| WebSocket | Origin bypass · injection · replay · rate limit | ✅ Live |
| CORS | 9 checks · CVSS 3.1–9.3 | ✅ Live |
| OpenAPI | Swagger 2.0 + OpenAPI 3.x · attack matrix | ✅ Live |
| gRPC | Reflection · injection · proto encoder | ✅ Live |
| Subdomain | 25+ fingerprints · dead NS · CNAME analysis | ✅ Live |
| MFA | 10 bypass techniques · OTP generator | ✅ Live |
| Reporting | Markdown · JSON · HTML Dashboard | ✅ Live |
| LLM — Local | Ollama + Qwen2.5-Coder | ✅ Live |
| Crash Analysis | GDB · Valgrind · ASAN | ✅ Live |
| IP Masking | Tor · Proxychains4 | ✅ Live |
| RL Agent | Stable Baselines3 · PyTorch | ✅ Live |
| Go Runtime | Go 1.22 · ProjectDiscovery suite | ✅ Live |
| LLM — Cloud | Claude API / OpenAI (optional) | 📋 Planned |
| Performance | Rust rewrite for core modules | 📋 Planned |

---

## File Structure

```
glitchicons/
├── glitchicons.py                  # Main CLI (17+ commands)
├── brute_force.py / brute_force_heavy.py
├── engagement_template.yaml
├── Dockerfile / docker-compose.yml
├── pyproject.toml / CONTRIBUTING.md / SECURITY.md
├── modules/
│   ├── auth/
│   │   ├── jwt_analyzer.py
│   │   ├── oauth_tester.py
│   │   ├── session_analyzer.py
│   │   └── mfa_bypass.py           # NEW v0.8.0
│   ├── business_logic/
│   │   ├── idor_fuzzer.py / price_manipulator.py / race_condition.py
│   ├── config/
│   │   ├── config_loader.py / siege_runner.py
│   ├── inject/
│   │   ├── xss_tester.py / sqli_tester.py / ssrf_tester.py
│   │   ├── ssti_tester.py / xxe_tester.py
│   │   ├── graphql_fuzzer.py / websocket_fuzzer.py / cors_checker.py
│   │   └── grpc_fuzzer.py          # NEW v0.8.0
│   ├── recon/
│   │   ├── recon_engine.py / tech_fingerprint.py / cloud_assets.py
│   │   ├── openapi_parser.py       # NEW v0.8.0
│   │   └── subdomain_takeover.py   # NEW v0.8.0
│   ├── report/
│   │   └── html_reporter.py
│   └── scanner/
│       └── nuclei_wrapper.py
├── tests/                          # 408 unit tests
│   ├── conftest.py
│   ├── test_seed_generator.py / test_jwt_analyzer.py
│   ├── test_inject_modules.py / test_graphql_fuzzer.py
│   ├── test_websocket_fuzzer.py / test_cors_checker.py
│   ├── test_html_reporter.py / test_crash_triage.py
│   ├── test_config_loader.py / test_openapi_parser.py
│   ├── test_grpc_fuzzer.py / test_subdomain_takeover.py
│   └── test_mfa_bypass.py
└── wordlists/ / engagements/ / findings/
```

---

## Why Glitchicons?

| | Conventional Tools | Glitchicons |
|---|---|---|
| **Recon** | Manual | Automated subfinder + httpx + katana |
| **API spec** | Manual read | Auto attack plan from OpenAPI/Swagger |
| **gRPC** | None / Burp Pro | Automated fuzzer + proto encoder |
| **Subdomain** | dig + manual | 25+ fingerprints, auto takeover detection |
| **MFA** | Manual | 10 bypass techniques automated |
| **GraphQL** | Manual / Burp | Introspection + DoS + batch automated |
| **WebSocket** | Manual only | 8 attack modules automated |
| **CORS** | Manual / extension | 9 checks, auto CVSS, dedup |
| **Reports** | Raw output | MD + JSON + HTML Dashboard |
| **CI/Testing** | None | 408 tests + GitHub Actions |
| **Deployment** | Manual | Docker one-command |
| **Config** | Long CLI flags | Single YAML file |
| **Cost** | Paid (Burp Pro) | Free (MIT) |

---

## Changelog

### v0.8.0 — API & Protocol Expansion

- ✅ **OpenAPI Parser** — Swagger 2.0 + OpenAPI 3.x auto attack plan, static security analysis, 55 tests
- ✅ **gRPC Fuzzer** — reflection, injection, metadata escalation, pure Python proto encoder, 49 tests
- ✅ **Subdomain Takeover** — 25+ cloud/SaaS fingerprints, dead NS detection, CNAME analysis, 40 tests
- ✅ **MFA Bypass Tester** — 10 attacks: OTP brute, skip, type juggling, race, remember-me, 55 tests
- ✅ **408 total tests**, 0 failures
- ✅ pip install: `websocket-client grpcio grpcio-reflection dnspython`

### v0.7.0 — Foundation + Attack Surface Expansion

- ✅ GitHub Actions CI + Docker + pyproject.toml
- ✅ 209 tests across GraphQL, WebSocket, CORS, HTML report, Config system
- ✅ GraphQL Fuzzer (7 modules) · WebSocket Fuzzer (8 modules) · CORS Checker (9 checks)
- ✅ HTML Report Dashboard · Config File System (YAML siege mode)

### v0.6.0 — Web Offensive Toolkit

- ✅ 15 web offensive modules: Recon · JWT · OAuth · XSS · SQLi · SSRF · SSTI · XXE · IDOR · Race

### v0.5.0 — v0.2.0

- ✅ Brute force · Binary fuzzing · Crash triage · First live engagement (18 findings)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) · **Ranks:** `RECRUIT` → `OPERATIVE` → `COMMANDER` → `WARLORD`

- 🐛 [Open an issue](https://github.com/ardanov96/glitchicons/issues)
- 💡 [Start a discussion](https://github.com/ardanov96/glitchicons/discussions)

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
