# GLITCHICONS ⬡

### Decepticons Siege Division — AI-Powered Security Research Platform

[![Status](https://img.shields.io/badge/status-active%20development-blueviolet?style=flat-square)](https://github.com/ardanov96/glitchicons)
[![Version](https://img.shields.io/badge/version-0.7.0--dev-purple?style=flat-square)](https://github.com/ardanov96/glitchicons)
[![License](https://img.shields.io/badge/license-MIT-blueviolet?style=flat-square)](https://github.com/ardanov96/glitchicons/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-purple?style=flat-square)](https://python.org)
[![Go](https://img.shields.io/badge/go-1.22%2B-cyan?style=flat-square)](https://go.dev)
[![CI](https://img.shields.io/github/actions/workflow/status/ardanov96/glitchicons/ci.yml?style=flat-square&label=CI)](https://github.com/ardanov96/glitchicons/actions)
[![Tests](https://img.shields.io/badge/tests-51%20passed-green?style=flat-square)](https://github.com/ardanov96/glitchicons/tree/main/tests)
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
Source Code / Binary / Network Protocol / Web Application
                         ↓
    ┌─────────────────────────────────────────┐
    │         GLITCHICONS SIEGE CORE          │
    │      LLM Orchestration + Brain Memory   │  ← Ollama / Claude API
    └──────────────────┬──────────────────────┘
                       ↓
    ┌──────────────────────────────────────────────────────────────────┐
    │  Recon Engine    │  Nuclei Scanner  │  Tech Fingerprint          │
    │  (subfinder +    │  (12,958 tmpl)   │  (CMS/WAF/CDN/framework)  │
    │   httpx + katana)│                  │                            │
    └──────────────────────────────────────────────────────────────────┘
                       ↓
    ┌──────────────────────────────────────────────────────────────────┐
    │  JWT Analyzer    │  OAuth Tester    │  Session Analyzer          │
    │  (alg confusion, │  (state param,   │  (fixation, entropy,       │
    │   weak secret)   │   redirect_uri)  │   cookie flags)            │
    └──────────────────────────────────────────────────────────────────┘
                       ↓
    ┌──────────────────────────────────────────────────────────────────┐
    │  XSS Tester      │  SQLi Tester     │  SSRF / SSTI / XXE         │
    │  GraphQL Fuzzer  │  (error-based,   │  (cloud metadata,          │
    │  (introspection, │   time-based)    │   template injection)      │
    │   field enum)    │                  │                            │
    └──────────────────────────────────────────────────────────────────┘
                       ↓
    ┌──────────────────────────────────────────────────────────────────┐
    │  IDOR Fuzzer     │  Price Manip.    │  Race Condition            │
    │  (sequential,    │  (negative,      │  (concurrent threads,      │
    │   mass assign.)  │   overflow)      │   TOCTOU detection)        │
    └──────────────────────────────────────────────────────────────────┘
                       ↓
    ┌──────────────────────────────────────────────────────────────────┐
    │  Seed Generator  │  AFL++ Runner    │  Protocol Fuzzer           │
    │  (LLM-guided)    │  (300k/sec)      │  (HTTP/TLS/DNS)            │
    └──────────────────────────────────────────────────────────────────┘
                       ↓
    ┌──────────────────────────────────────────────────────────────────┐
    │  Crash Triage    │  Coverage Map    │  Brute Force               │
    │  (GDB + LLM)     │  (gcov/LLVM)     │  (CSRF-aware)              │
    └──────────────────────────────────────────────────────────────────┘
                       ↓
         CVE Report → Pentest Report → Bounty Ready
```

---

## Development Status

### Core Modules (Binary & Protocol)

| Module | Component | Status | Description |
|---|---|---|---|
| **0** | CLI (14 commands) | ✅ DONE | `seed` `fuzz` `protocol` `triage` `coverage` `brain` `siege` `map` `export` `status` `recon` `scan` `jwt` `idor` |
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

### v0.7.0 — Foundation & New Modules (Current)

| Category | Component | Status | Description |
|---|---|---|---|
| **infra/** | GitHub Actions CI | ✅ DONE | Auto lint + test (Python 3.10/3.11/3.12) + Docker build |
| **infra/** | Docker + docker-compose | ✅ DONE | Glitchicons + Ollama + Tor — one command start |
| **infra/** | pyproject.toml | ✅ DONE | Proper packaging, ruff linter, pytest config |
| **tests/** | Unit test suite | ✅ DONE | 51 tests — seed, jwt, inject, crash triage |
| **inject/** | `graphql_fuzzer.py` | ✅ DONE | Introspection, field enum, nested DoS, batching attack |
| **Cloud** | Glitchicons Cloud | 📋 Planned | SaaS — upload binary, get report |

---

## Quick Start

### Option A — Docker (Recommended, Zero Setup)

```bash
git clone https://github.com/ardanov96/glitchicons.git
cd glitchicons

# Start Ollama + Tor (pull model otomatis ~2GB)
docker-compose up -d

# Tunggu Ollama siap (~60 detik pertama kali)
docker-compose logs -f ollama-setup

# Jalankan perintah
docker-compose run --rm glitchicons status
docker-compose run --rm glitchicons recon target.com --mode passive
```

### Option B — Manual (Linux/WSL2)

```bash
# System dependencies
sudo apt install afl++ gdb python3 python3-pip python3-venv tor proxychains4 hydra golang-go -y

# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
echo 'export PATH=$HOME/go/bin:$PATH' >> ~/.bashrc && source ~/.bashrc
nuclei -update-templates

# Ollama (local LLM, no API key needed)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder:3b

# Clone & install
git clone https://github.com/ardanov96/glitchicons.git
cd glitchicons
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Option C — Windows 11

```powershell
git clone https://github.com/ardanov96/glitchicons.git
cd glitchicons
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

---

## Usage

### Core Commands

```bash
# Check environment
python3 glitchicons.py status

# Generate AI-powered seed corpus
python3 glitchicons.py seed --type json --count 20
python3 glitchicons.py seed --type http --count 15

# Run AFL++ with AI seeds
python3 glitchicons.py fuzz ./target_binary

# Protocol fuzzing
python3 glitchicons.py protocol https://target.com \
  --endpoints /login --endpoints /api \
  --post --delay 1.5 --output ./findings/protocol

# Triage crashes → CVE report
python3 glitchicons.py triage ./target_binary ./findings/crashes

# Export pentest report
python3 glitchicons.py export \
  --reports ./findings/reports \
  --format internal --org "Client Name"
```

### Web Offensive Commands

```bash
# Recon — passive (no LOA needed)
python3 glitchicons.py recon target.com --mode passive

# Recon — active (requires LOA)
python3 glitchicons.py recon target.com --mode active --output ./findings/recon

# Vulnerability scan
python3 glitchicons.py scan https://target.com --profile deep \
  --severity medium,high,critical --output ./findings/nuclei

# JWT analysis
python3 glitchicons.py jwt eyJhbGciOiJSUzI1NiJ9... --output ./findings/jwt

# IDOR fuzzing
python3 glitchicons.py idor https://target.com/api/user/{id} --output ./findings/idor

# GraphQL fuzzing (NEW in v0.7.0)
python3 glitchicons.py graphql https://target.com/graphql --output ./findings/graphql
python3 glitchicons.py graphql https://target.com/graphql --introspect --dos-test
```

### Brute Force

```bash
# Standard with lockout detection
python3 brute_force.py \
  --target https://target.com \
  --emails wordlists/emails.txt \
  --passwords wordlists/passwords.txt \
  --delay 2.0

# Via Tor for IP masking
sudo service tor start
proxychains4 -q python3 brute_force.py ...
```

### Developer Commands

```bash
# Run test suite (51 unit tests)
pytest tests/ -v

# Run only unit tests (no network)
pytest tests/ -m unit -v

# Lint check
ruff check .

# Security scan on source
bandit -r . -x .venv,tests
```

---

## Proof of Concept

### Binary Fuzzing (AFL++)

Tested against an intentionally vulnerable C binary (buffer overflow via `strcpy`):

```
Seeds generated : 60 files (JSON + HTTP + XML via LLM)
AFL++ runtime   : 5 minutes
Total crashes   : 726
Unique crashes  : 1 saved (CWE-121: Stack Buffer Overflow)
Exec speed      : ~300,000 / second
Triage time     : < 30 seconds per crash
CVSS Score      : 8.1 (HIGH)
```

### Web Application Engagement — B2B Platform (70K users)

Authorized penetration test against live B2B wholesale platform:

```
Duration         : < 8 hours (unauthenticated)
Total findings   : 18 confirmed

  CRITICAL (1)   : No brute force protection (CVSS 9.1)
                   → 2,353 attempts/60 min, zero lockout
  HIGH (4)       : Checkout webhook auth bypass (CVSS 8.6)
                   Unauthenticated wholesale pricing API (CVSS 7.5)
                   URL rewriting bypass
                   Internal 500 errors on endpoints
  MEDIUM (7)     : Ziggy route table exposure, missing security headers,
                   Reviews.io API key, cache warming URLs, path disclosure,
                   Google OAuth Client ID, DMARC p=none
  LOW/INFO (6)   : Various misconfigurations and advisory items

Data exfiltrated : 1,360 products with wholesale pricing in 2.5 min
Stealth          : Full Tor routing — IP never exposed
Detection        : Zero — no WAF alerts triggered
```

---

## Tech Stack

| Layer | Technology | Status |
|---|---|---|
| CLI | Python 3.10+ · Click · Rich | ✅ Live |
| CI/CD | GitHub Actions · ruff · bandit | ✅ Live |
| Containerization | Docker · docker-compose · Ollama image | ✅ Live |
| Test Suite | pytest · pytest-cov · responses | ✅ Live (51 tests) |
| Fuzzing Engine | AFL++ 4.09c | ✅ Live |
| Web Recon | subfinder v2.14 · httpx v1.9 · katana | ✅ Live |
| Web Scanner | nuclei v3.8 · 12,958 templates | ✅ Live |
| Auth Testing | JWT · OAuth · Session analyzer | ✅ Live |
| Injection | XSS · SQLi · SSRF · SSTI · XXE · GraphQL | ✅ Live |
| Business Logic | IDOR · Price manipulation · Race condition | ✅ Live |
| LLM — Local | Ollama + Qwen2.5-Coder / DeepSeek | ✅ Live |
| Crash Analysis | GDB 15.x · Valgrind · ASAN | ✅ Live |
| IP Masking | Tor · Proxychains4 | ✅ Live |
| Reporting | Markdown · CVSS v3.1 scoring | ✅ Live |
| Brain Memory | Custom RAG · JSON store | ✅ Live |
| RL Agent | Stable Baselines3 · PyTorch | ✅ Live |
| Go Runtime | Go 1.22 · ProjectDiscovery suite | ✅ Live |
| LLM — Cloud | Claude API / OpenAI (optional) | 📋 Planned |
| Performance | Rust rewrite for core modules | 📋 Planned |

---

## File Structure

```
glitchicons/
├── glitchicons.py              # Main CLI (15 commands)
├── brute_force.py              # CSRF-aware brute force
├── brute_force_heavy.py        # Extended stress testing
├── Dockerfile                  # Container image
├── docker-compose.yml          # Glitchicons + Ollama + Tor
├── pyproject.toml              # Packaging + ruff + pytest config
├── CONTRIBUTING.md             # Contributor guide + rank system
├── SECURITY.md                 # Responsible disclosure policy
├── modules/
│   ├── auth/
│   │   ├── jwt_analyzer.py
│   │   ├── oauth_tester.py
│   │   └── session_analyzer.py
│   ├── business_logic/
│   │   ├── idor_fuzzer.py
│   │   ├── price_manipulator.py
│   │   └── race_condition.py
│   ├── inject/
│   │   ├── xss_tester.py
│   │   ├── sqli_tester.py
│   │   ├── ssrf_tester.py
│   │   ├── ssti_tester.py
│   │   ├── xxe_tester.py
│   │   └── graphql_fuzzer.py   # NEW v0.7.0
│   ├── recon/
│   │   ├── recon_engine.py
│   │   ├── tech_fingerprint.py
│   │   └── cloud_assets.py
│   └── scanner/
│       └── nuclei_wrapper.py
├── tests/                      # NEW v0.7.0
│   ├── conftest.py
│   ├── test_seed_generator.py
│   ├── test_jwt_analyzer.py
│   ├── test_inject_modules.py
│   ├── test_graphql_fuzzer.py
│   └── test_crash_triage.py
├── wordlists/
│   ├── rockyou.txt
│   └── business_passwords.txt
└── engagements/                # Client data (gitignored)
```

---

## Why Glitchicons?

| | Conventional Pentest Tools | Glitchicons |
|---|---|---|
| **Recon** | Manual | Automated subfinder + httpx + katana |
| **Scanning** | Static signatures | 12,958 nuclei templates + dynamic |
| **Auth testing** | Manual | JWT/OAuth/Session automated |
| **Injection** | Wordlist-based | LLM-guided + algorithmic |
| **GraphQL** | Manual / Burp Pro | Automated introspection + DoS test |
| **Business logic** | Manual only | IDOR + price + race automated |
| **Crash analysis** | Manual | Automated GDB + LLM triage |
| **Reports** | Raw output | CVSS-scored pentest reports |
| **Stealth** | None built-in | Tor/proxychains integrated |
| **Learning** | Stateless | RL agent + brain memory |
| **CI/Testing** | None | 51 unit tests + GitHub Actions |
| **Deployment** | Manual | Docker one-command start |
| **Cost** | Paid (Burp Pro, etc.) | Free (MIT) |

---

## Changelog

### v0.7.0 — Foundation + GraphQL Fuzzer (Current)

- ✅ GitHub Actions CI — auto lint + test matrix (Python 3.10/3.11/3.12) + Docker build
- ✅ Docker + docker-compose — Glitchicons + Ollama + Tor, zero-friction deployment
- ✅ pyproject.toml — proper packaging, ruff linter, bandit, pytest config
- ✅ Unit test suite — 51 tests across seed generator, JWT, inject, crash triage
- ✅ `graphql` command — introspection dump, field enumeration, nested query DoS, batching attack
- ✅ CONTRIBUTING.md — contributor guide with rank system (RECRUIT → WARLORD)
- ✅ SECURITY.md — responsible disclosure policy
- ✅ Windows 11 support — tested on Python 3.12 + PowerShell

### v0.6.0 — Web Offensive Toolkit

- ✅ 15 new web offensive modules across 5 categories
- ✅ `recon` command — subfinder + httpx + nuclei + katana pipeline
- ✅ `scan` command — nuclei scanner with 5 profiles (12,958 templates)
- ✅ `jwt` command — algorithm confusion, weak secret, claim manipulation
- ✅ `idor` command — sequential ID, parameter, mass assignment fuzzer
- ✅ Full inject suite: XSS, SQLi, SSRF, SSTI, XXE
- ✅ Business logic suite: IDOR, price manipulation, race condition
- ✅ Auth suite: JWT, OAuth, session analysis
- ✅ CLI expanded from 10 → 14 commands

### v0.5.0 — Brute Force Module

- ✅ CSRF-aware login brute forcer with lockout detection
- ✅ Extended stress testing with zero delay mode
- ✅ Tor/proxychains integration for IP masking
- ✅ First live engagement — 18 findings, 1 CRITICAL, 4 HIGH confirmed

### v0.4.0 — All Core Modules Complete

- ✅ All 8 core modules operational
- ✅ Protocol fuzzer — full HTTP attack surface coverage
- ✅ Auto report export with CVSS scoring
- ✅ Brain memory system active

### v0.2.0 — Initial Release

- ✅ AFL++ runner with AI seeds
- ✅ Crash triage with GDB + LLM
- ✅ LLM seed generator

---

## Contributing

Glitchicons is built in public. All skill levels welcome.

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guide including dev setup, branch naming, and commit format.

**Contributor ranks:** `RECRUIT` → `OPERATIVE` → `COMMANDER` → `WARLORD`

- 🐛 **Bug?** [Open an issue](https://github.com/ardanov96/glitchicons/issues)
- 💡 **Idea?** [Start a discussion](https://github.com/ardanov96/glitchicons/discussions)
- 🔧 **Code?** Look for `good-first-issue` labels

---

## Professional Services

Need AI-powered security assessment for your organization?

→ **[glitchicons.io](https://ardanov96.github.io/GTCN/)** — Pentest services by ARDATRON
→ Email: ardanov96@gmail.com

---

## License

MIT License © 2026 GLITCHICONS

---

> *As MEGATRON forged the Constructicons from raw Cybertronian steel —*
> *ARDATRON forged GLITCHICONS from code, chaos, and conviction.*
> *Not to construct. To expose.*
