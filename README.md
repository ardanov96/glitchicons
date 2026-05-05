# GLITCHICONS ⬡
### Decepticons Siege Division — AI-Powered Security Research Platform

[![Status](https://img.shields.io/badge/status-active%20development-blueviolet?style=flat-square)](https://github.com/ardanov96/glitchicons)
[![Version](https://img.shields.io/badge/version-0.6.0--dev-purple?style=flat-square)](https://github.com/ardanov96/glitchicons)
[![License](https://img.shields.io/badge/license-MIT-blueviolet?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-purple?style=flat-square)](https://python.org)
[![Go](https://img.shields.io/badge/go-1.22%2B-cyan?style=flat-square)](https://go.dev)
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
    │  (reflected,     │  (error-based,   │  (cloud metadata,          │
    │   stored, DOM)   │   time-based)    │   template injection)      │
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
|--------|-----------|--------|-------------|
| **0** | CLI (14 commands) | ✅ **DONE** | `seed` `fuzz` `protocol` `triage` `coverage` `brain` `siege` `map` `export` `status` `recon` `scan` `jwt` `idor` |
| **1** | LLM Seed Generator | ✅ **DONE** | Ollama + Qwen2.5-Coder → targeted corpus generation |
| **2** | AFL++ Runner | ✅ **DONE** | AI-seeded AFL++ · 726 crashes in 5 min (PoC) |
| **3** | Crash Triage | ✅ **DONE** | GDB + LLM classification → CVE-style report |
| **4** | Protocol Fuzzer | ✅ **DONE** | HTTP header/path/param/POST fuzzing |
| **5** | Coverage Map | ✅ **DONE** | gcov/LLVM visualization of code paths |
| **6** | RL Agent | ✅ **DONE** | Reinforcement learning for adaptive mutation |
| **7** | CFG Code Mapper | ✅ **DONE** | AST + control flow graph analysis |
| **8** | Auto Report Export | ✅ **DONE** | Internal/external pentest report with CVSS |
| **9** | Brute Force | ✅ **DONE** | CSRF-aware login brute force + lockout detection |
| **10** | Heavy Brute Force | ✅ **DONE** | Time-limited stress testing with rate analysis |

### Web Offensive Modules (v0.6.0 — NEW)

| Category | Module | Status | Description |
|----------|--------|--------|-------------|
| **recon/** | `recon_engine.py` | ✅ **DONE** | subfinder + httpx + nuclei + katana pipeline |
| **recon/** | `tech_fingerprint.py` | ✅ **DONE** | CMS, WAF, CDN, framework detection |
| **recon/** | `cloud_assets.py` | ✅ **DONE** | S3, Azure Blob, GCS bucket exposure |
| **auth/** | `jwt_analyzer.py` | ✅ **DONE** | Algorithm confusion, weak secrets, claim manipulation |
| **auth/** | `oauth_tester.py` | ✅ **DONE** | State parameter, redirect_uri bypass |
| **auth/** | `session_analyzer.py` | ✅ **DONE** | Fixation, cookie flags, entropy analysis |
| **inject/** | `xss_tester.py` | ✅ **DONE** | Reflected, stored, DOM-based XSS |
| **inject/** | `sqli_tester.py` | ✅ **DONE** | Error-based, time-based blind SQLi |
| **inject/** | `ssrf_tester.py` | ✅ **DONE** | Cloud metadata, localhost, blind SSRF |
| **inject/** | `ssti_tester.py` | ✅ **DONE** | Jinja2, Twig, Smarty, Freemarker detection |
| **inject/** | `xxe_tester.py` | ✅ **DONE** | File read, SSRF via XML, blind XXE |
| **business_logic/** | `idor_fuzzer.py` | ✅ **DONE** | Sequential ID, parameter, mass assignment |
| **business_logic/** | `price_manipulator.py` | ✅ **DONE** | Negative price, zero, overflow, discount abuse |
| **business_logic/** | `race_condition.py` | ✅ **DONE** | Concurrent threading, TOCTOU detection |
| **scanner/** | `nuclei_wrapper.py` | ✅ **DONE** | 5 scan profiles, 12,958 templates |
| **Cloud** | Glitchicons Cloud | 📋 Planned | SaaS — upload binary, get report |

---

## Quick Start

### Requirements

```bash
# System dependencies (Ubuntu/WSL2)
sudo apt install afl++ gdb python3 python3-pip python3-venv tor proxychains4 hydra golang-go -y

# Go tools (web offensive stack)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Add Go bin to PATH
echo 'export PATH=$HOME/go/bin:$PATH' >> ~/.bashrc && source ~/.bashrc

# Download nuclei templates
nuclei -update-templates

# Ollama — local LLM, no API key required
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder:3b
```

### Install

```bash
git clone https://github.com/ardanov96/glitchicons.git
cd glitchicons

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Usage — Core Commands

```bash
# Check environment
python3 glitchicons.py status

# Generate AI-powered seed corpus
python3 glitchicons.py seed --type json --count 20
python3 glitchicons.py seed --type http --count 15

# Run AFL++ with AI seeds
python3 glitchicons.py fuzz ./target_binary

# Protocol fuzzing — web application
python3 glitchicons.py protocol https://target.com \
  --endpoints /login --endpoints /api \
  --post --delay 1.5 \
  --output ./findings/protocol

# Triage crashes → CVE report
python3 glitchicons.py triage ./target_binary ./findings/crashes

# Export pentest report
python3 glitchicons.py export \
  --reports ./findings/reports \
  --format internal \
  --org "Client Name"
```

### Usage — Web Offensive Commands (v0.6.0 NEW)

```bash
# Recon pipeline — passive (DNS only, no LOA needed)
python3 glitchicons.py recon target.com --mode passive

# Recon pipeline — active (requires LOA)
python3 glitchicons.py recon target.com --mode active --output ./findings/recon

# Vulnerability scan — quick profile
python3 glitchicons.py scan https://target.com --profile quick

# Vulnerability scan — deep with CVEs
python3 glitchicons.py scan https://target.com \
  --profile deep \
  --severity medium,high,critical \
  --output ./findings/nuclei

# JWT analysis
python3 glitchicons.py jwt eyJhbGciOiJSUzI1NiJ9... --output ./findings/jwt

# IDOR fuzzing
python3 glitchicons.py idor https://target.com/api/user/{id} \
  --output ./findings/idor
```

### Brute Force Module

```bash
# Standard brute force with lockout detection
python3 brute_force.py \
  --target https://target.com \
  --emails wordlists/emails.txt \
  --passwords wordlists/passwords.txt \
  --delay 2.0

# Heavy stress test (time-limited)
python3 brute_force_heavy.py \
  --target https://target.com \
  --email admin@target.com \
  --passwords wordlists/rockyou.txt \
  --max-minutes 60

# Via Tor for IP masking
sudo service tor start
proxychains4 -q python3 brute_force.py
```

### Status Check Output

```
⬡ GLITCHICONS STATUS  v0.6.0-dev

  AFL++        ✓ available    /usr/bin/afl-fuzz
  Ollama       ✓ available    /usr/local/bin/ollama
  Models       ✓ loaded       qwen2.5-coder:3b
  Python       ✓ available    3.12.3
  Go           ✓ available    1.22.2
  subfinder    ✓ available    v2.14.0
  httpx        ✓ available    v1.9.0
  nuclei       ✓ available    v3.8.0 (12,958 templates)
  katana       ✓ available    latest
  GDB          ✓ available    /usr/bin/gdb
  Tor          ✓ available    127.0.0.1:9050
  Hydra        ✓ available    v9.5
  Brain Memory ✓ active
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
                   (zero authentication required)
Stealth          : Full Tor routing — IP never exposed
Detection        : Zero — no WAF alerts triggered
```

### Brute Force Stress Test

```
Standard test (1s delay):
  Duration   : 60 minutes
  Attempts   : 2,353
  Lockout    : NEVER triggered

Zero delay stress test:
  Duration   : 10 minutes
  Attempts   : 1,116
  Avg rate   : 112 attempts/min
  Peak rate  : 134 attempts/min
  Rate limit : NEVER triggered

Finding: CRITICAL — No brute force protection (CVSS 9.1)
Platform: 70,000 registered customers
```

### Passive DNS Recon (Pre-LOA)
Example output against university target (public DNS only):

```
Subdomains found    : 20+
  simpeg.target.ac.id           ← HR system
  simmahasiswa.target.ac.id     ← student database
  ujianpenmaru.target.ac.id     ← entrance exam system
  cloud.target.ac.id            ← cloud storage

DNS Findings:
  DMARC policy    : p=none (email spoofing CONFIRMED possible)
  SPF             : ~all (softfail — not enforced)
  WAF             : Cloudflare
  CalDAV/CardDAV  : service exposed
```

---

## Module Details

### Recon Engine (`modules/recon/recon_engine.py`)
- Subdomain enumeration via subfinder
- HTTP probing with status codes, titles, tech detection via httpx
- URL crawling via katana (depth-configurable)
- Nuclei scanning with template auto-selection
- Passive mode (DNS only) and active mode (requires LOA)
- Markdown report auto-generated with all findings

### Tech Fingerprint (`modules/recon/tech_fingerprint.py`)
- Detects: WordPress, Laravel, Joomla, Django, Rails, Django
- WAF detection: Cloudflare, Akamai, Imperva
- CDN detection, server fingerprinting
- JavaScript framework detection: Vue, React, Inertia.js

### JWT Analyzer (`modules/auth/jwt_analyzer.py`)
- Algorithm confusion (RS256 → none, HS256 → RS256)
- Weak secret brute force against common wordlist
- Claim manipulation: role escalation, user_id tampering, expiry bypass
- Outputs forged tokens for manual verification

### OAuth Tester (`modules/auth/oauth_tester.py`)
- Missing/weak state parameter detection (CSRF risk)
- redirect_uri bypass testing (open redirect chains)
- Token leakage detection in referrer headers

### Inject Suite (`modules/inject/`)
- **XSS**: reflected + stored with 10 payload variants
- **SQLi**: error-based signatures + time-based blind detection
- **SSRF**: cloud metadata (AWS/GCP/Azure), localhost, service ports
- **SSTI**: Jinja2, Twig, Smarty, Freemarker, ERB detection
- **XXE**: file read (/etc/passwd), SSRF via XML, blind XXE

### IDOR Fuzzer (`modules/business_logic/idor_fuzzer.py`)
- Sequential integer ID enumeration
- Parameter-based IDOR (URL + body)
- Mass assignment field injection
- Automatic baseline comparison

### Nuclei Wrapper (`modules/scanner/nuclei_wrapper.py`)
- 5 scan profiles: `quick` / `standard` / `deep` / `cves` / `auth`
- 12,958 templates covering technologies, exposures, CVEs, default logins
- Subdomain bulk scanning support
- CVSS severity filtering

---

## Tech Stack

| Layer | Technology | Status |
|-------|-----------|--------|
| CLI | Python 3.10+ · Click · Rich | ✅ Live |
| Fuzzing Engine | AFL++ 4.09c | ✅ Live |
| Web Recon | subfinder v2.14 · httpx v1.9 · katana | ✅ Live |
| Web Scanner | nuclei v3.8 · 12,958 templates | ✅ Live |
| Auth Testing | JWT · OAuth · Session analyzer | ✅ Live |
| Injection | XSS · SQLi · SSRF · SSTI · XXE | ✅ Live |
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

## Module File Structure

```
glitchicons/
├── glitchicons.py              # Main CLI (14 commands)
├── brute_force.py              # CSRF-aware brute force
├── brute_force_heavy.py        # Extended stress testing
├── modules/
│   ├── auth/
│   │   ├── jwt_analyzer.py     # JWT attack suite
│   │   ├── oauth_tester.py     # OAuth flow testing
│   │   └── session_analyzer.py # Session security
│   ├── business_logic/
│   │   ├── idor_fuzzer.py      # IDOR enumeration
│   │   ├── price_manipulator.py # Business logic bypass
│   │   └── race_condition.py   # Concurrency testing
│   ├── inject/
│   │   ├── xss_tester.py       # XSS detection
│   │   ├── sqli_tester.py      # SQL injection
│   │   ├── ssrf_tester.py      # SSRF detection
│   │   ├── ssti_tester.py      # Template injection
│   │   └── xxe_tester.py       # XML injection
│   ├── recon/
│   │   ├── recon_engine.py     # Full recon pipeline
│   │   ├── tech_fingerprint.py # Technology detection
│   │   └── cloud_assets.py     # Cloud bucket exposure
│   └── scanner/
│       └── nuclei_wrapper.py   # Nuclei integration
├── wordlists/
│   ├── rockyou.txt
│   └── business_passwords.txt
└── engagements/                # Client data (gitignored)
```

---

## Why Glitchicons?

| | Conventional Pentest Tools | Glitchicons |
|--|--|--|
| **Recon** | Manual | Automated subfinder + httpx + katana |
| **Scanning** | Static signatures | 12,958 nuclei templates + dynamic |
| **Auth testing** | Manual | JWT/OAuth/Session automated |
| **Injection** | Wordlist-based | LLM-guided + algorithmic |
| **Business logic** | Manual only | IDOR + price + race automated |
| **Crash analysis** | Manual | Automated GDB + LLM triage |
| **Reports** | Raw output | CVSS-scored pentest reports |
| **Stealth** | None built-in | Tor/proxychains integrated |
| **Learning** | Stateless | RL agent + brain memory |
| **Cost** | Paid (Burp Pro, etc.) | Free (MIT) |

---

## Changelog

### v0.6.0 — Web Offensive Toolkit
- ✅ 15 new web offensive modules across 5 categories
- ✅ `recon` command — subfinder + httpx + nuclei + katana pipeline
- ✅ `scan` command — nuclei scanner with 5 profiles (12,958 templates)
- ✅ `jwt` command — algorithm confusion, weak secret, claim manipulation
- ✅ `idor` command — sequential ID, parameter, mass assignment fuzzer
- ✅ Go toolchain integration: subfinder v2.14, httpx v1.9, nuclei v3.8, katana
- ✅ Full inject suite: XSS, SQLi, SSRF, SSTI, XXE
- ✅ Business logic suite: IDOR, price manipulation, race condition
- ✅ Auth suite: JWT, OAuth, session analysis
- ✅ Recon suite: engine, tech fingerprint, cloud assets
- ✅ CLI expanded from 10 → 14 commands

### v0.5.0 — Brute Force Module
- ✅ `brute_force.py` — CSRF-aware login brute forcer with lockout detection
- ✅ `brute_force_heavy.py` — Extended stress testing with zero delay mode
- ✅ Tor/proxychains integration for IP masking
- ✅ First live engagement — 18 findings, 1 CRITICAL, 4 HIGH confirmed

### v0.4.0 — All Core Modules Complete
- ✅ All 8 core modules operational
- ✅ CLI fixed — all 10 commands working
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

- 🐛 **Bug?** [Open an issue](https://github.com/ardanov96/glitchicons/issues)
- 💡 **Idea?** [Start a discussion](https://github.com/ardanov96/glitchicons/discussions)
- 🔧 **Code?** Look for `good-first-issue` labels

**Contributor ranks:** `RECRUIT` → `OPERATIVE` → `COMMANDER` → `WARLORD`

---

## Professional Services

Need AI-powered security assessment for your organization?

→ **[glitchicons.io](https://ardanov96.github.io/GTCN/)** — Pentest services by ARDATRON
→ Email: ardanov96@gmail.com

**Capabilities:**
- Web application penetration testing (automated + manual)
- Authentication security (JWT, OAuth, session)
- Business logic vulnerability assessment
- Brute force and credential security analysis
- Cloud asset exposure discovery
- Binary fuzzing and crash analysis
- Full pentest report with CVSS v3.1 scoring

---

## License

MIT License © 2026 GLITCHICONS

---

> *As MEGATRON forged the Constructicons from raw Cybertronian steel —*
> *ARDATRON forged GLITCHICONS from code, chaos, and conviction.*
> *Not to construct. To expose.*
