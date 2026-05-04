# GLITCHICONS ⬡
### Decepticons Siege Division — AI-Powered Security Research Platform

[![Status](https://img.shields.io/badge/status-active%20development-blueviolet?style=flat-square)](https://github.com/ardanov96/glitchicons)
[![Version](https://img.shields.io/badge/version-0.5.0--dev-purple?style=flat-square)](https://github.com/ardanov96/glitchicons)
[![License](https://img.shields.io/badge/license-MIT-blueviolet?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-purple?style=flat-square)](https://python.org)
[![Stars](https://img.shields.io/github/stars/ardanov96/glitchicons?style=flat-square&color=blueviolet)](https://github.com/ardanov96/glitchicons/stargazers)

> *Where others probe, we siege. Where others test, we break.*

---

## What is Glitchicons?

Glitchicons is an open-source **AI-powered security research platform** that combines large language model intelligence with adaptive fuzzing, protocol testing, brute force analysis, and automated vulnerability reporting.

Unlike conventional fuzzers that throw random inputs at a target, Glitchicons **reads your target first** — using LLMs to understand code structure and generate precision attacks. The result is faster vulnerability discovery with less noise.

```
Conventional fuzzer:  random inputs → hope for crash
Glitchicons:          read code → understand structure → targeted attack → crash → analysis → report
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
    ┌──────────────────────────────────────────────────────┐
    │  Seed Generator  │  AFL++ Runner  │  Protocol Fuzzer │
    │  (LLM-guided)    │  (300k/sec)    │  (HTTP/TLS/DNS)  │
    └──────────────────────────────────────────────────────┘
                       ↓
    ┌──────────────────────────────────────────────────────┐
    │  Crash Triage   │  Coverage Map  │  Brute Force      │
    │  (GDB + LLM)    │  (gcov/LLVM)   │  (CSRF-aware)     │
    └──────────────────────────────────────────────────────┘
                       ↓
    ┌──────────────────────────────────────────────────────┐
    │  CFG Code Mapper │  RL Agent     │  Auto Report      │
    │  (AST/Graph)     │  (adaptive)   │  (CVSS scored)    │
    └──────────────────────────────────────────────────────┘
                       ↓
         CVE Report → Pentest Report → Bounty Ready
```

---

## Development Status

| Module | Component | Status | Description |
|--------|-----------|--------|-------------|
| **0** | CLI (10 commands) | ✅ **DONE** | `seed` `fuzz` `protocol` `triage` `coverage` `brain` `siege` `map` `export` `status` |
| **1** | LLM Seed Generator | ✅ **DONE** | Ollama + Qwen2.5-Coder → targeted corpus generation |
| **2** | AFL++ Runner | ✅ **DONE** | AI-seeded AFL++ · 726 crashes in 5 min (PoC) |
| **3** | Crash Triage | ✅ **DONE** | GDB + LLM classification → CVE-style report |
| **4** | Protocol Fuzzer | ✅ **DONE** | HTTP header/path/param/POST fuzzing with finding detection |
| **5** | Coverage Map | ✅ **DONE** | gcov/LLVM visualization of code paths |
| **6** | RL Agent | ✅ **DONE** | Reinforcement learning for adaptive mutation |
| **7** | CFG Code Mapper | ✅ **DONE** | AST + control flow graph analysis |
| **8** | Auto Report Export | ✅ **DONE** | Internal/external pentest report with CVSS scoring |
| **9** | Brute Force | ✅ **DONE** | CSRF-aware login brute force + lockout detection |
| **10** | Heavy Brute Force | ✅ **DONE** | Time-limited stress testing with rate/peak analysis |
| **11** | Glitchicons Cloud | 📋 Planned | SaaS — upload binary, get report |

---

## Quick Start

### Requirements

```bash
# System dependencies (Ubuntu/WSL2)
sudo apt install afl++ gdb python3 python3-pip python3-venv tor proxychains4 hydra

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

### Usage

```bash
# Check environment
python3 glitchicons.py status

# Generate AI-powered seed corpus
python3 glitchicons.py seed --type json --count 20
python3 glitchicons.py seed --type http --count 15
python3 glitchicons.py seed --source ./target.c --count 30

# Run AFL++ with AI seeds
python3 glitchicons.py fuzz ./target_binary

# Protocol fuzzing — web application
python3 glitchicons.py protocol https://target.com \
  --endpoints /login --endpoints /api \
  --post --delay 1.5 \
  --output ./findings/protocol

# Triage crashes → CVE report
python3 glitchicons.py triage ./target_binary ./findings/crashes

# Coverage mapping
python3 glitchicons.py coverage ./target_binary ./corpus

# CFG code analysis
python3 glitchicons.py map ./target.c

# Export pentest report
python3 glitchicons.py export \
  --reports ./findings/reports \
  --protocol ./findings/protocol \
  --format internal \
  --org "Client Name"

# Brain memory status
python3 glitchicons.py brain

# Siege mode (full pipeline)
python3 glitchicons.py siege https://target.com
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
⬡ GLITCHICONS STATUS  v0.5.0-dev

  AFL++        ✓ available    /usr/bin/afl-fuzz
  Ollama       ✓ available    /usr/local/bin/ollama
  Models       ✓ loaded       qwen2.5-coder:3b
  Python       ✓ available    3.12.3
  GDB          ✓ available    /usr/bin/gdb
  Valgrind     ✓ available    /usr/bin/valgrind
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
Trigger         : HTTP seed generated by LLM
CVSS Score      : 8.1 (HIGH)
```

### Web Application Protocol Fuzzing
Tested against a live authorized target (B2B wholesale platform, 70K customers):

```
Scan duration    : ~3 hours (unauthenticated)
Findings         : 12 total
  CRITICAL       : 1  (No brute force protection — CVSS 9.1)
  HIGH           : 2  (URL rewriting bypass, internal 500 errors)
  MEDIUM         : 5  (Route table exposure, missing headers, API key leak, etc.)
  LOW            : 4  (Misconfigured endpoints, placeholder files)
Stealth          : Full Tor routing — IP never exposed
Detection        : Zero — no alerts triggered on target
```

### Brute Force Stress Test
Live authorized brute force test against authenticated endpoint:

```
Standard test (1s delay):
  Duration   : 60 minutes
  Attempts   : 2,353
  Rate       : 39 attempts/min
  Lockout    : NEVER triggered

Zero delay stress test:
  Duration   : 10 minutes
  Attempts   : 1,116
  Avg rate   : 112 attempts/min
  Peak rate  : 134 attempts/min
  Rate limit : NEVER triggered
  Lockout    : NEVER triggered

Finding: No brute force protection confirmed on platform
with 70,000 registered customers (CRITICAL, CVSS 9.1)
```

---

## Module Details

### Protocol Fuzzer (`protocol_fuzzer.py`)
- HTTP path traversal and endpoint discovery
- Header injection (X-Original-URL, X-Forwarded-For, etc.)
- GET parameter fuzzing with baseline comparison
- POST body fuzzing with LLM-generated payloads
- Privilege escalation detection
- Rate-limited to avoid service disruption
- Auto-saves findings as markdown report

### Brute Force (`brute_force.py`)
- CSRF token grabber (Laravel/Inertia.js compatible)
- Rate-aware login brute force
- Account lockout detection
- Rate limit detection (429, 503, soft blocks)
- Username enumeration support
- Tor/proxychains compatible
- Auto report generation with timestamps

### Heavy Brute Force (`brute_force_heavy.py`)
- Extended time-limited testing (configurable duration)
- Zero delay mode for maximum speed stress testing
- Real-time rate calculation (avg + peak)
- Session auto-refresh on connection errors
- Comprehensive final report
- Designed for authorized stress testing only

### Auto Report Export (`report_exporter.py`)
- CVSS scoring per finding
- Internal and external format support
- LLM-enriched vulnerability descriptions
- Multi-finding aggregation
- Markdown output ready for client delivery

---

## Wordlist Setup

```bash
mkdir -p wordlists

# RockYou (14M passwords)
curl -L https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt \
  -o wordlists/rockyou.txt

# Common passwords (10K)
curl -L https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt \
  -o wordlists/10k-common.txt

# Usernames
curl -L https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt \
  -o wordlists/usernames.txt
```

---

## Tech Stack

| Layer | Technology | Status |
|-------|-----------|--------|
| CLI | Python 3.10+ · Click · Rich | ✅ Live |
| Fuzzing Engine | AFL++ 4.09c | ✅ Live |
| LLM — Local | Ollama + Qwen2.5-Coder / DeepSeek | ✅ Live |
| Crash Analysis | GDB 15.x · Valgrind · ASAN | ✅ Live |
| Protocol Fuzzing | Python Requests · Custom HTTP engine | ✅ Live |
| Brute Force | Python Requests · CSRF-aware · Hydra | ✅ Live |
| IP Masking | Tor · Proxychains4 | ✅ Live |
| Reporting | Markdown · CVSS scoring | ✅ Live |
| Brain Memory | Custom RAG · JSON store | ✅ Live |
| RL Agent | Stable Baselines3 · PyTorch | ✅ Live |
| GNN / CFG | AST parser · Graph analysis | ✅ Live |
| LLM — Cloud | Claude API / OpenAI (optional) | 📋 Planned |
| Performance | Rust rewrite | 📋 Planned |

---

## Why Glitchicons?

| | Conventional Pentest Tools | Glitchicons |
|--|--|--|
| **Input strategy** | Random/wordlist | LLM-guided, context-aware |
| **Crash analysis** | Manual | Automated GDB + LLM |
| **Web fuzzing** | Static payloads | Dynamic LLM-generated payloads |
| **Brute force** | Basic attempts | CSRF-aware + lockout detection |
| **Reports** | Raw output | CVSS-scored pentest reports |
| **Stealth** | None built-in | Tor/proxychains integrated |
| **Learning** | Stateless | RL agent + brain memory |
| **Cost** | Paid (Burp Pro, etc.) | Free (MIT) |

---

## Changelog

### v0.5.0 — Brute Force Module
- ✅ `brute_force.py` — CSRF-aware login brute forcer with lockout detection
- ✅ `brute_force_heavy.py` — Extended stress testing with zero delay mode
- ✅ Tor/proxychains integration for IP masking
- ✅ Rate and peak analysis reporting
- ✅ First live engagement completed — 12 findings, 1 CRITICAL confirmed

### v0.4.0 — All Core Modules Complete
- ✅ All 8 core modules operational
- ✅ CLI fixed — all 10 commands working
- ✅ Protocol fuzzer — full HTTP attack surface coverage
- ✅ Auto report export with CVSS scoring
- ✅ Brain memory system active
- ✅ CFG code mapper and RL agent

### v0.2.0 — Initial Release
- ✅ AFL++ runner with AI seeds
- ✅ Crash triage with GDB + LLM
- ✅ LLM seed generator
- ✅ Basic CLI skeleton

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
- Web application penetration testing
- Brute force and credential security analysis
- Security header and configuration audits
- GDPR compliance risk assessment
- Full pentest report with CVSS scoring

---

## License

MIT License © 2026 GLITCHICONS

---

> *As MEGATRON forged the Constructicons from raw Cybertronian steel —*
> *ARDATRON forged GLITCHICONS from code, chaos, and conviction.*
> *Not to construct. To expose.*
