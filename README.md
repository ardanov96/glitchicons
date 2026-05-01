# GLITCHICONS ⬡
### Decepticons Siege Division — AI-Powered Security Research Platform

[![Status](https://img.shields.io/badge/status-active%20development-blueviolet?style=flat-square)](https://github.com/ardanov96/glitchicons)
[![Version](https://img.shields.io/badge/version-0.4.0--dev-purple?style=flat-square)](https://github.com/ardanov96/glitchicons)
[![License](https://img.shields.io/badge/license-MIT-blueviolet?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-purple?style=flat-square)](https://python.org)
[![Lines](https://img.shields.io/badge/codebase-7%2C000%2B%20lines-blueviolet?style=flat-square)](https://github.com/ardanov96/glitchicons)

> *Where others probe, we siege. Where others test, we break.*

---

## What is Glitchicons?

Glitchicons is an open-source **AI security research platform** — not just a fuzzer.

It combines **LLM intelligence**, **adaptive fuzzing**, **reinforcement learning**, and **automated vulnerability analysis** into a single unified pipeline. From source code analysis to HackerOne-ready report, fully automated.

```
Source Code / Binary / API Endpoint
              ↓
    ┌─────────────────────────┐
    │   CFG Code Mapper       │  ← AST parsing, attack surface scoring
    └──────────┬──────────────┘
               ↓
    ┌─────────────────────────┐
    │   LLM Seed Generator    │  ← Ollama + code-aware mutation
    │   + Brain Memory        │  ← learns what works per target
    └──────────┬──────────────┘
               ↓
    ┌────────────────────────────────────┐
    │  AFL++ Runner  │  RL Agent         │
    │  (binary)      │  (adaptive strat) │  ← Q-Learning, gets smarter
    └────────────────────────────────────┘
               ↓
    ┌────────────────────────────────────┐
    │  Protocol Fuzzer  │  Coverage Map  │
    │  (HTTP/API)       │  (HTML visual) │
    └────────────────────────────────────┘
               ↓
    ┌─────────────────────────┐
    │   Crash Triage          │  ← GDB + LLM → CWE + CVSS
    └──────────┬──────────────┘
               ↓
    ┌─────────────────────────┐
    │   Auto Report Export    │  ← HackerOne / Bugcrowd / Internal
    └─────────────────────────┘
```

---

## Development Status

| Module | Component | Status | Description |
|--------|-----------|--------|-------------|
| **0** | CLI Skeleton | ✅ **DONE** | 10 commands: `seed fuzz protocol triage coverage brain siege map export status` |
| **1** | LLM Seed Generator | ✅ **DONE** | Ollama + Qwen2.5-Coder · semantic dedup · AST-aware prompts |
| **2** | AFL++ Runner | ✅ **DONE** | AI-seeded AFL++ · 726 crashes in 5 min (PoC) |
| **3** | Crash Triage | ✅ **DONE** | GDB backtrace + LLM classification → CVE-style report |
| **4** | Protocol Fuzzer | ✅ **DONE** | HTTP/API · JWT bypass · header injection · path discovery |
| **BQ** | Build Quality | ✅ **DONE** | Semantic dedup · AST context extractor · Session memory |
| **5** | Coverage Map | ✅ **DONE** | gcov + AFL++ · interactive D3.js HTML visualization |
| **6** | RL Agent | ✅ **DONE** | Q-Learning · 10 strategies · persists across sessions |
| **7** | CFG Code Mapper | ✅ **DONE** | C/C++ + Python CFG · centrality scoring · D3.js graph |
| **8** | Auto Report Export | ✅ **DONE** | HackerOne · Bugcrowd · Internal audit · JSON |
| **9** | Glitchicons Cloud | 📋 Planned | SaaS — upload binary, get report |

---

## Quick Start

### Requirements

```bash
# System (Ubuntu / WSL2)
sudo apt install afl++ gdb valgrind gcov build-essential python3 python3-pip python3-venv

# Ollama — local LLM, no API key, no cost
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
pip install ollama requests networkx
```

### Verify

```bash
python3 glitchicons.py status
```

Expected:
```
⬡ GLITCHICONS STATUS  v0.4.0-dev

  AFL++        ✓ available    /usr/bin/afl-fuzz
  GDB          ✓ available    /usr/bin/gdb
  Valgrind     ✓ available    /usr/bin/valgrind
  gcov         ✓ available    /usr/bin/gcov
  Ollama       ✓ available    /usr/local/bin/ollama
  Python       ✓ available    3.12.3
  LLM Models   ✓ loaded       qwen2.5-coder:3b
  requests     ✓ available    2.33.1
  ollama       ✓ available    ok
  Brain Memory ✓ active       2 sessions · 2 targets learned
```

---

## Full Pipeline Usage

### Step 1 — Map the target (CFG analysis)
```bash
python3 glitchicons.py map ./target.c
# → Builds CFG, scores attack surface
# → Generates interactive HTML graph
# → Outputs seed generation hints
```

### Step 2 — Generate AI seeds
```bash
# From source code (AST-aware)
python3 glitchicons.py seed --source ./target.c --count 30

# From input type
python3 glitchicons.py seed --type json --count 20
python3 glitchicons.py seed --type http --count 20
```

### Step 3a — Binary fuzzing (AFL++)
```bash
python3 glitchicons.py fuzz ./target_binary
```

### Step 3b — RL-guided adaptive fuzzing
```bash
# Agent learns optimal mutation strategy for this target
python3 glitchicons.py siege ./target_binary --interval 60 --duration 3600
```

### Step 3c — HTTP/API fuzzing
```bash
python3 glitchicons.py protocol https://api.target.com
python3 glitchicons.py protocol https://api.target.com \
  --endpoints /users --endpoints /admin \
  --token eyJhbGc... --delay 1.0
```

### Step 4 — Coverage map
```bash
python3 glitchicons.py coverage ./findings
# → Interactive HTML report: which paths hit, which remain
```

### Step 5 — Triage crashes
```bash
python3 glitchicons.py triage ./target_binary ./findings/default/crashes
# → GDB analysis + LLM classification
# → CWE, CVSS, root cause, remediation
```

### Step 6 — Export reports
```bash
# All formats
python3 glitchicons.py export

# HackerOne submission
python3 glitchicons.py export --format h1 --program "GoTo Bug Bounty"

# Internal audit
python3 glitchicons.py export --format internal --org "PT Startup Indonesia"
```

### Brain memory stats
```bash
python3 glitchicons.py brain
# → Shows which payload patterns work per target type
# → Accumulated across all sessions
```

---

## Proof of Concept

Tested against an intentionally vulnerable C binary (`strcpy` buffer overflow):

```
Seeds generated : 60 files (JSON + HTTP + XML via LLM)
AFL++ runtime   : 5 minutes
Total crashes   : 726
Unique crashes  : 1 (CWE-121: Stack Buffer Overflow, CVSS 8.1)
Exec speed      : ~300,000 executions/second
Triage time     : < 30 seconds
Trigger         : HTTP seed generated by LLM
RL Agent        : learned havoc = best strategy (avg reward 9.4)
Export          : HackerOne + Bugcrowd + Internal reports generated
```

---

## Codebase

| File | Module | Lines |
|------|--------|-------|
| `glitchicons.py` | CLI (10 commands) | 459 |
| `seed_generator.py` | Module 1 | 273 |
| `crash_triage.py` | Module 3 | 429 |
| `protocol_fuzzer.py` | Module 4 | 766 |
| `glitchicons_brain.py` | Build Quality | 587 |
| `coverage_map.py` | Module 5 | 669 |
| `rl_agent.py` | Module 6 | 775 |
| `code_mapper.py` | Module 7 | 941 |
| `report_exporter.py` | Module 8 | 940 |
| **Total** | **8 modules** | **~6,800 lines** |

---

## Tech Stack

| Layer | Technology | Status |
|-------|-----------|--------|
| CLI | Python 3.10+ · Click · Rich | ✅ Live |
| Fuzzing Engine | AFL++ 4.09c | ✅ Live |
| LLM — Local | Ollama + Qwen2.5-Coder:3b | ✅ Live |
| Crash Analysis | GDB 15.x · Valgrind · ASAN | ✅ Live |
| Graph Analysis | NetworkX (CFG) | ✅ Live |
| RL Agent | Tabular Q-Learning (pure Python) | ✅ Live |
| Visualization | D3.js (CFG + Coverage) | ✅ Live |
| LLM — Cloud | Claude API / OpenAI (optional) | 📋 Planned |
| Performance | Rust | 📋 Planned |

---

## Why Glitchicons?

| | Conventional Fuzzer | Glitchicons |
|--|--|--|
| **Input strategy** | Random mutation | LLM-guided, code-aware |
| **Adaptation** | Stateless | RL agent learns per target |
| **Memory** | None | Brain persists across sessions |
| **Code understanding** | Zero | CFG mapper + AST extractor |
| **Crash analysis** | Manual | Automated GDB + LLM |
| **Reports** | Raw crash dumps | HackerOne/Bugcrowd ready |
| **Coverage** | Terminal only | Interactive HTML map |
| **Cost** | Free | Free (MIT) |

No competitor integrates all of this in one tool.

---

## Contributing

Built in public. All skill levels welcome.

- 🐛 **Bug?** [Open an issue](https://github.com/ardanov96/glitchicons/issues)
- 💡 **Idea?** [Start a discussion](https://github.com/ardanov96/glitchicons/discussions)
- 🔧 **Code?** Look for `good-first-issue` labels

**Contributor ranks:** `RECRUIT` → `OPERATIVE` → `COMMANDER` → `WARLORD`

---

## Professional Services

Need AI-powered security assessment for your startup or fintech?

→ **[glitchicons.io](https://ardanov96.github.io/GLTN/)** — Pentest services by ARDATRON
→ Contact: ardatron@glitchicons.io

---

## License

MIT License © 2026 ARDATRON

---

> *As MEGATRON forged the Constructicons from raw Cybertronian steel —*
> *ARDATRON forged GLITCHICONS from code, chaos, and conviction.*
> *Not to construct. To expose.*
