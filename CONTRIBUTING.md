# Contributing to Glitchicons

> Where others probe, we siege. — ARDATRON

Thank you for contributing to Glitchicons. This guide covers everything you need to submit a quality pull request — whether you're adding a Python module, a Go binary, or fixing a bug.

---

## Table of Contents

- [Setup](#setup)
- [Project Structure](#project-structure)
- [Contributing a Python Module](#contributing-a-python-module)
- [Contributing a Go Binary](#contributing-a-go-binary)
- [Tests](#tests)
- [Pull Request Requirements](#pull-request-requirements)
- [Contributor Ranks](#contributor-ranks)
- [Code of Conduct](#code-of-conduct)

---

## Setup

```bash
git clone https://github.com/ardanov96/glitchicons.git
cd glitchicons

python3 -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .\.venv\Scripts\Activate.ps1  # Windows

pip install -e ".[dev]"
pytest tests/ -q
# Expected: 1757 passed, 0 failures
```

Go binaries (optional — only if contributing to Go layer):

```bash
# Go 1.22+ required
go version

# Build any binary
cd glitchscan && go build -ldflags="-s -w" -o ../bin/glitchscan . && cd ..
.\bin\glitchscan.exe --version  # Windows
./bin/glitchscan --version      # Linux/macOS
```

---

## Project Structure

```
glitchicons/
├── modules/               # Python modules
│   ├── inject/            # Web attack modules
│   ├── recon/             # Reconnaissance
│   ├── intelligence/      # LLM + threat intel
│   ├── auth/              # Authentication attacks
│   ├── cloud/             # Cloud security
│   ├── report/            # Reporting + compliance
│   └── core/              # Platform (DB, scheduler, webhooks)
├── tests/                 # Pytest test suite (1757 tests)
├── bin/                   # Compiled Go binaries
├── glitchscan/            # Go binary source (one dir per binary)
├── glitchsmb/
├── ...
├── .github/workflows/     # CI/CD (test + build + release)
└── README.md
```

---

## Contributing a Python Module

### 1. Create the module

```python
# modules/inject/my_module.py

from dataclasses import dataclass, field
from typing import Optional
import httpx

@dataclass
class MyModuleResult:
    target: str
    findings: list = field(default_factory=list)
    errors: list   = field(default_factory=list)

class MyModule:
    """
    One-line description of what this module does.

    Args:
        target: Target URL or host
        timeout: Request timeout in seconds
    """

    def __init__(self, target: str, timeout: int = 10):
        self.target  = target
        self.timeout = timeout

    def run(self) -> MyModuleResult:
        result = MyModuleResult(target=self.target)
        # ... implementation
        return result
```

### 2. Write tests

```python
# tests/test_my_module.py
import pytest
from modules.inject.my_module import MyModule, MyModuleResult

class TestMyModule:
    def test_init(self):
        m = MyModule("https://example.com")
        assert m.target == "https://example.com"
        assert m.timeout == 10

    def test_run_returns_result(self):
        m = MyModule("https://example.com")
        result = m.run()
        assert isinstance(result, MyModuleResult)
        assert isinstance(result.findings, list)

    def test_finding_structure(self):
        # If your module produces findings, verify structure
        m = MyModule("https://example.com")
        result = m.run()
        for f in result.findings:
            assert "title" in f
            assert "severity" in f
            assert f["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
```

**Minimum test coverage: 3 tests per module.**

---

## Contributing a Go Binary

### 1. Create the binary directory

```bash
mkdir glitchmynew
cd glitchmynew
```

### 2. go.mod (standard library only preferred)

```
module glitchmynew

go 1.22
```

### 3. main.go template

```go
// glitchmynew/main.go
// GLITCHICONS — One-line description
//
// Longer description of what this binary does,
// what protocols it tests, and what findings it produces.
//
// Usage:
//   glitchmynew --target https://target.com --output findings.json
//   glitchmynew --version

package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "os"
    "time"
)

const Version = "5.5.0" // use current platform version

type Finding struct {
    Title       string  `json:"title"`
    Severity    string  `json:"severity"`   // CRITICAL|HIGH|MEDIUM|LOW|INFO
    CVSS        float64 `json:"cvss"`
    CWE         string  `json:"cwe"`
    Target      string  `json:"target"`
    Description string  `json:"description"`
    Evidence    string  `json:"evidence"`
    Remediation string  `json:"remediation"`
    Source      string  `json:"source"`     // "module:glitchmynew"
}

type ScanResult struct {
    Target    string    `json:"target"`
    Timestamp string    `json:"timestamp"`
    Findings  []Finding `json:"findings"`
    Version   string    `json:"scanner_version"`
}

func scan(target string) ScanResult {
    result := ScanResult{
        Target:    target,
        Timestamp: time.Now().UTC().Format(time.RFC3339),
        Findings:  []Finding{},
        Version:   Version,
    }
    // ... implementation
    return result
}

func main() {
    target  := flag.String("target",  "", "Target URL or host (required)")
    output  := flag.String("output",  "", "Output JSON file")
    verbose := flag.Bool("verbose",   false, "Verbose output")
    ver     := flag.Bool("version",   false, "Print version")
    flag.Parse()

    if *ver {
        fmt.Printf("glitchmynew v%s\n", Version)
        os.Exit(0)
    }
    if *target == "" {
        fmt.Fprintln(os.Stderr, "Usage: glitchmynew --target <target>")
        os.Exit(1)
    }

    _ = verbose
    result := scan(*target)

    data, _ := json.MarshalIndent(result, "", "  ")
    if *output != "" {
        os.WriteFile(*output, data, 0644)
        fmt.Printf("[+] Saved to %s\n", *output)
    } else {
        fmt.Println(string(data))
    }
}
```

### 4. Register in glitchd

Add your binary to `glitchd/main.go` → `BinaryRegistry`:

```go
"glitchmynew": {
    Name:        "glitchmynew",
    Protocol:    "HTTP",
    Description: "One-line description",
    Flags:       []string{"--target", "--timeout", "--output"},
    Category:    "recon",   // recon|protocol|exploit|fuzz|credentials|cloud|iot|etc
    Tier:        "4",
    Since:       "v5.6",
},
```

### 5. Required flags

Every Go binary **must** support:

| Flag | Description |
|------|-------------|
| `--target` | Target host or URL |
| `--output` | JSON output file path |
| `--verbose` | Verbose logging |
| `--version` | Print version string and exit |

### 6. Required output schema

```json
{
  "target": "https://example.com",
  "timestamp": "2026-06-10T00:00:00Z",
  "findings": [
    {
      "title": "Descriptive finding title",
      "severity": "HIGH",
      "cvss": 7.5,
      "cwe": "CWE-200",
      "target": "https://example.com",
      "description": "What was found and why it matters",
      "evidence": "Raw output / response excerpt proving the finding",
      "remediation": "Specific fix recommendation",
      "source": "module:glitchmynew"
    }
  ],
  "scanner_version": "5.5.0"
}
```

---

## Tests

Run the full test suite before submitting:

```bash
# All tests
pytest tests/ -q --tb=short

# Specific module
pytest tests/test_my_module.py -v

# Coverage (optional but appreciated)
pytest tests/ --cov=modules --cov-report=term-missing -q
```

**CI will fail if any test fails.** All 1757 existing tests must still pass after your change.

---

## Pull Request Requirements

Before opening a PR, verify:

- [ ] `pytest tests/ -q` passes (0 failures)
- [ ] New module has ≥3 tests
- [ ] Go binary compiles: `go build -ldflags="-s -w" -o bin/glitchmynew .`
- [ ] `--version` flag works and prints correct version
- [ ] JSON output matches standard Finding schema
- [ ] Registered in `glitchd/main.go` BinaryRegistry
- [ ] PR title follows: `feat:`, `fix:`, `docs:`, `ci:`, `refactor:`

### PR template

```
## What does this PR do?
Brief description.

## Type
- [ ] New Python module
- [ ] New Go binary
- [ ] Bug fix
- [ ] Documentation

## Testing
- Tests added: N
- All 1757 existing tests pass: ✅

## Checklist
- [ ] --version flag works
- [ ] JSON output matches Finding schema
- [ ] Registered in glitchd BinaryRegistry (Go binary only)
```

---

## Contributor Ranks

| Rank | Requirement |
|------|-------------|
| **RECRUIT** | First PR merged |
| **OPERATIVE** | 5 PRs merged |
| **COMMANDER** | 15 PRs merged + module ownership |
| **WARLORD** | Core maintainer (invited) |

---

## Code of Conduct

- Glitchicons is for **authorized security testing only**
- Do not submit modules that enable unauthorized access
- All offensive capabilities must include ethical use documentation
- Be respectful in code reviews and discussions
- Security vulnerabilities in Glitchicons itself → see [SECURITY.md](SECURITY.md)

---

Questions? Open a GitHub Discussion or reach out at ardanov96@gmail.com.
