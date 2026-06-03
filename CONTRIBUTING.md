# Contributing to GLITCHICONS ⬡

Thank you for your interest in contributing to GLITCHICONS!
This project is built in public, MIT licensed, and welcomes contributors of all skill levels.

---

## Contributor Ranks

```
RECRUIT    → First PR merged
OPERATIVE  → 5 PRs merged
COMMANDER  → 15 PRs merged + module ownership
WARLORD    → Core maintainer
```

---

## Quick Start for Contributors

### 1. Fork & Clone

```bash
git clone https://github.com/YOUR_USERNAME/glitchicons.git
cd glitchicons
```

### 2. Set Up Dev Environment

```bash
# Python venv
python3 -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .\.venv\Scripts\Activate.ps1     # Windows PowerShell

# Install all dependencies + dev tools
pip install -e ".[dev]"
pip install grpcio grpcio-reflection dnspython websocket-client

# Optional: Web Dashboard
pip install fastapi uvicorn
```

### 3. Verify Setup

```bash
# Run test suite (should be 1131 passed, 0 failures)
pytest tests/ -q --tb=short

# Lint
ruff check .

# Security scan
bandit -r glitchicons/ modules/ -x tests -ll -q
```

### 4. Build Go Binaries (optional)

```bash
cd glitchsmb  && go build -o ../bin/glitchsmb  . && cd ..
cd glitchssh  && go build -o ../bin/glitchssh  . && cd ..
cd glitchrdp  && go build -o ../bin/glitchrdp  . && cd ..
# repeat for glitchrace, glitchscan, glitchfuzz, glitchdns, glitchtls, glitchproxy
```

---

## Development Workflow

### Branch Naming

```
feature/module-name       # new feature or module
fix/bug-description       # bug fix
test/module-name          # add/improve tests
docs/page-name            # documentation update
refactor/module-name      # refactor without new features
```

### Commit Message Format

```
type(scope): short description

feat(saml): add signature wrapping (XSW) attack
fix(cloud): handle S3 XML namespace in listing parse
test(pkce): add weak code_verifier test cases
docs(readme): update Go binary build instructions
refactor(async): extract rate limiter to separate class
```

### Pull Request Process

1. **Create a branch** from `main`
2. **Write tests** for new code — required for all new modules
3. **Run** `pytest tests/` — all tests must pass
4. **Run** `ruff check .` — no lint errors
5. **Push** to your fork
6. **Open a PR** to `main` with a clear description

**PR Requirements:**
- All existing tests must pass (1131+, 0 failures)
- New modules must include unit tests
- Mock all HTTP calls — no real network calls in unit tests
- Follow existing module structure (see below)

**Review SLA:** PRs reviewed within 72 hours.

---

## Adding a New Python Module

Standard structure for a new module:

```python
# modules/category/module_name.py

"""
Module Name — Short description.

Usage:
    from modules.category.module_name import ModuleName
    findings = ModuleName(target="https://target.com").run()

Author: your-username
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
from rich.console import Console

console = Console()


def _finding(title, severity, cvss, cwe, description, evidence, remediation, target, source="module_name"):
    assert severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    assert 0.0 <= cvss <= 10.0
    assert cwe.startswith("CWE-")
    return {
        "title": title, "severity": severity, "cvss": cvss, "cwe": cwe,
        "target": target, "description": description, "evidence": evidence,
        "remediation": remediation, "source": f"module:{source}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


class ModuleName:
    """Module description."""

    def __init__(self, target: str, output_dir: str = "./findings"):
        self.target     = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.client     = httpx.Client(timeout=10, verify=False)

    def run(self) -> list[dict]:
        """Main entry point. Returns list of findings."""
        console.print(f"\n  [bold cyan]ModuleName[/bold cyan] → {self.target}")
        findings = []
        # ... your logic here
        self._save(findings)
        return findings

    def _save(self, findings: list[dict]) -> Path:
        out = self.output_dir / f"module_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps({"target": self.target, "findings": findings}, indent=2))
        return out
```

And the test file:

```python
# tests/test_module_name.py

import pytest
from unittest.mock import patch, MagicMock
from modules.category.module_name import ModuleName, _finding


class TestFinding:

    @pytest.mark.unit
    def test_valid_finding(self):
        f = _finding("T", "HIGH", 7.5, "CWE-89", "d", "e", "r", "t")
        assert f["severity"] == "HIGH"

    @pytest.mark.unit
    def test_invalid_severity_raises(self):
        with pytest.raises(AssertionError):
            _finding("T", "INVALID", 7.5, "CWE-89", "d", "e", "r", "t")


class TestModuleName:

    @pytest.fixture
    def module(self, tmp_path):
        return ModuleName(target="https://target.com", output_dir=str(tmp_path))

    @pytest.mark.unit
    def test_init(self, module):
        assert "target.com" in module.target

    @pytest.mark.unit
    def test_run_returns_list(self, module):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "{}"
        with patch.object(module.client, "get", return_value=mock_resp):
            findings = module.run()
        assert isinstance(findings, list)
```

---

## Adding a Go Binary

New Go binaries go in their own directory at the project root (e.g. `glitchxxx/`).

**Requirements:**
- `main.go` + `go.mod` (Go 1.22+)
- Standard library preferred; minimal external dependencies
- `--version` flag returning `glitchxxx v<VERSION>`
- JSON output with `findings` array matching the finding schema
- Flags: `--target`, `--timeout`, `--output`, `--verbose`, `--version`

See `glitchsmb/`, `glitchssh/`, `glitchrdp/` for reference implementations.

---

## Test Guidelines

**Required for every PR touching a module:**

- Unit test for happy path
- Unit test for error/edge cases  
- Mock all HTTP calls (use `unittest.mock`)
- No real network calls in unit tests

**Available markers:**

```python
@pytest.mark.unit         # pure unit test, no external dependencies
@pytest.mark.integration  # requires network or external tools
@pytest.mark.slow         # takes > 10 seconds
```

Run only unit tests:
```bash
pytest tests/ -m unit -q
```

---

## Good First Issues

Check the [`good-first-issue`](https://github.com/ardanov96/glitchicons/issues?q=label%3Agood-first-issue) label on GitHub Issues.

Good starting points:
- Add new payload patterns to existing detectors
- Improve error messages in existing modules
- Add missing test cases for edge conditions
- Fix typos in documentation
- Add usage examples to README

---

## Code Style

- **Linter**: ruff (configured in `pyproject.toml`)
- **Line length**: 100 characters
- **Type hints**: required for public methods
- **Docstrings**: at minimum one line per class and public method
- **Comments**: English only

---

## Security Issues

If you find a security issue in GLITCHICONS itself,
**do not open a public issue**. See [SECURITY.md](SECURITY.md).

---

## Need Help?

- 🐛 Bug? → [Open Issue](https://github.com/ardanov96/glitchicons/issues)
- 💡 Idea? → [Start Discussion](https://github.com/ardanov96/glitchicons/discussions)
- 📧 Direct? → ardanov96@gmail.com

---

*Where others probe, we siege. — ARDATRON*
