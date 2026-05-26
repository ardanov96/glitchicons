# Contributing to GLITCHICONS ⬡

Terima kasih sudah tertarik berkontribusi ke GLITCHICONS!
Project ini dibangun di publik, MIT licensed, dan semua skill level welcome.

---

## Contributor Ranks

```
RECRUIT    → PR pertama merged
OPERATIVE  → 5 PR merged
COMMANDER  → 15 PR merged + module ownership
WARLORD    → Core maintainer
```

---

## Quick Start untuk Contributor

### 1. Fork & Clone

```bash
git clone https://github.com/YOUR_USERNAME/glitchicons.git
cd glitchicons
```

### 2. Setup Dev Environment

```bash
# Python venv
python3 -m venv .venv
source .venv/bin/activate          # Linux/Mac
# .venv\Scripts\Activate.ps1       # Windows PowerShell

# Install semua dependencies + dev tools
pip install -e ".[dev]"
```

### 3. Verifikasi Setup

```bash
# Jalankan test suite
pytest tests/ -v

# Cek code style
ruff check .

# Cek security issues
bandit -r . -x .venv,tests
```

---

## Development Workflow

### Branch Naming

```
feature/nama-fitur          # fitur baru
fix/deskripsi-bug           # bug fix
test/nama-module            # tambah tests
docs/nama-halaman           # dokumentasi
refactor/nama-modul         # refactor tanpa fitur baru
```

### Commit Message Format

```
type(scope): deskripsi singkat

feat(jwt): tambah RS256→HS256 algorithm confusion
fix(brute): handle lockout detection false positive
test(sqli): tambah time-based blind test cases
docs(readme): update installation steps
refactor(recon): extract http probing ke fungsi terpisah
```

### Pull Request Process

1. **Buat branch** dari `main`
2. **Tulis tests** untuk kode baru (wajib untuk modul baru)
3. **Jalankan** `pytest tests/` — semua harus pass
4. **Jalankan** `ruff check .` — tidak boleh ada error
5. **Push** ke fork kamu
6. **Buat PR** ke `main` dengan description yang jelas

---

## Menambah Module Baru

Struktur standar untuk module baru:

```python
# modules/category/nama_module.py

"""
Nama Module — Deskripsi singkat.

Usage:
    python glitchicons.py nama-command --target https://target.com

Author: username
"""

import httpx
from rich.console import Console

console = Console()


class NamaModule:
    """Deskripsi class."""

    def __init__(self, target: str, output_dir: str = "./findings"):
        self.target = target
        self.output_dir = output_dir
        self.findings = []

    def run(self) -> list[dict]:
        """Entry point utama. Return list of findings."""
        console.print(f"[cyan]⬡ Scanning {self.target}...[/cyan]")
        # ... logic di sini
        return self.findings

    def _generate_finding(self, title: str, severity: str, cvss: float, **kwargs) -> dict:
        """Buat finding object standar."""
        return {
            "title": title,
            "severity": severity,
            "cvss": cvss,
            "target": self.target,
            **kwargs,
        }
```

Dan test-nya:

```python
# tests/test_nama_module.py

import pytest

class TestNamaModule:

    @pytest.mark.unit
    def test_something(self):
        assert True  # replace dengan test nyata
```

---

## Test Guidelines

### Wajib untuk setiap PR yang touch modul:

- Unit test untuk happy path
- Unit test untuk error/edge case
- Mock semua HTTP calls (gunakan `responses` library)
- Tidak boleh hit network nyata di unit tests

### Marker yang tersedia:

```python
@pytest.mark.unit         # pure unit test, tidak butuh external tools
@pytest.mark.integration  # butuh network/tools external
@pytest.mark.slow         # test yang lama
```

Jalankan hanya unit tests:
```bash
pytest tests/ -m unit -v
```

---

## Good First Issues

Lihat label [`good-first-issue`](https://github.com/ardanov96/glitchicons/issues?q=label%3Agood-first-issue) di GitHub Issues.

Contoh kontribusi yang cocok untuk pemula:
- Tambah payload baru ke wordlist
- Improve error messages di module yang ada
- Tambah test case yang belum ada
- Fix typo di dokumentasi
- Tambah contoh penggunaan ke README

---

## Code Style

- **Formatter**: Black-compatible (ruff format)
- **Line length**: 100 karakter
- **Type hints**: wajib untuk public methods
- **Docstrings**: minimal satu baris untuk setiap class dan public method
- **Bahasa**: komentar boleh Bahasa Indonesia atau English

---

## Security Issues

Jika kamu menemukan security issue di GLITCHICONS itu sendiri,
**jangan buat public issue**. Lihat [SECURITY.md](SECURITY.md).

---

## Butuh Bantuan?

- 🐛 Bug? → [Open Issue](https://github.com/ardanov96/glitchicons/issues)
- 💡 Ide? → [Start Discussion](https://github.com/ardanov96/glitchicons/discussions)
- 📧 Direct? → ardanov96@gmail.com

---

*Where others probe, we siege. — ARDATRON*
