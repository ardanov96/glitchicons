"""
GLITCHICONS ⬡ — Crash Triage Module
Decepticons Siege Division

Takes AFL++ crash files →
runs GDB analysis →
sends to LLM for classification →
generates CVE-style report
"""

import os
import re
import json
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

console = Console()

# ── SEVERITY MAPPING ────────────────────────────────────────────────────────

SIGNAL_MAP = {
    "6":  ("SIGABRT",  "HIGH",     "Abort — buffer overflow or assertion"),
    "11": ("SIGSEGV",  "CRITICAL", "Segmentation fault — invalid memory access"),
    "4":  ("SIGILL",   "HIGH",     "Illegal instruction"),
    "8":  ("SIGFPE",   "MEDIUM",   "Floating point exception / division by zero"),
    "7":  ("SIGBUS",   "HIGH",     "Bus error — misaligned memory access"),
    "5":  ("SIGTRAP",  "MEDIUM",   "Trace trap"),
}

VULN_PATTERNS = {
    r"buffer overflow":      ("CWE-121", "Stack-based Buffer Overflow"),
    r"strcpy|strcat|gets":   ("CWE-676", "Use of Potentially Dangerous Function"),
    r"heap.*corrupt":        ("CWE-122", "Heap-based Buffer Overflow"),
    r"use.after.free":       ("CWE-416", "Use After Free"),
    r"null.*deref|nullptr":  ("CWE-476", "NULL Pointer Dereference"),
    r"integer.*overflow":    ("CWE-190", "Integer Overflow"),
    r"format.*string":       ("CWE-134", "Uncontrolled Format String"),
    r"double.*free":         ("CWE-415", "Double Free"),
}

LLM_TRIAGE_PROMPT = """You are a security vulnerability analyst.
Analyze this crash report from a fuzzing session and provide:

1. VULNERABILITY TYPE (e.g., Stack Buffer Overflow, Use-After-Free)
2. ROOT CAUSE (1 sentence)
3. IMPACT (what an attacker could do)
4. CVSS SCORE ESTIMATE (0.0-10.0)
5. REMEDIATION (specific code fix)

Crash details:
{crash_details}

GDB backtrace:
{backtrace}

Crash input (hex):
{crash_input_hex}

Respond in this exact format:
VULN_TYPE: <type>
ROOT_CAUSE: <cause>
IMPACT: <impact>
CVSS: <score>
REMEDIATION: <fix>"""


# ── CRASH TRIAGE CLASS ───────────────────────────────────────────────────────

class CrashTriage:
    """
    Automated crash analysis using GDB + LLM.
    
    Processes AFL++ crash files, extracts GDB analysis,
    classifies vulnerabilities, and generates CVE-style reports.
    """

    def __init__(
        self,
        target_binary: str,
        crash_dir: str,
        output_dir: str = "./reports",
        model: str = "qwen2.5-coder:3b",
    ):
        self.target = Path(target_binary)
        self.crash_dir = Path(crash_dir)
        self.output_dir = Path(output_dir)
        self.model = model
        self.output_dir.mkdir(parents=True, exist_ok=True)

        if not self.target.exists():
            raise FileNotFoundError(f"Target binary not found: {target_binary}")

    def _get_crash_files(self) -> list[Path]:
        """Get all crash files from AFL++ output directory."""
        if not self.crash_dir.exists():
            return []
        files = [
            f for f in self.crash_dir.iterdir()
            if f.is_file() and f.name.startswith("id:")
        ]
        return sorted(files)

    def _parse_crash_filename(self, path: Path) -> dict:
        """Extract metadata from AFL++ crash filename."""
        # Format: id:000000,sig:06,src:000010,time:2640,execs:1285,op:havoc,rep:8
        meta = {}
        for part in path.name.split(","):
            if ":" in part:
                k, v = part.split(":", 1)
                meta[k] = v
        return meta

    def _run_gdb(self, crash_file: Path) -> dict:
        """Run GDB on crash file, extract backtrace and registers."""
        if not shutil.which("gdb"):
            return {"error": "GDB not found"}

        gdb_script = f"""
set pagination off
set logging enabled off
run {crash_file}
bt full
info registers
x/32xb $rsp
quit
"""
        try:
            result = subprocess.run(
                ["gdb", "-batch", "-ex", f"run {crash_file}",
                 "-ex", "bt", "-ex", "info registers",
                 str(self.target)],
                capture_output=True,
                text=True,
                timeout=30
            )
            output = result.stdout + result.stderr

            # Extract backtrace
            bt_match = re.search(r"(#0.*?)(?:\nrax|\Z)", output, re.DOTALL)
            backtrace = bt_match.group(1).strip() if bt_match else output[:2000]

            # Extract signal
            sig_match = re.search(r"signal (\w+), (\w+)", output, re.IGNORECASE)
            signal = sig_match.group(2) if sig_match else "UNKNOWN"

            # Extract crash location
            loc_match = re.search(r"at (.+\.c:\d+)", output)
            location = loc_match.group(1) if loc_match else "unknown"

            return {
                "backtrace": backtrace,
                "signal": signal,
                "location": location,
                "raw_output": output[:3000]
            }
        except subprocess.TimeoutExpired:
            return {"error": "GDB timeout"}
        except Exception as e:
            return {"error": str(e)}

    def _classify_vuln(self, gdb_output: dict) -> dict:
        """Classify vulnerability from GDB output using pattern matching."""
        bt = gdb_output.get("backtrace", "").lower()
        raw = gdb_output.get("raw_output", "").lower()
        combined = bt + raw

        cwe = "CWE-Unknown"
        vuln_type = "Unknown Vulnerability"

        for pattern, (cwe_id, vtype) in VULN_PATTERNS.items():
            if re.search(pattern, combined, re.IGNORECASE):
                cwe = cwe_id
                vuln_type = vtype
                break

        signal_num = gdb_output.get("signal", "")
        sig_info = SIGNAL_MAP.get(
            re.search(r"\d+", signal_num).group() if re.search(r"\d+", signal_num) else "",
            ("UNKNOWN", "MEDIUM", "Unknown signal")
        )

        return {
            "cwe": cwe,
            "vuln_type": vuln_type,
            "signal": sig_info[0],
            "severity": sig_info[1],
            "signal_desc": sig_info[2],
        }

    def _query_llm(self, crash_file: Path, gdb_data: dict, vuln_class: dict) -> dict:
        """Send crash details to LLM for deep analysis."""
        if not OLLAMA_AVAILABLE:
            return {"error": "ollama not installed"}

        # Read crash input
        try:
            crash_bytes = crash_file.read_bytes()[:512]
            crash_hex = crash_bytes.hex()
            crash_preview = crash_bytes.decode("utf-8", errors="replace")[:200]
        except Exception:
            crash_hex = "unreadable"
            crash_preview = "unreadable"

        crash_details = (
            f"Signal: {vuln_class['signal']} ({vuln_class['signal_desc']})\n"
            f"Location: {gdb_data.get('location', 'unknown')}\n"
            f"Initial classification: {vuln_class['vuln_type']} ({vuln_class['cwe']})\n"
            f"Crash input preview: {crash_preview}"
        )

        prompt = LLM_TRIAGE_PROMPT.format(
            crash_details=crash_details,
            backtrace=gdb_data.get("backtrace", "not available")[:1500],
            crash_input_hex=crash_hex[:200]
        )

        try:
            response = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0.2, "num_predict": 1024}
            )
            raw = response["message"]["content"]

            # Parse structured response
            result = {}
            for field in ["VULN_TYPE", "ROOT_CAUSE", "IMPACT", "CVSS", "REMEDIATION"]:
                match = re.search(rf"{field}:\s*(.+?)(?:\n[A-Z_]+:|$)", raw, re.DOTALL)
                result[field.lower()] = match.group(1).strip() if match else "N/A"

            return result
        except Exception as e:
            return {"error": str(e)}

    def _generate_report(
        self,
        crash_file: Path,
        meta: dict,
        gdb_data: dict,
        vuln_class: dict,
        llm_analysis: dict,
    ) -> str:
        """Generate markdown CVE-style report."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        crash_id = meta.get("id", "000000")

        # Read crash input
        try:
            crash_input = crash_file.read_bytes().decode("utf-8", errors="replace")[:300]
        except Exception:
            crash_input = "unreadable"

        severity = vuln_class.get("severity", "MEDIUM")
        cvss = llm_analysis.get("cvss", "N/A")

        report = f"""# GLITCHICONS ⬡ Vulnerability Report
**Generated:** {timestamp}  
**Tool:** Glitchicons v0.2.0-dev — Decepticons Siege Division  

---

## Summary

| Field | Value |
|-------|-------|
| **Crash ID** | {crash_id} |
| **Severity** | {severity} |
| **CVSS Score** | {cvss} |
| **Signal** | {vuln_class.get('signal', 'UNKNOWN')} — {vuln_class.get('signal_desc', '')} |
| **CWE** | {vuln_class.get('cwe', 'Unknown')} |
| **Location** | {gdb_data.get('location', 'unknown')} |
| **AFL++ Source** | seed {meta.get('src', '?')} via {meta.get('op', '?')} |

---

## Vulnerability Details

**Type:** {llm_analysis.get('vuln_type', vuln_class.get('vuln_type', 'Unknown'))}

**Root Cause:**  
{llm_analysis.get('root_cause', 'Analysis pending')}

**Impact:**  
{llm_analysis.get('impact', 'Analysis pending')}

---

## Crash Input

```
{crash_input}
```

---

## GDB Backtrace

```
{gdb_data.get('backtrace', 'Not available')[:1500]}
```

---

## Remediation

{llm_analysis.get('remediation', 'Review the crash location and fix the root cause.')}

---

## Reproduction

```bash
# Reproduce crash:
{self.target} {crash_file}

# GDB analysis:
gdb -batch -ex "run {crash_file}" -ex "bt" -ex "info registers" {self.target}
```

---

*Report generated by GLITCHICONS ⬡ — Where others probe, we siege.*
"""
        return report

    def run(self, max_crashes: int = 10) -> list[Path]:
        """
        Run full triage pipeline on all crash files.
        
        Returns list of generated report paths.
        """
        crash_files = self._get_crash_files()

        if not crash_files:
            console.print(f"[yellow]⚠ No crash files found in {self.crash_dir}[/yellow]")
            return []

        console.print(Panel(
            f"[bold purple]⬡ CRASH TRIAGE[/bold purple]\n\n"
            f"[dim]Target  :[/dim] {self.target}\n"
            f"[dim]Crashes :[/dim] {len(crash_files)} files\n"
            f"[dim]Model   :[/dim] {self.model}\n"
            f"[dim]Output  :[/dim] {self.output_dir}",
            border_style="purple"
        ))

        reports = []
        process_count = min(len(crash_files), max_crashes)

        for i, crash_file in enumerate(crash_files[:process_count]):
            console.print(f"\n[purple]⬡ Triaging crash {i+1}/{process_count}:[/purple] {crash_file.name}")

            # 1. Parse metadata
            meta = self._parse_crash_filename(crash_file)

            # 2. GDB analysis
            with Progress(SpinnerColumn(style="purple"),
                          TextColumn("[dim]{task.description}"),
                          console=console) as p:
                t = p.add_task("Running GDB analysis...", total=None)
                gdb_data = self._run_gdb(crash_file)
                p.update(t, description="GDB done")

            if "error" in gdb_data:
                console.print(f"  [red]✗ GDB error: {gdb_data['error']}[/red]")
                continue

            # 3. Pattern-based classification
            vuln_class = self._classify_vuln(gdb_data)
            console.print(
                f"  [green]✓[/green] {vuln_class['vuln_type']} "
                f"[dim]({vuln_class['cwe']})[/dim] "
                f"— severity: [{'red' if vuln_class['severity']=='CRITICAL' else 'yellow'}]"
                f"{vuln_class['severity']}[/]"
            )

            # 4. LLM deep analysis
            with Progress(SpinnerColumn(style="purple"),
                          TextColumn("[dim]{task.description}"),
                          console=console) as p:
                t = p.add_task("LLM analysis...", total=None)
                llm_data = self._query_llm(crash_file, gdb_data, vuln_class)
                p.update(t, description="LLM done")

            # 5. Generate report
            report_md = self._generate_report(crash_file, meta, gdb_data, vuln_class, llm_data)
            report_path = self.output_dir / f"crash_{meta.get('id', str(i).zfill(6))}_report.md"
            report_path.write_text(report_md)
            reports.append(report_path)
            console.print(f"  [green]✓[/green] Report saved: {report_path.name}")

        # Summary table
        if reports:
            console.print(f"\n[bold green]⬡ TRIAGE COMPLETE — {len(reports)} reports generated[/bold green]")
            console.print(f"[dim]Reports in: {self.output_dir}[/dim]\n")

        return reports


# ── STANDALONE TEST ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/target")
    crash_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.expanduser(
        "~/glitchicons/findings/default/crashes"
    )

    triage = CrashTriage(
        target_binary=target,
        crash_dir=crash_dir,
        output_dir="./reports",
        model="qwen2.5-coder:3b",
    )
    triage.run()
