"""
GLITCHICONS ⬡ — Auto Report Export Module
Decepticons Siege Division

Transforms raw crash triage data into professional
vulnerability reports ready for:
- HackerOne submission
- Bugcrowd submission  
- Internal security audit (PDF/DOCX style)
- CVE disclosure draft

Pipeline:
  crash_triage output + CFG analysis + protocol findings
  → LLM enrichment
  → structured report (Markdown + JSON)
  → platform-specific format
"""

import re
import json
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

console = Console()


# ══════════════════════════════════════════════════════════════════════════════
# CVSS CALCULATOR (v3.1)
# ══════════════════════════════════════════════════════════════════════════════

class CVSSCalculator:
    """
    Simplified CVSS v3.1 score calculation.
    
    Metrics derived from crash type and vulnerability class.
    """

    # Base metric weights
    AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}  # Attack Vector
    AC = {"L": 0.77, "H": 0.44}                           # Attack Complexity
    PR = {"N": 0.85, "L": 0.62, "H": 0.27}               # Privileges Required
    UI = {"N": 0.85, "R": 0.62}                           # User Interaction
    S  = {"U": False, "C": True}                           # Scope
    C  = {"N": 0.00, "L": 0.22, "H": 0.56}               # Confidentiality
    I  = {"N": 0.00, "L": 0.22, "H": 0.56}               # Integrity
    A  = {"N": 0.00, "L": 0.22, "H": 0.56}               # Availability

    # Preset profiles by vulnerability type
    VULN_PROFILES = {
        "Stack-based Buffer Overflow": {
            "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "score": 9.8, "severity": "CRITICAL"
        },
        "Heap-based Buffer Overflow": {
            "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "score": 8.1, "severity": "HIGH"
        },
        "Use After Free": {
            "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "score": 8.1, "severity": "HIGH"
        },
        "NULL Pointer Dereference": {
            "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "score": 7.5, "severity": "HIGH"
        },
        "Integer Overflow": {
            "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "score": 9.8, "severity": "CRITICAL"
        },
        "Format String": {
            "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "score": 9.8, "severity": "CRITICAL"
        },
        "SQL Injection": {
            "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "score": 9.8, "severity": "CRITICAL"
        },
        "Command Injection": {
            "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "score": 9.8, "severity": "CRITICAL"
        },
        "Authentication Bypass": {
            "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "score": 9.8, "severity": "CRITICAL"
        },
        "Server Error": {
            "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H",
            "score": 8.2, "severity": "HIGH"
        },
        "default": {
            "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "score": 7.3, "severity": "HIGH"
        }
    }

    @classmethod
    def get_score(cls, vuln_type: str) -> dict:
        """Get CVSS score for a vulnerability type."""
        # Fuzzy match
        for key, profile in cls.VULN_PROFILES.items():
            if key.lower() in vuln_type.lower() or \
               vuln_type.lower() in key.lower():
                return profile
        return cls.VULN_PROFILES["default"]

    @classmethod
    def severity_from_score(cls, score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "INFORMATIONAL"


# ══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY DATA CLASS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class VulnerabilityReport:
    """Complete vulnerability report data."""

    # Core info
    title: str = ""
    vuln_type: str = ""
    cwe: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    severity: str = ""

    # Discovery
    discovered_by: str = "ARDATRON via GLITCHICONS ⬡"
    discovery_method: str = "AI-powered fuzzing (AFL++ + LLM seed generation)"
    discovery_date: str = field(
        default_factory=lambda: datetime.now().strftime("%Y-%m-%d")
    )

    # Technical details
    target: str = ""
    affected_function: str = ""
    affected_file: str = ""
    crash_signal: str = ""
    crash_input: str = ""
    backtrace: str = ""

    # Analysis
    root_cause: str = ""
    impact: str = ""
    proof_of_concept: str = ""
    remediation: str = ""

    # Platform metadata
    program_name: str = ""
    asset_type: str = "SOURCE_CODE"

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


# ══════════════════════════════════════════════════════════════════════════════
# REPORT PARSER (reads crash_triage output)
# ══════════════════════════════════════════════════════════════════════════════

class ReportParser:
    """
    Parses Glitchicons crash_triage markdown reports
    and protocol_fuzzer finding reports into
    VulnerabilityReport objects.
    """

    def parse_crash_report(self, report_path: str) -> Optional[VulnerabilityReport]:
        """Parse a crash_triage markdown report."""
        path = Path(report_path)
        if not path.exists():
            return None

        content = path.read_text()
        report = VulnerabilityReport()

        # Extract fields from markdown table
        def extract_field(field_name: str) -> str:
            pattern = rf'\|\s*\*\*{re.escape(field_name)}\*\*\s*\|\s*(.+?)\s*\|'
            match = re.search(pattern, content)
            return match.group(1).strip() if match else ""

        # Parse severity
        sev = extract_field("Severity")
        report.severity = sev if sev else "HIGH"

        # Parse CVSS
        cvss_str = extract_field("CVSS Score")
        try:
            report.cvss_score = float(re.search(r'[\d.]+', cvss_str).group())
        except Exception:
            report.cvss_score = 7.0

        # Parse CWE
        report.cwe = extract_field("CWE")

        # Parse crash location
        loc = extract_field("Location")
        if ":" in loc:
            parts = loc.split(":")
            report.affected_file = parts[0]
            report.affected_function = parts[-1].strip() if len(parts) > 1 else ""

        # Parse signal
        report.crash_signal = extract_field("Signal")

        # Parse crash input (code block after "Crash Input")
        input_match = re.search(
            r'## Crash Input\s*```\s*(.*?)\s*```',
            content, re.DOTALL
        )
        if input_match:
            report.crash_input = input_match.group(1)[:200]

        # Parse backtrace
        bt_match = re.search(
            r'## GDB Backtrace\s*```\s*(.*?)\s*```',
            content, re.DOTALL
        )
        if bt_match:
            report.backtrace = bt_match.group(1)[:1000]

        # Parse remediation
        rem_match = re.search(
            r'## Remediation\s*\n+(.*?)(?=\n##|\Z)',
            content, re.DOTALL
        )
        if rem_match:
            report.remediation = rem_match.group(1).strip()[:500]

        # Infer vuln type from content
        vuln_patterns = [
            ("Stack-based Buffer Overflow", r"buffer overflow|strcpy|stack"),
            ("Use After Free", r"use.after.free"),
            ("NULL Pointer Dereference", r"null.pointer|sigsegv"),
            ("Format String", r"format.string|printf"),
            ("Integer Overflow", r"integer.overflow"),
        ]
        for vtype, pattern in vuln_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                report.vuln_type = vtype
                break
        if not report.vuln_type:
            report.vuln_type = "Memory Corruption"

        # Get CVSS from profile if not already set
        if report.cvss_score == 7.0:
            cvss = CVSSCalculator.get_score(report.vuln_type)
            report.cvss_score = cvss["score"]
            report.cvss_vector = cvss["vector"]
            report.severity = cvss["severity"]

        report.title = f"{report.vuln_type} in {report.affected_function or 'target'}"

        return report

    def parse_protocol_finding(self, finding: dict) -> VulnerabilityReport:
        """Convert a protocol_fuzzer finding dict to VulnerabilityReport."""
        report = VulnerabilityReport()

        report.vuln_type = finding.get("vuln_type", "Web Vulnerability")
        report.severity = finding.get("severity", "MEDIUM")
        report.target = finding.get("url", "")
        report.crash_input = finding.get("payload", "")[:200]
        report.affected_function = f"{finding.get('method', 'GET')} {finding.get('url', '')}"

        cvss = CVSSCalculator.get_score(report.vuln_type)
        report.cvss_score = cvss["score"]
        report.cvss_vector = cvss["vector"]
        if report.severity == "CRITICAL":
            report.cvss_score = max(report.cvss_score, 9.0)

        report.title = f"{report.vuln_type} — {finding.get('url', 'target')}"
        report.discovery_method = "AI-powered HTTP fuzzing (Glitchicons Protocol Fuzzer)"
        report.asset_type = "URL"

        return report


# ══════════════════════════════════════════════════════════════════════════════
# LLM ENRICHER
# ══════════════════════════════════════════════════════════════════════════════

class LLMEnricher:
    """
    Uses LLM to enrich vulnerability reports with:
    - Clear root cause explanation
    - Impact assessment
    - Proof of concept steps
    - Remediation recommendations
    """

    ENRICH_PROMPT = """You are a professional security researcher writing a bug bounty report.

Vulnerability details:
- Type: {vuln_type}
- CWE: {cwe}
- Signal: {crash_signal}
- Location: {location}
- Crash input: {crash_input}
- Backtrace snippet: {backtrace}

Write concise, professional content for each section:

ROOT_CAUSE: (1-2 sentences explaining WHY this vulnerability exists)
IMPACT: (1-2 sentences on what an attacker can achieve)
POC_STEPS: (numbered steps to reproduce the crash)
REMEDIATION: (specific code fix recommendation)

Format exactly as shown above, one section per line starting with the label."""

    def __init__(self, model: str = "qwen2.5-coder:3b"):
        self.model = model

    def enrich(self, report: VulnerabilityReport) -> VulnerabilityReport:
        """Enrich a VulnerabilityReport using LLM."""
        if not OLLAMA_AVAILABLE:
            return report

        prompt = self.ENRICH_PROMPT.format(
            vuln_type=report.vuln_type,
            cwe=report.cwe or "Unknown",
            crash_signal=report.crash_signal or "SIGABRT",
            location=f"{report.affected_file}:{report.affected_function}",
            crash_input=report.crash_input[:100] if report.crash_input else "N/A",
            backtrace=report.backtrace[:300] if report.backtrace else "N/A",
        )

        try:
            console.print("[dim]  → LLM enriching report...[/dim]")
            r = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0.2, "num_predict": 1024}
            )
            raw = r["message"]["content"]

            # Parse structured response
            sections = {
                "ROOT_CAUSE": "root_cause",
                "IMPACT": "impact",
                "POC_STEPS": "proof_of_concept",
                "REMEDIATION": "remediation",
            }
            for label, attr in sections.items():
                pattern = rf'{label}:\s*(.+?)(?=\n[A-Z_]+:|$)'
                match = re.search(pattern, raw, re.DOTALL)
                if match:
                    setattr(report, attr, match.group(1).strip())

        except Exception as e:
            console.print(f"[dim]  LLM enrichment skipped: {e}[/dim]")

        return report


# ══════════════════════════════════════════════════════════════════════════════
# REPORT FORMATTERS
# ══════════════════════════════════════════════════════════════════════════════

class HackerOneFormatter:
    """
    Formats VulnerabilityReport as HackerOne submission markdown.
    Follows HackerOne's preferred report structure.
    """

    def format(self, report: VulnerabilityReport, program: str = "") -> str:
        poc = report.proof_of_concept or \
            f"1. Compile target with AFL++ instrumentation\n" \
            f"2. Run: glitchicons seed --type binary\n" \
            f"3. Run: glitchicons fuzz ./target\n" \
            f"4. Crash reproduced with input:\n   `{report.crash_input[:100]}`"

        return f"""# {report.title}

## Summary

{report.root_cause or f'A {report.vuln_type} vulnerability was discovered in the target application via AI-powered fuzzing.'}

**Vulnerability Type:** {report.vuln_type}
**Severity:** {report.severity}
**CVSS Score:** {report.cvss_score} ({report.cvss_vector})
**CWE:** {report.cwe or 'CWE-119'}

---

## Impact

{report.impact or f'An attacker who can supply malformed input to the {report.affected_function or "target"} function may cause application crash, potentially leading to denial of service or remote code execution.'}

---

## Steps To Reproduce

{poc}

---

## Supporting Material

**Crash Signal:** `{report.crash_signal or 'SIGABRT'}`
**Affected Function:** `{report.affected_function or 'unknown'}`
**Affected File:** `{report.affected_file or 'unknown'}`

**Crash-triggering input:**
```
{report.crash_input or 'See attached crash file'}
```

**GDB Backtrace:**
```
{report.backtrace[:600] if report.backtrace else 'Not available'}
```

---

## Remediation

{report.remediation or 'Review the affected function and add proper input validation and bounds checking.'}

---

## Discovery

**Discovered by:** {report.discovered_by}
**Discovery Method:** {report.discovery_method}
**Discovery Date:** {report.discovery_date}

*Report generated by GLITCHICONS ⬡ — Decepticons Siege Division*
"""


class BugcrowdFormatter:
    """
    Formats VulnerabilityReport for Bugcrowd submission.
    Follows Bugcrowd VRT (Vulnerability Rating Taxonomy).
    """

    # Bugcrowd VRT mapping
    VRT_MAP = {
        "Stack-based Buffer Overflow":  "server_side_injection.memory_corruption.buffer_overflow",
        "Heap-based Buffer Overflow":   "server_side_injection.memory_corruption.buffer_overflow",
        "Use After Free":               "server_side_injection.memory_corruption.use_after_free",
        "NULL Pointer Dereference":     "server_side_injection.memory_corruption.null_pointer_dereference",
        "Format String":                "server_side_injection.format_string",
        "SQL Injection":                "server_side_injection.sql_injection",
        "Command Injection":            "server_side_injection.os_command_injection",
        "Authentication Bypass":        "broken_authentication_and_session_management.authentication_bypass",
        "default":                      "server_side_injection.memory_corruption",
    }

    def get_vrt(self, vuln_type: str) -> str:
        for key, vrt in self.VRT_MAP.items():
            if key.lower() in vuln_type.lower():
                return vrt
        return self.VRT_MAP["default"]

    def format(self, report: VulnerabilityReport) -> str:
        vrt = self.get_vrt(report.vuln_type)
        poc = report.proof_of_concept or \
            f"1. Run Glitchicons against target\n" \
            f"2. Crash reproduced with: `{report.crash_input[:80]}`"

        return f"""## Title
{report.title}

## VRT Classification
`{vrt}`

## CVSS
**Score:** {report.cvss_score}
**Vector:** `{report.cvss_vector}`
**Severity:** {report.severity}

## Summary
{report.root_cause or f'A {report.vuln_type} was identified in {report.affected_function or "the target"}.'}

## Asset
**Type:** {report.asset_type}
**Identifier:** `{report.target or report.affected_file or 'unknown'}`

## Steps to Reproduce
{poc}

## Impact
{report.impact or 'Denial of service or potential remote code execution.'}

## Remediation
{report.remediation or 'Add proper input validation and bounds checking.'}

## Additional Notes
- **CWE:** {report.cwe or 'CWE-119'}
- **Signal:** {report.crash_signal or 'SIGABRT'}
- **Discovery:** {report.discovery_method}
- **Date:** {report.discovery_date}

---
*Generated by GLITCHICONS ⬡ — Decepticons Siege Division*
"""


class InternalFormatter:
    """
    Formats VulnerabilityReport as a professional internal
    security audit report (suitable for sending to clients).
    """

    def format(self, report: VulnerabilityReport, org: str = "") -> str:
        sev_color_map = {
            "CRITICAL": "🔴",
            "HIGH":     "🟠",
            "MEDIUM":   "🟡",
            "LOW":      "🟢",
            "INFO":     "⚪",
        }
        icon = sev_color_map.get(report.severity, "⚪")

        return f"""# Security Vulnerability Report
## {org + ' — ' if org else ''}Penetration Test Findings

---

## Executive Summary

| Field | Detail |
|-------|--------|
| **Finding** | {report.title} |
| **Severity** | {icon} {report.severity} |
| **CVSS v3.1** | {report.cvss_score} — `{report.cvss_vector}` |
| **CWE** | {report.cwe or 'CWE-119'} |
| **Status** | Open — Remediation Required |
| **Date Found** | {report.discovery_date} |
| **Tested By** | {report.discovered_by} |

---

## Technical Description

### Vulnerability Type
**{report.vuln_type}**

### Affected Component
| Component | Value |
|-----------|-------|
| File | `{report.affected_file or 'unknown'}` |
| Function | `{report.affected_function or 'unknown'}` |
| Signal | `{report.crash_signal or 'SIGABRT'}` |

### Root Cause
{report.root_cause or f'A {report.vuln_type} vulnerability exists due to insufficient input validation in the {report.affected_function or "target"} function.'}

---

## Risk Assessment

### Impact
{report.impact or 'This vulnerability may allow an attacker to cause application crash or potentially achieve remote code execution.'}

### Likelihood
**HIGH** — The crash-triggering input was generated automatically via AI-powered fuzzing, indicating the vulnerability is reachable through normal application input channels.

---

## Proof of Concept

**Crash-triggering input:**
```
{report.crash_input[:300] if report.crash_input else 'See attached crash file'}
```

**GDB Analysis:**
```
{report.backtrace[:500] if report.backtrace else 'Not available — run: gdb -batch -ex "run <crash_file>" -ex "bt" ./target'}
```

---

## Remediation

### Recommended Fix
{report.remediation or 'Implement proper bounds checking and input validation before processing user-supplied data.'}

### General Recommendations
1. Replace unsafe functions (`strcpy`, `sprintf`, `gets`) with safe alternatives (`strncpy`, `snprintf`)
2. Enable compiler protections: `-fstack-protector-all -D_FORTIFY_SOURCE=2`
3. Enable ASLR: `echo 2 > /proc/sys/kernel/randomize_va_space`
4. Add fuzzing to CI/CD pipeline using Glitchicons

---

## Discovery Method

This vulnerability was discovered using **GLITCHICONS ⬡**, an AI-powered security research platform:

```
Tool      : GLITCHICONS v0.4.0-dev
Method    : {report.discovery_method}
Engine    : AFL++ 4.09c + LLM mutation intelligence
Duration  : Automated session
```

---

*Confidential — Prepared by ARDATRON | Decepticons Siege Division*
*For authorized recipient only*
"""


# ══════════════════════════════════════════════════════════════════════════════
# AUTO REPORT EXPORTER (main class)
# ══════════════════════════════════════════════════════════════════════════════

class AutoReportExporter:
    """
    Main interface: scans for findings → enriches → exports reports.

    Scans:
    - ./reports/*.md (crash_triage output)
    - ./protocol_findings/*.md (protocol_fuzzer output)

    Exports to:
    - HackerOne markdown
    - Bugcrowd markdown
    - Internal audit report
    - JSON summary (machine-readable)
    """

    def __init__(
        self,
        output_dir: str = "./exported_reports",
        model: str = "qwen2.5-coder:3b",
        program_name: str = "",
        org_name: str = "",
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.model = model
        self.program_name = program_name
        self.org_name = org_name

        self.parser = ReportParser()
        self.enricher = LLMEnricher(model)
        self.h1_formatter = HackerOneFormatter()
        self.bc_formatter = BugcrowdFormatter()
        self.internal_formatter = InternalFormatter()

    def _find_crash_reports(self, reports_dir: str = "./reports") -> list[Path]:
        """Find all crash triage markdown reports."""
        p = Path(reports_dir)
        if not p.exists():
            return []
        return list(p.glob("crash_*_report.md"))

    def _find_protocol_reports(
        self, findings_dir: str = "./protocol_findings"
    ) -> list[Path]:
        """Find all protocol fuzzer reports."""
        p = Path(findings_dir)
        if not p.exists():
            return []
        return list(p.glob("protocol_findings_*.md"))

    def _parse_protocol_markdown(self, report_path: Path) -> list[dict]:
        """Extract individual findings from protocol report markdown."""
        content = report_path.read_text()
        findings = []

        # Find all H3 sections (each finding)
        sections = re.split(r'\n### \d+\.', content)
        for section in sections[1:]:  # Skip header
            finding = {}
            # Extract vuln type from heading
            title_match = re.match(r'\s*(.+?)\n', section)
            if title_match:
                finding["vuln_type"] = title_match.group(1).strip()

            # Extract table values
            def get_field(field: str) -> str:
                m = re.search(rf'\|\s*\*\*{re.escape(field)}\*\*\s*\|\s*`?(.+?)`?\s*\|',
                              section)
                return m.group(1).strip() if m else ""

            finding["severity"] = get_field("Severity")
            finding["url"] = get_field("URL")
            finding["method"] = get_field("Method")
            finding["payload"] = get_field("Payload")

            if finding.get("vuln_type"):
                findings.append(finding)

        return findings

    def export_all(
        self,
        reports_dir: str = "./reports",
        protocol_dir: str = "./protocol_findings",
        formats: list[str] = None,
        enrich: bool = True,
    ) -> dict:
        """
        Find all findings, enrich, and export to all formats.

        Args:
            reports_dir    : Directory with crash_triage reports
            protocol_dir   : Directory with protocol_fuzzer reports
            formats        : ["h1", "bugcrowd", "internal", "json"]
            enrich         : Use LLM to enrich reports

        Returns:
            Summary dict with exported file paths
        """
        if formats is None:
            formats = ["h1", "bugcrowd", "internal", "json"]

        console.print(Panel(
            f"[bold purple]⬡ AUTO REPORT EXPORT[/bold purple]\n\n"
            f"[dim]Crash reports :[/dim] {reports_dir}\n"
            f"[dim]Protocol finds:[/dim] {protocol_dir}\n"
            f"[dim]Output dir    :[/dim] {self.output_dir}\n"
            f"[dim]Formats       :[/dim] {', '.join(formats)}\n"
            f"[dim]LLM enrichment:[/dim] {'enabled' if enrich else 'disabled'}",
            border_style="purple"
        ))

        all_reports: list[VulnerabilityReport] = []

        # Parse crash triage reports
        crash_files = self._find_crash_reports(reports_dir)
        console.print(f"\n[dim]→ Found {len(crash_files)} crash report(s)[/dim]")
        for cf in crash_files:
            console.print(f"  Parsing: {cf.name}")
            r = self.parser.parse_crash_report(str(cf))
            if r:
                if enrich:
                    r = self.enricher.enrich(r)
                r.program_name = self.program_name
                all_reports.append(r)

        # Parse protocol reports
        proto_files = self._find_protocol_reports(protocol_dir)
        console.print(f"[dim]→ Found {len(proto_files)} protocol report(s)[/dim]")
        for pf in proto_files:
            findings = self._parse_protocol_markdown(pf)
            console.print(f"  Parsing: {pf.name} ({len(findings)} findings)")
            for finding in findings:
                r = self.parser.parse_protocol_finding(finding)
                if enrich:
                    r = self.enricher.enrich(r)
                r.program_name = self.program_name
                all_reports.append(r)

        if not all_reports:
            console.print("[yellow]⚠ No findings to export.[/yellow]")
            console.print("[dim]  Run 'glitchicons triage' or 'glitchicons protocol' first.[/dim]")
            return {}

        console.print(f"\n[green]✓ {len(all_reports)} findings to export[/green]")

        # Export to each format
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        exported = {}

        for i, report in enumerate(all_reports, 1):
            slug = re.sub(r'[^\w]', '_', report.title)[:40].lower()
            prefix = self.output_dir / f"{i:02d}_{slug}_{timestamp}"

            self._print_finding_summary(report)

            # HackerOne
            if "h1" in formats:
                h1_path = Path(f"{prefix}_h1.md")
                h1_path.write_text(
                    self.h1_formatter.format(report, self.program_name)
                )
                exported.setdefault("hackerone", []).append(str(h1_path))

            # Bugcrowd
            if "bugcrowd" in formats:
                bc_path = Path(f"{prefix}_bugcrowd.md")
                bc_path.write_text(self.bc_formatter.format(report))
                exported.setdefault("bugcrowd", []).append(str(bc_path))

            # Internal
            if "internal" in formats:
                int_path = Path(f"{prefix}_internal.md")
                int_path.write_text(
                    self.internal_formatter.format(report, self.org_name)
                )
                exported.setdefault("internal", []).append(str(int_path))

            # JSON
            if "json" in formats:
                json_path = Path(f"{prefix}_data.json")
                json_path.write_text(json.dumps(report.to_dict(), indent=2))
                exported.setdefault("json", []).append(str(json_path))

        # Write summary
        summary = {
            "exported_at": datetime.now().isoformat(),
            "total_findings": len(all_reports),
            "severity_breakdown": {
                sev: sum(1 for r in all_reports if r.severity == sev)
                for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            },
            "files": exported,
            "tool": "GLITCHICONS ⬡ v0.4.0-dev",
        }

        summary_path = self.output_dir / f"summary_{timestamp}.json"
        summary_path.write_text(json.dumps(summary, indent=2))

        self._print_summary(summary)
        return summary

    def _print_finding_summary(self, report: VulnerabilityReport):
        """Print one-line finding summary."""
        sev_colors = {
            "CRITICAL": "red", "HIGH": "red",
            "MEDIUM": "yellow", "LOW": "cyan"
        }
        color = sev_colors.get(report.severity, "white")
        console.print(
            f"  [dim]→[/dim] [{color}]{report.severity}[/{color}] "
            f"[bold]{report.title[:60]}[/bold] "
            f"[dim](CVSS {report.cvss_score})[/dim]"
        )

    def _print_summary(self, summary: dict):
        """Print export summary table."""
        console.print(f"\n[bold green]⬡ EXPORT COMPLETE[/bold green]")

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Metric", style="dim", width=20)
        table.add_column("Value")

        table.add_row("Total findings", str(summary["total_findings"]))
        sev = summary["severity_breakdown"]
        table.add_row(
            "Severity",
            f"[red]CRIT:{sev.get('CRITICAL',0)}[/] "
            f"[red]HIGH:{sev.get('HIGH',0)}[/] "
            f"[yellow]MED:{sev.get('MEDIUM',0)}[/] "
            f"[cyan]LOW:{sev.get('LOW',0)}[/]"
        )

        for fmt, paths in summary.get("files", {}).items():
            table.add_row(
                f"{fmt.upper()} files",
                f"{len(paths)} exported"
            )

        console.print(table)
        console.print(f"\n[dim]Reports in: {self.output_dir}[/dim]")


# ══════════════════════════════════════════════════════════════════════════════
# STANDALONE TEST
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    console.print("\n[bold purple]⬡ AUTO REPORT EXPORTER — Self Test[/bold purple]\n")

    # Create a mock crash report for testing
    mock_dir = Path("/tmp/glitch_test_reports")
    mock_dir.mkdir(exist_ok=True)

    mock_report = mock_dir / "crash_000000_report.md"
    mock_report.write_text("""# GLITCHICONS ⬡ Vulnerability Report
**Generated:** 2026-05-01 12:00:00

## Summary

| Field | Value |
|-------|-------|
| **Crash ID** | 000000 |
| **Severity** | HIGH |
| **CVSS Score** | 8.1 |
| **Signal** | SIGABRT (sig:06) |
| **CWE** | CWE-121 |
| **Location** | target.c:parse_input |

## Crash Input

```
zz TP/1.1\\r\\nContent-Type: t[1, 2
```

## GDB Backtrace

```
#0  __pthread_kill_implementation
#8  __strcpy_chk (dest=buf, src=input, destlen=64)
#9  strcpy at string_fortified.h:79
#10 parse_input (input=...) at target.c:6
#11 main (argc=...) at target.c:16
```

## Remediation

Replace strcpy with strncpy and add bounds checking.
""")

    exporter = AutoReportExporter(
        output_dir="/tmp/glitch_exported",
        model="qwen2.5-coder:3b",
        program_name="Test Program",
        org_name="Test Organization",
    )

    result = exporter.export_all(
        reports_dir=str(mock_dir),
        protocol_dir="/tmp/nonexistent",
        formats=["h1", "bugcrowd", "internal", "json"],
        enrich=True,
    )

    if result:
        console.print(f"\n[green]⬡ Self test passed.[/green]")
        console.print("[dim]Check /tmp/glitch_exported/ for output files[/dim]")
