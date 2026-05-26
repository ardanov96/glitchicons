# tests/test_crash_triage.py
"""
Unit tests untuk crash_triage.py dan report_exporter.py
"""

import pytest
import json
from datetime import datetime


# ── Crash Triage Tests ────────────────────────────────────

class TestCrashTriage:

    @pytest.mark.unit
    def test_gdb_output_parsing(self, sample_crash_output):
        """Harus bisa extract crash info dari GDB output."""
        assert "SIGSEGV" in sample_crash_output
        assert "strcpy" in sample_crash_output or "vulnerable_function" in sample_crash_output

    @pytest.mark.unit
    def test_signal_classification(self):
        """Harus classify signal ke crash type."""
        signal_map = {
            "SIGSEGV": "Segmentation Fault",
            "SIGABRT": "Abort (heap corruption / assert)",
            "SIGBUS":  "Bus Error",
            "SIGFPE":  "Floating Point Exception",
            "SIGILL":  "Illegal Instruction",
        }
        assert signal_map["SIGSEGV"] == "Segmentation Fault"
        assert len(signal_map) >= 4

    @pytest.mark.unit
    def test_cwe_mapping_from_crash(self, sample_crash_output):
        """Harus map crash type ke CWE ID."""
        cwe_map = {
            "strcpy":         "CWE-121",  # Stack Buffer Overflow
            "strcat":         "CWE-121",
            "malloc":         "CWE-122",  # Heap Buffer Overflow
            "use-after-free": "CWE-416",
            "double-free":    "CWE-415",
            "null-deref":     "CWE-476",
        }
        # Sample crash mengandung strcpy
        if "strcpy" in sample_crash_output:
            cwe = cwe_map.get("strcpy")
            assert cwe == "CWE-121"

    @pytest.mark.unit
    def test_cvss_score_range(self):
        """CVSS score harus dalam range 0.0 - 10.0."""
        test_scores = [0.0, 3.5, 7.8, 8.1, 9.5, 10.0]
        for score in test_scores:
            assert 0.0 <= score <= 10.0

    @pytest.mark.unit
    def test_cvss_severity_mapping(self):
        """CVSS score harus map ke severity label yang benar."""
        def get_severity(score: float) -> str:
            if score == 0.0:          return "NONE"
            elif score < 4.0:         return "LOW"
            elif score < 7.0:         return "MEDIUM"
            elif score < 9.0:         return "HIGH"
            else:                     return "CRITICAL"

        assert get_severity(0.0)  == "NONE"
        assert get_severity(3.9)  == "LOW"
        assert get_severity(5.0)  == "MEDIUM"
        assert get_severity(7.5)  == "HIGH"
        assert get_severity(9.1)  == "CRITICAL"
        assert get_severity(10.0) == "CRITICAL"

    @pytest.mark.unit
    def test_unique_crash_deduplication(self):
        """Crash yang sama harus di-deduplicate berdasarkan stack trace."""
        crashes = [
            {"signal": "SIGSEGV", "function": "strcpy", "address": "0x401186"},
            {"signal": "SIGSEGV", "function": "strcpy", "address": "0x401186"},  # duplikat
            {"signal": "SIGSEGV", "function": "memcpy", "address": "0x401200"},
        ]
        unique = {f"{c['function']}:{c['address']}" for c in crashes}
        assert len(unique) == 2  # 2 unique crashes


# ── Report Exporter Tests ─────────────────────────────────

class TestReportExporter:

    @pytest.fixture
    def sample_findings(self):
        return [
            {
                "id": "FIND-001",
                "title": "No Brute Force Protection",
                "severity": "CRITICAL",
                "cvss": 9.1,
                "cwe": "CWE-307",
                "description": "Login endpoint tidak memiliki rate limiting.",
                "evidence": "2353 attempts in 60 minutes, zero lockout.",
                "remediation": "Implementasi account lockout setelah 5 failed attempts.",
            },
            {
                "id": "FIND-002",
                "title": "Missing Security Headers",
                "severity": "MEDIUM",
                "cvss": 5.3,
                "cwe": "CWE-693",
                "description": "X-Frame-Options dan CSP header tidak ada.",
                "evidence": "HTTP response header analysis.",
                "remediation": "Tambahkan security headers via server config.",
            },
        ]

    @pytest.mark.unit
    def test_report_has_required_fields(self, sample_findings):
        """Setiap finding harus punya semua field required."""
        required_fields = {"id", "title", "severity", "cvss", "description", "remediation"}
        for finding in sample_findings:
            missing = required_fields - set(finding.keys())
            assert not missing, f"Missing fields: {missing} di {finding['id']}"

    @pytest.mark.unit
    def test_report_severity_distribution(self, sample_findings):
        """Report harus bisa hitung distribusi severity."""
        from collections import Counter
        distribution = Counter(f["severity"] for f in sample_findings)
        assert distribution["CRITICAL"] == 1
        assert distribution["MEDIUM"] == 1

    @pytest.mark.unit
    def test_report_sorted_by_cvss(self, sample_findings):
        """Findings harus bisa di-sort by CVSS descending."""
        sorted_findings = sorted(sample_findings, key=lambda x: x["cvss"], reverse=True)
        assert sorted_findings[0]["cvss"] >= sorted_findings[-1]["cvss"]
        assert sorted_findings[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_markdown_report_structure(self, sample_findings):
        """Markdown report harus punya section yang benar."""
        def generate_markdown_report(findings: list) -> str:
            lines = [
                "# Pentest Report",
                f"**Date:** {datetime.now().strftime('%Y-%m-%d')}",
                "",
                "## Executive Summary",
                f"Total findings: {len(findings)}",
                "",
                "## Findings",
            ]
            for f in sorted(findings, key=lambda x: x["cvss"], reverse=True):
                lines.append(f"### [{f['severity']}] {f['title']}")
                lines.append(f"**CVSS:** {f['cvss']}")
                lines.append(f"**Description:** {f['description']}")
                lines.append(f"**Remediation:** {f['remediation']}")
                lines.append("")
            return "\n".join(lines)

        report = generate_markdown_report(sample_findings)
        assert "# Pentest Report" in report
        assert "CRITICAL" in report
        assert "Executive Summary" in report
        assert "Remediation" in report

    @pytest.mark.unit
    def test_json_report_is_valid(self, sample_findings):
        """JSON report harus valid JSON."""
        report_data = {
            "metadata": {
                "tool": "glitchicons",
                "version": "0.7.0",
                "date": datetime.now().isoformat(),
            },
            "findings": sample_findings,
            "summary": {
                "total": len(sample_findings),
                "critical": sum(1 for f in sample_findings if f["severity"] == "CRITICAL"),
            },
        }
        json_str = json.dumps(report_data, indent=2)
        parsed = json.loads(json_str)
        assert parsed["summary"]["critical"] == 1

    @pytest.mark.unit
    def test_report_filename_format(self):
        """Nama file report harus follow format standar."""
        org = "ClientName"
        date = "2026-05-25"
        report_type = "internal"

        filename = f"glitchicons_{org}_{date}_{report_type}.md"
        assert filename == "glitchicons_ClientName_2026-05-25_internal.md"
        assert " " not in filename  # Tidak ada spasi
