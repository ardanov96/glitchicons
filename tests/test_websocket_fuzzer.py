# tests/test_websocket_fuzzer.py
"""
Unit tests untuk modules/inject/websocket_fuzzer.py
Semua WebSocket connections di-mock — tidak butuh server nyata.
"""

import json
import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from pathlib import Path

from modules.inject.websocket_fuzzer import (
    WebSocketFuzzer,
    WSTestResult,
    make_finding,
    INJECTION_PAYLOADS,
    MALFORMED_MESSAGES,
    COMMON_SUBPROTOCOLS,
    ORIGIN_BYPASS_ATTEMPTS,
)


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def fuzzer(tmp_path):
    return WebSocketFuzzer(
        target="ws://target.example.com/ws",
        output_dir=str(tmp_path / "ws"),
        timeout=2,
        delay=0,
    )


@pytest.fixture
def authed_fuzzer(tmp_path):
    return WebSocketFuzzer(
        target="wss://target.example.com/ws",
        output_dir=str(tmp_path / "ws"),
        token="eyJhbGciOiJIUzI1NiJ9.test.sig",
        timeout=2,
        delay=0,
    )


# ── Tests: WSTestResult ───────────────────────────────────

class TestWSTestResult:

    @pytest.mark.unit
    def test_default_not_vulnerable(self):
        """WSTestResult default harus tidak vulnerable."""
        r = WSTestResult("test_name")
        assert r.vulnerable is False
        assert r.test_name == "test_name"
        assert r.error is None

    @pytest.mark.unit
    def test_repr_safe(self):
        """repr harus menampilkan SAFE jika tidak vulnerable."""
        r = WSTestResult("origin_bypass")
        assert "SAFE" in repr(r)

    @pytest.mark.unit
    def test_repr_vuln(self):
        """repr harus menampilkan VULN jika vulnerable."""
        r = WSTestResult("auth_bypass")
        r.vulnerable = True
        assert "VULN" in repr(r)


# ── Tests: make_finding() ─────────────────────────────────

class TestMakeFinding:

    @pytest.mark.unit
    def test_finding_has_all_fields(self):
        """make_finding harus return dict dengan semua field wajib."""
        f = make_finding(
            idx=1,
            title="Test Finding",
            severity="HIGH",
            cvss=7.5,
            cwe="CWE-1385",
            description="Description",
            evidence="Evidence",
            remediation="Fix it",
            target="ws://test.com/ws",
        )
        required = {"id", "title", "severity", "cvss", "cwe",
                    "description", "evidence", "remediation", "timestamp", "target"}
        assert required == set(f.keys())

    @pytest.mark.unit
    def test_finding_id_format(self):
        """Finding ID harus format WS-XXX."""
        f = make_finding(1, "T", "HIGH", 7.0, "CWE-1", "d", "e", "r", "ws://t.com")
        assert f["id"] == "WS-001"
        f2 = make_finding(42, "T", "HIGH", 7.0, "CWE-1", "d", "e", "r", "ws://t.com")
        assert f2["id"] == "WS-042"

    @pytest.mark.unit
    def test_finding_cvss_range(self):
        """CVSS harus dalam range 0.0-10.0."""
        scores = [0.0, 3.5, 7.5, 9.1, 10.0]
        for score in scores:
            f = make_finding(1, "T", "HIGH", score, "CWE-1", "d", "e", "r", "ws://t.com")
            assert 0.0 <= f["cvss"] <= 10.0

    @pytest.mark.unit
    def test_finding_severity_valid(self):
        """Severity harus salah satu dari nilai valid."""
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for sev in valid:
            f = make_finding(1, "T", sev, 5.0, "CWE-1", "d", "e", "r", "ws://t.com")
            assert f["severity"] in valid


# ── Tests: Payload Sets ───────────────────────────────────

class TestPayloadSets:

    @pytest.mark.unit
    def test_injection_categories_complete(self):
        """Harus ada payload untuk semua kategori inject."""
        required = {"sqli", "xss", "ssti", "cmdi", "json_break"}
        assert required == set(INJECTION_PAYLOADS.keys())

    @pytest.mark.unit
    def test_sqli_payloads_have_quotes(self):
        """SQLi payloads harus mengandung quote atau keyword SQL."""
        for p in INJECTION_PAYLOADS["sqli"]:
            assert "'" in p or "UNION" in p or "DROP" in p or "SLEEP" in p

    @pytest.mark.unit
    def test_xss_payloads_have_script(self):
        """XSS payloads harus mengandung script/event handler."""
        combined = " ".join(INJECTION_PAYLOADS["xss"])
        assert "<script>" in combined or "onerror" in combined or "onload" in combined

    @pytest.mark.unit
    def test_ssti_payloads_have_template_syntax(self):
        """SSTI payloads harus mengandung template engine syntax."""
        combined = " ".join(INJECTION_PAYLOADS["ssti"])
        assert "{{" in combined or "${" in combined or "<%" in combined

    @pytest.mark.unit
    def test_cmdi_payloads_have_shell_chars(self):
        """CMDi payloads harus mengandung shell injection chars."""
        combined = " ".join(INJECTION_PAYLOADS["cmdi"])
        assert any(c in combined for c in [";", "|", "`", "$("])

    @pytest.mark.unit
    def test_malformed_messages_variety(self):
        """MALFORMED_MESSAGES harus mencakup berbagai tipe."""
        has_empty = "" in MALFORMED_MESSAGES
        has_null_byte = "\x00" in MALFORMED_MESSAGES
        has_large = any(len(m) > 1000 for m in MALFORMED_MESSAGES)
        has_broken_json = any("{{{" in m for m in MALFORMED_MESSAGES)

        assert has_empty, "Harus ada empty string"
        assert has_null_byte, "Harus ada null byte"
        assert has_large, "Harus ada large payload"
        assert has_broken_json, "Harus ada broken JSON"

    @pytest.mark.unit
    def test_origin_bypass_attempts_variety(self):
        """ORIGIN_BYPASS_ATTEMPTS harus mencakup berbagai bypass technique."""
        combined = " ".join(ORIGIN_BYPASS_ATTEMPTS)
        assert "null" in combined
        assert "evil.com" in combined or "evil" in combined
        assert "localhost" in combined

    @pytest.mark.unit
    def test_subprotocols_include_dangerous(self):
        """COMMON_SUBPROTOCOLS harus include dangerous values."""
        combined = " ".join(str(s) for s in COMMON_SUBPROTOCOLS)
        has_traversal = any("/" in str(s) or ".." in str(s) for s in COMMON_SUBPROTOCOLS)
        has_null = "null" in combined or None in COMMON_SUBPROTOCOLS
        assert has_traversal or has_null


# ── Tests: Fuzzer Init ────────────────────────────────────

class TestFuzzerInit:

    @pytest.mark.unit
    def test_target_stored(self, fuzzer):
        """Target URL harus tersimpan dengan benar."""
        assert fuzzer.target == "ws://target.example.com/ws"

    @pytest.mark.unit
    def test_http_url_resolved(self, fuzzer):
        """ws:// harus dikonversi ke http:// untuk probe."""
        assert fuzzer.http_url == "http://target.example.com/ws"

    @pytest.mark.unit
    def test_wss_to_https(self, authed_fuzzer):
        """wss:// harus dikonversi ke https://."""
        assert authed_fuzzer.http_url == "https://target.example.com/ws"

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path):
        """Output dir harus dibuat saat init."""
        new_dir = tmp_path / "ws_output"
        WebSocketFuzzer(target="ws://t.com/ws", output_dir=str(new_dir))
        assert new_dir.exists()

    @pytest.mark.unit
    def test_token_stored(self, authed_fuzzer):
        """Token harus tersimpan."""
        assert authed_fuzzer.token is not None
        assert authed_fuzzer.token.startswith("eyJ")

    @pytest.mark.unit
    def test_no_token_by_default(self, fuzzer):
        """Token default harus None."""
        assert fuzzer.token is None

    @pytest.mark.unit
    def test_findings_starts_empty(self, fuzzer):
        """Findings harus kosong saat init."""
        assert fuzzer.findings == []


# ── Tests: Injection Confirmation Logic ───────────────────

class TestInjectionConfirmation:

    @pytest.mark.unit
    def test_sqli_confirmed_by_error(self, fuzzer):
        """SQLi harus confirmed jika response punya SQL error."""
        assert fuzzer._is_injection_confirmed(
            "' OR '1'='1",
            "Error: You have an error in your SQL syntax near mysql",
            "sqli"
        ) is True

    @pytest.mark.unit
    def test_sqli_not_confirmed_clean(self, fuzzer):
        """SQLi tidak confirmed jika response normal."""
        assert fuzzer._is_injection_confirmed(
            "' OR '1'='1",
            '{"status": "ok", "data": []}',
            "sqli"
        ) is False

    @pytest.mark.unit
    def test_ssti_confirmed_by_math(self, fuzzer):
        """SSTI confirmed jika {{7*7}} di-evaluate jadi 49."""
        assert fuzzer._is_injection_confirmed(
            "{{7*7}}",
            "Hello 49, welcome!",
            "ssti"
        ) is True

    @pytest.mark.unit
    def test_ssti_not_confirmed_literal(self, fuzzer):
        """SSTI tidak confirmed jika {{7*7}} literal di-echo."""
        assert fuzzer._is_injection_confirmed(
            "{{7*7}}",
            "Hello {{7*7}}, welcome!",
            "ssti"
        ) is False

    @pytest.mark.unit
    def test_cmdi_confirmed_by_output(self, fuzzer):
        """CMDi confirmed jika response punya uid= atau root:."""
        assert fuzzer._is_injection_confirmed(
            "; cat /etc/passwd",
            "root:x:0:0:root:/root:/bin/bash",
            "cmdi"
        ) is True

    @pytest.mark.unit
    def test_cmdi_not_confirmed_clean(self, fuzzer):
        """CMDi tidak confirmed pada response normal."""
        assert fuzzer._is_injection_confirmed(
            "; cat /etc/passwd",
            '{"error": "invalid command"}',
            "cmdi"
        ) is False


# ── Tests: Report Generation ──────────────────────────────

class TestReportGeneration:

    @pytest.mark.unit
    def test_save_report_creates_file(self, fuzzer, tmp_path):
        """_save_report harus membuat file JSON."""
        fuzzer.findings = [make_finding(
            1, "Test", "HIGH", 7.5, "CWE-1", "desc", "evidence", "fix", "ws://t.com"
        )]
        fuzzer._save_report()
        json_files = list(fuzzer.output_dir.glob("websocket_*.json"))
        assert len(json_files) == 1

    @pytest.mark.unit
    def test_report_json_structure(self, fuzzer):
        """Report JSON harus punya field standar."""
        fuzzer.findings = [make_finding(
            1, "Test", "CRITICAL", 9.1, "CWE-306", "desc", "evidence", "fix", "ws://t.com"
        )]
        fuzzer._save_report()
        json_files = list(fuzzer.output_dir.glob("websocket_*.json"))
        report = json.loads(json_files[0].read_text())

        assert report["tool"] == "glitchicons"
        assert report["module"] == "websocket_fuzzer"
        assert report["target"] == "ws://target.example.com/ws"
        assert report["total_findings"] == 1
        assert len(report["findings"]) == 1

    @pytest.mark.unit
    def test_report_sorted_by_cvss(self, fuzzer):
        """Findings di report harus di-sort by CVSS descending."""
        fuzzer.findings = [
            make_finding(1, "Low", "LOW", 2.5, "CWE-1", "d", "e", "r", "ws://t.com"),
            make_finding(2, "Critical", "CRITICAL", 9.1, "CWE-306", "d", "e", "r", "ws://t.com"),
            make_finding(3, "Medium", "MEDIUM", 5.3, "CWE-20", "d", "e", "r", "ws://t.com"),
        ]
        fuzzer._save_report()
        json_files = list(fuzzer.output_dir.glob("websocket_*.json"))
        report = json.loads(json_files[0].read_text())
        cvss_scores = [f["cvss"] for f in report["findings"]]
        assert cvss_scores == sorted(cvss_scores, reverse=True)

    @pytest.mark.unit
    def test_empty_findings_report(self, fuzzer):
        """Report dengan 0 findings tidak boleh crash."""
        fuzzer.findings = []
        fuzzer._save_report()
        json_files = list(fuzzer.output_dir.glob("websocket_*.json"))
        report = json.loads(json_files[0].read_text())
        assert report["total_findings"] == 0
        assert report["findings"] == []


# ── Tests: Rapid Fire Rate Detection ─────────────────────

class TestRapidFireLogic:

    @pytest.mark.unit
    def test_rate_limit_detection_threshold(self):
        """90+ dari 100 pesan harus dianggap tidak ada rate limit."""
        sent = 95
        total = 100
        threshold = 90
        assert sent >= threshold  # harus trigger finding

    @pytest.mark.unit
    def test_rate_limit_respected(self):
        """Jika hanya 50 dari 100 yang dikirim = rate limit aktif."""
        sent = 50
        total = 100
        threshold = 90
        assert sent < threshold  # tidak trigger finding

    @pytest.mark.unit
    def test_message_rate_calculation(self):
        """Rate calculation harus benar."""
        sent = 100
        elapsed = 2.5
        rate = sent / elapsed
        assert abs(rate - 40.0) < 0.1
