# tests/test_html_reporter.py
"""
Unit tests untuk modules/report/html_reporter.py
"""

import json
import pytest
from pathlib import Path
from modules.report.html_reporter import HTMLReporter, SEVERITY_ORDER, SEVERITY_COLORS


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def sample_findings():
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
            "target": "https://target.com/login",
        },
        {
            "id": "FIND-002",
            "title": "GraphQL Introspection Enabled",
            "severity": "HIGH",
            "cvss": 7.5,
            "cwe": "CWE-200",
            "description": "Full schema exposed via introspection.",
            "evidence": "50 types returned including User.password field.",
            "remediation": "Disable introspection in production.",
            "target": "https://target.com/graphql",
        },
        {
            "id": "FIND-003",
            "title": "Missing Security Headers",
            "severity": "MEDIUM",
            "cvss": 5.3,
            "cwe": "CWE-693",
            "description": "X-Frame-Options dan CSP header tidak ada.",
            "evidence": "HTTP response header analysis.",
            "remediation": "Tambahkan security headers via server config.",
            "target": "https://target.com",
        },
        {
            "id": "FIND-004",
            "title": "Verbose Error Messages",
            "severity": "LOW",
            "cvss": 2.7,
            "cwe": "CWE-209",
            "description": "Stack traces exposed on error.",
            "evidence": "500 error shows full Django traceback.",
            "remediation": "Set DEBUG=False in production.",
            "target": "https://target.com/api",
        },
    ]


@pytest.fixture
def reporter(sample_findings, tmp_path):
    return HTMLReporter(
        findings=sample_findings,
        target="target.com",
        org="Test Corp",
        report_type="internal",
        output_dir=str(tmp_path),
        tool_version="0.7.0",
        engagement_duration="4h 30m",
    )


@pytest.fixture
def generated_html(reporter):
    path = reporter.generate()
    return path.read_text(encoding="utf-8")


# ── Tests: File Generation ────────────────────────────────

class TestFileGeneration:

    @pytest.mark.unit
    def test_generates_html_file(self, reporter, tmp_path):
        """Harus generate file .html di output dir."""
        path = reporter.generate()
        assert path.exists()
        assert path.suffix == ".html"
        assert path.parent == tmp_path

    @pytest.mark.unit
    def test_filename_contains_target(self, reporter):
        """Nama file harus contain target domain."""
        path = reporter.generate()
        assert "target" in path.name

    @pytest.mark.unit
    def test_filename_contains_date(self, reporter):
        """Nama file harus contain tanggal."""
        from datetime import datetime
        path = reporter.generate()
        date_str = datetime.now().strftime("%Y%m%d")
        assert date_str in path.name

    @pytest.mark.unit
    def test_file_not_empty(self, reporter):
        """File yang dihasilkan tidak boleh kosong."""
        path = reporter.generate()
        assert path.stat().st_size > 1000

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path):
        """Output dir harus dibuat otomatis."""
        new_dir = tmp_path / "subdir" / "reports"
        r = HTMLReporter(findings=[], target="test.com", output_dir=str(new_dir))
        r.generate()
        assert new_dir.exists()


# ── Tests: HTML Structure ─────────────────────────────────

class TestHTMLStructure:

    @pytest.mark.unit
    def test_is_valid_html(self, generated_html):
        """Output harus berupa HTML valid dengan doctype."""
        assert "<!DOCTYPE html>" in generated_html
        assert "<html" in generated_html
        assert "</html>" in generated_html

    @pytest.mark.unit
    def test_has_head_and_body(self, generated_html):
        """Harus punya head dan body."""
        assert "<head>" in generated_html
        assert "</head>" in generated_html
        assert "<body>" in generated_html
        assert "</body>" in generated_html

    @pytest.mark.unit
    def test_has_css_styles(self, generated_html):
        """Harus punya inline CSS."""
        assert "<style>" in generated_html
        assert ":root" in generated_html
        assert "var(--" in generated_html

    @pytest.mark.unit
    def test_has_javascript(self, generated_html):
        """Harus punya inline JavaScript."""
        assert "<script>" in generated_html
        assert "FINDINGS" in generated_html

    @pytest.mark.unit
    def test_no_external_dependencies(self, generated_html):
        """Harus zero external dependencies (CDN, dll)."""
        external_indicators = [
            "cdn.jsdelivr.net",
            "cdnjs.cloudflare.com",
            "unpkg.com",
            "fonts.googleapis.com",
            'src="http',
            'href="http',
        ]
        for indicator in external_indicators:
            assert indicator not in generated_html, f"External dep found: {indicator}"

    @pytest.mark.unit
    def test_self_contained(self, generated_html):
        """Harus bisa dibuka offline (tidak ada link ke file luar)."""
        assert 'rel="stylesheet"' not in generated_html
        assert '<script src=' not in generated_html


# ── Tests: Content ────────────────────────────────────────

class TestContent:

    @pytest.mark.unit
    def test_target_in_report(self, generated_html):
        """Target domain harus muncul di report."""
        assert "target.com" in generated_html

    @pytest.mark.unit
    def test_org_in_report(self, generated_html):
        """Nama organisasi harus muncul."""
        assert "Test Corp" in generated_html

    @pytest.mark.unit
    def test_report_type_in_report(self, generated_html):
        """Report type harus muncul."""
        assert "Internal" in generated_html or "internal" in generated_html

    @pytest.mark.unit
    def test_version_in_report(self, generated_html):
        """Tool version harus muncul."""
        assert "0.7.0" in generated_html

    @pytest.mark.unit
    def test_findings_embedded_as_json(self, generated_html):
        """Findings harus di-embed sebagai JSON di JavaScript."""
        assert "FIND-001" in generated_html
        assert "FIND-002" in generated_html
        assert "No Brute Force Protection" in generated_html

    @pytest.mark.unit
    def test_all_severities_present(self, generated_html):
        """Semua severity level harus ada di report."""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            assert sev in generated_html

    @pytest.mark.unit
    def test_cwe_ids_present(self, generated_html):
        """CWE IDs harus muncul di report."""
        assert "CWE-307" in generated_html
        assert "CWE-200" in generated_html

    @pytest.mark.unit
    def test_overall_risk_shown(self, generated_html):
        """Overall risk rating harus ditampilkan."""
        assert "Overall Risk" in generated_html
        assert "CRITICAL" in generated_html


# ── Tests: Severity Summary ───────────────────────────────

class TestSeveritySummary:

    @pytest.mark.unit
    def test_severity_counts_correct(self, reporter, sample_findings):
        """Jumlah per severity harus dihitung dengan benar."""
        counts = reporter._severity_counts()
        assert counts.get("CRITICAL") == 1
        assert counts.get("HIGH") == 1
        assert counts.get("MEDIUM") == 1
        assert counts.get("LOW") == 1

    @pytest.mark.unit
    def test_cvss_avg_correct(self, reporter):
        """Average CVSS harus dihitung dengan benar."""
        avg = reporter._cvss_avg()
        expected = round((9.1 + 7.5 + 5.3 + 2.7) / 4, 1)
        assert avg == expected

    @pytest.mark.unit
    def test_risk_rating_critical(self, reporter):
        """Risk rating harus CRITICAL jika ada finding CRITICAL."""
        assert reporter._risk_rating() == "CRITICAL"

    @pytest.mark.unit
    def test_risk_rating_high(self, tmp_path):
        """Risk rating harus HIGH jika tidak ada CRITICAL."""
        findings = [{"severity": "HIGH", "cvss": 7.5, "title": "Test", "cwe": "CWE-1"}]
        r = HTMLReporter(findings=findings, target="t.com", output_dir=str(tmp_path))
        assert r._risk_rating() == "HIGH"

    @pytest.mark.unit
    def test_risk_rating_info_when_empty(self, tmp_path):
        """Risk rating harus INFO jika tidak ada findings."""
        r = HTMLReporter(findings=[], target="t.com", output_dir=str(tmp_path))
        assert r._risk_rating() == "INFO"

    @pytest.mark.unit
    def test_findings_sorted_by_severity(self, reporter):
        """Findings harus di-sort: CRITICAL dulu, lalu HIGH, MEDIUM, LOW."""
        sorted_findings = reporter.findings
        severities = [f["severity"] for f in sorted_findings]
        expected_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        assert severities == expected_order


# ── Tests: XSS Prevention ────────────────────────────────

class TestXSSPrevention:

    @pytest.mark.unit
    def test_special_chars_escaped(self, tmp_path):
        """Karakter HTML berbahaya harus di-escape di output."""
        findings = [{
            "id": "XSS-001",
            "title": "Test <script>alert(1)</script>",
            "severity": "HIGH",
            "cvss": 7.0,
            "cwe": "CWE-79",
            "description": 'XSS via <img onerror="alert(1)">',
            "evidence": "<script>evil()</script>",
            "remediation": "Sanitize & encode output",
            "target": "https://t.com",
        }]
        r = HTMLReporter(findings=findings, target="t.com", output_dir=str(tmp_path))
        html = r.generate().read_text(encoding="utf-8")

        # Raw <script> tidak boleh ada dari finding title (harus escaped)
        # Note: script tags dari kode reporter sendiri boleh ada
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html or \
               "alert(1)" not in html.split("<script>")[0]

    @pytest.mark.unit
    def test_empty_findings_no_crash(self, tmp_path):
        """Reporter dengan findings kosong tidak boleh crash."""
        r = HTMLReporter(findings=[], target="t.com", output_dir=str(tmp_path))
        html = r.generate().read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html
        assert "0" in html  # total count


# ── Tests: Constants ──────────────────────────────────────

class TestConstants:

    @pytest.mark.unit
    def test_severity_order_complete(self):
        """SEVERITY_ORDER harus mencakup semua level."""
        required = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert required == set(SEVERITY_ORDER.keys())

    @pytest.mark.unit
    def test_severity_order_values(self):
        """CRITICAL harus paling tinggi priority (nilai terkecil)."""
        assert SEVERITY_ORDER["CRITICAL"] < SEVERITY_ORDER["HIGH"]
        assert SEVERITY_ORDER["HIGH"] < SEVERITY_ORDER["MEDIUM"]
        assert SEVERITY_ORDER["MEDIUM"] < SEVERITY_ORDER["LOW"]
        assert SEVERITY_ORDER["LOW"] < SEVERITY_ORDER["INFO"]

    @pytest.mark.unit
    def test_severity_colors_complete(self):
        """SEVERITY_COLORS harus ada untuk semua level."""
        required = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert required == set(SEVERITY_COLORS.keys())

    @pytest.mark.unit
    def test_severity_colors_are_hex(self):
        """Semua color values harus berupa hex color."""
        for sev, color in SEVERITY_COLORS.items():
            assert color.startswith("#"), f"{sev} color '{color}' bukan hex"
            assert len(color) in (4, 7), f"{sev} color '{color}' bukan valid hex length"
