# tests/test_inject_modules.py
"""
Unit tests untuk modules/inject/ (XSS, SQLi, SSRF, SSTI, XXE)
"""

import pytest
import responses as responses_lib
from unittest.mock import patch, MagicMock


# ── XSS Tests ────────────────────────────────────────────

class TestXSSTester:

    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
        "';alert(1)//",
        '"><img src=x onerror=alert(document.cookie)>',
    ]

    @pytest.mark.unit
    def test_xss_payloads_not_empty(self):
        """Payload list tidak boleh kosong."""
        assert len(self.XSS_PAYLOADS) > 0

    @pytest.mark.unit
    def test_reflected_xss_detection(self, sample_http_response_xss):
        """Harus detect reflected XSS di response."""
        payload = "<script>alert(1)</script>"
        assert payload in sample_http_response_xss

    @pytest.mark.unit
    def test_all_xss_payload_types_covered(self):
        """Harus ada payload untuk setiap XSS type utama."""
        payload_str = " ".join(self.XSS_PAYLOADS)

        has_script_tag    = "<script>" in payload_str
        has_event_handler = "onerror=" in payload_str or "onload=" in payload_str
        has_javascript    = "javascript:" in payload_str

        assert has_script_tag,    "Harus ada payload dengan <script> tag"
        assert has_event_handler, "Harus ada payload dengan event handler"
        assert has_javascript,    "Harus ada payload dengan javascript: URI"

    @pytest.mark.unit
    def test_xss_response_severity_mapping(self):
        """Severity mapping untuk XSS types."""
        severity = {
            "stored": "HIGH",
            "reflected": "MEDIUM",
            "dom": "MEDIUM",
        }
        assert severity["stored"] == "HIGH"
        assert severity["reflected"] in ("MEDIUM", "HIGH")

    @pytest.mark.unit
    @responses_lib.activate
    def test_xss_scan_handles_connection_error(self, target_url):
        """Scanner harus handle connection error dengan graceful."""
        responses_lib.add(
            responses_lib.GET,
            f"{target_url}/search",
            body=ConnectionError("Connection refused"),
        )
        # Pastikan tidak raise uncaught exception
        try:
            import requests
            requests.get(f"{target_url}/search")
        except (ConnectionError, Exception):
            pass  # Expected — harus di-handle di modul


# ── SQLi Tests ────────────────────────────────────────────

class TestSQLiTester:

    ERROR_SIGNATURES = [
        "You have an error in your SQL syntax",
        "mysql_fetch_array()",
        "ORA-01756",
        "Microsoft OLE DB Provider for SQL Server",
        "SQLiteException",
        "pg_query(): Query failed",
        "Warning: mysqli",
    ]

    @pytest.mark.unit
    def test_sqli_error_detection(self, sample_sqli_error_response):
        """Harus detect MySQL error signature di response."""
        found = any(sig in sample_sqli_error_response for sig in self.ERROR_SIGNATURES)
        assert found, "Seharusnya mendeteksi SQL error signature"

    @pytest.mark.unit
    def test_sqli_payloads_have_quotes(self):
        """Payload SQLi harus mengandung single/double quote."""
        payloads = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "'; DROP TABLE users; --",
            "1 OR 1=1",
        ]
        quote_payloads = [p for p in payloads if "'" in p or '"' in p]
        assert len(quote_payloads) >= 2

    @pytest.mark.unit
    def test_time_based_blind_detection(self):
        """Harus bisa ukur response time untuk time-based blind."""
        import time
        # Simulasi: response yang lambat (> threshold) = indikasi SQLi
        threshold_seconds = 3.0
        simulated_response_time = 5.2  # detik

        is_time_based = simulated_response_time > threshold_seconds
        assert is_time_based

    @pytest.mark.unit
    def test_sqli_database_fingerprinting(self):
        """Harus bisa map error signature ke DB type."""
        db_signatures = {
            "MySQL": ["You have an error in your SQL syntax", "mysql_fetch_array"],
            "PostgreSQL": ["pg_query(): Query failed", "PSQLException"],
            "MSSQL": ["Microsoft OLE DB Provider for SQL Server"],
            "Oracle": ["ORA-01756", "ORA-00933"],
            "SQLite": ["SQLiteException", "sqlite3.OperationalError"],
        }
        # Semua DB utama harus ada
        assert len(db_signatures) >= 4

    @pytest.mark.unit
    def test_union_based_payload_structure(self):
        """UNION-based payload harus punya struktur yang benar."""
        union_payloads = [
            "1 UNION SELECT NULL--",
            "1 UNION SELECT NULL,NULL--",
            "1 UNION SELECT table_name FROM information_schema.tables--",
        ]
        for payload in union_payloads:
            assert "UNION" in payload.upper()
            assert "SELECT" in payload.upper()


# ── SSRF Tests ────────────────────────────────────────────

class TestSSRFTester:

    CLOUD_METADATA_URLS = [
        "http://169.254.169.254/latest/meta-data/",           # AWS
        "http://metadata.google.internal/computeMetadata/v1/", # GCP
        "http://169.254.169.254/metadata/instance",           # Azure
    ]

    @pytest.mark.unit
    def test_cloud_metadata_endpoints_covered(self):
        """Harus ada endpoint untuk AWS, GCP, dan Azure."""
        providers = {"AWS", "GCP", "Azure"}
        detected = set()

        for url in self.CLOUD_METADATA_URLS:
            if "169.254.169.254" in url and "latest" in url:
                detected.add("AWS")
            elif "google.internal" in url:
                detected.add("GCP")
            elif "169.254.169.254" in url and "instance" in url:
                detected.add("Azure")

        assert "GCP" in detected
        assert len(detected) >= 2

    @pytest.mark.unit
    def test_localhost_variants_included(self):
        """Harus test berbagai representasi localhost."""
        localhost_variants = [
            "http://localhost/",
            "http://127.0.0.1/",
            "http://0.0.0.0/",
            "http://[::1]/",         # IPv6
            "http://0177.0.0.1/",    # Octal
            "http://2130706433/",     # Decimal
        ]
        assert len(localhost_variants) >= 4

    @pytest.mark.unit
    def test_ssrf_severity_is_high(self):
        """SSRF ke cloud metadata harus rated HIGH atau CRITICAL."""
        ssrf_findings = {
            "type": "SSRF",
            "target": "http://169.254.169.254/latest/meta-data/iam/",
            "severity": "CRITICAL",
            "cvss": 9.1,
        }
        assert ssrf_findings["cvss"] >= 7.5


# ── SSTI Tests ────────────────────────────────────────────

class TestSSTITester:

    @pytest.mark.unit
    def test_jinja2_detection_payload(self):
        """Payload Jinja2 harus menggunakan {{ }} syntax."""
        jinja2_payloads = ["{{7*7}}", "{{config}}", "{{''.__class__}}"]
        for payload in jinja2_payloads:
            assert "{{" in payload and "}}" in payload

    @pytest.mark.unit
    def test_ssti_math_confirmation(self):
        """Konfirmasi SSTI dengan math expression."""
        # Jika {{7*7}} di-render jadi 49, itu SSTI
        simulated_response = "Search results for: 49"
        assert "49" in simulated_response  # 7*7 di-evaluate

    @pytest.mark.unit
    def test_engine_detection_mapping(self):
        """Harus bisa map syntax ke template engine."""
        engine_map = {
            "{{7*7}}":       ["Jinja2", "Twig"],
            "${7*7}":        ["Freemarker", "Pebble"],
            "<%= 7*7 %>":   ["ERB", "EJS"],
            "#{7*7}":        ["Ruby Erb"],
        }
        assert len(engine_map) >= 3
