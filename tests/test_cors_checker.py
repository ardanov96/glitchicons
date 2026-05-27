# tests/test_cors_checker.py
"""
Unit tests untuk modules/inject/cors_checker.py
Semua HTTP calls di-mock menggunakan responses library.
"""

import json
import pytest
import responses as responses_lib
from pathlib import Path

from modules.inject.cors_checker import (
    CORSChecker,
    CORSResponse,
    SEVERITY_MAP,
    SENSITIVE_ENDPOINTS,
    CORS_HEADERS,
)


# ── Mock response helpers ─────────────────────────────────

def make_mock_response(
    url: str,
    allow_origin: str | None = None,
    allow_credentials: bool = False,
    allow_methods: str | None = None,
    status: int = 200,
):
    """Register a mocked HTTP response with CORS headers."""
    headers = {}
    if allow_origin:
        headers["Access-Control-Allow-Origin"] = allow_origin
    if allow_credentials:
        headers["Access-Control-Allow-Credentials"] = "true"
    if allow_methods:
        headers["Access-Control-Allow-Methods"] = allow_methods

    responses_lib.add(
        responses_lib.GET,
        url,
        json={"data": "sensitive"},
        headers=headers,
        status=status,
    )


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def checker(tmp_path):
    return CORSChecker(
        target="https://target.example.com",
        output_dir=str(tmp_path / "cors"),
        timeout=3,
        delay=0,
    )


@pytest.fixture
def authed_checker(tmp_path):
    return CORSChecker(
        target="https://target.example.com",
        output_dir=str(tmp_path / "cors"),
        token="test-token-123",
        timeout=3,
        delay=0,
    )


# ── Tests: CORSResponse ───────────────────────────────────

class TestCORSResponse:

    @pytest.mark.unit
    def test_allow_origin_parsed(self):
        """allow_origin harus di-parse dari response headers."""
        # Manual construction dari httpx Response
        import httpx
        r = httpx.Response(200, headers={"access-control-allow-origin": "https://trusted.com"})
        cors = CORSResponse(r)
        assert cors.allow_origin == "https://trusted.com"

    @pytest.mark.unit
    def test_wildcard_detection(self):
        """is_wildcard harus True jika ACAO: *."""
        import httpx
        r = httpx.Response(200, headers={"access-control-allow-origin": "*"})
        cors = CORSResponse(r)
        assert cors.is_wildcard is True

    @pytest.mark.unit
    def test_not_wildcard(self):
        """is_wildcard harus False jika ACAO bukan *."""
        import httpx
        r = httpx.Response(200, headers={"access-control-allow-origin": "https://trusted.com"})
        cors = CORSResponse(r)
        assert cors.is_wildcard is False

    @pytest.mark.unit
    def test_credentials_true(self):
        """allow_credentials harus True jika ACAC: true."""
        import httpx
        r = httpx.Response(200, headers={
            "access-control-allow-origin": "https://trusted.com",
            "access-control-allow-credentials": "true",
        })
        cors = CORSResponse(r)
        assert cors.allow_credentials is True

    @pytest.mark.unit
    def test_credentials_false_by_default(self):
        """allow_credentials harus False jika header tidak ada."""
        import httpx
        r = httpx.Response(200, headers={"access-control-allow-origin": "*"})
        cors = CORSResponse(r)
        assert cors.allow_credentials is False

    @pytest.mark.unit
    def test_reflects_origin_true(self):
        """reflects_origin harus True jika ACAO sama dengan Origin."""
        import httpx
        origin = "https://evil.com"
        r = httpx.Response(200, headers={"access-control-allow-origin": origin})
        cors = CORSResponse(r)
        assert cors.reflects_origin(origin) is True

    @pytest.mark.unit
    def test_reflects_origin_false(self):
        """reflects_origin harus False jika ACAO berbeda."""
        import httpx
        r = httpx.Response(200, headers={"access-control-allow-origin": "https://trusted.com"})
        cors = CORSResponse(r)
        assert cors.reflects_origin("https://evil.com") is False

    @pytest.mark.unit
    def test_has_cors_true(self):
        """has_cors harus True jika ACAO header ada."""
        import httpx
        r = httpx.Response(200, headers={"access-control-allow-origin": "*"})
        cors = CORSResponse(r)
        assert cors.has_cors is True

    @pytest.mark.unit
    def test_has_cors_false(self):
        """has_cors harus False jika tidak ada ACAO header."""
        import httpx
        r = httpx.Response(200, headers={"content-type": "application/json"})
        cors = CORSResponse(r)
        assert cors.has_cors is False

    @pytest.mark.unit
    def test_to_dict_structure(self):
        """to_dict harus return dict dengan field yang benar."""
        import httpx
        r = httpx.Response(200, headers={
            "access-control-allow-origin": "https://trusted.com",
            "access-control-allow-credentials": "true",
            "access-control-allow-methods": "GET, POST",
        })
        cors = CORSResponse(r)
        d = cors.to_dict()
        assert "allow_origin" in d
        assert "allow_credentials" in d
        assert "allow_methods" in d


# ── Tests: Domain Extraction ──────────────────────────────

class TestDomainExtraction:

    @pytest.mark.unit
    def test_extract_https_domain(self, checker):
        """Harus extract domain dari HTTPS URL."""
        assert checker._extract_domain("https://target.com") == "target.com"

    @pytest.mark.unit
    def test_extract_http_domain(self, checker):
        """Harus extract domain dari HTTP URL."""
        assert checker._extract_domain("http://target.com") == "target.com"

    @pytest.mark.unit
    def test_extract_domain_with_path(self, checker):
        """Harus strip path dari URL."""
        assert checker._extract_domain("https://target.com/api/v1") == "target.com"

    @pytest.mark.unit
    def test_extract_domain_with_port(self, checker):
        """Harus strip port dari domain."""
        assert checker._extract_domain("https://target.com:8443") == "target.com"

    @pytest.mark.unit
    def test_extract_subdomain(self, checker):
        """Harus preserve subdomain."""
        assert checker._extract_domain("https://api.target.com") == "api.target.com"

    @pytest.mark.unit
    def test_checker_domain_set(self, checker):
        """checker.domain harus di-set dengan benar saat init."""
        assert checker.domain == "target.example.com"


# ── Tests: Evidence Formatting ────────────────────────────

class TestEvidenceFormatting:

    @pytest.mark.unit
    def test_format_evidence_includes_origin(self, checker):
        """Evidence harus menyertakan request Origin."""
        import httpx
        r = httpx.Response(200, headers={"access-control-allow-origin": "https://evil.com"})
        cors = CORSResponse(r)
        evidence = checker._format_evidence(cors, "https://evil.com")
        assert "https://evil.com" in evidence
        assert "Access-Control-Allow-Origin" in evidence

    @pytest.mark.unit
    def test_format_evidence_with_credentials(self, checker):
        """Evidence harus menyertakan Credentials jika ada."""
        import httpx
        r = httpx.Response(200, headers={
            "access-control-allow-origin": "https://evil.com",
            "access-control-allow-credentials": "true",
        })
        cors = CORSResponse(r)
        evidence = checker._format_evidence(cors, "https://evil.com")
        assert "Credentials" in evidence or "credentials" in evidence


# ── Tests: Finding Deduplication ─────────────────────────

class TestFindingDeduplication:

    @pytest.mark.unit
    def test_duplicate_finding_not_added(self, checker):
        """Finding yang sama (title + endpoint) tidak boleh ditambah dua kali."""
        checker._add_finding(
            title="CORS Test", severity="HIGH", cvss=7.5, cwe="CWE-942",
            description="desc", evidence="ev", remediation="fix",
            endpoint="https://target.example.com",
        )
        checker._add_finding(
            title="CORS Test", severity="HIGH", cvss=7.5, cwe="CWE-942",
            description="desc2", evidence="ev2", remediation="fix2",
            endpoint="https://target.example.com",
        )
        assert len(checker.findings) == 1

    @pytest.mark.unit
    def test_different_endpoints_both_added(self, checker):
        """Finding dengan endpoint berbeda harus keduanya ditambah."""
        checker._add_finding(
            title="CORS Test", severity="HIGH", cvss=7.5, cwe="CWE-942",
            description="desc", evidence="ev", remediation="fix",
            endpoint="https://target.example.com/api/user",
        )
        checker._add_finding(
            title="CORS Test", severity="HIGH", cvss=7.5, cwe="CWE-942",
            description="desc", evidence="ev", remediation="fix",
            endpoint="https://target.example.com/api/admin",
        )
        assert len(checker.findings) == 2

    @pytest.mark.unit
    def test_finding_id_sequential(self, checker):
        """Finding ID harus sequential CORS-001, CORS-002, dst."""
        checker._add_finding("T1", "HIGH", 7.0, "CWE-942", "d", "e", "r",
                              "https://target.example.com/a")
        checker._add_finding("T2", "MEDIUM", 5.0, "CWE-942", "d", "e", "r",
                              "https://target.example.com/b")
        assert checker.findings[0]["id"] == "CORS-001"
        assert checker.findings[1]["id"] == "CORS-002"


# ── Tests: Severity Map ───────────────────────────────────

class TestSeverityMap:

    @pytest.mark.unit
    def test_all_vuln_types_have_entries(self):
        """Semua vulnerability type harus ada di SEVERITY_MAP."""
        required = {
            "reflected_with_credentials",
            "null_with_credentials",
            "wildcard_with_credentials",
            "reflected_no_credentials",
            "post_domain_bypass",
            "pre_domain_bypass",
            "null_no_credentials",
            "http_downgrade",
            "wildcard_public",
            "preflight_bypass",
            "sensitive_endpoint_cors",
        }
        assert required.issubset(set(SEVERITY_MAP.keys()))

    @pytest.mark.unit
    def test_credentials_findings_critical(self):
        """Findings dengan credentials harus CRITICAL."""
        cred_types = [
            "reflected_with_credentials",
            "null_with_credentials",
            "wildcard_with_credentials",
        ]
        for t in cred_types:
            sev, cvss, cwe = SEVERITY_MAP[t]
            assert sev == "CRITICAL", f"{t} harus CRITICAL, got {sev}"
            assert cvss >= 9.0, f"{t} CVSS harus >= 9.0, got {cvss}"

    @pytest.mark.unit
    def test_cwe_format(self):
        """Semua CWE harus format CWE-XXX."""
        for vuln_type, (sev, cvss, cwe) in SEVERITY_MAP.items():
            assert cwe.startswith("CWE-"), f"{vuln_type} CWE invalid: {cwe}"
            assert cwe.split("-")[1].isdigit(), f"{vuln_type} CWE number invalid: {cwe}"

    @pytest.mark.unit
    def test_cvss_in_range(self):
        """Semua CVSS harus dalam range 0.0-10.0."""
        for vuln_type, (sev, cvss, cwe) in SEVERITY_MAP.items():
            assert 0.0 <= cvss <= 10.0, f"{vuln_type} CVSS out of range: {cvss}"

    @pytest.mark.unit
    def test_severity_ordering(self):
        """reflected_with_credentials harus punya CVSS tertinggi."""
        critical_scores = [
            SEVERITY_MAP["reflected_with_credentials"][1],
            SEVERITY_MAP["null_with_credentials"][1],
        ]
        low_scores = [
            SEVERITY_MAP["wildcard_public"][1],
            SEVERITY_MAP["http_downgrade"][1],
        ]
        assert min(critical_scores) > max(low_scores)


# ── Tests: Sensitive Endpoints ────────────────────────────

class TestSensitiveEndpoints:

    @pytest.mark.unit
    def test_sensitive_endpoints_not_empty(self):
        """SENSITIVE_ENDPOINTS tidak boleh kosong."""
        assert len(SENSITIVE_ENDPOINTS) > 5

    @pytest.mark.unit
    def test_common_api_paths_covered(self):
        """Harus cover endpoint API yang umum."""
        combined = " ".join(SENSITIVE_ENDPOINTS)
        assert "/api/user" in combined or "/api/users" in combined
        assert "/api/me" in combined
        assert "/api/admin" in combined
        assert "/graphql" in combined

    @pytest.mark.unit
    def test_endpoints_start_with_slash(self):
        """Semua endpoint harus diawali /."""
        for ep in SENSITIVE_ENDPOINTS:
            assert ep.startswith("/"), f"'{ep}' harus diawali /"


# ── Tests: CORS Headers Constants ─────────────────────────

class TestCORSHeaders:

    @pytest.mark.unit
    def test_cors_headers_keys(self):
        """CORS_HEADERS harus cover semua standard CORS headers."""
        required = {
            "allow_origin", "allow_credentials",
            "allow_methods", "allow_headers",
        }
        assert required.issubset(set(CORS_HEADERS.keys()))

    @pytest.mark.unit
    def test_cors_header_values_lowercase(self):
        """Header names harus lowercase (HTTP/2 convention)."""
        for key, val in CORS_HEADERS.items():
            assert val == val.lower(), f"'{val}' harus lowercase"

    @pytest.mark.unit
    def test_allow_origin_header_correct(self):
        """ACAO header name harus benar."""
        assert CORS_HEADERS["allow_origin"] == "access-control-allow-origin"


# ── Tests: Report Generation ──────────────────────────────

class TestReportGeneration:

    @pytest.mark.unit
    def test_save_report_creates_file(self, checker, tmp_path):
        """_save_report harus membuat file JSON."""
        checker._add_finding(
            "CORS Test", "HIGH", 7.5, "CWE-942",
            "desc", "evidence", "fix",
            "https://target.example.com",
        )
        checker._save_report()
        json_files = list(checker.output_dir.glob("cors_*.json"))
        assert len(json_files) == 1

    @pytest.mark.unit
    def test_report_structure(self, checker):
        """Report JSON harus punya field standar."""
        checker._add_finding(
            "CORS Test", "CRITICAL", 9.3, "CWE-942",
            "desc", "evidence", "fix",
            "https://target.example.com",
        )
        checker._save_report()
        json_files = list(checker.output_dir.glob("cors_*.json"))
        report = json.loads(json_files[0].read_text(encoding="utf-8"))

        assert report["tool"] == "glitchicons"
        assert report["module"] == "cors_checker"
        assert report["target"] == "https://target.example.com"
        assert report["domain"] == "target.example.com"
        assert report["total_findings"] == 1

    @pytest.mark.unit
    def test_report_sorted_by_cvss(self, checker):
        """Findings di report harus di-sort by CVSS descending."""
        checker._add_finding("Low",  "LOW",      2.0, "CWE-942", "d", "e", "r", "https://t.com/a")
        checker._add_finding("Crit", "CRITICAL",  9.3, "CWE-942", "d", "e", "r", "https://t.com/b")
        checker._add_finding("Med",  "MEDIUM",    5.4, "CWE-942", "d", "e", "r", "https://t.com/c")
        checker._save_report()
        json_files = list(checker.output_dir.glob("cors_*.json"))
        report = json.loads(json_files[0].read_text(encoding="utf-8"))
        scores = [f["cvss"] for f in report["findings"]]
        assert scores == sorted(scores, reverse=True)

    @pytest.mark.unit
    def test_empty_findings_report_ok(self, checker):
        """Report dengan 0 findings tidak boleh crash."""
        checker._save_report()
        json_files = list(checker.output_dir.glob("cors_*.json"))
        report = json.loads(json_files[0].read_text(encoding="utf-8"))
        assert report["total_findings"] == 0
        assert report["findings"] == []


# ── Tests: Header Building ────────────────────────────────

class TestHeaderBuilding:

    @pytest.mark.unit
    def test_headers_include_origin(self, checker):
        """_build_headers harus menyertakan Origin."""
        headers = checker._build_headers("https://evil.com")
        assert "Origin" in headers
        assert headers["Origin"] == "https://evil.com"

    @pytest.mark.unit
    def test_headers_include_token(self, authed_checker):
        """_build_headers harus menyertakan Authorization jika ada token."""
        headers = authed_checker._build_headers("https://evil.com")
        assert "Authorization" in headers
        assert "Bearer" in headers["Authorization"]
        assert "test-token-123" in headers["Authorization"]

    @pytest.mark.unit
    def test_headers_no_token_by_default(self, checker):
        """_build_headers tidak boleh ada Authorization jika tidak ada token."""
        headers = checker._build_headers("https://evil.com")
        assert "Authorization" not in headers
