# tests/test_compliance.py
"""
Unit tests untuk modules/report/compliance.py
Pure logic testing — no network, no files required.
"""

import json
import pytest
from pathlib import Path

from modules.report.compliance import (
    OWASPMapper, PCIDSSChecker, ISO27001Mapper, ComplianceReporter,
    OWASPMapping, PCIMapping, ISOMapping, ComplianceReport,
    OWASP_TOP10_2021, PCI_DSS_REQUIREMENTS, ISO27001_CONTROLS,
)


# ── Fixtures ──────────────────────────────────────────────

def sqli_finding():
    return {
        "title":       "SQL Injection in /api/search",
        "severity":    "CRITICAL",
        "cvss":        9.8,
        "cwe":         "CWE-89",
        "target":      "https://target.com/api/search",
        "description": "SQL injection found in q parameter.",
        "evidence":    "MySQL error: syntax near",
        "remediation": "Use parameterized queries.",
    }


def xss_finding():
    return {
        "title":       "Reflected XSS in /search",
        "severity":    "HIGH",
        "cvss":        7.5,
        "cwe":         "CWE-79",
        "target":      "https://target.com/search",
        "description": "XSS reflected in search parameter.",
        "evidence":    "<script>alert(1)</script>",
        "remediation": "Sanitize output.",
    }


def ssrf_finding():
    return {
        "title":       "SSRF via redirect parameter",
        "severity":    "HIGH",
        "cvss":        8.1,
        "cwe":         "CWE-918",
        "target":      "https://target.com/redirect",
        "description": "SSRF to 169.254.169.254 metadata endpoint confirmed.",
        "evidence":    "ami-id in response",
        "remediation": "Validate and allowlist URLs.",
    }


def auth_finding():
    return {
        "title":       "MFA Bypass via null OTP",
        "severity":    "HIGH",
        "cvss":        8.1,
        "cwe":         "CWE-306",
        "target":      "https://target.com/auth/2fa",
        "description": "MFA bypass using null body in authentication request.",
        "evidence":    "HTTP 200 with valid session token",
        "remediation": "Validate OTP server-side.",
    }


def crypto_finding():
    return {
        "title":       "Weak SSH Cipher — RC4 (arcfour) Supported",
        "severity":    "CRITICAL",
        "cvss":        9.1,
        "cwe":         "CWE-327",
        "target":      "ssh://target.com:22",
        "description": "Weak cipher rc4 detected on SSH server.",
        "evidence":    "Cipher: arcfour",
        "remediation": "Disable RC4 ciphers.",
    }


def cve_finding():
    return {
        "title":       "Log4Shell CVE-2021-44228 Detected",
        "severity":    "CRITICAL",
        "cvss":        10.0,
        "cwe":         "CWE-1035",
        "target":      "https://target.com",
        "description": "Vulnerable component CVE-2021-44228 Log4Shell detected.",
        "evidence":    "JNDI lookup response triggered",
        "remediation": "Update Log4j to 2.17.1+",
    }


def all_findings():
    return [sqli_finding(), xss_finding(), ssrf_finding(),
            auth_finding(), crypto_finding(), cve_finding()]


@pytest.fixture
def owasp():
    return OWASPMapper()


@pytest.fixture
def pci():
    return PCIDSSChecker()


@pytest.fixture
def iso():
    return ISO27001Mapper()


@pytest.fixture
def reporter(tmp_path):
    return ComplianceReporter(
        findings=all_findings(),
        target="target.com",
        output_dir=str(tmp_path),
    )


# ── Tests: OWASP Data Integrity ───────────────────────────

class TestOWASPData:

    @pytest.mark.unit
    def test_all_10_categories_present(self):
        assert len(OWASP_TOP10_2021) == 10

    @pytest.mark.unit
    def test_categories_a01_to_a10(self):
        for i in range(1, 11):
            assert f"A{i:02d}" in OWASP_TOP10_2021

    @pytest.mark.unit
    def test_each_category_has_required_fields(self):
        required = {"name", "cwes", "keywords", "description", "remediation"}
        for cat_id, cat in OWASP_TOP10_2021.items():
            missing = required - set(cat.keys())
            assert not missing, f"{cat_id} missing: {missing}"

    @pytest.mark.unit
    def test_cwes_start_with_cwe(self):
        for cat in OWASP_TOP10_2021.values():
            for cwe in cat["cwes"]:
                assert cwe.startswith("CWE-"), f"Invalid CWE: {cwe}"


# ── Tests: OWASPMapper ────────────────────────────────────

class TestOWASPMapper:

    @pytest.mark.unit
    def test_sqli_maps_to_a03(self, owasp):
        mapping = owasp.map_finding(sqli_finding())
        assert mapping is not None
        assert mapping.category_id == "A03"
        assert mapping.category_name == "Injection"

    @pytest.mark.unit
    def test_xss_maps_to_a03(self, owasp):
        mapping = owasp.map_finding(xss_finding())
        assert mapping is not None
        assert mapping.category_id == "A03"

    @pytest.mark.unit
    def test_ssrf_maps_to_a10(self, owasp):
        mapping = owasp.map_finding(ssrf_finding())
        assert mapping is not None
        assert mapping.category_id == "A10"

    @pytest.mark.unit
    def test_auth_maps_to_a07(self, owasp):
        mapping = owasp.map_finding(auth_finding())
        assert mapping is not None
        assert mapping.category_id == "A07"

    @pytest.mark.unit
    def test_crypto_maps_to_a02(self, owasp):
        mapping = owasp.map_finding(crypto_finding())
        assert mapping is not None
        assert mapping.category_id == "A02"

    @pytest.mark.unit
    def test_cve_maps_to_a06(self, owasp):
        mapping = owasp.map_finding(cve_finding())
        assert mapping is not None
        assert mapping.category_id == "A06"

    @pytest.mark.unit
    def test_map_findings_returns_dict(self, owasp):
        result = owasp.map_findings(all_findings())
        assert isinstance(result, dict)
        assert len(result) > 0

    @pytest.mark.unit
    def test_map_findings_groups_correctly(self, owasp):
        result = owasp.map_findings([sqli_finding(), xss_finding()])
        assert "A03" in result
        assert len(result["A03"]) == 2

    @pytest.mark.unit
    def test_coverage_summary_has_all_categories(self, owasp):
        summary = owasp.coverage_summary(all_findings())
        assert len(summary) == 10

    @pytest.mark.unit
    def test_coverage_summary_a03_covered(self, owasp):
        summary = owasp.coverage_summary([sqli_finding()])
        assert summary["A03"]["covered"] is True
        assert summary["A03"]["count"] >= 1

    @pytest.mark.unit
    def test_coverage_summary_uncovered_category(self, owasp):
        # Only SQLi — A10 (SSRF) should not be covered
        summary = owasp.coverage_summary([sqli_finding()])
        assert summary["A10"]["covered"] is False

    @pytest.mark.unit
    def test_empty_findings_returns_empty(self, owasp):
        result = owasp.map_findings([])
        assert result == {}

    @pytest.mark.unit
    def test_mapping_has_match_reason(self, owasp):
        mapping = owasp.map_finding(sqli_finding())
        assert mapping.match_reason != ""

    @pytest.mark.unit
    def test_cwe_match_priority(self, owasp):
        # CWE-89 explicitly in A03 — should match via CWE
        mapping = owasp.map_finding(sqli_finding())
        assert "CWE-89" in mapping.cwe
        assert "CWE match" in mapping.match_reason


# ── Tests: PCI DSS Data ───────────────────────────────────

class TestPCIData:

    @pytest.mark.unit
    def test_requirements_not_empty(self):
        assert len(PCI_DSS_REQUIREMENTS) >= 10

    @pytest.mark.unit
    def test_each_req_has_required_fields(self):
        required = {"title", "keywords", "severity", "guidance"}
        for req_id, req in PCI_DSS_REQUIREMENTS.items():
            missing = required - set(req.keys())
            assert not missing, f"{req_id} missing: {missing}"

    @pytest.mark.unit
    def test_severity_values_valid(self):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for req in PCI_DSS_REQUIREMENTS.values():
            assert req["severity"] in valid


# ── Tests: PCIDSSChecker ──────────────────────────────────

class TestPCIDSSChecker:

    @pytest.mark.unit
    def test_sqli_violates_6_2(self, pci):
        mappings = pci.check_findings([sqli_finding()])
        req_ids = [m.requirement_id for m in mappings]
        assert "6.2" in req_ids

    @pytest.mark.unit
    def test_crypto_violates_4_2(self, pci):
        mappings = pci.check_findings([crypto_finding()])
        req_ids = [m.requirement_id for m in mappings]
        assert "4.2" in req_ids

    @pytest.mark.unit
    def test_cve_violates_6_3(self, pci):
        mappings = pci.check_findings([cve_finding()])
        req_ids = [m.requirement_id for m in mappings]
        assert "6.3" in req_ids

    @pytest.mark.unit
    def test_auth_violates_8_3(self, pci):
        mappings = pci.check_findings([auth_finding()])
        req_ids = [m.requirement_id for m in mappings]
        assert "8.3" in req_ids or "8" in req_ids or "8.2" in req_ids

    @pytest.mark.unit
    def test_gap_analysis_structure(self, pci):
        gap = pci.gap_analysis(all_findings())
        assert isinstance(gap, dict)
        for req_id, info in gap.items():
            assert "violated" in info
            assert "severity" in info
            assert isinstance(info["violated"], bool)

    @pytest.mark.unit
    def test_compliance_score_range(self, pci):
        score = pci.compliance_score(all_findings())
        assert 0 <= score <= 100

    @pytest.mark.unit
    def test_no_findings_100_percent(self, pci):
        score = pci.compliance_score([])
        assert score == 100.0

    @pytest.mark.unit
    def test_empty_findings_no_violations(self, pci):
        mappings = pci.check_findings([])
        assert mappings == []

    @pytest.mark.unit
    def test_mapping_has_titles(self, pci):
        mappings = pci.check_findings([sqli_finding()])
        for m in mappings:
            assert m.requirement_title != ""
            assert m.finding_title != ""


# ── Tests: ISO 27001 Data ─────────────────────────────────

class TestISO27001Data:

    @pytest.mark.unit
    def test_controls_not_empty(self):
        assert len(ISO27001_CONTROLS) >= 12

    @pytest.mark.unit
    def test_each_control_has_required_fields(self):
        required = {"title", "keywords", "domain"}
        for ctrl_id, ctrl in ISO27001_CONTROLS.items():
            missing = required - set(ctrl.keys())
            assert not missing, f"{ctrl_id} missing: {missing}"

    @pytest.mark.unit
    def test_control_ids_format(self):
        for ctrl_id in ISO27001_CONTROLS:
            assert ctrl_id.startswith("A."), f"Invalid format: {ctrl_id}"


# ── Tests: ISO27001Mapper ─────────────────────────────────

class TestISO27001Mapper:

    @pytest.mark.unit
    def test_sqli_violates_a8_28(self, iso):
        mappings = iso.map_findings([sqli_finding()])
        ctrl_ids = [m.control_id for m in mappings]
        assert "A.8.28" in ctrl_ids

    @pytest.mark.unit
    def test_auth_violates_a8_5(self, iso):
        mappings = iso.map_findings([auth_finding()])
        ctrl_ids = [m.control_id for m in mappings]
        assert "A.8.5" in ctrl_ids

    @pytest.mark.unit
    def test_cve_violates_a8_8(self, iso):
        mappings = iso.map_findings([cve_finding()])
        ctrl_ids = [m.control_id for m in mappings]
        assert "A.8.8" in ctrl_ids

    @pytest.mark.unit
    def test_controls_violated_returns_sorted_list(self, iso):
        violated = iso.controls_violated(all_findings())
        assert isinstance(violated, list)
        assert violated == sorted(violated)

    @pytest.mark.unit
    def test_domain_summary_returns_dict(self, iso):
        summary = iso.domain_summary(all_findings())
        assert isinstance(summary, dict)
        assert all(isinstance(v, int) for v in summary.values())

    @pytest.mark.unit
    def test_empty_findings(self, iso):
        mappings = iso.map_findings([])
        assert mappings == []

    @pytest.mark.unit
    def test_mapping_has_domain(self, iso):
        mappings = iso.map_findings([sqli_finding()])
        for m in mappings:
            assert m.domain != ""
            assert m.control_title != ""


# ── Tests: ComplianceReporter ─────────────────────────────

class TestComplianceReporter:

    @pytest.mark.unit
    def test_init(self, reporter):
        assert reporter.target == "target.com"
        assert reporter.output_dir.exists()

    @pytest.mark.unit
    def test_build_report_structure(self, reporter):
        report = reporter._build_report()
        assert isinstance(report, ComplianceReport)
        assert report.total_findings == len(all_findings())
        assert report.risk_score >= 0.0

    @pytest.mark.unit
    def test_risk_score_is_avg_cvss(self, reporter):
        report = reporter._build_report()
        cvss_avg = sum(f["cvss"] for f in all_findings()) / len(all_findings())
        assert abs(report.risk_score - cvss_avg) < 0.1

    @pytest.mark.unit
    def test_save_json_creates_file(self, reporter, tmp_path):
        report = reporter._build_report()
        path   = reporter._save_json(report)
        assert path.exists()
        data = json.loads(path.read_text())
        assert "owasp_mappings" in data
        assert "pci_mappings" in data
        assert "iso_mappings" in data

    @pytest.mark.unit
    def test_save_html_creates_file(self, reporter, tmp_path):
        report = reporter._build_report()
        path   = reporter._save_html(report)
        assert path.exists()
        content = path.read_text()
        assert "<!DOCTYPE html>" in content
        assert "OWASP" in content
        assert "PCI DSS" in content
        assert "ISO 27001" in content

    @pytest.mark.unit
    def test_generate_all_returns_paths(self, reporter, tmp_path):
        paths = reporter.generate_all()
        assert "json" in paths
        assert "html" in paths
        assert paths["json"].exists()
        assert paths["html"].exists()

    @pytest.mark.unit
    def test_report_owasp_coverage_not_empty(self, reporter):
        report = reporter._build_report()
        assert len(report.owasp_coverage) > 0

    @pytest.mark.unit
    def test_report_pci_coverage(self, reporter):
        report = reporter._build_report()
        assert isinstance(report.pci_coverage, dict)

    @pytest.mark.unit
    def test_empty_findings_reporter(self, tmp_path):
        r = ComplianceReporter(findings=[], target="t.com",
                               output_dir=str(tmp_path))
        report = r._build_report()
        assert report.total_findings == 0
        assert report.risk_score == 0.0
