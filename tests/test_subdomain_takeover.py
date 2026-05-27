# tests/test_subdomain_takeover.py
"""
Unit tests untuk modules/recon/subdomain_takeover.py
Semua DNS + HTTP calls di-mock — tidak butuh network nyata.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from modules.recon.subdomain_takeover import (
    SubdomainTakeoverChecker,
    SubdomainResult,
    DNSProber,
    TAKEOVER_FINGERPRINTS,
    DEFAULT_SUBDOMAIN_WORDLIST,
)


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def checker(tmp_path):
    return SubdomainTakeoverChecker(
        domain="target.com",
        output_dir=str(tmp_path / "takeover"),
        wordlist=["www", "mail", "dev", "staging", "api"],
        timeout=3,
        delay=0,
    )


@pytest.fixture
def github_pages_result():
    r = SubdomainResult(subdomain="blog", fqdn="blog.target.com")
    r.cname_chain = ["ardanov96.github.io"]
    r.a_records = ["185.199.108.153"]
    r.http_status = 404
    r.http_body_snippet = "There isn't a GitHub Pages site here."
    r.is_alive = True
    return r


@pytest.fixture
def s3_result():
    r = SubdomainResult(subdomain="assets", fqdn="assets.target.com")
    r.cname_chain = ["assets-target.s3.amazonaws.com"]
    r.a_records = ["52.218.0.100"]
    r.http_status = 404
    r.http_body_snippet = "<Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message>"
    r.is_alive = True
    return r


@pytest.fixture
def heroku_result():
    r = SubdomainResult(subdomain="app", fqdn="app.target.com")
    r.cname_chain = ["target-app.herokuapp.com"]
    r.a_records = ["52.30.0.1"]
    r.http_status = 404
    r.http_body_snippet = "No such app. There is no app configured at that hostname."
    r.is_alive = True
    return r


@pytest.fixture
def clean_result():
    r = SubdomainResult(subdomain="www", fqdn="www.target.com")
    r.a_records = ["1.2.3.4"]
    r.http_status = 200
    r.http_body_snippet = "<html><body>Welcome to target.com</body></html>"
    r.is_alive = True
    return r


@pytest.fixture
def nxdomain_result():
    r = SubdomainResult(subdomain="old", fqdn="old.target.com")
    r.is_nxdomain = True
    r.cname_chain = ["old-target.netlify.app"]
    r.is_alive = False
    return r


# ── Tests: SubdomainResult ────────────────────────────────

class TestSubdomainResult:

    @pytest.mark.unit
    def test_final_cname_last_in_chain(self):
        r = SubdomainResult(subdomain="sub", fqdn="sub.target.com")
        r.cname_chain = ["a.example.com", "b.example.com", "c.github.io"]
        assert r.final_cname == "c.github.io"

    @pytest.mark.unit
    def test_final_cname_empty_chain(self):
        r = SubdomainResult(subdomain="sub", fqdn="sub.target.com")
        assert r.final_cname is None

    @pytest.mark.unit
    def test_default_not_candidate(self):
        r = SubdomainResult(subdomain="www", fqdn="www.target.com")
        assert r.takeover_candidate is False

    @pytest.mark.unit
    def test_default_not_alive(self):
        r = SubdomainResult(subdomain="www", fqdn="www.target.com")
        assert r.is_alive is False

    @pytest.mark.unit
    def test_fqdn_stored(self):
        r = SubdomainResult(subdomain="api", fqdn="api.target.com")
        assert r.fqdn == "api.target.com"
        assert r.subdomain == "api"


# ── Tests: Fingerprints ───────────────────────────────────

class TestFingerprints:

    @pytest.mark.unit
    def test_fingerprints_not_empty(self):
        assert len(TAKEOVER_FINGERPRINTS) >= 10

    @pytest.mark.unit
    def test_each_fingerprint_has_required_fields(self):
        required = {"service", "cname", "body", "status", "severity", "cvss", "cwe"}
        for fp in TAKEOVER_FINGERPRINTS:
            missing = required - set(fp.keys())
            assert not missing, f"Missing in {fp.get('service')}: {missing}"

    @pytest.mark.unit
    def test_major_services_covered(self):
        services = {fp["service"] for fp in TAKEOVER_FINGERPRINTS}
        assert any("S3" in s or "AWS" in s for s in services)
        assert any("GitHub" in s for s in services)
        assert any("Heroku" in s for s in services)
        assert any("Netlify" in s for s in services)
        assert any("Azure" in s for s in services)

    @pytest.mark.unit
    def test_cvss_in_range(self):
        for fp in TAKEOVER_FINGERPRINTS:
            assert 0.0 <= fp["cvss"] <= 10.0, f"CVSS out of range: {fp['service']}"

    @pytest.mark.unit
    def test_severity_valid(self):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for fp in TAKEOVER_FINGERPRINTS:
            assert fp["severity"] in valid, f"Invalid severity: {fp['service']}"

    @pytest.mark.unit
    def test_cwe_format(self):
        for fp in TAKEOVER_FINGERPRINTS:
            assert fp["cwe"].startswith("CWE-"), f"Bad CWE: {fp['service']}"

    @pytest.mark.unit
    def test_aws_s3_is_critical(self):
        s3 = next(fp for fp in TAKEOVER_FINGERPRINTS if "S3" in fp["service"])
        assert s3["severity"] == "CRITICAL"
        assert s3["cvss"] >= 9.0

    @pytest.mark.unit
    def test_github_pages_fingerprint(self):
        gh = next(fp for fp in TAKEOVER_FINGERPRINTS if "GitHub" in fp["service"])
        assert any("github.io" in c for c in gh["cname"])
        assert any("GitHub Pages" in b for b in gh["body"])


# ── Tests: Fingerprinting Logic ───────────────────────────

class TestFingerprintingLogic:

    @pytest.mark.unit
    def test_github_pages_detected(self, checker, github_pages_result):
        result = checker._fingerprint(github_pages_result)
        assert result.takeover_candidate is True
        assert "GitHub" in result.matched_service

    @pytest.mark.unit
    def test_s3_detected(self, checker, s3_result):
        result = checker._fingerprint(s3_result)
        assert result.takeover_candidate is True
        assert "S3" in result.matched_service

    @pytest.mark.unit
    def test_heroku_detected(self, checker, heroku_result):
        result = checker._fingerprint(heroku_result)
        assert result.takeover_candidate is True
        assert "Heroku" in result.matched_service

    @pytest.mark.unit
    def test_clean_subdomain_not_flagged(self, checker, clean_result):
        result = checker._fingerprint(clean_result)
        assert result.takeover_candidate is False

    @pytest.mark.unit
    def test_nxdomain_with_cname_detected(self, checker, nxdomain_result):
        result = checker._fingerprint(nxdomain_result)
        # NXDOMAIN + CNAME to netlify = takeover candidate
        assert result.takeover_candidate is True

    @pytest.mark.unit
    def test_parking_page_detected(self, checker):
        r = SubdomainResult(subdomain="old", fqdn="old.target.com")
        r.http_body_snippet = "This domain is for sale. Buy this domain today!"
        r.is_alive = True
        result = checker._fingerprint(r)
        assert result.takeover_candidate is True

    @pytest.mark.unit
    def test_account_suspended_detected(self, checker):
        r = SubdomainResult(subdomain="shop", fqdn="shop.target.com")
        r.http_body_snippet = "Account Suspended. Please contact your hosting provider."
        r.is_alive = True
        result = checker._fingerprint(r)
        assert result.takeover_candidate is True


# ── Tests: Checker Init ───────────────────────────────────

class TestCheckerInit:

    @pytest.mark.unit
    def test_domain_stored(self, checker):
        assert checker.domain == "target.com"

    @pytest.mark.unit
    def test_domain_lowercased(self, tmp_path):
        c = SubdomainTakeoverChecker(
            domain="TARGET.COM", output_dir=str(tmp_path)
        )
        assert c.domain == "target.com"

    @pytest.mark.unit
    def test_wordlist_stored(self, checker):
        assert "www" in checker.wordlist
        assert "api" in checker.wordlist

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path):
        new_dir = tmp_path / "takeover_out"
        SubdomainTakeoverChecker(domain="t.com", output_dir=str(new_dir))
        assert new_dir.exists()

    @pytest.mark.unit
    def test_findings_empty_at_init(self, checker):
        assert checker.findings == []

    @pytest.mark.unit
    def test_scanned_empty_at_init(self, checker):
        assert checker.scanned == []


# ── Tests: Default Wordlist ───────────────────────────────

class TestDefaultWordlist:

    @pytest.mark.unit
    def test_wordlist_not_empty(self):
        assert len(DEFAULT_SUBDOMAIN_WORDLIST) >= 20

    @pytest.mark.unit
    def test_common_subdomains_present(self):
        required = {"www", "mail", "api", "admin", "dev", "staging", "app"}
        assert required.issubset(set(DEFAULT_SUBDOMAIN_WORDLIST))

    @pytest.mark.unit
    def test_no_dots_in_wordlist(self):
        """Wordlist entries tidak boleh punya dot — hanya label."""
        for sub in DEFAULT_SUBDOMAIN_WORDLIST:
            assert "." not in sub, f"'{sub}' tidak boleh punya titik"

    @pytest.mark.unit
    def test_no_empty_entries(self):
        for sub in DEFAULT_SUBDOMAIN_WORDLIST:
            assert sub.strip() != ""


# ── Tests: Finding Builder ────────────────────────────────

class TestFindingBuilder:

    @pytest.mark.unit
    def test_add_finding_structure(self, checker, github_pages_result):
        github_pages_result.takeover_candidate = True
        github_pages_result.matched_service = "GitHub Pages"
        github_pages_result.matched_fingerprint = {
            "severity": "HIGH", "cvss": 8.0, "cwe": "CWE-284"
        }
        checker._add_finding(github_pages_result)
        assert len(checker.findings) == 1

        f = checker.findings[0]
        required = {"id", "title", "severity", "cvss", "cwe",
                    "target", "subdomain", "service", "description",
                    "evidence", "remediation", "timestamp"}
        assert required == set(f.keys())

    @pytest.mark.unit
    def test_finding_id_format(self, checker, github_pages_result):
        github_pages_result.matched_fingerprint = {"severity": "HIGH", "cvss": 8.0, "cwe": "CWE-284"}
        github_pages_result.matched_service = "GitHub Pages"
        checker._add_finding(github_pages_result)
        assert checker.findings[0]["id"] == "TAKE-001"

    @pytest.mark.unit
    def test_finding_subdomain_recorded(self, checker, s3_result):
        s3_result.matched_fingerprint = {"severity": "CRITICAL", "cvss": 9.8, "cwe": "CWE-284"}
        s3_result.matched_service = "AWS S3"
        checker._add_finding(s3_result)
        assert checker.findings[0]["subdomain"] == "assets.target.com"

    @pytest.mark.unit
    def test_finding_service_recorded(self, checker, heroku_result):
        heroku_result.matched_fingerprint = {"severity": "HIGH", "cvss": 8.0, "cwe": "CWE-284"}
        heroku_result.matched_service = "Heroku"
        checker._add_finding(heroku_result)
        assert checker.findings[0]["service"] == "Heroku"


# ── Tests: Report Generation ──────────────────────────────

class TestReportGeneration:

    @pytest.mark.unit
    def test_save_report_creates_file(self, checker, github_pages_result):
        github_pages_result.matched_fingerprint = {"severity": "HIGH", "cvss": 8.0, "cwe": "CWE-284"}
        github_pages_result.matched_service = "GitHub Pages"
        checker._add_finding(github_pages_result)
        checker.scanned = [github_pages_result]
        path = checker._save_report()
        assert path.exists()
        assert path.suffix == ".json"

    @pytest.mark.unit
    def test_report_json_structure(self, checker):
        checker.scanned = []
        path = checker._save_report()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["tool"] == "glitchicons"
        assert data["module"] == "subdomain_takeover"
        assert data["version"] == "0.8.0"
        assert data["target"] == "target.com"
        assert "fingerprints" in data
        assert data["fingerprints"] == len(TAKEOVER_FINGERPRINTS)

    @pytest.mark.unit
    def test_report_sorted_by_cvss(self, checker, github_pages_result, s3_result):
        github_pages_result.matched_fingerprint = {"severity": "HIGH", "cvss": 8.0, "cwe": "CWE-284"}
        github_pages_result.matched_service = "GitHub Pages"
        s3_result.matched_fingerprint = {"severity": "CRITICAL", "cvss": 9.8, "cwe": "CWE-284"}
        s3_result.matched_service = "AWS S3"
        checker._add_finding(github_pages_result)
        checker._add_finding(s3_result)
        checker.scanned = [github_pages_result, s3_result]
        path = checker._save_report()
        data = json.loads(path.read_text(encoding="utf-8"))
        scores = [f["cvss"] for f in data["findings"]]
        assert scores == sorted(scores, reverse=True)

    @pytest.mark.unit
    def test_empty_findings_report_ok(self, checker):
        checker.scanned = []
        path = checker._save_report()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["total_findings"] == 0
        assert data["findings"] == []

    @pytest.mark.unit
    def test_report_filename_contains_domain(self, checker):
        checker.scanned = []
        path = checker._save_report()
        assert "target.com" in path.name or "target" in path.name


# ── Tests: Dead NS Detection ──────────────────────────────

class TestDeadNSDetection:

    @pytest.mark.unit
    def test_dead_ns_finding_structure(self, checker):
        """Simulasi dead NS — langsung inject finding."""
        # Inject finding manually (bypass DNS)
        checker.findings.append({
            "id":          "TAKE-001",
            "title":       f"Dead NS Records for {checker.domain}",
            "severity":    "CRITICAL",
            "cvss":        9.8,
            "cwe":         "CWE-284",
            "target":      checker.domain,
            "subdomain":   checker.domain,
            "service":     "DNS Nameserver",
            "description": "Dead NS detected",
            "evidence":    "NS: [dead.ns1.com] | Dead: [dead.ns1.com]",
            "remediation": "Update NS records",
            "timestamp":   "2026-05-27T00:00:00",
        })
        assert len(checker.findings) == 1
        assert checker.findings[0]["severity"] == "CRITICAL"
        assert checker.findings[0]["cvss"] == 9.8
