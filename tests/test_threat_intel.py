# tests/test_threat_intel.py
"""
Unit tests untuk modules/intelligence/threat_intel.py
Network calls di-mock — tidak butuh NVD/Shodan/crt.sh API keys.
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from modules.intelligence.threat_intel import (
    CVELookup, ShodanRecon, CTRecon, ExploitChecker, ThreatIntelScanner,
    CVEResult, ShodanHost, CTDomain, ThreatIntelResult,
    _finding, _cve_severity,
    KNOWN_CRITICAL_CVES, EPSS_CRITICAL, EPSS_HIGH,
    NVD_API_URL, EPSS_API_URL, CRTSH_API_URL,
)


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def cve_lookup(tmp_path):
    return CVELookup(output_dir=str(tmp_path), timeout=5)


@pytest.fixture
def shodan(tmp_path):
    return ShodanRecon(api_key="test_key", output_dir=str(tmp_path), timeout=5)


@pytest.fixture
def ct(tmp_path):
    return CTRecon(output_dir=str(tmp_path), timeout=5)


@pytest.fixture
def exploit(tmp_path):
    return ExploitChecker(output_dir=str(tmp_path), timeout=5)


@pytest.fixture
def scanner(tmp_path):
    return ThreatIntelScanner(
        target="https://target.com",
        output_dir=str(tmp_path),
        timeout=5,
    )


def sample_finding(cve_id="CVE-2021-44228"):
    return {
        "title":       f"Log4Shell {cve_id}",
        "severity":    "CRITICAL",
        "cvss":        10.0,
        "cwe":         "CWE-917",
        "target":      "https://target.com",
        "description": f"Log4Shell vulnerability {cve_id} detected",
        "evidence":    f"CVE: {cve_id}",
        "remediation": "Update Log4j",
    }


def mock_resp(status=200, json_data=None, text=""):
    m = MagicMock()
    m.status_code = status
    m.text = text or (json.dumps(json_data) if json_data else "")
    if json_data is not None:
        m.json.return_value = json_data
    else:
        m.json.side_effect = Exception("no json")
    return m


# ── Tests: _finding ───────────────────────────────────────

class TestFinding:

    @pytest.mark.unit
    def test_valid(self):
        f = _finding("T", "HIGH", 7.5, "CWE-89", "d", "e", "r", "t")
        assert f["severity"] == "HIGH"

    @pytest.mark.unit
    def test_invalid_severity(self):
        with pytest.raises(AssertionError):
            _finding("T", "EXTREME", 7.5, "CWE-89", "d", "e", "r", "t")


# ── Tests: _cve_severity ──────────────────────────────────

class TestCVESeverity:

    @pytest.mark.unit
    def test_critical(self):
        assert _cve_severity(9.8) == "CRITICAL"

    @pytest.mark.unit
    def test_high(self):
        assert _cve_severity(7.5) == "HIGH"

    @pytest.mark.unit
    def test_medium(self):
        assert _cve_severity(5.0) == "MEDIUM"

    @pytest.mark.unit
    def test_low(self):
        assert _cve_severity(2.0) == "LOW"

    @pytest.mark.unit
    def test_boundary_critical(self):
        assert _cve_severity(9.0) == "CRITICAL"

    @pytest.mark.unit
    def test_boundary_high(self):
        assert _cve_severity(7.0) == "HIGH"


# ── Tests: CVEResult ──────────────────────────────────────

class TestCVEResult:

    @pytest.mark.unit
    def test_init(self):
        r = CVEResult(
            cve_id="CVE-2021-44228", description="Log4Shell",
            cvss_score=10.0, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            severity="CRITICAL", published="2021-12-10", modified="2021-12-14",
        )
        assert r.cve_id == "CVE-2021-44228"
        assert r.epss_score == 0.0

    @pytest.mark.unit
    def test_epss_defaults(self):
        r = CVEResult("CVE-2021-44228", "", 10.0, "", "CRITICAL", "", "")
        assert r.epss_score == 0.0
        assert r.has_exploit is False


# ── Tests: CVELookup ──────────────────────────────────────

class TestCVELookup:

    @pytest.mark.unit
    def test_init(self, cve_lookup):
        assert cve_lookup.output_dir.exists()

    @pytest.mark.unit
    def test_search_by_cve_id_success(self, cve_lookup):
        nvd_resp = mock_resp(200, json_data={
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [{"lang": "en", "value": "Log4Shell RCE"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {
                        "baseScore": 10.0,
                        "vectorString": "CVSS:3.1/AV:N",
                    }}]},
                    "published": "2021-12-10",
                    "lastModified": "2021-12-14",
                    "references": [],
                }
            }]
        })
        epss_resp = mock_resp(200, json_data={
            "data": [{"cve": "CVE-2021-44228", "epss": "0.975", "percentile": "0.99"}]
        })
        with patch.object(cve_lookup.client, "get", side_effect=[nvd_resp, epss_resp]):
            result = cve_lookup.search_by_cve_id("CVE-2021-44228")
        assert result is not None
        assert result.cve_id == "CVE-2021-44228"
        assert result.cvss_score == 10.0

    @pytest.mark.unit
    def test_search_by_cve_id_not_found(self, cve_lookup):
        resp = mock_resp(200, json_data={"vulnerabilities": []})
        with patch.object(cve_lookup.client, "get", return_value=resp):
            result = cve_lookup.search_by_cve_id("CVE-9999-99999")
        assert result is None

    @pytest.mark.unit
    def test_search_by_cve_id_api_error(self, cve_lookup):
        resp = mock_resp(500, text="error")
        with patch.object(cve_lookup.client, "get", return_value=resp):
            result = cve_lookup.search_by_cve_id("CVE-2021-44228")
        assert result is None

    @pytest.mark.unit
    def test_search_by_keyword(self, cve_lookup):
        nvd_resp = mock_resp(200, json_data={
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [{"lang": "en", "value": "Log4Shell"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "vectorString": ""}}]},
                    "published": "2021-12-10", "lastModified": "2021-12-14", "references": [],
                }
            }]
        })
        epss_resp = mock_resp(200, json_data={"data": []})
        with patch.object(cve_lookup.client, "get", side_effect=[nvd_resp, epss_resp]):
            results = cve_lookup.search_by_keyword("log4j")
        assert len(results) >= 1

    @pytest.mark.unit
    def test_get_epss_success(self, cve_lookup):
        resp = mock_resp(200, json_data={
            "data": [
                {"cve": "CVE-2021-44228", "epss": "0.975", "percentile": "0.99"},
                {"cve": "CVE-2022-0847",  "epss": "0.450", "percentile": "0.95"},
            ]
        })
        with patch.object(cve_lookup.client, "get", return_value=resp):
            scores = cve_lookup.get_epss(["CVE-2021-44228", "CVE-2022-0847"])
        assert "CVE-2021-44228" in scores
        assert scores["CVE-2021-44228"][0] == pytest.approx(0.975)

    @pytest.mark.unit
    def test_get_epss_empty_input(self, cve_lookup):
        result = cve_lookup.get_epss([])
        assert result == {}

    @pytest.mark.unit
    def test_get_epss_api_error(self, cve_lookup):
        with patch.object(cve_lookup.client, "get", side_effect=Exception("timeout")):
            result = cve_lookup.get_epss(["CVE-2021-44228"])
        assert result == {}

    @pytest.mark.unit
    def test_enrich_findings_high_epss(self, cve_lookup, tmp_path):
        findings = [sample_finding("CVE-2021-44228")]
        nvd_resp = mock_resp(200, json_data={
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [{"lang": "en", "value": "Log4Shell"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "vectorString": ""}}]},
                    "published": "2021-12-10", "lastModified": "2021-12-14", "references": [],
                }
            }]
        })
        epss_resp1 = mock_resp(200, json_data={
            "data": [{"cve": "CVE-2021-44228", "epss": "0.975", "percentile": "0.99"}]
        })
        epss_resp2 = mock_resp(200, json_data={
            "data": [{"cve": "CVE-2021-44228", "epss": "0.975", "percentile": "0.99"}]
        })
        with patch.object(cve_lookup.client, "get", side_effect=[nvd_resp, epss_resp1, epss_resp2]):
            new_findings = cve_lookup.enrich_findings(findings)
        assert len(new_findings) >= 1
        assert new_findings[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_enrich_findings_no_cve(self, cve_lookup):
        findings = [{"title": "CORS misconfiguration", "description": "No CVE", "evidence": ""}]
        new_findings = cve_lookup.enrich_findings(findings)
        assert new_findings == []

    @pytest.mark.unit
    def test_network_error_returns_empty(self, cve_lookup):
        with patch.object(cve_lookup.client, "get", side_effect=Exception("timeout")):
            result = cve_lookup.search_by_cve_id("CVE-2021-44228")
        assert result is None


# ── Tests: ShodanRecon ────────────────────────────────────

class TestShodanRecon:

    @pytest.mark.unit
    def test_init(self, shodan):
        assert shodan.api_key == "test_key"
        assert shodan.output_dir.exists()

    @pytest.mark.unit
    def test_no_api_key_returns_none(self, tmp_path):
        s = ShodanRecon(api_key="", output_dir=str(tmp_path))
        result = s.lookup_ip("1.2.3.4")
        assert result is None

    @pytest.mark.unit
    def test_lookup_ip_success(self, shodan):
        resp = mock_resp(200, json_data={
            "ip_str": "1.2.3.4",
            "hostnames": ["target.com"],
            "org": "Target Corp",
            "country_name": "United States",
            "ports": [80, 443, 22, 3306],
            "vulns": {"CVE-2021-44228": {}},
            "tags": [],
            "last_update": "2024-01-01",
            "data": [],
        })
        with patch.object(shodan.client, "get", return_value=resp):
            host = shodan.lookup_ip("1.2.3.4")
        assert host is not None
        assert host.ip == "1.2.3.4"
        assert 3306 in host.open_ports
        assert "CVE-2021-44228" in host.vulns

    @pytest.mark.unit
    def test_lookup_ip_api_error(self, shodan):
        with patch.object(shodan.client, "get", side_effect=Exception("timeout")):
            result = shodan.lookup_ip("1.2.3.4")
        assert result is None

    @pytest.mark.unit
    def test_build_findings_critical_port(self, shodan):
        host = ShodanHost(
            ip="1.2.3.4", hostnames=["target.com"], org="Corp",
            country="US", open_ports=[3306, 27017], vulns=[],
            tags=[], last_update="2024-01-01",
        )
        findings = shodan.build_findings(host, "https://target.com")
        critical = [f for f in findings if f["severity"] == "CRITICAL"]
        assert len(critical) >= 2  # MySQL + MongoDB

    @pytest.mark.unit
    def test_build_findings_cve(self, shodan):
        host = ShodanHost(
            ip="1.2.3.4", hostnames=[], org="", country="",
            open_ports=[], vulns=["CVE-2021-44228"],
            tags=[], last_update="",
        )
        findings = shodan.build_findings(host, "https://target.com")
        cve_f = [f for f in findings if "CVE-2021-44228" in f["title"]]
        assert len(cve_f) >= 1

    @pytest.mark.unit
    def test_build_findings_honeypot(self, shodan):
        host = ShodanHost(
            ip="1.2.3.4", hostnames=[], org="", country="",
            open_ports=[], vulns=[], tags=["honeypot"], last_update="",
        )
        findings = shodan.build_findings(host, "target.com")
        hp = [f for f in findings if "Honeypot" in f["title"]]
        assert len(hp) >= 1

    @pytest.mark.unit
    def test_dangerous_ports_not_empty(self, shodan):
        assert len(shodan.DANGEROUS_PORTS) >= 10
        assert 445 in shodan.DANGEROUS_PORTS  # SMB
        assert 6379 in shodan.DANGEROUS_PORTS  # Redis


# ── Tests: CTRecon ────────────────────────────────────────

class TestCTRecon:

    @pytest.mark.unit
    def test_init(self, ct):
        assert ct.output_dir.exists()

    @pytest.mark.unit
    def test_find_subdomains_success(self, ct):
        resp = mock_resp(200, json_data=[
            {"name_value": "api.target.com"},
            {"name_value": "admin.target.com"},
            {"name_value": "staging.target.com"},
            {"name_value": "*.target.com"},
        ])
        with patch.object(ct.client, "get", return_value=resp):
            domains = ct.find_subdomains("target.com")
        assert isinstance(domains, list)

    @pytest.mark.unit
    def test_find_subdomains_api_error(self, ct):
        with patch.object(ct.client, "get", side_effect=Exception("timeout")):
            domains = ct.find_subdomains("target.com")
        assert domains == []

    @pytest.mark.unit
    def test_parse_ct_response(self, ct):
        data = [
            {"name_value": "api.target.com"},
            {"name_value": "admin.target.com\ndev.target.com"},
            {"name_value": "*.target.com"},  # wildcard stripped
        ]
        result = ct._parse_ct_response(data, "target.com")
        assert "api.target.com" in result
        assert "admin.target.com" in result

    @pytest.mark.unit
    def test_build_findings_with_subdomains(self, ct):
        subdomains = [
            "api.target.com", "admin.target.com",
            "staging.target.com", "db.target.com",
        ]
        findings = ct.build_findings("target.com", subdomains)
        assert len(findings) >= 1
        sensitive = [f for f in findings if "Sensitive" in f["title"]]
        assert len(sensitive) >= 1

    @pytest.mark.unit
    def test_build_findings_empty_subdomains(self, ct):
        findings = ct.build_findings("target.com", [])
        assert findings == []

    @pytest.mark.unit
    def test_get_ct_entries_success(self, ct):
        resp = mock_resp(200, json_data=[
            {
                "name_value": "api.target.com",
                "issuer_name": "Let's Encrypt",
                "not_before": "2024-01-01",
                "not_after": "2024-04-01",
                "entry_timestamp": "2024-01-01",
            }
        ])
        with patch.object(ct.client, "get", return_value=resp):
            entries = ct.get_ct_entries("target.com")
        assert isinstance(entries, list)


# ── Tests: ExploitChecker ─────────────────────────────────

class TestExploitChecker:

    @pytest.mark.unit
    def test_init(self, exploit):
        assert exploit.output_dir.exists()

    @pytest.mark.unit
    def test_check_known_cve(self, exploit):
        result = exploit.check_cve("CVE-2021-44228")
        assert result is not None
        assert result["name"] == "Log4Shell"
        assert result["cvss"] == 10.0

    @pytest.mark.unit
    def test_check_unknown_cve(self, exploit):
        result = exploit.check_cve("CVE-9999-99999")
        assert result is None

    @pytest.mark.unit
    def test_check_cve_case_insensitive(self, exploit):
        result = exploit.check_cve("cve-2021-44228")
        assert result is not None

    @pytest.mark.unit
    def test_check_multiple(self, exploit):
        results = exploit.check_multiple(["CVE-2021-44228", "CVE-2017-0144", "CVE-9999-0000"])
        assert "CVE-2021-44228" in results
        assert "CVE-2017-0144" in results
        assert "CVE-9999-0000" not in results

    @pytest.mark.unit
    def test_check_findings_with_known_cve(self, exploit):
        findings = [sample_finding("CVE-2021-44228")]
        new_findings = exploit.check_findings(findings)
        assert len(new_findings) >= 1
        assert new_findings[0]["severity"] in ("CRITICAL", "HIGH")
        assert "CVE-2021-44228" in new_findings[0]["title"]

    @pytest.mark.unit
    def test_check_findings_no_cve(self, exploit):
        findings = [{"title": "CORS", "description": "No CVE", "evidence": "", "target": "t"}]
        new_findings = exploit.check_findings(findings)
        assert new_findings == []

    @pytest.mark.unit
    def test_known_critical_cves_not_empty(self):
        assert len(KNOWN_CRITICAL_CVES) >= 10
        assert "CVE-2021-44228" in KNOWN_CRITICAL_CVES
        assert "CVE-2017-0144" in KNOWN_CRITICAL_CVES
        assert "CVE-2019-0708" in KNOWN_CRITICAL_CVES

    @pytest.mark.unit
    def test_log4shell_critical(self):
        info = KNOWN_CRITICAL_CVES["CVE-2021-44228"]
        assert info["cvss"] >= 9.0
        assert info["type"] == "RCE"

    @pytest.mark.unit
    def test_eternalblue_present(self):
        info = KNOWN_CRITICAL_CVES["CVE-2017-0144"]
        assert info["name"] == "EternalBlue"


# ── Tests: ThreatIntelScanner ─────────────────────────────

class TestThreatIntelScanner:

    @pytest.mark.unit
    def test_init(self, scanner):
        assert scanner.target == "https://target.com"
        assert scanner.output_dir.exists()

    @pytest.mark.unit
    def test_extract_domain(self, scanner):
        assert scanner._extract_domain() == "target.com"

    @pytest.mark.unit
    def test_extract_domain_with_path(self, tmp_path):
        s = ThreatIntelScanner("https://api.target.com/v1/users", output_dir=str(tmp_path))
        assert s._extract_domain() == "api.target.com"

    @pytest.mark.unit
    def test_extract_domain_plain(self, tmp_path):
        s = ThreatIntelScanner("target.com", output_dir=str(tmp_path))
        assert s._extract_domain() == "target.com"

    @pytest.mark.unit
    def test_run_returns_result(self, scanner):
        ct_resp = mock_resp(200, json_data=[
            {"name_value": "api.target.com"},
        ])
        with patch.object(scanner._ct.client, "get", return_value=ct_resp):
            with patch.object(scanner._cve.client, "get", side_effect=Exception("no net")):
                result = scanner.run(findings=[])
        assert isinstance(result, ThreatIntelResult)
        assert result.target == "https://target.com"

    @pytest.mark.unit
    def test_run_saves_file(self, scanner, tmp_path):
        ct_resp = mock_resp(200, json_data=[])
        with patch.object(scanner._ct.client, "get", return_value=ct_resp):
            with patch.object(scanner._cve.client, "get", side_effect=Exception("no net")):
                scanner.run(findings=[])
        files = list(tmp_path.glob("threat_intel_*.json"))
        assert len(files) >= 1

    @pytest.mark.unit
    def test_epss_constants(self):
        assert EPSS_CRITICAL > EPSS_HIGH
        assert EPSS_HIGH > 0
        assert EPSS_CRITICAL <= 1.0
