# tests/test_cicd_native.py
"""
Unit tests untuk modules/integrations/cicd_native.py
Network calls di-mock — tidak butuh real GitHub/GitLab/DefectDojo.
"""

import gzip
import json
import base64
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from modules.integrations.cicd_native import (
    SARIFExporter, GitHubIntegration, GitLabIntegration,
    DefectDojoIntegration, ExportResult,
    SARIF_LEVEL, GITLAB_SEVERITY, DOJO_SEVERITY,
)


# ── Sample data ───────────────────────────────────────────

def make_finding(severity="HIGH", title="Test Finding", cvss=7.5, cwe="CWE-89"):
    return {
        "id":          "f001",
        "title":       title,
        "severity":    severity,
        "cvss":        cvss,
        "cwe":         cwe,
        "target":      "https://target.com/api/search",
        "description": "A security vulnerability was found",
        "evidence":    "Payload: ' OR 1=1-- triggered error",
        "remediation": "Use parameterized queries",
        "source":      "module:sqli_tester",
    }


SAMPLE_FINDINGS = [
    make_finding("CRITICAL", "SQL Injection",      9.8,  "CWE-89"),
    make_finding("HIGH",     "Reflected XSS",      7.4,  "CWE-79"),
    make_finding("MEDIUM",   "CORS Wildcard",       5.9,  "CWE-942"),
    make_finding("LOW",      "Missing HSTS",        3.1,  "CWE-319"),
    make_finding("INFO",     "Version Disclosure",  0.0,  "CWE-200"),
]


def mock_resp(status=200, json_data=None):
    m = MagicMock()
    m.status_code = status
    if json_data is not None:
        m.json.return_value = json_data
    else:
        m.json.side_effect = Exception("no json")
    return m


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def sarif():
    return SARIFExporter(tool_name="Glitchicons", tool_version="3.2.0")


@pytest.fixture
def github(tmp_path):
    return GitHubIntegration(
        token="ghp_test_token",
        repo="ardanov96/glitchicons",
        timeout=5,
    )


@pytest.fixture
def gitlab():
    return GitLabIntegration(scanner_name="Glitchicons", scanner_version="3.2.0")


@pytest.fixture
def defectdojo():
    return DefectDojoIntegration(
        url="https://dojo.corp.com",
        api_key="test_api_key_123",
        timeout=5,
        verify_ssl=False,
    )


# ── Tests: SARIFExporter ──────────────────────────────────

class TestSARIFExporter:

    @pytest.mark.unit
    def test_init(self, sarif):
        assert sarif.tool_name    == "Glitchicons"
        assert sarif.tool_version == "3.2.0"

    @pytest.mark.unit
    def test_build_sarif_structure(self, sarif):
        doc = sarif.build_sarif(SAMPLE_FINDINGS)
        assert "$schema"  in doc
        assert "version"  in doc
        assert "runs"     in doc
        assert doc["version"] == "2.1.0"

    @pytest.mark.unit
    def test_build_sarif_has_rules(self, sarif):
        doc = sarif.build_sarif(SAMPLE_FINDINGS)
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 1

    @pytest.mark.unit
    def test_build_sarif_has_results(self, sarif):
        doc = sarif.build_sarif(SAMPLE_FINDINGS)
        results = doc["runs"][0]["results"]
        assert len(results) == len(SAMPLE_FINDINGS)

    @pytest.mark.unit
    def test_sarif_level_critical_is_error(self, sarif):
        doc = sarif.build_sarif([make_finding("CRITICAL")])
        result = doc["runs"][0]["results"][0]
        assert result["level"] == "error"

    @pytest.mark.unit
    def test_sarif_level_medium_is_warning(self, sarif):
        doc = sarif.build_sarif([make_finding("MEDIUM")])
        result = doc["runs"][0]["results"][0]
        assert result["level"] == "warning"

    @pytest.mark.unit
    def test_sarif_level_info_is_none(self, sarif):
        doc = sarif.build_sarif([make_finding("INFO")])
        result = doc["runs"][0]["results"][0]
        assert result["level"] == "none"

    @pytest.mark.unit
    def test_result_has_location(self, sarif):
        doc     = sarif.build_sarif([make_finding()])
        result  = doc["runs"][0]["results"][0]
        loc     = result["locations"][0]["physicalLocation"]
        assert "artifactLocation" in loc
        assert "uri" in loc["artifactLocation"]

    @pytest.mark.unit
    def test_result_message_contains_title(self, sarif):
        doc    = sarif.build_sarif([make_finding(title="SQL Injection Found")])
        result = doc["runs"][0]["results"][0]
        assert "SQL Injection Found" in result["message"]["text"]

    @pytest.mark.unit
    def test_export_creates_file(self, sarif, tmp_path):
        out = str(tmp_path / "results.sarif")
        result = sarif.export(SAMPLE_FINDINGS, output_path=out)
        assert result.success is True
        assert Path(out).exists()

    @pytest.mark.unit
    def test_exported_sarif_valid_json(self, sarif, tmp_path):
        out = str(tmp_path / "results.sarif")
        sarif.export(SAMPLE_FINDINGS, output_path=out)
        content = json.loads(Path(out).read_text())
        assert content["version"] == "2.1.0"

    @pytest.mark.unit
    def test_make_rule_id_with_cwe(self, sarif):
        f = make_finding(cwe="CWE-89")
        rule_id = sarif._make_rule_id(f)
        assert "0089" in rule_id or "89" in rule_id

    @pytest.mark.unit
    def test_count_by_level(self, sarif):
        counts = sarif.count_by_level(SAMPLE_FINDINGS)
        assert counts.get("error", 0)   >= 2   # CRITICAL + HIGH
        assert counts.get("warning", 0) >= 1   # MEDIUM

    @pytest.mark.unit
    def test_sarif_level_map_complete(self):
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert sev in SARIF_LEVEL

    @pytest.mark.unit
    def test_empty_findings(self, sarif, tmp_path):
        out    = str(tmp_path / "empty.sarif")
        result = sarif.export([], output_path=out)
        assert result.success is True
        assert result.finding_count == 0


# ── Tests: GitHubIntegration ──────────────────────────────

class TestGitHubIntegration:

    @pytest.mark.unit
    def test_init(self, github):
        assert github.repo == "ardanov96/glitchicons"

    @pytest.mark.unit
    def test_post_pr_comment_success(self, github):
        resp = mock_resp(201, {"id": 12345})
        with patch.object(github.client, "post", return_value=resp):
            result = github.post_pr_comment(42, SAMPLE_FINDINGS)
        assert result["success"]    is True
        assert result["comment_id"] == 12345

    @pytest.mark.unit
    def test_post_pr_comment_failure(self, github):
        resp = mock_resp(403, {"message": "Forbidden"})
        with patch.object(github.client, "post", return_value=resp):
            result = github.post_pr_comment(42, SAMPLE_FINDINGS)
        assert result["success"] is False

    @pytest.mark.unit
    def test_post_pr_comment_network_error(self, github):
        with patch.object(github.client, "post", side_effect=Exception("timeout")):
            result = github.post_pr_comment(42, SAMPLE_FINDINGS)
        assert result["success"] is False
        assert "error" in result

    @pytest.mark.unit
    def test_pr_comment_contains_severity_counts(self, github):
        body = github._build_pr_comment(SAMPLE_FINDINGS)
        assert "Critical" in body
        assert "High"     in body
        assert "Total"    in body

    @pytest.mark.unit
    def test_pr_comment_with_target(self, github):
        body = github._build_pr_comment(SAMPLE_FINDINGS, target="https://api.target.com")
        assert "api.target.com" in body

    @pytest.mark.unit
    def test_pr_comment_shows_top_findings(self, github):
        body = github._build_pr_comment(SAMPLE_FINDINGS)
        assert "SQL Injection" in body or "XSS" in body or "Top Findings" in body

    @pytest.mark.unit
    def test_create_check_run_success(self, github):
        resp = mock_resp(201, {"id": 9876})
        with patch.object(github.client, "post", return_value=resp):
            result = github.create_check_run(
                "Glitchicons Scan", "abc123sha", SAMPLE_FINDINGS
            )
        assert result["success"] is True
        assert result["check_run_id"] == 9876

    @pytest.mark.unit
    def test_create_check_run_conclusion_failure(self, github):
        resp = mock_resp(201, {"id": 1})
        with patch.object(github.client, "post", return_value=resp):
            result = github.create_check_run(
                "Scan", "sha", SAMPLE_FINDINGS[:2]  # CRITICAL + HIGH
            )
        assert result["conclusion"] == "failure"

    @pytest.mark.unit
    def test_create_check_run_conclusion_success(self, github):
        resp = mock_resp(201, {"id": 1})
        low_findings = [make_finding("LOW", "Minor issue", 2.0)]
        with patch.object(github.client, "post", return_value=resp):
            result = github.create_check_run("Scan", "sha", low_findings)
        assert result["conclusion"] == "success"

    @pytest.mark.unit
    def test_upload_sarif_file_not_found(self, github, tmp_path):
        result = github.upload_sarif(
            str(tmp_path / "nonexistent.sarif"),
            ref="refs/heads/main",
        )
        assert result["success"] is False
        assert "not found" in result["error"].lower()

    @pytest.mark.unit
    def test_upload_sarif_success(self, github, tmp_path, sarif):
        sarif_path = str(tmp_path / "test.sarif")
        sarif.export(SAMPLE_FINDINGS, output_path=sarif_path)
        resp = mock_resp(202, {"id": 42})
        with patch.object(github.client, "post", return_value=resp):
            result = github.upload_sarif(sarif_path, "refs/heads/main", "abc123")
        assert result["success"]     is True
        assert result["analysis_id"] == 42

    @pytest.mark.unit
    def test_build_annotations_limit(self, github):
        many_findings = [make_finding() for _ in range(60)]
        annotations   = github._build_annotations(many_findings[:50])
        assert len(annotations) == 50

    @pytest.mark.unit
    def test_get_open_prs_success(self, github):
        resp = mock_resp(200, [{"number": 1, "title": "PR 1"}])
        with patch.object(github.client, "get", return_value=resp):
            prs = github.get_open_prs()
        assert len(prs) == 1


# ── Tests: GitLabIntegration ──────────────────────────────

class TestGitLabIntegration:

    @pytest.mark.unit
    def test_init(self, gitlab):
        assert gitlab.scanner_name == "Glitchicons"

    @pytest.mark.unit
    def test_export_dast_report(self, gitlab, tmp_path):
        out    = str(tmp_path / "gl-dast-report.json")
        result = gitlab.export_dast_report(SAMPLE_FINDINGS, output_path=out)
        assert result.success is True
        assert Path(out).exists()

    @pytest.mark.unit
    def test_dast_report_valid_json(self, gitlab, tmp_path):
        out = str(tmp_path / "gl-dast-report.json")
        gitlab.export_dast_report(SAMPLE_FINDINGS, output_path=out)
        doc = json.loads(Path(out).read_text())
        assert "vulnerabilities" in doc
        assert "scan"            in doc
        assert doc["scan"]["type"] == "dast"

    @pytest.mark.unit
    def test_dast_vuln_count(self, gitlab, tmp_path):
        out = str(tmp_path / "report.json")
        gitlab.export_dast_report(SAMPLE_FINDINGS, output_path=out)
        doc = json.loads(Path(out).read_text())
        assert len(doc["vulnerabilities"]) == len(SAMPLE_FINDINGS)

    @pytest.mark.unit
    def test_export_sast_report(self, gitlab, tmp_path):
        out    = str(tmp_path / "gl-sast-report.json")
        result = gitlab.export_sast_report(SAMPLE_FINDINGS, output_path=out)
        assert result.success is True
        doc = json.loads(Path(out).read_text())
        assert doc["scan"]["type"] == "sast"

    @pytest.mark.unit
    def test_vuln_severity_mapping(self, gitlab):
        finding = make_finding("CRITICAL")
        vuln    = gitlab._finding_to_vuln(finding)
        assert vuln["severity"] == "Critical"

    @pytest.mark.unit
    def test_vuln_has_identifiers(self, gitlab):
        finding = make_finding(cwe="CWE-89")
        vuln    = gitlab._finding_to_vuln(finding)
        assert len(vuln["identifiers"]) >= 1
        cwe_ids = [i for i in vuln["identifiers"] if i["type"] == "cwe"]
        assert len(cwe_ids) >= 1

    @pytest.mark.unit
    def test_vuln_has_location(self, gitlab):
        vuln = gitlab._finding_to_vuln(make_finding())
        assert "location" in vuln
        assert "hostname" in vuln["location"]

    @pytest.mark.unit
    def test_vuln_id_deterministic(self, gitlab):
        f    = make_finding()
        id1  = gitlab._finding_to_vuln(f)["id"]
        id2  = gitlab._finding_to_vuln(f)["id"]
        assert id1 == id2

    @pytest.mark.unit
    def test_gitlab_severity_map(self):
        assert GITLAB_SEVERITY["CRITICAL"] == "Critical"
        assert GITLAB_SEVERITY["HIGH"]     == "High"
        assert GITLAB_SEVERITY["INFO"]     == "Info"

    @pytest.mark.unit
    def test_empty_findings_export(self, gitlab, tmp_path):
        out    = str(tmp_path / "empty.json")
        result = gitlab.export_dast_report([], output_path=out)
        assert result.success is True
        doc = json.loads(Path(out).read_text())
        assert doc["vulnerabilities"] == []


# ── Tests: DefectDojoIntegration ─────────────────────────

class TestDefectDojoIntegration:

    @pytest.mark.unit
    def test_init(self, defectdojo):
        assert "dojo.corp.com" in defectdojo.url
        assert defectdojo.api_key == "test_api_key_123"

    @pytest.mark.unit
    def test_push_findings_success(self, defectdojo):
        create_test_resp  = mock_resp(201, {"id": 99})
        create_finding_resp = mock_resp(201, {"id": 1})
        with patch.object(defectdojo.client, "post",
                         side_effect=[create_test_resp] + [create_finding_resp] * 5):
            result = defectdojo.push_findings(SAMPLE_FINDINGS, 1, 1)
        assert result["success"] is True
        assert result["pushed"]  == 5
        assert result["test_id"] == 99

    @pytest.mark.unit
    def test_push_findings_test_creation_fails(self, defectdojo):
        resp = mock_resp(400, {"error": "Bad request"})
        with patch.object(defectdojo.client, "post", return_value=resp):
            result = defectdojo.push_findings(SAMPLE_FINDINGS, 1, 1)
        assert result["success"] is False
        assert "Failed to create test" in result["error"]

    @pytest.mark.unit
    def test_get_product_success(self, defectdojo):
        resp = mock_resp(200, {"id": 1, "name": "Test Product"})
        with patch.object(defectdojo.client, "get", return_value=resp):
            product = defectdojo.get_product(1)
        assert product is not None
        assert product["name"] == "Test Product"

    @pytest.mark.unit
    def test_get_product_not_found(self, defectdojo):
        resp = mock_resp(404)
        with patch.object(defectdojo.client, "get", return_value=resp):
            product = defectdojo.get_product(99)
        assert product is None

    @pytest.mark.unit
    def test_get_engagement_success(self, defectdojo):
        resp = mock_resp(200, {"id": 42, "name": "Sprint 10"})
        with patch.object(defectdojo.client, "get", return_value=resp):
            eng = defectdojo.get_engagement(42)
        assert eng["id"] == 42

    @pytest.mark.unit
    def test_list_findings_success(self, defectdojo):
        resp = mock_resp(200, {"results": [{"id": 1, "title": "SQLi"}], "count": 1})
        with patch.object(defectdojo.client, "get", return_value=resp):
            findings = defectdojo.list_findings(engagement_id=1)
        assert len(findings) == 1

    @pytest.mark.unit
    def test_list_findings_network_error(self, defectdojo):
        with patch.object(defectdojo.client, "get", side_effect=Exception("timeout")):
            findings = defectdojo.list_findings(engagement_id=1)
        assert findings == []

    @pytest.mark.unit
    def test_close_finding_success(self, defectdojo):
        resp = mock_resp(200, {"id": 1, "active": False})
        with patch.object(defectdojo.client, "patch", return_value=resp):
            ok = defectdojo.close_finding(1)
        assert ok is True

    @pytest.mark.unit
    def test_close_finding_failure(self, defectdojo):
        resp = mock_resp(404)
        with patch.object(defectdojo.client, "patch", return_value=resp):
            ok = defectdojo.close_finding(99)
        assert ok is False

    @pytest.mark.unit
    def test_create_finding_cwe_parsed(self, defectdojo):
        payloads_sent = []
        def mock_post(url, **kwargs):
            payloads_sent.append(kwargs.get("json", {}))
            return mock_resp(201, {"id": 1})
        f = make_finding(cwe="CWE-89")
        with patch.object(defectdojo.client, "post", side_effect=mock_post):
            defectdojo._create_finding(f, test_id=1, product_id=1)
        assert payloads_sent[0]["cwe"] == 89

    @pytest.mark.unit
    def test_severity_mapping_critical(self, defectdojo):
        payloads_sent = []
        def mock_post(url, **kwargs):
            payloads_sent.append(kwargs.get("json", {}))
            return mock_resp(201, {"id": 1})
        f = make_finding("CRITICAL")
        with patch.object(defectdojo.client, "post", side_effect=mock_post):
            defectdojo._create_finding(f, test_id=1, product_id=1)
        assert payloads_sent[0]["severity"] == "Critical"

    @pytest.mark.unit
    def test_dojo_severity_map(self):
        assert DOJO_SEVERITY["CRITICAL"] == "Critical"
        assert DOJO_SEVERITY["INFO"]     == "Informational"
        assert len(DOJO_SEVERITY)        >= 5
