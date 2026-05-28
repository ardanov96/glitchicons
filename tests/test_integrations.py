from unittest.mock import patch, MagicMock
# tests/test_integrations.py
"""
Unit tests untuk modules/integrations/integrations.py
HTTP calls di-mock — tidak butuh Slack/Discord/Jira nyata.
"""

import json
import pytest
import responses as responses_lib
from pathlib import Path
from xml.etree import ElementTree as ET

from modules.integrations.integrations import (
    BurpExporter,
    SlackNotifier,
    DiscordNotifier,
    JiraIntegration,
    SARIFExporter,
    SEVERITY_COLORS,
    SEVERITY_EMOJIS,
    JIRA_PRIORITY_MAP,
)


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def sample_findings():
    return [
        {
            "id": "FIND-001",
            "title": "SQL Injection in search",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "cwe": "CWE-89",
            "target": "https://target.com/search",
            "description": "SQLi found in q parameter.",
            "evidence": "MySQL error: syntax error",
            "remediation": "Use parameterized queries.",
            "verdict": "CONFIRMED",
        },
        {
            "id": "FIND-002",
            "title": "Reflected XSS",
            "severity": "HIGH",
            "cvss": 7.5,
            "cwe": "CWE-79",
            "target": "https://target.com/search",
            "description": "XSS reflected in response.",
            "evidence": "<script>alert(1)</script> found",
            "remediation": "Sanitize output.",
            "verdict": "LIKELY",
        },
        {
            "id": "FIND-003",
            "title": "Missing Security Headers",
            "severity": "MEDIUM",
            "cvss": 5.3,
            "cwe": "CWE-693",
            "target": "https://target.com",
            "description": "X-Frame-Options missing.",
            "evidence": "HTTP headers analysis",
            "remediation": "Add security headers.",
        },
        {
            "id": "FIND-004",
            "title": "Verbose Error Messages",
            "severity": "LOW",
            "cvss": 2.7,
            "cwe": "CWE-209",
            "target": "https://target.com/api",
            "description": "Stack traces exposed.",
            "evidence": "Django traceback shown",
            "remediation": "Set DEBUG=False.",
        },
    ]


@pytest.fixture
def critical_findings(sample_findings):
    return [f for f in sample_findings if f["severity"] == "CRITICAL"]


@pytest.fixture
def slack():
    return SlackNotifier(webhook_url="https://hooks.slack.com/test/webhook")


@pytest.fixture
def discord():
    return DiscordNotifier(webhook_url="https://discord.com/api/webhooks/test")


@pytest.fixture
def jira():
    return JiraIntegration(
        url="https://company.atlassian.net",
        email="test@company.com",
        api_token="test-token-abc",
    )


# ── Tests: BurpExporter ───────────────────────────────────

class TestBurpExporter:

    @pytest.mark.unit
    def test_export_creates_xml_file(self, tmp_path, sample_findings):
        out = str(tmp_path / "burp.xml")
        path = BurpExporter().export(sample_findings, out)
        assert path.exists()
        assert path.suffix == ".xml"

    @pytest.mark.unit
    def test_exported_xml_is_valid(self, tmp_path, sample_findings):
        out = str(tmp_path / "burp.xml")
        path = BurpExporter().export(sample_findings, out)
        tree = ET.parse(str(path))
        root = tree.getroot()
        assert root.tag == "issues"

    @pytest.mark.unit
    def test_correct_issue_count(self, tmp_path, sample_findings):
        out = str(tmp_path / "burp.xml")
        path = BurpExporter().export(sample_findings, out)
        tree = ET.parse(str(path))
        issues = tree.getroot().findall("issue")
        assert len(issues) == len(sample_findings)

    @pytest.mark.unit
    def test_issue_has_name(self, tmp_path, sample_findings):
        out = str(tmp_path / "burp.xml")
        path = BurpExporter().export(sample_findings, out)
        tree = ET.parse(str(path))
        first = tree.getroot().findall("issue")[0]
        name_el = first.find("name")
        assert name_el is not None
        assert "SQL" in name_el.text or name_el.text != ""

    @pytest.mark.unit
    def test_severity_mapped_correctly(self, tmp_path, sample_findings):
        out = str(tmp_path / "burp.xml")
        path = BurpExporter().export(sample_findings, out)
        tree = ET.parse(str(path))
        issues = tree.getroot().findall("issue")
        # CRITICAL -> High in Burp
        critical_issue = issues[0]
        sev_el = critical_issue.find("severity")
        assert sev_el.text == "High"

    @pytest.mark.unit
    def test_empty_findings_creates_file(self, tmp_path):
        out = str(tmp_path / "empty_burp.xml")
        path = BurpExporter().export([], out)
        assert path.exists()

    @pytest.mark.unit
    def test_parse_url_https(self):
        exporter = BurpExporter()
        host, path, protocol = exporter._parse_url("https://target.com/api/users")
        assert host == "target.com"
        assert path == "/api/users"
        assert protocol == "https"

    @pytest.mark.unit
    def test_parse_url_with_query(self):
        exporter = BurpExporter()
        host, path, protocol = exporter._parse_url("https://target.com/search?q=test")
        assert host == "target.com"

    @pytest.mark.unit
    def test_parse_url_empty(self):
        exporter = BurpExporter()
        host, path, protocol = exporter._parse_url("")
        assert host == "unknown"
        assert path == "/"

    @pytest.mark.unit
    def test_severity_map_complete(self):
        exporter = BurpExporter()
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert sev in exporter.SEVERITY_MAP

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path, sample_findings):
        out = str(tmp_path / "subdir" / "burp.xml")
        path = BurpExporter().export(sample_findings, out)
        assert path.exists()


# ── Tests: SlackNotifier ──────────────────────────────────

class TestSlackNotifier:

    @pytest.mark.unit
    def test_init_stores_webhook(self, slack):
        assert "hooks.slack.com" in slack.webhook_url

    @pytest.mark.unit
    def test_init_default_username(self, slack):
        assert slack.username == "Glitchicons"

    @pytest.mark.unit
    def test_notify_critical_sends_request(self, slack, sample_findings):
        with patch("httpx.post") as mp:
            mp.return_value = MagicMock(status_code=200)
            result = slack.notify_critical(sample_findings, target="target.com")
            assert result is True
            assert mp.called

    @pytest.mark.unit
    def test_notify_critical_no_findings_skips(self, slack, sample_findings):
        low_findings = [f for f in sample_findings if f["severity"] == "LOW"]
        result = slack.notify_critical(low_findings, target="target.com")
        assert result is True

    @pytest.mark.unit
    def test_notify_summary_sends_request(self, slack, sample_findings):
        with patch("httpx.post") as mp:
            mp.return_value = MagicMock(status_code=200)
            result = slack.notify_summary(sample_findings, target="target.com", duration="4h")
            assert result is True

    @pytest.mark.unit
    def test_notify_finding_sends_request(self, slack, sample_findings):
        with patch("httpx.post") as mp:
            mp.return_value = MagicMock(status_code=200)
            result = slack.notify_finding(sample_findings[0])
            assert result is True

    @pytest.mark.unit
    def test_returns_false_on_error(self, slack, sample_findings):
        with patch("httpx.post") as mp:
            mp.return_value = MagicMock(status_code=500)
            result = slack.notify_critical(sample_findings, target="target.com")
            assert result is False

    @pytest.mark.unit
    def test_payload_includes_username(self, slack, sample_findings):
        """Payload yang dikirim harus include username."""
        with patch("httpx.post") as mp:
            mp.return_value = MagicMock(status_code=200)
            slack.notify_summary(sample_findings, "t.com")
            call_kwargs = mp.call_args
            posted_json = call_kwargs[1].get("json", call_kwargs[0][1] if len(call_kwargs[0]) > 1 else {})
            assert "username" in posted_json


# ── Tests: DiscordNotifier ────────────────────────────────

class TestDiscordNotifier:

    @pytest.mark.unit
    def test_init_stores_webhook(self, discord):
        assert "discord.com" in discord.webhook_url

    @pytest.mark.unit
    def test_notify_summary_sends_embed(self, discord, sample_findings):
        with patch("httpx.post") as mp:
            mp.return_value = MagicMock(status_code=200)
            result = discord.notify_summary(sample_findings, target="target.com")
            assert result is True

    @pytest.mark.unit
    def test_notify_critical_sends_embed(self, discord, sample_findings):
        with patch("httpx.post") as mp:
            mp.return_value = MagicMock(status_code=200)
            result = discord.notify_critical(sample_findings, target="target.com")
            assert result is True

    @pytest.mark.unit
    def test_notify_critical_no_findings_skips(self, discord):
        result = discord.notify_critical([], target="target.com")
        assert result is True

    @pytest.mark.unit
    def test_notify_finding_single(self, discord, sample_findings):
        with patch("httpx.post") as mp:
            mp.return_value = MagicMock(status_code=200)
            result = discord.notify_finding(sample_findings[0])
            assert result is True

    @pytest.mark.unit
    def test_discord_color_map_complete(self, discord):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert sev in discord.DISCORD_COLORS
            assert isinstance(discord.DISCORD_COLORS[sev], int)


# ── Tests: JiraIntegration ────────────────────────────────

class TestJiraIntegration:

    @pytest.mark.unit
    def test_init_strips_trailing_slash(self):
        jira = JiraIntegration("https://company.atlassian.net/", "e@c.com", "tok")
        assert not jira.base_url.endswith("/")

    @pytest.mark.unit
    def test_create_tickets_calls_api(self, jira, sample_findings):
        with patch("httpx.post") as mp:
            mp.return_value = MagicMock(status_code=201, json=lambda: {"key": "SEC-1", "id": "10001"})
            tickets = jira.create_tickets(sample_findings, project_key="SEC", min_severity="CRITICAL")
            assert len(tickets) == 1
            assert tickets[0]["key"] == "SEC-1"

    @pytest.mark.unit
    def test_create_tickets_filters_by_severity(self, jira, sample_findings):
        with patch("httpx.post") as mp:
            mp.return_value = MagicMock(status_code=201, json=lambda: {"key": "SEC-1", "id": "10001"})
            tickets = jira.create_tickets(sample_findings, project_key="SEC", min_severity="HIGH")
            assert mp.call_count == 2

    @pytest.mark.unit
    def test_no_eligible_findings_returns_empty(self, jira, sample_findings):
        low_only = [f for f in sample_findings if f["severity"] == "LOW"]
        tickets = jira.create_tickets(low_only, "SEC", min_severity="CRITICAL")
        assert tickets == []

    @pytest.mark.unit
    def test_priority_map_complete(self):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert sev in JIRA_PRIORITY_MAP

    @pytest.mark.unit
    def test_build_description_structure(self, jira, sample_findings):
        desc = jira._build_description(sample_findings[0])
        assert desc["version"] == 1
        assert desc["type"] == "doc"
        assert "content" in desc

    @pytest.mark.unit
    def test_get_project_success(self, jira):
        with patch("httpx.get") as mg:
            mg.return_value = MagicMock(status_code=200, json=lambda: {"key": "SEC", "name": "Security"})
            project = jira.get_project("SEC")
            assert project is not None
            assert project["key"] == "SEC"

    @pytest.mark.unit
    def test_get_project_not_found(self, jira):
        with patch("httpx.get") as mg:
            mg.return_value = MagicMock(status_code=404)
            project = jira.get_project("MISSING")
            assert project is None


# ── Tests: SARIFExporter ──────────────────────────────────

class TestSARIFExporter:

    @pytest.mark.unit
    def test_export_creates_json_file(self, tmp_path, sample_findings):
        out = str(tmp_path / "results.sarif")
        path = SARIFExporter().export(sample_findings, out)
        assert path.exists()
        assert path.suffix == ".sarif"

    @pytest.mark.unit
    def test_exported_sarif_valid_json(self, tmp_path, sample_findings):
        out = str(tmp_path / "results.sarif")
        path = SARIFExporter().export(sample_findings, out)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["version"] == "2.1.0"

    @pytest.mark.unit
    def test_sarif_has_runs(self, tmp_path, sample_findings):
        out = str(tmp_path / "results.sarif")
        path = SARIFExporter().export(sample_findings, out)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "runs" in data
        assert len(data["runs"]) == 1

    @pytest.mark.unit
    def test_sarif_tool_name(self, tmp_path, sample_findings):
        out = str(tmp_path / "results.sarif")
        path = SARIFExporter().export(sample_findings, out)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["runs"][0]["tool"]["driver"]["name"] == "Glitchicons"

    @pytest.mark.unit
    def test_sarif_result_count(self, tmp_path, sample_findings):
        out = str(tmp_path / "results.sarif")
        path = SARIFExporter().export(sample_findings, out)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert len(data["runs"][0]["results"]) == len(sample_findings)

    @pytest.mark.unit
    def test_sarif_level_mapping(self, tmp_path, sample_findings):
        out = str(tmp_path / "results.sarif")
        path = SARIFExporter().export(sample_findings, out)
        data = json.loads(path.read_text(encoding="utf-8"))
        results = data["runs"][0]["results"]
        # CRITICAL -> error
        assert results[0]["level"] == "error"
        # MEDIUM -> warning
        medium_result = next(r for r in results
                             if r["properties"]["cvss"] == 5.3)
        assert medium_result["level"] == "warning"

    @pytest.mark.unit
    def test_sarif_rules_deduplicated(self, tmp_path, sample_findings):
        """Rules tidak boleh duplikat per CWE."""
        # Add duplicate CWE
        duped = sample_findings + [{**sample_findings[0], "id": "FIND-999"}]
        out = str(tmp_path / "results.sarif")
        path = SARIFExporter().export(duped, out)
        data = json.loads(path.read_text(encoding="utf-8"))
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert len(rule_ids) == len(set(rule_ids))

    @pytest.mark.unit
    def test_empty_findings_valid_sarif(self, tmp_path):
        out = str(tmp_path / "empty.sarif")
        path = SARIFExporter().export([], out)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["runs"][0]["results"] == []


# ── Tests: Constants ──────────────────────────────────────

class TestConstants:

    @pytest.mark.unit
    def test_severity_colors_complete(self):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert sev in SEVERITY_COLORS
            assert SEVERITY_COLORS[sev].startswith("#")

    @pytest.mark.unit
    def test_severity_emojis_complete(self):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert sev in SEVERITY_EMOJIS

    @pytest.mark.unit
    def test_jira_priority_map_complete(self):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert sev in JIRA_PRIORITY_MAP

    @pytest.mark.unit
    def test_critical_highest_jira_priority(self):
        assert JIRA_PRIORITY_MAP["CRITICAL"] == "Critical"
        assert JIRA_PRIORITY_MAP["HIGH"] == "High"
