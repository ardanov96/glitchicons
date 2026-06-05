# tests/test_ai_reporter.py
"""
Unit tests untuk modules/report/ai_reporter.py
LLM calls di-mock — tidak butuh API key.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from modules.report.ai_reporter import (
    ReportNarrator, ExecutiveSummaryWriter, FindingNarrator,
    RemediationRoadmap, PentestReportGenerator,
    NarratedFinding, ExecutiveSummary, RemediationItem, PentestReport,
    SEVERITY_COLOR, SEVERITY_ICON, SEVERITY_ORDER,
    CWE_EFFORT, DEFAULT_MODELS,
)


# ── Sample data ───────────────────────────────────────────

def make_finding(severity="HIGH", title="SQL Injection", cvss=7.5, cwe="CWE-89"):
    return {
        "id":          "f001",
        "title":       title,
        "severity":    severity,
        "cvss":        cvss,
        "cwe":         cwe,
        "target":      "https://target.com/api/search",
        "description": "SQL injection allows attacker to query database directly.",
        "evidence":    "Parameter 'q' with payload \"' OR 1=1--\" returned all records.",
        "remediation": "Use parameterized queries. Never concatenate user input into SQL.",
        "source":      "module:sqli_tester",
    }


SAMPLE_FINDINGS = [
    make_finding("CRITICAL", "SQL Injection",         9.8,  "CWE-89"),
    make_finding("HIGH",     "Reflected XSS",          7.4,  "CWE-79"),
    make_finding("HIGH",     "JWT Algorithm Confusion", 8.1,  "CWE-287"),
    make_finding("MEDIUM",   "CORS Wildcard",           5.9,  "CWE-942"),
    make_finding("MEDIUM",   "Missing HSTS",            5.3,  "CWE-319"),
    make_finding("LOW",      "Version Disclosure",      2.1,  "CWE-200"),
]


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def narrator_no_key():
    return ReportNarrator(provider="anthropic", api_key="", timeout=5)


@pytest.fixture
def narrator_ollama():
    return ReportNarrator(provider="ollama", api_key="", timeout=5)


@pytest.fixture
def exec_writer(narrator_no_key):
    return ExecutiveSummaryWriter(narrator_no_key)


@pytest.fixture
def find_narrator(narrator_no_key):
    return FindingNarrator(narrator_no_key)


@pytest.fixture
def roadmap():
    return RemediationRoadmap()


@pytest.fixture
def report_gen(tmp_path):
    return PentestReportGenerator(
        provider="anthropic", api_key="", timeout=5,
    )


# ── Tests: ReportNarrator ─────────────────────────────────

class TestReportNarrator:

    @pytest.mark.unit
    def test_init_defaults(self, narrator_no_key):
        assert narrator_no_key.provider == "anthropic"
        assert narrator_no_key.model    == DEFAULT_MODELS["anthropic"]

    @pytest.mark.unit
    def test_default_models_not_empty(self):
        assert "anthropic" in DEFAULT_MODELS
        assert "openai"    in DEFAULT_MODELS
        assert "ollama"    in DEFAULT_MODELS

    @pytest.mark.unit
    def test_generate_returns_empty_on_no_key(self, narrator_no_key):
        # No API key + anthropic provider → fails gracefully
        with patch.object(narrator_no_key.client, "post", side_effect=Exception("401 Unauthorized")):
            result = narrator_no_key.generate("Test prompt")
        assert result == ""

    @pytest.mark.unit
    def test_generate_anthropic_success(self, narrator_no_key):
        narrator_no_key.api_key = "sk-test"
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"content": [{"text": "Generated text"}]}
        with patch.object(narrator_no_key.client, "post", return_value=mock_resp):
            result = narrator_no_key.generate("Test prompt")
        assert result == "Generated text"

    @pytest.mark.unit
    def test_generate_openai_success(self):
        n = ReportNarrator(provider="openai", api_key="sk-test", timeout=5)
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "OpenAI response"}}]
        }
        with patch.object(n.client, "post", return_value=mock_resp):
            result = n.generate("Test")
        assert result == "OpenAI response"

    @pytest.mark.unit
    def test_generate_ollama_success(self, narrator_ollama):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"response": "Ollama response"}
        with patch.object(narrator_ollama.client, "post", return_value=mock_resp):
            result = narrator_ollama.generate("Test")
        assert result == "Ollama response"

    @pytest.mark.unit
    def test_generate_unknown_provider(self):
        n = ReportNarrator(provider="unknown_provider", api_key="key", timeout=5)
        result = n.generate("Test")
        assert result == ""

    @pytest.mark.unit
    def test_parse_json_response_valid(self, narrator_no_key):
        raw    = '{"key1": "value1", "key2": "value2"}'
        result = narrator_no_key._parse_json_response(raw, ["key1", "key2"])
        assert result["key1"] == "value1"

    @pytest.mark.unit
    def test_parse_json_response_embedded(self, narrator_no_key):
        raw    = 'Here is the result: {"key1": "val1"} done.'
        result = narrator_no_key._parse_json_response(raw, ["key1", "key2"])
        assert result["key1"] == "val1"
        assert result["key2"] == ""

    @pytest.mark.unit
    def test_parse_json_response_invalid(self, narrator_no_key):
        result = narrator_no_key._parse_json_response("not json", ["k1", "k2"])
        assert result == {"k1": "", "k2": ""}

    @pytest.mark.unit
    def test_generate_structured_success(self):
        n = ReportNarrator(provider="anthropic", api_key="sk-test", timeout=5)
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "content": [{"text": '{"opening": "Risk is high", "scope": "Web app"}'}]
        }
        with patch.object(n.client, "post", return_value=mock_resp):
            result = n.generate_structured("Prompt", ["opening", "scope"])
        assert result["opening"] == "Risk is high"


# ── Tests: ExecutiveSummaryWriter ─────────────────────────

class TestExecutiveSummaryWriter:

    @pytest.mark.unit
    def test_init(self, exec_writer):
        assert exec_writer.narrator is not None

    @pytest.mark.unit
    def test_write_returns_summary(self, exec_writer):
        summary = exec_writer.write(SAMPLE_FINDINGS, "https://target.com", "Test Engagement")
        assert isinstance(summary, ExecutiveSummary)
        assert summary.risk_rating != ""
        assert summary.risk_score  >= 0

    @pytest.mark.unit
    def test_risk_score_critical_high(self, exec_writer):
        score = exec_writer._calculate_risk_score(SAMPLE_FINDINGS)
        assert score >= 7.0

    @pytest.mark.unit
    def test_risk_score_empty_findings(self, exec_writer):
        score = exec_writer._calculate_risk_score([])
        assert score == 0.0

    @pytest.mark.unit
    def test_risk_score_only_info(self, exec_writer):
        findings = [make_finding("INFO", "Test", 0.0)]
        score    = exec_writer._calculate_risk_score(findings)
        assert score < 3.0

    @pytest.mark.unit
    def test_risk_rating_critical(self, exec_writer):
        rating, _ = exec_writer._risk_rating(9.5)
        assert rating == "Critical"

    @pytest.mark.unit
    def test_risk_rating_high(self, exec_writer):
        rating, _ = exec_writer._risk_rating(7.5)
        assert rating == "High"

    @pytest.mark.unit
    def test_risk_rating_medium(self, exec_writer):
        rating, _ = exec_writer._risk_rating(5.5)
        assert rating == "Medium"

    @pytest.mark.unit
    def test_risk_rating_low(self, exec_writer):
        rating, _ = exec_writer._risk_rating(3.5)
        assert rating == "Low"

    @pytest.mark.unit
    def test_template_summary_has_content(self, exec_writer):
        summary = exec_writer.write(SAMPLE_FINDINGS, "https://target.com", "Test")
        assert len(summary.opening)       > 20
        assert len(summary.key_findings)  > 20
        assert len(summary.next_steps)    > 20

    @pytest.mark.unit
    def test_summary_mentions_target(self, exec_writer):
        summary = exec_writer.write(SAMPLE_FINDINGS, "https://target.com", "Test")
        assert "target.com" in summary.scope or "target.com" in summary.opening

    @pytest.mark.unit
    def test_risk_thresholds_ordered(self, exec_writer):
        thresholds = [t[0] for t in exec_writer.RISK_THRESHOLDS]
        assert thresholds == sorted(thresholds, reverse=True)


# ── Tests: FindingNarrator ────────────────────────────────

class TestFindingNarrator:

    @pytest.mark.unit
    def test_narrate_returns_narrated_finding(self, find_narrator):
        nf = find_narrator.narrate(SAMPLE_FINDINGS[0])
        assert isinstance(nf, NarratedFinding)
        assert nf.original  is not None

    @pytest.mark.unit
    def test_narrate_template_not_empty(self, find_narrator):
        nf = find_narrator._narrate_template(SAMPLE_FINDINGS[0])
        assert len(nf.impact_story)  > 20
        assert len(nf.poc_steps)     > 20
        assert len(nf.business_risk) > 20

    @pytest.mark.unit
    def test_impact_critical_severity(self, find_narrator):
        impact = find_narrator._default_impact(make_finding("CRITICAL"))
        assert "critical" in impact.lower()

    @pytest.mark.unit
    def test_impact_info_severity(self, find_narrator):
        impact = find_narrator._default_impact(make_finding("INFO"))
        assert "informational" in impact.lower()

    @pytest.mark.unit
    def test_business_risk_critical(self, find_narrator):
        risk = find_narrator._default_business_risk(make_finding("CRITICAL"))
        assert "breach" in risk.lower() or "penalty" in risk.lower()

    @pytest.mark.unit
    def test_narrate_bulk_returns_list(self, find_narrator):
        results = find_narrator.narrate_bulk(SAMPLE_FINDINGS, limit=3)
        assert len(results) == 3
        assert all(isinstance(r, NarratedFinding) for r in results)

    @pytest.mark.unit
    def test_narrate_bulk_respects_limit(self, find_narrator):
        results = find_narrator.narrate_bulk(SAMPLE_FINDINGS, limit=2)
        assert len(results) == 2

    @pytest.mark.unit
    def test_narrate_bulk_sorted_by_severity(self, find_narrator):
        results = find_narrator.narrate_bulk(SAMPLE_FINDINGS, limit=6)
        severities = [r.original.get("severity") for r in results]
        orders     = [SEVERITY_ORDER.get(s, 99) for s in severities]
        assert orders == sorted(orders)


# ── Tests: RemediationRoadmap ─────────────────────────────

class TestRemediationRoadmap:

    @pytest.mark.unit
    def test_build_returns_items(self, roadmap):
        items = roadmap.build(SAMPLE_FINDINGS)
        assert len(items) == len(SAMPLE_FINDINGS)

    @pytest.mark.unit
    def test_critical_is_p1(self, roadmap):
        items = roadmap.build([make_finding("CRITICAL")])
        assert items[0].priority == 1

    @pytest.mark.unit
    def test_low_is_p3(self, roadmap):
        items = roadmap.build([make_finding("LOW")])
        assert items[0].priority == 3

    @pytest.mark.unit
    def test_xss_is_quick_win(self, roadmap):
        xss_finding = make_finding("HIGH", "XSS", 7.4, "CWE-79")
        items       = roadmap.build([xss_finding])
        assert items[0].quick_win is True

    @pytest.mark.unit
    def test_sqli_has_dev_owner(self, roadmap):
        items = roadmap.build([make_finding("CRITICAL", cwe="CWE-89")])
        assert items[0].owner == "dev"

    @pytest.mark.unit
    def test_format_markdown_has_sections(self, roadmap):
        items = roadmap.build(SAMPLE_FINDINGS)
        md    = roadmap.format_markdown(items)
        assert "Remediation Roadmap" in md
        assert "P1" in md

    @pytest.mark.unit
    def test_summary_stats_structure(self, roadmap):
        items = roadmap.build(SAMPLE_FINDINGS)
        stats = roadmap.summary_stats(items)
        assert "total"         in stats
        assert "p1_immediate"  in stats
        assert "quick_wins"    in stats
        assert "by_owner"      in stats
        assert stats["total"]  == len(SAMPLE_FINDINGS)

    @pytest.mark.unit
    def test_effort_days_positive(self, roadmap):
        items = roadmap.build(SAMPLE_FINDINGS)
        assert all(i.effort_days >= 0 for i in items)

    @pytest.mark.unit
    def test_cwe_effort_not_empty(self):
        assert len(CWE_EFFORT) >= 10
        assert "CWE-79" in CWE_EFFORT
        assert "CWE-89" in CWE_EFFORT


# ── Tests: PentestReportGenerator ────────────────────────

class TestPentestReportGenerator:

    @pytest.mark.unit
    def test_init(self, report_gen):
        assert report_gen.narrator is not None
        assert report_gen.exec_writer is not None

    @pytest.mark.unit
    def test_generate_creates_files(self, report_gen, tmp_path):
        report = report_gen.generate(
            findings=SAMPLE_FINDINGS,
            target="https://target.com",
            engagement_name="Test Engagement",
            output_dir=str(tmp_path),
            narrate_findings=False,
        )
        assert Path(report.html_path).exists()
        assert Path(report.md_path).exists()

    @pytest.mark.unit
    def test_generate_html_is_valid(self, report_gen, tmp_path):
        report = report_gen.generate(
            SAMPLE_FINDINGS, "https://target.com",
            output_dir=str(tmp_path), narrate_findings=False,
        )
        html = Path(report.html_path).read_text()
        assert "<!DOCTYPE html>" in html
        assert "GLITCHICONS"    in html
        assert "SQL Injection"  in html

    @pytest.mark.unit
    def test_generate_markdown_has_findings(self, report_gen, tmp_path):
        report = report_gen.generate(
            SAMPLE_FINDINGS, "https://target.com",
            output_dir=str(tmp_path), narrate_findings=False,
        )
        md = Path(report.md_path).read_text()
        assert "# " in md
        assert "SQL Injection" in md
        assert "Remediation Roadmap" in md

    @pytest.mark.unit
    def test_report_has_correct_counts(self, report_gen, tmp_path):
        report = report_gen.generate(
            SAMPLE_FINDINGS, "https://target.com",
            output_dir=str(tmp_path), narrate_findings=False,
        )
        assert report.total_findings == len(SAMPLE_FINDINGS)

    @pytest.mark.unit
    def test_report_risk_score_positive(self, report_gen, tmp_path):
        report = report_gen.generate(
            SAMPLE_FINDINGS, "https://target.com",
            output_dir=str(tmp_path), narrate_findings=False,
        )
        assert report.risk_score > 0

    @pytest.mark.unit
    def test_generate_with_llm_mock(self, tmp_path):
        gen = PentestReportGenerator(
            provider="anthropic", api_key="sk-test", timeout=5
        )
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "content": [{"text": '{"opening":"High risk","key_findings":"SQLi found","business_risk":"Data breach risk","next_steps":"Patch immediately","impact_story":"Critical","poc_steps":"1. Send payload","fix_guidance":"Use params"}'}]
        }
        with patch.object(gen.narrator.client, "post", return_value=mock_resp):
            report = gen.generate(
                [SAMPLE_FINDINGS[0]], "https://target.com",
                output_dir=str(tmp_path), narrate_findings=True, max_narrated=1,
            )
        assert report.html_path != ""

    @pytest.mark.unit
    def test_html_has_score_cards(self, report_gen, tmp_path):
        report = report_gen.generate(
            SAMPLE_FINDINGS, "https://target.com",
            output_dir=str(tmp_path), narrate_findings=False,
        )
        html = Path(report.html_path).read_text()
        assert "score-card" in html
        assert "Critical"   in html

    @pytest.mark.unit
    def test_empty_findings_no_crash(self, report_gen, tmp_path):
        report = report_gen.generate(
            [], "https://target.com",
            output_dir=str(tmp_path), narrate_findings=False,
        )
        assert Path(report.html_path).exists()
        assert report.total_findings == 0

    @pytest.mark.unit
    def test_severity_colors_complete(self):
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert sev in SEVERITY_COLOR
            assert sev in SEVERITY_ICON

    @pytest.mark.unit
    def test_severity_order_sorted(self):
        assert SEVERITY_ORDER["CRITICAL"] < SEVERITY_ORDER["HIGH"]
        assert SEVERITY_ORDER["HIGH"]     < SEVERITY_ORDER["MEDIUM"]
        assert SEVERITY_ORDER["MEDIUM"]   < SEVERITY_ORDER["LOW"]
