# tests/test_severity_reasoner.py
"""
Unit tests untuk modules/intelligence/severity_reasoner.py
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch

from modules.intelligence.severity_reasoner import (
    SeverityReasoner,
    CVSSCalculator,
    CVSSBreakdown,
    SeverityReasoning,
    CVSS_METRICS,
    CVSS_METRIC_LABELS,
    CVSS_VALUE_LABELS,
    DEFAULT_VECTORS,
    BUSINESS_IMPACT_TEMPLATES,
    PRIORITY_FACTORS,
)


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def reasoner(tmp_path):
    return SeverityReasoner(
        provider="ollama",
        output_dir=str(tmp_path / "reasoned"),
        rescore=False,
    )


@pytest.fixture
def sqli_finding():
    return {
        "id": "FIND-001",
        "title": "SQL Injection in search",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cwe": "CWE-89",
        "target": "https://target.com/search",
        "description": "SQLi found",
        "evidence": "MySQL error: syntax error near ' OR '1'='1'",
        "remediation": "Use parameterized queries",
    }


@pytest.fixture
def xss_finding():
    return {
        "id": "FIND-002",
        "title": "Reflected XSS",
        "severity": "HIGH",
        "cvss": 7.5,
        "cwe": "CWE-79",
        "target": "https://target.com/search",
        "description": "XSS found",
        "evidence": "<script>alert(1)</script> reflected",
        "remediation": "Sanitize output",
    }


@pytest.fixture
def dos_finding():
    return {
        "id": "FIND-003",
        "title": "WebSocket DoS — No Rate Limiting",
        "severity": "MEDIUM",
        "cvss": 5.8,
        "cwe": "CWE-770",
        "target": "wss://target.com/ws",
        "description": "DoS via flooding",
        "evidence": "100 messages accepted",
        "remediation": "Add rate limiting",
    }


# ── Tests: CVSSCalculator ─────────────────────────────────

class TestCVSSCalculator:

    @pytest.mark.unit
    def test_parse_vector_basic(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        metrics = CVSSCalculator.parse_vector(v)
        assert metrics["AV"] == "N"
        assert metrics["AC"] == "L"
        assert metrics["C"] == "H"
        assert metrics["A"] == "H"

    @pytest.mark.unit
    def test_parse_vector_all_metrics(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        metrics = CVSSCalculator.parse_vector(v)
        expected_keys = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
        assert expected_keys == set(metrics.keys())

    @pytest.mark.unit
    def test_calculate_score_critical(self):
        """AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H harus CRITICAL (9.8)."""
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "H", "I": "H", "A": "H"}
        score = CVSSCalculator.calculate_score(metrics)
        assert score >= 9.0

    @pytest.mark.unit
    def test_calculate_score_medium(self):
        """AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N harus MEDIUM."""
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "R",
                   "S": "C", "C": "L", "I": "L", "A": "N"}
        score = CVSSCalculator.calculate_score(metrics)
        assert 4.0 <= score <= 7.0

    @pytest.mark.unit
    def test_calculate_score_no_impact_is_zero(self):
        """Tidak ada impact (C:N I:N A:N) harus return 0.0."""
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                   "S": "U", "C": "N", "I": "N", "A": "N"}
        score = CVSSCalculator.calculate_score(metrics)
        assert score == 0.0

    @pytest.mark.unit
    def test_score_in_range(self):
        """Score harus selalu dalam range 0.0-10.0."""
        test_vectors = [
            {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
            {"AV": "P", "AC": "H", "PR": "H", "UI": "R", "S": "U", "C": "L", "I": "N", "A": "N"},
        ]
        for metrics in test_vectors:
            score = CVSSCalculator.calculate_score(metrics)
            assert 0.0 <= score <= 10.0

    @pytest.mark.unit
    def test_score_to_severity_critical(self):
        assert CVSSCalculator.score_to_severity(9.5) == "CRITICAL"
        assert CVSSCalculator.score_to_severity(9.0) == "CRITICAL"

    @pytest.mark.unit
    def test_score_to_severity_high(self):
        assert CVSSCalculator.score_to_severity(8.0) == "HIGH"
        assert CVSSCalculator.score_to_severity(7.0) == "HIGH"

    @pytest.mark.unit
    def test_score_to_severity_medium(self):
        assert CVSSCalculator.score_to_severity(5.5) == "MEDIUM"
        assert CVSSCalculator.score_to_severity(4.0) == "MEDIUM"

    @pytest.mark.unit
    def test_score_to_severity_low(self):
        assert CVSSCalculator.score_to_severity(2.0) == "LOW"
        assert CVSSCalculator.score_to_severity(0.1) == "LOW"

    @pytest.mark.unit
    def test_score_to_severity_none(self):
        assert CVSSCalculator.score_to_severity(0.0) == "NONE"

    @pytest.mark.unit
    def test_breakdown_parses_vector(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        bd = CVSSCalculator.breakdown(v)
        assert bd is not None
        assert bd.metrics["AV"] == "N"
        assert bd.severity == "CRITICAL"
        assert bd.base_score >= 9.0

    @pytest.mark.unit
    def test_breakdown_metric_labels(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        bd = CVSSCalculator.breakdown(v)
        assert "Attack Vector" in bd.metric_labels
        assert bd.metric_labels["Attack Vector"] == "Network"

    @pytest.mark.unit
    def test_breakdown_to_dict(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        bd = CVSSCalculator.breakdown(v)
        d = bd.to_dict()
        required = {"vector", "base_score", "severity", "metrics",
                    "exploitability", "impact"}
        assert required == set(d.keys())

    @pytest.mark.unit
    def test_build_vector_sqli(self):
        v = CVSSCalculator.build_vector("sqli", {"title": "SQL Injection"})
        assert v.startswith("CVSS:3.1/")
        assert "AV:N" in v

    @pytest.mark.unit
    def test_build_vector_dos_adjusts_cia(self):
        """DoS finding harus adjust A:H, C:N, I:N."""
        v = CVSSCalculator.build_vector("generic", {
            "title": "Denial of Service via flooding"
        })
        assert "A:H" in v
        assert "C:N" in v
        assert "I:N" in v


# ── Tests: CVSS Constants ─────────────────────────────────

class TestCVSSConstants:

    @pytest.mark.unit
    def test_all_metrics_defined(self):
        required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
        assert required == set(CVSS_METRICS.keys())

    @pytest.mark.unit
    def test_metric_values_in_range(self):
        for metric, values in CVSS_METRICS.items():
            for val, score in values.items():
                assert 0.0 <= score <= 1.0, f"{metric}:{val} = {score}"

    @pytest.mark.unit
    def test_metric_labels_complete(self):
        assert len(CVSS_METRIC_LABELS) == 8

    @pytest.mark.unit
    def test_value_labels_complete(self):
        assert "AV" in CVSS_VALUE_LABELS
        assert "Network" in CVSS_VALUE_LABELS["AV"].values()

    @pytest.mark.unit
    def test_default_vectors_exist(self):
        assert "sqli" in DEFAULT_VECTORS
        assert "xss" in DEFAULT_VECTORS
        assert "generic" in DEFAULT_VECTORS

    @pytest.mark.unit
    def test_default_vectors_valid_format(self):
        for attack, vector in DEFAULT_VECTORS.items():
            assert vector.startswith("CVSS:3.1/"), f"{attack} vector invalid"
            assert "AV:" in vector and "AC:" in vector


# ── Tests: Priority Calculator ────────────────────────────

class TestPriorityCalculator:

    @pytest.mark.unit
    def test_critical_highest_priority(self, reasoner, sqli_finding):
        bd = CVSSCalculator.breakdown(DEFAULT_VECTORS["sqli"])
        priority = reasoner._calculate_priority(sqli_finding, bd)
        assert priority >= 80

    @pytest.mark.unit
    def test_medium_lower_priority(self, reasoner, dos_finding):
        bd = CVSSCalculator.breakdown(DEFAULT_VECTORS["generic"])
        priority = reasoner._calculate_priority(dos_finding, bd)
        assert priority < 80

    @pytest.mark.unit
    def test_priority_in_range(self, reasoner, sqli_finding):
        bd = CVSSCalculator.breakdown(DEFAULT_VECTORS["sqli"])
        priority = reasoner._calculate_priority(sqli_finding, bd)
        assert 0 <= priority <= 100

    @pytest.mark.unit
    def test_network_vector_increases_priority(self, reasoner):
        finding = {"title": "Auth Bypass", "severity": "HIGH", "cvss": 8.0, "evidence": ""}
        bd_network = CVSSCalculator.breakdown("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        bd_local   = CVSSCalculator.breakdown("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
        p_net = reasoner._calculate_priority(finding, bd_network)
        p_loc = reasoner._calculate_priority(finding, bd_local)
        assert p_net >= p_loc

    @pytest.mark.unit
    def test_priority_factors_defined(self):
        assert PRIORITY_FACTORS["CRITICAL"] > PRIORITY_FACTORS["HIGH"]
        assert PRIORITY_FACTORS["HIGH"]     > PRIORITY_FACTORS["MEDIUM"]
        assert PRIORITY_FACTORS["MEDIUM"]   > PRIORITY_FACTORS["LOW"]


# ── Tests: Attack Type Detection ─────────────────────────

class TestAttackTypeDetection:

    @pytest.mark.unit
    def test_sqli_detected(self, reasoner, sqli_finding):
        assert reasoner._detect_attack_type(sqli_finding) == "sqli"

    @pytest.mark.unit
    def test_xss_detected(self, reasoner, xss_finding):
        assert reasoner._detect_attack_type(xss_finding) == "xss"

    @pytest.mark.unit
    def test_mfa_detected(self, reasoner):
        f = {"title": "MFA Bypass via OTP Skip", "cwe": "CWE-287"}
        assert reasoner._detect_attack_type(f) == "mfa"

    @pytest.mark.unit
    def test_takeover_detected(self, reasoner):
        f = {"title": "Subdomain Takeover: blog.target.com", "cwe": "CWE-284"}
        assert reasoner._detect_attack_type(f) == "takeover"

    @pytest.mark.unit
    def test_generic_fallback(self, reasoner):
        f = {"title": "Unknown issue", "cwe": "CWE-999"}
        assert reasoner._detect_attack_type(f) == "generic"


# ── Tests: Business Impact Templates ─────────────────────

class TestBusinessImpactTemplates:

    @pytest.mark.unit
    def test_all_severities_covered(self):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            assert sev in BUSINESS_IMPACT_TEMPLATES
            assert len(BUSINESS_IMPACT_TEMPLATES[sev]) > 50

    @pytest.mark.unit
    def test_critical_mentions_immediate(self):
        assert "immediate" in BUSINESS_IMPACT_TEMPLATES["CRITICAL"].lower()

    @pytest.mark.unit
    def test_low_mentions_schedule(self):
        low = BUSINESS_IMPACT_TEMPLATES["LOW"].lower()
        assert "schedule" in low or "sprint" in low or "cycle" in low


# ── Tests: Executive Summary ──────────────────────────────

class TestExecutiveSummary:

    @pytest.mark.unit
    def test_summary_contains_title(self, reasoner, sqli_finding):
        summary = reasoner._build_executive_summary(sqli_finding, "CRITICAL")
        assert "SQL" in summary or "Injection" in summary or "injection" in summary

    @pytest.mark.unit
    def test_summary_contains_severity_word(self, reasoner, sqli_finding):
        summary = reasoner._build_executive_summary(sqli_finding, "CRITICAL")
        assert "serious" in summary.lower() or "critical" in summary.lower() or "extremely" in summary.lower()

    @pytest.mark.unit
    def test_summary_contains_cvss(self, reasoner, sqli_finding):
        summary = reasoner._build_executive_summary(sqli_finding, "CRITICAL")
        assert "9.8" in summary or "/10" in summary

    @pytest.mark.unit
    def test_summary_is_string(self, reasoner, sqli_finding):
        summary = reasoner._build_executive_summary(sqli_finding, "HIGH")
        assert isinstance(summary, str)
        assert len(summary) > 50


# ── Tests: Report Generation ──────────────────────────────

class TestReportGeneration:

    @pytest.mark.unit
    def test_save_enriched_creates_file(self, reasoner, sqli_finding):
        enriched = [{**sqli_finding, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                     "narrative": "test", "business_impact": "test",
                     "executive_summary": "test", "remediation_priority": 95}]
        path = reasoner._save_enriched(enriched)
        assert path.exists()
        assert path.suffix == ".json"

    @pytest.mark.unit
    def test_saved_report_structure(self, reasoner, sqli_finding):
        enriched = [{**sqli_finding, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                     "narrative": "test", "business_impact": "test",
                     "executive_summary": "test", "remediation_priority": 95}]
        path = reasoner._save_enriched(enriched)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["tool"] == "glitchicons"
        assert data["module"] == "severity_reasoner"
        assert data["version"] == "0.9.0"
        assert "findings" in data

    @pytest.mark.unit
    def test_apply_reasoning_merges_fields(self, reasoner, sqli_finding):
        reasoning = SeverityReasoning(
            finding_id="F1",
            original_score=9.8,
            original_severity="CRITICAL",
            suggested_score=None,
            suggested_severity=None,
            score_changed=False,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_breakdown=CVSSCalculator.breakdown("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            narrative="This is a critical SQL injection.",
            business_impact="Immediate risk.",
            executive_summary="Critical vuln found.",
            remediation_priority=95,
        )
        enriched = reasoner._apply_reasoning(sqli_finding, reasoning)
        assert "cvss_vector" in enriched
        assert "narrative" in enriched
        assert "business_impact" in enriched
        assert "executive_summary" in enriched
        assert "remediation_priority" in enriched
        assert enriched["remediation_priority"] == 95

    @pytest.mark.unit
    def test_score_change_fields_added(self, reasoner, sqli_finding):
        reasoning = SeverityReasoning(
            finding_id="F1",
            original_score=9.8, original_severity="CRITICAL",
            suggested_score=7.5, suggested_severity="HIGH",
            score_changed=True,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_breakdown=None,
            narrative="test", business_impact="test",
            executive_summary="test", remediation_priority=80,
        )
        enriched = reasoner._apply_reasoning(sqli_finding, reasoning)
        assert "cvss_suggested" in enriched
        assert enriched["cvss_suggested"] == 7.5
        assert "score_change_note" in enriched
