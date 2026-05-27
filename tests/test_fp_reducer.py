# tests/test_fp_reducer.py
"""
Unit tests untuk modules/intelligence/fp_reducer.py
LLM calls di-mock — tidak butuh Ollama atau API key.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from modules.intelligence.fp_reducer import (
    FalsePositiveReducer,
    VerificationResult,
    VERDICT_CONFIRMED,
    VERDICT_LIKELY,
    VERDICT_UNCERTAIN,
    VERDICT_FALSE_POSITIVE,
    CONFIDENCE_THRESHOLDS,
    STRONG_EVIDENCE_PATTERNS,
    FALSE_POSITIVE_PATTERNS,
    CONFIRMATION_PAYLOADS,
)


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def reducer(tmp_path):
    return FalsePositiveReducer(
        provider="ollama",
        model="qwen2.5-coder:3b",
        output_dir=str(tmp_path / "verified"),
        confidence_threshold=0.35,
        reprobe=False,
    )


@pytest.fixture
def sqli_finding():
    return {
        "id": "FIND-001",
        "title": "SQL Injection in search parameter",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cwe": "CWE-89",
        "target": "https://target.com/search",
        "description": "SQLi found in q parameter",
        "evidence": (
            "You have an error in your SQL syntax; check the manual "
            "that corresponds to your MySQL server version"
        ),
        "remediation": "Use parameterized queries",
    }


@pytest.fixture
def xss_finding():
    return {
        "id": "FIND-002",
        "title": "Reflected XSS in search",
        "severity": "HIGH",
        "cvss": 7.5,
        "cwe": "CWE-79",
        "target": "https://target.com/search",
        "description": "XSS reflected in response",
        "evidence": "Response body: <script>alert(1)</script> found in page",
        "remediation": "Sanitize output",
    }


@pytest.fixture
def waf_blocked_finding():
    return {
        "id": "FIND-003",
        "title": "Possible XSS",
        "severity": "HIGH",
        "cvss": 7.5,
        "cwe": "CWE-79",
        "target": "https://target.com/search",
        "description": "XSS attempted",
        "evidence": "403 forbidden - WAF blocked this request - security violation detected",
        "remediation": "Sanitize output",
    }


@pytest.fixture
def cors_finding():
    return {
        "id": "FIND-004",
        "title": "CORS Reflected Origin",
        "severity": "CRITICAL",
        "cvss": 9.3,
        "cwe": "CWE-942",
        "target": "https://target.com/api",
        "description": "CORS misconfiguration",
        "evidence": (
            "Request Origin: https://evil.com\n"
            "Access-Control-Allow-Origin: https://evil.com\n"
            "Access-Control-Allow-Credentials: true"
        ),
        "remediation": "Fix CORS policy",
    }


@pytest.fixture
def uncertain_finding():
    return {
        "id": "FIND-005",
        "title": "Possible SSRF",
        "severity": "HIGH",
        "cvss": 8.0,
        "cwe": "CWE-918",
        "target": "https://target.com/fetch",
        "description": "Possible SSRF",
        "evidence": "Response time was slightly longer than baseline. No direct output observed.",
        "remediation": "Validate URLs",
    }


# ── Tests: VerificationResult ─────────────────────────────

class TestVerificationResult:

    @pytest.mark.unit
    def test_is_real_confirmed(self):
        r = VerificationResult(
            finding_id="F1", original_severity="HIGH", original_cvss=7.5,
            verdict=VERDICT_CONFIRMED, confidence=0.95,
            llm_reasoning="Clear evidence", static_signals=[],
            reprobed=False, reprobe_confirmed=None,
            verified_at="2026-01-01",
        )
        assert r.is_real is True

    @pytest.mark.unit
    def test_is_real_likely(self):
        r = VerificationResult(
            finding_id="F1", original_severity="HIGH", original_cvss=7.5,
            verdict=VERDICT_LIKELY, confidence=0.70,
            llm_reasoning="Probable", static_signals=[],
            reprobed=False, reprobe_confirmed=None,
            verified_at="2026-01-01",
        )
        assert r.is_real is True

    @pytest.mark.unit
    def test_is_real_false_positive(self):
        r = VerificationResult(
            finding_id="F1", original_severity="HIGH", original_cvss=7.5,
            verdict=VERDICT_FALSE_POSITIVE, confidence=0.10,
            llm_reasoning="WAF blocked", static_signals=[],
            reprobed=False, reprobe_confirmed=None,
            verified_at="2026-01-01",
        )
        assert r.is_real is False

    @pytest.mark.unit
    def test_verdict_color_confirmed(self):
        r = VerificationResult(
            "F1", "HIGH", 7.5, VERDICT_CONFIRMED, 0.95,
            "", [], False, None, ""
        )
        assert r.verdict_color() == "green"

    @pytest.mark.unit
    def test_verdict_color_false_positive(self):
        r = VerificationResult(
            "F1", "HIGH", 7.5, VERDICT_FALSE_POSITIVE, 0.10,
            "", [], False, None, ""
        )
        assert r.verdict_color() == "red"


# ── Tests: Confidence Thresholds ──────────────────────────

class TestConfidenceThresholds:

    @pytest.mark.unit
    def test_confirmed_threshold(self, reducer):
        verdict = reducer._confidence_to_verdict(0.90)
        assert verdict == VERDICT_CONFIRMED

    @pytest.mark.unit
    def test_confirmed_exact_threshold(self, reducer):
        verdict = reducer._confidence_to_verdict(0.85)
        assert verdict == VERDICT_CONFIRMED

    @pytest.mark.unit
    def test_likely_threshold(self, reducer):
        verdict = reducer._confidence_to_verdict(0.70)
        assert verdict == VERDICT_LIKELY

    @pytest.mark.unit
    def test_likely_exact_threshold(self, reducer):
        verdict = reducer._confidence_to_verdict(0.60)
        assert verdict == VERDICT_LIKELY

    @pytest.mark.unit
    def test_uncertain_threshold(self, reducer):
        verdict = reducer._confidence_to_verdict(0.50)
        assert verdict == VERDICT_UNCERTAIN

    @pytest.mark.unit
    def test_fp_threshold(self, reducer):
        verdict = reducer._confidence_to_verdict(0.20)
        assert verdict == VERDICT_FALSE_POSITIVE

    @pytest.mark.unit
    def test_fp_zero(self, reducer):
        verdict = reducer._confidence_to_verdict(0.0)
        assert verdict == VERDICT_FALSE_POSITIVE

    @pytest.mark.unit
    def test_confirmed_max(self, reducer):
        verdict = reducer._confidence_to_verdict(1.0)
        assert verdict == VERDICT_CONFIRMED

    @pytest.mark.unit
    def test_thresholds_in_order(self):
        assert (
            CONFIDENCE_THRESHOLDS[VERDICT_CONFIRMED] >
            CONFIDENCE_THRESHOLDS[VERDICT_LIKELY] >
            CONFIDENCE_THRESHOLDS[VERDICT_UNCERTAIN] >=
            CONFIDENCE_THRESHOLDS[VERDICT_FALSE_POSITIVE]
        )


# ── Tests: Static Analysis ────────────────────────────────

class TestStaticAnalysis:

    @pytest.mark.unit
    def test_sqli_error_detected(self, reducer):
        evidence = "You have an error in your SQL syntax near mysql"
        signals = reducer._static_analysis(evidence, "sqli")
        assert len(signals) >= 1

    @pytest.mark.unit
    def test_xss_script_tag_detected(self, reducer):
        evidence = "Response: <script>alert(1)</script> found"
        signals = reducer._static_analysis(evidence, "xss")
        assert len(signals) >= 1

    @pytest.mark.unit
    def test_ssti_49_detected(self, reducer):
        evidence = "Output: 49 (from 7*7 template eval)"
        signals = reducer._static_analysis(evidence, "ssti")
        assert len(signals) >= 1

    @pytest.mark.unit
    def test_ssrf_metadata_detected(self, reducer):
        evidence = "Response: ami-id\ninstance-id\nlocal-hostname"
        signals = reducer._static_analysis(evidence, "ssrf")
        assert len(signals) >= 1

    @pytest.mark.unit
    def test_clean_evidence_no_signals(self, reducer):
        evidence = "HTTP 200 OK. Normal page response."
        signals = reducer._static_analysis(evidence, "sqli")
        assert len(signals) == 0

    @pytest.mark.unit
    def test_cors_reflected_detected(self, reducer):
        evidence = "Access-Control-Allow-Origin: https://evil.com"
        signals = reducer._static_analysis(evidence, "cors")
        assert len(signals) >= 1

    @pytest.mark.unit
    def test_multiple_signals_detected(self, reducer):
        evidence = (
            "You have an error in your SQL syntax. "
            "Warning: mysql_fetch_array() expects parameter"
        )
        signals = reducer._static_analysis(evidence, "sqli")
        assert len(signals) >= 2


# ── Tests: False Positive Detection ──────────────────────

class TestFPAnalysis:

    @pytest.mark.unit
    def test_waf_blocked_detected(self, reducer):
        evidence = "403 forbidden - WAF blocked this request"
        signals = reducer._fp_analysis(evidence)
        assert len(signals) >= 1

    @pytest.mark.unit
    def test_security_violation_detected(self, reducer):
        evidence = "Security violation detected. Request rejected."
        signals = reducer._fp_analysis(evidence)
        assert len(signals) >= 1

    @pytest.mark.unit
    def test_access_denied_detected(self, reducer):
        evidence = "Access denied. You don't have permission."
        signals = reducer._fp_analysis(evidence)
        assert len(signals) >= 1

    @pytest.mark.unit
    def test_real_evidence_not_flagged(self, reducer):
        evidence = "You have an error in your SQL syntax near mysql"
        signals = reducer._fp_analysis(evidence)
        assert len(signals) == 0


# ── Tests: Attack Type Detection ─────────────────────────

class TestAttackTypeDetection:

    @pytest.mark.unit
    def test_sqli_by_cwe(self, reducer, sqli_finding):
        attack_type = reducer._detect_attack_type(sqli_finding)
        assert attack_type == "sqli"

    @pytest.mark.unit
    def test_xss_by_title(self, reducer, xss_finding):
        attack_type = reducer._detect_attack_type(xss_finding)
        assert attack_type == "xss"

    @pytest.mark.unit
    def test_cors_by_title(self, reducer, cors_finding):
        attack_type = reducer._detect_attack_type(cors_finding)
        assert attack_type == "cors"

    @pytest.mark.unit
    def test_ssrf_by_cwe(self, reducer):
        finding = {"title": "SSRF vulnerability", "cwe": "CWE-918"}
        attack_type = reducer._detect_attack_type(finding)
        assert attack_type == "ssrf"

    @pytest.mark.unit
    def test_generic_fallback(self, reducer):
        finding = {"title": "Unknown vulnerability", "cwe": "CWE-999"}
        attack_type = reducer._detect_attack_type(finding)
        assert attack_type == "generic"


# ── Tests: LLM Response Parsing ──────────────────────────

class TestLLMResponseParsing:

    @pytest.mark.unit
    def test_parse_valid_json(self, reducer):
        raw = '{"confidence": 0.92, "verdict": "CONFIRMED", "reasoning": "Clear SQL error."}'
        confidence, verdict, reasoning = reducer._parse_llm_response(raw)
        assert confidence == 0.92
        assert verdict == VERDICT_CONFIRMED
        assert "SQL error" in reasoning

    @pytest.mark.unit
    def test_parse_json_in_text(self, reducer):
        raw = 'Sure! Here is my analysis: {"confidence": 0.15, "verdict": "FALSE_POSITIVE", "reasoning": "WAF block."} Hope that helps!'
        confidence, verdict, reasoning = reducer._parse_llm_response(raw)
        assert confidence == 0.15
        assert verdict == VERDICT_FALSE_POSITIVE

    @pytest.mark.unit
    def test_parse_empty_response(self, reducer):
        confidence, verdict, reasoning = reducer._parse_llm_response("")
        assert verdict == VERDICT_UNCERTAIN
        assert confidence == 0.5

    @pytest.mark.unit
    def test_parse_invalid_json(self, reducer):
        confidence, verdict, reasoning = reducer._parse_llm_response("not json at all")
        assert verdict == VERDICT_UNCERTAIN

    @pytest.mark.unit
    def test_confidence_clamped_to_range(self, reducer):
        raw = '{"confidence": 1.5, "verdict": "CONFIRMED", "reasoning": "test"}'
        confidence, _, _ = reducer._parse_llm_response(raw)
        assert 0.0 <= confidence <= 1.0

    @pytest.mark.unit
    def test_confidence_clamped_negative(self, reducer):
        raw = '{"confidence": -0.5, "verdict": "FALSE_POSITIVE", "reasoning": "test"}'
        confidence, _, _ = reducer._parse_llm_response(raw)
        assert confidence >= 0.0


# ── Tests: Fast Path Logic ────────────────────────────────

class TestFastPathLogic:

    @pytest.mark.unit
    def test_strong_evidence_fast_confirmed(self, reducer, sqli_finding):
        """Dua+ static signals dan tidak ada FP signals = fast CONFIRMED."""
        # With strong SQLi evidence, result should be CONFIRMED with high confidence
        with patch.object(reducer, '_llm_verify', return_value=(0.95, VERDICT_CONFIRMED, 'test')) as mock_llm:
            result = reducer.verify_one(sqli_finding)
            assert result.verdict == VERDICT_CONFIRMED
            assert result.confidence >= 0.90

    @pytest.mark.unit
    def test_waf_blocked_fast_fp(self, reducer, waf_blocked_finding):
        """WAF block evidence tanpa static signals = fast FALSE_POSITIVE."""
        with patch.object(reducer, '_llm_verify') as mock_llm:
            result = reducer.verify_one(waf_blocked_finding)
            if result.verdict == VERDICT_FALSE_POSITIVE:
                mock_llm.assert_not_called()


# ── Tests: Strong Evidence Patterns ──────────────────────

class TestStrongEvidencePatterns:

    @pytest.mark.unit
    def test_patterns_not_empty(self):
        assert len(STRONG_EVIDENCE_PATTERNS) >= 4

    @pytest.mark.unit
    def test_sqli_patterns_exist(self):
        assert "sqli" in STRONG_EVIDENCE_PATTERNS
        assert len(STRONG_EVIDENCE_PATTERNS["sqli"]) >= 3

    @pytest.mark.unit
    def test_xss_patterns_exist(self):
        assert "xss" in STRONG_EVIDENCE_PATTERNS
        assert len(STRONG_EVIDENCE_PATTERNS["xss"]) >= 2

    @pytest.mark.unit
    def test_fp_patterns_not_empty(self):
        assert len(FALSE_POSITIVE_PATTERNS) >= 3

    @pytest.mark.unit
    def test_confirmation_payloads_exist(self):
        assert "sqli" in CONFIRMATION_PAYLOADS
        assert "xss" in CONFIRMATION_PAYLOADS
        assert "ssti" in CONFIRMATION_PAYLOADS


# ── Tests: Report Generation ──────────────────────────────

class TestReportGeneration:

    @pytest.mark.unit
    def test_save_verified_creates_file(self, reducer, sqli_finding):
        findings = [{**sqli_finding, "verdict": VERDICT_CONFIRMED, "confidence": 0.95,
                     "llm_reasoning": "Clear evidence", "static_signals": [],
                     "reprobe_confirmed": None, "verified_at": "2026-01-01"}]
        stats = {VERDICT_CONFIRMED: 1, VERDICT_LIKELY: 0,
                 VERDICT_UNCERTAIN: 0, VERDICT_FALSE_POSITIVE: 0}
        path = reducer._save_verified(findings, stats)
        assert path.exists()
        assert path.suffix == ".json"

    @pytest.mark.unit
    def test_saved_report_structure(self, reducer, sqli_finding):
        findings = [{**sqli_finding, "verdict": VERDICT_CONFIRMED, "confidence": 0.95,
                     "llm_reasoning": "test", "static_signals": [],
                     "reprobe_confirmed": None, "verified_at": "2026-01-01"}]
        stats = {VERDICT_CONFIRMED: 1, VERDICT_LIKELY: 0,
                 VERDICT_UNCERTAIN: 0, VERDICT_FALSE_POSITIVE: 0}
        path = reducer._save_verified(findings, stats)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["tool"] == "glitchicons"
        assert data["module"] == "fp_reducer"
        assert data["version"] == "0.9.0"
        assert "stats" in data
        assert "actionable" in data

    @pytest.mark.unit
    def test_actionable_count_correct(self, reducer):
        findings = [
            {"verdict": VERDICT_CONFIRMED,      "confidence": 0.95},
            {"verdict": VERDICT_LIKELY,          "confidence": 0.70},
            {"verdict": VERDICT_UNCERTAIN,       "confidence": 0.45},
            {"verdict": VERDICT_FALSE_POSITIVE,  "confidence": 0.10},
        ]
        stats = {VERDICT_CONFIRMED: 1, VERDICT_LIKELY: 1,
                 VERDICT_UNCERTAIN: 1, VERDICT_FALSE_POSITIVE: 1}
        path = reducer._save_verified(findings, stats)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["actionable"] == 2  # CONFIRMED + LIKELY

    @pytest.mark.unit
    def test_findings_sorted_by_confidence(self, reducer):
        findings = [
            {"verdict": VERDICT_UNCERTAIN,  "confidence": 0.45},
            {"verdict": VERDICT_CONFIRMED,  "confidence": 0.95},
            {"verdict": VERDICT_LIKELY,     "confidence": 0.70},
        ]
        stats = {v: 0 for v in [VERDICT_CONFIRMED, VERDICT_LIKELY,
                                  VERDICT_UNCERTAIN, VERDICT_FALSE_POSITIVE]}
        path = reducer._save_verified(findings, stats)
        data = json.loads(path.read_text(encoding="utf-8"))
        confidences = [f["confidence"] for f in data["findings"]]
        assert confidences == sorted(confidences, reverse=True)
