# tests/test_llm_mutator.py
"""
Unit tests untuk modules/intelligence/llm_mutator.py
LLM dan HTTP calls di-mock — tidak butuh Ollama atau server nyata.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from modules.intelligence.llm_mutator import (
    LLMMutator,
    LLMClient,
    HTTPProber,
    ResponseSnapshot,
    MutationResult,
    SuccessDetector,
    MUTATION_PROMPTS,
    SQLI_ERRORS,
    XSS_SUCCESS,
    SSTI_SUCCESS_PATTERN,
    SSRF_SUCCESS,
)


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def mutator(tmp_path):
    return LLMMutator(
        provider="ollama",
        model="qwen2.5-coder:3b",
        output_dir=str(tmp_path / "mutations"),
        request_delay=0,
        request_timeout=3,
    )


@pytest.fixture
def llm_client():
    return LLMClient(provider="ollama", model="qwen2.5-coder:3b")


@pytest.fixture
def clean_snapshot():
    return ResponseSnapshot(
        payload="test",
        status_code=200,
        response_time_ms=150.0,
        body_length=500,
        body_snippet="<html><body>Search results for: test</body></html>",
        headers={"content-type": "text/html"},
        error_keywords=[],
        reflection_found=True,
        redirect_location="",
    )


@pytest.fixture
def sqli_error_snapshot():
    return ResponseSnapshot(
        payload="' OR '1'='1",
        status_code=500,
        response_time_ms=200.0,
        body_length=800,
        body_snippet="You have an error in your SQL syntax near mysql",
        headers={"content-type": "text/html"},
        error_keywords=["syntax error", "mysql"],
        reflection_found=False,
        redirect_location="",
    )


@pytest.fixture
def xss_success_snapshot():
    return ResponseSnapshot(
        payload="<script>alert(1)</script>",
        status_code=200,
        response_time_ms=100.0,
        body_length=600,
        body_snippet="<html>Search: <script>alert(1)</script></html>",
        headers={"content-type": "text/html"},
        error_keywords=[],
        reflection_found=True,
        redirect_location="",
    )


@pytest.fixture
def ssti_success_snapshot():
    return ResponseSnapshot(
        payload="{{7*7}}",
        status_code=200,
        response_time_ms=120.0,
        body_length=400,
        body_snippet="Hello 49, welcome to our site!",
        headers={"content-type": "text/html"},
        error_keywords=[],
        reflection_found=False,
        redirect_location="",
    )


@pytest.fixture
def ssrf_success_snapshot():
    return ResponseSnapshot(
        payload="http://169.254.169.254/latest/meta-data/",
        status_code=200,
        response_time_ms=300.0,
        body_length=1200,
        body_snippet="ami-id\ninstance-id\nlocal-hostname",
        headers={"content-type": "text/plain"},
        error_keywords=[],
        reflection_found=False,
        redirect_location="",
    )


@pytest.fixture
def timeout_snapshot():
    return ResponseSnapshot(
        payload="'; SELECT SLEEP(5);--",
        status_code=0,
        response_time_ms=5100.0,
        body_length=0,
        body_snippet="[TIMEOUT]",
        headers={},
        error_keywords=[],
        reflection_found=False,
        redirect_location="",
    )


# ── Tests: ResponseSnapshot ───────────────────────────────

class TestResponseSnapshot:

    @pytest.mark.unit
    def test_to_llm_context_contains_payload(self, clean_snapshot):
        context = clean_snapshot.to_llm_context()
        assert clean_snapshot.payload in context

    @pytest.mark.unit
    def test_to_llm_context_contains_status(self, clean_snapshot):
        context = clean_snapshot.to_llm_context()
        assert "200" in context

    @pytest.mark.unit
    def test_to_llm_context_contains_reflection(self, clean_snapshot):
        context = clean_snapshot.to_llm_context()
        assert "True" in context or "reflected" in context.lower()

    @pytest.mark.unit
    def test_to_llm_context_contains_errors(self, sqli_error_snapshot):
        context = sqli_error_snapshot.to_llm_context()
        assert "syntax error" in context or "mysql" in context

    @pytest.mark.unit
    def test_to_llm_context_is_string(self, clean_snapshot):
        assert isinstance(clean_snapshot.to_llm_context(), str)

    @pytest.mark.unit
    def test_snapshot_fields_set(self, clean_snapshot):
        assert clean_snapshot.status_code == 200
        assert clean_snapshot.response_time_ms == 150.0
        assert clean_snapshot.reflection_found is True
        assert clean_snapshot.error_keywords == []


# ── Tests: SuccessDetector ────────────────────────────────

class TestSuccessDetector:

    @pytest.mark.unit
    def test_sqli_error_keywords(self, sqli_error_snapshot):
        assert SuccessDetector.sqli(sqli_error_snapshot) is True

    @pytest.mark.unit
    def test_sqli_time_based(self, timeout_snapshot):
        """Response > 3000ms harus detected sebagai time-based SQLi."""
        assert SuccessDetector.sqli(timeout_snapshot) is True

    @pytest.mark.unit
    def test_sqli_clean_not_detected(self, clean_snapshot):
        assert SuccessDetector.sqli(clean_snapshot) is False

    @pytest.mark.unit
    def test_xss_success_detected(self, xss_success_snapshot):
        assert SuccessDetector.xss(xss_success_snapshot) is True

    @pytest.mark.unit
    def test_xss_no_script_not_detected(self, clean_snapshot):
        assert SuccessDetector.xss(clean_snapshot) is False

    @pytest.mark.unit
    def test_xss_reflection_required(self):
        """XSS harus ada reflection untuk dikonfirmasi."""
        snap = ResponseSnapshot(
            payload="<script>alert(1)</script>",
            status_code=200,
            response_time_ms=100,
            body_length=500,
            body_snippet="safe page without script",
            headers={},
            error_keywords=[],
            reflection_found=False,  # no reflection
            redirect_location="",
        )
        assert SuccessDetector.xss(snap) is False

    @pytest.mark.unit
    def test_ssti_49_detected(self, ssti_success_snapshot):
        assert SuccessDetector.ssti(ssti_success_snapshot) is True

    @pytest.mark.unit
    def test_ssti_literal_not_detected(self, clean_snapshot):
        assert SuccessDetector.ssti(clean_snapshot) is False

    @pytest.mark.unit
    def test_ssrf_metadata_detected(self, ssrf_success_snapshot):
        assert SuccessDetector.ssrf(ssrf_success_snapshot) is True

    @pytest.mark.unit
    def test_ssrf_clean_not_detected(self, clean_snapshot):
        assert SuccessDetector.ssrf(clean_snapshot) is False

    @pytest.mark.unit
    def test_detect_dispatcher_sqli(self, sqli_error_snapshot):
        assert SuccessDetector.detect("sqli", sqli_error_snapshot) is True

    @pytest.mark.unit
    def test_detect_dispatcher_xss(self, xss_success_snapshot):
        assert SuccessDetector.detect("xss", xss_success_snapshot) is True

    @pytest.mark.unit
    def test_detect_dispatcher_ssti(self, ssti_success_snapshot):
        assert SuccessDetector.detect("ssti", ssti_success_snapshot) is True

    @pytest.mark.unit
    def test_detect_dispatcher_ssrf(self, ssrf_success_snapshot):
        assert SuccessDetector.detect("ssrf", ssrf_success_snapshot) is True

    @pytest.mark.unit
    def test_detect_unknown_attack_returns_false(self, clean_snapshot):
        assert SuccessDetector.detect("unknown_attack", clean_snapshot) is False


# ── Tests: LLMClient ─────────────────────────────────────

class TestLLMClient:

    @pytest.mark.unit
    def test_provider_stored(self, llm_client):
        assert llm_client.provider == "ollama"

    @pytest.mark.unit
    def test_model_stored(self, llm_client):
        assert llm_client.model == "qwen2.5-coder:3b"

    @pytest.mark.unit
    def test_parse_payloads_basic(self, llm_client):
        output = "' OR '1'='1\n\" OR \"1\"=\"1\nADMIN'--"
        payloads = llm_client.parse_payloads(output)
        assert len(payloads) == 3
        assert "' OR '1'='1" in payloads

    @pytest.mark.unit
    def test_parse_payloads_strips_numbers(self, llm_client):
        """Numbered list harus di-strip nomor-nya."""
        output = "1. ' OR '1'='1\n2. UNION SELECT\n3. admin'--"
        payloads = llm_client.parse_payloads(output)
        assert all(not p[0].isdigit() for p in payloads)

    @pytest.mark.unit
    def test_parse_payloads_skips_empty(self, llm_client):
        output = "payload1\n\n\npayload2\n  \npayload3"
        payloads = llm_client.parse_payloads(output)
        assert len(payloads) == 3

    @pytest.mark.unit
    def test_parse_payloads_max_10(self, llm_client):
        """Harus cap output di 10 payloads."""
        output = "\n".join([f"payload_{i}" for i in range(20)])
        payloads = llm_client.parse_payloads(output)
        assert len(payloads) <= 10

    @pytest.mark.unit
    def test_parse_payloads_empty_input(self, llm_client):
        payloads = llm_client.parse_payloads("")
        assert payloads == []

    @pytest.mark.unit
    def test_invalid_provider_raises(self):
        client = LLMClient(provider="unknown_llm")
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            client.generate("test prompt")

    @pytest.mark.unit
    def test_is_available_no_key_anthropic(self):
        client = LLMClient(provider="anthropic", api_key=None)
        assert client.is_available() is False

    @pytest.mark.unit
    def test_is_available_with_key_openai(self):
        client = LLMClient(provider="openai", api_key="sk-test")
        assert client.is_available() is True


# ── Tests: Mutation Prompts ───────────────────────────────

class TestMutationPrompts:

    @pytest.mark.unit
    def test_all_attack_types_have_prompts(self):
        required = {"sqli", "xss", "ssti", "ssrf", "generic"}
        assert required == set(MUTATION_PROMPTS.keys())

    @pytest.mark.unit
    def test_prompts_have_placeholders(self):
        for attack_type, prompt in MUTATION_PROMPTS.items():
            assert "{target_url}" in prompt, f"{attack_type} missing {{target_url}}"
            assert "{param}" in prompt, f"{attack_type} missing {{param}}"
            assert "{context}" in prompt, f"{attack_type} missing {{context}}"

    @pytest.mark.unit
    def test_sqli_prompt_mentions_db_engines(self):
        sqli = MUTATION_PROMPTS["sqli"]
        engines = ["mysql", "postgresql", "oracle", "mssql"]
        assert "database engine" in sqli.lower() or any(e.lower() in sqli.lower() for e in engines)

    @pytest.mark.unit
    def test_xss_prompt_mentions_encoding(self):
        xss = MUTATION_PROMPTS["xss"]
        assert "encod" in xss.lower()

    @pytest.mark.unit
    def test_ssrf_prompt_mentions_cloud(self):
        ssrf = MUTATION_PROMPTS["ssrf"]
        assert "169.254" in ssrf or "metadata" in ssrf.lower()

    @pytest.mark.unit
    def test_prompts_specify_output_format(self):
        for attack_type, prompt in MUTATION_PROMPTS.items():
            assert "per line" in prompt.lower() or "one payload" in prompt.lower()


# ── Tests: Error/Success Constants ───────────────────────

class TestConstants:

    @pytest.mark.unit
    def test_sqli_errors_not_empty(self):
        assert len(SQLI_ERRORS) >= 5

    @pytest.mark.unit
    def test_sqli_errors_cover_major_dbs(self):
        combined = " ".join(SQLI_ERRORS).lower()
        assert "mysql" in combined
        assert "syntax error" in combined

    @pytest.mark.unit
    def test_xss_success_has_script(self):
        assert any("script" in s.lower() for s in XSS_SUCCESS)

    @pytest.mark.unit
    def test_ssti_pattern_is_49(self):
        assert SSTI_SUCCESS_PATTERN == "49"  # 7*7

    @pytest.mark.unit
    def test_ssrf_success_has_aws(self):
        assert any("ami" in s.lower() or "instance" in s.lower() for s in SSRF_SUCCESS)


# ── Tests: Mutator Init ───────────────────────────────────

class TestMutatorInit:

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path):
        new_dir = tmp_path / "mutations_out"
        LLMMutator(output_dir=str(new_dir))
        assert new_dir.exists()

    @pytest.mark.unit
    def test_llm_provider_set(self, mutator):
        assert mutator.llm.provider == "ollama"

    @pytest.mark.unit
    def test_prober_created(self, mutator):
        assert mutator.prober is not None


# ── Tests: Finding Builder ────────────────────────────────

class TestFindingBuilder:

    @pytest.mark.unit
    def test_sqli_finding_critical(self, mutator, sqli_error_snapshot):
        f = mutator._make_finding("' OR '1'='1", sqli_error_snapshot, "sqli")
        assert f["severity"] == "CRITICAL"
        assert f["cvss"] == 9.8
        assert f["cwe"] == "CWE-89"

    @pytest.mark.unit
    def test_xss_finding_high(self, mutator, xss_success_snapshot):
        f = mutator._make_finding("<script>alert(1)</script>", xss_success_snapshot, "xss")
        assert f["severity"] == "HIGH"
        assert f["cwe"] == "CWE-79"

    @pytest.mark.unit
    def test_ssti_finding_critical(self, mutator, ssti_success_snapshot):
        f = mutator._make_finding("{{7*7}}", ssti_success_snapshot, "ssti")
        assert f["severity"] == "CRITICAL"
        assert f["cwe"] == "CWE-94"

    @pytest.mark.unit
    def test_finding_contains_payload(self, mutator, sqli_error_snapshot):
        payload = "' OR '1'='1"
        f = mutator._make_finding(payload, sqli_error_snapshot, "sqli")
        assert payload in f["payload"]

    @pytest.mark.unit
    def test_finding_structure(self, mutator, clean_snapshot):
        f = mutator._make_finding("test", clean_snapshot, "generic")
        required = {"id", "title", "severity", "cvss", "cwe",
                    "description", "evidence", "remediation", "timestamp"}
        assert required.issubset(set(f.keys()))


# ── Tests: Save Result ────────────────────────────────────

class TestSaveResult:

    @pytest.mark.unit
    def test_save_creates_file(self, mutator, clean_snapshot):
        result = MutationResult(
            attack_type="sqli",
            target_url="https://target.com/search",
            param="q",
            rounds_run=2,
            payloads_tried=["payload1", "payload2"],
            successful_payload=None,
            snapshots=[clean_snapshot],
            finding=None,
            total_time_s=3.5,
        )
        mutator._save_result(result)
        files = list(mutator.output_dir.glob("mutation_sqli_*.json"))
        assert len(files) == 1

    @pytest.mark.unit
    def test_saved_json_structure(self, mutator, clean_snapshot):
        result = MutationResult(
            attack_type="xss",
            target_url="https://target.com/search",
            param="q",
            rounds_run=3,
            payloads_tried=["<script>alert(1)</script>"],
            successful_payload="<script>alert(1)</script>",
            snapshots=[clean_snapshot],
            finding={"title": "XSS found"},
            total_time_s=5.0,
        )
        mutator._save_result(result)
        files = list(mutator.output_dir.glob("mutation_xss_*.json"))
        data = json.loads(files[0].read_text(encoding="utf-8"))

        assert data["tool"] == "glitchicons"
        assert data["module"] == "llm_mutator"
        assert data["version"] == "0.9.0"
        assert data["attack_type"] == "xss"
        assert data["success"] is True
        assert "snapshots" in data

    @pytest.mark.unit
    def test_mutation_result_success_property(self):
        r = MutationResult(
            attack_type="sqli", target_url="", param="",
            rounds_run=1, payloads_tried=[], successful_payload="payload",
            snapshots=[], finding={}, total_time_s=1.0,
        )
        assert r.success is True

    @pytest.mark.unit
    def test_mutation_result_failure_property(self):
        r = MutationResult(
            attack_type="sqli", target_url="", param="",
            rounds_run=5, payloads_tried=[], successful_payload=None,
            snapshots=[], finding=None, total_time_s=10.0,
        )
        assert r.success is False
