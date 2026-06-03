# tests/test_llm_intelligence_v2.py
"""
Unit tests untuk modules/intelligence/llm_intelligence_v2.py
Network calls di-mock — tidak butuh LLM server.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from modules.intelligence.llm_intelligence_v2 import (
    FrameworkDetector, FrameworkResult,
    NucleiTemplateGenerator,
    PayloadLibrary, PayloadEntry,
    ContextAwarePayloadGen,
    FRAMEWORK_SIGNATURES, DEFAULT_PAYLOADS,
    TECH_INDICATORS,
)


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def detector():
    return FrameworkDetector(timeout=5, probe_paths=False)


@pytest.fixture
def nuclei_gen(tmp_path):
    return NucleiTemplateGenerator(output_dir=str(tmp_path / "templates"))


@pytest.fixture
def payload_lib(tmp_path):
    lib = PayloadLibrary(db_path=str(tmp_path / "payloads.json"))
    return lib


@pytest.fixture
def payload_gen(tmp_path):
    lib = PayloadLibrary(db_path=str(tmp_path / "payloads.json"))
    return ContextAwarePayloadGen(provider="ollama", payload_library=lib)


def sample_finding(attack="xss"):
    return {
        "title":       f"Reflected XSS in /search" if attack == "xss" else f"SQL Injection",
        "severity":    "HIGH",
        "cvss":        7.5,
        "cwe":         "CWE-79" if attack == "xss" else "CWE-89",
        "target":      "https://target.com/search?q=test",
        "description": f"Found {attack} vulnerability",
        "evidence":    f"Payload: <script>alert(1)</script>" if attack == "xss" else "MySQL error",
        "remediation": "Sanitize input",
    }


# ── Tests: FrameworkResult ────────────────────────────────

class TestFrameworkResult:

    @pytest.mark.unit
    def test_init(self):
        r = FrameworkResult(
            framework="django", confidence=0.8, version="4.2",
            language="python", indicators=["cookie:csrftoken"],
            attack_hints=["SSTI: {{7*7}}"],
        )
        assert r.framework == "django"
        assert r.confidence == 0.8
        assert r.language == "python"

    @pytest.mark.unit
    def test_default_version_empty(self):
        r = FrameworkResult("flask", 0.5, "", "python", [], [])
        assert r.version == ""


# ── Tests: FrameworkDetector ──────────────────────────────

class TestFrameworkDetector:

    @pytest.mark.unit
    def test_init(self, detector):
        assert detector.timeout == 5

    @pytest.mark.unit
    def test_detect_django_from_cookie(self, detector):
        result = detector.detect_from_response(
            headers={"Content-Type": "text/html"},
            body="<html></html>",
            cookies={"csrftoken": "abc123", "sessionid": "xyz"},
        )
        assert result.framework == "django"
        assert result.language == "python"
        assert result.confidence > 0

    @pytest.mark.unit
    def test_detect_flask_from_header(self, detector):
        result = detector.detect_from_response(
            headers={"Server": "Werkzeug/2.3.0"},
            body="werkzeug.exceptions.NotFound: 404 Not Found",
            cookies={"session": "abc123"},
        )
        assert result.framework == "flask"
        assert result.language == "python"

    @pytest.mark.unit
    def test_detect_spring_from_body(self, detector):
        result = detector.detect_from_response(
            headers={},
            body="Whitelabel Error Page\norg.springframework.web.HttpRequestMethodNotSupportedException",
            cookies={"JSESSIONID": "abc123"},
        )
        assert result.framework == "spring"
        assert result.language == "java"

    @pytest.mark.unit
    def test_detect_laravel_from_cookie(self, detector):
        result = detector.detect_from_response(
            headers={},
            body="Whoops, looks like something went wrong.",
            cookies={"laravel_session": "abc", "XSRF-TOKEN": "xyz"},
        )
        assert result.framework == "laravel"
        assert result.language == "php"

    @pytest.mark.unit
    def test_detect_express_from_header(self, detector):
        result = detector.detect_from_response(
            headers={"X-Powered-By": "Express"},
            body="Cannot GET /notfound",
            cookies={},
        )
        assert result.framework == "express"
        assert result.language == "nodejs"

    @pytest.mark.unit
    def test_detect_wordpress_from_body(self, detector):
        result = detector.detect_from_response(
            headers={},
            body='<link rel="stylesheet" href="/wp-content/themes/default/style.css">',
            cookies={},
        )
        assert result.framework == "wordpress"
        assert result.language == "php"

    @pytest.mark.unit
    def test_detect_unknown_framework(self, detector):
        result = detector.detect_from_response(
            headers={"Content-Type": "text/html"},
            body="Hello World",
            cookies={},
        )
        assert result.framework == "unknown"
        assert result.confidence == 0.0

    @pytest.mark.unit
    def test_attack_hints_populated(self, detector):
        result = detector.detect_from_response(
            headers={"Server": "Werkzeug/2.3.0"},
            body="",
            cookies={},
        )
        assert len(result.attack_hints) > 0
        assert any("SSTI" in h or "Werkzeug" in h for h in result.attack_hints)

    @pytest.mark.unit
    def test_get_attack_hints_known_framework(self, detector):
        hints = detector.get_attack_hints("django")
        assert len(hints) > 0
        assert any("SSTI" in h for h in hints)

    @pytest.mark.unit
    def test_get_attack_hints_unknown(self, detector):
        hints = detector.get_attack_hints("nonexistent")
        assert isinstance(hints, list)
        assert len(hints) > 0  # Returns generic hints

    @pytest.mark.unit
    def test_extract_version_django(self, detector):
        version = detector._extract_version(
            "django",
            {},
            "Environment: Django/4.2.0 on Python 3.11",
        )
        assert version == "4.2.0"

    @pytest.mark.unit
    def test_detect_from_network(self, detector):
        mock_resp = MagicMock()
        mock_resp.headers = {"Server": "Werkzeug/2.3.0"}
        mock_resp.text     = "Werkzeug debugger"
        mock_resp.cookies  = {}
        with patch.object(detector.client, "get", return_value=mock_resp):
            result = detector.detect("https://target.com")
        assert result.framework == "flask"

    @pytest.mark.unit
    def test_detect_network_error(self, detector):
        with patch.object(detector.client, "get", side_effect=Exception("timeout")):
            result = detector.detect("https://target.com")
        assert result.framework == "unknown"

    @pytest.mark.unit
    def test_framework_signatures_complete(self):
        required_keys = {"language", "headers", "cookies", "body_patterns", "attack_hints"}
        for fw, sig in FRAMEWORK_SIGNATURES.items():
            missing = required_keys - set(sig.keys())
            assert not missing, f"{fw} missing: {missing}"

    @pytest.mark.unit
    def test_all_frameworks_have_attack_hints(self):
        for fw, sig in FRAMEWORK_SIGNATURES.items():
            assert len(sig["attack_hints"]) >= 3, f"{fw} needs more attack hints"


# ── Tests: NucleiTemplateGenerator ───────────────────────

class TestNucleiTemplateGenerator:

    @pytest.mark.unit
    def test_init(self, nuclei_gen):
        assert nuclei_gen.output_dir.exists()

    @pytest.mark.unit
    def test_from_finding_creates_file(self, nuclei_gen):
        path = nuclei_gen.from_finding(sample_finding("xss"))
        assert path.exists()
        assert path.suffix == ".yaml"

    @pytest.mark.unit
    def test_template_has_required_fields(self, nuclei_gen):
        path = nuclei_gen.from_finding(sample_finding("xss"))
        content = path.read_text()
        assert "id:" in content
        assert "info:" in content
        assert "name:" in content
        assert "severity:" in content
        assert "requests:" in content

    @pytest.mark.unit
    def test_xss_template_has_payload(self, nuclei_gen):
        path = nuclei_gen.from_finding(sample_finding("xss"))
        content = path.read_text()
        assert "script" in content or "onerror" in content or "alert" in content

    @pytest.mark.unit
    def test_sqli_template_has_matcher(self, nuclei_gen):
        path = nuclei_gen.from_finding(sample_finding("sqli"))
        content = path.read_text()
        assert "matchers:" in content
        assert "syntax error" in content.lower() or "sleep" in content.lower()

    @pytest.mark.unit
    def test_template_id_unique(self, nuclei_gen):
        p1 = nuclei_gen.from_finding(sample_finding("xss"))
        p2 = nuclei_gen.from_finding(sample_finding("xss"))
        assert p1.name != p2.name

    @pytest.mark.unit
    def test_from_findings_multiple(self, nuclei_gen):
        findings = [sample_finding("xss"), sample_finding("sqli")]
        paths = nuclei_gen.from_findings(findings)
        assert len(paths) == 2

    @pytest.mark.unit
    def test_classify_xss(self, nuclei_gen):
        assert nuclei_gen._classify_finding("Reflected XSS", "") == "xss"

    @pytest.mark.unit
    def test_classify_sqli(self, nuclei_gen):
        assert nuclei_gen._classify_finding("SQL Injection", "MySQL syntax error") == "sqli"

    @pytest.mark.unit
    def test_classify_ssrf(self, nuclei_gen):
        assert nuclei_gen._classify_finding("SSRF via redirect", "") == "ssrf"

    @pytest.mark.unit
    def test_classify_cors(self, nuclei_gen):
        assert nuclei_gen._classify_finding("CORS Misconfiguration", "") == "cors"

    @pytest.mark.unit
    def test_classify_generic(self, nuclei_gen):
        result = nuclei_gen._classify_finding("Unknown Issue", "")
        assert result == "generic"

    @pytest.mark.unit
    def test_severity_mapping(self, nuclei_gen):
        assert nuclei_gen.SEVERITY_MAP["CRITICAL"] == "critical"
        assert nuclei_gen.SEVERITY_MAP["HIGH"]     == "high"
        assert nuclei_gen.SEVERITY_MAP["INFO"]     == "info"

    @pytest.mark.unit
    def test_cors_template_has_origin(self, nuclei_gen):
        cors_finding = {
            "title": "CORS Misconfiguration", "severity": "HIGH",
            "cvss": 7.4, "cwe": "CWE-942",
            "target": "https://target.com/api",
            "description": "CORS allows all origins",
            "evidence": "Access-Control-Allow-Origin: *",
            "remediation": "Restrict origins",
        }
        path = nuclei_gen.from_finding(cors_finding)
        content = path.read_text()
        assert "Origin" in content or "evil" in content


# ── Tests: PayloadEntry ───────────────────────────────────

class TestPayloadEntry:

    @pytest.mark.unit
    def test_success_rate_zero_attempts(self):
        e = PayloadEntry(payload="test", attack_type="xss", framework="generic")
        assert e.success_rate == 0.0

    @pytest.mark.unit
    def test_success_rate_calculation(self):
        e = PayloadEntry(
            payload="test", attack_type="xss", framework="generic",
            success_count=3, attempt_count=10,
        )
        assert e.success_rate == 0.3

    @pytest.mark.unit
    def test_effectiveness_score_no_use(self):
        e = PayloadEntry(payload="test", attack_type="xss", framework="generic")
        assert e.effectiveness_score == 0.0

    @pytest.mark.unit
    def test_effectiveness_score_with_success(self):
        e = PayloadEntry(
            payload="test", attack_type="xss", framework="generic",
            success_count=5, attempt_count=10,
        )
        assert e.effectiveness_score >= 0.5


# ── Tests: PayloadLibrary ─────────────────────────────────

class TestPayloadLibrary:

    @pytest.mark.unit
    def test_init_creates_file(self, tmp_path):
        lib = PayloadLibrary(db_path=str(tmp_path / "payloads.json"))
        assert (tmp_path / "payloads.json").exists()

    @pytest.mark.unit
    def test_default_payloads_seeded(self, payload_lib):
        assert payload_lib.stats["total_payloads"] > 0

    @pytest.mark.unit
    def test_get_payloads_ssti_django(self, payload_lib):
        payloads = payload_lib.get_payloads("ssti", "django")
        assert len(payloads) > 0
        assert "{{7*7}}" in payloads

    @pytest.mark.unit
    def test_get_payloads_fallback_to_generic(self, payload_lib):
        payloads = payload_lib.get_payloads("ssti", "unknown_framework")
        assert len(payloads) > 0  # Falls back to generic

    @pytest.mark.unit
    def test_record_success_increments(self, payload_lib):
        payload_lib.get_payloads("ssti", "django")
        payload = "{{7*7}}"
        payload_lib.record_success("ssti", payload, "django")
        entries = payload_lib._get_entries("ssti", "django")
        entry = next((e for e in entries if e.payload == payload), None)
        assert entry is not None
        assert entry.success_count >= 1

    @pytest.mark.unit
    def test_record_success_new_payload(self, payload_lib):
        new_payload = "{{config.__class__.__init__.__globals__}}"
        payload_lib.record_success("ssti", new_payload, "flask")
        payloads = payload_lib.get_payloads("ssti", "flask")
        assert new_payload in payloads

    @pytest.mark.unit
    def test_add_payload(self, payload_lib):
        payload_lib.add_payload("xss", "<img src=x onerror=fetch('//evil.com')>", "react")
        payloads = payload_lib.get_payloads("xss", "react")
        assert len(payloads) > 0

    @pytest.mark.unit
    def test_no_duplicate_payloads(self, payload_lib):
        payload_lib.add_payload("xss", "<script>test</script>", "generic")
        payload_lib.add_payload("xss", "<script>test</script>", "generic")
        payloads = payload_lib.get_payloads("xss", "generic")
        assert payloads.count("<script>test</script>") <= 1

    @pytest.mark.unit
    def test_stats_structure(self, payload_lib):
        stats = payload_lib.stats
        assert "total_payloads" in stats
        assert "attack_types" in stats
        assert stats["total_payloads"] > 0

    @pytest.mark.unit
    def test_persistence_roundtrip(self, tmp_path):
        path = tmp_path / "payloads.json"
        lib1 = PayloadLibrary(db_path=str(path))
        lib1.add_payload("sqli", "' OR 1=1--", "mysql")
        lib1.record_success("sqli", "' OR 1=1--", "mysql")

        lib2 = PayloadLibrary(db_path=str(path))
        payloads = lib2.get_payloads("sqli", "mysql")
        assert "' OR 1=1--" in payloads

    @pytest.mark.unit
    def test_top_n_limit(self, payload_lib):
        payloads = payload_lib.get_payloads("sqli", "generic", top_n=2)
        assert len(payloads) <= 2

    @pytest.mark.unit
    def test_default_payloads_not_empty(self):
        assert len(DEFAULT_PAYLOADS) >= 4
        assert "ssti" in DEFAULT_PAYLOADS
        assert "sqli" in DEFAULT_PAYLOADS
        assert "xss" in DEFAULT_PAYLOADS


# ── Tests: ContextAwarePayloadGen ─────────────────────────

class TestContextAwarePayloadGen:

    @pytest.mark.unit
    def test_init(self, payload_gen):
        assert payload_gen.provider == "ollama"

    @pytest.mark.unit
    def test_parse_response_json_array(self, payload_gen):
        raw = '["payload1", "payload2", "payload3"]'
        result = payload_gen._parse_response(raw)
        assert result == ["payload1", "payload2", "payload3"]

    @pytest.mark.unit
    def test_parse_response_embedded_json(self, payload_gen):
        raw = 'Here are the payloads:\n["p1", "p2"]\nDone.'
        result = payload_gen._parse_response(raw)
        assert "p1" in result

    @pytest.mark.unit
    def test_parse_response_fallback_lines(self, payload_gen):
        raw = "payload_a\npayload_b\npayload_c"
        result = payload_gen._parse_response(raw)
        assert len(result) >= 2

    @pytest.mark.unit
    def test_fallback_payloads_sqli(self, payload_gen):
        payloads = payload_gen._fallback_payloads("sqli")
        assert len(payloads) >= 1
        assert any("OR" in p for p in payloads)

    @pytest.mark.unit
    def test_fallback_payloads_xss(self, payload_gen):
        payloads = payload_gen._fallback_payloads("xss")
        assert len(payloads) >= 1
        assert any("script" in p.lower() for p in payloads)

    @pytest.mark.unit
    def test_fallback_on_llm_error(self, payload_gen):
        with patch.object(payload_gen.client, "post", side_effect=Exception("LLM offline")):
            payloads = payload_gen.generate("sqli", "django")
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    @pytest.mark.unit
    def test_generate_with_mock_ollama(self, payload_gen):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"response": '["payload1", "{{7*7}}", "${7*7}"]'}
        with patch.object(payload_gen.client, "post", return_value=mock_resp):
            payloads = payload_gen.generate("ssti", "django", context="Django error page")
        assert len(payloads) >= 1

    @pytest.mark.unit
    def test_build_prompt_contains_framework(self, payload_gen):
        prompt = payload_gen._build_prompt(
            attack_type="ssti", framework="spring",
            context="", waf_detected="", base_payloads=[], num_payloads=5,
        )
        assert "spring" in prompt.lower()
        assert "ssti" in prompt.lower()

    @pytest.mark.unit
    def test_build_prompt_includes_waf(self, payload_gen):
        prompt = payload_gen._build_prompt(
            attack_type="xss", framework="generic",
            context="", waf_detected="Cloudflare", base_payloads=[], num_payloads=5,
        )
        assert "Cloudflare" in prompt

    @pytest.mark.unit
    def test_build_prompt_includes_base_payloads(self, payload_gen):
        base = ["<script>alert(1)</script>"]
        prompt = payload_gen._build_prompt(
            attack_type="xss", framework="generic",
            context="", waf_detected="", base_payloads=base, num_payloads=5,
        )
        assert "alert(1)" in prompt
