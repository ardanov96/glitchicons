# tests/test_waf_evasion.py
"""
Unit tests untuk modules/intelligence/waf_evasion.py
Pure unit tests — tidak butuh network.
"""

import pytest
import base64
import urllib.parse

from modules.intelligence.waf_evasion import (
    WAFEvasionEngine,
    EvasionVariant,
    Encoder,
    WAF_SIGNATURES,
    WAF_BYPASS_PRIORITY,
)


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def engine():
    return WAFEvasionEngine()


@pytest.fixture
def sqli_payload():
    return "' OR '1'='1"


@pytest.fixture
def xss_payload():
    return "<script>alert(1)</script>"


@pytest.fixture
def sql_keyword():
    return "SELECT * FROM users WHERE id=1 UNION SELECT NULL--"


# ── Tests: Encoder — URL Encoding ─────────────────────────

class TestEncoderURL:

    @pytest.mark.unit
    def test_url_single_encodes_special(self):
        encoded = Encoder.url_encode_single("' OR '1'='1")
        assert "'" not in encoded
        assert "%27" in encoded

    @pytest.mark.unit
    def test_url_single_encodes_space(self):
        encoded = Encoder.url_encode_single("hello world")
        assert " " not in encoded
        assert "%20" in encoded

    @pytest.mark.unit
    def test_url_double_double_encodes(self):
        encoded = Encoder.url_encode_double("'")
        assert "%2527" in encoded  # %27 -> %2527

    @pytest.mark.unit
    def test_url_partial_keeps_alphanum(self):
        encoded = Encoder.url_encode_partial("SELECT 1")
        assert "SELECT" in encoded  # alphanum preserved
        assert "1" in encoded

    @pytest.mark.unit
    def test_url_decode_recovers_original(self):
        original = "' OR '1'='1"
        encoded = Encoder.url_encode_single(original)
        decoded = urllib.parse.unquote(encoded)
        assert decoded == original


# ── Tests: Encoder — Unicode ──────────────────────────────

class TestEncoderUnicode:

    @pytest.mark.unit
    def test_unicode_encodes_special_chars(self):
        encoded = Encoder.unicode_encode("'")
        assert "%u0027" in encoded.upper() or "%u0027" in encoded.lower()

    @pytest.mark.unit
    def test_unicode_keeps_alphanumeric(self):
        encoded = Encoder.unicode_encode("SELECT")
        assert "SELECT" in encoded  # letters not encoded

    @pytest.mark.unit
    def test_unicode_format_valid(self):
        encoded = Encoder.unicode_encode("<")
        assert "%u003C" in encoded.upper() or "%u003c" in encoded.lower()


# ── Tests: Encoder — HTML Entities ───────────────────────

class TestEncoderHTML:

    @pytest.mark.unit
    def test_html_named_encodes_lt(self):
        encoded = Encoder.html_entity_named("<script>")
        assert "&lt;" in encoded
        assert "&gt;" in encoded

    @pytest.mark.unit
    def test_html_decimal_format(self):
        encoded = Encoder.html_entity_decimal("<")
        assert "&#x3C;" in encoded or "&#60;" in encoded

    @pytest.mark.unit
    def test_html_hex_format(self):
        encoded = Encoder.html_entity_hex("<")
        assert "&#x" in encoded


# ── Tests: Encoder — Hex & Base64 ─────────────────────────

class TestEncoderHexBase64:

    @pytest.mark.unit
    def test_hex_encode_format(self):
        encoded = Encoder.hex_encode("A")
        assert "\\x41" in encoded

    @pytest.mark.unit
    def test_hex_string_mysql_format(self):
        encoded = Encoder.hex_string("test")
        assert encoded.startswith("0x")
        assert encoded == "0x" + "test".encode().hex()

    @pytest.mark.unit
    def test_base64_valid(self):
        original = "alert(1)"
        encoded = Encoder.base64_encode(original)
        decoded = base64.b64decode(encoded).decode()
        assert decoded == original

    @pytest.mark.unit
    def test_char_function_format(self):
        encoded = Encoder.char_function("A")
        assert "CHAR(65)" in encoded

    @pytest.mark.unit
    def test_char_function_multiple_chars(self):
        encoded = Encoder.char_function("AB")
        assert "CHAR(65,66)" in encoded


# ── Tests: Encoder — Case Manipulation ───────────────────

class TestEncoderCase:

    @pytest.mark.unit
    def test_case_upper(self):
        assert Encoder.case_upper("select") == "SELECT"

    @pytest.mark.unit
    def test_case_lower(self):
        assert Encoder.case_lower("SELECT") == "select"

    @pytest.mark.unit
    def test_case_mixed_alternating(self):
        result = Encoder.case_mixed("select")
        # Should alternate case
        assert result != result.upper()
        assert result != result.lower()

    @pytest.mark.unit
    def test_case_mixed_length_preserved(self):
        original = "SELECT"
        assert len(Encoder.case_mixed(original)) == len(original)

    @pytest.mark.unit
    def test_case_alternating_starts_lower(self):
        result = Encoder.case_alternating("A")
        assert result == "a"


# ── Tests: Encoder — Whitespace ──────────────────────────

class TestEncoderWhitespace:

    @pytest.mark.unit
    def test_whitespace_tab_replaces_spaces(self):
        result = Encoder.whitespace_tab("hello world")
        assert " " not in result
        assert "\t" in result

    @pytest.mark.unit
    def test_whitespace_newline_replaces_spaces(self):
        result = Encoder.whitespace_newline("hello world")
        assert " " not in result
        assert "\n" in result

    @pytest.mark.unit
    def test_whitespace_multi_doubles_spaces(self):
        result = Encoder.whitespace_multi("a b")
        assert "  " in result


# ── Tests: Encoder — Comments ─────────────────────────────

class TestEncoderComments:

    @pytest.mark.unit
    def test_comment_inline_replaces_spaces(self):
        result = Encoder.comment_inline("hello world")
        assert " " not in result
        assert "/**/" in result

    @pytest.mark.unit
    def test_comment_between_keywords_breaks_select(self):
        result = Encoder.comment_between_keywords("SELECT 1")
        assert "/**/" in result
        assert "SELECT" not in result or "/**/" in result

    @pytest.mark.unit
    def test_comment_hash_replaces_double_dash(self):
        result = Encoder.comment_hash("1--")
        assert "--" not in result
        assert "#" in result

    @pytest.mark.unit
    def test_comment_url_encode(self):
        result = Encoder.comment_url_encode("1--")
        assert "--" not in result
        assert "%2d" in result.lower()

    @pytest.mark.unit
    def test_null_byte_appended(self):
        result = Encoder.null_byte("test")
        assert result.endswith("%00")

    @pytest.mark.unit
    def test_null_byte_prefix_prepended(self):
        result = Encoder.null_byte_prefix("test")
        assert result.startswith("%00")


# ── Tests: Encoder — SQL Functions ───────────────────────

class TestEncoderSQL:

    @pytest.mark.unit
    def test_concat_mysql_format(self):
        result = Encoder.concat_mysql("hello")
        assert "CONCAT(" in result

    @pytest.mark.unit
    def test_concat_oracle_format(self):
        result = Encoder.concat_oracle("hello")
        assert "||" in result

    @pytest.mark.unit
    def test_concat_short_string_handled(self):
        """Single char string harus tidak crash."""
        result = Encoder.concat_mysql("x")
        assert result == "x"  # too short to concat

    @pytest.mark.unit
    def test_concat_mysql_splits_in_half(self):
        result = Encoder.concat_mysql("abcd")
        assert "CONCAT('ab','cd')" == result


# ── Tests: Encoder — XSS ─────────────────────────────────

class TestEncoderXSS:

    @pytest.mark.unit
    def test_xss_svg_wrapper(self):
        result = Encoder.xss_svg("alert(1)")
        assert "<svg" in result
        assert "onload" in result
        assert "alert(1)" in result

    @pytest.mark.unit
    def test_xss_img_onerror(self):
        result = Encoder.xss_img_onerror("alert(1)")
        assert "<img" in result
        assert "onerror" in result
        assert "alert(1)" in result

    @pytest.mark.unit
    def test_xss_template_replaces_quotes(self):
        result = Encoder.xss_template_literal("alert('XSS')")
        assert "'" not in result
        assert "`" in result

    @pytest.mark.unit
    def test_xss_fromcharcode_format(self):
        result = Encoder.xss_fromcharcode("alert(1)")
        assert "String.fromCharCode(" in result
        assert "eval(" in result


# ── Tests: WAFEvasionEngine ───────────────────────────────

class TestWAFEvasionEngine:

    @pytest.mark.unit
    def test_evade_returns_variants(self, engine, sqli_payload):
        variants = engine.evade(sqli_payload, attack_type="sqli")
        assert len(variants) > 0

    @pytest.mark.unit
    def test_evade_all_different_from_original(self, engine, sqli_payload):
        variants = engine.evade(sqli_payload, attack_type="sqli")
        for v in variants:
            assert v.encoded != sqli_payload

    @pytest.mark.unit
    def test_evade_respects_max_variants(self, engine, sqli_payload):
        variants = engine.evade(sqli_payload, attack_type="sqli", max_variants=5)
        assert len(variants) <= 5

    @pytest.mark.unit
    def test_evade_sorted_by_bypass_rate(self, engine, sqli_payload):
        variants = engine.evade(sqli_payload, attack_type="sqli")
        rates = [v.estimated_bypass_rate for v in variants]
        assert rates == sorted(rates, reverse=True)

    @pytest.mark.unit
    def test_evade_xss_includes_svg(self, engine, xss_payload):
        variants = engine.evade(xss_payload, attack_type="xss")
        techniques = {v.technique for v in variants}
        assert "xss_svg" in techniques or "url_single" in techniques

    @pytest.mark.unit
    def test_evade_no_duplicates(self, engine, sqli_payload):
        variants = engine.evade(sqli_payload, attack_type="sqli")
        encoded_values = [v.encoded for v in variants]
        assert len(encoded_values) == len(set(encoded_values))

    @pytest.mark.unit
    def test_evade_specific_technique(self, engine, sqli_payload):
        variants = engine.evade(sqli_payload, technique="url_single")
        assert len(variants) >= 1
        assert variants[0].technique == "url_single"

    @pytest.mark.unit
    def test_evade_unknown_technique(self, engine, sqli_payload):
        variants = engine.evade(sqli_payload, technique="nonexistent_technique")
        assert variants == []

    @pytest.mark.unit
    def test_evasion_variant_fields(self, engine, sqli_payload):
        variants = engine.evade(sqli_payload, attack_type="sqli", max_variants=1)
        assert len(variants) >= 1
        v = variants[0]
        assert v.original == sqli_payload
        assert v.attack_type == "sqli"
        assert 0.0 <= v.estimated_bypass_rate <= 1.0
        assert v.technique_description != ""


# ── Tests: WAF Fingerprinting ─────────────────────────────

class TestWAFFingerprinting:

    @pytest.mark.unit
    def test_cloudflare_detected_by_header(self, engine):
        headers = {"cf-ray": "abc123", "server": "cloudflare"}
        waf = engine.fingerprint_waf(headers, "")
        assert waf == "Cloudflare"

    @pytest.mark.unit
    def test_modsecurity_detected_by_body(self, engine):
        waf = engine.fingerprint_waf({}, "406 Not Acceptable - mod_security")
        assert waf == "ModSecurity"

    @pytest.mark.unit
    def test_imperva_detected_by_header(self, engine):
        headers = {"x-iinfo": "123", "set-cookie": "visid_incap_abc=xyz"}
        waf = engine.fingerprint_waf(headers, "")
        assert waf == "Imperva"

    @pytest.mark.unit
    def test_unknown_returns_unknown(self, engine):
        waf = engine.fingerprint_waf({}, "<html><body>Normal page</body></html>")
        assert waf == "Unknown"

    @pytest.mark.unit
    def test_is_blocked_on_403(self, engine):
        assert engine.is_blocked(403, "") is True

    @pytest.mark.unit
    def test_is_blocked_on_406(self, engine):
        assert engine.is_blocked(406, "") is True

    @pytest.mark.unit
    def test_is_blocked_by_body(self, engine):
        assert engine.is_blocked(200, "Your request has been blocked by our WAF") is True

    @pytest.mark.unit
    def test_not_blocked_200_clean(self, engine):
        assert engine.is_blocked(200, "<html>Normal response</html>") is False


# ── Tests: Wordlist Generation ────────────────────────────

class TestWordlistGeneration:

    @pytest.mark.unit
    def test_generate_wordlist_not_empty(self, engine):
        payloads = ["' OR '1'='1", "UNION SELECT NULL--"]
        wordlist = engine.generate_wordlist(payloads, attack_type="sqli")
        assert len(wordlist) > 0

    @pytest.mark.unit
    def test_generate_wordlist_no_duplicates(self, engine):
        payloads = ["' OR '1'='1"]
        wordlist = engine.generate_wordlist(payloads, attack_type="sqli")
        assert len(wordlist) == len(set(wordlist))

    @pytest.mark.unit
    def test_generate_wordlist_saves_file(self, engine, tmp_path):
        payloads = ["' OR '1'='1"]
        out = str(tmp_path / "wordlist.txt")
        wordlist = engine.generate_wordlist(payloads, output_file=out)
        from pathlib import Path
        assert Path(out).exists()
        lines = Path(out).read_text().splitlines()
        assert len(lines) == len(wordlist)

    @pytest.mark.unit
    def test_describe_techniques_returns_list(self, engine):
        techniques = engine.describe_techniques("sqli")
        assert isinstance(techniques, list)
        assert len(techniques) > 5

    @pytest.mark.unit
    def test_describe_techniques_sorted_by_rate(self, engine):
        techniques = engine.describe_techniques("sqli")
        rates = [t["bypass_rate"] for t in techniques]
        assert rates == sorted(rates, reverse=True)

    @pytest.mark.unit
    def test_describe_techniques_has_required_fields(self, engine):
        techniques = engine.describe_techniques("xss")
        for t in techniques:
            assert "name" in t
            assert "description" in t
            assert "bypass_rate" in t


# ── Tests: WAF Signatures & Bypass Priority ───────────────

class TestWAFConstants:

    @pytest.mark.unit
    def test_major_wafs_have_signatures(self):
        required = {"Cloudflare", "ModSecurity", "Akamai", "AWS WAF"}
        assert required.issubset(set(WAF_SIGNATURES.keys()))

    @pytest.mark.unit
    def test_each_waf_has_signatures(self):
        for waf, sigs in WAF_SIGNATURES.items():
            assert len(sigs) >= 2, f"{waf} needs at least 2 signatures"

    @pytest.mark.unit
    def test_bypass_priority_covers_major_wafs(self):
        for waf in ["Cloudflare", "ModSecurity", "AWS WAF"]:
            assert waf in WAF_BYPASS_PRIORITY

    @pytest.mark.unit
    def test_bypass_priorities_not_empty(self):
        for waf, techniques in WAF_BYPASS_PRIORITY.items():
            assert len(techniques) >= 3, f"{waf} needs at least 3 priority techniques"
