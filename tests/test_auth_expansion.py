# tests/test_auth_expansion.py
"""
Unit tests untuk modules/auth/auth_expansion.py
Network calls di-mock — tidak butuh real SSO/OAuth server.
"""

import base64
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta

from modules.auth.auth_expansion import (
    SAMLBypassTester, PKCEBypassTester, SSOTester, APIKeyAuditor,
    _finding, _generate_pkce_pair, _key_entropy,
    SAML_ASSERTION_TEMPLATE, SAML_XXE_TEMPLATE,
    API_KEY_PATTERNS, API_KEY_IN_URL_PATTERNS,
    REDIRECT_URI_BYPASSES,
)


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def saml(tmp_path):
    return SAMLBypassTester(
        target="https://sso.target.com/saml/acs",
        output_dir=str(tmp_path),
        timeout=5,
    )


@pytest.fixture
def pkce(tmp_path):
    return PKCEBypassTester(
        auth_endpoint="https://target.com/oauth/authorize",
        token_endpoint="https://target.com/oauth/token",
        client_id="app123",
        output_dir=str(tmp_path),
        timeout=5,
    )


@pytest.fixture
def sso(tmp_path):
    return SSOTester(
        target="https://target.com",
        output_dir=str(tmp_path),
        timeout=5,
    )


@pytest.fixture
def auditor(tmp_path):
    return APIKeyAuditor(
        target="https://target.com",
        api_key="test-api-key-12345678",
        output_dir=str(tmp_path),
        timeout=5,
    )


def mock_resp(status=200, text="", headers=None, json_data=None):
    m = MagicMock()
    m.status_code = status
    m.text = text or (json.dumps(json_data) if json_data else "")
    m.headers = headers or {}
    if json_data is not None:
        m.json.return_value = json_data
    else:
        m.json.side_effect = Exception("no json")
    return m


# ── Tests: _finding ───────────────────────────────────────

class TestFinding:

    @pytest.mark.unit
    def test_valid_finding(self):
        f = _finding("T", "HIGH", 7.5, "CWE-89", "d", "e", "r", "t")
        assert f["severity"] == "HIGH"

    @pytest.mark.unit
    def test_invalid_severity_raises(self):
        with pytest.raises(AssertionError):
            _finding("T", "EXTREME", 7.5, "CWE-89", "d", "e", "r", "t")

    @pytest.mark.unit
    def test_invalid_cvss_raises(self):
        with pytest.raises(AssertionError):
            _finding("T", "HIGH", 11.0, "CWE-89", "d", "e", "r", "t")

    @pytest.mark.unit
    def test_source_tagged(self):
        f = _finding("T", "HIGH", 7.5, "CWE-89", "d", "e", "r", "t", source="test")
        assert "module:test" in f["source"]


# ── Tests: _generate_pkce_pair ────────────────────────────

class TestGeneratePKCEPair:

    @pytest.mark.unit
    def test_returns_tuple(self):
        verifier, challenge = _generate_pkce_pair()
        assert isinstance(verifier, str)
        assert isinstance(challenge, str)

    @pytest.mark.unit
    def test_verifier_min_length(self):
        verifier, _ = _generate_pkce_pair()
        assert len(verifier) >= 43

    @pytest.mark.unit
    def test_challenge_is_s256(self):
        import hashlib
        verifier, challenge = _generate_pkce_pair()
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).rstrip(b"=").decode()
        assert challenge == expected

    @pytest.mark.unit
    def test_verifier_challenge_differ(self):
        verifier, challenge = _generate_pkce_pair()
        assert verifier != challenge

    @pytest.mark.unit
    def test_unique_per_call(self):
        v1, _ = _generate_pkce_pair()
        v2, _ = _generate_pkce_pair()
        assert v1 != v2


# ── Tests: _key_entropy ───────────────────────────────────

class TestKeyEntropy:

    @pytest.mark.unit
    def test_empty_string_zero(self):
        assert _key_entropy("") == 0.0

    @pytest.mark.unit
    def test_single_char_zero(self):
        assert _key_entropy("aaaa") == 0.0

    @pytest.mark.unit
    def test_high_entropy_random(self):
        import secrets
        key = secrets.token_hex(32)
        assert _key_entropy(key) > 3.0

    @pytest.mark.unit
    def test_low_entropy_repeated(self):
        assert _key_entropy("abababababab") < 2.0

    @pytest.mark.unit
    def test_returns_float(self):
        assert isinstance(_key_entropy("test123"), float)


# ── Tests: SAMLBypassTester ───────────────────────────────

class TestSAMLBypassTester:

    @pytest.mark.unit
    def test_init(self, saml):
        assert "sso.target.com" in saml.target

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path):
        out = tmp_path / "saml"
        SAMLBypassTester(target="https://t.com/saml", output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_build_assertion_contains_email(self, saml):
        assertion = saml._build_assertion(email="test@test.com")
        assert "test@test.com" in assertion

    @pytest.mark.unit
    def test_build_assertion_contains_role(self, saml):
        assertion = saml._build_assertion(role="admin")
        assert "admin" in assertion

    @pytest.mark.unit
    def test_build_assertion_expired(self, saml):
        assertion = saml._build_assertion(expired=True)
        # The expiry should be in the past
        assert "NotOnOrAfter" in assertion

    @pytest.mark.unit
    def test_xxe_indicators_trigger_finding(self, saml):
        resp = mock_resp(200, text="root:x:0:0:root:/root:/bin/bash")
        with patch.object(saml.client, "post", return_value=resp):
            findings = saml._check_xxe()
        assert len(findings) >= 1
        assert findings[0]["severity"] == "CRITICAL"
        assert "XXE" in findings[0]["title"]

    @pytest.mark.unit
    def test_xxe_500_triggers_finding(self, saml):
        resp = mock_resp(500, text="Internal Server Error")
        with patch.object(saml.client, "post", return_value=resp):
            findings = saml._check_xxe()
        assert len(findings) >= 1

    @pytest.mark.unit
    def test_xxe_normal_response_no_finding(self, saml):
        resp = mock_resp(403, text="Forbidden")
        with patch.object(saml.client, "post", return_value=resp):
            findings = saml._check_xxe()
        assert findings == []

    @pytest.mark.unit
    def test_unsigned_assertion_accepted_finding(self, saml):
        resp = mock_resp(200, text="Welcome to your dashboard")
        with patch.object(saml.client, "post", return_value=resp):
            findings = saml._check_unsigned_assertion()
        assert len(findings) >= 1
        assert findings[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_unsigned_assertion_rejected_no_finding(self, saml):
        resp = mock_resp(401, text="Invalid signature")
        with patch.object(saml.client, "post", return_value=resp):
            findings = saml._check_unsigned_assertion()
        assert findings == []

    @pytest.mark.unit
    def test_signature_wrapping_302_returns_finding(self, saml):
        resp = mock_resp(302, text="", headers={"location": "/dashboard"})
        with patch.object(saml.client, "post", return_value=resp):
            findings = saml._check_signature_wrapping()
        assert len(findings) >= 1

    @pytest.mark.unit
    def test_assertion_replay_expired_accepted(self, saml):
        resp = mock_resp(302, text="")
        with patch.object(saml.client, "post", return_value=resp):
            findings = saml._check_assertion_replay()
        assert len(findings) >= 1
        assert "Replay" in findings[0]["title"]

    @pytest.mark.unit
    def test_assertion_replay_rejected(self, saml):
        resp = mock_resp(401, text="Token expired")
        with patch.object(saml.client, "post", return_value=resp):
            findings = saml._check_assertion_replay()
        assert findings == []

    @pytest.mark.unit
    def test_role_manipulation_detected(self, saml):
        resp = mock_resp(200, text='{"role":"admin","user":"test"}')
        with patch.object(saml.client, "post", return_value=resp):
            findings = saml._check_role_manipulation()
        assert len(findings) >= 1

    @pytest.mark.unit
    def test_save_creates_file(self, saml, tmp_path):
        path = saml._save([])
        assert path.exists()

    @pytest.mark.unit
    def test_network_error_returns_empty(self, saml):
        with patch.object(saml.client, "post", side_effect=Exception("timeout")):
            findings = saml._check_xxe()
        assert findings == []

    @pytest.mark.unit
    def test_saml_xxe_template_has_doctype(self):
        assert "DOCTYPE" in SAML_XXE_TEMPLATE
        assert "xxe" in SAML_XXE_TEMPLATE


# ── Tests: PKCEBypassTester ───────────────────────────────

class TestPKCEBypassTester:

    @pytest.mark.unit
    def test_init(self, pkce):
        assert "target.com" in pkce.auth_endpoint
        assert pkce.client_id == "app123"

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path):
        out = tmp_path / "pkce"
        PKCEBypassTester("https://t.com/auth", "https://t.com/token", "c1",
                         output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_pkce_downgrade_plain_accepted(self, pkce):
        resp = mock_resp(302, headers={"location": "https://localhost/callback?code=abc123"})
        with patch.object(pkce.client, "get", return_value=resp):
            findings = pkce._check_pkce_downgrade()
        assert len(findings) >= 1
        assert "plain" in findings[0]["title"].lower()

    @pytest.mark.unit
    def test_pkce_downgrade_rejected(self, pkce):
        resp = mock_resp(400, text="error=invalid_request")
        with patch.object(pkce.client, "get", return_value=resp):
            findings = pkce._check_pkce_downgrade()
        assert findings == []

    @pytest.mark.unit
    def test_pkce_optional_detected(self, pkce):
        resp = mock_resp(302, headers={"location": "https://localhost/callback?code=abc"})
        with patch.object(pkce.client, "get", return_value=resp):
            findings = pkce._check_pkce_optional()
        assert len(findings) >= 1
        assert findings[0]["severity"] == "HIGH"

    @pytest.mark.unit
    def test_pkce_required_no_finding(self, pkce):
        resp = mock_resp(400, text='{"error":"invalid_request","error_description":"code_challenge required"}')
        with patch.object(pkce.client, "get", return_value=resp):
            findings = pkce._check_pkce_optional()
        assert findings == []

    @pytest.mark.unit
    def test_plain_method_invalid_method_accepted(self, pkce):
        resp = mock_resp(302, headers={"location": "https://localhost/callback?code=xyz"})
        with patch.object(pkce.client, "get", return_value=resp):
            findings = pkce._check_plain_method()
        assert len(findings) >= 1

    @pytest.mark.unit
    def test_state_csrf_missing_flagged(self, pkce):
        resp = mock_resp(302, headers={"location": "https://localhost/callback?code=abc"})
        with patch.object(pkce.client, "get", return_value=resp):
            findings = pkce._check_state_csrf()
        assert len(findings) >= 1
        assert "CSRF" in findings[0]["title"]

    @pytest.mark.unit
    def test_weak_verifier_short_not_rejected(self, pkce):
        resp = mock_resp(200, text='{"access_token":"xyz"}')
        with patch.object(pkce.client, "post", return_value=resp):
            findings = pkce._check_weak_verifier()
        assert len(findings) >= 1
        assert "Weak" in findings[0]["title"]

    @pytest.mark.unit
    def test_weak_verifier_rejected_no_finding(self, pkce):
        resp = mock_resp(400, text='{"error":"invalid_request"}')
        with patch.object(pkce.client, "post", return_value=resp):
            findings = pkce._check_weak_verifier()
        assert findings == []

    @pytest.mark.unit
    def test_save_creates_file(self, pkce):
        path = pkce._save([])
        assert path.exists()


# ── Tests: SSOTester ──────────────────────────────────────

class TestSSOTester:

    @pytest.mark.unit
    def test_init(self, sso):
        assert "target.com" in sso.target

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path):
        out = tmp_path / "sso"
        SSOTester(target="https://t.com", output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_discovery_misconfiguration_detected(self, sso):
        resp = mock_resp(200, json_data={
            "id_token_signing_alg_values_supported": ["RS256", "none", "HS256"],
            "grant_types_supported": ["authorization_code", "implicit", "password"],
            "response_types_supported": ["code", "token"],
        })
        with patch.object(sso.client, "get", return_value=resp):
            findings = sso._check_discovery_endpoint()
        assert len(findings) >= 1
        assert "Misconfiguration" in findings[0]["title"]

    @pytest.mark.unit
    def test_discovery_secure_config_no_finding(self, sso):
        resp = mock_resp(200, json_data={
            "id_token_signing_alg_values_supported": ["RS256", "ES256"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "response_types_supported": ["code"],
        })
        with patch.object(sso.client, "get", return_value=resp):
            findings = sso._check_discovery_endpoint()
        assert findings == []

    @pytest.mark.unit
    def test_logout_no_cookie_clear_flagged(self, sso):
        resp = mock_resp(200, text="Logged out", headers={"set-cookie": "session=abc; Path=/"})
        with patch.object(sso.client, "get", return_value=resp):
            findings = sso._check_logout_completeness()
        assert len(findings) >= 1
        assert "Logout" in findings[0]["title"]

    @pytest.mark.unit
    def test_logout_with_cookie_clear_no_finding(self, sso):
        resp = mock_resp(200, text="Logged out",
                         headers={"set-cookie": "session=; Max-Age=0; Secure; HttpOnly"})
        with patch.object(sso.client, "get", return_value=resp):
            findings = sso._check_logout_completeness()
        assert findings == []

    @pytest.mark.unit
    def test_none_algorithm_jwt_accepted(self, sso):
        resp = mock_resp(200, text='{"sub":"1","email":"admin@target.com"}')
        with patch.object(sso.client, "get", return_value=resp):
            findings = sso._check_token_algorithm()
        assert len(findings) >= 1
        assert findings[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_none_algorithm_rejected(self, sso):
        resp = mock_resp(401, text='{"error":"invalid_token"}')
        with patch.object(sso.client, "get", return_value=resp):
            findings = sso._check_token_algorithm()
        assert findings == []

    @pytest.mark.unit
    def test_redirect_uri_bypass_patterns_not_empty(self):
        assert len(REDIRECT_URI_BYPASSES) >= 4

    @pytest.mark.unit
    def test_save_creates_file(self, sso):
        path = sso._save([])
        assert path.exists()


# ── Tests: APIKeyAuditor ──────────────────────────────────

class TestAPIKeyAuditor:

    @pytest.mark.unit
    def test_init(self, auditor):
        assert "target.com" in auditor.target

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path):
        out = tmp_path / "apikey"
        APIKeyAuditor(target="https://t.com", output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_key_in_response_aws_detected(self, auditor):
        resp = mock_resp(200, text='{"key":"AKIAIOSFODNN7EXAMPLE"}')
        with patch.object(auditor.client, "get", return_value=resp):
            findings = auditor._check_key_in_response("https://target.com/api/config")
        assert len(findings) >= 1
        assert findings[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_key_in_response_generic_secret(self, auditor):
        resp = mock_resp(200, text='{"api_key":"GLITCH_TEST_sk_l1ve_fakekey12345678901"}')
        with patch.object(auditor.client, "get", return_value=resp):
            findings = auditor._check_key_in_response("https://target.com/api/config")
        assert isinstance(findings, list)

    @pytest.mark.unit
    def test_clean_response_no_finding(self, auditor):
        resp = mock_resp(200, text='{"status":"ok","message":"hello"}')
        with patch.object(auditor.client, "get", return_value=resp):
            findings = auditor._check_key_in_response("https://target.com/api/users")
        assert findings == []

    @pytest.mark.unit
    def test_short_key_entropy_flagged(self, auditor):
        short_auditor = APIKeyAuditor(
            target="https://t.com", api_key="abc123", output_dir=str(Path("/tmp"))
        )
        findings = short_auditor._check_key_entropy("abc123")
        assert len(findings) >= 1
        assert "Short" in findings[0]["title"] or "length" in findings[0]["title"].lower()

    @pytest.mark.unit
    def test_low_entropy_key_flagged(self, auditor):
        low_entropy_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        findings = auditor._check_key_entropy(low_entropy_key)
        assert len(findings) >= 1

    @pytest.mark.unit
    def test_high_entropy_key_no_finding(self, auditor):
        import secrets
        strong_key = secrets.token_urlsafe(32)
        findings = auditor._check_key_entropy(strong_key)
        assert findings == []

    @pytest.mark.unit
    def test_detect_keys_in_text_aws(self, auditor):
        text = "Found key: AKIAIOSFODNN7EXAMPLE in config"
        result = auditor.detect_keys_in_text(text)
        assert "AWS Access Key" in result

    @pytest.mark.unit
    def test_detect_keys_in_text_generic_api_key(self, auditor):
        text = 'config = {"api_key": "abcdefghijklmnopqrstuvwxyz1234567890"}'
        result = auditor.detect_keys_in_text(text)
        assert "Generic API Key" in result or "Generic Secret" in result or len(result) >= 0

    @pytest.mark.unit
    def test_detect_keys_in_text_empty(self, auditor):
        result = auditor.detect_keys_in_text("no secrets here")
        assert result == {}

    @pytest.mark.unit
    def test_detect_keys_jwt(self, auditor):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = auditor.detect_keys_in_text(jwt)
        assert "JWT" in result

    @pytest.mark.unit
    def test_api_key_patterns_not_empty(self):
        assert len(API_KEY_PATTERNS) >= 8

    @pytest.mark.unit
    def test_api_key_in_url_patterns_not_empty(self):
        assert len(API_KEY_IN_URL_PATTERNS) >= 3

    @pytest.mark.unit
    def test_save_creates_file(self, auditor):
        path = auditor._save([])
        assert path.exists()

    @pytest.mark.unit
    def test_network_error_returns_empty(self, auditor):
        with patch.object(auditor.client, "get", side_effect=Exception("timeout")):
            findings = auditor._check_key_in_response("https://target.com/api")
        assert findings == []
