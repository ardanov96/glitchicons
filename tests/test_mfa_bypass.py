# tests/test_mfa_bypass.py
"""
Unit tests untuk modules/auth/mfa_bypass.py
Semua HTTP calls di-mock — tidak butuh server nyata.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from modules.auth.mfa_bypass import (
    MFABypassTester,
    MFATestResult,
    MFARequestBuilder,
    OTPGenerator,
    TYPE_JUGGLING_PAYLOADS,
    REMEMBER_ME_VALUES,
    OTP_FIELD_NAMES,
    SESSION_FIELD_NAMES,
    SUCCESS_INDICATORS,
    ERROR_INDICATORS,
)


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def tester(tmp_path):
    return MFABypassTester(
        target="https://target.example.com/auth/mfa",
        output_dir=str(tmp_path / "mfa"),
        session="sess_abc123",
        timeout=3,
        delay=0,
    )


@pytest.fixture
def authed_tester(tmp_path):
    return MFABypassTester(
        target="https://target.example.com/2fa/verify",
        output_dir=str(tmp_path / "mfa"),
        token="eyJhbGciOiJIUzI1NiJ9.test.sig",
        session="sess_xyz789",
        timeout=3,
        delay=0,
    )


@pytest.fixture
def req_builder():
    return MFARequestBuilder(
        target_url="https://target.example.com/auth/mfa",
        otp_field="otp",
        session_field="session",
        session_value="sess_abc123",
    )


# ── Tests: MFATestResult ──────────────────────────────────

class TestMFATestResult:

    @pytest.mark.unit
    def test_default_not_vulnerable(self):
        r = MFATestResult("common_pins")
        assert r.vulnerable is False
        assert r.attempts == 0

    @pytest.mark.unit
    def test_repr_safe(self):
        r = MFATestResult("type_juggling")
        assert "SAFE" in repr(r)

    @pytest.mark.unit
    def test_repr_vuln(self):
        r = MFATestResult("otp_skip")
        r.vulnerable = True
        assert "VULN" in repr(r)

    @pytest.mark.unit
    def test_test_name_stored(self):
        r = MFATestResult("race_condition")
        assert r.test_name == "race_condition"


# ── Tests: OTPGenerator ───────────────────────────────────

class TestOTPGenerator:

    @pytest.mark.unit
    def test_sequential_generates_correct_range(self):
        otps = OTPGenerator.sequential(0, 9)
        assert len(otps) == 10
        assert otps[0] == "000000"
        assert otps[9] == "000009"

    @pytest.mark.unit
    def test_sequential_zero_padded(self):
        otps = OTPGenerator.sequential(0, 5)
        for otp in otps:
            assert len(otp) == 6

    @pytest.mark.unit
    def test_sequential_max_value(self):
        otps = OTPGenerator.sequential(999999, 999999)
        assert otps[0] == "999999"

    @pytest.mark.unit
    def test_common_pins_not_empty(self):
        pins = OTPGenerator.common_pins()
        assert len(pins) >= 10

    @pytest.mark.unit
    def test_common_pins_includes_repeated(self):
        pins = OTPGenerator.common_pins()
        assert "000000" in pins
        assert "111111" in pins
        assert "999999" in pins

    @pytest.mark.unit
    def test_common_pins_includes_sequential(self):
        pins = OTPGenerator.common_pins()
        assert "123456" in pins
        assert "654321" in pins

    @pytest.mark.unit
    def test_common_pins_no_duplicates(self):
        pins = OTPGenerator.common_pins()
        assert len(pins) == len(set(pins))

    @pytest.mark.unit
    def test_backup_codes_not_empty(self):
        codes = OTPGenerator.backup_codes()
        assert len(codes) >= 5

    @pytest.mark.unit
    def test_backup_codes_include_common(self):
        codes = OTPGenerator.backup_codes()
        assert "00000000" in codes

    @pytest.mark.unit
    def test_expired_range_numeric(self):
        otps = OTPGenerator.expired_range("123456", window=2)
        assert len(otps) == 5  # -2, -1, 0, +1, +2
        assert "123456" in otps

    @pytest.mark.unit
    def test_expired_range_wraps_at_million(self):
        otps = OTPGenerator.expired_range("000001", window=2)
        # 000001 - 2 = -1 should wrap to 999999
        assert "999999" in otps

    @pytest.mark.unit
    def test_expired_range_invalid_otp(self):
        """Non-numeric OTP harus return empty list."""
        otps = OTPGenerator.expired_range("abc123", window=2)
        assert otps == []


# ── Tests: MFARequestBuilder ──────────────────────────────

class TestMFARequestBuilder:

    @pytest.mark.unit
    def test_build_body_includes_otp(self, req_builder):
        body = req_builder.build_body("123456")
        assert body["otp"] == "123456"

    @pytest.mark.unit
    def test_build_body_includes_session(self, req_builder):
        body = req_builder.build_body("123456")
        assert body["session"] == "sess_abc123"

    @pytest.mark.unit
    def test_build_body_no_session_when_empty(self):
        r = MFARequestBuilder("https://t.com/mfa", session_value="")
        body = r.build_body("123456")
        assert "session" not in body

    @pytest.mark.unit
    def test_build_body_extra_fields(self):
        r = MFARequestBuilder("https://t.com/mfa", extra_fields={"device": "mobile"})
        body = r.build_body("123456")
        assert body["device"] == "mobile"

    @pytest.mark.unit
    def test_build_headers_content_type(self, req_builder):
        headers = req_builder.build_headers()
        assert headers["Content-Type"] == "application/json"

    @pytest.mark.unit
    def test_build_headers_with_token(self):
        r = MFARequestBuilder("https://t.com/mfa", token="mytoken")
        headers = r.build_headers()
        assert "Authorization" in headers
        assert "Bearer mytoken" in headers["Authorization"]

    @pytest.mark.unit
    def test_build_headers_no_token_by_default(self, req_builder):
        headers = req_builder.build_headers()
        assert "Authorization" not in headers

    @pytest.mark.unit
    def test_is_success_200_with_token(self, req_builder):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"access_token": "eyJ...", "success": true}'
        assert req_builder.is_success(mock_resp) is True

    @pytest.mark.unit
    def test_is_success_false_for_error(self, req_builder):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = '{"error": "invalid otp"}'
        assert req_builder.is_success(mock_resp) is False

    @pytest.mark.unit
    def test_is_success_200_with_error_body(self, req_builder):
        """200 status tapi body mengandung error = tidak sukses."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"success": false, "error": "invalid code"}'
        assert req_builder.is_success(mock_resp) is False

    @pytest.mark.unit
    def test_is_locked_on_429(self, req_builder):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = '{"error": "rate limited"}'
        assert req_builder.is_locked(mock_resp) is True

    @pytest.mark.unit
    def test_is_locked_by_body(self, req_builder):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Too many attempts. Please try again in 30 minutes."
        assert req_builder.is_locked(mock_resp) is True

    @pytest.mark.unit
    def test_is_locked_false_normal(self, req_builder):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = '{"error": "invalid otp"}'
        assert req_builder.is_locked(mock_resp) is False


# ── Tests: Type Juggling Payloads ─────────────────────────

class TestTypeJugglingPayloads:

    @pytest.mark.unit
    def test_payloads_not_empty(self):
        assert len(TYPE_JUGGLING_PAYLOADS) >= 8

    @pytest.mark.unit
    def test_includes_boolean(self):
        assert True in TYPE_JUGGLING_PAYLOADS
        assert False in TYPE_JUGGLING_PAYLOADS or 0 in TYPE_JUGGLING_PAYLOADS

    @pytest.mark.unit
    def test_includes_null(self):
        assert None in TYPE_JUGGLING_PAYLOADS

    @pytest.mark.unit
    def test_includes_integer(self):
        int_payloads = [p for p in TYPE_JUGGLING_PAYLOADS if isinstance(p, int) and not isinstance(p, bool)]
        assert len(int_payloads) >= 1

    @pytest.mark.unit
    def test_includes_array(self):
        array_payloads = [p for p in TYPE_JUGGLING_PAYLOADS if isinstance(p, list)]
        assert len(array_payloads) >= 1

    @pytest.mark.unit
    def test_includes_empty_string(self):
        assert "" in TYPE_JUGGLING_PAYLOADS or " " in TYPE_JUGGLING_PAYLOADS

    @pytest.mark.unit
    def test_includes_very_long_string(self):
        long = [p for p in TYPE_JUGGLING_PAYLOADS if isinstance(p, str) and len(p) > 20]
        assert len(long) >= 1


# ── Tests: Remember Me Values ─────────────────────────────

class TestRememberMeValues:

    @pytest.mark.unit
    def test_values_not_empty(self):
        assert len(REMEMBER_ME_VALUES) >= 5

    @pytest.mark.unit
    def test_includes_boolean_true(self):
        assert True in REMEMBER_ME_VALUES

    @pytest.mark.unit
    def test_includes_string_true(self):
        assert "true" in REMEMBER_ME_VALUES or "1" in REMEMBER_ME_VALUES

    @pytest.mark.unit
    def test_includes_extended_duration(self):
        """Harus ada nilai yang mencoba extend session lama."""
        extended = [v for v in REMEMBER_ME_VALUES
                    if isinstance(v, (int, str)) and str(v).startswith("365") or v == 999999]
        assert len(extended) >= 1


# ── Tests: Tester Init ────────────────────────────────────

class TestTesterInit:

    @pytest.mark.unit
    def test_target_stored(self, tester):
        assert tester.target == "https://target.example.com/auth/mfa"

    @pytest.mark.unit
    def test_session_stored(self, tester):
        assert tester.session == "sess_abc123"

    @pytest.mark.unit
    def test_token_stored(self, authed_tester):
        assert authed_tester.token is not None

    @pytest.mark.unit
    def test_findings_empty_at_init(self, tester):
        assert tester.findings == []

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path):
        new_dir = tmp_path / "mfa_out"
        MFABypassTester(target="https://t.com/mfa", output_dir=str(new_dir))
        assert new_dir.exists()


# ── Tests: Field Name Constants ───────────────────────────

class TestConstants:

    @pytest.mark.unit
    def test_otp_field_names_not_empty(self):
        assert len(OTP_FIELD_NAMES) >= 5

    @pytest.mark.unit
    def test_common_otp_fields_covered(self):
        assert "otp" in OTP_FIELD_NAMES
        assert "code" in OTP_FIELD_NAMES
        assert "token" in OTP_FIELD_NAMES

    @pytest.mark.unit
    def test_session_field_names_not_empty(self):
        assert len(SESSION_FIELD_NAMES) >= 3

    @pytest.mark.unit
    def test_success_indicators_not_empty(self):
        assert len(SUCCESS_INDICATORS) >= 5

    @pytest.mark.unit
    def test_error_indicators_not_empty(self):
        assert len(ERROR_INDICATORS) >= 3


# ── Tests: Report Generation ──────────────────────────────

class TestReportGeneration:

    @pytest.mark.unit
    def test_save_report_creates_file(self, tester):
        tester.findings = [
            tester._make_finding(
                "No Lockout", "CRITICAL", 9.5, "CWE-307", "d", "e", "r"
            )
        ]
        path = tester._save_report()
        assert path.exists()
        assert path.suffix == ".json"

    @pytest.mark.unit
    def test_report_json_structure(self, tester):
        tester.findings = []
        path = tester._save_report()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["tool"] == "glitchicons"
        assert data["module"] == "mfa_bypass"
        assert data["version"] == "0.8.0"
        assert data["target"] == "https://target.example.com/auth/mfa"

    @pytest.mark.unit
    def test_report_sorted_by_cvss(self, tester):
        tester.findings = [
            tester._make_finding("Low",  "MEDIUM", 5.0, "CWE-1", "d", "e", "r"),
            tester._make_finding("Crit", "CRITICAL", 9.8, "CWE-307", "d", "e", "r"),
            tester._make_finding("High", "HIGH", 8.0, "CWE-287", "d", "e", "r"),
        ]
        path = tester._save_report()
        data = json.loads(path.read_text(encoding="utf-8"))
        scores = [f["cvss"] for f in data["findings"]]
        assert scores == sorted(scores, reverse=True)

    @pytest.mark.unit
    def test_finding_structure(self, tester):
        f = tester._make_finding("T", "HIGH", 7.5, "CWE-307", "d", "e", "r")
        required = {"id", "title", "severity", "cvss", "cwe",
                    "target", "description", "evidence", "remediation", "timestamp"}
        assert required == set(f.keys())

    @pytest.mark.unit
    def test_finding_id_format(self, tester):
        f1 = tester._make_finding("T1", "HIGH", 7.0, "CWE-307", "d", "e", "r")
        tester.findings.append(f1)
        f2 = tester._make_finding("T2", "MEDIUM", 5.0, "CWE-287", "d", "e", "r")
        assert f1["id"] == "MFA-001"
        assert f2["id"] == "MFA-002"
