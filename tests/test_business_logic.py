# tests/test_business_logic.py
"""
Unit tests untuk modules/business/business_logic.py
Network calls di-mock — tidak butuh real server.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from modules.business.business_logic import (
    PriceManipulationTester, AccountTakeoverChain,
    PrivilegeEscalationMapper, WorkflowBypassTester,
    PriceTestResult, ATOChainResult,
    _finding,
    PRICE_PAYLOADS, QUANTITY_PAYLOADS, DISCOUNT_PAYLOADS,
    ROLE_ESCALATION_PAYLOADS, PRIVILEGED_ENDPOINTS,
)


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def price_tester(tmp_path):
    return PriceManipulationTester(
        target="https://shop.target.com",
        output_dir=str(tmp_path), timeout=5,
    )


@pytest.fixture
def ato_tester(tmp_path):
    return AccountTakeoverChain(
        target="https://target.com",
        output_dir=str(tmp_path), timeout=5,
    )


@pytest.fixture
def priv_mapper(tmp_path):
    return PrivilegeEscalationMapper(
        target="https://api.target.com",
        output_dir=str(tmp_path),
        token="user_token_123", timeout=5,
    )


@pytest.fixture
def workflow(tmp_path):
    return WorkflowBypassTester(
        target="https://target.com",
        output_dir=str(tmp_path), timeout=5,
    )


def mock_resp(status=200, text="", json_data=None, cookies=None):
    m = MagicMock()
    m.status_code = status
    m.text = text or (json.dumps(json_data) if json_data else "")
    m.cookies = cookies or {}
    if json_data is not None:
        m.json.return_value = json_data
    else:
        m.json.side_effect = Exception("no json")
    return m


# ── Tests: _finding ───────────────────────────────────────

class TestFinding:

    @pytest.mark.unit
    def test_valid_finding(self):
        f = _finding("T", "HIGH", 7.5, "CWE-840", "d", "e", "r", "t")
        assert f["severity"] == "HIGH"

    @pytest.mark.unit
    def test_invalid_severity(self):
        with pytest.raises(AssertionError):
            _finding("T", "EXTREME", 7.5, "CWE-840", "d", "e", "r", "t")

    @pytest.mark.unit
    def test_source_tagged(self):
        f = _finding("T", "HIGH", 7.5, "CWE-840", "d", "e", "r", "t", source="price")
        assert "module:price" in f["source"]


# ── Tests: PriceManipulationTester ───────────────────────

class TestPriceManipulationTester:

    @pytest.mark.unit
    def test_init(self, price_tester):
        assert "shop.target.com" in price_tester.target

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path):
        out = tmp_path / "biz"
        PriceManipulationTester(target="https://t.com", output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_negative_price_detected(self, price_tester):
        resp = mock_resp(201, json_data={"order_id": "123", "success": True})
        with patch.object(price_tester.client, "post", return_value=resp):
            findings = price_tester._test_negative_price("/api/cart")
        assert len(findings) >= 1
        assert findings[0]["severity"] == "CRITICAL"
        assert "Negative" in findings[0]["title"]

    @pytest.mark.unit
    def test_negative_price_rejected(self, price_tester):
        resp = mock_resp(400, text='{"error": "Invalid price"}')
        with patch.object(price_tester.client, "post", return_value=resp):
            findings = price_tester._test_negative_price("/api/cart")
        assert findings == []

    @pytest.mark.unit
    def test_zero_price_detected(self, price_tester):
        resp = mock_resp(200, json_data={"success": True, "total": 0})
        with patch.object(price_tester.client, "post", return_value=resp):
            findings = price_tester._test_zero_price("/api/cart")
        assert len(findings) >= 1
        assert findings[0]["severity"] == "HIGH"

    @pytest.mark.unit
    def test_negative_quantity_detected(self, price_tester):
        resp = mock_resp(200, json_data={"success": True})
        with patch.object(price_tester.client, "post", return_value=resp):
            findings = price_tester._test_quantity_manipulation("/api/cart")
        assert len(findings) >= 1

    @pytest.mark.unit
    def test_discount_overflow_detected(self, price_tester):
        resp = mock_resp(200, json_data={"discount_applied": 101, "total": -1})
        with patch.object(price_tester.client, "post", return_value=resp):
            findings = price_tester._test_discount_overflow("/api/cart")
        assert len(findings) >= 1
        assert "Overflow" in findings[0]["title"]

    @pytest.mark.unit
    def test_price_tamper_detected(self, price_tester):
        resp = mock_resp(201, json_data={"total": 0.01, "order_id": "ORD-123"})
        with patch.object(price_tester.client, "post", return_value=resp):
            findings = price_tester._test_price_parameter_tamper("/api/orders")
        assert len(findings) >= 1
        assert findings[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_currency_manipulation_idr(self, price_tester):
        resp = mock_resp(200, json_data={"currency": "IDR", "success": True})
        with patch.object(price_tester.client, "post", return_value=resp):
            findings = price_tester._test_currency_manipulation("/api/cart")
        assert len(findings) >= 1
        assert "IDR" in findings[0]["title"] or "Currency" in findings[0]["title"]

    @pytest.mark.unit
    def test_is_price_suspicious_negative(self, price_tester):
        assert price_tester._is_price_suspicious(-1, 200, '{"ok":true}', "") is True

    @pytest.mark.unit
    def test_is_price_suspicious_zero(self, price_tester):
        assert price_tester._is_price_suspicious(0, 200, '{"ok":true}', "") is True

    @pytest.mark.unit
    def test_is_price_suspicious_non200(self, price_tester):
        assert price_tester._is_price_suspicious(-1, 400, '{"error":"bad"}', "") is False

    @pytest.mark.unit
    def test_try_json_valid(self, price_tester):
        result = price_tester._try_json('{"key": "value"}')
        assert result == {"key": "value"}

    @pytest.mark.unit
    def test_try_json_invalid(self, price_tester):
        result = price_tester._try_json("not json")
        assert result is None

    @pytest.mark.unit
    def test_save_creates_file(self, price_tester, tmp_path):
        path = price_tester._save([])
        assert path.exists()

    @pytest.mark.unit
    def test_price_payloads_include_negative(self):
        assert any(isinstance(p, (int, float)) and p < 0 for p in PRICE_PAYLOADS)

    @pytest.mark.unit
    def test_price_payloads_include_zero(self):
        assert 0 in PRICE_PAYLOADS or 0.0 in PRICE_PAYLOADS

    @pytest.mark.unit
    def test_quantity_payloads_include_negative(self):
        assert any(q < 0 for q in QUANTITY_PAYLOADS)

    @pytest.mark.unit
    def test_discount_payloads_include_overflow(self):
        assert any(d > 100 for d in DISCOUNT_PAYLOADS)


# ── Tests: AccountTakeoverChain ───────────────────────────

class TestAccountTakeoverChain:

    @pytest.mark.unit
    def test_init(self, ato_tester):
        assert "target.com" in ato_tester.target

    @pytest.mark.unit
    def test_host_header_injection_detected(self, ato_tester):
        resp = mock_resp(200, json_data={"message": "Reset email sent"})
        with patch.object(ato_tester.client, "post", return_value=resp):
            findings = ato_tester._check_host_header_injection("test@test.com")
        assert len(findings) >= 1
        assert "Host Header" in findings[0]["title"]
        assert findings[0]["severity"] == "HIGH"

    @pytest.mark.unit
    def test_host_header_injection_rejected(self, ato_tester):
        resp = mock_resp(404, text="Not Found")
        with patch.object(ato_tester.client, "post", return_value=resp):
            findings = ato_tester._check_host_header_injection("test@test.com")
        assert findings == []

    @pytest.mark.unit
    def test_weak_reset_token_detected(self, ato_tester):
        resp = mock_resp(200, json_data={"success": True, "message": "Password changed"})
        with patch.object(ato_tester.client, "post", return_value=resp):
            findings = ato_tester._check_password_reset_no_expiry()
        assert len(findings) >= 1
        assert "Weak" in findings[0]["title"]
        assert findings[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_email_change_no_verify_detected(self, ato_tester):
        resp = mock_resp(200, json_data={"email": "attacker@evil.com", "success": True})
        with patch.object(ato_tester.client, "put", return_value=resp):
            findings = ato_tester._check_email_change_no_verify()
        assert len(findings) >= 1
        assert "Email Change" in findings[0]["title"]

    @pytest.mark.unit
    def test_email_change_rejected(self, ato_tester):
        resp = mock_resp(401, text='{"error": "Unauthorized"}')
        with patch.object(ato_tester.client, "put", return_value=resp):
            findings = ato_tester._check_email_change_no_verify()
        assert findings == []

    @pytest.mark.unit
    def test_oauth_merge_detected(self, ato_tester):
        resp = mock_resp(200, json_data={"linked": True, "provider": "google"})
        with patch.object(ato_tester.client, "post", return_value=resp):
            findings = ato_tester._check_oauth_account_merge()
        assert len(findings) >= 1
        assert "OAuth" in findings[0]["title"]

    @pytest.mark.unit
    def test_concurrent_session_flagged(self, ato_tester):
        resp = mock_resp(200, json_data={"success": True})
        with patch.object(ato_tester.client, "put", return_value=resp):
            findings = ato_tester._check_concurrent_session()
        assert len(findings) >= 1
        assert "Session" in findings[0]["title"]

    @pytest.mark.unit
    def test_common_prefix_detection(self, ato_tester):
        tokens = ["abcdef123456", "abcdef789012", "abcdefXXXXXX"]
        prefix = ato_tester._common_prefix(tokens)
        assert prefix == "abcdef"

    @pytest.mark.unit
    def test_common_prefix_empty(self, ato_tester):
        prefix = ato_tester._common_prefix([])
        assert prefix == ""

    @pytest.mark.unit
    def test_extract_remember_token(self, ato_tester):
        body = '{"remember_me": "abc123def456ghi789"}'
        token = ato_tester._extract_remember_token(body)
        assert token == "abc123def456ghi789"

    @pytest.mark.unit
    def test_save_creates_file(self, ato_tester, tmp_path):
        path = ato_tester._save([])
        assert path.exists()


# ── Tests: PrivilegeEscalationMapper ─────────────────────

class TestPrivilegeEscalationMapper:

    @pytest.mark.unit
    def test_init(self, priv_mapper):
        assert "api.target.com" in priv_mapper.target

    @pytest.mark.unit
    def test_admin_endpoint_accessible(self, priv_mapper):
        resp = mock_resp(200, json_data={"users": [{"id": 1, "role": "admin"}]})
        with patch.object(priv_mapper.client, "request", return_value=resp):
            findings = priv_mapper._check_admin_endpoints()
        assert len(findings) >= 1
        assert findings[0]["severity"] == "CRITICAL"
        assert "Admin" in findings[0]["title"]

    @pytest.mark.unit
    def test_admin_endpoint_blocked(self, priv_mapper):
        resp = mock_resp(403, text='{"error": "Forbidden"}')
        with patch.object(priv_mapper.client, "request", return_value=resp):
            findings = priv_mapper._check_admin_endpoints()
        assert findings == []

    @pytest.mark.unit
    def test_role_escalation_detected(self, priv_mapper):
        resp = mock_resp(200, json_data={"role": "admin", "is_admin": True})
        with patch.object(priv_mapper.client, "patch", return_value=resp):
            findings = priv_mapper._check_role_escalation()
        assert len(findings) >= 1
        assert findings[0]["severity"] == "CRITICAL"
        assert "Role" in findings[0]["title"]

    @pytest.mark.unit
    def test_role_escalation_rejected(self, priv_mapper):
        resp = mock_resp(403, text='{"error": "Cannot change role"}')
        with patch.object(priv_mapper.client, "patch", return_value=resp):
            findings = priv_mapper._check_role_escalation()
        assert findings == []

    @pytest.mark.unit
    def test_idor_horizontal_detected(self, priv_mapper):
        resp = mock_resp(200, json_data={
            "id": 2, "email": "victim@target.com", "name": "Victim User"
        })
        with patch.object(priv_mapper.client, "get", return_value=resp):
            findings = priv_mapper._check_idor_horizontal()
        assert len(findings) >= 1
        assert "IDOR" in findings[0]["title"]

    @pytest.mark.unit
    def test_idor_blocked(self, priv_mapper):
        resp = mock_resp(403, text='{"error": "Forbidden"}')
        with patch.object(priv_mapper.client, "get", return_value=resp):
            findings = priv_mapper._check_idor_horizontal()
        assert findings == []

    @pytest.mark.unit
    def test_looks_like_user_data_true(self, priv_mapper):
        assert priv_mapper._looks_like_user_data({"email": "t@t.com", "id": 1}) is True

    @pytest.mark.unit
    def test_looks_like_user_data_false(self, priv_mapper):
        assert priv_mapper._looks_like_user_data({"status": "ok"}) is False

    @pytest.mark.unit
    def test_privileged_endpoints_not_empty(self):
        assert len(PRIVILEGED_ENDPOINTS) >= 10
        assert any("/admin" in ep[0] for ep in PRIVILEGED_ENDPOINTS)

    @pytest.mark.unit
    def test_role_escalation_payloads_variety(self):
        assert len(ROLE_ESCALATION_PAYLOADS) >= 5
        assert any("admin" in str(p).lower() for p in ROLE_ESCALATION_PAYLOADS)

    @pytest.mark.unit
    def test_save_creates_file(self, priv_mapper, tmp_path):
        path = priv_mapper._save([])
        assert path.exists()


# ── Tests: WorkflowBypassTester ───────────────────────────

class TestWorkflowBypassTester:

    @pytest.mark.unit
    def test_init(self, workflow):
        assert "target.com" in workflow.target

    @pytest.mark.unit
    def test_payment_skip_detected(self, workflow):
        resp = mock_resp(200, json_data={"order_id": "ORD-123", "status": "completed"})
        with patch.object(workflow.client, "post", return_value=resp):
            findings = workflow._check_payment_skip()
        assert len(findings) >= 1
        assert findings[0]["severity"] == "CRITICAL"
        assert "Payment" in findings[0]["title"]

    @pytest.mark.unit
    def test_payment_skip_rejected(self, workflow):
        resp = mock_resp(402, text='{"error": "Payment required"}')
        with patch.object(workflow.client, "post", return_value=resp):
            findings = workflow._check_payment_skip()
        assert findings == []

    @pytest.mark.unit
    def test_email_verify_bypass_detected(self, workflow):
        resp = mock_resp(200, json_data={"verified": True, "message": "Email verified"})
        with patch.object(workflow.client, "post", return_value=resp):
            findings = workflow._check_email_verify_skip()
        assert len(findings) >= 1
        assert "Email Verification" in findings[0]["title"]

    @pytest.mark.unit
    def test_email_verify_rejected(self, workflow):
        resp = mock_resp(400, text='{"error": "Invalid token"}')
        with patch.object(workflow.client, "post", return_value=resp):
            findings = workflow._check_email_verify_skip()
        assert findings == []

    @pytest.mark.unit
    def test_force_browse_detected(self, workflow):
        resp = mock_resp(200, text="<html>" + "Dashboard content " * 50 + "</html>")
        with patch.object(workflow.client, "get", return_value=resp):
            findings = workflow._check_force_browse()
        assert len(findings) >= 1
        assert "Force Browse" in findings[0]["title"]

    @pytest.mark.unit
    def test_force_browse_redirects_to_login(self, workflow):
        resp = mock_resp(200, text="<html>Please login to continue. login page</html>")
        with patch.object(workflow.client, "get", return_value=resp):
            findings = workflow._check_force_browse()
        assert findings == []

    @pytest.mark.unit
    def test_save_creates_file(self, workflow, tmp_path):
        path = workflow._save([])
        assert path.exists()

    @pytest.mark.unit
    def test_run_returns_list(self, workflow):
        resp_404 = mock_resp(404, text="Not Found")
        with patch.object(workflow.client, "post", return_value=resp_404):
            with patch.object(workflow.client, "get", return_value=resp_404):
                findings = workflow.run()
        assert isinstance(findings, list)
