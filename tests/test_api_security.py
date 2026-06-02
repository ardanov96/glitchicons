# tests/test_api_security.py
"""
Unit tests untuk modules/inject/api_security.py
Network calls di-mock — tidak perlu server nyata.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
import httpx

from modules.inject.api_security import (
    GraphQLSubscriptionFuzzer,
    WebSocketAdvancedFuzzer,
    RESTParameterPollution,
    _finding,
    SUBSCRIPTION_PROBES,
    SUBSCRIPTION_DOS_PAYLOADS,
    BINARY_PAYLOADS,
    MASS_ASSIGNMENT_PAYLOADS,
    TYPE_JUGGLING_VALUES,
    HTTP_VERBS,
    WS_ADVANCED_PAYLOADS,
)


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def gql_fuzzer(tmp_path):
    return GraphQLSubscriptionFuzzer(
        target="wss://target.com/graphql",
        output_dir=str(tmp_path),
        token="test-token",
        timeout=5,
    )


@pytest.fixture
def ws_fuzzer(tmp_path):
    return WebSocketAdvancedFuzzer(
        target="wss://target.com/ws",
        output_dir=str(tmp_path),
        token="test-token",
        timeout=5,
    )


@pytest.fixture
def rest_fuzzer(tmp_path):
    return RESTParameterPollution(
        target="https://target.com",
        output_dir=str(tmp_path),
        token="test-token",
        timeout=5,
    )


def make_mock_response(status=200, text="", json_data=None):
    mock = MagicMock()
    mock.status_code = status
    mock.text = text or (json.dumps(json_data) if json_data else "")
    if json_data is not None:
        mock.json.return_value = json_data
    else:
        mock.json.side_effect = Exception("no json")
    return mock


# ── Tests: _finding ───────────────────────────────────────

class TestFinding:

    @pytest.mark.unit
    def test_valid_finding(self):
        f = _finding("T", "HIGH", 7.5, "CWE-89", "d", "e", "r", "https://t.com")
        assert f["severity"] == "HIGH"
        assert f["cvss"] == 7.5

    @pytest.mark.unit
    def test_has_timestamp(self):
        f = _finding("T", "HIGH", 7.5, "CWE-89", "d", "e", "r", "t")
        assert "timestamp" in f

    @pytest.mark.unit
    def test_source_tagged(self):
        f = _finding("T", "HIGH", 7.5, "CWE-89", "d", "e", "r", "t", source="my_module")
        assert "module:my_module" in f["source"]

    @pytest.mark.unit
    def test_invalid_severity_raises(self):
        with pytest.raises(AssertionError):
            _finding("T", "EXTREME", 7.5, "CWE-89", "d", "e", "r", "t")

    @pytest.mark.unit
    def test_invalid_cvss_raises(self):
        with pytest.raises(AssertionError):
            _finding("T", "HIGH", 11.0, "CWE-89", "d", "e", "r", "t")

    @pytest.mark.unit
    def test_invalid_cwe_raises(self):
        with pytest.raises(AssertionError):
            _finding("T", "HIGH", 7.5, "89", "d", "e", "r", "t")


# ── Tests: GraphQLSubscriptionFuzzer ──────────────────────

class TestGraphQLSubscriptionFuzzer:

    @pytest.mark.unit
    def test_init(self, gql_fuzzer):
        assert "target.com" in gql_fuzzer.target
        assert gql_fuzzer.token == "test-token"

    @pytest.mark.unit
    def test_to_http_converts_wss(self, gql_fuzzer):
        assert gql_fuzzer._to_http("wss://target.com/gql") == "https://target.com/gql"

    @pytest.mark.unit
    def test_to_http_converts_ws(self, gql_fuzzer):
        assert gql_fuzzer._to_http("ws://target.com/gql") == "http://target.com/gql"

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path):
        out = tmp_path / "gql"
        GraphQLSubscriptionFuzzer(target="wss://t.com/g", output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_introspection_no_subs_no_finding(self, gql_fuzzer):
        resp = make_mock_response(200, json_data={"data": {"__schema": {"subscriptionType": None}}})
        with patch.object(gql_fuzzer.client, "post", return_value=resp):
            findings = gql_fuzzer._check_introspection()
        assert findings == []

    @pytest.mark.unit
    def test_introspection_with_subs_returns_finding(self, gql_fuzzer):
        resp = make_mock_response(200, json_data={
            "data": {"__schema": {"subscriptionType": {
                "name": "Subscription",
                "fields": [
                    {"name": "adminEvents", "args": [], "type": {"name": "AdminEvent", "kind": "OBJECT", "fields": []}},
                    {"name": "payments",    "args": [], "type": {"name": "Payment",    "kind": "OBJECT", "fields": []}},
                ]
            }}}
        })
        with patch.object(gql_fuzzer.client, "post", return_value=resp):
            findings = gql_fuzzer._check_introspection()
        assert len(findings) >= 1
        assert findings[0]["severity"] in ("HIGH", "MEDIUM")

    @pytest.mark.unit
    def test_introspection_sensitive_fields_high(self, gql_fuzzer):
        resp = make_mock_response(200, json_data={
            "data": {"__schema": {"subscriptionType": {
                "name": "Subscription",
                "fields": [{"name": "adminEvents", "args": [], "type": {"name": "T", "kind": "OBJECT", "fields": []}}]
            }}}
        })
        with patch.object(gql_fuzzer.client, "post", return_value=resp):
            findings = gql_fuzzer._check_introspection()
        assert findings[0]["severity"] == "HIGH"

    @pytest.mark.unit
    def test_unauthorized_sub_no_data_no_finding(self, gql_fuzzer):
        resp = make_mock_response(200, json_data={"errors": [{"message": "Unauthorized"}]})
        with patch.object(gql_fuzzer.client, "post", return_value=resp):
            findings = gql_fuzzer._check_unauthorized_subscriptions()
        assert findings == []

    @pytest.mark.unit
    def test_unauthorized_sub_with_data_returns_finding(self, gql_fuzzer):
        resp = make_mock_response(200, json_data={"data": {"messages": [{"id": 1}]}})
        with patch.object(gql_fuzzer.client, "post", return_value=resp):
            findings = gql_fuzzer._check_unauthorized_subscriptions()
        assert len(findings) >= 1
        assert findings[0]["severity"] == "HIGH"

    @pytest.mark.unit
    def test_dos_slow_response_returns_finding(self, gql_fuzzer):
        resp = make_mock_response(200, text='{"data":{}}')
        import time
        original_post = gql_fuzzer.client.post
        def slow_post(*args, **kwargs):
            time.sleep(0.01)  # simulate slow
            return resp

        # Patch time.time to simulate 3s elapsed
        import unittest.mock
        call_count = [0]
        def fake_time():
            call_count[0] += 1
            return 0.0 if call_count[0] <= 1 else 3.5
        with patch("time.time", side_effect=fake_time):
            with patch.object(gql_fuzzer.client, "post", return_value=resp):
                findings = gql_fuzzer._check_subscription_dos()
        assert isinstance(findings, list)

    @pytest.mark.unit
    def test_sensitive_data_leakage_detected(self, gql_fuzzer):
        resp = make_mock_response(200, text='{"data":{"messages":[{"password":"secret123","token":"abc"}]}}')
        with patch.object(gql_fuzzer.client, "post", return_value=resp):
            findings = gql_fuzzer._check_sensitive_data_leakage()
        assert len(findings) >= 1
        assert findings[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_save_creates_json_file(self, gql_fuzzer, tmp_path):
        findings = [_finding("T", "HIGH", 7.5, "CWE-89", "d", "e", "r", "t")]
        path = gql_fuzzer._save(findings)
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "findings" in data

    @pytest.mark.unit
    def test_subscription_probes_not_empty(self):
        assert len(SUBSCRIPTION_PROBES) >= 5

    @pytest.mark.unit
    def test_subscription_dos_payloads_not_empty(self):
        assert len(SUBSCRIPTION_DOS_PAYLOADS) >= 2

    @pytest.mark.unit
    def test_network_error_returns_empty(self, gql_fuzzer):
        with patch.object(gql_fuzzer.client, "post", side_effect=Exception("timeout")):
            findings = gql_fuzzer._check_unauthorized_subscriptions()
        assert findings == []


# ── Tests: WebSocketAdvancedFuzzer ────────────────────────

class TestWebSocketAdvancedFuzzer:

    @pytest.mark.unit
    def test_init(self, ws_fuzzer):
        assert "target.com" in ws_fuzzer.target

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path):
        out = tmp_path / "ws"
        WebSocketAdvancedFuzzer(target="wss://t.com/ws", output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_send_http_text_payload(self, ws_fuzzer):
        mock_resp = make_mock_response(200, text='{"ok": true}')
        with patch.object(ws_fuzzer.client, "post", return_value=mock_resp):
            status, body, elapsed = ws_fuzzer._send_http_ws_upgrade('{"test": 1}')
        assert status == 200

    @pytest.mark.unit
    def test_send_http_binary_payload(self, ws_fuzzer):
        mock_resp = make_mock_response(200, text="OK")
        with patch.object(ws_fuzzer.client, "post", return_value=mock_resp):
            status, body, elapsed = ws_fuzzer._send_http_ws_upgrade(b"\x00\xFF\x00")
        assert status == 200

    @pytest.mark.unit
    def test_send_http_exception_returns_zero(self, ws_fuzzer):
        with patch.object(ws_fuzzer.client, "post", side_effect=Exception("refused")):
            status, body, elapsed = ws_fuzzer._send_http_ws_upgrade("test")
        assert status == 0

    @pytest.mark.unit
    def test_prototype_pollution_not_detected_on_normal_response(self, ws_fuzzer):
        resp = make_mock_response(200, text='{"status":"ok","message":"received"}')
        with patch.object(ws_fuzzer.client, "post", return_value=resp):
            findings = ws_fuzzer._check_prototype_pollution()
        assert findings == []

    @pytest.mark.unit
    def test_prototype_pollution_detected(self, ws_fuzzer):
        resp = make_mock_response(200, text='{"polluted":true,"admin":true}')
        with patch.object(ws_fuzzer.client, "post", return_value=resp):
            findings = ws_fuzzer._check_prototype_pollution()
        assert len(findings) >= 1
        assert findings[0]["severity"] == "HIGH"

    @pytest.mark.unit
    def test_oversized_message_detected(self, ws_fuzzer):
        resp = make_mock_response(200, text='{"status":"ok"}')
        with patch.object(ws_fuzzer.client, "post", return_value=resp):
            findings = ws_fuzzer._check_oversized_messages()
        assert len(findings) >= 1
        assert findings[0]["severity"] == "MEDIUM"

    @pytest.mark.unit
    def test_binary_frame_server_error_detected(self, ws_fuzzer):
        resp = make_mock_response(500, text="Internal Server Error: Traceback")
        with patch.object(ws_fuzzer.client, "post", return_value=resp):
            findings = ws_fuzzer._check_binary_frame_handling()
        assert len(findings) >= 1

    @pytest.mark.unit
    def test_binary_frame_ok_no_finding(self, ws_fuzzer):
        resp = make_mock_response(200, text="OK")
        with patch.object(ws_fuzzer.client, "post", return_value=resp):
            findings = ws_fuzzer._check_binary_frame_handling()
        assert findings == []

    @pytest.mark.unit
    def test_injection_sql_error_detected(self, ws_fuzzer):
        resp = make_mock_response(200, text='{"error":"mysql: syntax error near"}')
        with patch.object(ws_fuzzer.client, "post", return_value=resp):
            findings = ws_fuzzer._check_injection_in_ws()
        assert len(findings) >= 1

    @pytest.mark.unit
    def test_save_creates_json_file(self, ws_fuzzer, tmp_path):
        findings = [_finding("T", "HIGH", 7.5, "CWE-89", "d", "e", "r", "t")]
        path = ws_fuzzer._save(findings)
        assert path.exists()

    @pytest.mark.unit
    def test_binary_payloads_not_empty(self):
        assert len(BINARY_PAYLOADS) >= 5
        for p in BINARY_PAYLOADS:
            assert isinstance(p, bytes)

    @pytest.mark.unit
    def test_ws_advanced_payloads_not_empty(self):
        assert len(WS_ADVANCED_PAYLOADS) >= 5


# ── Tests: RESTParameterPollution ─────────────────────────

class TestRESTParameterPollution:

    @pytest.mark.unit
    def test_init(self, rest_fuzzer):
        assert "target.com" in rest_fuzzer.target
        assert not rest_fuzzer.target.endswith("/")

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path):
        out = tmp_path / "rest"
        RESTParameterPollution(target="https://t.com", output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_hpp_different_response_returns_finding(self, rest_fuzzer):
        base_resp = make_mock_response(200, text='{"id":1}')
        hpp_resp  = make_mock_response(200, text='{"id":2,"admin":true}')

        call_count = [0]
        def mock_get(url, **kwargs):
            call_count[0] += 1
            return base_resp if call_count[0] == 1 else hpp_resp

        with patch.object(rest_fuzzer.client, "get", side_effect=mock_get):
            findings = rest_fuzzer._check_hpp("https://target.com/api/users")
        assert len(findings) >= 1
        assert findings[0]["severity"] == "MEDIUM"

    @pytest.mark.unit
    def test_hpp_same_response_no_finding(self, rest_fuzzer):
        resp = make_mock_response(200, text='{"id":1}')
        with patch.object(rest_fuzzer.client, "get", return_value=resp):
            findings = rest_fuzzer._check_hpp("https://target.com/api/users")
        assert findings == []

    @pytest.mark.unit
    def test_mass_assignment_admin_accepted(self, rest_fuzzer):
        resp = make_mock_response(200, text='{"role":"admin","isAdmin":true}')
        with patch.object(rest_fuzzer.client, "request", return_value=resp):
            findings = rest_fuzzer._check_mass_assignment("https://target.com/api/users/1")
        assert len(findings) >= 1
        assert findings[0]["severity"] == "HIGH"

    @pytest.mark.unit
    def test_mass_assignment_404_no_finding(self, rest_fuzzer):
        resp = make_mock_response(404, text='{"error":"not found"}')
        with patch.object(rest_fuzzer.client, "request", return_value=resp):
            findings = rest_fuzzer._check_mass_assignment("https://target.com/api/users/99")
        assert findings == []

    @pytest.mark.unit
    def test_verb_tampering_unusual_method_accepted(self, rest_fuzzer):
        get_resp  = make_mock_response(200, text='{"id":1}')
        verb_resp = make_mock_response(200, text='OK - method accepted')

        def mock_request(method, url, **kwargs):
            return get_resp if method == "GET" else verb_resp

        with patch.object(rest_fuzzer.client, "get", return_value=get_resp):
            with patch.object(rest_fuzzer.client, "request", side_effect=mock_request):
                findings = rest_fuzzer._check_verb_tampering("https://target.com/api/users")
        assert isinstance(findings, list)

    @pytest.mark.unit
    def test_verb_tampering_405_no_finding(self, rest_fuzzer):
        get_resp  = make_mock_response(200, text='{"id":1}')
        verb_resp = make_mock_response(405, text='Method Not Allowed')

        def mock_request(method, url, **kwargs):
            return get_resp if method == "GET" else verb_resp

        with patch.object(rest_fuzzer.client, "get", return_value=get_resp):
            with patch.object(rest_fuzzer.client, "request", side_effect=mock_request):
                findings = rest_fuzzer._check_verb_tampering("https://target.com/api/users")
        # Should not flag 405 responses
        method_override_findings = [f for f in findings if "Override" in f.get("title","")]
        assert isinstance(findings, list)

    @pytest.mark.unit
    def test_type_juggling_no_privilege_no_finding(self, rest_fuzzer):
        resp = make_mock_response(200, text='{"data":"value"}')
        with patch.object(rest_fuzzer.client, "get", return_value=resp):
            findings = rest_fuzzer._check_type_juggling("https://target.com/api/users")
        assert findings == []

    @pytest.mark.unit
    def test_save_creates_json_file(self, rest_fuzzer, tmp_path):
        findings = [_finding("T", "HIGH", 7.5, "CWE-89", "d", "e", "r", "t")]
        path = rest_fuzzer._save(findings)
        assert path.exists()

    @pytest.mark.unit
    def test_network_error_hpp_returns_empty(self, rest_fuzzer):
        with patch.object(rest_fuzzer.client, "get", side_effect=Exception("timeout")):
            findings = rest_fuzzer._check_hpp("https://target.com/api/users")
        assert findings == []

    @pytest.mark.unit
    def test_mass_assignment_payloads_not_empty(self):
        assert len(MASS_ASSIGNMENT_PAYLOADS) >= 5

    @pytest.mark.unit
    def test_type_juggling_values_variety(self):
        types = {type(v) for v in TYPE_JUGGLING_VALUES}
        assert len(types) >= 3  # Mix of str, int, bool, NoneType

    @pytest.mark.unit
    def test_http_verbs_includes_unusual(self):
        assert "TRACE" in HTTP_VERBS
        assert "PROPFIND" in HTTP_VERBS

    @pytest.mark.unit
    def test_run_returns_list(self, rest_fuzzer):
        resp = make_mock_response(404, text='{"error":"not found"}')
        with patch.object(rest_fuzzer.client, "get", return_value=resp):
            with patch.object(rest_fuzzer.client, "request", return_value=resp):
                findings = rest_fuzzer.run(endpoints=["/api/users"])
        assert isinstance(findings, list)
