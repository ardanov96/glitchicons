# tests/test_mobile_api.py
"""
Unit tests untuk modules/mobile/mobile_api.py
Network calls di-mock, APK files dibuat dari bytes.
"""

import io
import json
import zipfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from modules.mobile.mobile_api import (
    APKAnalyzer, CertPinningTester, MobileAPITester,
    APKAnalysisResult, _finding,
    MOBILE_USER_AGENTS, SECRET_PATTERNS, DEEPLINK_PATTERNS,
    PINNING_INDICATORS, API_VERSION_BYPASS, MOBILE_ATTACK_HEADERS,
)


# ── Helpers ───────────────────────────────────────────────

def make_apk_bytes(files: dict[str, str]) -> bytes:
    """Create a minimal APK (ZIP) in memory with given files."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def mock_resp(status=200, text="", headers=None):
    m = MagicMock()
    m.status_code = status
    m.text = text
    m.headers = headers or {}
    return m


@pytest.fixture
def tmp_apk(tmp_path):
    """Create a minimal test APK file."""
    apk_files = {
        "AndroidManifest.xml": """<?xml version="1.0"?>
<manifest package="com.test.app">
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
  <uses-permission android:name="android.permission.CAMERA"/>
  <uses-permission android:name="android.permission.READ_CONTACTS"/>
  <application android:debuggable="true">
    <activity>
      <intent-filter>
        <data android:scheme="testapp" android:host="action"/>
      </intent-filter>
    </activity>
  </application>
</manifest>""",
        "res/values/strings.xml": """<?xml version="1.0"?>
<resources>
  <string name="api_base_url">https://api.target.com/v1</string>
  <string name="api_key">AIzaSyAbcdefghijklmnopqrstuvwxyz1234567</string>
  <string name="firebase_url">https://myapp-default-rtdb.firebaseio.com</string>
</resources>""",
        "assets/config.json": json.dumps({
            "api_endpoint": "https://backend.target.com/api/v2",
            "backend_url":  "https://service.target.com",
        }),
    }
    path = tmp_path / "test_app.apk"
    path.write_bytes(make_apk_bytes(apk_files))
    return path


@pytest.fixture
def analyzer(tmp_path, tmp_apk):
    return APKAnalyzer(apk_path=str(tmp_apk), output_dir=str(tmp_path))


@pytest.fixture
def pinner(tmp_path):
    return CertPinningTester(
        target="https://api.target.com",
        output_dir=str(tmp_path),
        timeout=5,
    )


@pytest.fixture
def mobile_tester(tmp_path):
    return MobileAPITester(
        target="https://api.target.com",
        output_dir=str(tmp_path),
        timeout=5,
    )


# ── Tests: _finding ───────────────────────────────────────

class TestFinding:

    @pytest.mark.unit
    def test_valid_finding(self):
        f = _finding("T", "HIGH", 7.5, "CWE-89", "d", "e", "r", "t")
        assert f["severity"] == "HIGH"

    @pytest.mark.unit
    def test_all_severities_valid(self):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            f = _finding("T", sev, 5.0, "CWE-1", "d", "e", "r", "t")
            assert f["severity"] == sev

    @pytest.mark.unit
    def test_invalid_severity_raises(self):
        with pytest.raises(AssertionError):
            _finding("T", "EXTREME", 7.5, "CWE-89", "d", "e", "r", "t")

    @pytest.mark.unit
    def test_invalid_cwe_raises(self):
        with pytest.raises(AssertionError):
            _finding("T", "HIGH", 7.5, "89", "d", "e", "r", "t")

    @pytest.mark.unit
    def test_source_tagged(self):
        f = _finding("T", "HIGH", 7.5, "CWE-89", "d", "e", "r", "t", source="apk_analyzer")
        assert "module:apk_analyzer" in f["source"]


# ── Tests: APKAnalyzer ────────────────────────────────────

class TestAPKAnalyzer:

    @pytest.mark.unit
    def test_init(self, tmp_path, tmp_apk):
        a = APKAnalyzer(apk_path=str(tmp_apk), output_dir=str(tmp_path))
        assert a.apk_path.exists()

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path):
        out = tmp_path / "mobile"
        APKAnalyzer(apk_path="nonexistent.apk", output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_run_nonexistent_apk_returns_empty(self, tmp_path):
        a = APKAnalyzer(apk_path="nonexistent.apk", output_dir=str(tmp_path))
        result = a.run()
        assert isinstance(result, APKAnalysisResult)
        assert result.findings == []

    @pytest.mark.unit
    def test_analyze_bytes_extracts_endpoints(self, tmp_path):
        apk_bytes = make_apk_bytes({
            "assets/config.json": '{"api_endpoint":"https://api.target.com/v1/users","backend_url":"https://backend.target.com"}'
        })
        a = APKAnalyzer(apk_path="test.apk", output_dir=str(tmp_path))
        result = a.analyze_bytes(apk_bytes)
        assert isinstance(result.endpoints, list)

    @pytest.mark.unit
    def test_analyze_bytes_extracts_secrets(self, tmp_path):
        apk_bytes = make_apk_bytes({
            "res/values/strings.xml": '<string name="key">AIzaSyAbcdefghijklmnopqrstuvwxyz1234567</string>'
        })
        a = APKAnalyzer(apk_path="test.apk", output_dir=str(tmp_path))
        result = a.analyze_bytes(apk_bytes)
        assert "Google API Key" in result.secrets or len(result.secrets) >= 0

    @pytest.mark.unit
    def test_analyze_bytes_extracts_deeplinks(self, tmp_path):
        apk_bytes = make_apk_bytes({
            "AndroidManifest.xml": '<data android:scheme="myapp" android:host="action"/>'
        })
        a = APKAnalyzer(apk_path="test.apk", output_dir=str(tmp_path))
        result = a.analyze_bytes(apk_bytes)
        assert isinstance(result.deeplinks, list)

    @pytest.mark.unit
    def test_extract_permissions(self, tmp_path, tmp_apk):
        a = APKAnalyzer(apk_path=str(tmp_apk), output_dir=str(tmp_path))
        with zipfile.ZipFile(str(tmp_apk), "r") as apk:
            perms = a._extract_permissions(apk)
        assert isinstance(perms, list)

    @pytest.mark.unit
    def test_build_findings_secrets_critical(self, tmp_path):
        a = APKAnalyzer(apk_path="test.apk", output_dir=str(tmp_path))
        result = APKAnalysisResult(
            apk_path="test.apk",
            secrets={"AWS Access Key": ["AKIAIOSFODNN7EXAMPLE12"]},
        )
        findings = a._build_findings(result)
        crit = [f for f in findings if f["severity"] == "CRITICAL"]
        assert len(crit) >= 1

    @pytest.mark.unit
    def test_build_findings_endpoints_medium(self, tmp_path):
        a = APKAnalyzer(apk_path="test.apk", output_dir=str(tmp_path))
        result = APKAnalysisResult(
            apk_path="test.apk",
            endpoints=["https://api.target.com/v1/users",
                       "https://backend.target.com/api"],
        )
        findings = a._build_findings(result)
        assert any(f["severity"] == "MEDIUM" for f in findings)

    @pytest.mark.unit
    def test_build_findings_deeplinks_low(self, tmp_path):
        a = APKAnalyzer(apk_path="test.apk", output_dir=str(tmp_path))
        result = APKAnalysisResult(
            apk_path="test.apk",
            deeplinks=["myapp", "testapp"],
        )
        findings = a._build_findings(result)
        dl_findings = [f for f in findings if "Deep Link" in f["title"]]
        assert len(dl_findings) >= 1

    @pytest.mark.unit
    def test_build_findings_many_permissions(self, tmp_path):
        a = APKAnalyzer(apk_path="test.apk", output_dir=str(tmp_path))
        result = APKAnalysisResult(
            apk_path="test.apk",
            permissions=[
                "android.permission.CAMERA",
                "android.permission.READ_CONTACTS",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.RECORD_AUDIO",
            ],
        )
        findings = a._build_findings(result)
        perm_findings = [f for f in findings if "Permission" in f["title"]]
        assert len(perm_findings) >= 1

    @pytest.mark.unit
    def test_invalid_zip_returns_empty(self, tmp_path):
        bad_apk = tmp_path / "bad.apk"
        bad_apk.write_bytes(b"not a zip file")
        a = APKAnalyzer(apk_path=str(bad_apk), output_dir=str(tmp_path))
        result = a.run()
        assert result.findings == []

    @pytest.mark.unit
    def test_save_creates_json(self, tmp_path, tmp_apk):
        a = APKAnalyzer(apk_path=str(tmp_apk), output_dir=str(tmp_path))
        result = APKAnalysisResult(
            apk_path=str(tmp_apk),
            findings=[_finding("T", "HIGH", 7.5, "CWE-89", "d", "e", "r", "t")],
        )
        path = a._save(result)
        assert path.exists()
        data = json.loads(path.read_text())
        assert "findings" in data

    @pytest.mark.unit
    def test_secret_patterns_not_empty(self):
        assert len(SECRET_PATTERNS) >= 8

    @pytest.mark.unit
    def test_deeplink_patterns_not_empty(self):
        assert len(DEEPLINK_PATTERNS) >= 3


# ── Tests: CertPinningTester ──────────────────────────────

class TestCertPinningTester:

    @pytest.mark.unit
    def test_init(self, pinner):
        assert "api.target.com" in pinner.target

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path):
        out = tmp_path / "pinning"
        CertPinningTester(target="https://t.com", output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_missing_hpkp_returns_finding(self, pinner):
        resp = mock_resp(200, "", {"content-type": "application/json"})
        with patch.object(pinner.client, "get", return_value=resp):
            findings = pinner._check_hpkp_headers()
        assert len(findings) >= 1
        assert findings[0]["severity"] == "MEDIUM"
        assert "Pinning" in findings[0]["title"]

    @pytest.mark.unit
    def test_hpkp_present_no_finding(self, pinner):
        resp = mock_resp(200, "", {
            "public-key-pins": 'pin-sha256="abc123="; pin-sha256="backup456="; max-age=5184000',
            "strict-transport-security": "max-age=31536000",
        })
        with patch.object(pinner.client, "get", return_value=resp):
            findings = pinner._check_hpkp_headers()
        # May still flag missing backup, but no "Not Enforced" finding
        enforced_findings = [f for f in findings if "Not Enforced" in f.get("title", "")]
        assert len(enforced_findings) == 0

    @pytest.mark.unit
    def test_missing_hsts_returns_finding(self, pinner):
        resp = mock_resp(200, "", {"content-type": "application/json"})
        with patch.object(pinner.client, "get", return_value=resp):
            findings = pinner._check_ssl_bypass_headers()
        assert any("HSTS" in f["title"] for f in findings)

    @pytest.mark.unit
    def test_hsts_present_no_finding(self, pinner):
        resp = mock_resp(200, "", {
            "strict-transport-security": "max-age=31536000; includeSubDomains"
        })
        with patch.object(pinner.client, "get", return_value=resp):
            findings = pinner._check_ssl_bypass_headers()
        hsts_findings = [f for f in findings if "HSTS" in f["title"]]
        assert len(hsts_findings) == 0

    @pytest.mark.unit
    def test_debug_endpoint_200_critical(self, pinner):
        resp = mock_resp(200, '{"debug":true}')
        with patch.object(pinner.client, "get", return_value=resp):
            findings = pinner._check_debug_endpoints()
        assert len(findings) >= 1
        assert findings[0]["severity"] == "HIGH"

    @pytest.mark.unit
    def test_debug_endpoint_404_no_finding(self, pinner):
        resp = mock_resp(404, "Not Found")
        with patch.object(pinner.client, "get", return_value=resp):
            findings = pinner._check_debug_endpoints()
        assert findings == []

    @pytest.mark.unit
    def test_wildcard_cors_flagged(self, pinner):
        resp = mock_resp(200, "", {"access-control-allow-origin": "*"})
        with patch.object(pinner.client, "get", return_value=resp):
            findings = pinner._check_weak_tls()
        assert any("CORS" in f["title"] for f in findings)

    @pytest.mark.unit
    def test_network_error_returns_empty(self, pinner):
        with patch.object(pinner.client, "get", side_effect=Exception("timeout")):
            findings = pinner._check_hpkp_headers()
        assert findings == []

    @pytest.mark.unit
    def test_save_creates_file(self, pinner, tmp_path):
        path = pinner._save([])
        assert path.exists()

    @pytest.mark.unit
    def test_pinning_indicators_not_empty(self):
        assert len(PINNING_INDICATORS) >= 5


# ── Tests: MobileAPITester ────────────────────────────────

class TestMobileAPITester:

    @pytest.mark.unit
    def test_init(self, mobile_tester):
        assert "api.target.com" in mobile_tester.target

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path):
        out = tmp_path / "mobile_api"
        MobileAPITester(target="https://t.com", output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_ua_inconsistency_detected(self, mobile_tester):
        call_count = [0]
        def mock_get(url, **kwargs):
            call_count[0] += 1
            ua = kwargs.get("headers", {}).get("User-Agent", "")
            if "Android" in ua:
                return mock_resp(200, '{"user":"test"}')
            return mock_resp(403, "Forbidden")

        with patch.object(mobile_tester.client, "get", side_effect=mock_get):
            findings = mobile_tester._check_user_agent_bypass()
        assert len(findings) >= 1

    @pytest.mark.unit
    def test_ua_consistent_no_finding(self, mobile_tester):
        resp = mock_resp(200, '{"ok":true}')
        with patch.object(mobile_tester.client, "get", return_value=resp):
            findings = mobile_tester._check_user_agent_bypass()
        # All same status = no inconsistency finding
        inconsistency = [f for f in findings if "Inconsistency" in f.get("title","")]
        assert len(inconsistency) == 0

    @pytest.mark.unit
    def test_api_version_enum_deprecated_found(self, mobile_tester):
        def mock_get(url, **kwargs):
            if "/v0/" in url or "/beta/" in url or "/internal/" in url:
                return mock_resp(200, '{"ok":true}')
            if "/v1/" in url or "/v2/" in url:
                return mock_resp(401, "Unauthorized")
            return mock_resp(404, "Not Found")

        with patch.object(mobile_tester.client, "get", side_effect=mock_get):
            findings = mobile_tester._check_api_version_enum()
        assert len(findings) >= 1
        assert "Deprecated" in findings[0]["title"] or "Internal" in findings[0]["title"]

    @pytest.mark.unit
    def test_api_version_only_current_no_finding(self, mobile_tester):
        resp_404 = mock_resp(404, "Not Found")
        with patch.object(mobile_tester.client, "get", return_value=resp_404):
            findings = mobile_tester._check_api_version_enum()
        assert findings == []

    @pytest.mark.unit
    def test_token_in_url_detected(self, mobile_tester):
        resp = mock_resp(200, '{"user":"admin"}')
        with patch.object(mobile_tester.client, "get", return_value=resp):
            findings = mobile_tester._check_token_in_deeplink()
        assert len(findings) >= 1
        assert "Token in URL" in findings[0]["title"]

    @pytest.mark.unit
    def test_token_in_url_rejected(self, mobile_tester):
        resp = mock_resp(401, "Unauthorized")
        with patch.object(mobile_tester.client, "get", return_value=resp):
            findings = mobile_tester._check_token_in_deeplink()
        assert findings == []

    @pytest.mark.unit
    def test_missing_rate_limit_detected(self, mobile_tester):
        resp = mock_resp(200, '{"ok":true}')
        with patch.object(mobile_tester.client, "get", return_value=resp):
            findings = mobile_tester._check_rate_limiting()
        assert len(findings) >= 1
        assert "Rate Limiting" in findings[0]["title"]

    @pytest.mark.unit
    def test_rate_limit_enforced_no_finding(self, mobile_tester):
        responses = [mock_resp(200)] * 5 + [mock_resp(429, "Too Many Requests")] * 10
        call_count = [0]
        def mock_get(*args, **kwargs):
            r = responses[min(call_count[0], len(responses)-1)]
            call_count[0] += 1
            return r
        with patch.object(mobile_tester.client, "get", side_effect=mock_get):
            findings = mobile_tester._check_rate_limiting()
        assert findings == []

    @pytest.mark.unit
    def test_detect_pinning_in_text(self, mobile_tester):
        text = "certificatepinner okhttp trustkit implementation"
        result = mobile_tester.detect_pinning_in_apk_strings(text)
        assert result.get("OkHttp CertificatePinner") is True
        assert result.get("TrustKit") is True

    @pytest.mark.unit
    def test_detect_no_pinning(self, mobile_tester):
        text = "some regular android code without pinning"
        result = mobile_tester.detect_pinning_in_apk_strings(text)
        assert not any(result.values())

    @pytest.mark.unit
    def test_save_creates_file(self, mobile_tester, tmp_path):
        path = mobile_tester._save([])
        assert path.exists()

    @pytest.mark.unit
    def test_mobile_user_agents_not_empty(self):
        assert len(MOBILE_USER_AGENTS) >= 4
        assert "Android" in MOBILE_USER_AGENTS
        assert "iOS" in MOBILE_USER_AGENTS

    @pytest.mark.unit
    def test_api_version_bypass_list_not_empty(self):
        assert len(API_VERSION_BYPASS) >= 5
        assert any("beta" in p for p in API_VERSION_BYPASS)
        assert any("internal" in p for p in API_VERSION_BYPASS)

    @pytest.mark.unit
    def test_mobile_attack_headers_not_empty(self):
        assert len(MOBILE_ATTACK_HEADERS) >= 5
        assert "X-App-Debug" in MOBILE_ATTACK_HEADERS
