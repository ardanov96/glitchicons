# tests/test_cloud_security.py
"""
Unit tests untuk modules/cloud/cloud_security.py
Network calls di-mock — tidak butuh AWS/Azure/GCP credentials.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from modules.cloud.cloud_security import (
    CloudSecurityScanner,
    S3BucketChecker,
    AzureBlobChecker,
    GCPStorageChecker,
    CloudMetadataChecker,
    CloudFrontChecker,
    _make_finding,
    _derive_bucket_names,
    METADATA_ENDPOINTS,
    S3_BUCKET_PATTERNS,
    AZURE_BLOB_PATTERNS,
    GCP_STORAGE_PATTERNS,
)
import re


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def s3_checker(tmp_path):
    return S3BucketChecker(output_dir=str(tmp_path), timeout=5)


@pytest.fixture
def azure_checker(tmp_path):
    return AzureBlobChecker(output_dir=str(tmp_path), timeout=5)


@pytest.fixture
def gcp_checker(tmp_path):
    return GCPStorageChecker(output_dir=str(tmp_path), timeout=5)


@pytest.fixture
def metadata_checker(tmp_path):
    return CloudMetadataChecker(output_dir=str(tmp_path), timeout=3)


@pytest.fixture
def cf_checker(tmp_path):
    return CloudFrontChecker(output_dir=str(tmp_path), timeout=5)


@pytest.fixture
def scanner(tmp_path):
    return CloudSecurityScanner(
        target="target.com",
        output_dir=str(tmp_path),
        timeout=5,
        check_metadata=False,
    )


S3_LISTING_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-bucket</Name>
  <Key>index.html</Key>
  <Key>assets/style.css</Key>
  <Key>uploads/secret.pdf</Key>
  <Contents><Key>readme.txt</Key></Contents>
</ListBucketResult>"""

AZURE_CONTAINER_XML = """<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="https://test.blob.core.windows.net/">
  <Containers>
    <Container><Name>public-assets</Name></Container>
    <Container><Name>backups</Name></Container>
  </Containers>
</EnumerationResults>"""


# ── Tests: _make_finding ──────────────────────────────────

class TestMakeFinding:

    @pytest.mark.unit
    def test_valid_finding(self):
        f = _make_finding("T", "HIGH", 7.5, "CWE-284", "d", "e", "r", "https://t.com")
        assert f["severity"] == "HIGH"
        assert f["cvss"] == 7.5
        assert f["cwe"] == "CWE-284"

    @pytest.mark.unit
    def test_has_timestamp(self):
        f = _make_finding("T", "HIGH", 7.5, "CWE-284", "d", "e", "r", "https://t.com")
        assert "timestamp" in f

    @pytest.mark.unit
    def test_source_tagged(self):
        f = _make_finding("T", "HIGH", 7.5, "CWE-284", "d", "e", "r", "t", source="s3_bucket_checker")
        assert "module:s3_bucket_checker" in f["source"]

    @pytest.mark.unit
    def test_invalid_severity_raises(self):
        with pytest.raises(AssertionError):
            _make_finding("T", "EXTREME", 7.5, "CWE-284", "d", "e", "r", "t")

    @pytest.mark.unit
    def test_invalid_cvss_raises(self):
        with pytest.raises(AssertionError):
            _make_finding("T", "HIGH", 11.0, "CWE-284", "d", "e", "r", "t")

    @pytest.mark.unit
    def test_invalid_cwe_raises(self):
        with pytest.raises(AssertionError):
            _make_finding("T", "HIGH", 7.5, "284", "d", "e", "r", "t")

    @pytest.mark.unit
    def test_all_severities_valid(self):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            f = _make_finding("T", sev, 5.0, "CWE-1", "d", "e", "r", "t")
            assert f["severity"] == sev


# ── Tests: _derive_bucket_names ───────────────────────────

class TestDeriveBucketNames:

    @pytest.mark.unit
    def test_returns_list(self):
        names = _derive_bucket_names("target.com")
        assert isinstance(names, list)
        assert len(names) > 0

    @pytest.mark.unit
    def test_base_name_included(self):
        names = _derive_bucket_names("acme.com")
        assert "acme" in names

    @pytest.mark.unit
    def test_common_suffixes_included(self):
        names = _derive_bucket_names("acme.com")
        assert any("backup" in n for n in names)
        assert any("static" in n for n in names)
        assert any("assets" in n for n in names)

    @pytest.mark.unit
    def test_www_stripped(self):
        names = _derive_bucket_names("www.acme.com")
        assert "acme" in names

    @pytest.mark.unit
    def test_no_duplicates(self):
        names = _derive_bucket_names("acme.com")
        assert len(names) == len(set(names))


# ── Tests: S3BucketChecker ────────────────────────────────

class TestS3BucketChecker:

    @pytest.mark.unit
    def test_init_creates_output_dir(self, tmp_path):
        out = tmp_path / "cloud"
        S3BucketChecker(output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_public_listing_detected(self, s3_checker):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = S3_LISTING_XML

        with patch.object(s3_checker.client, "get", return_value=mock_resp):
            findings = s3_checker.check_bucket("test-bucket")

        assert len(findings) >= 1
        assert findings[0]["severity"] == "CRITICAL"
        assert "Listing" in findings[0]["title"]

    @pytest.mark.unit
    def test_403_returns_info_finding(self, s3_checker):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "<Error><Code>AccessDenied</Code></Error>"

        with patch.object(s3_checker.client, "get", return_value=mock_resp):
            findings = s3_checker.check_bucket("private-bucket")

        assert len(findings) >= 1
        assert findings[0]["severity"] == "INFO"

    @pytest.mark.unit
    def test_404_returns_no_findings(self, s3_checker):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = "<Error><Code>NoSuchBucket</Code></Error>"

        with patch.object(s3_checker.client, "get", return_value=mock_resp):
            findings = s3_checker.check_bucket("nonexistent-bucket")

        assert findings == []

    @pytest.mark.unit
    def test_parse_s3_listing(self, s3_checker):
        keys = s3_checker._parse_s3_listing(S3_LISTING_XML)
        assert len(keys) > 0
        assert "index.html" in keys or "readme.txt" in keys

    @pytest.mark.unit
    def test_parse_empty_xml(self, s3_checker):
        keys = s3_checker._parse_s3_listing("<ListBucketResult></ListBucketResult>")
        assert keys == []

    @pytest.mark.unit
    def test_parse_invalid_xml(self, s3_checker):
        keys = s3_checker._parse_s3_listing("not xml at all")
        assert keys == []

    @pytest.mark.unit
    def test_check_domain_calls_multiple_buckets(self, s3_checker):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = ""

        with patch.object(s3_checker.client, "get", return_value=mock_resp):
            findings = s3_checker.check_domain("target.com")

        assert isinstance(findings, list)

    @pytest.mark.unit
    def test_check_urls_from_html(self, s3_checker):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = ""

        html = '<img src="https://mybucket.s3.amazonaws.com/logo.png">'
        with patch.object(s3_checker.client, "get", return_value=mock_resp):
            findings = s3_checker.check_urls_from_html(html, "https://target.com")

        assert isinstance(findings, list)

    @pytest.mark.unit
    def test_network_error_handled(self, s3_checker):
        with patch.object(s3_checker.client, "get", side_effect=Exception("timeout")):
            findings = s3_checker.check_bucket("test-bucket")
        assert findings == []


# ── Tests: AzureBlobChecker ───────────────────────────────

class TestAzureBlobChecker:

    @pytest.mark.unit
    def test_init_creates_output_dir(self, tmp_path):
        out = tmp_path / "azure"
        AzureBlobChecker(output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_public_container_listing_detected(self, azure_checker):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = AZURE_CONTAINER_XML

        with patch.object(azure_checker.client, "get", return_value=mock_resp):
            findings = azure_checker.check_account("teststorage")

        assert len(findings) >= 1
        assert findings[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_403_no_finding(self, azure_checker):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = ""

        with patch.object(azure_checker.client, "get", return_value=mock_resp):
            findings = azure_checker.check_account("privateaccount")

        assert findings == []

    @pytest.mark.unit
    def test_sas_token_detection(self, azure_checker):
        url = "https://test.blob.core.windows.net/container/file.pdf?sv=2023-01-03&se=2024-12-31&sr=b&sp=r&sig=abc123"
        findings = azure_checker.check_sas_token_in_url(url)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "HIGH"
        assert "SAS" in findings[0]["title"]

    @pytest.mark.unit
    def test_no_sas_token_no_finding(self, azure_checker):
        url = "https://test.blob.core.windows.net/container/file.pdf"
        findings = azure_checker.check_sas_token_in_url(url)
        assert findings == []

    @pytest.mark.unit
    def test_check_domain_runs(self, azure_checker):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = ""

        with patch.object(azure_checker.client, "get", return_value=mock_resp):
            findings = azure_checker.check_domain("target.com")

        assert isinstance(findings, list)

    @pytest.mark.unit
    def test_network_error_handled(self, azure_checker):
        with patch.object(azure_checker.client, "get", side_effect=Exception("timeout")):
            findings = azure_checker.check_account("teststorage")
        assert findings == []


# ── Tests: GCPStorageChecker ──────────────────────────────

class TestGCPStorageChecker:

    @pytest.mark.unit
    def test_init_creates_output_dir(self, tmp_path):
        out = tmp_path / "gcp"
        GCPStorageChecker(output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_public_bucket_detected(self, gcp_checker):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<ListBucketResult><Key>file.txt</Key></ListBucketResult>"
        mock_resp.json.return_value = {"items": [{"name": "file.txt"}]}

        with patch.object(gcp_checker.client, "get", return_value=mock_resp):
            findings = gcp_checker.check_bucket("public-bucket")

        assert len(findings) >= 1
        assert findings[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_403_returns_info(self, gcp_checker):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = ""

        with patch.object(gcp_checker.client, "get", return_value=mock_resp):
            findings = gcp_checker.check_bucket("private-bucket")

        assert len(findings) >= 1
        assert findings[0]["severity"] == "INFO"

    @pytest.mark.unit
    def test_404_no_findings(self, gcp_checker):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = ""

        with patch.object(gcp_checker.client, "get", return_value=mock_resp):
            findings = gcp_checker.check_bucket("notexist-bucket")

        assert findings == []

    @pytest.mark.unit
    def test_check_domain_runs(self, gcp_checker):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = ""

        with patch.object(gcp_checker.client, "get", return_value=mock_resp):
            findings = gcp_checker.check_domain("target.com")

        assert isinstance(findings, list)


# ── Tests: CloudMetadataChecker ───────────────────────────

class TestCloudMetadataChecker:

    @pytest.mark.unit
    def test_init_creates_output_dir(self, tmp_path):
        out = tmp_path / "meta"
        CloudMetadataChecker(output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_accessible_endpoint_returns_finding(self, metadata_checker):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "ami-id\ninstance-id\nlocal-ipv4"

        with patch.object(metadata_checker.client, "get", return_value=mock_resp):
            ep = METADATA_ENDPOINTS[0]
            finding = metadata_checker._check_endpoint(ep)

        assert finding is not None
        assert finding["severity"] in ("CRITICAL", "HIGH")

    @pytest.mark.unit
    def test_inaccessible_endpoint_returns_none(self, metadata_checker):
        with patch.object(metadata_checker.client, "get", side_effect=Exception("refused")):
            ep = METADATA_ENDPOINTS[0]
            finding = metadata_checker._check_endpoint(ep)

        assert finding is None

    @pytest.mark.unit
    def test_404_returns_none(self, metadata_checker):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = ""

        with patch.object(metadata_checker.client, "get", return_value=mock_resp):
            finding = metadata_checker._check_endpoint(METADATA_ENDPOINTS[0])

        assert finding is None

    @pytest.mark.unit
    def test_check_all_returns_list(self, metadata_checker):
        with patch.object(metadata_checker.client, "get", side_effect=Exception("refused")):
            findings = metadata_checker.check_all()
        assert isinstance(findings, list)

    @pytest.mark.unit
    def test_ssrf_confirmed_finding(self, metadata_checker):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "ami-id\ninstance-id\niam/security-credentials"

        with patch.object(metadata_checker.client, "get", return_value=mock_resp):
            findings = metadata_checker.check_ssrf_via_target(
                "https://target.com/fetch?url=",
                ssrf_param="url",
            )

        assert len(findings) >= 1
        assert findings[0]["severity"] == "CRITICAL"
        assert "SSRF" in findings[0]["title"]

    @pytest.mark.unit
    def test_ssrf_no_indicator_no_finding(self, metadata_checker):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><body>Not found</body></html>"

        with patch.object(metadata_checker.client, "get", return_value=mock_resp):
            findings = metadata_checker.check_ssrf_via_target(
                "https://target.com/fetch",
                ssrf_param="url",
            )

        assert findings == []


# ── Tests: CloudFrontChecker ──────────────────────────────

class TestCloudFrontChecker:

    @pytest.mark.unit
    def test_init_creates_output_dir(self, tmp_path):
        out = tmp_path / "cf"
        CloudFrontChecker(output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_cloudfront_detected_missing_headers(self, cf_checker):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html></html>"
        mock_resp.headers = {
            "X-Cache": "Miss from cloudfront",
            "X-Amz-Cf-Id": "abc123",
            # No security headers
        }

        with patch.object(cf_checker.client, "get", return_value=mock_resp):
            findings = cf_checker.check_domain("target.com")

        # Should flag missing security headers
        missing_finding = next(
            (f for f in findings if "Missing" in f["title"]), None
        )
        assert missing_finding is not None
        assert missing_finding["severity"] == "LOW"

    @pytest.mark.unit
    def test_no_cloudfront_no_findings(self, cf_checker):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html></html>"
        mock_resp.headers = {"Content-Type": "text/html"}

        with patch.object(cf_checker.client, "get", return_value=mock_resp):
            findings = cf_checker.check_domain("target.com")

        assert findings == []

    @pytest.mark.unit
    def test_network_error_handled(self, cf_checker):
        with patch.object(cf_checker.client, "get", side_effect=Exception("timeout")):
            findings = cf_checker.check_domain("target.com")
        assert findings == []


# ── Tests: CloudSecurityScanner ───────────────────────────

class TestCloudSecurityScanner:

    @pytest.mark.unit
    def test_init(self, scanner):
        assert scanner.target == "target.com"

    @pytest.mark.unit
    def test_run_returns_list(self, scanner, tmp_path):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = ""
        mock_resp.headers = {"Content-Type": "text/html"}

        with patch("httpx.Client.get", return_value=mock_resp):
            findings = scanner.run()

        assert isinstance(findings, list)

    @pytest.mark.unit
    def test_save_creates_json_file(self, scanner, tmp_path):
        findings = [
            _make_finding("T", "HIGH", 7.5, "CWE-284", "d", "e", "r", "https://t.com")
        ]
        path = scanner._save(findings)
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "findings" in data
        assert len(data["findings"]) == 1

    @pytest.mark.unit
    def test_check_metadata_false_by_default(self, tmp_path):
        scanner = CloudSecurityScanner(
            target="target.com",
            output_dir=str(tmp_path),
            check_metadata=False,
        )
        assert scanner.check_metadata is False


# ── Tests: Constants + Patterns ───────────────────────────

class TestConstants:

    @pytest.mark.unit
    def test_metadata_endpoints_not_empty(self):
        assert len(METADATA_ENDPOINTS) >= 5

    @pytest.mark.unit
    def test_metadata_endpoints_have_required_fields(self):
        required = {"url", "provider", "version", "severity", "cvss", "description", "remediation"}
        for ep in METADATA_ENDPOINTS:
            missing = required - set(ep.keys())
            assert not missing, f"Endpoint {ep.get('provider')} missing: {missing}"

    @pytest.mark.unit
    def test_aws_endpoint_has_critical_severity(self):
        aws = next(ep for ep in METADATA_ENDPOINTS if ep["provider"] == "AWS")
        assert aws["severity"] == "CRITICAL"
        assert aws["cvss"] >= 9.0

    @pytest.mark.unit
    def test_s3_patterns_match_valid_urls(self):
        valid_urls = [
            "mybucket.s3.amazonaws.com",
            "s3.amazonaws.com/mybucket",
            "mybucket.s3-us-east-1.amazonaws.com",
        ]
        for url in valid_urls:
            matched = any(re.search(p, url) for p in S3_BUCKET_PATTERNS)
            assert matched, f"S3 pattern should match: {url}"

    @pytest.mark.unit
    def test_azure_patterns_match_valid_urls(self):
        valid_urls = [
            "myaccount.blob.core.windows.net",
            "myaccount.blob.core.windows.net/container",
        ]
        for url in valid_urls:
            matched = any(re.search(p, url) for p in AZURE_BLOB_PATTERNS)
            assert matched, f"Azure pattern should match: {url}"

    @pytest.mark.unit
    def test_gcp_patterns_match_valid_urls(self):
        valid_urls = [
            "mybucket.storage.googleapis.com",
            "storage.googleapis.com/mybucket",
        ]
        for url in valid_urls:
            matched = any(re.search(p, url) for p in GCP_STORAGE_PATTERNS)
            assert matched, f"GCP pattern should match: {url}"
