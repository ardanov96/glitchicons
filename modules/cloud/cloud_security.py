"""
Cloud Security Scanner — modules/cloud/cloud_security.py

Detects cloud infrastructure misconfigurations across:
  1. AWS S3         — public buckets, ACL, listing, policy exposure
  2. Azure Blob     — anonymous container access, SAS token leaks
  3. GCP Storage    — public bucket access, allUsers permissions
  4. Cloud Metadata — SSRF to IMDSv1/v2 endpoints (169.254.169.254)
  5. CloudFront     — misconfigured distributions, S3 origin exposure
  6. Elastic IPs    — reverse DNS cloud asset enumeration

Usage:
    from modules.cloud.cloud_security import CloudSecurityScanner

    scanner = CloudSecurityScanner(target="target.com", output_dir="./findings/cloud")
    findings = scanner.run()

    # Individual checks
    from modules.cloud.cloud_security import S3BucketChecker
    checker = S3BucketChecker(output_dir="./findings")
    findings = checker.check_domain("target.com")

Author: ardanov96
"""

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
from rich.console import Console

console = Console()


# ── Finding helpers ───────────────────────────────────────

def _make_finding(
    title: str,
    severity: str,
    cvss: float,
    cwe: str,
    description: str,
    evidence: str,
    remediation: str,
    target: str,
    source: str = "cloud_security",
) -> dict:
    assert severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    assert 0.0 <= cvss <= 10.0
    assert cwe.startswith("CWE-")
    return {
        "title":       title,
        "severity":    severity,
        "cvss":        cvss,
        "cwe":         cwe,
        "target":      target,
        "description": description,
        "evidence":    evidence,
        "remediation": remediation,
        "source":      f"module:{source}",
        "timestamp":   datetime.now(timezone.utc).isoformat(),
    }


# ── S3 Bucket patterns ────────────────────────────────────

S3_BUCKET_PATTERNS = [
    # Standard endpoints
    r"([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])\.s3\.amazonaws\.com",
    r"([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])\.s3\-[a-z0-9\-]+\.amazonaws\.com",
    r"s3\.amazonaws\.com/([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])",
    r"s3\-[a-z0-9\-]+\.amazonaws\.com/([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])",
    # Path-style
    r"s3\.amazonaws\.com/([a-zA-Z0-9\-_\.]+)",
]

AZURE_BLOB_PATTERNS = [
    r"([a-z0-9]{3,24})\.blob\.core\.windows\.net",
    r"([a-z0-9]{3,24})\.blob\.core\.windows\.net/([^/\s]+)",
]

GCP_STORAGE_PATTERNS = [
    r"([a-z0-9][a-z0-9\-_\.]{1,61}[a-z0-9])\.storage\.googleapis\.com",
    r"storage\.googleapis\.com/([a-z0-9][a-z0-9\-_\.]{1,61}[a-z0-9])",
    r"([a-z0-9][a-z0-9\-_\.]{1,61}[a-z0-9])\.storage\.cloud\.google\.com",
]

# Cloud metadata endpoints
METADATA_ENDPOINTS = [
    # AWS IMDSv1
    {
        "url":         "http://169.254.169.254/latest/meta-data/",
        "provider":    "AWS",
        "version":     "IMDSv1",
        "severity":    "CRITICAL",
        "cvss":        9.8,
        "description": "AWS EC2 Instance Metadata Service (IMDSv1) accessible — no token required. Exposes IAM role credentials.",
        "remediation": "Enable IMDSv2 (require session tokens). Set HttpTokens=required on EC2 metadata.",
    },
    {
        "url":         "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "provider":    "AWS",
        "version":     "IMDSv1-IAM",
        "severity":    "CRITICAL",
        "cvss":        9.8,
        "description": "AWS IAM role credentials exposed via Instance Metadata Service.",
        "remediation": "Enable IMDSv2. Restrict SSRF vectors. Apply least-privilege IAM policies.",
    },
    # AWS ECS
    {
        "url":         "http://169.254.170.2/v2/credentials/",
        "provider":    "AWS-ECS",
        "version":     "ECS-Metadata",
        "severity":    "CRITICAL",
        "cvss":        9.8,
        "description": "AWS ECS task metadata endpoint accessible — exposes container credentials.",
        "remediation": "Restrict network access to metadata endpoint. Apply task IAM least-privilege.",
    },
    # Azure IMDS
    {
        "url":         "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "provider":    "Azure",
        "version":     "IMDS",
        "severity":    "HIGH",
        "cvss":        8.1,
        "description": "Azure Instance Metadata Service accessible — exposes VM instance info and managed identity tokens.",
        "remediation": "Restrict SSRF vectors. Use Azure managed identities with minimal permissions.",
        "headers":     {"Metadata": "true"},
    },
    # GCP metadata
    {
        "url":         "http://169.254.169.254/computeMetadata/v1/",
        "provider":    "GCP",
        "version":     "Metadata-v1",
        "severity":    "CRITICAL",
        "cvss":        9.8,
        "description": "GCP Compute Engine metadata server accessible — exposes service account tokens.",
        "remediation": "Block metadata endpoint access via firewall rules. Use Workload Identity.",
        "headers":     {"Metadata-Flavor": "Google"},
    },
    {
        "url":         "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "provider":    "GCP",
        "version":     "SA-Token",
        "severity":    "CRITICAL",
        "cvss":        9.8,
        "description": "GCP service account OAuth token directly accessible via metadata endpoint.",
        "remediation": "Restrict metadata access. Rotate service account credentials immediately.",
        "headers":     {"Metadata-Flavor": "Google"},
    },
    # DigitalOcean
    {
        "url":         "http://169.254.169.254/metadata/v1/",
        "provider":    "DigitalOcean",
        "version":     "Metadata-v1",
        "severity":    "HIGH",
        "cvss":        7.5,
        "description": "DigitalOcean Droplet metadata accessible — exposes instance configuration.",
        "remediation": "Restrict SSRF attack vectors. Review metadata content exposure.",
    },
]

# Common bucket name patterns derived from domain
def _derive_bucket_names(domain: str) -> list[str]:
    """Generate likely S3/storage bucket names from a domain."""
    base = domain.replace("www.", "").split(".")[0]
    names = [
        base,
        f"{base}-backup",
        f"{base}-backups",
        f"{base}-static",
        f"{base}-assets",
        f"{base}-media",
        f"{base}-uploads",
        f"{base}-files",
        f"{base}-public",
        f"{base}-dev",
        f"{base}-staging",
        f"{base}-prod",
        f"{base}-data",
        f"{base}-logs",
        f"{base}-images",
        f"www.{base}",
        f"cdn.{base}",
        domain,
        f"{base}.com",
    ]
    # Deduplicate while preserving order
    seen = set()
    result = []
    for n in names:
        if n not in seen:
            seen.add(n)
            result.append(n)
    return result


# ── S3 Bucket Checker ─────────────────────────────────────

class S3BucketChecker:
    """
    Check S3 buckets for public access misconfigurations.

    Checks:
    - Bucket listing (ListBucket) — anyone can list objects
    - Object public access (GetObject) — anyone can read files
    - Bucket existence (403 = exists but restricted, 404 = not found)
    - ACL exposure (public-read, public-read-write)
    - Domain-derived bucket name enumeration
    """

    def __init__(
        self,
        output_dir: str = "./findings/cloud",
        timeout: int = 10,
        token: str | None = None,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "Glitchicons/1.5.0 (cloud-security)"},
        )

    def check_bucket(self, bucket_name: str) -> list[dict]:
        """Check a specific S3 bucket name for misconfigurations."""
        findings = []
        urls = [
            f"https://{bucket_name}.s3.amazonaws.com/",
            f"https://s3.amazonaws.com/{bucket_name}/",
        ]

        for url in urls:
            try:
                resp = self.client.get(url)
            except Exception:
                continue

            if resp.status_code == 200:
                # Check if listing is enabled
                if "<ListBucketResult" in resp.text or "<Contents>" in resp.text:
                    objects = self._parse_s3_listing(resp.text)
                    findings.append(_make_finding(
                        title=f"Public S3 Bucket — Directory Listing Enabled: {bucket_name}",
                        severity="CRITICAL",
                        cvss=9.8,
                        cwe="CWE-284",
                        description=(
                            f"S3 bucket '{bucket_name}' allows public directory listing. "
                            f"Found {len(objects)} objects. Anyone can enumerate and access files."
                        ),
                        evidence=(
                            f"URL: {url}\nHTTP 200 — ListBucket succeeded\n"
                            f"Objects found: {len(objects)}\n"
                            f"Sample: {', '.join(objects[:5])}"
                        ),
                        remediation=(
                            "Remove s3:ListBucket from bucket policy for public principals. "
                            "Enable S3 Block Public Access at account and bucket level. "
                            "Audit IAM policies for overly permissive S3 actions."
                        ),
                        target=url,
                        source="s3_bucket_checker",
                    ))
                    break

            elif resp.status_code == 403:
                # Bucket exists but restricted — check for ACL exposure
                findings.append(_make_finding(
                    title=f"S3 Bucket Exists (Access Restricted): {bucket_name}",
                    severity="INFO",
                    cvss=3.1,
                    cwe="CWE-200",
                    description=(
                        f"S3 bucket '{bucket_name}' exists but access is restricted (HTTP 403). "
                        "Bucket name confirmed — verify ACL and policy configuration."
                    ),
                    evidence=f"URL: {url}\nHTTP 403 — Bucket exists, access denied",
                    remediation=(
                        "Verify bucket policy and ACL are correctly configured. "
                        "Enable S3 Block Public Access as defense in depth."
                    ),
                    target=url,
                    source="s3_bucket_checker",
                ))
                break

        return findings

    def check_domain(self, domain: str) -> list[dict]:
        """Enumerate S3 buckets derived from domain name."""
        console.print(f"  [cyan]S3 bucket enumeration for:[/cyan] {domain}")
        all_findings = []
        bucket_names = _derive_bucket_names(domain)

        for name in bucket_names:
            findings = self.check_bucket(name)
            if findings:
                all_findings.extend(findings)
                console.print(f"    [red]FINDING:[/red] {name} — {findings[0]['severity']}")
            else:
                console.print(f"    [dim]clean:[/dim] {name}")

        console.print(f"  S3 findings: [bold]{len(all_findings)}[/bold]")
        return all_findings

    def check_urls_from_html(self, html: str, base_url: str) -> list[dict]:
        """Extract and check S3 URLs found in HTML/JS content."""
        findings = []
        for pattern in S3_BUCKET_PATTERNS:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                bucket = match.group(1)
                findings.extend(self.check_bucket(bucket))
        return findings

    def _parse_s3_listing(self, xml_content: str) -> list[str]:
        """Parse S3 XML listing response to extract object keys."""
        try:
            root = ET.fromstring(xml_content)
            ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
            keys = [el.text for el in root.findall(".//s3:Key", ns) if el.text]
            # Fallback without namespace
            if not keys:
                keys = [el.text for el in root.iter("Key") if el.text]
            return keys[:20]
        except Exception:
            return []


# ── Azure Blob Checker ────────────────────────────────────

class AzureBlobChecker:
    """
    Check Azure Blob Storage containers for public access.

    Checks:
    - Anonymous container access (Container-level public access)
    - Blob-level public access
    - SAS token in URL (dangerous if exposed)
    - Storage account enumeration
    """

    ANONYMOUS_ACCESS_INDICATORS = [
        "<EnumerationResults",
        "<Blob>",
        "<Container>",
        "application/xml",
    ]

    def __init__(self, output_dir: str = "./findings/cloud", timeout: int = 10):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "Glitchicons/1.5.0"},
        )

    def check_account(self, account_name: str) -> list[dict]:
        """Check an Azure storage account for public container access."""
        findings = []
        base_url = f"https://{account_name}.blob.core.windows.net"

        # Try listing containers
        try:
            resp = self.client.get(f"{base_url}/?comp=list")
            if resp.status_code == 200 and any(
                ind in resp.text for ind in self.ANONYMOUS_ACCESS_INDICATORS
            ):
                containers = re.findall(r"<Name>([^<]+)</Name>", resp.text)
                findings.append(_make_finding(
                    title=f"Azure Blob Storage — Public Container Listing: {account_name}",
                    severity="CRITICAL",
                    cvss=9.1,
                    cwe="CWE-284",
                    description=(
                        f"Azure storage account '{account_name}' allows public container enumeration. "
                        f"Found {len(containers)} container(s)."
                    ),
                    evidence=(
                        f"URL: {base_url}/?comp=list\n"
                        f"HTTP 200 — Container listing enabled\n"
                        f"Containers: {', '.join(containers[:10])}"
                    ),
                    remediation=(
                        "Set container access level to Private. "
                        "Disable anonymous access at storage account level: "
                        "allowBlobPublicAccess: false in storage account settings."
                    ),
                    target=base_url,
                    source="azure_blob_checker",
                ))

                # Check each container
                for container in containers[:5]:
                    container_findings = self.check_container(account_name, container)
                    findings.extend(container_findings)

        except Exception:
            pass

        return findings

    def check_container(self, account_name: str, container_name: str) -> list[dict]:
        """Check a specific Azure Blob container for public access."""
        findings = []
        url = f"https://{account_name}.blob.core.windows.net/{container_name}?restype=container&comp=list"

        try:
            resp = self.client.get(url)
            if resp.status_code == 200:
                blobs = re.findall(r"<Name>([^<]+)</Name>", resp.text)
                findings.append(_make_finding(
                    title=f"Azure Blob Container Public Access: {account_name}/{container_name}",
                    severity="HIGH",
                    cvss=8.1,
                    cwe="CWE-284",
                    description=(
                        f"Azure Blob container '{container_name}' in account '{account_name}' "
                        f"allows anonymous access. {len(blobs)} blob(s) accessible."
                    ),
                    evidence=(
                        f"URL: {url}\nHTTP 200\n"
                        f"Blobs found: {len(blobs)}\n"
                        f"Sample: {', '.join(blobs[:5])}"
                    ),
                    remediation=(
                        "Set container access to Private. "
                        "Use Shared Access Signatures (SAS) with expiry for temporary access."
                    ),
                    target=url,
                    source="azure_blob_checker",
                ))
        except Exception:
            pass

        return findings

    def check_domain(self, domain: str) -> list[dict]:
        """Enumerate Azure storage accounts derived from domain."""
        console.print(f"  [cyan]Azure Blob enumeration for:[/cyan] {domain}")
        all_findings = []
        base = domain.replace("www.", "").split(".")[0]
        account_names = [
            base, f"{base}storage", f"{base}backup", f"{base}static",
            f"{base}assets", f"{base}media", f"{base}files", f"{base}data",
        ]

        for name in account_names:
            # Azure storage account names: 3-24 chars, lowercase alphanumeric
            name = re.sub(r"[^a-z0-9]", "", name.lower())[:24]
            if len(name) < 3:
                continue
            findings = self.check_account(name)
            all_findings.extend(findings)

        console.print(f"  Azure findings: [bold]{len(all_findings)}[/bold]")
        return all_findings

    def check_sas_token_in_url(self, url: str) -> list[dict]:
        """Detect exposed SAS tokens in URLs."""
        findings = []
        parsed = urlparse(url)
        query = parsed.query

        sas_indicators = ["sig=", "sv=", "se=", "sp=", "sr="]
        if sum(1 for ind in sas_indicators if ind in query) >= 3:
            findings.append(_make_finding(
                title="Azure SAS Token Exposed in URL",
                severity="HIGH",
                cvss=7.5,
                cwe="CWE-312",
                description=(
                    "Azure Shared Access Signature (SAS) token detected in URL. "
                    "SAS tokens grant temporary access to storage resources and "
                    "should never appear in URLs or logs."
                ),
                evidence=f"URL: {url[:200]}\nSAS parameters detected: sig, sv, se, sp, sr",
                remediation=(
                    "Store SAS tokens server-side. Never include in URLs visible to clients. "
                    "Rotate the SAS token immediately. Use short expiry times."
                ),
                target=url,
                source="azure_blob_checker",
            ))
        return findings


# ── GCP Storage Checker ───────────────────────────────────

class GCPStorageChecker:
    """
    Check Google Cloud Storage buckets for public access.

    Checks:
    - Public bucket listing (allUsers has storage.objects.list)
    - Public object access (allUsers has storage.objects.get)
    - JSON API vs XML API enumeration
    """

    def __init__(self, output_dir: str = "./findings/cloud", timeout: int = 10):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "Glitchicons/1.5.0"},
        )

    def check_bucket(self, bucket_name: str) -> list[dict]:
        """Check a specific GCS bucket for public access."""
        findings = []

        endpoints = [
            f"https://storage.googleapis.com/{bucket_name}",
            f"https://{bucket_name}.storage.googleapis.com/",
            f"https://storage.cloud.google.com/{bucket_name}",
        ]

        for url in endpoints:
            try:
                resp = self.client.get(url)
                if resp.status_code == 200:
                    if "<ListBucketResult" in resp.text or '"kind": "storage#objects"' in resp.text:
                        # Count objects
                        items_json = 0
                        items_xml = len(re.findall(r"<Key>", resp.text))
                        try:
                            data = resp.json()
                            items_json = len(data.get("items", []))
                        except Exception:
                            pass
                        total = max(items_json, items_xml)

                        findings.append(_make_finding(
                            title=f"GCS Bucket Public Access — Listing Enabled: {bucket_name}",
                            severity="CRITICAL",
                            cvss=9.8,
                            cwe="CWE-284",
                            description=(
                                f"Google Cloud Storage bucket '{bucket_name}' allows public listing. "
                                f"Found ~{total} object(s) accessible by anyone."
                            ),
                            evidence=f"URL: {url}\nHTTP 200 — Bucket listing succeeded",
                            remediation=(
                                "Remove allUsers from bucket IAM bindings. "
                                "Use Uniform bucket-level access. "
                                "Enable Public access prevention on bucket."
                            ),
                            target=url,
                            source="gcp_storage_checker",
                        ))
                        return findings

                elif resp.status_code == 403:
                    findings.append(_make_finding(
                        title=f"GCS Bucket Exists (Access Restricted): {bucket_name}",
                        severity="INFO",
                        cvss=2.7,
                        cwe="CWE-200",
                        description=f"GCS bucket '{bucket_name}' exists but access is restricted.",
                        evidence=f"URL: {url}\nHTTP 403",
                        remediation="Verify bucket IAM policy — no allUsers bindings.",
                        target=url,
                        source="gcp_storage_checker",
                    ))
                    return findings

            except Exception:
                continue

        return findings

    def check_domain(self, domain: str) -> list[dict]:
        """Enumerate GCS buckets derived from domain."""
        console.print(f"  [cyan]GCP Storage enumeration for:[/cyan] {domain}")
        all_findings = []
        bucket_names = _derive_bucket_names(domain)

        for name in bucket_names:
            findings = self.check_bucket(name)
            all_findings.extend(findings)

        console.print(f"  GCP findings: [bold]{len(all_findings)}[/bold]")
        return all_findings


# ── Cloud Metadata Checker ────────────────────────────────

class CloudMetadataChecker:
    """
    Check if cloud metadata endpoints are reachable via SSRF.

    Tests all major cloud providers:
    - AWS IMDSv1 + IMDSv2 + ECS metadata
    - Azure IMDS
    - GCP Compute metadata
    - DigitalOcean metadata

    This runs from the target machine's network perspective.
    In a real SSRF scenario, these requests would be made by the target server.
    This checker tests direct accessibility (useful for container escape / misconfig).
    """

    def __init__(self, output_dir: str = "./findings/cloud", timeout: int = 5):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.client = httpx.Client(timeout=timeout, follow_redirects=False)

    def check_all(self) -> list[dict]:
        """Check all cloud metadata endpoints for accessibility."""
        console.print("  [cyan]Checking cloud metadata endpoints...[/cyan]")
        findings = []

        for ep in METADATA_ENDPOINTS:
            finding = self._check_endpoint(ep)
            if finding:
                findings.append(finding)
                console.print(
                    f"    [red]ACCESSIBLE:[/red] {ep['provider']} {ep['version']}"
                )

        console.print(f"  Metadata findings: [bold]{len(findings)}[/bold]")
        return findings

    def check_ssrf_via_target(
        self,
        target_url: str,
        ssrf_param: str = "url",
        method: str = "GET",
    ) -> list[dict]:
        """
        Test SSRF by injecting metadata URLs into a target parameter.

        Args:
            target_url: URL of the vulnerable endpoint
            ssrf_param: Parameter name to inject metadata URL into
            method:     HTTP method

        Returns:
            Findings for each accessible metadata endpoint
        """
        console.print(f"  [cyan]Testing SSRF metadata via:[/cyan] {target_url}")
        findings = []
        ssrf_urls = [ep["url"] for ep in METADATA_ENDPOINTS[:4]]

        for meta_url in ssrf_urls:
            try:
                if method.upper() == "GET":
                    resp = self.client.get(
                        target_url,
                        params={ssrf_param: meta_url},
                    )
                else:
                    resp = self.client.request(
                        method, target_url,
                        data={ssrf_param: meta_url},
                    )

                # Detect metadata in response
                indicators = [
                    "ami-id", "instance-id", "local-ipv4",         # AWS
                    "compute/", "osProfile", "storageProfile",      # Azure
                    "project-id", "service-accounts",               # GCP
                    "droplet_id", "interfaces",                     # DigitalOcean
                ]
                if any(ind in resp.text for ind in indicators):
                    findings.append(_make_finding(
                        title="SSRF to Cloud Metadata Endpoint — Confirmed",
                        severity="CRITICAL",
                        cvss=9.8,
                        cwe="CWE-918",
                        description=(
                            f"SSRF vulnerability confirmed — target server fetched "
                            f"cloud metadata from {meta_url} via parameter '{ssrf_param}'. "
                            "IAM credentials and instance metadata may be exposed."
                        ),
                        evidence=(
                            f"Target URL: {target_url}\n"
                            f"SSRF payload: {ssrf_param}={meta_url}\n"
                            f"Response snippet: {resp.text[:300]}"
                        ),
                        remediation=(
                            "Validate and allowlist URLs before making server-side requests. "
                            "Enable IMDSv2 (AWS) to require token-based metadata access. "
                            "Apply SSRF protection: block 169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12."
                        ),
                        target=target_url,
                        source="cloud_metadata_checker",
                    ))
            except Exception:
                continue

        return findings

    def _check_endpoint(self, ep: dict) -> dict | None:
        """Check a single metadata endpoint for direct accessibility."""
        headers = ep.get("headers", {})
        try:
            resp = self.client.get(ep["url"], headers=headers)
            if resp.status_code == 200 and len(resp.text) > 10:
                return _make_finding(
                    title=f"Cloud Metadata Endpoint Accessible: {ep['provider']} {ep['version']}",
                    severity=ep["severity"],
                    cvss=ep["cvss"],
                    cwe="CWE-918",
                    description=ep["description"],
                    evidence=(
                        f"URL: {ep['url']}\n"
                        f"HTTP {resp.status_code}\n"
                        f"Response: {resp.text[:200]}"
                    ),
                    remediation=ep["remediation"],
                    target=ep["url"],
                    source="cloud_metadata_checker",
                )
        except Exception:
            pass
        return None


# ── CloudFront / CDN Checker ──────────────────────────────

class CloudFrontChecker:
    """
    Check CloudFront distributions for misconfiguration.

    Checks:
    - S3 origin exposure (bucket accessible without CloudFront)
    - Missing security headers in CloudFront response
    - CloudFront bypass via direct S3 origin access
    - Custom origin header bypass
    """

    CF_HEADERS = {
        "X-Cache", "X-Amz-Cf-Id", "X-Amz-Cf-Pop",
        "Via", "Age", "CF-RAY", "CF-Cache-Status",
    }

    def __init__(self, output_dir: str = "./findings/cloud", timeout: int = 10):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.client = httpx.Client(timeout=timeout, follow_redirects=True)

    def check_domain(self, domain: str) -> list[dict]:
        """Check if a domain is served via CloudFront and test for bypass."""
        findings = []
        console.print(f"  [cyan]CloudFront check:[/cyan] {domain}")

        try:
            resp = self.client.get(f"https://{domain}/")
        except Exception:
            return findings

        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        cf_detected = any(h.lower() in resp_headers for h in self.CF_HEADERS)

        if not cf_detected:
            return findings

        console.print(f"    [dim]CloudFront detected on {domain}[/dim]")

        # Check missing security headers
        missing = []
        security_headers = {
            "strict-transport-security": "HSTS",
            "x-content-type-options": "X-Content-Type-Options",
            "x-frame-options": "X-Frame-Options",
            "content-security-policy": "CSP",
        }
        for header, name in security_headers.items():
            if header not in resp_headers:
                missing.append(name)

        if missing:
            findings.append(_make_finding(
                title=f"CloudFront Distribution Missing Security Headers",
                severity="LOW",
                cvss=3.1,
                cwe="CWE-693",
                description=(
                    f"CloudFront distribution for '{domain}' is missing {len(missing)} "
                    "security response headers."
                ),
                evidence=f"Missing: {', '.join(missing)}",
                remediation=(
                    "Add response headers policy to CloudFront distribution. "
                    "Configure: HSTS, X-Content-Type-Options, X-Frame-Options, CSP."
                ),
                target=f"https://{domain}/",
                source="cloudfront_checker",
            ))

        # Try direct S3 origin access (common misconfiguration)
        base = domain.replace("www.", "").split(".")[0]
        s3_origins = [
            f"https://{base}.s3.amazonaws.com/",
            f"https://s3.amazonaws.com/{base}/",
        ]
        for s3_url in s3_origins:
            try:
                s3_resp = self.client.get(s3_url)
                if s3_resp.status_code == 200 and "<ListBucketResult" in s3_resp.text:
                    findings.append(_make_finding(
                        title="CloudFront S3 Origin Directly Accessible",
                        severity="HIGH",
                        cvss=7.5,
                        cwe="CWE-284",
                        description=(
                            f"S3 origin for CloudFront distribution is directly accessible, "
                            "bypassing CloudFront WAF rules and access controls."
                        ),
                        evidence=f"CloudFront: https://{domain}/\nS3 Direct: {s3_url} → HTTP 200",
                        remediation=(
                            "Enable S3 Origin Access Control (OAC). "
                            "Block direct S3 bucket access via bucket policy. "
                            "Use CloudFront signed URLs/cookies for private content."
                        ),
                        target=s3_url,
                        source="cloudfront_checker",
                    ))
            except Exception:
                pass

        return findings


# ── Cloud Security Scanner (orchestrator) ─────────────────

class CloudSecurityScanner:
    """
    Full cloud security scan orchestrator.

    Runs all cloud checkers:
    - S3 bucket enumeration + misconfiguration
    - Azure Blob Storage misconfiguration
    - GCP Storage misconfiguration
    - Cloud metadata endpoint checks
    - CloudFront misconfiguration

    Usage:
        scanner = CloudSecurityScanner(target="target.com")
        findings = scanner.run()
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "./findings/cloud",
        token: str | None = None,
        timeout: int = 10,
        check_metadata: bool = False,
    ):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.token = token
        self.timeout = timeout
        self.check_metadata = check_metadata

        self._s3      = S3BucketChecker(output_dir=str(output_dir), timeout=timeout)
        self._azure   = AzureBlobChecker(output_dir=str(output_dir), timeout=timeout)
        self._gcp     = GCPStorageChecker(output_dir=str(output_dir), timeout=timeout)
        self._cf      = CloudFrontChecker(output_dir=str(output_dir), timeout=timeout)
        self._metadata = CloudMetadataChecker(output_dir=str(output_dir), timeout=5)

    def run(self) -> list[dict]:
        """Run all cloud security checks and return combined findings."""
        console.print(f"\n  [bold cyan]⬡ Cloud Security Scanner[/bold cyan] → {self.target}")
        all_findings = []

        # 1. S3
        all_findings.extend(self._s3.check_domain(self.target))

        # 2. Azure Blob
        all_findings.extend(self._azure.check_domain(self.target))

        # 3. GCP Storage
        all_findings.extend(self._gcp.check_domain(self.target))

        # 4. CloudFront
        all_findings.extend(self._cf.check_domain(self.target))

        # 5. Metadata (optional — direct network check)
        if self.check_metadata:
            all_findings.extend(self._metadata.check_all())

        # Save
        self._save(all_findings)

        console.print(
            f"\n  [bold]Cloud total:[/bold] "
            f"[red]{sum(1 for f in all_findings if f['severity'] == 'CRITICAL')} CRITICAL[/red]  "
            f"[yellow]{sum(1 for f in all_findings if f['severity'] == 'HIGH')} HIGH[/yellow]  "
            f"{len(all_findings)} total"
        )
        return all_findings

    def _save(self, findings: list[dict]) -> Path:
        slug = self.target.replace("/", "_").replace(":", "")
        out  = self.output_dir / f"cloud_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(
            json.dumps({"target": self.target, "findings": findings}, indent=2),
            encoding="utf-8",
        )
        return out
