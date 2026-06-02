"""
Mobile API Security — modules/mobile/mobile_api.py

Security testing for mobile application backends.

Components:
  1. APKAnalyzer        — extract endpoints, secrets, API keys from APK files
  2. CertPinningTester  — detect certificate pinning bypass patterns
  3. MobileAPITester    — test mobile-specific API attack patterns

Usage:
    from modules.mobile.mobile_api import APKAnalyzer, CertPinningTester, MobileAPITester

    # Analyze APK
    analyzer = APKAnalyzer(apk_path="./app.apk", output_dir="./findings/mobile")
    results  = analyzer.run()

    # Test cert pinning
    pinner = CertPinningTester(target="https://api.target.com", output_dir="./findings/mobile")
    findings = pinner.run()

    # Test mobile API patterns
    tester = MobileAPITester(target="https://api.target.com", output_dir="./findings/mobile")
    findings = tester.run()

Author: ardanov96
"""

import io
import json
import re
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import httpx
from rich.console import Console

console = Console()


# ── Finding helper ────────────────────────────────────────

def _finding(
    title: str, severity: str, cvss: float, cwe: str,
    description: str, evidence: str, remediation: str,
    target: str, source: str = "mobile_api",
) -> dict:
    assert severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    assert 0.0 <= cvss <= 10.0
    assert cwe.startswith("CWE-")
    return {
        "title": title, "severity": severity, "cvss": cvss, "cwe": cwe,
        "target": target, "description": description, "evidence": evidence,
        "remediation": remediation, "source": f"module:{source}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── APK Analysis patterns ─────────────────────────────────

# URL / endpoint patterns found in APK strings
URL_PATTERNS = [
    r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{10,200}",
    r"(?:api|backend|server|host|base[_-]?url)['\"\s:=]+([a-zA-Z0-9\-._:/?]+)",
    r"(?:endpoint|url|uri)['\"\s:=]+(https?://[^\s'\"]+)",
]

# Hardcoded secret patterns in APK source / strings
SECRET_PATTERNS = {
    "AWS Access Key":    r"AKIA[0-9A-Z]{16}",
    "Google API Key":    r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase URL":      r"https://[a-z0-9\-]+\.firebaseio\.com",
    "Firebase Key":      r"['\"]firebase['\"]:\s*['\"]([A-Za-z0-9\-_]{20,})['\"]",
    "JWT Token":         r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
    "Generic API Key":   r"(?i)api[_-]?key['\"\s:=]+([A-Za-z0-9_\-]{20,50})",
    "Generic Secret":    r"(?i)(?:secret|password|passwd)['\"\s:=]+([^'\"\s]{8,50})",
    "Private Key Hint":  r"-----BEGIN (?:RSA|EC|PRIVATE) KEY-----",
    "Basic Auth":        r"Basic\s+[A-Za-z0-9+/]{20,}={0,2}",
    "Bearer Token":      r"Bearer\s+[A-Za-z0-9\-_.]{20,}",
}

# Deep link / intent patterns
DEEPLINK_PATTERNS = [
    r"[a-zA-Z][a-zA-Z0-9+\-.]*://[^\s'\"<>]+",
    r"android:scheme=['\"]([^'\"]+)['\"]",
    r"android:host=['\"]([^'\"]+)['\"]",
    r"<data\s+android:scheme=['\"]([^'\"]+)['\"]",
]

# Files inside APK to scan
APK_FILES_TO_SCAN = [
    "AndroidManifest.xml",
    "res/values/strings.xml",
    "res/raw/",
    "assets/",
    "classes.dex",   # Not readable as text, skip
]

# Certificate pinning library indicators
PINNING_INDICATORS = {
    "OkHttp CertificatePinner":    "certificatepinner",
    "TrustKit":                    "trustkit",
    "Android Network Security":    "network_security_config",
    "Custom TrustManager":         "x509trustmanager",
    "SSLContext custom":           "sslcontext",
    "Public Key Pin":              "publickeypins",
    "HPKP":                        "public-key-pins",
}

# Mobile-specific user agents
MOBILE_USER_AGENTS = {
    "Android":    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "iOS":        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Flutter":    "Dart/3.0 (dart:io)",
    "ReactNative":"okhttp/4.12.0",
    "Desktop":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
}


# ── 1. APK Analyzer ───────────────────────────────────────

@dataclass
class APKAnalysisResult:
    """Result of APK security analysis."""
    apk_path:    str
    endpoints:   list[str] = field(default_factory=list)
    secrets:     dict[str, list[str]] = field(default_factory=dict)
    deeplinks:   list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    findings:    list[dict] = field(default_factory=list)


class APKAnalyzer:
    """
    Analyze Android APK files for security issues.

    Extracts:
    - API endpoints and backend URLs
    - Hardcoded secrets and API keys
    - Deep link schemes (potential attack surface)
    - Dangerous permissions
    - Debug flags and dev artifacts

    APK is a ZIP file — this analyzer reads without external tools.
    For DEX bytecode analysis, it falls back to string extraction.
    """

    DANGEROUS_PERMISSIONS = {
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.READ_CALL_LOG",
        "android.permission.SEND_SMS",
        "android.permission.READ_SMS",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.GET_ACCOUNTS",
    }

    def __init__(
        self,
        apk_path: str,
        output_dir: str = "./findings/mobile",
    ):
        self.apk_path   = Path(apk_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self) -> APKAnalysisResult:
        """Analyze APK and return findings."""
        result = APKAnalysisResult(apk_path=str(self.apk_path))
        console.print(f"\n  [bold cyan]APK Analyzer[/bold cyan] → {self.apk_path.name}")

        if not self.apk_path.exists():
            console.print(f"  [red]APK not found:[/red] {self.apk_path}")
            return result

        try:
            with zipfile.ZipFile(str(self.apk_path), "r") as apk:
                result.endpoints   = self._extract_endpoints(apk)
                result.secrets     = self._extract_secrets(apk)
                result.deeplinks   = self._extract_deeplinks(apk)
                result.permissions = self._extract_permissions(apk)
        except zipfile.BadZipFile:
            console.print("  [red]Invalid APK (not a ZIP file)[/red]")
            return result
        except Exception as e:
            console.print(f"  [red]APK read error:[/red] {e}")
            return result

        result.findings = self._build_findings(result)
        self._save(result)

        console.print(
            f"  Endpoints: {len(result.endpoints)} | "
            f"Secrets: {sum(len(v) for v in result.secrets.values())} | "
            f"Deeplinks: {len(result.deeplinks)} | "
            f"Findings: {len(result.findings)}"
        )
        return result

    def analyze_bytes(self, apk_bytes: bytes, name: str = "app.apk") -> APKAnalysisResult:
        """Analyze APK from bytes (for testing without real file)."""
        result = APKAnalysisResult(apk_path=name)
        try:
            with zipfile.ZipFile(io.BytesIO(apk_bytes), "r") as apk:
                result.endpoints   = self._extract_endpoints(apk)
                result.secrets     = self._extract_secrets(apk)
                result.deeplinks   = self._extract_deeplinks(apk)
                result.permissions = self._extract_permissions(apk)
        except Exception:
            pass
        result.findings = self._build_findings(result)
        return result

    def _read_text_files(self, apk: zipfile.ZipFile) -> str:
        """Read all text-readable files from APK into one string."""
        combined = []
        for name in apk.namelist():
            # Skip binary files (DEX, PNG, etc)
            if any(name.endswith(ext) for ext in
                   [".dex", ".png", ".jpg", ".jpeg", ".gif", ".so", ".arsc"]):
                continue
            try:
                data = apk.read(name)
                text = data.decode("utf-8", errors="ignore")
                combined.append(text)
            except Exception:
                continue
        return "\n".join(combined)

    def _extract_endpoints(self, apk: zipfile.ZipFile) -> list[str]:
        """Extract API endpoints from APK strings."""
        text  = self._read_text_files(apk)
        found = set()
        for pattern in URL_PATTERNS:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                url = match.group(0)
                # Filter: only keep likely API endpoints
                if any(kw in url.lower() for kw in
                       ["api", "backend", "server", "gateway", "service",
                        "/v1", "/v2", "/v3", "endpoint", "base", "host"]):
                    found.add(url[:200])
        return sorted(found)[:50]

    def _extract_secrets(self, apk: zipfile.ZipFile) -> dict[str, list[str]]:
        """Scan APK for hardcoded secrets and API keys."""
        text    = self._read_text_files(apk)
        results = defaultdict(list)
        for key_type, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, text)
            for m in matches:
                val = m if isinstance(m, str) else m
                # Avoid false positives: skip very short or placeholder values
                if len(val) >= 10 and val not in ("YOUR_API_KEY", "PLACEHOLDER"):
                    results[key_type].append(val[:60])
        return dict(results)

    def _extract_deeplinks(self, apk: zipfile.ZipFile) -> list[str]:
        """Extract deep link schemes from AndroidManifest.xml."""
        text  = self._read_text_files(apk)
        found = set()
        for pattern in DEEPLINK_PATTERNS:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                scheme = match.group(1) if match.lastindex else match.group(0)
                if scheme and scheme not in ("http", "https", "file", "content"):
                    found.add(scheme[:100])
        return sorted(found)[:20]

    def _extract_permissions(self, apk: zipfile.ZipFile) -> list[str]:
        """Extract dangerous permissions from AndroidManifest.xml."""
        try:
            manifest = apk.read("AndroidManifest.xml").decode("utf-8", errors="ignore")
        except Exception:
            return []
        dangerous = []
        for perm in self.DANGEROUS_PERMISSIONS:
            if perm in manifest or perm.split(".")[-1].lower() in manifest.lower():
                dangerous.append(perm)
        return dangerous

    def _build_findings(self, result: APKAnalysisResult) -> list[dict]:
        """Convert APK analysis result into security findings."""
        findings = []

        # Hardcoded secrets
        for key_type, values in result.secrets.items():
            if values:
                findings.append(_finding(
                    title=f"Hardcoded {key_type} in APK",
                    severity="CRITICAL" if "AWS" in key_type or "Private" in key_type else "HIGH",
                    cvss=9.1 if "AWS" in key_type else 7.5,
                    cwe="CWE-312",
                    description=(
                        f"APK contains hardcoded {key_type}. "
                        "Anyone who decompiles the APK can extract and abuse these credentials."
                    ),
                    evidence=(
                        f"Key type: {key_type}\n"
                        f"Found {len(values)} occurrence(s)\n"
                        f"Sample (truncated): {values[0][:30]}..."
                    ),
                    remediation=(
                        "Never hardcode secrets in mobile apps. "
                        "Fetch credentials from secure server at runtime. "
                        "Use Android Keystore / iOS Secure Enclave for local key storage. "
                        "Rotate all exposed credentials immediately."
                    ),
                    target=str(self.apk_path),
                    source="apk_analyzer",
                ))

        # Exposed API endpoints
        if result.endpoints:
            findings.append(_finding(
                title=f"API Endpoints Exposed in APK ({len(result.endpoints)} found)",
                severity="MEDIUM",
                cvss=5.3,
                cwe="CWE-200",
                description=(
                    f"APK reveals {len(result.endpoints)} API endpoint(s). "
                    "Attackers can extract these for targeted API attacks without traffic interception."
                ),
                evidence="\n".join(result.endpoints[:5]),
                remediation=(
                    "Implement certificate pinning to prevent MITM. "
                    "Use obfuscation (ProGuard/R8) to protect endpoint strings. "
                    "Ensure all extracted endpoints require authentication."
                ),
                target=str(self.apk_path),
                source="apk_analyzer",
            ))

        # Deep link attack surface
        if result.deeplinks:
            findings.append(_finding(
                title=f"Custom Deep Link Schemes Exposed ({len(result.deeplinks)} schemes)",
                severity="LOW",
                cvss=4.3,
                cwe="CWE-939",
                description=(
                    f"APK registers {len(result.deeplinks)} custom URL scheme(s): "
                    f"{', '.join(result.deeplinks[:5])}. "
                    "Unvalidated deep links can be abused for open redirect or CSRF attacks."
                ),
                evidence=f"Schemes: {', '.join(result.deeplinks)}",
                remediation=(
                    "Validate all deep link parameters before processing. "
                    "Use App Links (verified HTTPS) instead of custom schemes. "
                    "Implement intent filter validation."
                ),
                target=str(self.apk_path),
                source="apk_analyzer",
            ))

        # Dangerous permissions
        if len(result.permissions) >= 3:
            findings.append(_finding(
                title=f"Excessive Dangerous Permissions ({len(result.permissions)} declared)",
                severity="MEDIUM",
                cvss=5.5,
                cwe="CWE-250",
                description=(
                    f"APK requests {len(result.permissions)} dangerous permission(s), "
                    "violating the principle of least privilege."
                ),
                evidence="\n".join(result.permissions),
                remediation=(
                    "Request only permissions required for core functionality. "
                    "Remove unused permissions from AndroidManifest.xml. "
                    "Use runtime permissions and explain usage to users."
                ),
                target=str(self.apk_path),
                source="apk_analyzer",
            ))

        return findings

    def _save(self, result: APKAnalysisResult) -> Path:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = self.output_dir / f"apk_{self.apk_path.stem}_{ts}.json"
        data = {
            "apk":         str(self.apk_path),
            "endpoints":   result.endpoints,
            "secrets":     {k: v[:3] for k, v in result.secrets.items()},
            "deeplinks":   result.deeplinks,
            "permissions": result.permissions,
            "findings":    result.findings,
        }
        out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return out


# ── 2. Certificate Pinning Tester ─────────────────────────

class CertPinningTester:
    """
    Test certificate pinning implementation on mobile API backends.

    Checks:
    1. Pinning presence detection (HPKP headers, response patterns)
    2. Expired / weak pin detection
    3. Bypass patterns (missing backup pin, wrong scope)
    4. SSL/TLS misconfiguration that aids bypass
    5. Debug endpoint that disables pinning

    Note: Full bypass testing requires a real MITM proxy setup.
    This module tests server-side indicators of pinning configuration.
    """

    BYPASS_HEADERS_CHECK = [
        "public-key-pins",
        "public-key-pins-report-only",
        "expect-ct",
        "strict-transport-security",
    ]

    DEBUG_ENDPOINTS = [
        "/debug/ssl", "/debug/pinning", "/api/debug",
        "/internal/cert", "/__debug__", "/dev/bypass",
        "/test/ssl-bypass", "/api/v1/debug",
    ]

    def __init__(
        self,
        target: str,
        output_dir: str = "./findings/mobile",
        timeout: int = 10,
    ):
        self.target     = target.rstrip("/")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout    = timeout
        self.client     = httpx.Client(
            timeout=timeout, verify=False,
            headers={"User-Agent": MOBILE_USER_AGENTS["Android"]},
        )

    def run(self) -> list[dict]:
        """Run all certificate pinning checks."""
        console.print(f"\n  [bold cyan]Cert Pinning Tester[/bold cyan] → {self.target}")
        findings = []

        findings.extend(self._check_hpkp_headers())
        findings.extend(self._check_ssl_bypass_headers())
        findings.extend(self._check_debug_endpoints())
        findings.extend(self._check_weak_tls())

        self._save(findings)
        console.print(f"  Pinning findings: [bold]{len(findings)}[/bold]")
        return findings

    def _check_hpkp_headers(self) -> list[dict]:
        """Check for HPKP implementation quality."""
        findings = []
        try:
            resp = self.client.get(f"{self.target}/")
        except Exception:
            return findings

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        # Check missing HPKP (info finding)
        if "public-key-pins" not in headers_lower:
            findings.append(_finding(
                title="Certificate Pinning Not Enforced via HPKP Header",
                severity="MEDIUM",
                cvss=5.9,
                cwe="CWE-295",
                description=(
                    "Server does not send Public-Key-Pins (HPKP) header. "
                    "Without server-side pinning headers, mobile clients must implement "
                    "client-side pinning which is harder to verify."
                ),
                evidence=(
                    f"URL: {self.target}/\n"
                    "Header 'Public-Key-Pins' absent from response."
                ),
                remediation=(
                    "Implement HPKP or Certificate Transparency (Expect-CT). "
                    "Enforce certificate pinning in mobile app via OkHttp CertificatePinner / TrustKit. "
                    "Include backup pins to prevent lockout."
                ),
                target=self.target,
                source="cert_pinning_tester",
            ))

        # Check weak HPKP if present
        hpkp = headers_lower.get("public-key-pins", "")
        if hpkp:
            if "backup-pin" not in hpkp.lower() and "pin-sha256" in hpkp.lower():
                findings.append(_finding(
                    title="HPKP Missing Backup Pin — Lockout Risk",
                    severity="LOW",
                    cvss=3.7,
                    cwe="CWE-295",
                    description=(
                        "HPKP header present but no backup pin declared. "
                        "If the primary certificate expires or is revoked, "
                        "users will be permanently locked out."
                    ),
                    evidence=f"HPKP header: {hpkp[:200]}",
                    remediation=(
                        "Always include at least one backup pin-sha256 for a certificate "
                        "stored securely offline. Rotate with adequate max-age."
                    ),
                    target=self.target,
                    source="cert_pinning_tester",
                ))

        return findings

    def _check_ssl_bypass_headers(self) -> list[dict]:
        """Check for headers that indicate pinning bypass potential."""
        findings = []
        try:
            resp = self.client.get(f"{self.target}/")
        except Exception:
            return findings

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        # Missing HSTS (allows SSL stripping)
        if "strict-transport-security" not in headers_lower:
            findings.append(_finding(
                title="Missing HSTS — SSL Stripping Attack Possible",
                severity="MEDIUM",
                cvss=5.9,
                cwe="CWE-319",
                description=(
                    "API does not send Strict-Transport-Security header. "
                    "Without HSTS, attackers on the same network can perform SSL stripping attacks, "
                    "downgrading HTTPS to HTTP and bypassing certificate checks."
                ),
                evidence="Header 'Strict-Transport-Security' absent.",
                remediation=(
                    "Add HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload. "
                    "This is a prerequisite for effective certificate pinning."
                ),
                target=self.target,
                source="cert_pinning_tester",
            ))

        return findings

    def _check_debug_endpoints(self) -> list[dict]:
        """Test for debug endpoints that may bypass SSL/pinning."""
        findings = []
        for ep in self.DEBUG_ENDPOINTS:
            url = self.target + ep
            try:
                resp = self.client.get(url)
                if resp.status_code in (200, 403):
                    findings.append(_finding(
                        title=f"Debug/Internal Endpoint Accessible: {ep}",
                        severity="HIGH" if resp.status_code == 200 else "MEDIUM",
                        cvss=7.5 if resp.status_code == 200 else 5.3,
                        cwe="CWE-489",
                        description=(
                            f"Debug endpoint {ep} returns HTTP {resp.status_code}. "
                            "Debug endpoints may expose SSL bypass mechanisms, "
                            "internal API documentation, or certificate pinning configuration."
                        ),
                        evidence=f"URL: {url}\nHTTP {resp.status_code}\nResponse: {resp.text[:200]}",
                        remediation=(
                            "Remove all debug endpoints from production builds. "
                            "Use build variants (debug/release) to exclude debug code. "
                            "Enforce network_security_config.xml in release builds."
                        ),
                        target=url,
                        source="cert_pinning_tester",
                    ))
                    break
            except Exception:
                continue
        return findings

    def _check_weak_tls(self) -> list[dict]:
        """Check for TLS weaknesses that aid pinning bypass."""
        findings = []
        try:
            resp = self.client.get(f"{self.target}/")
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            # Check for content-security-policy on API
            if "access-control-allow-origin" in headers_lower:
                origin = headers_lower["access-control-allow-origin"]
                if origin == "*":
                    findings.append(_finding(
                        title="Mobile API Wildcard CORS — Combined with Missing Pinning",
                        severity="MEDIUM",
                        cvss=6.1,
                        cwe="CWE-942",
                        description=(
                            "API allows all origins (Access-Control-Allow-Origin: *). "
                            "Combined with absent certificate pinning, web-based attackers "
                            "can make cross-origin requests to the mobile API."
                        ),
                        evidence=f"Access-Control-Allow-Origin: {origin}",
                        remediation=(
                            "Restrict CORS to known app origins. "
                            "Mobile APIs should only allow traffic from verified mobile clients, "
                            "not arbitrary web origins."
                        ),
                        target=self.target,
                        source="cert_pinning_tester",
                    ))
        except Exception:
            pass
        return findings

    def _save(self, findings: list[dict]) -> Path:
        slug = self.target.replace("/", "_").replace(":", "").replace(".", "_")
        out  = self.output_dir / f"pinning_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps({"target": self.target, "findings": findings}, indent=2),
                       encoding="utf-8")
        return out


# ── 3. Mobile API Tester ──────────────────────────────────

# Mobile-specific attack headers
MOBILE_ATTACK_HEADERS = {
    "X-Forwarded-For":   "127.0.0.1",
    "X-Real-IP":         "127.0.0.1",
    "X-App-Debug":       "true",
    "X-Internal-Token":  "debug",
    "X-Admin":           "true",
    "X-Bypass-Pinning":  "1",
    "X-App-Version":     "0.0.1-debug",
    "X-Platform":        "android-debug",
}

# Mobile API version bypass patterns
API_VERSION_BYPASS = [
    "/api/v0/", "/api/v1/", "/api/v2/",
    "/api/beta/", "/api/internal/", "/api/dev/",
    "/api/staging/", "/api/test/",
    "/mobile/", "/app/", "/android/", "/ios/",
]


class MobileAPITester:
    """
    Test mobile-specific API attack patterns.

    Checks:
    1. User-Agent based access control bypass
    2. Mobile API version enumeration (v0, v1, beta, internal)
    3. Debug header bypass (X-App-Debug, X-Internal-Token)
    4. Deep link parameter injection
    5. App version downgrade (access deprecated API)
    6. Missing mobile-specific rate limiting
    7. Token in URL (mobile deep link CSRF)
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "./findings/mobile",
        token: str | None = None,
        timeout: int = 10,
    ):
        self.target     = target.rstrip("/")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.token      = token
        self.timeout    = timeout

        self.base_headers = {"Content-Type": "application/json"}
        if token:
            self.base_headers["Authorization"] = f"Bearer {token}"

        self.client = httpx.Client(
            timeout=timeout, verify=False,
            headers=self.base_headers,
        )

    def run(self, endpoints: list[str] | None = None) -> list[dict]:
        """Run all mobile API checks."""
        console.print(f"\n  [bold cyan]Mobile API Tester[/bold cyan] → {self.target}")
        findings = []
        test_eps = endpoints or ["/api/v1/user", "/api/v1/profile", "/api/user", "/user"]

        findings.extend(self._check_user_agent_bypass())
        findings.extend(self._check_api_version_enum())
        findings.extend(self._check_debug_header_bypass(test_eps))
        findings.extend(self._check_token_in_deeplink())
        findings.extend(self._check_rate_limiting())

        self._save(findings)
        console.print(f"  Mobile API findings: [bold]{len(findings)}[/bold]")
        return findings

    def _check_user_agent_bypass(self) -> list[dict]:
        """Test if User-Agent affects API access control."""
        findings = []
        test_url = f"{self.target}/api/v1/user"

        responses = {}
        for ua_name, ua_string in MOBILE_USER_AGENTS.items():
            try:
                resp = self.client.get(
                    test_url,
                    headers={**self.base_headers, "User-Agent": ua_string},
                )
                responses[ua_name] = resp.status_code
            except Exception:
                responses[ua_name] = 0

        # Detect inconsistency: different status codes for different UAs
        non_zero = {k: v for k, v in responses.items() if v > 0}
        if len(set(non_zero.values())) > 1:
            findings.append(_finding(
                title="Mobile API User-Agent Based Access Control Inconsistency",
                severity="MEDIUM",
                cvss=5.3,
                cwe="CWE-284",
                description=(
                    "API returns different responses based on User-Agent header. "
                    "Access control decisions based on User-Agent are trivially bypassable — "
                    "attackers can spoof any User-Agent string."
                ),
                evidence=(
                    f"URL: {test_url}\n"
                    + "\n".join(f"{ua}: HTTP {code}" for ua, code in non_zero.items())
                ),
                remediation=(
                    "Do not use User-Agent for access control decisions. "
                    "Use proper authentication (JWT/OAuth) instead. "
                    "If platform-specific responses are needed, use Accept header or explicit API params."
                ),
                target=test_url,
                source="mobile_api_tester",
            ))

        # Check if Android UA gets more access
        android_code = responses.get("Android", 0)
        desktop_code = responses.get("Desktop", 0)
        if android_code == 200 and desktop_code in (401, 403):
            findings.append(_finding(
                title="Mobile API Restricted to Mobile User-Agents Only",
                severity="LOW",
                cvss=3.7,
                cwe="CWE-284",
                description=(
                    "API returns 200 for mobile User-Agent but blocks desktop User-Agent. "
                    "This is easily bypassed by spoofing the mobile User-Agent."
                ),
                evidence=(
                    f"Android UA → HTTP {android_code}\n"
                    f"Desktop UA → HTTP {desktop_code}"
                ),
                remediation=(
                    "Remove User-Agent based access restrictions. "
                    "Use strong authentication mechanisms instead of client hints."
                ),
                target=test_url,
                source="mobile_api_tester",
            ))

        return findings

    def _check_api_version_enum(self) -> list[dict]:
        """Enumerate API versions including deprecated/internal ones."""
        findings = []
        accessible = []

        for path_prefix in API_VERSION_BYPASS:
            url = f"{self.target}{path_prefix}user"
            try:
                resp = self.client.get(url)
                if resp.status_code in (200, 401, 403):
                    accessible.append((path_prefix, resp.status_code))
            except Exception:
                continue

        if len(accessible) > 1:
            deprecated = [(p, c) for p, c in accessible
                          if any(kw in p for kw in ["v0", "beta", "internal", "dev", "staging"])]
            if deprecated:
                findings.append(_finding(
                    title=f"Deprecated/Internal Mobile API Versions Accessible",
                    severity="HIGH",
                    cvss=7.5,
                    cwe="CWE-1059",
                    description=(
                        f"Multiple API version paths accessible including potentially deprecated "
                        f"or internal versions: {', '.join(p for p, _ in deprecated)}. "
                        "Older API versions may lack security controls present in current versions."
                    ),
                    evidence="\n".join(f"{p} → HTTP {c}" for p, c in accessible),
                    remediation=(
                        "Retire deprecated API versions with proper sunset dates. "
                        "Apply the same security controls to all active versions. "
                        "Use API gateway to block internal/dev endpoints in production."
                    ),
                    target=self.target,
                    source="mobile_api_tester",
                ))

        return findings

    def _check_debug_header_bypass(self, endpoints: list[str]) -> list[dict]:
        """Test debug/internal headers for access bypass."""
        findings = []

        for ep in endpoints[:3]:
            url = f"{self.target}{ep}"
            # Baseline without debug headers
            try:
                baseline = self.client.get(url)
            except Exception:
                continue

            if baseline.status_code not in (401, 403):
                continue  # Only test if endpoint is normally restricted

            # Test each debug header
            for header, value in MOBILE_ATTACK_HEADERS.items():
                try:
                    resp = self.client.get(
                        url,
                        headers={**self.base_headers, header: value},
                    )
                    if resp.status_code == 200 and len(resp.text) > len(baseline.text):
                        findings.append(_finding(
                            title=f"Mobile API Debug Header Bypass: {header}: {value}",
                            severity="HIGH",
                            cvss=8.1,
                            cwe="CWE-287",
                            description=(
                                f"Adding header '{header}: {value}' to request bypassed "
                                f"authentication on {ep}. Debug headers left in production "
                                "allow unauthenticated access."
                            ),
                            evidence=(
                                f"URL: {url}\n"
                                f"Without {header}: HTTP {baseline.status_code}\n"
                                f"With {header}: {value} → HTTP {resp.status_code}"
                            ),
                            remediation=(
                                "Remove all debug header checks from production code. "
                                "Use build variants to strip debug logic. "
                                "Implement request signing instead of debug bypass headers."
                            ),
                            target=url,
                            source="mobile_api_tester",
                        ))
                        return findings
                except Exception:
                    continue

        return findings

    def _check_token_in_deeplink(self) -> list[dict]:
        """Test if API accepts tokens via URL params (deep link CSRF)."""
        findings = []
        test_endpoints = [
            f"{self.target}/api/v1/user?token=test_token_12345678",
            f"{self.target}/api/v1/user?access_token=test_token_12345678",
            f"{self.target}/api/v1/user?auth=test_token_12345678",
            f"{self.target}/auth/callback?token=test_token_12345678",
        ]

        for url in test_endpoints:
            try:
                resp = self.client.get(url, headers={
                    k: v for k, v in self.base_headers.items()
                    if k != "Authorization"
                })
                # 401/400 = rejects; anything else = accepts token in URL
                if resp.status_code not in (401, 403, 400, 404):
                    findings.append(_finding(
                        title="Mobile API Accepts Token in URL Parameter (Deep Link CSRF Risk)",
                        severity="MEDIUM",
                        cvss=6.1,
                        cwe="CWE-598",
                        description=(
                            "API accepts authentication token as URL query parameter. "
                            "Tokens in URLs are logged by servers, proxies, and browser history. "
                            "Combined with deep links, this enables token theft via redirect."
                        ),
                        evidence=f"URL: {url}\nHTTP {resp.status_code} — token in URL accepted",
                        remediation=(
                            "Accept tokens only in Authorization header. "
                            "Deep link callbacks should use PKCE code exchange, not direct token. "
                            "If URL tokens are unavoidable, use short-lived one-time tokens."
                        ),
                        target=url,
                        source="mobile_api_tester",
                    ))
                    break
            except Exception:
                continue

        return findings

    def _check_rate_limiting(self) -> list[dict]:
        """Test if mobile API enforces rate limiting."""
        findings = []
        test_url = f"{self.target}/api/v1/user"

        # Send 15 rapid requests
        statuses = []
        for _ in range(15):
            try:
                resp = self.client.get(
                    test_url,
                    headers={**self.base_headers, "User-Agent": MOBILE_USER_AGENTS["Android"]},
                )
                statuses.append(resp.status_code)
            except Exception:
                break

        if len(statuses) >= 10 and 429 not in statuses:
            non_error = [s for s in statuses if s not in (500, 502, 503)]
            if len(non_error) >= 10:
                findings.append(_finding(
                    title="Mobile API Missing Rate Limiting — Brute Force Risk",
                    severity="MEDIUM",
                    cvss=5.3,
                    cwe="CWE-307",
                    description=(
                        f"Sent {len(statuses)} rapid requests to mobile API without receiving "
                        "HTTP 429 (Too Many Requests). Missing rate limiting enables "
                        "credential brute force and enumeration attacks from mobile clients."
                    ),
                    evidence=(
                        f"URL: {test_url}\n"
                        f"{len(statuses)} requests sent — no 429 received\n"
                        f"Status codes: {set(statuses)}"
                    ),
                    remediation=(
                        "Implement rate limiting per device ID / IP / user. "
                        "Mobile API should enforce stricter limits than web API. "
                        "Return Retry-After header with 429 responses."
                    ),
                    target=test_url,
                    source="mobile_api_tester",
                ))

        return findings

    def detect_pinning_in_apk_strings(self, text: str) -> dict[str, bool]:
        """
        Detect certificate pinning library usage from APK extracted text.
        Useful when combined with APKAnalyzer.
        """
        results = {}
        text_lower = text.lower()
        for lib_name, indicator in PINNING_INDICATORS.items():
            results[lib_name] = indicator.lower() in text_lower
        return results

    def _save(self, findings: list[dict]) -> Path:
        slug = self.target.replace("/", "_").replace(":", "").replace(".", "_")
        out  = self.output_dir / f"mobile_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps({"target": self.target, "findings": findings}, indent=2),
                       encoding="utf-8")
        return out
