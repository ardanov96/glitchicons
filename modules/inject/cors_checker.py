"""
CORS Checker — modules/inject/cors_checker.py

Checks:
  1.  Wildcard origin          — ACAO: * on credentialed endpoints
  2.  Reflected origin         — server mirrors any Origin back
  3.  Null origin              — server accepts Origin: null
  4.  Pre-domain bypass        — evil.target.com accepted
  5.  Post-domain bypass       — target.com.evil.com accepted
  6.  Subdomain wildcard       — *.target.com without restriction
  7.  HTTP downgrade           — HTTPS target accepts HTTP Origin
  8.  Credentials + wildcard   — ACAO: * with ACAC: true (forbidden combo)
  9.  Sensitive endpoint CORS  — /api/user /api/admin /api/me exposed
  10. Preflight bypass         — non-standard methods skip preflight

Requires: httpx (already in requirements.txt)

Usage:
    python3 glitchicons.py cors https://target.com
    python3 glitchicons.py cors https://target.com --output ./findings/cors

Author: ardanov96
"""

import time
import json
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
import httpx

console = Console()


# ── Constants ─────────────────────────────────────────────

SENSITIVE_ENDPOINTS = [
    "/api/user",
    "/api/users",
    "/api/me",
    "/api/account",
    "/api/profile",
    "/api/admin",
    "/api/dashboard",
    "/api/settings",
    "/api/v1/user",
    "/api/v1/me",
    "/api/v2/user",
    "/graphql",
    "/auth/token",
    "/auth/refresh",
]

CORS_HEADERS = {
    "allow_origin":      "access-control-allow-origin",
    "allow_credentials": "access-control-allow-credentials",
    "allow_methods":     "access-control-allow-methods",
    "allow_headers":     "access-control-allow-headers",
    "expose_headers":    "access-control-expose-headers",
    "max_age":           "access-control-max-age",
}

SEVERITY_MAP = {
    "reflected_with_credentials":  ("CRITICAL", 9.3, "CWE-942"),
    "null_with_credentials":       ("CRITICAL", 9.1, "CWE-942"),
    "wildcard_with_credentials":   ("CRITICAL", 9.0, "CWE-942"),
    "reflected_no_credentials":    ("HIGH",     7.5, "CWE-942"),
    "subdomain_wildcard":          ("HIGH",     7.4, "CWE-942"),
    "post_domain_bypass":          ("HIGH",     7.2, "CWE-942"),
    "pre_domain_bypass":           ("HIGH",     7.0, "CWE-942"),
    "null_no_credentials":         ("MEDIUM",   5.4, "CWE-942"),
    "http_downgrade":              ("MEDIUM",   5.0, "CWE-319"),
    "wildcard_public":             ("LOW",      3.1, "CWE-942"),
    "preflight_bypass":            ("MEDIUM",   5.3, "CWE-942"),
    "sensitive_endpoint_cors":     ("HIGH",     7.5, "CWE-942"),
}


# ── CORS Response parser ──────────────────────────────────

class CORSResponse:
    """Parse and expose CORS headers from an HTTP response."""

    def __init__(self, response: httpx.Response):
        self.status_code = response.status_code
        self.headers = {k.lower(): v for k, v in response.headers.items()}

    @property
    def allow_origin(self) -> str | None:
        return self.headers.get("access-control-allow-origin")

    @property
    def allow_credentials(self) -> bool:
        return self.headers.get("access-control-allow-credentials", "").lower() == "true"

    @property
    def allow_methods(self) -> str | None:
        return self.headers.get("access-control-allow-methods")

    @property
    def allow_headers(self) -> str | None:
        return self.headers.get("access-control-allow-headers")

    @property
    def is_wildcard(self) -> bool:
        return self.allow_origin == "*"

    @property
    def has_cors(self) -> bool:
        return self.allow_origin is not None

    def reflects_origin(self, origin: str) -> bool:
        return self.allow_origin == origin

    def to_dict(self) -> dict:
        return {
            "allow_origin":      self.allow_origin,
            "allow_credentials": self.allow_credentials,
            "allow_methods":     self.allow_methods,
            "allow_headers":     self.allow_headers,
        }


# ── Main checker ──────────────────────────────────────────

class CORSChecker:
    """
    Comprehensive CORS misconfiguration checker.

    Covers OWASP API Security and Web Security:
    - CWE-942: Overly Permissive Cross-domain Whitelist
    - CWE-319: Cleartext Transmission (HTTP downgrade)
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "./findings/cors",
        timeout: int = 8,
        delay: float = 0.3,
        cookies: dict | None = None,
        token: str | None = None,
    ):
        self.target = target.rstrip("/")
        self.output_dir = Path(output_dir)
        self.timeout = timeout
        self.delay = delay
        self.cookies = cookies or {}
        self.token = token
        self.findings: list[dict] = []
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Extract domain for crafting bypass Origins
        self.domain = self._extract_domain(target)

    def run(self) -> list[dict]:
        """Run all CORS checks. Return list of findings."""
        console.print(f"\n[bold cyan]  GLITCHICONS CORS Checker[/bold cyan]")
        console.print(f"  Target : [yellow]{self.target}[/yellow]")
        console.print(f"  Domain : {self.domain}\n")

        checks = [
            ("Wildcard Origin",          self._check_wildcard),
            ("Reflected Origin",         self._check_reflected_origin),
            ("Null Origin",              self._check_null_origin),
            ("Pre-domain Bypass",        self._check_pre_domain),
            ("Post-domain Bypass",       self._check_post_domain),
            ("HTTP Downgrade",           self._check_http_downgrade),
            ("Credentials + Wildcard",   self._check_credentials_wildcard),
            ("Sensitive Endpoints",      self._check_sensitive_endpoints),
            ("Preflight Bypass",         self._check_preflight_bypass),
        ]

        for name, fn in checks:
            console.print(f"  [cyan]>> {name}...[/cyan]", end=" ")
            try:
                count_before = len(self.findings)
                fn()
                new = len(self.findings) - count_before
                if new > 0:
                    console.print(f"[red]{new} finding(s)[/red]")
                else:
                    console.print(f"[green]clean[/green]")
            except Exception as e:
                console.print(f"[yellow]error: {e}[/yellow]")
            time.sleep(self.delay)

        self._print_summary()
        self._save_report()
        return self.findings

    # ── Check Methods ─────────────────────────────────────

    def _check_wildcard(self):
        """ACAO: * — dangerous if endpoint returns sensitive data."""
        cors = self._send(self.target, origin="https://evil.com")
        if not cors:
            return

        if cors.is_wildcard:
            # Wildcard + credentials is forbidden by spec but some servers do it
            vuln_type = "wildcard_with_credentials" if cors.allow_credentials else "wildcard_public"
            sev, cvss, cwe = SEVERITY_MAP[vuln_type]
            self._add_finding(
                title="CORS Wildcard Origin Allowed",
                severity=sev,
                cvss=cvss,
                cwe=cwe,
                description=(
                    f"Server responds with Access-Control-Allow-Origin: * "
                    f"{'AND Access-Control-Allow-Credentials: true (browsers reject this but may indicate misconfiguration)' if cors.allow_credentials else ''}. "
                    f"Any website can read responses from this endpoint."
                ),
                evidence=self._format_evidence(cors, "https://evil.com"),
                remediation=(
                    "Replace wildcard with an explicit allowlist of trusted origins. "
                    "Never combine ACAO: * with ACAC: true."
                ),
                endpoint=self.target,
            )

    def _check_reflected_origin(self):
        """Server mirrors any Origin back — most critical CORS bug."""
        test_origins = [
            "https://evil.com",
            "https://notreallytarget.com",
            "https://attacker.io",
        ]
        for origin in test_origins:
            cors = self._send(self.target, origin=origin)
            if not cors:
                continue

            if cors.reflects_origin(origin):
                vuln_type = (
                    "reflected_with_credentials" if cors.allow_credentials
                    else "reflected_no_credentials"
                )
                sev, cvss, cwe = SEVERITY_MAP[vuln_type]
                self._add_finding(
                    title="CORS Reflected Origin — Arbitrary Origin Accepted",
                    severity=sev,
                    cvss=cvss,
                    cwe=cwe,
                    description=(
                        f"Server reflects the Origin header back as "
                        f"Access-Control-Allow-Origin without validation. "
                        f"{'With credentials enabled, this allows full cross-origin account takeover.' if cors.allow_credentials else 'Attackers can read API responses from any domain.'}"
                    ),
                    evidence=self._format_evidence(cors, origin),
                    remediation=(
                        "Validate Origin against a strict server-side allowlist. "
                        "Never use request.headers['Origin'] directly as ACAO value. "
                        "If credentials are needed, explicitly list allowed origins."
                    ),
                    endpoint=self.target,
                )
                return  # One finding is enough

    def _check_null_origin(self):
        """Origin: null — accepted by some servers, exploitable via sandboxed iframes."""
        cors = self._send(self.target, origin="null")
        if not cors:
            return

        if cors.allow_origin == "null":
            vuln_type = "null_with_credentials" if cors.allow_credentials else "null_no_credentials"
            sev, cvss, cwe = SEVERITY_MAP[vuln_type]
            self._add_finding(
                title="CORS Null Origin Accepted",
                severity=sev,
                cvss=cvss,
                cwe=cwe,
                description=(
                    f"Server accepts Origin: null. "
                    f"Attackers can exploit this via sandboxed iframes "
                    f"('<iframe sandbox=\"allow-scripts\" src=\"data:text/html,...\">') "
                    f"to read responses"
                    + (" with user credentials." if cors.allow_credentials else ".")
                ),
                evidence=self._format_evidence(cors, "null"),
                remediation=(
                    "Never allow null Origin in production. "
                    "Treat null Origin as untrusted and reject it."
                ),
                endpoint=self.target,
            )

    def _check_pre_domain(self):
        """evil.target.com accepted — prefix bypass."""
        evil_origins = [
            f"https://evil.{self.domain}",
            f"https://notreally.{self.domain}",
            f"https://attacker.{self.domain}",
        ]
        for origin in evil_origins:
            cors = self._send(self.target, origin=origin)
            if cors and cors.reflects_origin(origin):
                sev, cvss, cwe = SEVERITY_MAP["pre_domain_bypass"]
                self._add_finding(
                    title="CORS Pre-domain Bypass",
                    severity=sev,
                    cvss=cvss,
                    cwe=cwe,
                    description=(
                        f"Server accepts arbitrary subdomains of {self.domain}. "
                        f"If any subdomain can be compromised or registered, "
                        f"it can be used to steal cross-origin data."
                    ),
                    evidence=self._format_evidence(cors, origin),
                    remediation=(
                        "Validate exact Origin values, not just domain suffix. "
                        "Use full origin comparison: 'https://app.target.com' not '*.target.com'. "
                        "Maintain an explicit allowlist of trusted subdomains."
                    ),
                    endpoint=self.target,
                )
                return

    def _check_post_domain(self):
        """target.com.evil.com accepted — suffix bypass."""
        evil_origins = [
            f"https://{self.domain}.evil.com",
            f"https://{self.domain}.attacker.io",
        ]
        for origin in evil_origins:
            cors = self._send(self.target, origin=origin)
            if cors and cors.reflects_origin(origin):
                sev, cvss, cwe = SEVERITY_MAP["post_domain_bypass"]
                self._add_finding(
                    title="CORS Post-domain Bypass",
                    severity=sev,
                    cvss=cvss,
                    cwe=cwe,
                    description=(
                        f"Server accepts Origins where the domain appears as a prefix "
                        f"(e.g., {self.domain}.evil.com). "
                        f"This is a classic regex bypass — validation checks if "
                        f"Origin 'contains' the domain instead of exact match."
                    ),
                    evidence=self._format_evidence(cors, origin),
                    remediation=(
                        "Use exact string comparison for Origin validation. "
                        "Do not use regex with 'contains' or 'endsWith' for domain matching. "
                        "Always check the full protocol + domain + port."
                    ),
                    endpoint=self.target,
                )
                return

    def _check_http_downgrade(self):
        """HTTPS target accepts HTTP Origin — protocol downgrade."""
        if not self.target.startswith("https://"):
            return

        http_origin = "http://" + self.domain
        cors = self._send(self.target, origin=http_origin)
        if cors and cors.reflects_origin(http_origin):
            sev, cvss, cwe = SEVERITY_MAP["http_downgrade"]
            self._add_finding(
                title="CORS HTTP Origin Accepted on HTTPS Endpoint",
                severity=sev,
                cvss=cvss,
                cwe=cwe,
                description=(
                    f"HTTPS endpoint accepts requests with HTTP Origin ({http_origin}). "
                    f"This enables protocol downgrade — attacker can intercept HTTP traffic "
                    f"to inject malicious content that then gets CORS access to HTTPS APIs."
                ),
                evidence=self._format_evidence(cors, http_origin),
                remediation=(
                    "Only allow HTTPS Origins in production CORS policy. "
                    "Explicitly reject http:// Origins on HTTPS endpoints. "
                    "Include protocol in Origin comparison."
                ),
                endpoint=self.target,
            )

    def _check_credentials_wildcard(self):
        """ACAO: * combined with ACAC: true — spec violation but worth flagging."""
        cors = self._send(self.target, origin="https://evil.com")
        if cors and cors.is_wildcard and cors.allow_credentials:
            sev, cvss, cwe = SEVERITY_MAP["wildcard_with_credentials"]
            self._add_finding(
                title="CORS Wildcard with Credentials Enabled",
                severity=sev,
                cvss=cvss,
                cwe=cwe,
                description=(
                    "Server sets both Access-Control-Allow-Origin: * and "
                    "Access-Control-Allow-Credentials: true. "
                    "Browsers reject this combination per spec, but it indicates "
                    "a serious CORS misconfiguration that may affect non-browser clients."
                ),
                evidence=self._format_evidence(cors, "https://evil.com"),
                remediation=(
                    "Choose one: either wildcard without credentials (for public APIs), "
                    "or explicit origin allowlist with credentials. Never both."
                ),
                endpoint=self.target,
            )

    def _check_sensitive_endpoints(self):
        """Test CORS on common sensitive API endpoints."""
        origin = "https://evil.com"
        for endpoint in SENSITIVE_ENDPOINTS:
            url = self.target + endpoint
            cors = self._send(url, origin=origin)
            if not cors:
                continue

            if cors.reflects_origin(origin) or (cors.is_wildcard and cors.allow_credentials):
                sev, cvss, cwe = SEVERITY_MAP["sensitive_endpoint_cors"]
                self._add_finding(
                    title=f"CORS Misconfiguration on Sensitive Endpoint: {endpoint}",
                    severity=sev,
                    cvss=cvss,
                    cwe=cwe,
                    description=(
                        f"Sensitive endpoint {endpoint} has a CORS misconfiguration. "
                        f"Origin '{origin}' was accepted with "
                        f"{'credentials enabled' if cors.allow_credentials else 'reflected origin'}. "
                        f"Attackers can read user account data cross-origin."
                    ),
                    evidence=self._format_evidence(cors, origin),
                    remediation=(
                        f"Apply strict CORS policy to {endpoint}. "
                        "Sensitive endpoints should only allow authenticated, "
                        "explicitly listed origins."
                    ),
                    endpoint=url,
                )
                time.sleep(self.delay)

    def _check_preflight_bypass(self):
        """Check if non-standard HTTP methods skip preflight checks."""
        bypass_methods = ["INVENTED", "HACK", "FUZZ"]

        for method in bypass_methods:
            try:
                headers = self._build_headers(origin="https://evil.com")
                resp = httpx.request(
                    method,
                    self.target,
                    headers=headers,
                    timeout=self.timeout,
                    follow_redirects=True,
                )
                cors = CORSResponse(resp)

                if cors.has_cors and cors.reflects_origin("https://evil.com"):
                    sev, cvss, cwe = SEVERITY_MAP["preflight_bypass"]
                    self._add_finding(
                        title="CORS Preflight Bypass via Non-standard Method",
                        severity=sev,
                        cvss=cvss,
                        cwe=cwe,
                        description=(
                            f"Custom HTTP method '{method}' bypasses preflight validation "
                            f"and receives CORS headers. Server may be processing "
                            f"unexpected methods without proper authorization checks."
                        ),
                        evidence=self._format_evidence(cors, "https://evil.com"),
                        remediation=(
                            "Validate CORS policy applies consistently to all HTTP methods. "
                            "Reject unknown/non-standard HTTP methods at the server level."
                        ),
                        endpoint=self.target,
                    )
                    return
            except Exception:
                continue

    # ── Helpers ───────────────────────────────────────────

    def _send(self, url: str, origin: str) -> CORSResponse | None:
        """Send request with Origin header. Return CORSResponse or None."""
        try:
            headers = self._build_headers(origin=origin)
            resp = httpx.get(
                url,
                headers=headers,
                cookies=self.cookies,
                timeout=self.timeout,
                follow_redirects=True,
            )
            return CORSResponse(resp)
        except (httpx.RequestError, httpx.TimeoutException):
            return None

    def _build_headers(self, origin: str) -> dict:
        """Build request headers with Origin and optional auth."""
        headers = {
            "Origin": origin,
            "User-Agent": "Mozilla/5.0 (Glitchicons CORS Checker)",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _format_evidence(self, cors: CORSResponse, origin: str) -> str:
        """Format CORS headers as evidence string."""
        lines = [f"Request Origin: {origin}"]
        if cors.allow_origin:
            lines.append(f"Access-Control-Allow-Origin: {cors.allow_origin}")
        if cors.allow_credentials:
            lines.append(f"Access-Control-Allow-Credentials: true")
        if cors.allow_methods:
            lines.append(f"Access-Control-Allow-Methods: {cors.allow_methods}")
        return "\n".join(lines)

    def _add_finding(
        self,
        title: str,
        severity: str,
        cvss: float,
        cwe: str,
        description: str,
        evidence: str,
        remediation: str,
        endpoint: str,
    ):
        """Add a finding if not already reported."""
        # Deduplicate by title + endpoint
        for existing in self.findings:
            if existing["title"] == title and existing["endpoint"] == endpoint:
                return

        self.findings.append({
            "id":          f"CORS-{len(self.findings) + 1:03d}",
            "title":       title,
            "severity":    severity,
            "cvss":        cvss,
            "cwe":         cwe,
            "target":      self.target,
            "endpoint":    endpoint,
            "description": description,
            "evidence":    evidence,
            "remediation": remediation,
            "timestamp":   datetime.now().isoformat(),
        })

    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract bare domain from URL."""
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        return domain.split(":")[0]  # strip port

    def _print_summary(self):
        """Print results table."""
        console.print(f"\n[bold cyan]  CORS Results — {self.target}[/bold cyan]")
        if not self.findings:
            console.print("  [green]No CORS misconfigurations found[/green]\n")
            return

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID",       style="cyan", width=10)
        table.add_column("Severity", width=10)
        table.add_column("CVSS",     width=6)
        table.add_column("Title")

        colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
        for f in sorted(self.findings, key=lambda x: x["cvss"], reverse=True):
            c = colors.get(f["severity"], "white")
            table.add_row(
                f["id"],
                f"[{c}]{f['severity']}[/{c}]",
                str(f["cvss"]),
                f["title"],
            )
        console.print(table)

    def _save_report(self):
        """Save JSON report."""
        report = {
            "tool":           "glitchicons",
            "module":         "cors_checker",
            "version":        "0.7.0",
            "target":         self.target,
            "domain":         self.domain,
            "timestamp":      datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings":       sorted(self.findings, key=lambda x: x.get("cvss", 0), reverse=True),
        }
        out = self.output_dir / f"cors_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        console.print(f"  Report: [cyan]{out}[/cyan]")
