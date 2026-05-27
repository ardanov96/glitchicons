# tests/test_grpc_fuzzer.py
"""
Unit tests untuk modules/inject/grpc_fuzzer.py
Semua network calls di-mock — tidak butuh gRPC server nyata.
"""

import json
import struct
import pytest
from pathlib import Path

from modules.inject.grpc_fuzzer import (
    GRPCFuzzer,
    GRPCTestResult,
    ProtoEncoder,
    INJECTION_PAYLOADS,
    METADATA_INJECTION,
    BOOLEAN_FLIP_VALUES,
    ENUM_ESCALATION_VALUES,
)


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def fuzzer(tmp_path):
    return GRPCFuzzer(
        target="grpc.target.example.com:443",
        output_dir=str(tmp_path / "grpc"),
        timeout=3,
        delay=0,
    )


@pytest.fixture
def authed_fuzzer(tmp_path):
    return GRPCFuzzer(
        target="grpc.target.example.com:443",
        output_dir=str(tmp_path / "grpc"),
        token="test-jwt-token-123",
        timeout=3,
        delay=0,
        insecure=False,
    )


# ── Tests: GRPCTestResult ─────────────────────────────────

class TestGRPCTestResult:

    @pytest.mark.unit
    def test_default_not_vulnerable(self):
        r = GRPCTestResult("reflection")
        assert r.vulnerable is False
        assert r.error is None

    @pytest.mark.unit
    def test_repr_safe(self):
        r = GRPCTestResult("auth_bypass")
        assert "SAFE" in repr(r)

    @pytest.mark.unit
    def test_repr_vuln(self):
        r = GRPCTestResult("injection")
        r.vulnerable = True
        assert "VULN" in repr(r)

    @pytest.mark.unit
    def test_test_name_stored(self):
        r = GRPCTestResult("metadata_injection")
        assert r.test_name == "metadata_injection"


# ── Tests: ProtoEncoder ───────────────────────────────────

class TestProtoEncoder:

    @pytest.mark.unit
    def test_encode_string_field(self):
        """String field harus encode dengan wire type 2."""
        encoded = ProtoEncoder.encode_string(1, "hello")
        assert len(encoded) > 0
        # Field 1, wire type 2: tag = (1 << 3) | 2 = 0x0a
        assert encoded[0] == 0x0a

    @pytest.mark.unit
    def test_encode_string_contains_value(self):
        """Encoded string harus mengandung value asli."""
        payload = "test payload"
        encoded = ProtoEncoder.encode_string(1, payload)
        assert payload.encode("utf-8") in encoded

    @pytest.mark.unit
    def test_encode_int_field(self):
        """Integer field harus encode dengan wire type 0."""
        encoded = ProtoEncoder.encode_int(2, 42)
        assert len(encoded) > 0
        # Field 2, wire type 0: tag = (2 << 3) | 0 = 0x10
        assert encoded[0] == 0x10

    @pytest.mark.unit
    def test_encode_bool_true(self):
        """Boolean True harus encode sebagai varint 1."""
        encoded = ProtoEncoder.encode_bool(1, True)
        # Harus ada byte 1 di payload (varint 1)
        assert b"\x01" in encoded

    @pytest.mark.unit
    def test_encode_bool_false(self):
        """Boolean False harus encode sebagai varint 0."""
        encoded = ProtoEncoder.encode_bool(1, False)
        assert b"\x00" in encoded

    @pytest.mark.unit
    def test_frame_message_structure(self):
        """gRPC frame harus punya 5-byte header."""
        proto = b"\x08\x01"
        framed = ProtoEncoder.frame_message(proto)
        # byte 0 = compression flag (0 = no compression)
        assert framed[0] == 0x00
        # bytes 1-4 = message length (big-endian uint32)
        msg_len = struct.unpack(">I", framed[1:5])[0]
        assert msg_len == len(proto)
        # bytes 5+ = actual message
        assert framed[5:] == proto

    @pytest.mark.unit
    def test_frame_message_total_length(self):
        """Frame length harus = 5 + proto_length."""
        proto = b"test"
        framed = ProtoEncoder.frame_message(proto)
        assert len(framed) == 5 + len(proto)

    @pytest.mark.unit
    def test_build_injection_message(self):
        """Injection message harus framed dan mengandung payload."""
        payload = "' OR '1'='1"
        msg = ProtoEncoder.build_injection_message(payload, num_fields=2)
        # Harus framed (starts with 0x00)
        assert msg[0] == 0x00
        # Harus mengandung payload
        assert payload.encode("utf-8") in msg

    @pytest.mark.unit
    def test_build_injection_message_multiple_fields(self):
        """Injection message harus encode payload ke semua fields."""
        payload = "test"
        msg_1 = ProtoEncoder.build_injection_message(payload, num_fields=1)
        msg_3 = ProtoEncoder.build_injection_message(payload, num_fields=3)
        # 3-field message harus lebih panjang dari 1-field
        assert len(msg_3) > len(msg_1)

    @pytest.mark.unit
    def test_build_large_message(self):
        """Large message harus memiliki ukuran yang sesuai."""
        size = 1024
        msg = ProtoEncoder.build_large_message(size)
        # Total = 5 (frame header) + ~6 (field tag + varint length) + size
        assert len(msg) >= size

    @pytest.mark.unit
    def test_varint_single_byte(self):
        """Nilai 0-127 harus encode sebagai 1 byte."""
        for v in [0, 1, 42, 127]:
            encoded = ProtoEncoder._varint(v)
            assert len(encoded) == 1

    @pytest.mark.unit
    def test_varint_multi_byte(self):
        """Nilai > 127 harus encode sebagai multi-byte varint."""
        encoded = ProtoEncoder._varint(128)
        assert len(encoded) == 2
        encoded = ProtoEncoder._varint(16384)
        assert len(encoded) == 3

    @pytest.mark.unit
    def test_encode_zero_int(self):
        """Integer 0 harus encode dengan benar."""
        encoded = ProtoEncoder.encode_int(1, 0)
        assert len(encoded) > 0


# ── Tests: Payload Sets ───────────────────────────────────

class TestPayloadSets:

    @pytest.mark.unit
    def test_injection_categories_complete(self):
        required = {"sqli", "ssti", "cmdi", "path", "fmt"}
        assert required == set(INJECTION_PAYLOADS.keys())

    @pytest.mark.unit
    def test_sqli_has_quotes(self):
        combined = " ".join(INJECTION_PAYLOADS["sqli"])
        assert "'" in combined or "UNION" in combined

    @pytest.mark.unit
    def test_ssti_has_template_syntax(self):
        combined = " ".join(INJECTION_PAYLOADS["ssti"])
        assert "{{" in combined or "${" in combined

    @pytest.mark.unit
    def test_cmdi_has_shell_chars(self):
        combined = " ".join(INJECTION_PAYLOADS["cmdi"])
        assert any(c in combined for c in [";", "|", "`"])

    @pytest.mark.unit
    def test_metadata_injection_has_privilege_escalation(self):
        keys = [k for k, _ in METADATA_INJECTION]
        assert "x-admin" in keys or "x-role" in keys

    @pytest.mark.unit
    def test_metadata_injection_has_auth_test(self):
        keys = [k for k, _ in METADATA_INJECTION]
        assert "authorization" in keys

    @pytest.mark.unit
    def test_boolean_flip_both_values(self):
        assert True in BOOLEAN_FLIP_VALUES
        assert False in BOOLEAN_FLIP_VALUES

    @pytest.mark.unit
    def test_enum_escalation_includes_boundary(self):
        assert 0 in ENUM_ESCALATION_VALUES
        assert -1 in ENUM_ESCALATION_VALUES
        assert 2147483647 in ENUM_ESCALATION_VALUES  # INT_MAX

    @pytest.mark.unit
    def test_enum_escalation_includes_out_of_range(self):
        """Harus ada nilai di luar normal enum range."""
        assert 999 in ENUM_ESCALATION_VALUES


# ── Tests: Fuzzer Init ────────────────────────────────────

class TestFuzzerInit:

    @pytest.mark.unit
    def test_target_stored(self, fuzzer):
        assert fuzzer.target == "grpc.target.example.com:443"

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path):
        new_dir = tmp_path / "grpc_out"
        GRPCFuzzer(target="t:443", output_dir=str(new_dir))
        assert new_dir.exists()

    @pytest.mark.unit
    def test_token_stored(self, authed_fuzzer):
        assert authed_fuzzer.token == "test-jwt-token-123"

    @pytest.mark.unit
    def test_no_token_default(self, fuzzer):
        assert fuzzer.token is None

    @pytest.mark.unit
    def test_insecure_default_false(self, fuzzer):
        assert fuzzer.insecure is False

    @pytest.mark.unit
    def test_insecure_flag(self, tmp_path):
        f = GRPCFuzzer(target="t:9090", output_dir=str(tmp_path), insecure=True)
        assert f.insecure is True

    @pytest.mark.unit
    def test_findings_empty_at_init(self, fuzzer):
        assert fuzzer.findings == []

    @pytest.mark.unit
    def test_services_empty_at_init(self, fuzzer):
        assert fuzzer.services == []


# ── Tests: Injection Confirmation ────────────────────────

class TestInjectionConfirmation:

    @pytest.mark.unit
    def test_sqli_confirmed_by_mysql_error(self, fuzzer):
        assert fuzzer._confirm_injection(
            "' OR '1'='1", "error: mysql syntax error", "sqli"
        ) is True

    @pytest.mark.unit
    def test_sqli_not_confirmed_clean(self, fuzzer):
        assert fuzzer._confirm_injection(
            "' OR '1'='1", '{"result": []}', "sqli"
        ) is False

    @pytest.mark.unit
    def test_ssti_confirmed_by_math(self, fuzzer):
        assert fuzzer._confirm_injection(
            "{{7*7}}", "Result: 49", "ssti"
        ) is True

    @pytest.mark.unit
    def test_ssti_not_confirmed_literal(self, fuzzer):
        assert fuzzer._confirm_injection(
            "{{7*7}}", "Result: {{7*7}}", "ssti"
        ) is False

    @pytest.mark.unit
    def test_cmdi_confirmed_by_uid(self, fuzzer):
        assert fuzzer._confirm_injection(
            "; id", "uid=1000(user) gid=1000", "cmdi"
        ) is True

    @pytest.mark.unit
    def test_cmdi_not_confirmed_clean(self, fuzzer):
        assert fuzzer._confirm_injection(
            "; id", '{"error": "invalid"}', "cmdi"
        ) is False


# ── Tests: Finding Builder ────────────────────────────────

class TestFindingBuilder:

    @pytest.mark.unit
    def test_finding_structure(self, fuzzer):
        f = fuzzer._make_finding(
            title="Test Finding",
            severity="HIGH",
            cvss=7.5,
            cwe="CWE-200",
            description="desc",
            evidence="evidence",
            remediation="fix",
        )
        required = {"id", "title", "severity", "cvss", "cwe",
                    "target", "description", "evidence", "remediation", "timestamp"}
        assert required == set(f.keys())

    @pytest.mark.unit
    def test_finding_id_sequential(self, fuzzer):
        f1 = fuzzer._make_finding("T1", "HIGH", 7.5, "CWE-1", "d", "e", "r")
        fuzzer.findings.append(f1)
        f2 = fuzzer._make_finding("T2", "MEDIUM", 5.0, "CWE-2", "d", "e", "r")
        assert f1["id"] == "GRPC-001"
        assert f2["id"] == "GRPC-002"

    @pytest.mark.unit
    def test_finding_target_set(self, fuzzer):
        f = fuzzer._make_finding("T", "HIGH", 7.0, "CWE-1", "d", "e", "r")
        assert f["target"] == "grpc.target.example.com:443"

    @pytest.mark.unit
    def test_finding_cvss_range(self, fuzzer):
        for cvss in [0.0, 5.0, 9.1, 10.0]:
            f = fuzzer._make_finding("T", "HIGH", cvss, "CWE-1", "d", "e", "r")
            assert 0.0 <= f["cvss"] <= 10.0


# ── Tests: Report Generation ──────────────────────────────

class TestReportGeneration:

    @pytest.mark.unit
    def test_save_report_creates_file(self, fuzzer):
        fuzzer.findings = [
            fuzzer._make_finding("T", "HIGH", 7.5, "CWE-200", "d", "e", "r")
        ]
        path = fuzzer._save_report()
        assert path.exists()
        assert path.suffix == ".json"

    @pytest.mark.unit
    def test_report_json_structure(self, fuzzer):
        fuzzer.findings = [
            fuzzer._make_finding("T", "CRITICAL", 9.1, "CWE-306", "d", "e", "r")
        ]
        path = fuzzer._save_report()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["tool"] == "glitchicons"
        assert data["module"] == "grpc_fuzzer"
        assert data["version"] == "0.8.0"
        assert data["target"] == "grpc.target.example.com:443"
        assert data["total_findings"] == 1

    @pytest.mark.unit
    def test_report_sorted_by_cvss(self, fuzzer):
        fuzzer.findings = [
            fuzzer._make_finding("Low",  "LOW",      2.0, "CWE-1", "d", "e", "r"),
            fuzzer._make_finding("Crit", "CRITICAL",  9.1, "CWE-2", "d", "e", "r"),
            fuzzer._make_finding("Med",  "MEDIUM",    5.3, "CWE-3", "d", "e", "r"),
        ]
        path = fuzzer._save_report()
        data = json.loads(path.read_text(encoding="utf-8"))
        scores = [f["cvss"] for f in data["findings"]]
        assert scores == sorted(scores, reverse=True)

    @pytest.mark.unit
    def test_report_includes_services(self, fuzzer):
        fuzzer.services = ["helloworld.Greeter", "users.UserService"]
        fuzzer.findings = []
        path = fuzzer._save_report()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "services_found" in data
        assert len(data["services_found"]) == 2

    @pytest.mark.unit
    def test_empty_findings_report_ok(self, fuzzer):
        path = fuzzer._save_report()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["total_findings"] == 0
        assert data["findings"] == []
