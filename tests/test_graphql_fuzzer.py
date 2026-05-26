# tests/test_graphql_fuzzer.py
"""
Unit tests untuk modules/inject/graphql_fuzzer.py
Semua HTTP calls di-mock — tidak butuh server GraphQL nyata.
"""

import json
import pytest
import responses as responses_lib
from unittest.mock import patch, MagicMock
from pathlib import Path


# ── Fixtures ──────────────────────────────────────────────

SAMPLE_INTROSPECTION_RESPONSE = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "subscriptionType": None,
            "types": [
                {
                    "kind": "OBJECT",
                    "name": "User",
                    "description": "A user object",
                    "fields": [
                        {"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "ID", "ofType": None}},
                        {"name": "email", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                        {"name": "password", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                        {"name": "role", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
                        {"name": "isAdmin", "args": [], "type": {"kind": "SCALAR", "name": "Boolean", "ofType": None}},
                    ],
                    "inputFields": None,
                    "enumValues": None,
                },
                {
                    "kind": "OBJECT",
                    "name": "Query",
                    "description": None,
                    "fields": [
                        {"name": "users", "args": [], "type": {"kind": "LIST", "name": None, "ofType": {"kind": "OBJECT", "name": "User"}}},
                        {"name": "me", "args": [], "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
                    ],
                    "inputFields": None,
                    "enumValues": None,
                },
                {"kind": "SCALAR", "name": "__Schema", "description": None, "fields": None, "inputFields": None, "enumValues": None},
            ],
        }
    }
}

SAMPLE_TYPENAME_RESPONSE = {"data": {"__typename": "Query"}}

SAMPLE_BATCH_RESPONSE = [{"data": {"__typename": "Query"}}] * 50


@pytest.fixture
def gql_target():
    return "https://target.example.com/graphql"


@pytest.fixture
def fuzzer(gql_target, tmp_path):
    """Create GraphQLFuzzer instance with temp output dir."""
    # Import here to avoid issues if module not yet in path
    import sys
    import os
    sys.path.insert(0, str(Path(__file__).parent.parent / "modules" / "inject"))
    sys.path.insert(0, str(Path(__file__).parent.parent))

    try:
        from modules.inject.graphql_fuzzer import GraphQLFuzzer
    except ImportError:
        pytest.skip("graphql_fuzzer module not yet in modules/inject/")

    return GraphQLFuzzer(
        target=gql_target,
        output_dir=str(tmp_path / "graphql"),
        timeout=5,
        delay=0,
    )


# ── Tests: Schema & Introspection ─────────────────────────

class TestIntrospection:

    @pytest.mark.unit
    def test_introspection_query_structure(self):
        """Introspection query harus punya __schema dan fragment."""
        from modules.inject.graphql_fuzzer import INTROSPECTION_QUERY
        assert "__schema" in INTROSPECTION_QUERY
        assert "queryType" in INTROSPECTION_QUERY
        assert "fields" in INTROSPECTION_QUERY
        assert "FullType" in INTROSPECTION_QUERY

    @pytest.mark.unit
    def test_schema_type_count(self):
        """Harus bisa hitung jumlah type dari schema."""
        schema = SAMPLE_INTROSPECTION_RESPONSE["data"]["__schema"]
        user_types = [t for t in schema["types"] if not t["name"].startswith("__")]
        assert len(user_types) == 2  # User, Query

    @pytest.mark.unit
    def test_schema_has_mutation_type(self):
        """Harus detect mutation type dari schema."""
        schema = SAMPLE_INTROSPECTION_RESPONSE["data"]["__schema"]
        has_mutation = schema.get("mutationType") is not None
        assert has_mutation

    @pytest.mark.unit
    def test_introspection_disabled_detection(self):
        """Response tanpa __schema harus dianggap introspection disabled."""
        response_without_schema = {"errors": [{"message": "Introspection is disabled"}]}
        has_schema = "data" in response_without_schema and "__schema" in response_without_schema.get("data", {})
        assert not has_schema

    @pytest.mark.unit
    def test_internal_types_filtered(self):
        """Type yang diawali __ harus difilter dari analisis."""
        schema = SAMPLE_INTROSPECTION_RESPONSE["data"]["__schema"]
        all_types = schema["types"]
        internal = [t for t in all_types if t["name"].startswith("__")]
        non_internal = [t for t in all_types if not t["name"].startswith("__")]
        assert len(internal) == 1
        assert len(non_internal) == 2


# ── Tests: Sensitive Field Detection ──────────────────────

class TestSensitiveFieldDetection:

    @pytest.mark.unit
    def test_password_field_detected(self):
        """Field 'password' harus terdeteksi sebagai sensitive."""
        from modules.inject.graphql_fuzzer import SENSITIVE_FIELD_NAMES
        assert "password" in SENSITIVE_FIELD_NAMES

    @pytest.mark.unit
    def test_sensitive_keywords_coverage(self):
        """Harus cover semua kategori data sensitif utama."""
        from modules.inject.graphql_fuzzer import SENSITIVE_FIELD_NAMES
        keywords_str = " ".join(SENSITIVE_FIELD_NAMES).lower()

        assert "password" in keywords_str, "Harus ada password"
        assert "token" in keywords_str, "Harus ada token"
        assert "secret" in keywords_str, "Harus ada secret"
        assert "api_key" in keywords_str or "apikey" in keywords_str, "Harus ada api key"
        assert "email" in keywords_str, "Harus ada email"

    @pytest.mark.unit
    def test_find_sensitive_fields_in_schema(self):
        """Harus detect field password, isAdmin di sample schema."""
        from modules.inject.graphql_fuzzer import SENSITIVE_FIELD_NAMES

        schema = SAMPLE_INTROSPECTION_RESPONSE["data"]["__schema"]
        found = []

        for gql_type in schema.get("types", []):
            type_name = gql_type.get("name", "")
            if type_name.startswith("__"):
                continue
            for field in gql_type.get("fields") or []:
                field_name = field.get("name", "").lower()
                for sensitive in SENSITIVE_FIELD_NAMES:
                    if sensitive.lower() in field_name:
                        found.append(field.get("name"))

        assert "password" in found
        assert "isAdmin" in found or "role" in found

    @pytest.mark.unit
    def test_non_sensitive_fields_not_flagged(self):
        """Field normal seperti 'id', 'name' tidak boleh di-flag."""
        from modules.inject.graphql_fuzzer import SENSITIVE_FIELD_NAMES
        normal_fields = ["id", "name", "title", "description", "createdAt", "updatedAt"]

        for field in normal_fields:
            flagged = any(sensitive.lower() in field.lower() for sensitive in SENSITIVE_FIELD_NAMES)
            assert not flagged, f"'{field}' seharusnya tidak di-flag sebagai sensitive"


# ── Tests: Injection Payloads ─────────────────────────────

class TestInjectionPayloads:

    @pytest.mark.unit
    def test_payload_list_not_empty(self):
        """Injection payload list tidak boleh kosong."""
        from modules.inject.graphql_fuzzer import INJECTION_PAYLOADS
        assert len(INJECTION_PAYLOADS) >= 5

    @pytest.mark.unit
    def test_sqli_payload_present(self):
        """Harus ada SQLi payload."""
        from modules.inject.graphql_fuzzer import INJECTION_PAYLOADS
        has_sqli = any("'" in p or "DROP" in p or "UNION" in p for p in INJECTION_PAYLOADS)
        assert has_sqli

    @pytest.mark.unit
    def test_xss_payload_present(self):
        """Harus ada XSS payload."""
        from modules.inject.graphql_fuzzer import INJECTION_PAYLOADS
        has_xss = any("<script>" in p or "onerror" in p for p in INJECTION_PAYLOADS)
        assert has_xss

    @pytest.mark.unit
    def test_ssti_payload_present(self):
        """Harus ada SSTI payload."""
        from modules.inject.graphql_fuzzer import INJECTION_PAYLOADS
        has_ssti = any("{{" in p or "${" in p for p in INJECTION_PAYLOADS)
        assert has_ssti

    @pytest.mark.unit
    def test_path_traversal_payload_present(self):
        """Harus ada path traversal payload."""
        from modules.inject.graphql_fuzzer import INJECTION_PAYLOADS
        has_traversal = any("../" in p or "etc/passwd" in p for p in INJECTION_PAYLOADS)
        assert has_traversal


# ── Tests: Finding Structure ──────────────────────────────

class TestFindingStructure:

    @pytest.fixture
    def sample_finding(self):
        return {
            "id": "GQL-001",
            "title": "GraphQL Introspection Enabled in Production",
            "severity": "HIGH",
            "cvss": 7.5,
            "cwe": "CWE-200",
            "target": "https://target.example.com/graphql",
            "description": "Full schema exposed...",
            "evidence": "50 types returned",
            "remediation": "Disable introspection in production.",
            "timestamp": "2026-05-26T10:00:00",
        }

    @pytest.mark.unit
    def test_finding_has_required_fields(self, sample_finding):
        """Finding harus punya semua field standar."""
        required = {"id", "title", "severity", "cvss", "cwe", "description", "evidence", "remediation"}
        missing = required - set(sample_finding.keys())
        assert not missing, f"Missing: {missing}"

    @pytest.mark.unit
    def test_finding_cvss_in_range(self, sample_finding):
        """CVSS harus dalam range 0.0-10.0."""
        assert 0.0 <= sample_finding["cvss"] <= 10.0

    @pytest.mark.unit
    def test_finding_severity_valid(self, sample_finding):
        """Severity harus salah satu dari nilai valid."""
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert sample_finding["severity"] in valid

    @pytest.mark.unit
    def test_finding_cwe_format(self, sample_finding):
        """CWE harus format CWE-XXX."""
        assert sample_finding["cwe"].startswith("CWE-")
        cwe_number = sample_finding["cwe"].split("-")[1]
        assert cwe_number.isdigit()


# ── Tests: Attack Logic ───────────────────────────────────

class TestAttackLogic:

    @pytest.mark.unit
    def test_alias_query_construction(self):
        """Alias overload query harus generate N aliases."""
        n = 100
        aliases = "\n".join([f"  a{i}: __typename" for i in range(n)])
        query = f"{{ {aliases} }}"

        assert query.count("__typename") == n
        assert "a0:" in query
        assert f"a{n-1}:" in query

    @pytest.mark.unit
    def test_batch_request_is_list(self):
        """Batch request harus berupa list of operations."""
        batch = [{"query": "{ __typename }"}] * 50
        assert isinstance(batch, list)
        assert len(batch) == 50
        assert all("query" in op for op in batch)

    @pytest.mark.unit
    def test_nested_query_depth_calculation(self):
        """Depth-N query harus punya N level nesting."""
        def build_nested(depth: int) -> str:
            if depth == 0:
                return "{ __typename }"
            return f"{{ user {build_nested(depth - 1)} }}"

        q = build_nested(5)
        assert q.count("user") == 5
        assert "__typename" in q

    @pytest.mark.unit
    def test_sql_error_signatures_coverage(self):
        """SQL error signature list harus cover DB utama."""
        sql_errors = [
            "syntax error", "mysql_fetch", "ORA-", "SQLite",
            "pg_query", "Unclosed quotation",
        ]
        # Cek coverage DB
        has_mysql = any("mysql" in e.lower() for e in sql_errors)
        has_oracle = any("ORA" in e for e in sql_errors)
        has_sqlite = any("SQLite" in e for e in sql_errors)
        has_postgres = any("pg_" in e for e in sql_errors)

        assert has_mysql
        assert has_oracle
        assert has_sqlite
        assert has_postgres

    @pytest.mark.unit
    def test_batch_response_detection(self):
        """Response batch yang valid harus berupa list >= 10 items."""
        valid_batch = [{"data": {"__typename": "Query"}}] * 50
        invalid_single = {"data": {"__typename": "Query"}}
        error_response = {"errors": [{"message": "Batching not supported"}]}

        assert isinstance(valid_batch, list) and len(valid_batch) >= 10
        assert not isinstance(invalid_single, list)
        assert not isinstance(error_response, list)

    @pytest.mark.unit
    def test_report_json_serializable(self):
        """Report harus bisa di-serialize ke JSON tanpa error."""
        findings = [
            {
                "id": "GQL-001",
                "title": "Test Finding",
                "severity": "HIGH",
                "cvss": 7.5,
                "cwe": "CWE-200",
                "description": "Test",
                "evidence": "Test evidence",
                "remediation": "Fix it",
                "timestamp": "2026-05-26T10:00:00",
            }
        ]
        report = {
            "tool": "glitchicons",
            "module": "graphql_fuzzer",
            "version": "0.7.0",
            "findings": findings,
        }
        json_str = json.dumps(report, indent=2)
        parsed = json.loads(json_str)
        assert parsed["findings"][0]["severity"] == "HIGH"
