# tests/test_openapi_parser.py
"""
Unit tests untuk modules/recon/openapi_parser.py
Menggunakan sample spec di-inline — tidak butuh file eksternal.
"""

import json
import pytest
from pathlib import Path

from modules.recon.openapi_parser import (
    OpenAPIParser,
    APIParameter,
    APIEndpoint,
    AttackPlan,
)


# ── Sample specs ──────────────────────────────────────────

SWAGGER_2_SPEC = {
    "swagger": "2.0",
    "info": {"title": "Test API", "version": "1.0"},
    "host": "api.target.com",
    "basePath": "/v1",
    "schemes": ["https"],
    "securityDefinitions": {
        "bearerAuth": {"type": "apiKey", "in": "header", "name": "Authorization"}
    },
    "security": [{"bearerAuth": []}],
    "paths": {
        "/users/{id}": {
            "get": {
                "operationId": "getUser",
                "summary": "Get user by ID",
                "tags": ["users"],
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {"name": "id", "in": "path", "required": True,
                     "type": "integer", "format": "int64"}
                ],
                "responses": {
                    "200": {
                        "schema": {
                            "properties": {
                                "id": {"type": "integer"},
                                "email": {"type": "string"},
                                "password": {"type": "string"},
                            }
                        }
                    }
                }
            }
        },
        "/admin/users": {
            "get": {
                "operationId": "listAdminUsers",
                "summary": "List all users (admin)",
                "tags": ["admin"],
                "security": [],
                "parameters": [],
                "responses": {"200": {"schema": {"type": "array"}}}
            }
        },
        "/login": {
            "post": {
                "operationId": "login",
                "summary": "Login",
                "security": [],
                "parameters": [
                    {"name": "body", "in": "body", "required": True,
                     "schema": {
                         "properties": {
                             "username": {"type": "string"},
                             "password": {"type": "string"},
                         }
                     }}
                ],
                "responses": {"200": {"schema": {"properties": {"token": {"type": "string"}}}}}
            }
        },
        "/search": {
            "get": {
                "operationId": "search",
                "summary": "Search items",
                "security": [],
                "parameters": [
                    {"name": "q", "in": "query", "required": False, "type": "string"},
                    {"name": "token", "in": "query", "required": False, "type": "string"},
                ],
                "responses": {"200": {"schema": {"type": "array"}}}
            }
        }
    }
}

OPENAPI_3_SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Modern API", "version": "2.0"},
    "servers": [{"url": "https://api.example.com/v2"}],
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"}
        },
        "schemas": {
            "User": {
                "type": "object",
                "properties": {
                    "id":       {"type": "integer"},
                    "email":    {"type": "string"},
                    "username": {"type": "string"},
                }
            }
        }
    },
    "paths": {
        "/users/{userId}": {
            "get": {
                "operationId": "getUser",
                "summary": "Get user",
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {"name": "userId", "in": "path", "required": True,
                     "schema": {"type": "integer", "format": "int64"}}
                ],
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/User"}
                            }
                        }
                    }
                }
            }
        },
        "/users": {
            "post": {
                "operationId": "createUser",
                "summary": "Create user",
                "security": [{"bearerAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "username": {"type": "string"},
                                    "email":    {"type": "string"},
                                    "role":     {"type": "string"},
                                }
                            }
                        }
                    }
                },
                "responses": {"201": {"description": "Created"}}
            }
        },
        "/public/health": {
            "get": {
                "operationId": "healthCheck",
                "summary": "Health check",
                "security": [],
                "parameters": [],
                "responses": {"200": {"description": "OK"}}
            }
        }
    }
}


@pytest.fixture
def parser(tmp_path):
    return OpenAPIParser(
        base_url="https://api.target.com/v1",
        output_dir=str(tmp_path / "openapi"),
        timeout=5,
        delay=0,
    )


@pytest.fixture
def swagger_plan(parser):
    parser._raw_spec = SWAGGER_2_SPEC
    return parser._build_plan()


@pytest.fixture
def openapi3_plan(parser):
    parser._raw_spec = OPENAPI_3_SPEC
    return parser._build_plan()


# ── Tests: Version Detection ──────────────────────────────

class TestVersionDetection:

    @pytest.mark.unit
    def test_detect_swagger_2(self, parser):
        assert parser.detect_version({"swagger": "2.0"}) == "swagger_2.0"

    @pytest.mark.unit
    def test_detect_openapi_3(self, parser):
        assert parser.detect_version({"openapi": "3.0.3"}) == "openapi_3.0.3"

    @pytest.mark.unit
    def test_detect_openapi_31(self, parser):
        assert parser.detect_version({"openapi": "3.1.0"}) == "openapi_3.1.0"

    @pytest.mark.unit
    def test_detect_unknown(self, parser):
        assert parser.detect_version({}) == "unknown"

    @pytest.mark.unit
    def test_swagger_plan_version(self, swagger_plan):
        assert "swagger" in swagger_plan.spec_version

    @pytest.mark.unit
    def test_openapi3_plan_version(self, openapi3_plan):
        assert "openapi" in openapi3_plan.spec_version


# ── Tests: Base URL Extraction ────────────────────────────

class TestBaseURLExtraction:

    @pytest.mark.unit
    def test_swagger_base_url(self, parser):
        parser.base_url = ""
        url = parser.extract_base_url(SWAGGER_2_SPEC)
        assert "api.target.com" in url
        assert url.startswith("https://")

    @pytest.mark.unit
    def test_openapi3_base_url(self, parser):
        parser.base_url = ""
        url = parser.extract_base_url(OPENAPI_3_SPEC)
        assert "api.example.com" in url

    @pytest.mark.unit
    def test_override_takes_priority(self, parser):
        """Jika base_url di-set manual, harus digunakan."""
        parser.base_url = "https://override.com"
        url = parser.extract_base_url(SWAGGER_2_SPEC)
        assert url == "https://override.com"

    @pytest.mark.unit
    def test_trailing_slash_stripped(self, parser):
        parser.base_url = ""
        url = parser.extract_base_url(OPENAPI_3_SPEC)
        assert not url.endswith("/")


# ── Tests: Auth Scheme Extraction ─────────────────────────

class TestAuthSchemeExtraction:

    @pytest.mark.unit
    def test_swagger_apikey_detected(self, parser):
        schemes = parser.extract_auth_schemes(SWAGGER_2_SPEC)
        assert any("apiKey" in s for s in schemes)

    @pytest.mark.unit
    def test_openapi3_bearer_detected(self, parser):
        schemes = parser.extract_auth_schemes(OPENAPI_3_SPEC)
        assert any("http" in s or "bearer" in s.lower() for s in schemes)

    @pytest.mark.unit
    def test_no_auth_returns_empty(self, parser):
        spec = {"swagger": "2.0", "info": {"title": "T", "version": "1"}}
        schemes = parser.extract_auth_schemes(spec)
        assert schemes == []


# ── Tests: Endpoint Extraction ────────────────────────────

class TestEndpointExtraction:

    @pytest.mark.unit
    def test_swagger_endpoint_count(self, swagger_plan):
        assert swagger_plan.total_endpoints == 4

    @pytest.mark.unit
    def test_openapi3_endpoint_count(self, openapi3_plan):
        assert openapi3_plan.total_endpoints == 3

    @pytest.mark.unit
    def test_endpoint_methods_extracted(self, swagger_plan):
        methods = {ep.method.upper() for ep in swagger_plan.endpoints}
        assert "GET" in methods
        assert "POST" in methods

    @pytest.mark.unit
    def test_endpoint_paths_extracted(self, swagger_plan):
        paths = {ep.path for ep in swagger_plan.endpoints}
        assert "/users/{id}" in paths
        assert "/login" in paths
        assert "/search" in paths

    @pytest.mark.unit
    def test_auth_required_detected(self, swagger_plan):
        """Endpoint dengan security harus requires_auth=True."""
        user_ep = next(e for e in swagger_plan.endpoints if e.path == "/users/{id}")
        assert user_ep.requires_auth is True

    @pytest.mark.unit
    def test_no_auth_detected(self, swagger_plan):
        """Endpoint tanpa security harus requires_auth=False."""
        admin_ep = next(e for e in swagger_plan.endpoints if e.path == "/admin/users")
        assert admin_ep.requires_auth is False

    @pytest.mark.unit
    def test_parameters_extracted(self, swagger_plan):
        user_ep = next(e for e in swagger_plan.endpoints if e.path == "/users/{id}")
        assert len(user_ep.parameters) >= 1
        assert user_ep.parameters[0].name == "id"

    @pytest.mark.unit
    def test_tags_extracted(self, swagger_plan):
        user_ep = next(e for e in swagger_plan.endpoints if e.path == "/users/{id}")
        assert "users" in user_ep.tags


# ── Tests: APIParameter ───────────────────────────────────

class TestAPIParameter:

    @pytest.fixture
    def int_path_param(self):
        return APIParameter(
            name="userId", location="path", required=True,
            schema_type="integer", schema_format="int64",
        )

    @pytest.fixture
    def string_query_param(self):
        return APIParameter(
            name="q", location="query", required=False,
            schema_type="string", schema_format="",
        )

    @pytest.fixture
    def password_param(self):
        return APIParameter(
            name="password", location="body", required=True,
            schema_type="string", schema_format="password",
        )

    @pytest.mark.unit
    def test_integer_id_detected(self, int_path_param):
        assert int_path_param.is_integer_id is True

    @pytest.mark.unit
    def test_string_query_injectable(self, string_query_param):
        assert string_query_param.is_injectable is True

    @pytest.mark.unit
    def test_integer_not_injectable(self, int_path_param):
        assert int_path_param.is_injectable is False

    @pytest.mark.unit
    def test_password_is_sensitive(self, password_param):
        assert password_param.is_sensitive is True

    @pytest.mark.unit
    def test_normal_param_not_sensitive(self, string_query_param):
        assert string_query_param.is_sensitive is False

    @pytest.mark.unit
    def test_id_in_name_is_idor_target(self):
        p = APIParameter(
            name="accountId", location="query", required=True,
            schema_type="integer", schema_format="",
        )
        assert p.is_integer_id is True


# ── Tests: Attack Surface ─────────────────────────────────

class TestAttackSurface:

    @pytest.mark.unit
    def test_idor_in_surface(self, swagger_plan):
        user_ep = next(e for e in swagger_plan.endpoints if e.path == "/users/{id}")
        assert "IDOR" in user_ep.attack_surface

    @pytest.mark.unit
    def test_sqli_for_string_params(self, swagger_plan):
        search_ep = next(e for e in swagger_plan.endpoints if e.path == "/search")
        assert "SQLi" in search_ep.attack_surface

    @pytest.mark.unit
    def test_auth_bypass_for_open_endpoints(self, swagger_plan):
        admin_ep = next(e for e in swagger_plan.endpoints if e.path == "/admin/users")
        assert "AUTH_BYPASS" in admin_ep.attack_surface

    @pytest.mark.unit
    def test_mass_assign_for_post(self, swagger_plan):
        login_ep = next(e for e in swagger_plan.endpoints if e.path == "/login")
        assert "MASS_ASSIGN" in login_ep.attack_surface

    @pytest.mark.unit
    def test_rate_limit_always_present(self, swagger_plan):
        for ep in swagger_plan.endpoints:
            assert "RATE_LIMIT" in ep.attack_surface

    @pytest.mark.unit
    def test_high_value_endpoints_sorted(self, swagger_plan):
        """high_value_endpoints harus di-sort by attack count descending."""
        hvs = swagger_plan.high_value_endpoints
        attack_counts = [len(ep.attack_surface) for ep in hvs]
        assert attack_counts == sorted(attack_counts, reverse=True)


# ── Tests: Static Security Findings ──────────────────────

class TestStaticSecurityFindings:

    @pytest.mark.unit
    def test_unauthenticated_admin_flagged(self, swagger_plan):
        """Admin endpoint tanpa auth harus terdeteksi."""
        titles = [f["title"] for f in swagger_plan.findings]
        admin_findings = [t for t in titles if "admin" in t.lower()]
        assert len(admin_findings) >= 1

    @pytest.mark.unit
    def test_sensitive_get_param_flagged(self, swagger_plan):
        """Token dalam GET query param harus di-flag."""
        titles = [f["title"] for f in swagger_plan.findings]
        token_findings = [t for t in titles if "token" in t.lower() or "query" in t.lower()]
        assert len(token_findings) >= 1

    @pytest.mark.unit
    def test_pii_in_response_flagged(self, swagger_plan):
        """Password dalam response schema harus di-flag."""
        titles = [f["title"] for f in swagger_plan.findings]
        pii_findings = [t for t in titles if "PII" in t or "sensitive" in t.lower()]
        assert len(pii_findings) >= 1

    @pytest.mark.unit
    def test_http_url_flagged(self, parser, tmp_path):
        """HTTP base URL harus di-flag sebagai HIGH."""
        parser.base_url = "http://api.target.com"
        parser._raw_spec = SWAGGER_2_SPEC
        plan = parser._build_plan()
        http_findings = [f for f in plan.findings if "HTTP" in f["title"] or "TLS" in f["title"]]
        assert len(http_findings) >= 1
        assert http_findings[0]["severity"] == "HIGH"

    @pytest.mark.unit
    def test_finding_structure(self, swagger_plan):
        """Setiap finding harus punya field standar."""
        required = {"id", "title", "severity", "cvss", "cwe",
                    "description", "evidence", "remediation"}
        for f in swagger_plan.findings:
            missing = required - set(f.keys())
            assert not missing, f"Missing fields: {missing}"

    @pytest.mark.unit
    def test_finding_id_format(self, swagger_plan):
        """Finding ID harus format OA-XXX."""
        for f in swagger_plan.findings:
            assert f["id"].startswith("OA-")
            assert f["id"].split("-")[1].isdigit()

    @pytest.mark.unit
    def test_cvss_in_range(self, swagger_plan):
        for f in swagger_plan.findings:
            assert 0.0 <= f["cvss"] <= 10.0

    @pytest.mark.unit
    def test_severity_valid(self, swagger_plan):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for f in swagger_plan.findings:
            assert f["severity"] in valid


# ── Tests: Plan Summary ───────────────────────────────────

class TestPlanSummary:

    @pytest.mark.unit
    def test_summary_total_endpoints(self, swagger_plan):
        s = swagger_plan.summary()
        assert s["total_endpoints"] == 4

    @pytest.mark.unit
    def test_summary_auth_counts(self, swagger_plan):
        s = swagger_plan.summary()
        assert s["auth_required"] + s["unauthenticated"] == s["total_endpoints"]

    @pytest.mark.unit
    def test_summary_attack_distribution(self, swagger_plan):
        s = swagger_plan.summary()
        dist = s["attack_distribution"]
        assert "RATE_LIMIT" in dist
        assert dist["RATE_LIMIT"] == 4  # all endpoints

    @pytest.mark.unit
    def test_summary_idor_count(self, swagger_plan):
        s = swagger_plan.summary()
        assert s["idor_targets"] >= 1


# ── Tests: File Parsing ───────────────────────────────────

class TestFileParsing:

    @pytest.mark.unit
    def test_parse_json_file(self, parser, tmp_path):
        """Harus bisa parse JSON spec dari file."""
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps(SWAGGER_2_SPEC), encoding="utf-8")
        plan = parser.parse_file(spec_file)
        assert plan.title == "Test API"
        assert plan.total_endpoints == 4

    @pytest.mark.unit
    def test_parse_yaml_file(self, parser, tmp_path):
        """Harus bisa parse YAML spec dari file."""
        import yaml
        spec_file = tmp_path / "spec.yaml"
        spec_file.write_text(yaml.dump(SWAGGER_2_SPEC), encoding="utf-8")
        plan = parser.parse_file(spec_file)
        assert plan.title == "Test API"

    @pytest.mark.unit
    def test_file_not_found_raises(self, parser):
        with pytest.raises(FileNotFoundError):
            parser.parse_file("/nonexistent/spec.json")


# ── Tests: Save Plan ─────────────────────────────────────

class TestSavePlan:

    @pytest.mark.unit
    def test_save_creates_file(self, parser, swagger_plan):
        path = parser.save_plan(swagger_plan)
        assert path.exists()
        assert path.suffix == ".json"

    @pytest.mark.unit
    def test_saved_json_valid(self, parser, swagger_plan):
        path = parser.save_plan(swagger_plan)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["tool"] == "glitchicons"
        assert data["module"] == "openapi_parser"
        assert "attack_matrix" in data
        assert "static_findings" in data

    @pytest.mark.unit
    def test_attack_matrix_structure(self, parser, swagger_plan):
        path = parser.save_plan(swagger_plan)
        data = json.loads(path.read_text(encoding="utf-8"))
        for entry in data["attack_matrix"]:
            assert "endpoint" in entry
            assert "attacks" in entry
            assert "parameters" in entry

    @pytest.mark.unit
    def test_saved_filename_contains_title(self, parser, swagger_plan):
        path = parser.save_plan(swagger_plan)
        assert "test_api" in path.name or "api" in path.name


# ── Tests: Ref Resolution ─────────────────────────────────

class TestRefResolution:

    @pytest.mark.unit
    def test_resolve_component_ref(self, parser):
        spec = {
            "components": {
                "schemas": {
                    "User": {"type": "object", "properties": {"id": {"type": "integer"}}}
                }
            }
        }
        schema = {"$ref": "#/components/schemas/User"}
        resolved = parser._resolve_ref(schema, spec)
        assert resolved["type"] == "object"
        assert "id" in resolved.get("properties", {})

    @pytest.mark.unit
    def test_no_ref_returns_same(self, parser):
        schema = {"type": "string", "format": "email"}
        resolved = parser._resolve_ref(schema, {})
        assert resolved == schema

    @pytest.mark.unit
    def test_invalid_ref_returns_empty(self, parser):
        schema = {"$ref": "#/definitions/NonExistent"}
        resolved = parser._resolve_ref(schema, {})
        assert resolved == {}
