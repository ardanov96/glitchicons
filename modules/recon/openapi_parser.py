"""
OpenAPI Parser — modules/recon/openapi_parser.py

Reads OpenAPI 2.0 (Swagger) and OpenAPI 3.x spec files (JSON or YAML)
and generates a structured attack plan targeting every endpoint.

Features:
  1. Auto-detect spec format    — Swagger 2.0 vs OpenAPI 3.x
  2. Endpoint extraction        — method, path, params, request body
  3. Auth scheme detection      — Bearer, Basic, API key, OAuth2
  4. Attack plan generation     — per-endpoint attack matrix
  5. Parameter fuzzing targets  — path, query, header, cookie params
  6. Sensitive data detection   — PII fields in schemas
  7. Security misconfiguration  — missing auth, HTTP endpoints
  8. Live probing               — test endpoints against real server

Attack matrix per endpoint:
  - IDOR          — integer ID params → enumerate
  - SQLi          — string params → inject
  - SSTI          — string params → template inject
  - Auth bypass   — try without/wrong token
  - Mass assign   — send extra fields not in spec
  - BOLA          — access other users' resources
  - Rate limit    — rapid fire the endpoint

Usage:
    # From file
    python3 glitchicons.py openapi --spec swagger.json --base-url https://api.target.com

    # From URL (auto-fetch spec)
    python3 glitchicons.py openapi --url https://api.target.com/swagger.json

    # With auth
    python3 glitchicons.py openapi --spec api.yaml --base-url https://api.target.com --token eyJ...

Author: ardanov96
"""

import json
import time
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table

console = Console()


# ── Data classes ──────────────────────────────────────────

@dataclass
class APIParameter:
    """A single parameter extracted from OpenAPI spec."""
    name: str
    location: str          # path | query | header | cookie | body
    required: bool
    schema_type: str       # string | integer | number | boolean | array | object
    schema_format: str     # int32 | int64 | email | uuid | date-time | password | ...
    enum_values: list = field(default_factory=list)
    example: object = None
    description: str = ""

    @property
    def is_integer_id(self) -> bool:
        """Likely an IDOR target — integer in path."""
        return (
            self.location == "path"
            and self.schema_type in ("integer", "number")
        ) or (
            self.schema_type in ("integer", "number")
            and any(kw in self.name.lower() for kw in ["id", "user", "account", "order", "item"])
        )

    @property
    def is_injectable(self) -> bool:
        """String param — SQLi/SSTI candidate."""
        return self.schema_type == "string" and self.location in ("query", "body", "path")

    @property
    def is_sensitive(self) -> bool:
        """Param likely contains PII or credentials."""
        sensitive_keywords = [
            "password", "passwd", "secret", "token", "api_key", "apikey",
            "email", "phone", "ssn", "credit_card", "cvv", "dob",
            "address", "salary", "private",
        ]
        return any(kw in self.name.lower() for kw in sensitive_keywords)


@dataclass
class APIEndpoint:
    """A single endpoint extracted from OpenAPI spec."""
    method: str
    path: str
    operation_id: str
    summary: str
    tags: list[str]
    parameters: list[APIParameter]
    request_body_schema: dict | None
    response_schemas: dict
    security: list[dict]       # e.g. [{"bearerAuth": []}]
    requires_auth: bool
    produces_json: bool

    @property
    def full_path(self) -> str:
        return f"{self.method.upper()} {self.path}"

    @property
    def path_params(self) -> list[APIParameter]:
        return [p for p in self.parameters if p.location == "path"]

    @property
    def query_params(self) -> list[APIParameter]:
        return [p for p in self.parameters if p.location == "query"]

    @property
    def integer_id_params(self) -> list[APIParameter]:
        return [p for p in self.parameters if p.is_integer_id]

    @property
    def injectable_params(self) -> list[APIParameter]:
        return [p for p in self.parameters if p.is_injectable]

    @property
    def attack_surface(self) -> list[str]:
        """Which attacks are relevant for this endpoint."""
        attacks = []
        if self.integer_id_params:
            attacks.append("IDOR")
        if self.injectable_params:
            attacks.extend(["SQLi", "SSTI", "XSS"])
        if not self.requires_auth:
            attacks.append("AUTH_BYPASS")
        if self.method.upper() in ("POST", "PUT", "PATCH") and self.request_body_schema:
            attacks.append("MASS_ASSIGN")
        if self.method.upper() == "GET" and self.integer_id_params:
            attacks.append("BOLA")
        attacks.append("RATE_LIMIT")
        return list(set(attacks))


@dataclass
class AttackPlan:
    """Full attack plan generated from an OpenAPI spec."""
    spec_version: str
    title: str
    base_url: str
    total_endpoints: int
    endpoints: list[APIEndpoint]
    auth_schemes: list[str]
    findings: list[dict]
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def high_value_endpoints(self) -> list[APIEndpoint]:
        """Endpoints with most attack surface."""
        return sorted(
            self.endpoints,
            key=lambda e: len(e.attack_surface),
            reverse=True,
        )[:10]

    def summary(self) -> dict:
        all_attacks = []
        for ep in self.endpoints:
            all_attacks.extend(ep.attack_surface)
        from collections import Counter
        return {
            "total_endpoints": self.total_endpoints,
            "auth_required": sum(1 for e in self.endpoints if e.requires_auth),
            "unauthenticated": sum(1 for e in self.endpoints if not e.requires_auth),
            "idor_targets": sum(1 for e in self.endpoints if "IDOR" in e.attack_surface),
            "injectable_targets": sum(1 for e in self.endpoints if "SQLi" in e.attack_surface),
            "mass_assign_targets": sum(1 for e in self.endpoints if "MASS_ASSIGN" in e.attack_surface),
            "attack_distribution": dict(Counter(all_attacks)),
        }


# ── Parser ────────────────────────────────────────────────

class OpenAPIParser:
    """
    Parse OpenAPI 2.0 / 3.x specs and generate attack plans.

    Supports:
    - JSON and YAML input files
    - Remote spec fetching (URL)
    - Swagger 2.0 and OpenAPI 3.0/3.1
    """

    def __init__(
        self,
        base_url: str = "",
        output_dir: str = "./findings/openapi",
        token: str | None = None,
        timeout: int = 10,
        delay: float = 0.5,
    ):
        self.base_url = base_url.rstrip("/")
        self.output_dir = Path(output_dir)
        self.token = token
        self.timeout = timeout
        self.delay = delay
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._raw_spec: dict = {}

    # ── Public API ────────────────────────────────────────

    def parse_file(self, path: str | Path) -> AttackPlan:
        """Parse spec from local file (.json or .yaml)."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Spec file not found: {p}")

        content = p.read_text(encoding="utf-8")

        if p.suffix in (".yaml", ".yml"):
            try:
                import yaml
                self._raw_spec = yaml.safe_load(content)
            except ImportError:
                raise ImportError("Install PyYAML: pip install pyyaml")
        else:
            self._raw_spec = json.loads(content)

        return self._build_plan()

    def fetch_and_parse(self, url: str) -> AttackPlan:
        """Fetch spec from URL then parse."""
        import httpx
        console.print(f"  Fetching spec from [cyan]{url}[/cyan]...")
        resp = httpx.get(url, timeout=self.timeout, follow_redirects=True)
        resp.raise_for_status()

        ct = resp.headers.get("content-type", "")
        if "yaml" in ct or url.endswith((".yaml", ".yml")):
            import yaml
            self._raw_spec = yaml.safe_load(resp.text)
        else:
            self._raw_spec = resp.json()

        return self._build_plan()

    # ── Spec detection ────────────────────────────────────

    def detect_version(self, spec: dict) -> str:
        """Detect Swagger 2.0 vs OpenAPI 3.x."""
        if "swagger" in spec:
            return f"swagger_{spec['swagger']}"
        if "openapi" in spec:
            return f"openapi_{spec['openapi']}"
        return "unknown"

    def extract_base_url(self, spec: dict) -> str:
        """Extract base URL from spec if not provided."""
        if self.base_url:
            return self.base_url

        version = self.detect_version(spec)

        if version.startswith("swagger"):
            scheme = (spec.get("schemes") or ["https"])[0]
            host = spec.get("host", "")
            base_path = spec.get("basePath", "")
            return f"{scheme}://{host}{base_path}"

        if version.startswith("openapi"):
            servers = spec.get("servers", [])
            if servers:
                return servers[0].get("url", "").rstrip("/")

        return ""

    # ── Auth scheme extraction ────────────────────────────

    def extract_auth_schemes(self, spec: dict) -> list[str]:
        """Extract all auth schemes defined in the spec."""
        schemes = []
        version = self.detect_version(spec)

        if version.startswith("swagger"):
            sec_defs = spec.get("securityDefinitions", {})
            for name, defn in sec_defs.items():
                t = defn.get("type", "")
                if t == "apiKey":
                    schemes.append(f"apiKey:{defn.get('in','header')}:{name}")
                elif t == "basic":
                    schemes.append("basic")
                elif t == "oauth2":
                    schemes.append(f"oauth2:{defn.get('flow','')}")

        if version.startswith("openapi"):
            components = spec.get("components", {})
            sec_schemes = components.get("securitySchemes", {})
            for name, defn in sec_schemes.items():
                t = defn.get("type", "")
                if t == "http":
                    schemes.append(f"http:{defn.get('scheme', 'bearer')}:{name}")
                elif t == "apiKey":
                    schemes.append(f"apiKey:{defn.get('in','header')}:{name}")
                elif t == "oauth2":
                    schemes.append(f"oauth2:{name}")
                elif t == "openIdConnect":
                    schemes.append(f"oidc:{name}")

        return schemes

    # ── Endpoint extraction ───────────────────────────────

    def extract_endpoints(self, spec: dict) -> list[APIEndpoint]:
        """Extract all endpoints from spec."""
        endpoints = []
        version = self.detect_version(spec)
        paths = spec.get("paths", {})
        global_security = spec.get("security", [])

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            # Shared params at path level
            path_level_params = path_item.get("parameters", [])

            for method in ("get", "post", "put", "patch", "delete", "options", "head"):
                operation = path_item.get(method)
                if not operation or not isinstance(operation, dict):
                    continue

                # Merge path-level params with operation params
                op_params = operation.get("parameters", [])
                all_raw_params = self._merge_params(path_level_params, op_params)

                parameters = [
                    self._parse_parameter(p, spec, version)
                    for p in all_raw_params
                    if isinstance(p, dict)
                ]

                # Request body (OpenAPI 3.x)
                req_body_schema = None
                if version.startswith("openapi"):
                    req_body = operation.get("requestBody", {})
                    content = req_body.get("content", {})
                    for media_type, media_obj in content.items():
                        if isinstance(media_obj, dict):
                            schema = media_obj.get("schema", {})
                            req_body_schema = self._resolve_ref(schema, spec)
                            break

                # Request body (Swagger 2.0 body param)
                if version.startswith("swagger"):
                    for p in all_raw_params:
                        if isinstance(p, dict) and p.get("in") == "body":
                            req_body_schema = self._resolve_ref(p.get("schema", {}), spec)
                            # Add as body parameter
                            parameters.append(APIParameter(
                                name=p.get("name", "body"),
                                location="body",
                                required=p.get("required", False),
                                schema_type="object",
                                schema_format="",
                                description=p.get("description", ""),
                            ))

                # Security
                op_security = operation.get("security", global_security)
                requires_auth = len(op_security) > 0 if op_security else False

                # Response schemas
                responses = operation.get("responses", {})
                response_schemas = {}
                for status_code, resp_obj in responses.items():
                    if isinstance(resp_obj, dict):
                        if version.startswith("swagger"):
                            s = resp_obj.get("schema")
                            if s:
                                response_schemas[str(status_code)] = self._resolve_ref(s, spec)
                        else:
                            content = resp_obj.get("content", {})
                            for _, media in content.items():
                                if isinstance(media, dict) and "schema" in media:
                                    response_schemas[str(status_code)] = self._resolve_ref(
                                        media["schema"], spec
                                    )
                                    break

                # Produces JSON?
                produces = operation.get("produces", spec.get("produces", []))
                produces_json = any("json" in p for p in produces) or not produces

                ep = APIEndpoint(
                    method=method,
                    path=path,
                    operation_id=operation.get("operationId", f"{method}_{path}"),
                    summary=operation.get("summary", ""),
                    tags=operation.get("tags", []),
                    parameters=parameters,
                    request_body_schema=req_body_schema,
                    response_schemas=response_schemas,
                    security=op_security or [],
                    requires_auth=requires_auth,
                    produces_json=produces_json,
                )
                endpoints.append(ep)

        return endpoints

    # ── Security findings ─────────────────────────────────

    def find_security_issues(
        self,
        endpoints: list[APIEndpoint],
        spec: dict,
        base_url: str,
    ) -> list[dict]:
        """Static analysis — find misconfigurations without hitting network."""
        findings = []
        idx = 1

        # 1. Unauthenticated sensitive endpoints
        sensitive_keywords = ["admin", "user", "account", "payment", "order", "invoice", "export"]
        for ep in endpoints:
            if not ep.requires_auth:
                path_lower = ep.path.lower()
                if any(kw in path_lower for kw in sensitive_keywords):
                    findings.append(self._make_finding(
                        idx=idx,
                        title=f"Sensitive endpoint without authentication: {ep.full_path}",
                        severity="HIGH",
                        cvss=7.5,
                        cwe="CWE-306",
                        description=(
                            f"{ep.full_path} handles sensitive data but has no security "
                            f"scheme defined in the OpenAPI spec. "
                            f"It may be accessible without authentication."
                        ),
                        evidence=f"Security: [] | Path: {ep.path}",
                        remediation=(
                            "Add appropriate security scheme to this endpoint in the spec "
                            "and enforce authentication server-side."
                        ),
                        endpoint=ep.full_path,
                    ))
                    idx += 1

        # 2. HTTP base URL (no TLS)
        if base_url.startswith("http://"):
            findings.append(self._make_finding(
                idx=idx,
                title="API serves over HTTP (no TLS)",
                severity="HIGH",
                cvss=7.4,
                cwe="CWE-319",
                description=(
                    f"The API base URL is {base_url} using plain HTTP. "
                    f"All traffic including credentials and tokens is transmitted in cleartext."
                ),
                evidence=f"Base URL: {base_url}",
                remediation="Enforce HTTPS. Redirect all HTTP traffic to HTTPS.",
                endpoint=base_url,
            ))
            idx += 1

        # 3. Password/secret params in GET
        for ep in endpoints:
            if ep.method.upper() == "GET":
                for param in ep.parameters:
                    if param.is_sensitive and param.location == "query":
                        findings.append(self._make_finding(
                            idx=idx,
                            title=f"Sensitive data in GET query parameter: {ep.path}?{param.name}",
                            severity="MEDIUM",
                            cvss=5.3,
                            cwe="CWE-598",
                            description=(
                                f"Sensitive parameter '{param.name}' is passed as a GET query "
                                f"parameter. It will be logged in server access logs, "
                                f"browser history, and proxy logs."
                            ),
                            evidence=f"GET {ep.path}?{param.name}=...",
                            remediation=(
                                "Move sensitive parameters to POST request body or "
                                "Authorization header. Never send credentials in URLs."
                            ),
                            endpoint=ep.full_path,
                        ))
                        idx += 1

        # 4. Endpoints exposing PII in response schema
        for ep in endpoints:
            for status, schema in ep.response_schemas.items():
                if not isinstance(schema, dict):
                    continue
                pii_fields = self._find_pii_in_schema(schema)
                if pii_fields and status == "200":
                    findings.append(self._make_finding(
                        idx=idx,
                        title=f"PII fields in response schema: {ep.full_path}",
                        severity="MEDIUM",
                        cvss=5.0,
                        cwe="CWE-213",
                        description=(
                            f"Response schema for {ep.full_path} contains potentially "
                            f"sensitive fields: {pii_fields}. "
                            f"Verify these are necessary and properly protected."
                        ),
                        evidence=f"Fields: {pii_fields}",
                        remediation=(
                            "Apply field-level access control. Strip sensitive fields "
                            "from responses unless explicitly needed by the client."
                        ),
                        endpoint=ep.full_path,
                    ))
                    idx += 1

        # 5. No global security defined
        if not spec.get("security") and not any(ep.requires_auth for ep in endpoints):
            findings.append(self._make_finding(
                idx=idx,
                title="No global security policy defined in spec",
                severity="MEDIUM",
                cvss=5.3,
                cwe="CWE-284",
                description=(
                    "The OpenAPI spec defines no global security requirements "
                    "and no per-endpoint security. This may indicate auth is "
                    "not enforced or not documented."
                ),
                evidence="spec.security: undefined",
                remediation=(
                    "Add a global security requirement to the spec. "
                    "Use security schemes (Bearer, OAuth2, API key) "
                    "and mark each endpoint's auth requirement explicitly."
                ),
                endpoint="spec-level",
            ))

        return findings

    # ── Attack plan builder ───────────────────────────────

    def _build_plan(self) -> AttackPlan:
        """Build full AttackPlan from loaded _raw_spec."""
        spec = self._raw_spec
        version = self.detect_version(spec)
        base_url = self.extract_base_url(spec)
        auth_schemes = self.extract_auth_schemes(spec)
        endpoints = self.extract_endpoints(spec)
        findings = self.find_security_issues(endpoints, spec, base_url)

        title = spec.get("info", {}).get("title", "Unknown API")

        return AttackPlan(
            spec_version=version,
            title=title,
            base_url=base_url,
            total_endpoints=len(endpoints),
            endpoints=endpoints,
            auth_schemes=auth_schemes,
            findings=findings,
        )

    # ── Helpers ───────────────────────────────────────────

    def _merge_params(self, path_params: list, op_params: list) -> list:
        """Merge path-level and operation-level params (op wins on conflict)."""
        merged = {p.get("name"): p for p in path_params if isinstance(p, dict)}
        for p in op_params:
            if isinstance(p, dict):
                merged[p.get("name")] = p
        return list(merged.values())

    def _parse_parameter(self, raw: dict, spec: dict, version: str) -> APIParameter:
        """Parse a raw parameter dict into APIParameter."""
        schema = raw.get("schema", {})
        if schema:
            schema = self._resolve_ref(schema, spec)
        else:
            schema = raw  # Swagger 2.0 inline schema

        return APIParameter(
            name=raw.get("name", ""),
            location=raw.get("in", "query"),
            required=raw.get("required", False),
            schema_type=schema.get("type", "string"),
            schema_format=schema.get("format", ""),
            enum_values=schema.get("enum", []),
            example=raw.get("example") or schema.get("example"),
            description=raw.get("description", ""),
        )

    def _resolve_ref(self, schema: dict, spec: dict) -> dict:
        """Resolve $ref to actual schema object."""
        if not isinstance(schema, dict):
            return {}
        ref = schema.get("$ref")
        if not ref:
            return schema
        parts = ref.lstrip("#/").split("/")
        obj = spec
        for part in parts:
            if isinstance(obj, dict):
                obj = obj.get(part, {})
        return obj if isinstance(obj, dict) else {}

    def _find_pii_in_schema(self, schema: dict) -> list[str]:
        """Find PII field names in a schema object."""
        pii_keywords = [
            "password", "email", "phone", "ssn", "dob", "address",
            "credit_card", "cvv", "token", "secret", "salary", "income",
        ]
        found = []
        props = schema.get("properties", {})
        for field_name in props:
            if any(kw in field_name.lower() for kw in pii_keywords):
                found.append(field_name)
        return found

    def _make_finding(self, idx: int, title: str, severity: str, cvss: float,
                      cwe: str, description: str, evidence: str,
                      remediation: str, endpoint: str) -> dict:
        return {
            "id":          f"OA-{idx:03d}",
            "title":       title,
            "severity":    severity,
            "cvss":        cvss,
            "cwe":         cwe,
            "endpoint":    endpoint,
            "description": description,
            "evidence":    evidence,
            "remediation": remediation,
            "timestamp":   datetime.now().isoformat(),
        }

    # ── Display & Save ────────────────────────────────────

    def print_plan(self, plan: AttackPlan):
        """Print attack plan summary to console."""
        console.print(f"\n[bold cyan]  OpenAPI Attack Plan — {plan.title}[/bold cyan]")
        console.print(f"  Spec    : {plan.spec_version}")
        console.print(f"  Base URL: [yellow]{plan.base_url}[/yellow]")
        console.print(f"  Auth    : {plan.auth_schemes or ['none detected']}\n")

        summary = plan.summary()
        console.print(f"  Endpoints  : {summary['total_endpoints']}")
        console.print(f"  Needs auth : {summary['auth_required']}")
        console.print(f"  Open       : [red]{summary['unauthenticated']}[/red]")
        console.print(f"  IDOR targets    : {summary['idor_targets']}")
        console.print(f"  Inject targets  : {summary['injectable_targets']}")
        console.print(f"  Mass assign     : {summary['mass_assign_targets']}\n")

        # High-value endpoints table
        table = Table(show_header=True, header_style="bold magenta",
                      title="Top Attack Targets")
        table.add_column("Method", width=8)
        table.add_column("Path")
        table.add_column("Auth", width=6)
        table.add_column("Attacks")

        for ep in plan.high_value_endpoints[:8]:
            auth_str = "[green]YES[/green]" if ep.requires_auth else "[red]NO[/red]"
            table.add_row(
                f"[cyan]{ep.method.upper()}[/cyan]",
                ep.path,
                auth_str,
                ", ".join(ep.attack_surface[:4]),
            )
        console.print(table)

        # Static findings
        if plan.findings:
            console.print(f"\n  [bold]Static findings: {len(plan.findings)}[/bold]")
            for f in plan.findings[:5]:
                color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(
                    f["severity"], "white"
                )
                console.print(
                    f"  [{color}][{f['severity']}][/{color}] {f['title'][:70]}"
                )

    def save_plan(self, plan: AttackPlan) -> Path:
        """Save attack plan to JSON."""
        data = {
            "tool":            "glitchicons",
            "module":          "openapi_parser",
            "version":         "0.8.0",
            "spec_version":    plan.spec_version,
            "title":           plan.title,
            "base_url":        plan.base_url,
            "auth_schemes":    plan.auth_schemes,
            "generated_at":    plan.generated_at,
            "summary":         plan.summary(),
            "static_findings": plan.findings,
            "attack_matrix": [
                {
                    "endpoint":      ep.full_path,
                    "summary":       ep.summary,
                    "tags":          ep.tags,
                    "requires_auth": ep.requires_auth,
                    "attacks":       ep.attack_surface,
                    "parameters":    [
                        {
                            "name":     p.name,
                            "in":       p.location,
                            "type":     p.schema_type,
                            "format":   p.schema_format,
                            "required": p.required,
                            "idor":     p.is_integer_id,
                            "inject":   p.is_injectable,
                            "sensitive": p.is_sensitive,
                        }
                        for p in ep.parameters
                    ],
                }
                for ep in plan.endpoints
            ],
        }

        slug = plan.title.lower().replace(" ", "_")[:30]
        out = self.output_dir / f"openapi_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        console.print(f"\n  Plan saved: [cyan]{out}[/cyan]")
        return out
