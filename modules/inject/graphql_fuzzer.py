"""
GraphQL Fuzzer — modules/inject/graphql_fuzzer.py

Attacks:
  1. Introspection dump      — extract full schema (types, fields, mutations)
  2. Field enumeration       — discover hidden/undocumented fields
  3. Nested query DoS        — deeply nested queries to exhaust server resources
  4. Batch query attack      — send 100+ operations in one request
  5. Injection via args      — SQLi/XSS/SSTI payloads in GraphQL arguments
  6. Auth bypass             — query sensitive fields without auth header
  7. Alias overload          — alias flooding to bypass rate limits

Usage:
    python3 glitchicons.py graphql https://target.com/graphql
    python3 glitchicons.py graphql https://target.com/graphql --introspect --dos-test
    python3 glitchicons.py graphql https://target.com/graphql --output ./findings/graphql

Author: ardanov96
"""

import json
import time
import httpx
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()


# ── Introspection Query ───────────────────────────────────

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
    args { ...InputValue }
    type { ...TypeRef }
  }
  inputFields { ...InputValue }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType { kind name }
    }
  }
}
"""

# ── Payload Sets ──────────────────────────────────────────

INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "<script>alert(1)</script>",
    "{{7*7}}",
    "'; DROP TABLE users; --",
    "../../../etc/passwd",
    "${7*7}",
    "admin' --",
]

SENSITIVE_FIELD_NAMES = [
    "password", "passwd", "secret", "token", "api_key", "apiKey",
    "private_key", "privateKey", "credit_card", "creditCard",
    "ssn", "social_security", "dob", "date_of_birth",
    "email", "phone", "address", "salary", "internal",
    "admin", "role", "permissions", "is_admin", "isAdmin",
]


class GraphQLFuzzer:
    """
    AI-guided GraphQL security fuzzer.

    Covers OWASP API Top 10 issues specific to GraphQL:
    - API8:2023 Security Misconfiguration (introspection enabled in prod)
    - API4:2023 Unrestricted Resource Consumption (nested DoS, batching)
    - API1:2023 Broken Object Level Authorization (field-level auth bypass)
    - API3:2023 Broken Object Property Level Authorization (hidden fields)
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "./findings/graphql",
        timeout: int = 10,
        delay: float = 0.5,
        headers: dict | None = None,
    ):
        self.target = target.rstrip("/")
        self.output_dir = Path(output_dir)
        self.timeout = timeout
        self.delay = delay
        self.headers = headers or {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Glitchicons Security Scanner)",
        }
        self.findings: list[dict] = []
        self.schema: dict | None = None
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ── Public Entry Point ────────────────────────────────

    def run(self, introspect: bool = True, dos_test: bool = False) -> list[dict]:
        """Run all GraphQL attack modules. Return list of findings."""
        console.print(f"\n[bold cyan]  GLITCHICONS GraphQL Fuzzer[/bold cyan]")
        console.print(f"  Target : [yellow]{self.target}[/yellow]")
        console.print(f"  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        # 1. Endpoint detection
        self._detect_endpoint()

        # 2. Introspection
        if introspect:
            self._test_introspection()

        # 3. Field enumeration (needs schema)
        if self.schema:
            self._enumerate_sensitive_fields()

        # 4. Injection via arguments
        self._test_argument_injection()

        # 5. Auth bypass
        self._test_auth_bypass()

        # 6. Alias flooding
        self._test_alias_overload()

        # 7. Batch attack
        self._test_batch_attack()

        # 8. Nested DoS (opt-in, more aggressive)
        if dos_test:
            self._test_nested_dos()

        # Report
        self._print_summary()
        self._save_report()

        return self.findings

    # ── Attack Modules ────────────────────────────────────

    def _detect_endpoint(self):
        """Try common GraphQL endpoint paths."""
        console.print("[cyan]  [1/8] GraphQL endpoint detection...[/cyan]")

        common_paths = [
            "/graphql", "/graphql/v1", "/api/graphql",
            "/v1/graphql", "/v2/graphql", "/query",
            "/gql", "/graphiql",
        ]

        for path in common_paths:
            url = self.target if self.target.endswith(
                tuple(common_paths)
            ) else self.target + path

            try:
                resp = httpx.post(
                    url,
                    json={"query": "{ __typename }"},
                    headers=self.headers,
                    timeout=self.timeout,
                    follow_redirects=True,
                )
                if resp.status_code == 200 and "data" in resp.text:
                    console.print(f"    [green]Found GraphQL endpoint: {url}[/green]")
                    self.target = url
                    return
            except (httpx.RequestError, httpx.TimeoutException):
                continue

        console.print(f"    [yellow]Using provided URL: {self.target}[/yellow]")

    def _test_introspection(self):
        """Test if introspection is enabled (CRITICAL in production)."""
        console.print("[cyan]  [2/8] Introspection test...[/cyan]")

        try:
            resp = self._gql_request(INTROSPECTION_QUERY)
            data = resp.json()

            if "data" in data and "__schema" in data.get("data", {}):
                schema = data["data"]["__schema"]
                self.schema = schema

                type_count = len(schema.get("types", []))
                has_mutation = schema.get("mutationType") is not None

                finding = self._make_finding(
                    title="GraphQL Introspection Enabled in Production",
                    severity="HIGH",
                    cvss=7.5,
                    cwe="CWE-200",
                    description=(
                        f"GraphQL introspection is enabled. "
                        f"Full schema exposed: {type_count} types, "
                        f"mutations: {'YES' if has_mutation else 'NO'}. "
                        f"Attackers can map the entire API surface without authentication."
                    ),
                    evidence=f"__schema returned {type_count} types",
                    remediation=(
                        "Disable introspection in production. "
                        "In Apollo Server: `introspection: false`. "
                        "In graphene: override `execute()` to block __schema queries."
                    ),
                )
                self.findings.append(finding)
                console.print(f"    [red]FINDING: Introspection enabled ({type_count} types)[/red]")

                # Save schema dump
                schema_file = self.output_dir / "schema_dump.json"
                schema_file.write_text(json.dumps(data, indent=2))
                console.print(f"    Schema saved: {schema_file}")

            else:
                console.print("    [green]Introspection disabled (good)[/green]")

        except (httpx.RequestError, httpx.TimeoutException, json.JSONDecodeError) as e:
            console.print(f"    [yellow]Introspection test error: {e}[/yellow]")

        time.sleep(self.delay)

    def _enumerate_sensitive_fields(self):
        """Find sensitive field names exposed in schema."""
        console.print("[cyan]  [3/8] Sensitive field enumeration...[/cyan]")

        if not self.schema:
            console.print("    [yellow]No schema available, skip[/yellow]")
            return

        found_fields = []
        for gql_type in self.schema.get("types", []):
            type_name = gql_type.get("name", "")
            if type_name.startswith("__"):
                continue
            for field in gql_type.get("fields") or []:
                field_name = field.get("name", "").lower()
                for sensitive in SENSITIVE_FIELD_NAMES:
                    if sensitive.lower() in field_name:
                        found_fields.append({
                            "type": type_name,
                            "field": field.get("name"),
                            "matched_keyword": sensitive,
                        })

        if found_fields:
            finding = self._make_finding(
                title="Sensitive Fields Exposed in GraphQL Schema",
                severity="MEDIUM",
                cvss=5.3,
                cwe="CWE-213",
                description=(
                    f"Schema exposes {len(found_fields)} potentially sensitive field(s). "
                    f"These may return sensitive data depending on authorization controls."
                ),
                evidence=json.dumps(found_fields[:5], indent=2),
                remediation=(
                    "Audit field-level permissions. "
                    "Apply @auth directives or resolver-level guards to sensitive fields. "
                    "Consider schema stitching to expose only public fields."
                ),
                extra={"sensitive_fields": found_fields},
            )
            self.findings.append(finding)
            console.print(f"    [yellow]Found {len(found_fields)} sensitive field(s)[/yellow]")
        else:
            console.print("    [green]No sensitive field names found[/green]")

    def _test_argument_injection(self):
        """Inject SQLi/XSS/SSTI payloads into GraphQL arguments."""
        console.print("[cyan]  [4/8] Argument injection test...[/cyan]")

        vulnerable = []
        for payload in INJECTION_PAYLOADS:
            queries = [
                f'{{ user(id: "{payload}") {{ id name }} }}',
                f'{{ search(query: "{payload}") {{ results }} }}',
                f'{{ login(username: "{payload}", password: "test") {{ token }} }}',
            ]
            for query in queries:
                try:
                    resp = self._gql_request(query)
                    body = resp.text

                    # Detect reflection of injection payload
                    if payload in body and "errors" not in body.lower():
                        vulnerable.append({
                            "payload": payload,
                            "query": query[:80],
                            "reflected": True,
                        })
                        break

                    # Detect SQL error signatures
                    sql_errors = [
                        "syntax error", "mysql_fetch", "ORA-", "SQLite",
                        "pg_query", "Unclosed quotation",
                    ]
                    if any(err.lower() in body.lower() for err in sql_errors):
                        vulnerable.append({
                            "payload": payload,
                            "query": query[:80],
                            "sql_error": True,
                        })
                        break

                except (httpx.RequestError, httpx.TimeoutException):
                    continue

                time.sleep(self.delay)

        if vulnerable:
            finding = self._make_finding(
                title="GraphQL Argument Injection Detected",
                severity="HIGH",
                cvss=8.1,
                cwe="CWE-89",
                description=(
                    f"GraphQL arguments reflect or process injection payloads unsafely. "
                    f"{len(vulnerable)} payload(s) produced anomalous responses."
                ),
                evidence=json.dumps(vulnerable[:3], indent=2),
                remediation=(
                    "Use parameterized resolvers — never interpolate arguments into raw queries. "
                    "Validate and sanitize all GraphQL input arguments. "
                    "Use an ORM or query builder instead of raw SQL in resolvers."
                ),
            )
            self.findings.append(finding)
            console.print(f"    [red]FINDING: {len(vulnerable)} injection payload(s) triggered[/red]")
        else:
            console.print("    [green]No injection vulnerabilities detected[/green]")

    def _test_auth_bypass(self):
        """Query sensitive fields without Authorization header."""
        console.print("[cyan]  [5/8] Auth bypass test...[/cyan]")

        # Remove auth header if present
        unauth_headers = {k: v for k, v in self.headers.items() if k.lower() != "authorization"}

        sensitive_queries = [
            "{ users { id email password role } }",
            "{ me { id email role permissions } }",
            "{ admin { users { email password } } }",
            "{ allUsers { id email isAdmin } }",
        ]

        accessible = []
        for query in sensitive_queries:
            try:
                resp = httpx.post(
                    self.target,
                    json={"query": query},
                    headers=unauth_headers,
                    timeout=self.timeout,
                    follow_redirects=True,
                )
                data = resp.json()

                # Non-error response to sensitive query = potential bypass
                if "data" in data and data.get("data") and resp.status_code == 200:
                    if not all(v is None for v in data["data"].values()):
                        accessible.append({
                            "query": query[:60],
                            "status": resp.status_code,
                        })

            except (httpx.RequestError, httpx.TimeoutException, json.JSONDecodeError):
                continue

            time.sleep(self.delay)

        if accessible:
            finding = self._make_finding(
                title="GraphQL Sensitive Fields Accessible Without Authentication",
                severity="CRITICAL",
                cvss=9.1,
                cwe="CWE-285",
                description=(
                    f"Sensitive GraphQL queries return data without Authorization header. "
                    f"{len(accessible)} query/queries returned non-null data unauthenticated."
                ),
                evidence=json.dumps(accessible, indent=2),
                remediation=(
                    "Implement authentication middleware at the GraphQL layer. "
                    "Use @auth or @authenticated directives on sensitive types/fields. "
                    "Never rely solely on frontend to hide sensitive queries."
                ),
            )
            self.findings.append(finding)
            console.print(f"    [red]FINDING: {len(accessible)} sensitive query/queries accessible[/red]")
        else:
            console.print("    [green]Auth checks appear to be in place[/green]")

    def _test_alias_overload(self):
        """Test alias flooding to bypass rate limiting."""
        console.print("[cyan]  [6/8] Alias overload test...[/cyan]")

        aliases = "\n".join(
            [f'  a{i}: __typename' for i in range(100)]
        )
        query = f"{{ {aliases} }}"

        try:
            start = time.time()
            resp = self._gql_request(query)
            elapsed = time.time() - start

            data = resp.json()
            alias_count_returned = len(data.get("data", {}).keys())

            if alias_count_returned >= 50:
                finding = self._make_finding(
                    title="GraphQL Alias Overload — Rate Limit Bypass",
                    severity="MEDIUM",
                    cvss=5.8,
                    cwe="CWE-770",
                    description=(
                        f"Server processed {alias_count_returned} aliased fields in {elapsed:.2f}s. "
                        f"Aliases can be used to bypass per-request rate limits and "
                        f"multiply the effective request rate without sending more HTTP requests."
                    ),
                    evidence=f"{alias_count_returned} aliases returned in {elapsed:.2f}s",
                    remediation=(
                        "Implement query complexity analysis. "
                        "Limit max aliases per query. "
                        "Use a GraphQL complexity library (e.g., graphql-query-complexity)."
                    ),
                )
                self.findings.append(finding)
                console.print(f"    [yellow]FINDING: {alias_count_returned} aliases processed[/yellow]")
            else:
                console.print("    [green]Alias count appears limited[/green]")

        except (httpx.RequestError, httpx.TimeoutException, json.JSONDecodeError) as e:
            console.print(f"    [yellow]Alias test error: {e}[/yellow]")

    def _test_batch_attack(self):
        """Test batch query attack — send 50 operations in one request."""
        console.print("[cyan]  [7/8] Batch query attack...[/cyan]")

        batch = [{"query": "{ __typename }"}] * 50

        try:
            start = time.time()
            resp = httpx.post(
                self.target,
                json=batch,
                headers=self.headers,
                timeout=self.timeout * 3,
                follow_redirects=True,
            )
            elapsed = time.time() - start

            if resp.status_code == 200:
                try:
                    result = resp.json()
                    if isinstance(result, list) and len(result) >= 10:
                        finding = self._make_finding(
                            title="GraphQL Batch Query Attack — Unrestricted Batching",
                            severity="MEDIUM",
                            cvss=5.3,
                            cwe="CWE-770",
                            description=(
                                f"Server processed {len(result)} batched operations in {elapsed:.2f}s. "
                                f"Unrestricted batching allows attackers to multiply request impact, "
                                f"enabling brute force and enumeration attacks bypassing rate limits."
                            ),
                            evidence=f"{len(result)} operations returned in {elapsed:.2f}s",
                            remediation=(
                                "Disable or limit GraphQL batching. "
                                "Set max batch size (e.g., 10 operations). "
                                "Apply rate limiting per operation, not per HTTP request."
                            ),
                        )
                        self.findings.append(finding)
                        console.print(f"    [yellow]FINDING: {len(result)} batch operations processed[/yellow]")
                        return
                except json.JSONDecodeError:
                    pass

            console.print("    [green]Batch queries appear limited or disabled[/green]")

        except (httpx.RequestError, httpx.TimeoutException) as e:
            console.print(f"    [yellow]Batch test error: {e}[/yellow]")

    def _test_nested_dos(self):
        """Test deeply nested query for DoS (opt-in, aggressive)."""
        console.print("[cyan]  [8/8] Nested query DoS test (depth=10)...[/cyan]")

        # Build a 10-level nested query
        def build_nested(depth: int) -> str:
            if depth == 0:
                return "{ __typename }"
            return f"{{ user {build_nested(depth - 1)} }}"

        query = build_nested(10)

        try:
            start = time.time()
            resp = self._gql_request(query, timeout=15)
            elapsed = time.time() - start

            if elapsed > 5.0:
                finding = self._make_finding(
                    title="GraphQL Nested Query DoS — No Depth Limiting",
                    severity="HIGH",
                    cvss=7.5,
                    cwe="CWE-400",
                    description=(
                        f"Deeply nested query (depth=10) took {elapsed:.2f}s to respond. "
                        f"Without query depth limiting, attackers can craft exponentially "
                        f"expensive queries to exhaust server CPU/memory."
                    ),
                    evidence=f"Depth-10 query responded in {elapsed:.2f}s",
                    remediation=(
                        "Implement query depth limiting (recommended max: 5-7). "
                        "Use graphql-depth-limit or similar library. "
                        "Combine with query complexity scoring."
                    ),
                )
                self.findings.append(finding)
                console.print(f"    [red]FINDING: Depth-10 query took {elapsed:.2f}s[/red]")
            else:
                console.print(f"    [green]Response time acceptable ({elapsed:.2f}s)[/green]")

        except (httpx.RequestError, httpx.TimeoutException) as e:
            console.print(f"    [yellow]Nested DoS test error: {e}[/yellow]")

    # ── Helpers ───────────────────────────────────────────

    def _gql_request(self, query: str, timeout: int | None = None) -> httpx.Response:
        """Send a GraphQL POST request."""
        return httpx.post(
            self.target,
            json={"query": query},
            headers=self.headers,
            timeout=timeout or self.timeout,
            follow_redirects=True,
        )

    def _make_finding(
        self,
        title: str,
        severity: str,
        cvss: float,
        cwe: str,
        description: str,
        evidence: str,
        remediation: str,
        **extra,
    ) -> dict:
        """Create a standardized finding object."""
        return {
            "id": f"GQL-{len(self.findings) + 1:03d}",
            "title": title,
            "severity": severity,
            "cvss": cvss,
            "cwe": cwe,
            "target": self.target,
            "description": description,
            "evidence": evidence,
            "remediation": remediation,
            "timestamp": datetime.now().isoformat(),
            **extra,
        }

    def _print_summary(self):
        """Print findings summary table."""
        console.print(f"\n[bold cyan]  Results for {self.target}[/bold cyan]")

        if not self.findings:
            console.print("  [green]No findings — target appears secure[/green]\n")
            return

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", style="cyan", width=8)
        table.add_column("Severity", width=10)
        table.add_column("CVSS", width=6)
        table.add_column("Title")

        severity_colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
            "INFO": "blue",
        }

        for f in sorted(self.findings, key=lambda x: x["cvss"], reverse=True):
            color = severity_colors.get(f["severity"], "white")
            table.add_row(
                f["id"],
                f"[{color}]{f['severity']}[/{color}]",
                str(f["cvss"]),
                f["title"],
            )

        console.print(table)

        total = len(self.findings)
        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        console.print(
            f"\n  Total: {total} | "
            f"[bold red]Critical: {critical}[/bold red] | "
            f"[red]High: {high}[/red]\n"
        )

    def _save_report(self):
        """Save JSON report to output directory."""
        report = {
            "tool": "glitchicons",
            "module": "graphql_fuzzer",
            "version": "0.7.0",
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings": sorted(self.findings, key=lambda x: x["cvss"], reverse=True),
        }

        report_file = self.output_dir / f"graphql_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_file.write_text(json.dumps(report, indent=2))
        console.print(f"  Report saved: [cyan]{report_file}[/cyan]")
