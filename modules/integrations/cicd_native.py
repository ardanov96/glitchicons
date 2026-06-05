"""
CI/CD Native Integration — modules/integrations/cicd_native.py

Native integrations for CI/CD pipelines and security platforms:
  1. SARIFExporter        — SARIF v2.1.0 for GitHub/GitLab Security tabs
  2. GitHubIntegration    — Checks API, SARIF upload, PR comment
  3. GitLabIntegration    — GitLab Security Report (SAST/DAST JSON format)
  4. DefectDojoIntegration — Push findings to DefectDojo engagements

Usage:
    from modules.integrations.cicd_native import (
        SARIFExporter, GitHubIntegration,
        GitLabIntegration, DefectDojoIntegration,
    )

    # Export SARIF
    sarif = SARIFExporter(tool_name="Glitchicons", tool_version="3.2.0")
    path  = sarif.export(findings, output_path="./gl-dast-report.sarif")

    # GitHub PR comment + SARIF upload
    gh = GitHubIntegration(token="ghp_...", repo="owner/repo")
    gh.post_pr_comment(pr_number=42, findings=findings)
    gh.upload_sarif(sarif_path="./results.sarif", ref="refs/heads/main")

    # GitLab Security Report
    gl = GitLabIntegration()
    gl.export_dast_report(findings, output_path="./gl-dast-report.json")

    # DefectDojo
    dd = DefectDojoIntegration(url="https://dojo.corp.com", api_key="...")
    dd.push_findings(findings, engagement_id=42, product_id=1)

Author: ardanov96
"""

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import httpx
from rich.console import Console

console = Console()

VERSION = "3.2.0"

# ── Severity maps ─────────────────────────────────────────

# SARIF severity levels
SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
    "INFO":     "none",
}

# GitLab severity levels
GITLAB_SEVERITY = {
    "CRITICAL": "Critical",
    "HIGH":     "High",
    "MEDIUM":   "Medium",
    "LOW":      "Low",
    "INFO":     "Info",
    "UNKNOWN":  "Unknown",
}

# DefectDojo severity
DOJO_SEVERITY = {
    "CRITICAL": "Critical",
    "HIGH":     "High",
    "MEDIUM":   "Medium",
    "LOW":      "Low",
    "INFO":     "Informational",
}


# ── Data classes ──────────────────────────────────────────

@dataclass
class SARIFResult:
    """SARIF v2.1.0 run result."""
    rule_id:     str
    level:       str        # error | warning | note | none
    message:     str
    uri:         str        # Target URL as URI
    snippet:     str = ""   # Evidence snippet
    help_uri:    str = ""


@dataclass
class GitHubCheckRun:
    """GitHub Check Run result."""
    name:        str
    head_sha:    str
    status:      str        # queued | in_progress | completed
    conclusion:  str = ""   # success | failure | neutral | cancelled
    title:       str = ""
    summary:     str = ""
    annotations: list[dict] = field(default_factory=list)


@dataclass
class GitLabVulnerability:
    """GitLab Security Report vulnerability entry."""
    id:          str
    name:        str
    severity:    str
    confidence:  str
    description: str
    scanner:     dict
    location:    dict
    identifiers: list[dict] = field(default_factory=list)
    links:       list[dict] = field(default_factory=list)
    solution:    str        = ""


@dataclass
class DojoFinding:
    """DefectDojo finding format."""
    title:         str
    severity:      str
    description:   str
    mitigation:    str
    impact:        str
    references:    str = ""
    cwe:           int = 0
    cvssv3_score:  float = 0.0
    url:           str = ""
    verified:      bool = False
    false_p:       bool = False
    active:        bool = True


@dataclass
class ExportResult:
    """Result of a findings export operation."""
    format:       str
    output_path:  str
    finding_count: int
    success:      bool
    message:      str = ""


# ── 1. SARIF Exporter ─────────────────────────────────────

class SARIFExporter:
    """
    Export Glitchicons findings to SARIF v2.1.0 format.

    SARIF (Static Analysis Results Interchange Format) is the
    industry standard for security tool output. Supported by:
    - GitHub Advanced Security (code scanning)
    - GitLab SAST/DAST
    - Azure DevOps
    - VS Code SARIF Viewer

    The exported file can be uploaded to GitHub via the
    /code-scanning/sarifs API endpoint.
    """

    SARIF_SCHEMA   = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    SARIF_VERSION  = "2.1.0"

    def __init__(
        self,
        tool_name: str = "Glitchicons",
        tool_version: str = VERSION,
        tool_url: str = "https://github.com/ardanov96/glitchicons",
    ):
        self.tool_name    = tool_name
        self.tool_version = tool_version
        self.tool_url     = tool_url

    def export(
        self,
        findings: list[dict],
        output_path: str = "./glitchicons.sarif",
    ) -> ExportResult:
        """Export findings to SARIF file."""
        sarif_doc = self.build_sarif(findings)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
        console.print(f"  [green]SARIF:[/green] {path} ({len(findings)} findings)")
        return ExportResult(
            format="sarif",
            output_path=str(path),
            finding_count=len(findings),
            success=True,
        )

    def build_sarif(self, findings: list[dict]) -> dict:
        """Build SARIF v2.1.0 document from findings."""
        rules   = self._build_rules(findings)
        results = [self._finding_to_result(f) for f in findings]

        return {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name":            self.tool_name,
                        "version":         self.tool_version,
                        "informationUri":  self.tool_url,
                        "rules":           rules,
                    }
                },
                "results":          results,
                "columnKind":       "utf16CodeUnits",
                "invocations": [{
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                }],
            }],
        }

    def _build_rules(self, findings: list[dict]) -> list[dict]:
        """Build SARIF rules from unique CWEs."""
        seen_rules: set[str] = set()
        rules = []
        for f in findings:
            rule_id = self._make_rule_id(f)
            if rule_id in seen_rules:
                continue
            seen_rules.add(rule_id)
            cwe     = f.get("cwe", "")
            rules.append({
                "id":   rule_id,
                "name": self._make_rule_name(f.get("title", "")),
                "shortDescription": {
                    "text": f.get("title", "Security Finding")[:200],
                },
                "fullDescription": {
                    "text": f.get("description", "")[:500] or f.get("title", ""),
                },
                "defaultConfiguration": {
                    "level": SARIF_LEVEL.get(f.get("severity", "INFO"), "none"),
                },
                "properties": {
                    "tags":     ["security", f.get("severity", "INFO").lower()],
                    "precision": "medium",
                    "severity":  f.get("severity", "INFO"),
                    "cwe":       cwe,
                },
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html" if cwe else "",
            })
        return rules

    def _finding_to_result(self, finding: dict) -> dict:
        """Convert a Glitchicons finding to SARIF result."""
        target  = finding.get("target", "https://unknown")
        uri     = target if target.startswith("http") else f"https://{target}"
        rule_id = self._make_rule_id(finding)
        level   = SARIF_LEVEL.get(finding.get("severity", "INFO"), "none")
        evidence = finding.get("evidence", "")[:500]

        result: dict = {
            "ruleId":  rule_id,
            "level":   level,
            "message": {
                "text": f"{finding.get('title', '')}. {finding.get('description', '')}".strip()[:1000],
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": uri,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": 1,
                        "snippet": {"text": evidence[:200]} if evidence else None,
                    },
                }
            }],
            "properties": {
                "severity":     finding.get("severity", "INFO"),
                "cvss":         finding.get("cvss", 0.0),
                "cwe":          finding.get("cwe", ""),
                "source":       finding.get("source", ""),
                "remediation":  finding.get("remediation", "")[:500],
            },
        }

        # Clean None values
        if not evidence:
            del result["locations"][0]["physicalLocation"]["region"]["snippet"]

        return result

    def _make_rule_id(self, finding: dict) -> str:
        """Generate stable rule ID from finding."""
        cwe   = finding.get("cwe", "").replace("CWE-", "")
        sev   = finding.get("severity", "INFO")
        title = finding.get("title", "")[:20]
        slug  = "".join(c if c.isalnum() else "_" for c in title).lower()
        if cwe:
            return f"GI{cwe.zfill(4)}"
        return f"GI-{sev[:3]}-{slug}"

    def _make_rule_name(self, title: str) -> str:
        words = title.split()
        return "".join(w.capitalize() for w in words[:5])

    def count_by_level(self, findings: list[dict]) -> dict:
        """Count findings by SARIF level."""
        counts: dict[str, int] = {}
        for f in findings:
            level = SARIF_LEVEL.get(f.get("severity", "INFO"), "none")
            counts[level] = counts.get(level, 0) + 1
        return counts


# ── 2. GitHub Integration ─────────────────────────────────

class GitHubIntegration:
    """
    Native GitHub integration.

    Features:
    - Upload SARIF to GitHub Code Scanning
    - Post PR comments with finding summary
    - Create GitHub Check Runs with annotations
    - Comment format: markdown table by severity

    Requires: GitHub token with security_events + checks write scope.
    """

    BASE_URL = "https://api.github.com"

    def __init__(
        self,
        token: str,
        repo: str,     # "owner/repo"
        timeout: int = 15,
    ):
        self.token   = token
        self.repo    = repo
        self.timeout = timeout
        self.client  = httpx.Client(
            timeout=timeout,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept":        "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent":    f"Glitchicons/{VERSION}",
            },
        )

    def post_pr_comment(
        self,
        pr_number: int,
        findings: list[dict],
        scan_target: str = "",
    ) -> dict:
        """Post a scan summary comment on a pull request."""
        body = self._build_pr_comment(findings, scan_target)
        url  = f"{self.BASE_URL}/repos/{self.repo}/issues/{pr_number}/comments"
        try:
            resp = self.client.post(url, json={"body": body})
            return {
                "success":    resp.status_code in (200, 201),
                "comment_id": resp.json().get("id") if resp.status_code in (200, 201) else None,
                "status_code": resp.status_code,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def upload_sarif(
        self,
        sarif_path: str,
        ref: str,
        commit_sha: str = "",
    ) -> dict:
        """Upload SARIF file to GitHub Code Scanning."""
        import base64, gzip
        path = Path(sarif_path)
        if not path.exists():
            return {"success": False, "error": f"SARIF file not found: {sarif_path}"}

        content     = path.read_bytes()
        compressed  = gzip.compress(content)
        encoded     = base64.b64encode(compressed).decode("utf-8")

        url = f"{self.BASE_URL}/repos/{self.repo}/code-scanning/sarifs"
        payload = {
            "ref":          ref,
            "commit_sha":   commit_sha or self._get_latest_commit(ref),
            "sarif":        encoded,
            "tool_name":    "Glitchicons",
        }
        try:
            resp = self.client.post(url, json=payload)
            data = resp.json() if resp.status_code in (200, 201, 202) else {}
            return {
                "success":    resp.status_code in (200, 201, 202),
                "analysis_id": data.get("id"),
                "status_code": resp.status_code,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def create_check_run(
        self,
        name: str,
        head_sha: str,
        findings: list[dict],
        conclusion: str = "",
    ) -> dict:
        """Create a GitHub Check Run with finding annotations."""
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high     = sum(1 for f in findings if f.get("severity") == "HIGH")

        if not conclusion:
            conclusion = "failure" if (critical + high) > 0 else "success"

        annotations = self._build_annotations(findings[:50])  # GitHub limit: 50

        payload = {
            "name":       name,
            "head_sha":   head_sha,
            "status":     "completed",
            "conclusion": conclusion,
            "output": {
                "title":       f"Glitchicons: {len(findings)} findings",
                "summary":     self._check_summary(findings),
                "annotations": annotations,
            },
        }
        url = f"{self.BASE_URL}/repos/{self.repo}/check-runs"
        try:
            resp = self.client.post(url, json=payload)
            return {
                "success":       resp.status_code in (200, 201),
                "check_run_id":  resp.json().get("id") if resp.status_code in (200, 201) else None,
                "conclusion":    conclusion,
                "status_code":   resp.status_code,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_open_prs(self) -> list[dict]:
        """List open pull requests for the repo."""
        url = f"{self.BASE_URL}/repos/{self.repo}/pulls?state=open"
        try:
            resp = self.client.get(url)
            if resp.status_code == 200:
                return resp.json()
            return []
        except Exception:
            return []

    def _build_pr_comment(self, findings: list[dict], target: str = "") -> str:
        """Build a markdown PR comment with finding summary."""
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high     = sum(1 for f in findings if f.get("severity") == "HIGH")
        medium   = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        low      = sum(1 for f in findings if f.get("severity") == "LOW")

        status_icon = "🔴" if critical > 0 else ("🟡" if high > 0 else "🟢")
        target_line = f"\n**Target:** `{target}`" if target else ""

        lines = [
            f"## {status_icon} Glitchicons Security Scan Results",
            target_line,
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| 🔴 Critical | {critical} |",
            f"| 🟠 High | {high} |",
            f"| 🟡 Medium | {medium} |",
            f"| 🟢 Low | {low} |",
            f"| **Total** | **{len(findings)}** |",
            "",
        ]

        # Top 5 critical/high findings
        top_findings = [f for f in findings
                        if f.get("severity") in ("CRITICAL", "HIGH")][:5]
        if top_findings:
            lines.append("### Top Findings")
            lines.append("")
            for f in top_findings:
                sev_icon = "🔴" if f.get("severity") == "CRITICAL" else "🟠"
                lines.append(f"- {sev_icon} **{f.get('title', 'Unknown')}**  ")
                lines.append(f"  `{f.get('target', '')}` — CVSS: {f.get('cvss', 0)}")
            lines.append("")

        lines.append("---")
        lines.append(f"*Generated by [Glitchicons](https://github.com/ardanov96/glitchicons) v{VERSION}*")

        return "\n".join(lines)

    def _build_annotations(self, findings: list[dict]) -> list[dict]:
        """Build GitHub Check annotations from findings."""
        annotations = []
        for f in findings:
            level = "failure" if f.get("severity") in ("CRITICAL", "HIGH") else "warning"
            annotations.append({
                "path":              ".",
                "start_line":        1,
                "end_line":          1,
                "annotation_level":  level,
                "message":           f"[{f.get('severity')}] {f.get('title', '')}",
                "title":             f.get("title", "")[:255],
                "raw_details":       f.get("evidence", "")[:64000],
            })
        return annotations

    def _check_summary(self, findings: list[dict]) -> str:
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        parts = [f"{sev}: {count}" for sev, count in severity_counts.items()]
        return f"Found {len(findings)} security issues. " + ", ".join(parts)

    def _get_latest_commit(self, ref: str) -> str:
        """Get latest commit SHA for a ref."""
        branch = ref.replace("refs/heads/", "")
        url    = f"{self.BASE_URL}/repos/{self.repo}/git/ref/heads/{branch}"
        try:
            resp = self.client.get(url)
            if resp.status_code == 200:
                return resp.json().get("object", {}).get("sha", "")
        except Exception:
            pass
        return ""


# ── 3. GitLab Integration ─────────────────────────────────

class GitLabIntegration:
    """
    Native GitLab CI/CD integration.

    Exports findings in GitLab Security Report formats:
    - DAST (Dynamic Analysis): gl-dast-report.json
    - SAST (Static Analysis):  gl-sast-report.json
    - Dependency Scanning:     gl-dependency-scanning-report.json

    The exported JSON is uploaded as a GitLab CI artifact,
    which GitLab automatically parses and displays in MRs.

    .gitlab-ci.yml example:
        glitchicons_scan:
          script: python glitchicons.py scan --target $CI_ENVIRONMENT_URL
          artifacts:
            reports:
              dast: gl-dast-report.json
    """

    SCHEMA_VERSION = "15.0.7"

    def __init__(
        self,
        scanner_name: str = "Glitchicons",
        scanner_version: str = VERSION,
        gitlab_url: str = "",
        token: str = "",
    ):
        self.scanner_name    = scanner_name
        self.scanner_version = scanner_version
        self.gitlab_url      = gitlab_url
        self.token           = token
        self._scanner_info   = {
            "id":      "glitchicons",
            "name":    scanner_name,
            "url":     "https://github.com/ardanov96/glitchicons",
            "vendor":  {"name": "ARDATRON"},
            "version": scanner_version,
        }

    def export_dast_report(
        self,
        findings: list[dict],
        output_path: str = "./gl-dast-report.json",
        target_url: str = "",
    ) -> ExportResult:
        """Export findings as GitLab DAST Security Report."""
        doc = self._build_report(findings, "dast", target_url)
        return self._write_report(doc, output_path, findings)

    def export_sast_report(
        self,
        findings: list[dict],
        output_path: str = "./gl-sast-report.json",
    ) -> ExportResult:
        """Export findings as GitLab SAST Security Report."""
        doc = self._build_report(findings, "sast")
        return self._write_report(doc, output_path, findings)

    def _build_report(
        self,
        findings: list[dict],
        scan_type: str,
        target_url: str = "",
    ) -> dict:
        """Build GitLab Security Report document."""
        vulns = [self._finding_to_vuln(f) for f in findings]
        now   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

        doc: dict = {
            "version":          self.SCHEMA_VERSION,
            "vulnerabilities":  vulns,
            "scan": {
                "scanner":    self._scanner_info,
                "type":       scan_type,
                "start_time": now,
                "end_time":   now,
                "status":     "success",
                "analyzer": {
                    "id":      "glitchicons",
                    "name":    self.scanner_name,
                    "url":     "https://github.com/ardanov96/glitchicons",
                    "version": self.scanner_version,
                },
            },
        }

        if target_url and scan_type == "dast":
            doc["scan"]["primary_identifiers"] = []
            doc["scan"]["scanned_resources"] = [
                {"url": target_url, "request_method": "GET", "type": "url"}
            ]

        return doc

    def _finding_to_vuln(self, finding: dict) -> dict:
        """Convert Glitchicons finding to GitLab vulnerability."""
        vid      = str(uuid.uuid5(uuid.NAMESPACE_URL, finding.get("title", "") +
                                  finding.get("target", "")))
        cwe      = finding.get("cwe", "")
        cvss     = finding.get("cvss", 0.0)
        target   = finding.get("target", "")

        identifiers = []
        if cwe:
            num = cwe.replace("CWE-", "")
            identifiers.append({
                "type":  "cwe",
                "name":  f"CWE-{num}",
                "value": num,
                "url":   f"https://cwe.mitre.org/data/definitions/{num}.html",
            })
        identifiers.append({
            "type":  "glitchicons_finding",
            "name":  finding.get("title", "")[:100],
            "value": vid,
        })

        return {
            "id":          vid,
            "category":    "dast",
            "name":        finding.get("title", ""),
            "message":     finding.get("title", ""),
            "description": finding.get("description", ""),
            "severity":    GITLAB_SEVERITY.get(finding.get("severity", "INFO"), "Unknown"),
            "confidence":  "High" if cvss >= 7.0 else "Medium",
            "solution":    finding.get("remediation", ""),
            "scanner":     self._scanner_info,
            "identifiers": identifiers,
            "location": {
                "hostname":   target,
                "path":       "/",
                "method":     "GET",
                "param":      "",
            },
            "evidence": {
                "summary": finding.get("evidence", "")[:500],
            },
            "cvss_v3": {
                "base_score":     cvss,
                "vector_string":  "",
            } if cvss > 0 else {},
        }

    def _write_report(
        self,
        doc: dict,
        output_path: str,
        findings: list[dict],
    ) -> ExportResult:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        console.print(f"  [green]GitLab Report:[/green] {path} ({len(findings)} vulns)")
        return ExportResult(
            format="gitlab",
            output_path=str(path),
            finding_count=len(findings),
            success=True,
        )


# ── 4. DefectDojo Integration ─────────────────────────────

class DefectDojoIntegration:
    """
    Push findings to DefectDojo security management platform.

    DefectDojo is an open-source ASPM platform for tracking
    vulnerabilities across products and engagements.

    Creates test + findings in an existing engagement.
    Supports deduplication by title+description hash.

    API docs: https://demo.defectdojo.org/api/v2/doc/
    """

    def __init__(
        self,
        url: str,
        api_key: str,
        timeout: int = 15,
        verify_ssl: bool = True,
    ):
        self.url     = url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.client  = httpx.Client(
            timeout=timeout,
            verify=verify_ssl,
            headers={
                "Authorization": f"Token {api_key}",
                "Content-Type":  "application/json",
                "User-Agent":    f"Glitchicons/{VERSION}",
            },
        )

    def push_findings(
        self,
        findings: list[dict],
        engagement_id: int,
        product_id: int,
        test_title: str = "",
        scan_type: str = "Generic Findings Import",
    ) -> dict:
        """
        Push findings to a DefectDojo engagement.

        Creates a new Test in the engagement, then imports
        all findings into that test.

        Returns dict with test_id and finding count.
        """
        # Create test
        test_id = self._create_test(engagement_id, test_title, scan_type)
        if not test_id:
            return {"success": False, "error": "Failed to create test in DefectDojo"}

        # Push findings
        pushed  = 0
        errors  = 0
        for f in findings:
            ok = self._create_finding(f, test_id, product_id)
            if ok:
                pushed += 1
            else:
                errors += 1

        console.print(
            f"  [green]DefectDojo:[/green] test_id={test_id} "
            f"pushed={pushed} errors={errors}"
        )
        return {
            "success":  errors == 0,
            "test_id":  test_id,
            "pushed":   pushed,
            "errors":   errors,
        }

    def get_product(self, product_id: int) -> dict | None:
        """Get a DefectDojo product by ID."""
        try:
            resp = self.client.get(f"{self.url}/api/v2/products/{product_id}/")
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    def get_engagement(self, engagement_id: int) -> dict | None:
        """Get a DefectDojo engagement by ID."""
        try:
            resp = self.client.get(f"{self.url}/api/v2/engagements/{engagement_id}/")
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    def list_findings(
        self,
        engagement_id: int | None = None,
        product_id: int | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """List findings from DefectDojo with optional filters."""
        params: dict = {"limit": limit}
        if engagement_id:
            params["test__engagement"] = engagement_id
        if product_id:
            params["test__engagement__product"] = product_id
        if severity:
            params["severity"] = DOJO_SEVERITY.get(severity, severity)
        try:
            resp = self.client.get(f"{self.url}/api/v2/findings/", params=params)
            if resp.status_code == 200:
                return resp.json().get("results", [])
        except Exception:
            pass
        return []

    def close_finding(self, finding_id: int) -> bool:
        """Mark a finding as mitigated in DefectDojo."""
        try:
            resp = self.client.patch(
                f"{self.url}/api/v2/findings/{finding_id}/",
                json={"mitigated": True, "is_mitigated": True, "active": False},
            )
            return resp.status_code in (200, 201, 204)
        except Exception:
            return False

    def _create_test(
        self,
        engagement_id: int,
        title: str = "",
        scan_type: str = "Generic Findings Import",
    ) -> int | None:
        """Create a test in DefectDojo and return test ID."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        payload = {
            "engagement":      engagement_id,
            "test_type":       1,   # Generic
            "target_start":    now,
            "target_end":      now,
            "title":           title or f"Glitchicons Scan {now}",
            "scan_type":       scan_type,
            "environment":     "Production",
        }
        try:
            resp = self.client.post(f"{self.url}/api/v2/tests/", json=payload)
            if resp.status_code in (200, 201):
                return resp.json().get("id")
        except Exception:
            pass
        return None

    def _create_finding(self, finding: dict, test_id: int, product_id: int) -> bool:
        """Create a single finding in DefectDojo."""
        cwe_raw = finding.get("cwe", "").replace("CWE-", "")
        cwe_int = int(cwe_raw) if cwe_raw.isdigit() else 0
        payload = {
            "test":         test_id,
            "title":        finding.get("title", "")[:500],
            "severity":     DOJO_SEVERITY.get(finding.get("severity", "INFO"), "Informational"),
            "description":  finding.get("description", ""),
            "mitigation":   finding.get("remediation", ""),
            "impact":       f"CVSS: {finding.get('cvss', 0.0)}",
            "references":   finding.get("target", ""),
            "cwe":          cwe_int,
            "cvssv3_score": finding.get("cvss", 0.0),
            "url":          finding.get("target", ""),
            "active":       True,
            "verified":     False,
            "false_p":      finding.get("false_positive", False),
            "duplicate":    False,
        }
        try:
            resp = self.client.post(f"{self.url}/api/v2/findings/", json=payload)
            return resp.status_code in (200, 201)
        except Exception:
            return False
