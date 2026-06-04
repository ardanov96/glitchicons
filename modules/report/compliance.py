"""
Compliance & Reporting v2 — modules/report/compliance.py

Map security findings to compliance frameworks:
  1. OWASPMapper      — OWASP Top 10 2021 category mapping
  2. PCIDSSChecker    — PCI DSS v4.0 requirement mapping
  3. ISO27001Mapper   — ISO 27001:2022 Annex A control mapping
  4. ComplianceReporter — unified compliance report generation

Usage:
    from modules.report.compliance import (
        OWASPMapper, PCIDSSChecker, ISO27001Mapper, ComplianceReporter,
    )

    findings = [...]  # From any Glitchicons module

    # Map to OWASP
    owasp = OWASPMapper()
    report = owasp.map_findings(findings)

    # Full compliance report
    reporter = ComplianceReporter(
        findings=findings,
        target="target.com",
        output_dir="./findings/compliance",
    )
    reporter.generate_all()

Author: ardanov96
"""

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()


# ── OWASP Top 10 2021 ────────────────────────────────────

OWASP_TOP10_2021 = {
    "A01": {
        "name":   "Broken Access Control",
        "cwes":   ["CWE-200", "CWE-201", "CWE-352", "CWE-284", "CWE-285",
                   "CWE-639", "CWE-269", "CWE-732", "CWE-425", "CWE-602"],
        "keywords": ["idor", "access control", "privilege", "authorization",
                     "broken access", "force browse", "horizontal", "vertical",
                     "admin endpoint", "rbac", "role escalation"],
        "description": "Restrictions on authenticated users are not properly enforced.",
        "remediation": "Deny by default. Implement RBAC. Log access failures. Limit CORS.",
    },
    "A02": {
        "name":   "Cryptographic Failures",
        "cwes":   ["CWE-310", "CWE-311", "CWE-312", "CWE-319", "CWE-326",
                   "CWE-327", "CWE-328", "CWE-330", "CWE-331", "CWE-338"],
        "keywords": ["weak cipher", "cleartext", "unencrypted", "md5", "sha1",
                     "hardcoded secret", "api key exposed", "weak tls",
                     "ssl", "tls 1.0", "tls 1.1", "des", "rc4", "entropy"],
        "description": "Failures related to cryptography leading to data exposure.",
        "remediation": "Encrypt sensitive data at rest and in transit. Use strong algorithms.",
    },
    "A03": {
        "name":   "Injection",
        "cwes":   ["CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-90",
                   "CWE-94", "CWE-917", "CWE-1321"],
        "keywords": ["sql injection", "sqli", "xss", "cross-site scripting",
                     "command injection", "ssti", "template injection",
                     "ldap injection", "nosql injection", "xxe", "code injection",
                     "script injection", "prototype pollution"],
        "description": "User-supplied data is not validated, filtered, or sanitized.",
        "remediation": "Use parameterized queries. Validate and escape input. Apply allowlisting.",
    },
    "A04": {
        "name":   "Insecure Design",
        "cwes":   ["CWE-73", "CWE-183", "CWE-209", "CWE-256", "CWE-501",
                   "CWE-522", "CWE-840", "CWE-841"],
        "keywords": ["business logic", "price manipulation", "workflow bypass",
                     "design flaw", "race condition", "logic flaw",
                     "payment skip", "discount overflow", "missing limit"],
        "description": "Missing or ineffective security controls by design.",
        "remediation": "Use threat modeling. Apply secure design principles.",
    },
    "A05": {
        "name":   "Security Misconfiguration",
        "cwes":   ["CWE-2", "CWE-16", "CWE-388", "CWE-489", "CWE-693",
                   "CWE-732", "CWE-749"],
        "keywords": ["misconfiguration", "debug mode", "verbose error",
                     "default credential", "exposed admin", "cors misconfiguration",
                     "missing header", "hsts", "x-frame-options", "csp",
                     "directory listing", "s3 public", "k8s privileged",
                     "dockerfile root"],
        "description": "Missing security hardening or improperly configured permissions.",
        "remediation": "Automate configuration review. Apply security benchmarks (CIS).",
    },
    "A06": {
        "name":   "Vulnerable and Outdated Components",
        "cwes":   ["CWE-937", "CWE-1035", "CWE-1104"],
        "keywords": ["cve-", "vulnerable version", "outdated", "known vulnerability",
                     "eternalblue", "log4shell", "spring4shell", "bluekeep",
                     "exploit available", "epss", "unpatched", "deprecated"],
        "description": "Components with known vulnerabilities used without patching.",
        "remediation": "Maintain SBOM. Subscribe to security advisories. Automate patching.",
    },
    "A07": {
        "name":   "Identification and Authentication Failures",
        "cwes":   ["CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290",
                   "CWE-294", "CWE-295", "CWE-297", "CWE-300", "CWE-302",
                   "CWE-303", "CWE-304", "CWE-305", "CWE-306", "CWE-307",
                   "CWE-321", "CWE-384", "CWE-521", "CWE-613", "CWE-620",
                   "CWE-640"],
        "keywords": ["authentication", "mfa bypass", "jwt", "oauth", "saml",
                     "pkce", "sso", "session fixation", "weak password",
                     "brute force", "credential", "remember me", "token",
                     "account takeover", "ato", "password reset"],
        "description": "Authentication and session management implemented incorrectly.",
        "remediation": "Implement MFA. Use secure session management. Enforce password policy.",
    },
    "A08": {
        "name":   "Software and Data Integrity Failures",
        "cwes":   ["CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502",
                   "CWE-565", "CWE-784", "CWE-829", "CWE-830"],
        "keywords": ["deserialization", "supply chain", "unpinned action",
                     "unsigned", "curl bash", "untrusted source",
                     "insecure deserialization", "viewstate", "pickle",
                     "yaml.load", "dependency confusion"],
        "description": "Code and infrastructure without integrity verification.",
        "remediation": "Verify digital signatures. Use trusted package sources.",
    },
    "A09": {
        "name":   "Security Logging and Monitoring Failures",
        "cwes":   ["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
        "keywords": ["logging", "monitoring", "audit", "no healthcheck",
                     "missing log", "no alert", "secret in log"],
        "description": "Insufficient logging and monitoring enabling attackers to persist.",
        "remediation": "Log auth events. Set up alerting. Use SIEM. Test detection.",
    },
    "A10": {
        "name":   "Server-Side Request Forgery (SSRF)",
        "cwes":   ["CWE-918"],
        "keywords": ["ssrf", "server-side request", "169.254.169.254",
                     "metadata endpoint", "imds", "internal request",
                     "blind ssrf", "partial ssrf"],
        "description": "Application fetches remote resource using attacker-controlled URL.",
        "remediation": "Validate and allowlist URLs. Block 169.254.x.x, 10.x.x.x. Use allowlist.",
    },
}


# ── PCI DSS v4.0 Requirements ─────────────────────────────

PCI_DSS_REQUIREMENTS = {
    "6.2": {
        "title":    "Bespoke and custom software are developed securely",
        "keywords": ["xss", "sqli", "injection", "csrf", "ssti", "xxe",
                     "insecure code", "input validation"],
        "severity": "HIGH",
        "guidance": "All custom code must be reviewed for common vulnerabilities (OWASP Top 10).",
    },
    "6.3": {
        "title":    "Security vulnerabilities are identified and addressed",
        "keywords": ["cve-", "vulnerable", "unpatched", "outdated", "known exploit"],
        "severity": "HIGH",
        "guidance": "Maintain a vulnerability management process. Patch critical within 1 month.",
    },
    "6.4": {
        "title":    "Public-facing web applications are protected",
        "keywords": ["waf", "web application firewall", "cors", "xss",
                     "sqli", "public endpoint", "api exposed"],
        "severity": "HIGH",
        "guidance": "Deploy WAF or conduct periodic security assessments for public-facing apps.",
    },
    "7.1": {
        "title":    "Access to system components is limited by business need",
        "keywords": ["access control", "privilege", "admin endpoint",
                     "rbac", "idor", "unauthorized access"],
        "severity": "HIGH",
        "guidance": "Implement deny-by-default. Restrict access to minimum necessary.",
    },
    "7.2": {
        "title":    "Access to system components is managed via access control system",
        "keywords": ["role escalation", "privilege escalation", "admin bypass",
                     "permission", "unauthorized"],
        "severity": "HIGH",
        "guidance": "Use role-based access control. Review access quarterly.",
    },
    "8.2": {
        "title":    "User identification and accounts are managed",
        "keywords": ["mfa", "multi-factor", "authentication", "weak password",
                     "default credential", "credential"],
        "severity": "HIGH",
        "guidance": "Enforce MFA for all administrative access. Disable default accounts.",
    },
    "8.3": {
        "title":    "User authentication is managed",
        "keywords": ["jwt", "session", "token", "oauth", "saml", "pkce",
                     "password reset", "account takeover", "session fixation"],
        "severity": "HIGH",
        "guidance": "Implement secure session management. Enforce session timeout.",
    },
    "4.2": {
        "title":    "PAN is protected with strong cryptography during transmission",
        "keywords": ["cleartext", "unencrypted", "tls", "ssl", "https",
                     "weak cipher", "hsts missing", "tls 1.0", "tls 1.1"],
        "severity": "CRITICAL",
        "guidance": "Use TLS 1.2+ for all cardholder data transmission. Disable weak protocols.",
    },
    "3.5": {
        "title":    "Primary account number is secured with encryption",
        "keywords": ["hardcoded secret", "api key exposed", "credential exposed",
                     "secret in code", "cleartext password"],
        "severity": "CRITICAL",
        "guidance": "Encrypt stored credentials. Never hardcode secrets.",
    },
    "10.2": {
        "title":    "Audit logs capture all security events",
        "keywords": ["logging", "audit", "no log", "missing healthcheck"],
        "severity": "MEDIUM",
        "guidance": "Log all authentication events, privilege changes, and security failures.",
    },
    "11.3": {
        "title":    "External and internal vulnerabilities are regularly identified",
        "keywords": ["vulnerability", "scan", "pentest", "finding"],
        "severity": "MEDIUM",
        "guidance": "Perform quarterly external vulnerability scans. Annual penetration tests.",
    },
    "12.3": {
        "title":    "Risks are formally identified, evaluated, and managed",
        "keywords": ["risk", "cvss", "severity", "remediation"],
        "severity": "MEDIUM",
        "guidance": "Maintain a risk register. Prioritize by CVSS score.",
    },
}


# ── ISO 27001:2022 Annex A Controls ───────────────────────

ISO27001_CONTROLS = {
    "A.5.14": {
        "title":    "Information transfer",
        "keywords": ["cleartext", "unencrypted", "tls", "data exposure",
                     "ssrf", "sensitive data"],
        "domain":   "5. Organizational Controls",
    },
    "A.5.24": {
        "title":    "Information security incident management",
        "keywords": ["logging", "monitoring", "incident", "alert"],
        "domain":   "5. Organizational Controls",
    },
    "A.6.8": {
        "title":    "Information security event reporting",
        "keywords": ["logging", "audit trail", "no log"],
        "domain":   "6. People Controls",
    },
    "A.7.6": {
        "title":    "Working in secure areas",
        "keywords": ["access control", "privilege", "admin"],
        "domain":   "7. Physical Controls",
    },
    "A.8.2": {
        "title":    "Privileged access rights",
        "keywords": ["privilege escalation", "admin access", "rbac",
                     "role escalation", "sudo", "root"],
        "domain":   "8. Technological Controls",
    },
    "A.8.3": {
        "title":    "Information access restriction",
        "keywords": ["access control", "idor", "unauthorized", "broken access"],
        "domain":   "8. Technological Controls",
    },
    "A.8.5": {
        "title":    "Secure authentication",
        "keywords": ["authentication", "mfa", "weak password", "jwt", "oauth",
                     "session", "token", "saml", "pkce"],
        "domain":   "8. Technological Controls",
    },
    "A.8.7": {
        "title":    "Protection against malware",
        "keywords": ["malware", "supply chain", "dependency confusion",
                     "untrusted package"],
        "domain":   "8. Technological Controls",
    },
    "A.8.8": {
        "title":    "Management of technical vulnerabilities",
        "keywords": ["cve-", "vulnerability", "unpatched", "outdated",
                     "known exploit", "epss"],
        "domain":   "8. Technological Controls",
    },
    "A.8.9": {
        "title":    "Configuration management",
        "keywords": ["misconfiguration", "default config", "debug mode",
                     "cors", "missing header", "s3 public", "k8s"],
        "domain":   "8. Technological Controls",
    },
    "A.8.20": {
        "title":    "Network security",
        "keywords": ["network", "smb", "ssh", "rdp", "port exposed",
                     "firewall", "open port"],
        "domain":   "8. Technological Controls",
    },
    "A.8.23": {
        "title":    "Web filtering",
        "keywords": ["xss", "sqli", "injection", "ssrf", "web attack"],
        "domain":   "8. Technological Controls",
    },
    "A.8.24": {
        "title":    "Use of cryptography",
        "keywords": ["weak cipher", "md5", "sha1", "des", "rc4",
                     "tls 1.0", "tls 1.1", "hardcoded key"],
        "domain":   "8. Technological Controls",
    },
    "A.8.25": {
        "title":    "Secure development lifecycle",
        "keywords": ["injection", "xss", "sqli", "insecure code",
                     "github actions", "dockerfile", "ci/cd"],
        "domain":   "8. Technological Controls",
    },
    "A.8.28": {
        "title":    "Secure coding",
        "keywords": ["sql injection", "xss", "command injection", "ssti",
                     "xxe", "deserialization", "insecure code"],
        "domain":   "8. Technological Controls",
    },
    "A.8.29": {
        "title":    "Security testing in development and acceptance",
        "keywords": ["vulnerability", "pentest", "finding", "scan result"],
        "domain":   "8. Technological Controls",
    },
}


# ── Data classes ──────────────────────────────────────────

@dataclass
class OWASPMapping:
    """A finding mapped to OWASP Top 10 2021."""
    finding_title: str
    category_id:   str
    category_name: str
    severity:      str
    cvss:          float
    cwe:           str
    match_reason:  str


@dataclass
class PCIMapping:
    """A finding mapped to PCI DSS requirement."""
    finding_title:   str
    requirement_id:  str
    requirement_title: str
    finding_severity: str
    pci_severity:     str
    match_reason:    str


@dataclass
class ISOMapping:
    """A finding mapped to ISO 27001 control."""
    finding_title: str
    control_id:    str
    control_title: str
    domain:        str
    finding_severity: str
    match_reason:  str


@dataclass
class ComplianceReport:
    """Full compliance mapping report."""
    target:       str
    generated_at: str
    total_findings: int
    owasp_mappings:  list[OWASPMapping]
    pci_mappings:    list[PCIMapping]
    iso_mappings:    list[ISOMapping]
    owasp_coverage:  dict[str, int]   # category_id → count
    pci_coverage:    dict[str, int]   # requirement → count
    iso_coverage:    dict[str, int]   # control → count
    risk_score:      float            # aggregate risk (0-10)


# ── 1. OWASP Mapper ───────────────────────────────────────

class OWASPMapper:
    """
    Map Glitchicons findings to OWASP Top 10 2021 categories.

    Uses CWE mapping + keyword matching for accurate categorization.
    """

    def map_findings(self, findings: list[dict]) -> dict[str, list[OWASPMapping]]:
        """Map all findings to OWASP categories. Returns dict by category."""
        result: dict[str, list[OWASPMapping]] = defaultdict(list)

        for f in findings:
            mapping = self._map_one(f)
            if mapping:
                result[mapping.category_id].append(mapping)

        return dict(result)

    def map_finding(self, finding: dict) -> OWASPMapping | None:
        """Map a single finding to its OWASP category."""
        return self._map_one(finding)

    def coverage_summary(self, findings: list[dict]) -> dict:
        """Return OWASP coverage — which categories have findings."""
        mapped = self.map_findings(findings)
        summary = {}
        for cat_id, cat_data in OWASP_TOP10_2021.items():
            count = len(mapped.get(cat_id, []))
            summary[cat_id] = {
                "name":     cat_data["name"],
                "count":    count,
                "covered":  count > 0,
            }
        return summary

    def _map_one(self, finding: dict) -> OWASPMapping | None:
        title   = finding.get("title", "").lower()
        desc    = finding.get("description", "").lower()
        cwe     = finding.get("cwe", "")
        combined = f"{title} {desc}"

        best_cat   = None
        best_score = 0

        for cat_id, cat_data in OWASP_TOP10_2021.items():
            score = 0
            reason_parts = []

            # CWE match (highest weight)
            if cwe and cwe in cat_data["cwes"]:
                score += 3
                reason_parts.append(f"CWE match: {cwe}")

            # Keyword match
            for kw in cat_data["keywords"]:
                if kw in combined:
                    score += 1
                    reason_parts.append(f"keyword: {kw}")
                    break  # one keyword match per category

            if score > best_score:
                best_score = score
                best_cat   = (cat_id, cat_data, "; ".join(reason_parts[:2]))

        if not best_cat:
            return None

        cat_id, cat_data, reason = best_cat
        return OWASPMapping(
            finding_title=finding.get("title", ""),
            category_id=cat_id,
            category_name=cat_data["name"],
            severity=finding.get("severity", "INFO"),
            cvss=float(finding.get("cvss", 0)),
            cwe=cwe,
            match_reason=reason,
        )

    def print_report(self, findings: list[dict]) -> None:
        """Print OWASP mapping as rich table."""
        mapped   = self.map_findings(findings)
        coverage = self.coverage_summary(findings)

        console.print("\n  [bold cyan]OWASP Top 10 2021 — Coverage Report[/bold cyan]")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Category", width=8)
        table.add_column("Name",     width=35)
        table.add_column("Findings", width=10)
        table.add_column("Status",   width=10)

        for cat_id in sorted(OWASP_TOP10_2021.keys()):
            info    = coverage[cat_id]
            count   = info["count"]
            covered = "⚠ FINDINGS" if count > 0 else "✓ CLEAN"
            color   = "red" if count > 0 else "green"
            table.add_row(
                cat_id,
                info["name"],
                str(count),
                f"[{color}]{covered}[/{color}]",
            )
        console.print(table)
        covered_count = sum(1 for v in coverage.values() if v["covered"])
        console.print(f"\n  Categories with findings: {covered_count}/10")


# ── 2. PCI DSS Checker ────────────────────────────────────

class PCIDSSChecker:
    """
    Map findings to PCI DSS v4.0 requirements.

    Identifies which PCI DSS requirements are violated
    based on security findings.
    """

    def check_findings(self, findings: list[dict]) -> list[PCIMapping]:
        """Check all findings against PCI DSS requirements."""
        mappings = []
        for f in findings:
            for req_id, req_data in PCI_DSS_REQUIREMENTS.items():
                if self._matches(f, req_data):
                    mappings.append(PCIMapping(
                        finding_title=f.get("title", ""),
                        requirement_id=req_id,
                        requirement_title=req_data["title"],
                        finding_severity=f.get("severity", "INFO"),
                        pci_severity=req_data["severity"],
                        match_reason=self._match_reason(f, req_data),
                    ))
        return mappings

    def gap_analysis(self, findings: list[dict]) -> dict:
        """Return PCI DSS gap analysis — violated vs clean requirements."""
        mappings = self.check_findings(findings)
        violated = {m.requirement_id for m in mappings}
        result   = {}
        for req_id, req_data in PCI_DSS_REQUIREMENTS.items():
            result[req_id] = {
                "title":    req_data["title"],
                "violated": req_id in violated,
                "severity": req_data["severity"],
                "guidance": req_data["guidance"],
                "findings": [m.finding_title for m in mappings
                             if m.requirement_id == req_id][:3],
            }
        return result

    def compliance_score(self, findings: list[dict]) -> float:
        """Calculate PCI DSS compliance score (0-100%)."""
        gap       = self.gap_analysis(findings)
        total     = len(gap)
        violated  = sum(1 for v in gap.values() if v["violated"])
        return round((total - violated) / total * 100, 1)

    def print_report(self, findings: list[dict]) -> None:
        """Print PCI DSS gap analysis as rich table."""
        gap   = self.gap_analysis(findings)
        score = self.compliance_score(findings)

        console.print(f"\n  [bold cyan]PCI DSS v4.0 — Compliance Report[/bold cyan]")
        console.print(f"  Compliance Score: [bold]{score}%[/bold]")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Req",   width=6)
        table.add_column("Title", width=45)
        table.add_column("Status", width=12)
        table.add_column("Sev",   width=8)

        for req_id in sorted(gap.keys()):
            info     = gap[req_id]
            violated = info["violated"]
            status   = "[red]VIOLATED[/red]" if violated else "[green]PASS[/green]"
            table.add_row(req_id, info["title"][:44], status, info["severity"])
        console.print(table)

    def _matches(self, finding: dict, req_data: dict) -> bool:
        combined = (finding.get("title", "") + " " +
                    finding.get("description", "")).lower()
        return any(kw in combined for kw in req_data["keywords"])

    def _match_reason(self, finding: dict, req_data: dict) -> str:
        combined = (finding.get("title", "") + " " +
                    finding.get("description", "")).lower()
        matched  = [kw for kw in req_data["keywords"] if kw in combined]
        return f"keywords: {', '.join(matched[:3])}"


# ── 3. ISO 27001 Mapper ───────────────────────────────────

class ISO27001Mapper:
    """
    Map findings to ISO 27001:2022 Annex A controls.

    Provides control-level mapping for audit and compliance reporting.
    """

    def map_findings(self, findings: list[dict]) -> list[ISOMapping]:
        """Map all findings to ISO 27001 controls."""
        mappings = []
        for f in findings:
            for ctrl_id, ctrl_data in ISO27001_CONTROLS.items():
                if self._matches(f, ctrl_data):
                    mappings.append(ISOMapping(
                        finding_title=f.get("title", ""),
                        control_id=ctrl_id,
                        control_title=ctrl_data["title"],
                        domain=ctrl_data["domain"],
                        finding_severity=f.get("severity", "INFO"),
                        match_reason=self._match_reason(f, ctrl_data),
                    ))
        return mappings

    def controls_violated(self, findings: list[dict]) -> list[str]:
        """Return list of violated ISO 27001 control IDs."""
        mappings = self.map_findings(findings)
        return sorted(set(m.control_id for m in mappings))

    def domain_summary(self, findings: list[dict]) -> dict[str, int]:
        """Group violation count by domain."""
        mappings = self.map_findings(findings)
        summary: dict[str, int] = defaultdict(int)
        for m in mappings:
            summary[m.domain] += 1
        return dict(summary)

    def print_report(self, findings: list[dict]) -> None:
        """Print ISO 27001 mapping as rich table."""
        mappings = self.map_findings(findings)
        violated = set(m.control_id for m in mappings)

        console.print(f"\n  [bold cyan]ISO 27001:2022 — Control Mapping[/bold cyan]")
        console.print(f"  Controls violated: {len(violated)}/{len(ISO27001_CONTROLS)}")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Control", width=8)
        table.add_column("Title",   width=38)
        table.add_column("Domain",  width=25)
        table.add_column("Status",  width=10)

        for ctrl_id in sorted(ISO27001_CONTROLS.keys()):
            ctrl  = ISO27001_CONTROLS[ctrl_id]
            is_v  = ctrl_id in violated
            status = "[red]VIOLATED[/red]" if is_v else "[green]PASS[/green]"
            table.add_row(ctrl_id, ctrl["title"][:37],
                          ctrl["domain"][:24], status)
        console.print(table)

    def _matches(self, finding: dict, ctrl_data: dict) -> bool:
        combined = (finding.get("title", "") + " " +
                    finding.get("description", "")).lower()
        return any(kw in combined for kw in ctrl_data["keywords"])

    def _match_reason(self, finding: dict, ctrl_data: dict) -> str:
        combined = (finding.get("title", "") + " " +
                    finding.get("description", "")).lower()
        matched  = [kw for kw in ctrl_data["keywords"] if kw in combined]
        return f"keywords: {', '.join(matched[:3])}"


# ── 4. Compliance Reporter ────────────────────────────────

class ComplianceReporter:
    """
    Generate unified compliance reports from Glitchicons findings.

    Combines OWASP, PCI DSS, and ISO 27001 mappings into:
    - JSON structured report
    - HTML self-contained compliance dashboard
    - Risk score calculation
    """

    def __init__(
        self,
        findings: list[dict],
        target: str,
        output_dir: str = "./findings/compliance",
        engagement_name: str = "",
    ):
        self.findings        = findings
        self.target          = target
        self.output_dir      = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.engagement_name = engagement_name or f"Compliance Assessment — {target}"

        self._owasp  = OWASPMapper()
        self._pci    = PCIDSSChecker()
        self._iso    = ISO27001Mapper()

    def generate_all(self) -> dict[str, Path]:
        """Generate all compliance reports."""
        console.print(f"\n  [bold cyan]⬡ Compliance Reporter[/bold cyan] → {self.target}")
        report = self._build_report()
        paths  = {
            "json": self._save_json(report),
            "html": self._save_html(report),
        }
        console.print(f"  Reports saved: JSON + HTML")
        return paths

    def _build_report(self) -> ComplianceReport:
        """Build the full compliance report."""
        owasp_mappings = []
        for cat_findings in self._owasp.map_findings(self.findings).values():
            owasp_mappings.extend(cat_findings)

        pci_mappings = self._pci.check_findings(self.findings)
        iso_mappings = self._iso.map_findings(self.findings)

        # Coverage counts
        owasp_coverage = defaultdict(int)
        for m in owasp_mappings:
            owasp_coverage[m.category_id] += 1

        pci_coverage = defaultdict(int)
        for m in pci_mappings:
            pci_coverage[m.requirement_id] += 1

        iso_coverage = defaultdict(int)
        for m in iso_mappings:
            iso_coverage[m.control_id] += 1

        # Risk score: avg CVSS of all findings
        cvss_scores = [float(f.get("cvss", 0)) for f in self.findings if f.get("cvss")]
        risk_score  = round(sum(cvss_scores) / len(cvss_scores), 2) if cvss_scores else 0.0

        return ComplianceReport(
            target=self.target,
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_findings=len(self.findings),
            owasp_mappings=owasp_mappings,
            pci_mappings=pci_mappings,
            iso_mappings=iso_mappings,
            owasp_coverage=dict(owasp_coverage),
            pci_coverage=dict(pci_coverage),
            iso_coverage=dict(iso_coverage),
            risk_score=risk_score,
        )

    def _save_json(self, report: ComplianceReport) -> Path:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = self.output_dir / f"compliance_{ts}.json"
        data = {
            "target":         report.target,
            "generated_at":   report.generated_at,
            "total_findings": report.total_findings,
            "risk_score":     report.risk_score,
            "owasp_coverage": report.owasp_coverage,
            "pci_coverage":   report.pci_coverage,
            "iso_coverage":   report.iso_coverage,
            "owasp_mappings": [
                {"finding": m.finding_title, "category": m.category_id,
                 "name": m.category_name, "severity": m.severity}
                for m in report.owasp_mappings
            ],
            "pci_mappings": [
                {"finding": m.finding_title, "requirement": m.requirement_id,
                 "title": m.requirement_title, "severity": m.pci_severity}
                for m in report.pci_mappings
            ],
            "iso_mappings": [
                {"finding": m.finding_title, "control": m.control_id,
                 "title": m.control_title, "domain": m.domain}
                for m in report.iso_mappings
            ],
        }
        out.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return out

    def _save_html(self, report: ComplianceReport) -> Path:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = self.output_dir / f"compliance_{ts}.html"
        out.write_text(self._build_html(report), encoding="utf-8")
        return out

    def _build_html(self, report: ComplianceReport) -> str:
        pci_score = self._pci.compliance_score(self.findings)

        owasp_rows = ""
        for cat_id, cat_data in sorted(OWASP_TOP10_2021.items()):
            count  = report.owasp_coverage.get(cat_id, 0)
            status = f'<span style="color:#FF0040">⚠ {count} finding(s)</span>' if count > 0 \
                     else '<span style="color:#30D158">✓ Clean</span>'
            owasp_rows += f"<tr><td>{cat_id}</td><td>{cat_data['name']}</td><td>{status}</td></tr>\n"

        pci_rows = ""
        gap = self._pci.gap_analysis(self.findings)
        for req_id in sorted(gap.keys()):
            info   = gap[req_id]
            status = '<span style="color:#FF0040">VIOLATED</span>' if info["violated"] \
                     else '<span style="color:#30D158">PASS</span>'
            pci_rows += f"<tr><td>{req_id}</td><td>{info['title']}</td><td>{status}</td></tr>\n"

        iso_violated = set(m.control_id for m in report.iso_mappings)
        iso_rows = ""
        for ctrl_id in sorted(ISO27001_CONTROLS.keys()):
            ctrl   = ISO27001_CONTROLS[ctrl_id]
            is_v   = ctrl_id in iso_violated
            status = '<span style="color:#FF0040">VIOLATED</span>' if is_v \
                     else '<span style="color:#30D158">PASS</span>'
            iso_rows += f"<tr><td>{ctrl_id}</td><td>{ctrl['title']}</td><td>{ctrl['domain']}</td><td>{status}</td></tr>\n"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Compliance Report — {self.target}</title>
<style>
:root{{--bg:#06060D;--bg2:#0D0D1A;--bg3:#131326;--purple:#6B00FF;--text:#E8E8F8;--text2:#9898B8;--border:rgba(107,0,255,.2)}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;padding:2rem}}
.header{{border-bottom:1px solid var(--border);padding-bottom:1.5rem;margin-bottom:2rem}}
.title{{font-size:1.5rem;font-weight:700;color:var(--text);margin:.5rem 0 .25rem}}
.subtitle{{font-size:.85rem;color:var(--text2)}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;margin-bottom:2rem}}
.stat{{background:var(--bg3);border:1px solid var(--border);padding:1rem;text-align:center}}
.stat-num{{font-size:1.8rem;font-weight:700;color:var(--purple)}}
.stat-label{{font-size:.7rem;color:var(--text2);text-transform:uppercase;letter-spacing:.1em}}
.section{{margin-bottom:2rem}}
.section-title{{font-size:.75rem;letter-spacing:.2em;color:#A855F7;text-transform:uppercase;margin-bottom:1rem;padding-bottom:.5rem;border-bottom:1px solid var(--border)}}
table{{width:100%;border-collapse:collapse;font-size:.82rem}}
th{{text-align:left;padding:.6rem;background:var(--bg3);color:var(--text2);font-size:.7rem;letter-spacing:.1em;border-bottom:1px solid var(--border)}}
td{{padding:.55rem .6rem;border-bottom:1px solid rgba(255,255,255,.04);color:var(--text2)}}
tr:hover td{{background:var(--bg2)}}
</style>
</head>
<body>
<div class="header">
  <div style="font-size:.65rem;color:#FF00AA;letter-spacing:.25em">⬡ GLITCHICONS · COMPLIANCE REPORT</div>
  <div class="title">{self.engagement_name}</div>
  <div class="subtitle">Generated: {report.generated_at[:19].replace('T',' ')} UTC · Target: {report.target}</div>
</div>
<div class="stats">
  <div class="stat"><div class="stat-num">{report.total_findings}</div><div class="stat-label">Total Findings</div></div>
  <div class="stat"><div class="stat-num">{report.risk_score}</div><div class="stat-label">Avg CVSS</div></div>
  <div class="stat"><div class="stat-num">{len(report.owasp_coverage)}/10</div><div class="stat-label">OWASP Categories</div></div>
  <div class="stat"><div class="stat-num">{pci_score}%</div><div class="stat-label">PCI DSS Score</div></div>
  <div class="stat"><div class="stat-num">{len(set(m.control_id for m in report.iso_mappings))}/{len(ISO27001_CONTROLS)}</div><div class="stat-label">ISO Controls Violated</div></div>
</div>
<div class="section">
  <div class="section-title">OWASP Top 10 2021</div>
  <table><thead><tr><th>Category</th><th>Name</th><th>Status</th></tr></thead>
  <tbody>{owasp_rows}</tbody></table>
</div>
<div class="section">
  <div class="section-title">PCI DSS v4.0 Requirements</div>
  <table><thead><tr><th>Req</th><th>Title</th><th>Status</th></tr></thead>
  <tbody>{pci_rows}</tbody></table>
</div>
<div class="section">
  <div class="section-title">ISO 27001:2022 Annex A Controls</div>
  <table><thead><tr><th>Control</th><th>Title</th><th>Domain</th><th>Status</th></tr></thead>
  <tbody>{iso_rows}</tbody></table>
</div>
</body></html>"""
