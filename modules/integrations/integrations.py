"""
Integration Layer — modules/integrations/integrations.py

Connects Glitchicons findings to external tools and platforms.

Integrations:
  1. Burp Suite XML   — export findings as Burp-compatible XML
  2. Slack webhook    — real-time notifications to Slack channel
  3. Discord webhook  — real-time notifications to Discord channel
  4. Jira REST API    — auto-create tickets for CRITICAL/HIGH findings
  5. SARIF export     — GitHub Code Scanning compatible format

Usage:
    from modules.integrations.integrations import (
        BurpExporter, SlackNotifier, DiscordNotifier,
        JiraIntegration, SARIFExporter
    )

    # Burp XML
    BurpExporter().export(findings, "./findings/burp_export.xml")

    # Slack
    slack = SlackNotifier(webhook_url="https://hooks.slack.com/...")
    slack.notify_critical(findings)

    # Jira
    jira = JiraIntegration(url="https://company.atlassian.net",
                           email="you@company.com", api_token="...")
    jira.create_tickets(findings, project_key="SEC")

Author: ardanov96
"""

import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from xml.dom import minidom
import httpx
from rich.console import Console

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "#FF0000",
    "HIGH":     "#FF6B35",
    "MEDIUM":   "#FFD60A",
    "LOW":      "#30D158",
    "INFO":     "#64D2FF",
}

SEVERITY_EMOJIS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
}

JIRA_PRIORITY_MAP = {
    "CRITICAL": "Critical",
    "HIGH":     "High",
    "MEDIUM":   "Medium",
    "LOW":      "Low",
    "INFO":     "Lowest",
}


# ── 1. Burp Suite XML Exporter ────────────────────────────

class BurpExporter:
    """
    Export findings as Burp Suite XML format.

    Compatible with Burp Suite Pro's "Import from file" feature.
    Each finding becomes a Burp issue with host, path, severity, and details.
    """

    SEVERITY_MAP = {
        "CRITICAL": "High",
        "HIGH":     "High",
        "MEDIUM":   "Medium",
        "LOW":      "Low",
        "INFO":     "Information",
    }

    CONFIDENCE_MAP = {
        "CONFIRMED":      "Certain",
        "LIKELY":         "Firm",
        "UNCERTAIN":      "Tentative",
        "FALSE_POSITIVE": "Tentative",
    }

    def export(self, findings: list[dict], output_path: str) -> Path:
        """
        Export findings to Burp Suite XML format.

        Args:
            findings:    List of finding dicts
            output_path: Path to write XML file

        Returns:
            Path to created XML file
        """
        root = ET.Element("issues")
        root.set("burpVersion", "2024.1.0")
        root.set("exportTime", datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y"))

        for f in findings:
            issue = ET.SubElement(root, "issue")

            # Parse URL from target
            target = f.get("target", "") or f.get("endpoint", "")
            host, path, protocol = self._parse_url(target)

            self._add_element(issue, "serialNumber", str(hash(f.get("title", "")) & 0xFFFFFFFF))
            self._add_element(issue, "type", str(self._cwe_to_type(f.get("cwe", ""))))
            self._add_element(issue, "name", f.get("title", "Untitled"))
            self._add_element(issue, "host", host, {"ip": "", "port": "443"})
            self._add_element(issue, "path", path or "/")
            self._add_element(issue, "location", f"{host}{path or '/'}")
            self._add_element(issue, "severity",
                              self.SEVERITY_MAP.get(f.get("severity", "INFO"), "Information"))
            self._add_element(issue, "confidence",
                              self.CONFIDENCE_MAP.get(f.get("verdict", ""), "Firm"))
            self._add_element(issue, "issueBackground",
                              f.get("description", ""))
            self._add_element(issue, "remediationBackground",
                              f.get("remediation", ""))
            self._add_element(issue, "issueDetail",
                              f"Evidence:\n{f.get('evidence', '')}\n\n"
                              f"CVSS: {f.get('cvss', 'N/A')} | CWE: {f.get('cwe', 'N/A')}")

        # Pretty-print XML
        xml_str = minidom.parseString(
            ET.tostring(root, encoding="unicode")
        ).toprettyxml(indent="  ", encoding="utf-8")

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(xml_str)
        console.print(f"  Burp XML: [cyan]{out}[/cyan] ({len(findings)} issues)")
        return out

    def _add_element(self, parent: ET.Element, tag: str,
                     text: str = "", attrib: dict = None) -> ET.Element:
        el = ET.SubElement(parent, tag, attrib or {})
        el.text = text
        return el

    def _parse_url(self, url: str) -> tuple[str, str, str]:
        """Parse URL into (host, path, protocol)."""
        if not url:
            return ("unknown", "/", "https")
        protocol = "https" if url.startswith("https") else "http"
        url = url.replace("https://", "").replace("http://", "")
        parts = url.split("/", 1)
        host = parts[0]
        path = "/" + parts[1] if len(parts) > 1 else "/"
        return host, path, protocol

    def _cwe_to_type(self, cwe: str) -> int:
        """Map CWE to Burp issue type number."""
        cwe_map = {
            "CWE-89":  1049088,   # SQL injection
            "CWE-79":  2097920,   # XSS
            "CWE-918": 5243392,   # SSRF
            "CWE-942": 6291456,   # CORS
            "CWE-200": 7340032,   # Info disclosure
            "CWE-284": 8388608,   # Access control
        }
        return cwe_map.get(cwe, 134217728)  # Generic


# ── 2. Slack Notifier ─────────────────────────────────────

class SlackNotifier:
    """
    Send finding notifications to Slack via Incoming Webhooks.

    Supported message types:
    - notify_critical(): only CRITICAL findings, immediate alert
    - notify_summary(): end-of-scan summary with all severity counts
    - notify_finding(): single finding as formatted message
    """

    def __init__(
        self,
        webhook_url: str,
        channel: str = "",
        username: str = "Glitchicons",
        icon_emoji: str = ":shield:",
        timeout: int = 10,
    ):
        self.webhook_url = webhook_url
        self.channel = channel
        self.username = username
        self.icon_emoji = icon_emoji
        self.timeout = timeout

    def notify_critical(self, findings: list[dict], target: str = "") -> bool:
        """Send alert for all CRITICAL findings immediately."""
        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        if not critical:
            return True

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text",
                         "text": f"🔴 CRITICAL: {len(critical)} finding(s) on {target}"}
            },
            {"type": "divider"},
        ]

        for f in critical[:5]:  # max 5 per message
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*{f.get('title', 'Unknown')}*\n"
                        f"CVSS: `{f.get('cvss', 'N/A')}` | "
                        f"CWE: `{f.get('cwe', 'N/A')}`\n"
                        f"_{f.get('description', '')[:200]}_"
                    )
                }
            })

        return self._send({"blocks": blocks})

    def notify_summary(
        self,
        findings: list[dict],
        target: str,
        duration: str = "N/A",
    ) -> bool:
        """Send end-of-scan summary."""
        from collections import Counter
        counts = Counter(f.get("severity", "INFO") for f in findings)

        summary_lines = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if counts[sev]:
                emoji = SEVERITY_EMOJIS[sev]
                summary_lines.append(f"{emoji} {sev}: *{counts[sev]}*")

        text = "\n".join(summary_lines) or "No findings"

        payload = {
            "attachments": [{
                "color": SEVERITY_COLORS.get(
                    "CRITICAL" if counts["CRITICAL"] else
                    "HIGH" if counts["HIGH"] else "MEDIUM",
                    "#30D158"
                ),
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text",
                                 "text": f"⬡ Glitchicons Scan Complete — {target}"}
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Total findings*\n{len(findings)}"},
                            {"type": "mrkdwn", "text": f"*Duration*\n{duration}"},
                        ]
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": text}
                    },
                ]
            }]
        }
        return self._send(payload)

    def notify_finding(self, finding: dict) -> bool:
        """Send a single finding as a Slack message."""
        sev = finding.get("severity", "INFO")
        color = SEVERITY_COLORS.get(sev, "#64D2FF")
        emoji = SEVERITY_EMOJIS.get(sev, "🔵")

        payload = {
            "attachments": [{
                "color": color,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"{emoji} *[{sev}] {finding.get('title', 'Finding')}*\n"
                                f"CVSS `{finding.get('cvss', 'N/A')}` | "
                                f"CWE `{finding.get('cwe', 'N/A')}`"
                            )
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"_{finding.get('description', '')[:300]}_"
                        }
                    }
                ]
            }]
        }
        return self._send(payload)

    def _send(self, payload: dict) -> bool:
        """POST payload to Slack webhook. Return True on success."""
        if self.channel:
            payload["channel"] = self.channel
        payload["username"] = self.username
        payload["icon_emoji"] = self.icon_emoji

        try:
            resp = httpx.post(self.webhook_url, json=payload, timeout=self.timeout)
            return resp.status_code == 200
        except Exception as e:
            console.print(f"  [red]Slack error: {e}[/red]")
            return False


# ── 3. Discord Notifier ───────────────────────────────────

class DiscordNotifier:
    """
    Send finding notifications to Discord via Webhooks.

    Uses Discord's rich embed format for nicely formatted messages.
    """

    DISCORD_COLORS = {
        "CRITICAL": 0xFF0000,
        "HIGH":     0xFF6B35,
        "MEDIUM":   0xFFD60A,
        "LOW":      0x30D158,
        "INFO":     0x64D2FF,
    }

    def __init__(self, webhook_url: str, timeout: int = 10):
        self.webhook_url = webhook_url
        self.timeout = timeout

    def notify_summary(
        self,
        findings: list[dict],
        target: str,
        duration: str = "N/A",
    ) -> bool:
        """Send scan summary as Discord embed."""
        from collections import Counter
        counts = Counter(f.get("severity", "INFO") for f in findings)

        severity_text = "\n".join(
            f"{SEVERITY_EMOJIS[sev]} **{sev}**: {counts[sev]}"
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            if counts[sev]
        ) or "No findings"

        top_severity = next(
            (s for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
             if counts[s] > 0), "INFO"
        )

        embed = {
            "title": f"⬡ Glitchicons — Scan Complete",
            "description": f"**Target:** {target}\n**Duration:** {duration}",
            "color": self.DISCORD_COLORS.get(top_severity, 0x64D2FF),
            "fields": [
                {"name": "Findings", "value": severity_text, "inline": True},
                {"name": "Total", "value": str(len(findings)), "inline": True},
            ],
            "footer": {"text": f"Glitchicons v1.0.0 | {datetime.now().strftime('%Y-%m-%d %H:%M')}"},
            "thumbnail": {"url": "https://github.com/ardanov96/glitchicons/raw/main/docs/logo.png"},
        }

        return self._send({"embeds": [embed]})

    def notify_critical(self, findings: list[dict], target: str = "") -> bool:
        """Send alert embed for CRITICAL findings."""
        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        if not critical:
            return True

        fields = []
        for f in critical[:5]:
            fields.append({
                "name": f"🔴 {f.get('title', 'Unknown')}",
                "value": (
                    f"CVSS: **{f.get('cvss', 'N/A')}** | "
                    f"CWE: `{f.get('cwe', 'N/A')}`\n"
                    f"{f.get('description', '')[:200]}"
                ),
                "inline": False,
            })

        embed = {
            "title": f"🚨 CRITICAL Alert — {len(critical)} finding(s)",
            "description": f"Target: **{target}**",
            "color": 0xFF0000,
            "fields": fields,
            "footer": {"text": "Glitchicons Security Scanner"},
        }
        return self._send({"embeds": [embed]})

    def notify_finding(self, finding: dict) -> bool:
        """Send single finding as Discord embed."""
        sev = finding.get("severity", "INFO")
        embed = {
            "title": f"{SEVERITY_EMOJIS.get(sev, '🔵')} [{sev}] {finding.get('title', 'Finding')}",
            "description": finding.get("description", "")[:400],
            "color": self.DISCORD_COLORS.get(sev, 0x64D2FF),
            "fields": [
                {"name": "CVSS", "value": str(finding.get("cvss", "N/A")), "inline": True},
                {"name": "CWE",  "value": finding.get("cwe", "N/A"),        "inline": True},
                {"name": "Target", "value": finding.get("target", "N/A"),   "inline": True},
                {"name": "Remediation",
                 "value": finding.get("remediation", "N/A")[:300],
                 "inline": False},
            ],
            "footer": {"text": f"Glitchicons | {datetime.now().strftime('%Y-%m-%d %H:%M')}"},
        }
        return self._send({"embeds": [embed]})

    def _send(self, payload: dict) -> bool:
        try:
            resp = httpx.post(self.webhook_url, json=payload, timeout=self.timeout)
            return resp.status_code in (200, 204)
        except Exception as e:
            console.print(f"  [red]Discord error: {e}[/red]")
            return False


# ── 4. Jira Integration ───────────────────────────────────

class JiraIntegration:
    """
    Create Jira tickets from Glitchicons findings.

    Supports Jira Cloud and Jira Server.
    Uses Jira REST API v3.
    """

    def __init__(
        self,
        url: str,
        email: str,
        api_token: str,
        timeout: int = 15,
    ):
        self.base_url = url.rstrip("/")
        self.auth = (email, api_token)
        self.timeout = timeout
        self.headers = {
            "Accept":       "application/json",
            "Content-Type": "application/json",
        }

    def create_tickets(
        self,
        findings: list[dict],
        project_key: str,
        issue_type: str = "Bug",
        min_severity: str = "HIGH",
        labels: list[str] | None = None,
        assignee: str | None = None,
    ) -> list[dict]:
        """
        Create Jira tickets for findings at or above min_severity.

        Args:
            findings:     List of finding dicts
            project_key:  Jira project key (e.g. "SEC")
            issue_type:   Issue type name (Bug, Task, Story, etc.)
            min_severity: Minimum severity to create ticket (HIGH = HIGH + CRITICAL)
            labels:       Additional labels to add
            assignee:     Jira account ID to assign tickets to

        Returns:
            List of created ticket info dicts
        """
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        min_idx = severity_order.index(min_severity) if min_severity in severity_order else 3

        eligible = [
            f for f in findings
            if severity_order.index(f.get("severity", "INFO")) >= min_idx
        ]

        if not eligible:
            console.print(f"  No findings at {min_severity}+ severity to create tickets for")
            return []

        created = []
        console.print(f"  Creating {len(eligible)} Jira ticket(s) in project {project_key}...")

        for f in eligible:
            ticket = self._create_ticket(f, project_key, issue_type, labels, assignee)
            if ticket:
                created.append(ticket)
                console.print(f"  [green]Created:[/green] {ticket.get('key')} — {f.get('title', '')[:50]}")
            else:
                console.print(f"  [red]Failed:[/red] {f.get('title', '')[:50]}")

        return created

    def _create_ticket(
        self,
        finding: dict,
        project_key: str,
        issue_type: str,
        labels: list[str] | None,
        assignee: str | None,
    ) -> dict | None:
        """Create a single Jira issue from a finding."""
        sev = finding.get("severity", "INFO")
        priority = JIRA_PRIORITY_MAP.get(sev, "Medium")

        # Build description in Jira markdown (Atlassian Document Format simplified)
        description = self._build_description(finding)

        payload = {
            "fields": {
                "project":   {"key": project_key},
                "summary":   f"[{sev}] {finding.get('title', 'Security Finding')}",
                "issuetype": {"name": issue_type},
                "priority":  {"name": priority},
                "description": description,
                "labels":    (labels or []) + ["glitchicons", "security", sev.lower()],
            }
        }

        if assignee:
            payload["fields"]["assignee"] = {"accountId": assignee}

        try:
            resp = httpx.post(
                f"{self.base_url}/rest/api/3/issue",
                json=payload,
                headers=self.headers,
                auth=self.auth,
                timeout=self.timeout,
            )
            if resp.status_code == 201:
                data = resp.json()
                return {
                    "key":  data.get("key"),
                    "id":   data.get("id"),
                    "url":  f"{self.base_url}/browse/{data.get('key')}",
                    "title": finding.get("title"),
                }
            else:
                console.print(f"  [red]Jira API error {resp.status_code}:[/red] {resp.text[:200]}")
                return None
        except Exception as e:
            console.print(f"  [red]Jira request error: {e}[/red]")
            return None

    def _build_description(self, finding: dict) -> dict:
        """Build Jira Atlassian Document Format description."""
        sections = [
            ("Description", finding.get("description", "")),
            ("Evidence",    finding.get("evidence", "")),
            ("Remediation", finding.get("remediation", "")),
        ]
        meta = (
            f"CVSS: {finding.get('cvss', 'N/A')} | "
            f"CWE: {finding.get('cwe', 'N/A')} | "
            f"Target: {finding.get('target', 'N/A')}"
        )

        content = []
        content.append({
            "type": "paragraph",
            "content": [{"type": "text", "text": meta,
                         "marks": [{"type": "strong"}]}]
        })

        for title, text in sections:
            if text:
                content.append({
                    "type": "heading",
                    "attrs": {"level": 3},
                    "content": [{"type": "text", "text": title}]
                })
                content.append({
                    "type": "paragraph",
                    "content": [{"type": "text", "text": str(text)[:1000]}]
                })

        return {"version": 1, "type": "doc", "content": content}

    def get_project(self, project_key: str) -> dict | None:
        """Verify a Jira project exists and is accessible."""
        try:
            resp = httpx.get(
                f"{self.base_url}/rest/api/3/project/{project_key}",
                headers=self.headers,
                auth=self.auth,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception:
            return None


# ── 5. SARIF Exporter ─────────────────────────────────────

class SARIFExporter:
    """
    Export findings in SARIF (Static Analysis Results Interchange Format).

    Compatible with:
    - GitHub Code Scanning (upload via GitHub Actions)
    - VS Code SARIF Viewer extension
    - Azure DevOps
    """

    SARIF_LEVEL_MAP = {
        "CRITICAL": "error",
        "HIGH":     "error",
        "MEDIUM":   "warning",
        "LOW":      "note",
        "INFO":     "none",
    }

    def export(self, findings: list[dict], output_path: str, tool_version: str = "1.0.0") -> Path:
        """Export findings to SARIF 2.1.0 format."""
        rules = self._build_rules(findings)
        results = [self._build_result(f, i) for i, f in enumerate(findings)]

        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name":            "Glitchicons",
                        "version":         tool_version,
                        "informationUri":  "https://github.com/ardanov96/glitchicons",
                        "rules":           rules,
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                }]
            }]
        }

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        console.print(f"  SARIF: [cyan]{out}[/cyan] ({len(findings)} results)")
        return out

    def _build_rules(self, findings: list[dict]) -> list[dict]:
        seen = set()
        rules = []
        for f in findings:
            cwe = f.get("cwe", "CWE-0")
            if cwe in seen:
                continue
            seen.add(cwe)
            rules.append({
                "id": cwe,
                "name": f.get("title", cwe).replace(" ", ""),
                "shortDescription": {"text": f.get("title", cwe)},
                "fullDescription":  {"text": f.get("description", "")[:500]},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html",
                "properties": {
                    "security-severity": str(f.get("cvss", "5.0")),
                    "tags": ["security", f.get("severity", "MEDIUM").lower()],
                },
            })
        return rules

    def _build_result(self, finding: dict, idx: int) -> dict:
        target = finding.get("target", "") or finding.get("endpoint", "")
        uri = target if target.startswith("http") else f"https://{target}"

        return {
            "ruleId":  finding.get("cwe", "CWE-0"),
            "level":   self.SARIF_LEVEL_MAP.get(finding.get("severity", "INFO"), "none"),
            "message": {"text": finding.get("description", "")[:500]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": 1},
                }
            }],
            "properties": {
                "cvss":        finding.get("cvss", 0),
                "cwe":         finding.get("cwe", ""),
                "evidence":    finding.get("evidence", "")[:300],
                "remediation": finding.get("remediation", "")[:300],
            },
        }
