"""
AI-Powered Report Writing — modules/report/ai_reporter.py

Transform raw security findings into boardroom-ready pentest reports
using Large Language Models.

Components:
  1. ReportNarrator        — LLM interface (Anthropic/OpenAI/Ollama)
  2. ExecutiveSummaryWriter — executive summary for non-technical stakeholders
  3. FindingNarrator       — per-finding technical writeup with impact + PoC
  4. RemediationRoadmap    — prioritized remediation plan with effort estimates
  5. PentestReportGenerator — full report orchestrator → HTML + Markdown

Usage:
    from modules.report.ai_reporter import PentestReportGenerator

    gen = PentestReportGenerator(
        provider="anthropic",   # or "openai" or "ollama"
        api_key="sk-ant-...",
        model="claude-3-5-haiku-20241022",
    )

    report = gen.generate(
        findings=findings_list,
        target="https://target.com",
        engagement_name="Target Corp — Web Application Pentest",
        tester="ardanov96",
        output_dir="./reports",
    )

    print(f"Report: {report.html_path}")
    print(f"Markdown: {report.md_path}")

Author: ardanov96
"""

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# ── LLM providers ─────────────────────────────────────────

ANTHROPIC_URL  = "https://api.anthropic.com/v1/messages"
OPENAI_URL     = "https://api.openai.com/v1/chat/completions"
OLLAMA_URL     = "http://localhost:11434/api/generate"

DEFAULT_MODELS = {
    "anthropic": "claude-3-5-haiku-20241022",
    "openai":    "gpt-4o-mini",
    "ollama":    "qwen2.5-coder:3b",
}

# ── Severity colours for HTML ─────────────────────────────
SEVERITY_COLOR = {
    "CRITICAL": "#FF0040",
    "HIGH":     "#FF6B35",
    "MEDIUM":   "#FFB300",
    "LOW":      "#30D158",
    "INFO":     "#64D2FF",
}

SEVERITY_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ── Data classes ──────────────────────────────────────────

@dataclass
class NarratedFinding:
    """A finding enriched with AI-written narrative."""
    original:      dict
    impact_story:  str   # LLM-written impact narrative
    poc_steps:     str   # Step-by-step PoC description
    business_risk: str   # Business impact (for executives)
    fix_guidance:  str   # Enhanced remediation guidance


@dataclass
class ExecutiveSummary:
    """AI-written executive summary."""
    opening:       str   # Hook / key message
    scope:         str   # What was tested
    key_findings:  str   # Top findings in plain language
    risk_rating:   str   # Overall risk: Critical/High/Medium/Low
    risk_score:    float # Numerical 0-10
    next_steps:    str   # Recommended immediate actions


@dataclass
class RemediationItem:
    """A single item in the remediation roadmap."""
    finding_title:  str
    severity:       str
    effort:         str    # "hours" | "days" | "weeks"
    effort_days:    int    # Estimated effort in days
    priority:       int    # 1 = immediate, 2 = short-term, 3 = long-term
    owner:          str    # "dev" | "ops" | "security" | "management"
    quick_win:      bool   # Can be fixed in < 1 day


@dataclass
class PentestReport:
    """Complete generated pentest report."""
    engagement_name:  str
    target:           str
    tester:           str
    generated_at:     str
    executive_summary: ExecutiveSummary
    narrated_findings: list[NarratedFinding]
    remediation_items: list[RemediationItem]
    html_path:        str = ""
    md_path:          str = ""
    total_findings:   int = 0
    risk_score:       float = 0.0


# ── 1. Report Narrator (LLM Interface) ────────────────────

class ReportNarrator:
    """
    LLM interface for narrative generation.

    Handles Anthropic Claude, OpenAI GPT, and Ollama (local).
    Provides structured prompts optimized for security report writing.

    Designed for security professionals — tone is direct, technical,
    and authoritative, not generic AI text.
    """

    SYSTEM_PROMPT = """You are a senior penetration tester writing a professional security assessment report.
Your writing is:
- Direct and authoritative, not hedging
- Technical but accessible to developers
- Focused on real-world impact
- Specific — never generic
- Concise — no padding or filler text

Always respond with exactly what was asked, in the format specified."""

    def __init__(
        self,
        provider: str = "anthropic",
        api_key: str = "",
        model: str = "",
        base_url: str = "",
        timeout: int = 30,
    ):
        self.provider  = provider
        self.api_key   = api_key
        self.model     = model or DEFAULT_MODELS.get(provider, "")
        self.base_url  = base_url
        self.timeout   = timeout
        self.client    = httpx.Client(timeout=timeout)

    def generate(self, prompt: str, max_tokens: int = 500) -> str:
        """
        Generate text via configured LLM provider.

        Returns the generated text, or empty string on failure.
        Falls back gracefully — report generation continues even if LLM fails.
        """
        try:
            if self.provider == "anthropic":
                return self._call_anthropic(prompt, max_tokens)
            elif self.provider == "openai":
                return self._call_openai(prompt, max_tokens)
            elif self.provider == "ollama":
                return self._call_ollama(prompt, max_tokens)
            else:
                raise ValueError(f"Unknown provider: {self.provider}")
        except Exception as e:
            console.print(f"  [yellow]LLM warning:[/yellow] {e}")
            return ""

    def generate_structured(
        self,
        prompt: str,
        output_keys: list[str],
        max_tokens: int = 800,
    ) -> dict[str, str]:
        """
        Generate structured output as JSON dict.

        Prompts LLM to return JSON with specified keys.
        Falls back to empty strings if parsing fails.
        """
        json_prompt = (
            f"{prompt}\n\n"
            f"Return ONLY a JSON object with these exact keys: {output_keys}. "
            "No explanation, no markdown, just the JSON object."
        )
        raw = self.generate(json_prompt, max_tokens)
        return self._parse_json_response(raw, output_keys)

    def _call_anthropic(self, prompt: str, max_tokens: int) -> str:
        resp = self.client.post(
            self.base_url or ANTHROPIC_URL,
            headers={
                "x-api-key":         self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            },
            json={
                "model":      self.model,
                "max_tokens": max_tokens,
                "system":     self.SYSTEM_PROMPT,
                "messages":   [{"role": "user", "content": prompt}],
            },
        )
        resp.raise_for_status()
        content = resp.json().get("content", [])
        return content[0].get("text", "") if content else ""

    def _call_openai(self, prompt: str, max_tokens: int) -> str:
        resp = self.client.post(
            self.base_url or OPENAI_URL,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type":  "application/json",
            },
            json={
                "model":      self.model,
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user",   "content": prompt},
                ],
            },
        )
        resp.raise_for_status()
        choices = resp.json().get("choices", [])
        return choices[0]["message"]["content"] if choices else ""

    def _call_ollama(self, prompt: str, max_tokens: int) -> str:
        url = self.base_url or OLLAMA_URL
        resp = self.client.post(
            url,
            json={
                "model":  self.model,
                "prompt": f"{self.SYSTEM_PROMPT}\n\n{prompt}",
                "stream": False,
                "options": {"num_predict": max_tokens},
            },
        )
        resp.raise_for_status()
        return resp.json().get("response", "")

    def _parse_json_response(self, raw: str, keys: list[str]) -> dict[str, str]:
        """Parse JSON from LLM response, with fallback."""
        raw = raw.strip()
        # Try to extract JSON block
        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group(0))
                return {k: str(data.get(k, "")) for k in keys}
            except Exception:
                pass
        return {k: "" for k in keys}


# ── 2. Executive Summary Writer ───────────────────────────

class ExecutiveSummaryWriter:
    """
    Generate executive summaries for non-technical stakeholders.

    Written in plain language — no jargon, focus on business impact,
    financial risk, and recommended actions. Suitable for C-suite
    and board-level presentations.
    """

    RISK_THRESHOLDS = [
        (9.0, "Critical",  "Immediate action required. Active exploitation risk."),
        (7.0, "High",      "Urgent remediation needed within 7 days."),
        (5.0, "Medium",    "Address within 30 days. No immediate exploitation risk."),
        (3.0, "Low",       "Remediate within 90 days as part of normal operations."),
        (0.0, "Minimal",   "Best practice improvements. No significant risk."),
    ]

    def __init__(self, narrator: ReportNarrator):
        self.narrator = narrator

    def write(
        self,
        findings: list[dict],
        target: str,
        engagement_name: str,
    ) -> ExecutiveSummary:
        """Generate executive summary from findings."""
        risk_score = self._calculate_risk_score(findings)
        risk_rating, risk_desc = self._risk_rating(risk_score)

        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        high     = [f for f in findings if f.get("severity") == "HIGH"]

        # Try LLM generation
        if self.narrator.api_key or self.narrator.provider == "ollama":
            return self._generate_with_llm(
                findings, target, engagement_name,
                risk_score, risk_rating, critical, high,
            )

        # Fallback: template-based
        return self._generate_template(
            findings, target, engagement_name,
            risk_score, risk_rating, risk_desc, critical, high,
        )

    def _generate_with_llm(
        self,
        findings: list[dict],
        target: str,
        engagement_name: str,
        risk_score: float,
        risk_rating: str,
        critical: list[dict],
        high: list[dict],
    ) -> ExecutiveSummary:
        """Use LLM to write executive summary."""
        top_findings_text = "\n".join(
            f"- [{f['severity']}] {f['title']} (CVSS {f.get('cvss', 0)})"
            for f in (critical + high)[:5]
        )
        prompt = f"""Write an executive summary for this penetration test report.

Engagement: {engagement_name}
Target: {target}
Overall Risk: {risk_rating} ({risk_score:.1f}/10)
Total Findings: {len(findings)} ({len(critical)} Critical, {len(high)} High)

Top findings:
{top_findings_text}

Write 4 sections, each 2-3 sentences:
1. opening: A direct risk statement for C-level executives
2. key_findings: The most impactful findings in plain language (no jargon)
3. business_risk: Financial, operational, and reputational risk if unfixed
4. next_steps: 3 concrete actions the organization should take this week

Return as JSON with keys: opening, key_findings, business_risk, next_steps"""

        result = self.narrator.generate_structured(
            prompt,
            ["opening", "key_findings", "business_risk", "next_steps"],
            max_tokens=700,
        )

        scope = f"Security assessment of {target} identified {len(findings)} vulnerabilities."
        return ExecutiveSummary(
            opening=result.get("opening") or self._default_opening(risk_rating, len(findings)),
            scope=scope,
            key_findings=result.get("key_findings") or self._default_key_findings(critical, high),
            risk_rating=risk_rating,
            risk_score=risk_score,
            next_steps=result.get("next_steps") or self._default_next_steps(critical),
        )

    def _generate_template(
        self,
        findings: list[dict],
        target: str,
        engagement_name: str,
        risk_score: float,
        risk_rating: str,
        risk_desc: str,
        critical: list[dict],
        high: list[dict],
    ) -> ExecutiveSummary:
        """Template-based executive summary (no LLM required)."""
        return ExecutiveSummary(
            opening=self._default_opening(risk_rating, len(findings)),
            scope=(
                f"A comprehensive security assessment of {target} was conducted. "
                f"Testing covered web application security, authentication mechanisms, "
                f"access controls, and infrastructure exposure."
            ),
            key_findings=self._default_key_findings(critical, high),
            risk_rating=risk_rating,
            risk_score=risk_score,
            next_steps=self._default_next_steps(critical),
        )

    def _default_opening(self, risk_rating: str, total: int) -> str:
        return (
            f"The security assessment of this environment returned a {risk_rating} overall risk rating. "
            f"A total of {total} security vulnerabilities were identified, some of which could allow "
            f"unauthorized access to sensitive data or systems if exploited."
        )

    def _default_key_findings(self, critical: list[dict], high: list[dict]) -> str:
        if not critical and not high:
            return "No critical or high severity vulnerabilities were identified."
        parts = []
        if critical:
            parts.append(
                f"{len(critical)} critical vulnerabilities were found including: "
                + ", ".join(f['title'][:50] for f in critical[:3])
            )
        if high:
            parts.append(
                f"{len(high)} high severity issues including: "
                + ", ".join(f['title'][:50] for f in high[:3])
            )
        return ". ".join(parts) + "."

    def _default_next_steps(self, critical: list[dict]) -> str:
        steps = []
        if critical:
            steps.append(f"Immediately patch the {len(critical)} critical vulnerabilities identified")
        steps.append("Conduct a review of authentication mechanisms and access controls")
        steps.append("Establish a vulnerability management program with defined SLAs")
        return ". ".join(steps) + "."

    def _calculate_risk_score(self, findings: list[dict]) -> float:
        """Calculate overall risk score from findings."""
        if not findings:
            return 0.0
        weights = {"CRITICAL": 10.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "INFO": 0.5}
        scores  = [weights.get(f.get("severity", "INFO"), 0) for f in findings]
        # Weighted: max score + average of rest
        if not scores:
            return 0.0
        max_score = max(scores)
        avg_score = sum(scores) / len(scores)
        return round(min(10.0, max_score * 0.7 + avg_score * 0.3), 1)

    def _risk_rating(self, score: float) -> tuple[str, str]:
        for threshold, rating, desc in self.RISK_THRESHOLDS:
            if score >= threshold:
                return rating, desc
        return "Minimal", "No significant risk."


# ── 3. Finding Narrator ───────────────────────────────────

class FindingNarrator:
    """
    Generate detailed technical narratives for individual findings.

    Produces:
    - Impact story: Why this vulnerability matters in context
    - PoC steps: Step-by-step reproduction guide
    - Business risk: Non-technical impact explanation
    - Enhanced remediation: Specific code-level fix guidance
    """

    def __init__(self, narrator: ReportNarrator):
        self.narrator = narrator

    def narrate(self, finding: dict) -> NarratedFinding:
        """Generate full narrative for a single finding."""
        if self.narrator.api_key or self.narrator.provider == "ollama":
            return self._narrate_with_llm(finding)
        return self._narrate_template(finding)

    def narrate_bulk(
        self,
        findings: list[dict],
        limit: int = 20,
    ) -> list[NarratedFinding]:
        """Narrate multiple findings with progress display."""
        results = []
        to_narrate = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 4))
        to_narrate = to_narrate[:limit]

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Writing narratives...[/cyan] {task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("", total=len(to_narrate))
            for finding in to_narrate:
                progress.update(task, description=finding.get("title", "")[:40])
                results.append(self.narrate(finding))
                progress.advance(task)
                # Small delay to avoid API rate limits
                if self.narrator.api_key:
                    time.sleep(0.3)

        return results

    def _narrate_with_llm(self, finding: dict) -> NarratedFinding:
        """Use LLM to write finding narrative."""
        prompt = f"""Write a professional penetration test finding narrative.

Finding:
- Title: {finding.get('title', '')}
- Severity: {finding.get('severity', '')} (CVSS {finding.get('cvss', 0)})
- CWE: {finding.get('cwe', '')}
- Target: {finding.get('target', '')}
- Description: {finding.get('description', '')}
- Evidence: {finding.get('evidence', '')[:300]}
- Remediation: {finding.get('remediation', '')}

Write:
1. impact_story: 2-3 sentences explaining why this vulnerability is dangerous in real-world terms. Include what an attacker can do if they exploit it.
2. poc_steps: 3-5 numbered steps showing how to reproduce this finding
3. business_risk: 1-2 sentences for executives — what business impact if exploited (data breach, downtime, financial loss)
4. fix_guidance: Specific technical remediation with code example or config snippet if applicable

Return as JSON with keys: impact_story, poc_steps, business_risk, fix_guidance"""

        result = self.narrator.generate_structured(
            prompt,
            ["impact_story", "poc_steps", "business_risk", "fix_guidance"],
            max_tokens=600,
        )

        return NarratedFinding(
            original=finding,
            impact_story=result.get("impact_story") or self._default_impact(finding),
            poc_steps=result.get("poc_steps") or self._default_poc(finding),
            business_risk=result.get("business_risk") or self._default_business_risk(finding),
            fix_guidance=result.get("fix_guidance") or finding.get("remediation", ""),
        )

    def _narrate_template(self, finding: dict) -> NarratedFinding:
        """Template-based narrative (no LLM)."""
        return NarratedFinding(
            original=finding,
            impact_story=self._default_impact(finding),
            poc_steps=self._default_poc(finding),
            business_risk=self._default_business_risk(finding),
            fix_guidance=finding.get("remediation", ""),
        )

    def _default_impact(self, finding: dict) -> str:
        sev = finding.get("severity", "MEDIUM")
        title = finding.get("title", "This vulnerability")
        impact_map = {
            "CRITICAL": f"{title} poses critical risk. Successful exploitation could lead to complete system compromise, unauthorized access to all data, or full application takeover.",
            "HIGH":     f"{title} represents a significant security risk. An attacker exploiting this vulnerability could gain unauthorized access to sensitive data or functionality.",
            "MEDIUM":   f"{title} could be exploited to gain an advantage in a broader attack chain or access data that should be restricted.",
            "LOW":      f"{title} represents a low-severity issue that, while not directly exploitable, contributes to the overall attack surface.",
            "INFO":     f"{title} is an informational finding that improves the security posture when addressed.",
        }
        return impact_map.get(sev, impact_map["MEDIUM"])

    def _default_poc(self, finding: dict) -> str:
        evidence = finding.get("evidence", "")
        target   = finding.get("target", "https://target.com")
        return (
            f"1. Navigate to target: {target}\n"
            f"2. Identify the vulnerable parameter or endpoint\n"
            f"3. Apply test payload\n"
            f"4. Observe response indicating vulnerability\n"
            f"Evidence: {evidence[:200]}"
        )

    def _default_business_risk(self, finding: dict) -> str:
        sev = finding.get("severity", "MEDIUM")
        risk_map = {
            "CRITICAL": "If exploited, this vulnerability could result in a significant data breach, regulatory penalties, and severe reputational damage.",
            "HIGH":     "Exploitation could lead to unauthorized access to customer data or business systems, with potential regulatory and financial consequences.",
            "MEDIUM":   "This issue could contribute to a broader security incident if combined with other vulnerabilities.",
            "LOW":      "This issue has minimal direct business impact but should be addressed as part of security hygiene.",
            "INFO":     "Informational — no direct business risk.",
        }
        return risk_map.get(sev, risk_map["MEDIUM"])


# ── 4. Remediation Roadmap ────────────────────────────────

# Effort estimates by CWE category
CWE_EFFORT = {
    "CWE-79":   ("hours",  0, "dev",      True),   # XSS: add encoding
    "CWE-89":   ("hours",  1, "dev",      True),   # SQLi: parameterized queries
    "CWE-200":  ("hours",  2, "ops",      True),   # Info disclosure: config
    "CWE-284":  ("days",   2, "security", False),  # Access control
    "CWE-287":  ("days",   3, "dev",      False),  # Auth failure
    "CWE-295":  ("hours",  4, "ops",      False),  # Cert validation
    "CWE-306":  ("hours",  1, "dev",      True),   # Missing auth
    "CWE-312":  ("hours",  2, "dev",      True),   # Cleartext storage
    "CWE-319":  ("days",   1, "ops",      False),  # Cleartext transmission
    "CWE-327":  ("days",   3, "dev",      False),  # Weak crypto
    "CWE-352":  ("hours",  1, "dev",      True),   # CSRF
    "CWE-732":  ("days",   5, "security", False),  # Incorrect permissions
    "CWE-918":  ("hours",  3, "dev",      False),  # SSRF
    "CWE-942":  ("hours",  1, "ops",      True),   # CORS
}

SEVERITY_EFFORT_DEFAULT = {
    "CRITICAL": ("days",   1, "security", False),
    "HIGH":     ("days",   3, "dev",      False),
    "MEDIUM":   ("days",   5, "dev",      False),
    "LOW":      ("weeks",  1, "dev",      False),
    "INFO":     ("weeks",  2, "ops",      False),
}

EFFORT_DAYS = {"hours": 0, "days": 1, "weeks": 5}


class RemediationRoadmap:
    """
    Generate a prioritized remediation roadmap from findings.

    Categorizes fixes into:
    - P1 Immediate (Critical + High with quick wins)
    - P2 Short-term (30 days)
    - P3 Long-term (90 days)

    Estimates effort and assigns ownership (dev/ops/security/management).
    """

    def __init__(self, narrator: ReportNarrator | None = None):
        self.narrator = narrator

    def build(self, findings: list[dict]) -> list[RemediationItem]:
        """Build remediation roadmap from findings."""
        items = []
        for finding in sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 4)):
            item = self._build_item(finding)
            items.append(item)
        return items

    def format_markdown(self, items: list[RemediationItem]) -> str:
        """Format roadmap as markdown table."""
        p1 = [i for i in items if i.priority == 1]
        p2 = [i for i in items if i.priority == 2]
        p3 = [i for i in items if i.priority == 3]

        lines = ["## Remediation Roadmap\n"]

        for phase, phase_items, label in [
            (1, p1, "🔴 P1 — Immediate (< 7 days)"),
            (2, p2, "🟡 P2 — Short-term (< 30 days)"),
            (3, p3, "🟢 P3 — Long-term (< 90 days)"),
        ]:
            if not phase_items:
                continue
            lines.append(f"### {label}\n")
            lines.append("| # | Finding | Effort | Owner | Quick Win |")
            lines.append("|---|---------|--------|-------|-----------|")
            for i, item in enumerate(phase_items, 1):
                qw = "✅" if item.quick_win else "—"
                lines.append(
                    f"| {i} | {item.finding_title[:50]} | "
                    f"{item.effort_days}d | {item.owner} | {qw} |"
                )
            lines.append("")

        quick_wins = [i for i in items if i.quick_win]
        if quick_wins:
            lines.append(f"\n**{len(quick_wins)} Quick Wins** — fixes that can be done in hours:")
            for qw in quick_wins[:5]:
                lines.append(f"- {qw.finding_title}: {qw.effort} ({qw.owner})")

        return "\n".join(lines)

    def summary_stats(self, items: list[RemediationItem]) -> dict:
        """Get roadmap statistics."""
        return {
            "total":         len(items),
            "p1_immediate":  sum(1 for i in items if i.priority == 1),
            "p2_short_term": sum(1 for i in items if i.priority == 2),
            "p3_long_term":  sum(1 for i in items if i.priority == 3),
            "quick_wins":    sum(1 for i in items if i.quick_win),
            "total_effort_days": sum(i.effort_days for i in items),
            "by_owner": {
                "dev":        sum(1 for i in items if i.owner == "dev"),
                "ops":        sum(1 for i in items if i.owner == "ops"),
                "security":   sum(1 for i in items if i.owner == "security"),
                "management": sum(1 for i in items if i.owner == "management"),
            },
        }

    def _build_item(self, finding: dict) -> RemediationItem:
        cwe       = finding.get("cwe", "")
        severity  = finding.get("severity", "MEDIUM")

        effort_data = CWE_EFFORT.get(cwe) or SEVERITY_EFFORT_DEFAULT.get(severity, ("days", 3, "dev", False))
        effort_unit, effort_mult, owner, quick_win = effort_data
        effort_days = max(1, EFFORT_DAYS.get(effort_unit, 1) * max(1, effort_mult))

        # Priority based on severity + effort
        if severity in ("CRITICAL", "HIGH") and effort_days <= 2:
            priority = 1
        elif severity in ("CRITICAL", "HIGH"):
            priority = 1
        elif severity == "MEDIUM":
            priority = 2
        else:
            priority = 3

        return RemediationItem(
            finding_title=finding.get("title", "")[:80],
            severity=severity,
            effort=effort_unit,
            effort_days=effort_days,
            priority=priority,
            owner=owner,
            quick_win=quick_win,
        )


# ── 5. Pentest Report Generator (Orchestrator) ────────────

class PentestReportGenerator:
    """
    Full pentest report generator — from findings to deliverable.

    Orchestrates executive summary, finding narratives, and
    remediation roadmap into a complete HTML + Markdown report.

    The HTML report is self-contained, dark-themed, and suitable
    for direct delivery to clients.
    """

    def __init__(
        self,
        provider: str = "anthropic",
        api_key: str = "",
        model: str = "",
        base_url: str = "",
        timeout: int = 30,
    ):
        self.narrator = ReportNarrator(
            provider=provider, api_key=api_key,
            model=model, base_url=base_url, timeout=timeout,
        )
        self.exec_writer = ExecutiveSummaryWriter(self.narrator)
        self.find_writer  = FindingNarrator(self.narrator)
        self.roadmap      = RemediationRoadmap(self.narrator)

    def generate(
        self,
        findings: list[dict],
        target: str = "",
        engagement_name: str = "Security Assessment",
        tester: str = "Glitchicons",
        output_dir: str = "./reports",
        narrate_findings: bool = True,
        max_narrated: int = 15,
    ) -> PentestReport:
        """
        Generate complete pentest report.

        Args:
            findings:         List of Glitchicons finding dicts
            target:           Target URL or name
            engagement_name:  Name of the engagement
            tester:           Tester/team name
            output_dir:       Output directory for report files
            narrate_findings: Whether to use LLM for finding narratives
            max_narrated:     Max findings to narrate with LLM

        Returns:
            PentestReport with paths to generated files
        """
        console.print(f"\n  [bold cyan]⬡ AI Report Generator[/bold cyan]")
        console.print(f"  Engagement: {engagement_name}")
        console.print(f"  Findings:   {len(findings)}")
        console.print(f"  Provider:   {self.narrator.provider}")

        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        # 1. Executive summary
        console.print("  [dim]Writing executive summary...[/dim]")
        exec_summary = self.exec_writer.write(findings, target, engagement_name)

        # 2. Finding narratives
        narrated = []
        if narrate_findings and findings:
            console.print(f"  [dim]Narrating top {min(max_narrated, len(findings))} findings...[/dim]")
            narrated = self.find_writer.narrate_bulk(findings, limit=max_narrated)
        else:
            narrated = [self.find_writer._narrate_template(f) for f in findings[:max_narrated]]

        # 3. Remediation roadmap
        console.print("  [dim]Building remediation roadmap...[/dim]")
        road_items = self.roadmap.build(findings)

        report = PentestReport(
            engagement_name=engagement_name,
            target=target,
            tester=tester,
            generated_at=datetime.now(timezone.utc).isoformat(),
            executive_summary=exec_summary,
            narrated_findings=narrated,
            remediation_items=road_items,
            total_findings=len(findings),
            risk_score=exec_summary.risk_score,
        )

        # 4. Generate outputs
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        slug = re.sub(r"[^a-z0-9]+", "_", engagement_name.lower())[:30]

        md_path   = out_dir / f"report_{slug}_{ts}.md"
        html_path = out_dir / f"report_{slug}_{ts}.html"

        md_path.write_text(self._render_markdown(report), encoding="utf-8")
        html_path.write_text(self._render_html(report), encoding="utf-8")

        report.md_path   = str(md_path)
        report.html_path = str(html_path)

        console.print(f"\n  [green]✓[/green] Report generated!")
        console.print(f"  HTML: {html_path}")
        console.print(f"  MD:   {md_path}")

        return report

    def _render_markdown(self, report: PentestReport) -> str:
        """Render full report as Markdown."""
        es   = report.executive_summary
        lines = [
            f"# {report.engagement_name}",
            f"",
            f"**Target:** {report.target}  ",
            f"**Tester:** {report.tester}  ",
            f"**Date:** {report.generated_at[:10]}  ",
            f"**Overall Risk:** {es.risk_rating} ({es.risk_score:.1f}/10)  ",
            f"",
            "---",
            "",
            "## Executive Summary",
            "",
            es.opening,
            "",
            f"**Scope:** {es.scope}",
            "",
            f"**Key Findings:** {es.key_findings}",
            "",
            f"**Next Steps:** {es.next_steps}",
            "",
            "---",
            "",
            "## Findings Summary",
            "",
        ]

        # Severity breakdown
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = sum(1 for f in report.narrated_findings if f.original.get("severity") == sev)
            if count:
                icon = SEVERITY_ICON.get(sev, "")
                lines.append(f"- {icon} **{sev}:** {count}")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## Detailed Findings")
        lines.append("")

        for i, nf in enumerate(report.narrated_findings, 1):
            f   = nf.original
            sev = f.get("severity", "INFO")
            lines += [
                f"### {i}. {f.get('title', '')}",
                f"",
                f"**Severity:** {SEVERITY_ICON.get(sev, '')} {sev}  ",
                f"**CVSS:** {f.get('cvss', 0):.1f}  ",
                f"**CWE:** {f.get('cwe', '')}  ",
                f"**Target:** `{f.get('target', '')}`  ",
                f"",
                f"**Impact**",
                f"",
                nf.impact_story,
                f"",
                f"**Business Risk**",
                f"",
                nf.business_risk,
                f"",
                f"**Proof of Concept**",
                f"",
                f"```",
                nf.poc_steps,
                f"```",
                f"",
                f"**Remediation**",
                f"",
                nf.fix_guidance,
                f"",
                "---",
                "",
            ]

        # Roadmap
        lines.append(self.roadmap.format_markdown(report.remediation_items))

        return "\n".join(lines)

    def _render_html(self, report: PentestReport) -> str:
        """Render full report as self-contained dark-themed HTML."""
        es     = report.executive_summary
        stats  = self.roadmap.summary_stats(report.remediation_items)

        sev_counts = {}
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            sev_counts[sev] = sum(
                1 for f in report.narrated_findings if f.original.get("severity") == sev
            )

        # Build finding cards
        finding_cards = ""
        for i, nf in enumerate(report.narrated_findings, 1):
            f   = nf.original
            sev = f.get("severity", "INFO")
            col = SEVERITY_COLOR.get(sev, "#64D2FF")
            finding_cards += f"""
<div class="finding-card">
  <div class="finding-header" style="border-left:4px solid {col}">
    <span class="sev-badge" style="background:{col}20;color:{col}">{sev}</span>
    <span class="finding-num">#{i}</span>
    <h3>{f.get('title','')}</h3>
    <div class="finding-meta">
      CVSS {f.get('cvss',0):.1f} &nbsp;·&nbsp; {f.get('cwe','')} &nbsp;·&nbsp;
      <code>{f.get('target','')[:60]}</code>
    </div>
  </div>
  <div class="finding-body">
    <div class="section"><strong>Impact</strong><p>{nf.impact_story}</p></div>
    <div class="section"><strong>Business Risk</strong><p>{nf.business_risk}</p></div>
    <div class="section"><strong>Proof of Concept</strong>
      <pre>{nf.poc_steps[:600]}</pre></div>
    <div class="section"><strong>Remediation</strong><p>{nf.fix_guidance[:400]}</p></div>
  </div>
</div>"""

        # Roadmap rows
        road_rows = ""
        for item in report.remediation_items[:30]:
            pri_color = {"1": "#FF0040", "2": "#FFB300", "3": "#30D158"}
            pc = pri_color.get(str(item.priority), "#64D2FF")
            qw = "✅" if item.quick_win else "—"
            road_rows += f"""
<tr>
  <td><span style="color:{pc}">P{item.priority}</span></td>
  <td>{item.finding_title[:55]}</td>
  <td>{item.severity}</td>
  <td>{item.effort_days}d</td>
  <td>{item.owner}</td>
  <td>{qw}</td>
</tr>"""

        risk_color = SEVERITY_COLOR.get(
            "CRITICAL" if es.risk_score >= 9 else
            "HIGH"     if es.risk_score >= 7 else
            "MEDIUM"   if es.risk_score >= 5 else "LOW", "#30D158"
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{report.engagement_name}</title>
<style>
:root{{--bg:#06060D;--bg2:#0D0D1A;--bg3:#131326;--purple:#A855F7;--text:#E8E8F8;--text2:#9898B8;--border:rgba(107,0,255,.15)}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;line-height:1.6}}
.container{{max-width:1100px;margin:0 auto;padding:2rem}}
header{{padding:3rem 0 2rem;border-bottom:1px solid var(--border)}}
header h1{{color:var(--purple);font-size:1.8rem;margin-bottom:.5rem}}
header .meta{{color:var(--text2);font-size:.85rem;display:flex;gap:2rem;flex-wrap:wrap;margin-top:1rem}}
.score-row{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;margin:2rem 0}}
.score-card{{background:var(--bg3);border:1px solid var(--border);padding:1.25rem;text-align:center}}
.score-num{{font-size:2rem;font-weight:700}}
.score-label{{font-size:.7rem;color:var(--text2);text-transform:uppercase;letter-spacing:.1em;margin-top:.3rem}}
h2{{color:var(--purple);font-size:1.2rem;margin:2.5rem 0 1rem;padding-bottom:.5rem;border-bottom:1px solid var(--border)}}
.exec-block{{background:var(--bg2);border:1px solid var(--border);padding:1.5rem;margin-bottom:1rem}}
.exec-block .label{{color:var(--text2);font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:.5rem}}
.finding-card{{background:var(--bg2);border:1px solid var(--border);margin-bottom:1rem;overflow:hidden}}
.finding-header{{padding:1.25rem 1.5rem;border-bottom:1px solid var(--border)}}
.finding-header h3{{font-size:1rem;margin:.4rem 0}}
.finding-meta{{font-size:.8rem;color:var(--text2);margin-top:.3rem}}
.sev-badge{{display:inline-block;padding:.2rem .6rem;font-size:.7rem;font-weight:700;border-radius:2px;margin-right:.5rem}}
.finding-num{{color:var(--text2);font-size:.8rem;margin-right:.5rem}}
.finding-body{{padding:1.5rem;display:grid;grid-template-columns:1fr 1fr;gap:1rem}}
.section{{margin-bottom:.5rem}}
.section strong{{color:var(--text2);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;display:block;margin-bottom:.3rem}}
.section p{{font-size:.88rem;color:var(--text)}}
pre{{background:var(--bg3);padding:.75rem;font-size:.78rem;overflow-x:auto;white-space:pre-wrap;color:#64D2FF}}
code{{background:var(--bg3);padding:.1rem .4rem;font-size:.82rem;color:#A855F7}}
table{{width:100%;border-collapse:collapse;font-size:.85rem}}
th{{background:var(--bg3);color:var(--text2);padding:.6rem .75rem;text-align:left;font-weight:500}}
td{{padding:.5rem .75rem;border-bottom:1px solid rgba(255,255,255,.04)}}
tr:hover td{{background:var(--bg2)}}
footer{{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--border);color:var(--text2);font-size:.75rem;text-align:center}}
@media(max-width:700px){{.finding-body{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<div class="container">
<header>
  <h1>⬡ {report.engagement_name}</h1>
  <div class="meta">
    <span>Target: <strong>{report.target}</strong></span>
    <span>Tester: <strong>{report.tester}</strong></span>
    <span>Date: <strong>{report.generated_at[:10]}</strong></span>
    <span>Risk: <strong style="color:{risk_color}">{es.risk_rating} ({es.risk_score:.1f}/10)</strong></span>
  </div>
</header>

<div class="score-row">
  <div class="score-card"><div class="score-num" style="color:{risk_color}">{es.risk_score:.1f}</div><div class="score-label">Risk Score</div></div>
  <div class="score-card"><div class="score-num" style="color:{SEVERITY_COLOR['CRITICAL']}">{sev_counts.get('CRITICAL',0)}</div><div class="score-label">Critical</div></div>
  <div class="score-card"><div class="score-num" style="color:{SEVERITY_COLOR['HIGH']}">{sev_counts.get('HIGH',0)}</div><div class="score-label">High</div></div>
  <div class="score-card"><div class="score-num" style="color:{SEVERITY_COLOR['MEDIUM']}">{sev_counts.get('MEDIUM',0)}</div><div class="score-label">Medium</div></div>
  <div class="score-card"><div class="score-num">{stats['total']}</div><div class="score-label">Total Findings</div></div>
  <div class="score-card"><div class="score-num" style="color:#30D158">{stats['quick_wins']}</div><div class="score-label">Quick Wins</div></div>
</div>

<h2>Executive Summary</h2>
<div class="exec-block"><div class="label">Risk Statement</div>{es.opening}</div>
<div class="exec-block"><div class="label">Key Findings</div>{es.key_findings}</div>
<div class="exec-block"><div class="label">Recommended Next Steps</div>{es.next_steps}</div>

<h2>Detailed Findings</h2>
{finding_cards}

<h2>Remediation Roadmap</h2>
<table>
<tr><th>Priority</th><th>Finding</th><th>Severity</th><th>Effort</th><th>Owner</th><th>Quick Win</th></tr>
{road_rows}
</table>

<footer>
  Generated by <strong>GLITCHICONS</strong> v3.5.0 &nbsp;·&nbsp;
  {report.generated_at[:10]} &nbsp;·&nbsp;
  {len(report.narrated_findings)} findings reported
</footer>
</div>
</body>
</html>"""
