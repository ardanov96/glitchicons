"""
Severity Reasoning — modules/intelligence/severity_reasoner.py

Uses LLM to explain WHY a finding has a specific CVSS score,
generate human-readable severity justifications, and optionally
re-score findings if the original score seems wrong.

Features:
  1. CVSS breakdown        — explain each metric (AV, AC, PR, UI, S, C, I, A)
  2. Narrative explanation — plain-English "why this is HIGH" explanation
  3. Business impact       — translate technical finding to business risk
  4. Re-scoring            — LLM can challenge/confirm the original CVSS
  5. Remediation priority  — sort findings by urgency + exploitability
  6. Executive summary     — one paragraph per finding for non-technical readers
  7. CVSS vector string    — generate CVSSv3.1 vector from finding context

CVSS v3.1 Metrics:
  AV: Network(N) / Adjacent(A) / Local(L) / Physical(P)
  AC: Low(L) / High(H)
  PR: None(N) / Low(L) / High(H)
  UI: None(N) / Required(R)
  S:  Unchanged(U) / Changed(C)
  C:  None(N) / Low(L) / High(H)
  I:  None(N) / Low(L) / High(H)
  A:  None(N) / Low(L) / High(H)

Usage:
    from modules.intelligence.severity_reasoner import SeverityReasoner

    reasoner = SeverityReasoner(provider="ollama")
    enriched = reasoner.enrich_all(findings)
    # Each finding now has: cvss_breakdown, narrative, business_impact,
    #                        executive_summary, remediation_priority

Author: ardanov96
"""

import json
import re
import httpx
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table

console = Console()


# ── CVSS v3.1 constants ───────────────────────────────────

CVSS_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "S":  {"U": 0.00, "C": 1.00},   # Changed scope
    "C":  {"N": 0.00, "L": 0.22, "H": 0.56},
    "I":  {"N": 0.00, "L": 0.22, "H": 0.56},
    "A":  {"N": 0.00, "L": 0.22, "H": 0.56},
}

CVSS_METRIC_LABELS = {
    "AV": "Attack Vector",
    "AC": "Attack Complexity",
    "PR": "Privileges Required",
    "UI": "User Interaction",
    "S":  "Scope",
    "C":  "Confidentiality Impact",
    "I":  "Integrity Impact",
    "A":  "Availability Impact",
}

CVSS_VALUE_LABELS = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S":  {"U": "Unchanged", "C": "Changed"},
    "C":  {"N": "None", "L": "Low", "H": "High"},
    "I":  {"N": "None", "L": "Low", "H": "High"},
    "A":  {"N": "None", "L": "Low", "H": "High"},
}

SEVERITY_LABELS = {
    (9.0, 10.0): "CRITICAL",
    (7.0, 8.9):  "HIGH",
    (4.0, 6.9):  "MEDIUM",
    (0.1, 3.9):  "LOW",
    (0.0, 0.0):  "NONE",
}

# Default CVSS vectors by attack type
DEFAULT_VECTORS = {
    "sqli":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "xss":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "ssrf":    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
    "ssti":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "cors":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    "idor":    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
    "takeover":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "mfa":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "grpc":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "generic": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
}

# Business impact templates
BUSINESS_IMPACT_TEMPLATES = {
    "CRITICAL": (
        "This vulnerability poses an immediate, existential risk to the organization. "
        "Exploitation could result in complete system compromise, large-scale data breach, "
        "regulatory fines, and severe reputational damage. Immediate remediation required."
    ),
    "HIGH": (
        "This vulnerability represents a serious security risk that could enable attackers "
        "to access sensitive data or disrupt critical operations. "
        "Remediation should be prioritized within days."
    ),
    "MEDIUM": (
        "This vulnerability could be exploited under specific conditions to compromise "
        "user data or system integrity. "
        "Remediation should be planned within weeks."
    ),
    "LOW": (
        "This vulnerability has limited direct impact but could contribute to a broader attack. "
        "Remediation should be scheduled in the next sprint or release cycle."
    ),
}

# Remediation priority factors (higher = more urgent)
PRIORITY_FACTORS = {
    "CRITICAL": 100,
    "HIGH":     70,
    "MEDIUM":   40,
    "LOW":      15,
}


# ── Data classes ──────────────────────────────────────────

@dataclass
class CVSSBreakdown:
    """Parsed CVSS v3.1 vector with metric explanations."""
    vector: str
    base_score: float
    severity: str
    metrics: dict[str, str]         # e.g. {"AV": "N", "AC": "L", ...}
    metric_labels: dict[str, str]   # e.g. {"Attack Vector": "Network", ...}
    metric_scores: dict[str, float] # e.g. {"AV": 0.85, ...}
    exploitability: float
    impact: float

    def to_dict(self) -> dict:
        return {
            "vector":        self.vector,
            "base_score":    self.base_score,
            "severity":      self.severity,
            "metrics":       self.metric_labels,
            "exploitability": round(self.exploitability, 2),
            "impact":        round(self.impact, 2),
        }


@dataclass
class SeverityReasoning:
    """Full severity reasoning for one finding."""
    finding_id: str
    original_score: float
    original_severity: str
    suggested_score: float | None
    suggested_severity: str | None
    score_changed: bool
    cvss_vector: str
    cvss_breakdown: CVSSBreakdown | None
    narrative: str
    business_impact: str
    executive_summary: str
    remediation_priority: int
    reasoned_at: str = field(default_factory=lambda: datetime.now().isoformat())


# ── CVSS Calculator ───────────────────────────────────────

class CVSSCalculator:
    """Calculate CVSS v3.1 scores from vector strings."""

    @staticmethod
    def parse_vector(vector: str) -> dict[str, str]:
        """Parse CVSS:3.1/AV:N/AC:L/... into dict."""
        metrics = {}
        parts = vector.replace("CVSS:3.1/", "").split("/")
        for part in parts:
            if ":" in part:
                k, v = part.split(":", 1)
                metrics[k.strip()] = v.strip()
        return metrics

    @staticmethod
    def calculate_score(metrics: dict[str, str]) -> float:
        """Calculate CVSS v3.1 base score from parsed metrics."""
        try:
            av = CVSS_METRICS["AV"].get(metrics.get("AV", "N"), 0.85)
            ac = CVSS_METRICS["AC"].get(metrics.get("AC", "L"), 0.77)
            pr = CVSS_METRICS["PR"].get(metrics.get("PR", "N"), 0.85)
            ui = CVSS_METRICS["UI"].get(metrics.get("UI", "N"), 0.85)
            c  = CVSS_METRICS["C"].get(metrics.get("C", "N"), 0.00)
            i  = CVSS_METRICS["I"].get(metrics.get("I", "N"), 0.00)
            a  = CVSS_METRICS["A"].get(metrics.get("A", "N"), 0.00)
            scope = metrics.get("S", "U")

            exploitability = 8.22 * av * ac * pr * ui

            isc_base = 1 - (1 - c) * (1 - i) * (1 - a)
            if scope == "U":
                impact = 6.42 * isc_base
            else:
                impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

            if impact <= 0:
                return 0.0

            if scope == "U":
                score = min(impact + exploitability, 10)
            else:
                score = min(1.08 * (impact + exploitability), 10)

            # Round up to 1 decimal
            return round(min(10.0, max(0.0, score)), 1)

        except Exception:
            return 0.0

    @staticmethod
    def score_to_severity(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0.0:
            return "LOW"
        return "NONE"

    @classmethod
    def breakdown(cls, vector: str) -> CVSSBreakdown | None:
        """Parse vector and compute full breakdown."""
        try:
            metrics = cls.parse_vector(vector)
            if not metrics:
                return None

            score = cls.calculate_score(metrics)
            severity = cls.score_to_severity(score)

            metric_labels = {
                CVSS_METRIC_LABELS.get(k, k): CVSS_VALUE_LABELS.get(k, {}).get(v, v)
                for k, v in metrics.items()
            }
            metric_scores = {
                k: CVSS_METRICS.get(k, {}).get(v, 0)
                for k, v in metrics.items()
            }

            av = CVSS_METRICS["AV"].get(metrics.get("AV", "N"), 0.85)
            ac = CVSS_METRICS["AC"].get(metrics.get("AC", "L"), 0.77)
            pr = CVSS_METRICS["PR"].get(metrics.get("PR", "N"), 0.85)
            ui = CVSS_METRICS["UI"].get(metrics.get("UI", "N"), 0.85)
            exploitability = 8.22 * av * ac * pr * ui

            c = CVSS_METRICS["C"].get(metrics.get("C", "N"), 0.00)
            i = CVSS_METRICS["I"].get(metrics.get("I", "N"), 0.00)
            a = CVSS_METRICS["A"].get(metrics.get("A", "N"), 0.00)
            isc = 1 - (1 - c) * (1 - i) * (1 - a)

            return CVSSBreakdown(
                vector=vector,
                base_score=score,
                severity=severity,
                metrics=metrics,
                metric_labels=metric_labels,
                metric_scores=metric_scores,
                exploitability=exploitability,
                impact=isc,
            )
        except Exception:
            return None

    @classmethod
    def build_vector(cls, attack_type: str, finding: dict) -> str:
        """Build a CVSS vector string from finding context."""
        # Start with default for attack type
        base = DEFAULT_VECTORS.get(attack_type, DEFAULT_VECTORS["generic"])
        metrics = cls.parse_vector(base)

        # Adjust based on finding context
        title_lower = finding.get("title", "").lower()
        evidence_lower = finding.get("evidence", "").lower()

        # Auth required? → PR:L
        if "authenticated" in title_lower or "requires auth" in evidence_lower:
            metrics["PR"] = "L"

        # User interaction needed?
        if "phishing" in title_lower or "victim" in evidence_lower:
            metrics["UI"] = "R"

        # Local only?
        if "local" in title_lower and "network" not in title_lower:
            metrics["AV"] = "L"

        # No data exposure → C:N
        if "denial" in title_lower or "dos" in title_lower:
            metrics["C"] = "N"
            metrics["I"] = "N"
            metrics["A"] = "H"

        return "CVSS:3.1/" + "/".join(f"{k}:{v}" for k, v in metrics.items())


# ── LLM Prompts ───────────────────────────────────────────

NARRATIVE_PROMPT = """You are a senior penetration tester writing a finding narrative.
Write a clear, professional explanation of this security vulnerability in 3-4 sentences.

Finding:
  Title:    {title}
  Severity: {severity} (CVSS {cvss})
  Type:     {attack_type}
  Evidence: {evidence}

Requirements:
- Explain what the vulnerability is
- Explain how it can be exploited
- Explain what data/systems are at risk
- Use technical but clear language
- Do NOT include remediation in this section

Write only the narrative paragraph, no headers or bullet points."""

RESCORE_PROMPT = """You are a CVSS v3.1 scoring expert. Review this finding and determine if the score is accurate.

Finding:
  Title:    {title}
  Severity: {severity}
  Score:    {cvss}
  Vector:   {vector}
  Evidence: {evidence}

Current CVSS breakdown:
{breakdown}

Instructions:
1. Review each CVSS metric against the evidence
2. Determine if the score is accurate, too high, or too low
3. Suggest a corrected score if needed

Respond in this exact JSON format:
{{
  "score_accurate": true/false,
  "suggested_score": X.X,
  "suggested_vector": "CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X",
  "reasoning": "1-2 sentences explaining your assessment"
}}

Output only the JSON, nothing else."""


# ── Main reasoner ─────────────────────────────────────────

class SeverityReasoner:
    """
    LLM-powered severity reasoning engine.

    Enriches each finding with:
    - CVSS vector and metric breakdown
    - Plain-English narrative explanation
    - Business impact statement
    - Executive summary (non-technical)
    - Remediation priority score
    - Optional LLM re-scoring
    """

    def __init__(
        self,
        provider: str = "ollama",
        model: str = "qwen2.5-coder:3b",
        api_key: str | None = None,
        ollama_url: str = "http://localhost:11434",
        output_dir: str = "./findings/reasoned",
        rescore: bool = False,
    ):
        self.provider = provider
        self.model = model
        self.api_key = api_key
        self.ollama_url = ollama_url.rstrip("/")
        self.output_dir = Path(output_dir)
        self.rescore = rescore
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def enrich_all(self, findings: list[dict], delay: float = 0.2) -> list[dict]:
        """Enrich all findings with severity reasoning. Return enriched list."""
        if not findings:
            return []

        console.print(f"\n[bold cyan]  Severity Reasoner[/bold cyan]")
        console.print(f"  Findings : {len(findings)}")
        console.print(f"  LLM      : {self.provider}/{self.model}")
        console.print(f"  Re-score : {self.rescore}\n")

        enriched = []
        for i, finding in enumerate(findings, 1):
            fid = finding.get("id", f"F{i:03d}")
            title = finding.get("title", "Unknown")[:50]
            console.print(f"  [{i}/{len(findings)}] [cyan]{fid}[/cyan] {title}...", end=" ")

            reasoning = self.reason_one(finding)
            enriched_finding = self._apply_reasoning(finding, reasoning)
            enriched.append(enriched_finding)

            score_str = f"{reasoning.suggested_score}" if reasoning.score_changed else str(reasoning.original_score)
            change = " [yellow](rescored)[/yellow]" if reasoning.score_changed else ""
            console.print(f"[green]{reasoning.original_severity}[/green] {score_str}{change}")

        # Sort by priority
        enriched.sort(key=lambda f: f.get("remediation_priority", 0), reverse=True)
        self._save_enriched(enriched)
        return enriched

    def reason_one(self, finding: dict) -> SeverityReasoning:
        """Generate full severity reasoning for one finding."""
        fid = finding.get("id", "UNKNOWN")
        original_score = float(finding.get("cvss", 5.0))
        original_severity = finding.get("severity", "MEDIUM")
        attack_type = self._detect_attack_type(finding)

        # 1. Build CVSS vector
        existing_vector = finding.get("cvss_vector", "")
        if existing_vector and existing_vector.startswith("CVSS:3.1"):
            vector = existing_vector
        else:
            vector = CVSSCalculator.build_vector(attack_type, finding)

        # 2. Calculate breakdown
        breakdown = CVSSCalculator.breakdown(vector)

        # 3. Generate narrative via LLM (or fallback)
        narrative = self._generate_narrative(finding, attack_type)

        # 4. Business impact
        business_impact = BUSINESS_IMPACT_TEMPLATES.get(
            original_severity,
            BUSINESS_IMPACT_TEMPLATES["MEDIUM"],
        )

        # 5. Executive summary
        executive_summary = self._build_executive_summary(finding, original_severity)

        # 6. Remediation priority
        priority = self._calculate_priority(finding, breakdown)

        # 7. Optional re-scoring
        suggested_score = None
        suggested_severity = None
        score_changed = False

        if self.rescore and breakdown:
            suggested_score, suggested_vector, reasoning_text = self._rescore(
                finding, vector, breakdown
            )
            if suggested_score and abs(suggested_score - original_score) >= 0.5:
                score_changed = True
                suggested_severity = CVSSCalculator.score_to_severity(suggested_score)
                if suggested_vector:
                    vector = suggested_vector
                    breakdown = CVSSCalculator.breakdown(vector)

        return SeverityReasoning(
            finding_id=fid,
            original_score=original_score,
            original_severity=original_severity,
            suggested_score=suggested_score if score_changed else None,
            suggested_severity=suggested_severity if score_changed else None,
            score_changed=score_changed,
            cvss_vector=vector,
            cvss_breakdown=breakdown,
            narrative=narrative,
            business_impact=business_impact,
            executive_summary=executive_summary,
            remediation_priority=priority,
        )

    # ── Narrative generation ──────────────────────────────

    def _generate_narrative(self, finding: dict, attack_type: str) -> str:
        """Generate plain-English narrative via LLM or fallback."""
        prompt = NARRATIVE_PROMPT.format(
            title=finding.get("title", ""),
            severity=finding.get("severity", ""),
            cvss=finding.get("cvss", ""),
            attack_type=attack_type,
            evidence=finding.get("evidence", "")[:500],
        )
        raw = self._call_llm(prompt, max_tokens=200)
        if raw and len(raw.strip()) > 20:
            return raw.strip()

        # Fallback narrative
        return (
            f"A {finding.get('severity', 'security')} vulnerability was identified: "
            f"{finding.get('title', 'unknown issue')}. "
            f"This affects {finding.get('target', 'the target system')} and "
            f"may allow an attacker to compromise the system confidentiality, "
            f"integrity, or availability. Immediate investigation is recommended."
        )

    # ── Re-scoring ────────────────────────────────────────

    def _rescore(
        self,
        finding: dict,
        vector: str,
        breakdown: CVSSBreakdown,
    ) -> tuple[float | None, str | None, str]:
        """Ask LLM to verify and optionally correct the CVSS score."""
        breakdown_str = "\n".join(
            f"  {k}: {v}" for k, v in breakdown.metric_labels.items()
        )
        prompt = RESCORE_PROMPT.format(
            title=finding.get("title", ""),
            severity=finding.get("severity", ""),
            cvss=finding.get("cvss", ""),
            vector=vector,
            evidence=finding.get("evidence", "")[:400],
            breakdown=breakdown_str,
        )
        raw = self._call_llm(prompt, max_tokens=300)

        try:
            match = re.search(r"\{[^{}]*\}", raw, re.DOTALL)
            if match:
                data = json.loads(match.group())
                score = float(data.get("suggested_score", 0))
                suggested_vector = data.get("suggested_vector", "")
                reasoning = data.get("reasoning", "")
                if 0.0 <= score <= 10.0:
                    return score, suggested_vector, reasoning
        except Exception:
            pass

        return None, None, ""

    # ── Priority calculator ───────────────────────────────

    def _calculate_priority(self, finding: dict, breakdown: CVSSBreakdown | None) -> int:
        """Calculate remediation priority score (0-100)."""
        severity = finding.get("severity", "MEDIUM")
        base = PRIORITY_FACTORS.get(severity, 40)

        bonus = 0
        title_lower = finding.get("title", "").lower()

        # Higher priority for easily exploitable
        if breakdown:
            if breakdown.metrics.get("AC") == "L":   bonus += 10
            if breakdown.metrics.get("PR") == "N":   bonus += 10
            if breakdown.metrics.get("AV") == "N":   bonus += 10
            if breakdown.exploitability > 3.0:        bonus += 5

        # Higher priority for specific attack types
        if any(kw in title_lower for kw in ["auth", "bypass", "takeover", "injection"]):
            bonus += 5
        if "brute force" in title_lower or "no limit" in title_lower:
            bonus += 5

        return min(100, base + bonus)

    # ── Helpers ───────────────────────────────────────────

    def _detect_attack_type(self, finding: dict) -> str:
        """Detect attack type from finding title/CWE."""
        title = finding.get("title", "").lower()
        cwe = finding.get("cwe", "").lower()
        type_map = [
            ("sqli",    ["sql injection", "sqli", "cwe-89"]),
            ("xss",     ["xss", "cross-site scripting", "cwe-79"]),
            ("ssti",    ["template injection", "ssti", "cwe-94"]),
            ("ssrf",    ["ssrf", "server-side request", "cwe-918"]),
            ("cors",    ["cors", "cross-origin", "cwe-942"]),
            ("idor",    ["idor", "insecure direct", "cwe-639"]),
            ("takeover",["takeover", "subdomain", "dangling"]),
            ("mfa",     ["mfa", "2fa", "otp", "bypass"]),
            ("grpc",    ["grpc", "reflection api"]),
        ]
        for attack, keywords in type_map:
            if any(kw in title or kw in cwe for kw in keywords):
                return attack
        return "generic"

    def _build_executive_summary(self, finding: dict, severity: str) -> str:
        """Build non-technical executive summary."""
        severity_plain = {
            "CRITICAL": "extremely serious",
            "HIGH":     "serious",
            "MEDIUM":   "moderate",
            "LOW":      "low-risk",
        }.get(severity, "security")

        title = finding.get("title", "a security issue")
        target = finding.get("target", "the system")
        cvss = finding.get("cvss", "")

        return (
            f"Our security assessment identified a {severity_plain} vulnerability "
            f"({title}) affecting {target}. "
            f"With a severity score of {cvss}/10, this issue "
            f"{'requires immediate attention' if severity in ('CRITICAL', 'HIGH') else 'should be addressed in the near term'}. "
            f"{BUSINESS_IMPACT_TEMPLATES.get(severity, '')[:100]}"
        )

    def _apply_reasoning(self, finding: dict, reasoning: SeverityReasoning) -> dict:
        """Merge reasoning into finding dict."""
        enriched = dict(finding)
        enriched.update({
            "cvss_vector":           reasoning.cvss_vector,
            "cvss_breakdown":        reasoning.cvss_breakdown.to_dict() if reasoning.cvss_breakdown else None,
            "narrative":             reasoning.narrative,
            "business_impact":       reasoning.business_impact,
            "executive_summary":     reasoning.executive_summary,
            "remediation_priority":  reasoning.remediation_priority,
            "severity_reasoned_at":  reasoning.reasoned_at,
        })
        if reasoning.score_changed and reasoning.suggested_score:
            enriched["cvss_suggested"]          = reasoning.suggested_score
            enriched["severity_suggested"]       = reasoning.suggested_severity
            enriched["score_change_note"]        = (
                f"LLM suggested rescoring from {reasoning.original_score} "
                f"to {reasoning.suggested_score}"
            )
        return enriched

    def _call_llm(self, prompt: str, max_tokens: int = 300) -> str:
        """Call configured LLM provider."""
        try:
            if self.provider == "ollama":
                resp = httpx.post(
                    f"{self.ollama_url}/api/generate",
                    json={"model": self.model, "prompt": prompt, "stream": False,
                          "options": {"num_predict": max_tokens, "temperature": 0.3}},
                    timeout=45,
                )
                return resp.json().get("response", "")
            elif self.provider == "anthropic":
                resp = httpx.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={"x-api-key": self.api_key or "", "anthropic-version": "2023-06-01",
                             "content-type": "application/json"},
                    json={"model": self.model, "max_tokens": max_tokens,
                          "messages": [{"role": "user", "content": prompt}]},
                    timeout=30,
                )
                return resp.json()["content"][0]["text"]
            elif self.provider == "openai":
                resp = httpx.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key or ''}",
                             "Content-Type": "application/json"},
                    json={"model": self.model, "max_tokens": max_tokens, "temperature": 0.3,
                          "messages": [{"role": "user", "content": prompt}]},
                    timeout=30,
                )
                return resp.json()["choices"][0]["message"]["content"]
        except Exception as e:
            pass
        return ""

    def _save_enriched(self, findings: list[dict]) -> Path:
        """Save enriched findings to JSON."""
        report = {
            "tool":      "glitchicons",
            "module":    "severity_reasoner",
            "version":   "0.9.0",
            "timestamp": datetime.now().isoformat(),
            "llm":       f"{self.provider}/{self.model}",
            "total":     len(findings),
            "findings":  findings,
        }
        out = self.output_dir / f"reasoned_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        console.print(f"\n  Saved: [cyan]{out}[/cyan]")
        return out
