"""
False Positive Reducer — modules/intelligence/fp_reducer.py

Verifies each finding using LLM + re-probe before it enters the final report.

Problem: Traditional scanners have 20-40% false positive rate.
Solution: Before reporting, ask LLM to reason about the evidence and
          optionally re-probe with a confirmation payload.

Verification pipeline per finding:
  1. Static analysis     — check if evidence is internally consistent
  2. LLM reasoning       — "given this evidence, is this a real finding?"
  3. Confidence score    — 0.0–1.0 (findings below threshold filtered)
  4. Re-probe (optional) — send confirmation payload to target
  5. Verdict             — CONFIRMED | LIKELY | UNCERTAIN | FALSE_POSITIVE

Confidence thresholds:
  >= 0.85 → CONFIRMED   (include in report)
  >= 0.60 → LIKELY      (include with note)
  >= 0.35 → UNCERTAIN   (include with warning)
  <  0.35 → FALSE_POSITIVE (exclude from report)

Supports batch processing of full finding lists.

Usage:
    from modules.intelligence.fp_reducer import FalsePositiveReducer

    reducer = FalsePositiveReducer(provider="ollama")
    verified = reducer.verify_all(findings)
    # Only CONFIRMED and LIKELY findings returned
    clean_findings = [f for f in verified if f["verdict"] != "FALSE_POSITIVE"]

Author: ardanov96
"""

import json
import re
import time
import httpx
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass
from rich.console import Console
from rich.table import Table

console = Console()


# ── Verdict constants ─────────────────────────────────────

VERDICT_CONFIRMED      = "CONFIRMED"
VERDICT_LIKELY         = "LIKELY"
VERDICT_UNCERTAIN      = "UNCERTAIN"
VERDICT_FALSE_POSITIVE = "FALSE_POSITIVE"

CONFIDENCE_THRESHOLDS = {
    VERDICT_CONFIRMED:      0.85,
    VERDICT_LIKELY:         0.60,
    VERDICT_UNCERTAIN:      0.35,
    VERDICT_FALSE_POSITIVE: 0.0,
}


# ── Static heuristics ─────────────────────────────────────

# Evidence that strongly supports a finding being real
STRONG_EVIDENCE_PATTERNS = {
    "sqli": [
        r"you have an error in your sql syntax",
        r"mysql_fetch",
        r"ora-\d{5}",
        r"pg_query\(\).*failed",
        r"sqlite3\.operationalerror",
        r"unclosed quotation mark",
        r"unterminated string",
        r"warning.*mysql",
    ],
    "xss": [
        r"<script>alert\(",
        r"onerror=alert\(",
        r"onload=alert\(",
        r"javascript:alert\(",
    ],
    "ssti": [
        r"\b49\b.*7.*7",           # 7*7=49 confirmed
        r"jinja2",
        r"template.*error",
    ],
    "ssrf": [
        r"169\.254\.169\.254",
        r"ami-id",
        r"instance-id",
        r"computemetadata",
        r"root:x:0:0",
    ],
    "cors": [
        r"access-control-allow-origin:\s*https?://evil",
        r"access-control-allow-credentials:\s*true",
    ],
    "generic": [],
}

# Evidence that suggests a false positive
FALSE_POSITIVE_PATTERNS = [
    r"access denied",
    r"403 forbidden",
    r"waf blocked",
    r"this request was rejected",
    r"security violation detected",
    r"invalid request",
    r"honeypot",
]

# Confirmation payloads for re-probe
CONFIRMATION_PAYLOADS = {
    "sqli": "' AND SLEEP(0) AND '1'='1",   # should not delay if filtered
    "xss":  "<glitchtest>xss</glitchtest>",  # unique tag for reflection check
    "ssti": "{{1+1}}",                        # should return 2 if vulnerable
    "ssrf": "http://127.0.0.1:1",             # connection refused = SSRF exists
    "cors": None,                              # no confirmation payload
}


# ── Verification result ───────────────────────────────────

@dataclass
class VerificationResult:
    """Result of LLM + heuristic verification for one finding."""
    finding_id: str
    original_severity: str
    original_cvss: float
    verdict: str
    confidence: float
    llm_reasoning: str
    static_signals: list[str]
    reprobed: bool
    reprobe_confirmed: bool | None
    verified_at: str

    @property
    def is_real(self) -> bool:
        return self.verdict in (VERDICT_CONFIRMED, VERDICT_LIKELY)

    def verdict_color(self) -> str:
        colors = {
            VERDICT_CONFIRMED:      "green",
            VERDICT_LIKELY:         "cyan",
            VERDICT_UNCERTAIN:      "yellow",
            VERDICT_FALSE_POSITIVE: "red",
        }
        return colors.get(self.verdict, "white")


# ── LLM Verification Prompt ───────────────────────────────

VERIFICATION_PROMPT = """You are a senior penetration tester verifying a security finding.
Analyze the evidence and determine if this is a real vulnerability or a false positive.

Finding:
  Title:       {title}
  Severity:    {severity}
  Type:        {attack_type}
  Target:      {target}

Evidence:
{evidence}

Static signals detected: {static_signals}

Instructions:
1. Analyze if the evidence conclusively proves the vulnerability
2. Consider common false positive patterns (WAF blocking, input sanitization, generic error pages)
3. Give a confidence score from 0.0 (definitely false positive) to 1.0 (definitely real)
4. Provide brief reasoning (2-3 sentences max)

Respond in this exact JSON format:
{{
  "confidence": 0.XX,
  "verdict": "CONFIRMED|LIKELY|UNCERTAIN|FALSE_POSITIVE",
  "reasoning": "Your 2-3 sentence reasoning here"
}}

Do not include any text outside the JSON."""


# ── Main reducer ──────────────────────────────────────────

class FalsePositiveReducer:
    """
    LLM-powered false positive reducer.

    Each finding goes through:
    1. Static heuristic analysis (pattern matching on evidence)
    2. LLM reasoning (contextual analysis)
    3. Optional re-probe (live confirmation)
    4. Final verdict with confidence score
    """

    def __init__(
        self,
        provider: str = "ollama",
        model: str = "qwen2.5-coder:3b",
        api_key: str | None = None,
        ollama_url: str = "http://localhost:11434",
        output_dir: str = "./findings/verified",
        confidence_threshold: float = 0.35,
        reprobe: bool = False,
        reprobe_timeout: int = 8,
    ):
        self.provider = provider
        self.model = model
        self.api_key = api_key
        self.ollama_url = ollama_url.rstrip("/")
        self.output_dir = Path(output_dir)
        self.confidence_threshold = confidence_threshold
        self.reprobe = reprobe
        self.reprobe_timeout = reprobe_timeout
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ── Public API ────────────────────────────────────────

    def verify_all(
        self,
        findings: list[dict],
        delay: float = 0.3,
    ) -> list[dict]:
        """
        Verify all findings. Return enriched findings with verdict field.
        Findings below confidence_threshold are marked FALSE_POSITIVE.
        """
        if not findings:
            return []

        console.print(f"\n[bold cyan]  False Positive Reducer[/bold cyan]")
        console.print(f"  Findings  : {len(findings)}")
        console.print(f"  LLM       : {self.provider}/{self.model}")
        console.print(f"  Threshold : {self.confidence_threshold}\n")

        verified = []
        stats = {
            VERDICT_CONFIRMED:      0,
            VERDICT_LIKELY:         0,
            VERDICT_UNCERTAIN:      0,
            VERDICT_FALSE_POSITIVE: 0,
        }

        for i, finding in enumerate(findings, 1):
            fid = finding.get("id", f"FIND-{i:03d}")
            title = finding.get("title", "Unknown")[:50]
            console.print(f"  [{i}/{len(findings)}] [cyan]{fid}[/cyan] {title}...", end=" ")

            result = self.verify_one(finding)
            stats[result.verdict] += 1

            # Enrich finding with verification data
            enriched = {
                **finding,
                "verdict":         result.verdict,
                "confidence":      result.confidence,
                "llm_reasoning":   result.llm_reasoning,
                "static_signals":  result.static_signals,
                "reprobe_confirmed": result.reprobe_confirmed,
                "verified_at":     result.verified_at,
            }
            verified.append(enriched)

            color = result.verdict_color()
            console.print(
                f"[{color}]{result.verdict}[/{color}] "
                f"({result.confidence:.0%})"
            )
            time.sleep(delay)

        self._print_stats(stats, len(findings))
        self._save_verified(verified, stats)
        return verified

    def verify_one(self, finding: dict) -> VerificationResult:
        """Verify a single finding. Return VerificationResult."""
        fid = finding.get("id", "UNKNOWN")
        evidence = finding.get("evidence", "")
        attack_type = self._detect_attack_type(finding)

        # Step 1: Static analysis
        static_signals = self._static_analysis(evidence, attack_type)
        fp_signals = self._fp_analysis(evidence)

        # Step 2: Fast path — strong static evidence
        if len(static_signals) >= 2 and not fp_signals:
            return VerificationResult(
                finding_id=fid,
                original_severity=finding.get("severity", ""),
                original_cvss=finding.get("cvss", 0),
                verdict=VERDICT_CONFIRMED,
                confidence=0.95,
                llm_reasoning="Multiple strong evidence patterns confirmed by static analysis.",
                static_signals=static_signals,
                reprobed=False,
                reprobe_confirmed=None,
                verified_at=datetime.now().isoformat(),
            )

        # Fast path — clear false positive
        if fp_signals and not static_signals:
            return VerificationResult(
                finding_id=fid,
                original_severity=finding.get("severity", ""),
                original_cvss=finding.get("cvss", 0),
                verdict=VERDICT_FALSE_POSITIVE,
                confidence=0.10,
                llm_reasoning="Evidence contains WAF block or security rejection patterns.",
                static_signals=static_signals,
                reprobed=False,
                reprobe_confirmed=None,
                verified_at=datetime.now().isoformat(),
            )

        # Step 3: LLM analysis
        confidence, verdict, reasoning = self._llm_verify(finding, attack_type, static_signals)

        # Step 4: Optional re-probe
        reprobe_confirmed = None
        if self.reprobe and verdict != VERDICT_FALSE_POSITIVE:
            reprobe_confirmed = self._reprobe(finding, attack_type)
            if reprobe_confirmed is True:
                confidence = min(1.0, confidence + 0.15)
                verdict = VERDICT_CONFIRMED
            elif reprobe_confirmed is False:
                confidence = max(0.0, confidence - 0.20)
                if confidence < self.confidence_threshold:
                    verdict = VERDICT_FALSE_POSITIVE

        return VerificationResult(
            finding_id=fid,
            original_severity=finding.get("severity", ""),
            original_cvss=finding.get("cvss", 0),
            verdict=verdict,
            confidence=confidence,
            llm_reasoning=reasoning,
            static_signals=static_signals,
            reprobed=self.reprobe,
            reprobe_confirmed=reprobe_confirmed,
            verified_at=datetime.now().isoformat(),
        )

    # ── Static Analysis ───────────────────────────────────

    def _static_analysis(self, evidence: str, attack_type: str) -> list[str]:
        """Match evidence against known strong-signal patterns."""
        patterns = (
            STRONG_EVIDENCE_PATTERNS.get(attack_type, [])
            + STRONG_EVIDENCE_PATTERNS.get("generic", [])
        )
        evidence_lower = evidence.lower()
        matched = []
        for pattern in patterns:
            if re.search(pattern, evidence_lower):
                matched.append(pattern)
        return matched

    def _fp_analysis(self, evidence: str) -> list[str]:
        """Check if evidence contains false positive indicators."""
        evidence_lower = evidence.lower()
        matched = []
        for pattern in FALSE_POSITIVE_PATTERNS:
            if re.search(pattern, evidence_lower):
                matched.append(pattern)
        return matched

    def _detect_attack_type(self, finding: dict) -> str:
        """Detect attack type from finding title/CWE."""
        title = finding.get("title", "").lower()
        cwe = finding.get("cwe", "")

        type_map = {
            "sqli": ["sql", "injection", "cwe-89"],
            "xss":  ["xss", "cross-site script", "cwe-79"],
            "ssti": ["template", "ssti", "cwe-94"],
            "ssrf": ["ssrf", "server-side request", "cwe-918"],
            "cors": ["cors", "cross-origin", "cwe-942"],
            "idor": ["idor", "insecure direct", "cwe-639"],
            "sqli_timing": ["time-based", "sleep"],
        }

        for attack, keywords in type_map.items():
            if any(kw in title or (kw.startswith("cwe-") and kw == cwe.lower()) or (not kw.startswith("cwe-") and kw in title) for kw in keywords):
                return attack

        return "generic"

    # ── LLM Verification ─────────────────────────────────

    def _llm_verify(
        self,
        finding: dict,
        attack_type: str,
        static_signals: list[str],
    ) -> tuple[float, str, str]:
        """Ask LLM to reason about finding. Return (confidence, verdict, reasoning)."""

        prompt = VERIFICATION_PROMPT.format(
            title=finding.get("title", "Unknown"),
            severity=finding.get("severity", ""),
            attack_type=attack_type,
            target=finding.get("target", ""),
            evidence=finding.get("evidence", "")[:800],
            static_signals=static_signals or ["none"],
        )

        raw = self._call_llm(prompt)
        return self._parse_llm_response(raw)

    def _call_llm(self, prompt: str) -> str:
        """Call configured LLM provider."""
        try:
            if self.provider == "ollama":
                resp = httpx.post(
                    f"{self.ollama_url}/api/generate",
                    json={"model": self.model, "prompt": prompt, "stream": False,
                          "options": {"num_predict": 300, "temperature": 0.2}},
                    timeout=45,
                )
                return resp.json().get("response", "")

            elif self.provider == "anthropic":
                resp = httpx.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={"x-api-key": self.api_key or "", "anthropic-version": "2023-06-01",
                             "content-type": "application/json"},
                    json={"model": self.model, "max_tokens": 300,
                          "messages": [{"role": "user", "content": prompt}]},
                    timeout=30,
                )
                return resp.json()["content"][0]["text"]

            elif self.provider == "openai":
                resp = httpx.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key or ''}",
                             "Content-Type": "application/json"},
                    json={"model": self.model, "max_tokens": 300, "temperature": 0.2,
                          "messages": [{"role": "user", "content": prompt}]},
                    timeout=30,
                )
                return resp.json()["choices"][0]["message"]["content"]

        except Exception as e:
            console.print(f"  [yellow]LLM error: {e}[/yellow]")

        return ""

    def _parse_llm_response(self, raw: str) -> tuple[float, str, str]:
        """Parse LLM JSON response into (confidence, verdict, reasoning)."""
        if not raw:
            return 0.5, VERDICT_UNCERTAIN, "LLM unavailable — defaulting to UNCERTAIN."

        # Extract JSON from response
        try:
            # Try direct parse
            data = json.loads(raw.strip())
        except json.JSONDecodeError:
            # Try extracting JSON block
            match = re.search(r"\{[^{}]*\}", raw, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group())
                except json.JSONDecodeError:
                    return 0.5, VERDICT_UNCERTAIN, "Could not parse LLM response."
            else:
                return 0.5, VERDICT_UNCERTAIN, "LLM response was not valid JSON."

        confidence = float(data.get("confidence", 0.5))
        confidence = max(0.0, min(1.0, confidence))
        reasoning = str(data.get("reasoning", "No reasoning provided."))[:500]

        # Determine verdict from confidence
        verdict = self._confidence_to_verdict(confidence)

        # Override if LLM explicitly said FALSE_POSITIVE
        llm_verdict = str(data.get("verdict", "")).upper()
        if llm_verdict == VERDICT_FALSE_POSITIVE and confidence < 0.35:
            verdict = VERDICT_FALSE_POSITIVE

        return confidence, verdict, reasoning

    @staticmethod
    def _confidence_to_verdict(confidence: float) -> str:
        """Map confidence score to verdict string."""
        if confidence >= CONFIDENCE_THRESHOLDS[VERDICT_CONFIRMED]:
            return VERDICT_CONFIRMED
        if confidence >= CONFIDENCE_THRESHOLDS[VERDICT_LIKELY]:
            return VERDICT_LIKELY
        if confidence >= CONFIDENCE_THRESHOLDS[VERDICT_UNCERTAIN]:
            return VERDICT_UNCERTAIN
        return VERDICT_FALSE_POSITIVE

    # ── Re-probe ──────────────────────────────────────────

    def _reprobe(self, finding: dict, attack_type: str) -> bool | None:
        """Send confirmation payload to target. Return True/False/None."""
        payload = CONFIRMATION_PAYLOADS.get(attack_type)
        if not payload:
            return None

        target = finding.get("target", "") or finding.get("endpoint", "")
        if not target or not target.startswith("http"):
            return None

        try:
            resp = httpx.get(
                target,
                params={"q": payload, "search": payload, "input": payload},
                timeout=self.reprobe_timeout,
                follow_redirects=True,
            )
            body = resp.text.lower()

            if attack_type == "sqli":
                return any(err in body for err in ["syntax error", "mysql", "ora-"])
            elif attack_type == "xss":
                return "glitchtest" in body
            elif attack_type == "ssti":
                return "2" in body  # 1+1=2
            else:
                return None

        except Exception:
            return None

    # ── Display & Save ────────────────────────────────────

    def _print_stats(self, stats: dict, total: int):
        """Print verification summary table."""
        console.print(f"\n[bold cyan]  Verification Summary[/bold cyan]")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Verdict",    width=16)
        table.add_column("Count",      width=8)
        table.add_column("Percent",    width=10)

        colors = {
            VERDICT_CONFIRMED:      "green",
            VERDICT_LIKELY:         "cyan",
            VERDICT_UNCERTAIN:      "yellow",
            VERDICT_FALSE_POSITIVE: "red",
        }
        for verdict, count in stats.items():
            pct = f"{count/total*100:.0f}%" if total > 0 else "0%"
            c = colors[verdict]
            table.add_row(f"[{c}]{verdict}[/{c}]", str(count), pct)

        console.print(table)
        real = stats[VERDICT_CONFIRMED] + stats[VERDICT_LIKELY]
        console.print(
            f"\n  Actionable: [green]{real}[/green] / {total} "
            f"({real/total*100:.0f}% real)\n" if total > 0 else ""
        )

    def _save_verified(self, findings: list[dict], stats: dict) -> Path:
        """Save verified findings to JSON."""
        report = {
            "tool":       "glitchicons",
            "module":     "fp_reducer",
            "version":    "0.9.0",
            "timestamp":  datetime.now().isoformat(),
            "llm":        f"{self.provider}/{self.model}",
            "threshold":  self.confidence_threshold,
            "stats":      stats,
            "total":      len(findings),
            "actionable": sum(1 for f in findings
                              if f.get("verdict") in (VERDICT_CONFIRMED, VERDICT_LIKELY)),
            "findings":   sorted(findings, key=lambda x: x.get("confidence", 0), reverse=True),
        }
        out = self.output_dir / f"verified_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        console.print(f"  Saved: [cyan]{out}[/cyan]")
        return out
