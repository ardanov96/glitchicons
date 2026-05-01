"""
GLITCHICONS ⬡ — Seed Generator Module v2
Decepticons Siege Division

Upgraded with:
- Semantic deduplication (not just MD5)
- AST-based code context (smarter LLM prompts)
- Session memory integration (learns what works)
"""

import os
import hashlib
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

from glitchicons_brain import SemanticDedup, CodeContextExtractor, GlitchiconsBrain

console = Console()

PROMPT_FROM_CONTEXT = """You are a security researcher and expert fuzzer.
Analyze this security context extracted from a target program and generate
{count} malformed inputs that could trigger crashes or vulnerabilities.

{context}

Focus on:
- Inputs that target the dangerous functions identified above
- Values that exceed buffer sizes found
- Malformed versions of expected input format
- Boundary values for the target language/format

Return ONLY the raw inputs, one per line, no explanation, no numbering."""

PROMPT_FROM_TYPE = """You are a security researcher and expert fuzzer.
Generate {count} malformed inputs to fuzz a {target_type} parser/handler.

Previously effective payloads for this target type (learn from these):
{recalled_payloads}

Generate NEW diverse inputs — not copies of the above. Focus on:
- Boundary conditions and edge cases
- Malformed structure and encoding
- Deeply nested or recursive content
- Special characters, null bytes, format strings
- Type confusion and unexpected values

Return ONLY the raw inputs, one per line, no explanation."""


class SeedGenerator:
    """
    LLM-powered seed generator v2.
    
    Now with semantic dedup, AST parsing, and session memory.
    """

    def __init__(
        self,
        model: str = "qwen2.5-coder:3b",
        output_dir: str = "./corpus",
        seed_count: int = 20,
        similarity_threshold: float = 0.75,
        memory_file: str = "~/.glitchicons/brain.json",
    ):
        self.model = model
        self.output_dir = Path(output_dir)
        self.seed_count = seed_count
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Core improvements
        self.dedup = SemanticDedup(similarity_threshold)
        self.extractor = CodeContextExtractor()
        self.brain = GlitchiconsBrain(memory_file)

    def _check_ollama(self) -> bool:
        if not OLLAMA_AVAILABLE:
            console.print("[red]✗ pip install ollama[/red]")
            return False
        try:
            models = ollama.list()
            available = [m.model for m in models.models]
            model_base = self.model.split(":")[0]
            if not any(model_base in m for m in available):
                console.print(f"[red]✗ Model '{self.model}' not found[/red]")
                console.print(f"[dim]  ollama pull {self.model}[/dim]")
                return False
            return True
        except Exception as e:
            console.print(f"[red]✗ Ollama not running: {e}[/red]")
            return False

    def _query_llm(self, prompt: str) -> Optional[str]:
        try:
            r = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0.85, "num_predict": 2048}
            )
            return r["message"]["content"]
        except Exception as e:
            console.print(f"[red]LLM query failed: {e}[/red]")
            return None

    def _parse_raw(self, raw: str) -> list[str]:
        """Parse LLM response into individual seeds."""
        import re
        lines = raw.strip().split("\n")
        seeds = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("```"):
                continue
            line = re.sub(r"^\d+[\.\)]\s*|^[-*]\s*", "", line)
            if line:
                seeds.append(line)
        return seeds

    def _save_seeds(self, seeds: list[str], prefix: str = "seed") -> list[Path]:
        """Save deduplicated seeds to corpus directory."""
        saved = []
        for i, seed in enumerate(seeds):
            content = seed.encode("utf-8", errors="replace")
            h = hashlib.md5(content).hexdigest()[:8]
            filename = self.output_dir / f"{prefix}_{i:03d}_{h}.txt"
            with open(filename, "wb") as f:
                f.write(content)
            saved.append(filename)
        return saved

    def _show_preview(self, seeds: list[str]):
        console.print("\n[bold]Preview (first 5 seeds):[/bold]")
        for i, seed in enumerate(seeds[:5], 1):
            display = seed[:80] + "..." if len(seed) > 80 else seed
            console.print(f"  [dim]{i}.[/dim] [cyan]{display}[/cyan]")
        console.print()

    def from_source(self, source_path: str) -> list[Path]:
        """
        Generate seeds by analyzing source code via AST.
        Uses CodeContextExtractor for targeted LLM prompts.
        """
        console.print(Panel(
            f"[bold purple]⬡ SEED GENERATOR v2[/bold purple]\n"
            f"[dim]Source :[/dim] {source_path}\n"
            f"[dim]Model  :[/dim] {self.model}\n"
            f"[dim]Seeds  :[/dim] {self.seed_count}\n"
            f"[dim]Output :[/dim] {self.output_dir}",
            border_style="purple"
        ))

        if not self._check_ollama():
            return []

        # AST extraction — smarter context
        console.print("[dim]→ Extracting code context via AST...[/dim]")
        ctx = self.extractor.extract(source_path)
        context_prompt = self.extractor.to_llm_prompt(ctx)
        console.print(f"[dim]  Found: {len(ctx.get('dangerous_calls', {}))} dangerous call categories[/dim]")

        prompt = PROMPT_FROM_CONTEXT.format(
            count=self.seed_count,
            context=context_prompt
        )

        # Recall from brain memory
        file_ext = Path(source_path).suffix.replace('.', '')
        recalled = self.brain.recall_for_target(f"source_{file_ext}")

        with Progress(SpinnerColumn(style="purple"),
                      TextColumn("[purple]{task.description}"),
                      console=console) as p:
            t = p.add_task("Generating seeds via LLM...", total=None)
            raw = self._query_llm(prompt)
            p.update(t, description="Parsing + deduplicating...")

        if not raw:
            return []

        # Parse and deduplicate
        raw_seeds = self._parse_raw(raw)
        # Prepend recalled effective seeds
        all_seeds = recalled + raw_seeds
        unique_seeds = self.dedup.filter_batch(all_seeds)

        console.print(f"[green]✓ {len(unique_seeds)} unique seeds (from {len(all_seeds)} candidates)[/green]")

        saved = self._save_seeds(unique_seeds, prefix="src")
        console.print(f"[green]✓ Saved {len(saved)} seeds to {self.output_dir}[/green]")
        self._show_preview(unique_seeds)

        # Record session
        self.brain.record_session_start(f"source_{file_ext}")
        return saved

    def from_type(self, target_type: str) -> list[Path]:
        """
        Generate seeds for a known input type.
        Recalls effective payloads from brain memory.
        """
        console.print(Panel(
            f"[bold purple]⬡ SEED GENERATOR v2[/bold purple]\n"
            f"[dim]Type   :[/dim] {target_type}\n"
            f"[dim]Model  :[/dim] {self.model}\n"
            f"[dim]Seeds  :[/dim] {self.seed_count}\n"
            f"[dim]Output :[/dim] {self.output_dir}",
            border_style="purple"
        ))

        if not self._check_ollama():
            return []

        # Recall from brain
        recalled = self.brain.recall_for_target(target_type)
        recalled_str = "\n".join(f"- {p}" for p in recalled[:5]) if recalled \
                       else "(no prior knowledge — generating fresh)"

        prompt = PROMPT_FROM_TYPE.format(
            count=self.seed_count,
            target_type=target_type,
            recalled_payloads=recalled_str
        )

        with Progress(SpinnerColumn(style="purple"),
                      TextColumn("[purple]{task.description}"),
                      console=console) as p:
            t = p.add_task(f"Generating {target_type} seeds...", total=None)
            raw = self._query_llm(prompt)
            p.update(t, description="Parsing + deduplicating...")

        if not raw:
            return []

        raw_seeds = self._parse_raw(raw)
        all_seeds = recalled + raw_seeds
        unique_seeds = self.dedup.filter_batch(all_seeds)

        console.print(f"[green]✓ {len(unique_seeds)} unique seeds (from {len(all_seeds)} candidates)[/green]")
        saved = self._save_seeds(unique_seeds, prefix=target_type)
        console.print(f"[green]✓ Saved {len(saved)} seeds to {self.output_dir}[/green]")
        self._show_preview(unique_seeds)

        self.brain.record_session_start(target_type)
        return saved

    def record_crash(self, target_type: str, crash_type: str, payload: str):
        """Feed crash result back into brain memory."""
        self.brain.record_crash(target_type, crash_type, payload)
        console.print(f"[purple]⬡ Brain updated:[/purple] recorded {crash_type} for '{target_type}'")

    def brain_stats(self):
        """Show brain statistics."""
        self.brain.print_stats()


if __name__ == "__main__":
    gen = SeedGenerator(
        model="qwen2.5-coder:3b",
        output_dir="./corpus_test",
        seed_count=10,
        similarity_threshold=0.75,
    )
    console.print("[bold magenta]Testing upgraded seed generator...[/bold magenta]\n")
    gen.from_type("JSON")
    gen.brain_stats()
