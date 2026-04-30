"""
GLITCHICONS ⬡ — Seed Generator Module
Decepticons Siege Division

Takes source code or a target description → 
sends to local LLM (Ollama) → 
returns targeted malformed seed inputs for AFL++
"""

import os
import json
import hashlib
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.syntax import Syntax

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

console = Console()

# ── PROMPTS ────────────────────────────────────────────────────────────────

PROMPT_FROM_SOURCE = """You are a security researcher and expert fuzzer.
Analyze the following source code and generate {count} malformed inputs 
that could trigger crashes, buffer overflows, integer overflows, 
use-after-free, or other memory corruption bugs.

Focus on:
- Boundary values (INT_MAX, INT_MIN, 0, -1, empty strings)
- Format string injection (%s %x %n %p)
- Very long strings (100, 1000, 10000 chars)
- Null bytes embedded in strings
- Invalid encoding (non-UTF8, binary data)
- Nested/recursive structures that cause stack overflow
- Type confusion inputs

Source code to analyze:
{code}

Return ONLY the raw inputs, one per line, no explanation, no numbering.
Each input should be on its own line.
Binary/null bytes can be represented as \\x00, \\xff etc."""

PROMPT_FROM_TYPE = """You are a security researcher and expert fuzzer.
Generate {count} malformed inputs to fuzz a {target_type} parser/handler.

Focus on edge cases that commonly cause crashes:
- Boundary conditions
- Malformed structure 
- Unexpected types
- Deeply nested content
- Extremely long values
- Special characters and null bytes
- Format string sequences

Return ONLY the raw inputs, one per line, no explanation, no numbering."""

PROMPT_BINARY_PATTERNS = """You are a security researcher specializing in binary fuzzing.
Generate {count} binary mutation patterns for fuzzing.

The target is: {description}

Generate inputs as hex sequences (e.g. 41414141, ff00ff00).
Return ONLY hex strings, one per line, no explanation."""


# ── SEED GENERATOR CLASS ────────────────────────────────────────────────────

class SeedGenerator:
    """
    LLM-powered seed generator for AFL++ fuzzing campaigns.
    
    Analyzes source code or target description and generates
    semantically-aware malformed inputs as seed corpus.
    """

    def __init__(
        self,
        model: str = "qwen2.5-coder:3b",
        output_dir: str = "./corpus",
        seed_count: int = 20,
    ):
        self.model = model
        self.output_dir = Path(output_dir)
        self.seed_count = seed_count
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _check_ollama(self) -> bool:
        """Verify Ollama is running and model is available."""
        if not OLLAMA_AVAILABLE:
            console.print("[red]✗ ollama Python package not installed.[/red]")
            console.print("[dim]  Run: pip install ollama[/dim]")
            return False
        try:
            models = ollama.list()
            available = [m.model for m in models.models]
            # Check if our model is available (handle version tags)
            model_base = self.model.split(":")[0]
            found = any(model_base in m for m in available)
            if not found:
                console.print(f"[red]✗ Model '{self.model}' not found.[/red]")
                console.print(f"[dim]  Run: ollama pull {self.model}[/dim]")
                console.print(f"[dim]  Available: {available}[/dim]")
                return False
            return True
        except Exception as e:
            console.print(f"[red]✗ Ollama not running: {e}[/red]")
            console.print("[dim]  Run: sudo systemctl start ollama[/dim]")
            return False

    def _query_llm(self, prompt: str) -> Optional[str]:
        """Send prompt to LLM, return raw response."""
        try:
            response = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                options={
                    "temperature": 0.8,   # some creativity for diverse seeds
                    "num_predict": 2048,
                }
            )
            return response["message"]["content"]
        except Exception as e:
            console.print(f"[red]LLM query failed: {e}[/red]")
            return None

    def _parse_seeds(self, raw: str) -> list[str]:
        """
        Parse LLM response into individual seed strings.
        Handles: code blocks, numbering, blank lines.
        """
        lines = raw.strip().split("\n")
        seeds = []

        for line in lines:
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # Skip markdown code fences
            if line.startswith("```"):
                continue

            # Strip numbering: "1. ", "1) ", "- "
            import re
            line = re.sub(r"^\d+[\.\)]\s*", "", line)
            line = re.sub(r"^[-*]\s*", "", line)

            if line:
                seeds.append(line)

        return seeds

    def _save_seeds(self, seeds: list[str], prefix: str = "seed") -> list[Path]:
        """Save seeds to corpus directory, return list of saved paths."""
        saved = []
        for i, seed in enumerate(seeds):
            # Handle hex seeds
            if all(c in "0123456789abcdefABCDEF" for c in seed.replace(" ", "")):
                try:
                    content = bytes.fromhex(seed.replace(" ", ""))
                    ext = ".bin"
                except ValueError:
                    content = seed.encode("utf-8", errors="replace")
                    ext = ".txt"
            else:
                # Process escape sequences
                content = seed.encode("utf-8", errors="replace")
                ext = ".txt"

            # Use hash as filename to avoid duplicates
            h = hashlib.md5(content).hexdigest()[:8]
            filename = self.output_dir / f"{prefix}_{i:03d}_{h}{ext}"

            with open(filename, "wb") as f:
                f.write(content)
            saved.append(filename)

        return saved

    # ── PUBLIC METHODS ────────────────────────────────────────────────────

    def from_source(self, source_path: str) -> list[Path]:
        """
        Generate seeds by analyzing source code.
        
        Args:
            source_path: Path to C/C++/Python/etc source file
            
        Returns:
            List of paths to generated seed files
        """
        source = Path(source_path)
        if not source.exists():
            console.print(f"[red]✗ Source file not found: {source_path}[/red]")
            return []

        code = source.read_text(errors="replace")

        console.print(Panel(
            f"[bold purple]⬡ SEED GENERATOR[/bold purple]\n"
            f"[dim]Source:[/dim] {source_path}\n"
            f"[dim]Model :[/dim] {self.model}\n"
            f"[dim]Seeds :[/dim] {self.seed_count}\n"
            f"[dim]Output:[/dim] {self.output_dir}",
            border_style="purple"
        ))

        if not self._check_ollama():
            return []

        prompt = PROMPT_FROM_SOURCE.format(
            count=self.seed_count,
            code=code[:4000]  # limit context window
        )

        with Progress(
            SpinnerColumn(style="purple"),
            TextColumn("[purple]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Generating seeds via LLM...", total=None)
            raw = self._query_llm(prompt)
            progress.update(task, description="Parsing response...")

        if not raw:
            return []

        seeds = self._parse_seeds(raw)
        console.print(f"[green]✓ LLM generated {len(seeds)} seed candidates[/green]")

        saved = self._save_seeds(seeds, prefix="src")
        console.print(f"[green]✓ Saved {len(saved)} seeds to {self.output_dir}[/green]")

        self._show_preview(seeds[:5])
        return saved

    def from_type(self, target_type: str) -> list[Path]:
        """
        Generate seeds for a known input type (JSON, XML, HTTP, etc).
        
        Args:
            target_type: Type of input (json, xml, http, binary, csv, etc)
            
        Returns:
            List of paths to generated seed files
        """
        console.print(Panel(
            f"[bold purple]⬡ SEED GENERATOR[/bold purple]\n"
            f"[dim]Type  :[/dim] {target_type}\n"
            f"[dim]Model :[/dim] {self.model}\n"
            f"[dim]Seeds :[/dim] {self.seed_count}\n"
            f"[dim]Output:[/dim] {self.output_dir}",
            border_style="purple"
        ))

        if not self._check_ollama():
            return []

        prompt = PROMPT_FROM_TYPE.format(
            count=self.seed_count,
            target_type=target_type
        )

        with Progress(
            SpinnerColumn(style="purple"),
            TextColumn("[purple]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"Generating {target_type} seeds...", total=None)
            raw = self._query_llm(prompt)
            progress.update(task, description="Parsing response...")

        if not raw:
            return []

        seeds = self._parse_seeds(raw)
        console.print(f"[green]✓ LLM generated {len(seeds)} seed candidates[/green]")

        saved = self._save_seeds(seeds, prefix=target_type)
        console.print(f"[green]✓ Saved {len(saved)} seeds to {self.output_dir}[/green]")

        self._show_preview(seeds[:5])
        return saved

    def _show_preview(self, seeds: list[str]):
        """Show preview of first few seeds in terminal."""
        console.print("\n[bold]Preview (first 5 seeds):[/bold]")
        for i, seed in enumerate(seeds, 1):
            # Truncate long seeds for display
            display = seed[:80] + "..." if len(seed) > 80 else seed
            console.print(f"  [dim]{i}.[/dim] [cyan]{display}[/cyan]")
        console.print()


# ── STANDALONE TEST ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    gen = SeedGenerator(
        model="qwen2.5-coder:3b",
        output_dir="./corpus_test",
        seed_count=10,
    )

    if len(sys.argv) > 1:
        # Test from source file
        gen.from_source(sys.argv[1])
    else:
        # Default: test with JSON type
        console.print("[bold magenta]Testing seed generator with JSON target...[/bold magenta]\n")
        gen.from_type("JSON")
