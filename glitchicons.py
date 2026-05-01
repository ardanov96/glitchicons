#!/usr/bin/env python3
"""
GLITCHICONS ⬡
Decepticons Siege Division — AI-Powered Security Research Platform
v0.4.0-dev
"""

import shutil
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


@click.group()
@click.version_option(version="0.4.0-dev", prog_name="glitchicons")
def cli():
    """
    GLITCHICONS ⬡ — AI-Powered Security Research Platform

    Decepticons Siege Division | MIT License

    Where others probe, we siege. Where others test, we break.
    """
    pass


# ── SEED ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--source", "-s", type=click.Path(), default=None,
              help="Source code file to analyze via AST")
@click.option("--type", "-t", "input_type",
              type=click.Choice(["json","xml","http","binary",
                                 "csv","sql","html","yaml","protobuf"]),
              default=None, help="Input type for seed generation")
@click.option("--output", "-o", type=click.Path(), default="./corpus")
@click.option("--count", "-n", type=int, default=20)
@click.option("--model", "-m", type=str, default="qwen2.5-coder:3b")
@click.option("--threshold", type=float, default=0.75,
              help="Similarity threshold for dedup (default: 0.75)")
def seed(source, input_type, output, count, model, threshold):
    """
    Generate LLM-powered mutation seeds for AFL++ fuzzing.

    Uses AST analysis for source files and session memory
    to recall previously effective payloads.

    Examples:

        glitchicons seed --type json --count 30

        glitchicons seed --source ./target.c --output ./corpus

        glitchicons seed --type http --threshold 0.8
    """
    from seed_generator import SeedGenerator

    if not source and not input_type:
        console.print("[red]✗ Provide --source or --type[/red]")
        console.print("[dim]  glitchicons seed --type json[/dim]")
        raise click.Abort()

    gen = SeedGenerator(
        model=model,
        output_dir=output,
        seed_count=count,
        similarity_threshold=threshold,
    )
    saved = gen.from_source(source) if source else gen.from_type(input_type)

    if saved:
        console.print(f"\n[bold green]⬡ {len(saved)} seeds ready in {output}[/bold green]")
    else:
        console.print("\n[red]⬡ Seed generation failed[/red]")


# ── FUZZ ──────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--corpus", "-c", type=click.Path(), default="./corpus")
@click.option("--output", "-o", type=click.Path(), default="./findings")
@click.option("--timeout", "-t", type=int, default=3600)
def fuzz(target, corpus, output, timeout):
    """
    Launch AFL++ binary fuzzing siege against TARGET.

    Examples:

        glitchicons fuzz ./binary

        glitchicons fuzz ./binary --corpus ./my_corpus --timeout 7200
    """
    import subprocess
    from pathlib import Path

    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    corpus_path = Path(corpus)

    console.print(Panel(
        f"[bold purple]⬡ BINARY FUZZER[/bold purple]\n\n"
        f"[dim]Target :[/dim] {target}\n"
        f"[dim]Corpus :[/dim] {corpus}\n"
        f"[dim]Output :[/dim] {output}\n"
        f"[dim]Timeout:[/dim] {timeout}s",
        border_style="purple"
    ))

    if not corpus_path.exists() or not any(corpus_path.iterdir()):
        console.print("[yellow]⚠ Corpus empty. Run: glitchicons seed --type binary[/yellow]")
        if click.confirm("Generate seeds now?"):
            from seed_generator import SeedGenerator
            SeedGenerator(output_dir=corpus, seed_count=20).from_type("binary")

    if not shutil.which("afl-fuzz"):
        console.print("[red]✗ afl-fuzz not found. Run: sudo apt install afl++[/red]")
        return

    cmd = ["afl-fuzz", "-i", str(corpus_path), "-o", str(output_path),
           "--", target, "@@"]
    console.print(f"\n[bold purple]⬡ LAUNCHING AFL++ SIEGE...[/bold purple]")
    console.print(f"[dim]{' '.join(cmd)}[/dim]\n")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        console.print("\n[yellow]⬡ Siege interrupted.[/yellow]")


# ── PROTOCOL ──────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target_url")
@click.option("--endpoints", "-e", multiple=True,
              help="Endpoints to fuzz (repeatable)")
@click.option("--output", "-o", type=click.Path(), default="./protocol_findings")
@click.option("--model", "-m", type=str, default="qwen2.5-coder:3b")
@click.option("--delay", "-d", type=float, default=0.5)
@click.option("--token", type=str, default=None, help="Bearer auth token")
@click.option("--no-paths", is_flag=True, default=False)
@click.option("--no-headers", is_flag=True, default=False)
@click.option("--post", is_flag=True, default=False)
def protocol(target_url, endpoints, output, model, delay,
             token, no_paths, no_headers, post):
    """
    Launch HTTP/API protocol fuzzing siege against TARGET_URL.

    Examples:

        glitchicons protocol https://api.target.com

        glitchicons protocol https://api.target.com --endpoints /users --token eyJ...

        glitchicons protocol https://api.target.com --post --delay 1.0
    """
    try:
        from protocol_fuzzer import ProtocolFuzzer
    except ImportError as e:
        console.print(f"[red]✗ {e}[/red]")
        console.print("[dim]  pip install requests[/dim]")
        return

    fuzzer = ProtocolFuzzer(
        target_url=target_url,
        output_dir=output,
        model=model,
        delay=delay,
        auth_token=token,
    )
    fuzzer.run_full_siege(
        endpoints=list(endpoints) if endpoints else None,
        fuzz_params=True,
        fuzz_headers=not no_headers,
        fuzz_paths=not no_paths,
        fuzz_post=post,
    )


# ── TRIAGE ────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.argument("crash_dir", type=click.Path(exists=True))
@click.option("--output", "-o", default="./reports")
@click.option("--model", "-m", default="qwen2.5-coder:3b")
@click.option("--max", "max_crashes", type=int, default=10)
def triage(target, crash_dir, output, model, max_crashes):
    """
    Triage AFL++ crashes via GDB + LLM → CVE-style report.

    Examples:

        glitchicons triage ./binary ./findings/default/crashes

        glitchicons triage ./binary ./crashes --max 20
    """
    from crash_triage import CrashTriage
    try:
        t = CrashTriage(
            target_binary=target,
            crash_dir=crash_dir,
            output_dir=output,
            model=model,
        )
        reports = t.run(max_crashes=max_crashes)
        if reports:
            console.print(f"\n[green]⬡ {len(reports)} reports in {output}[/green]")
    except FileNotFoundError as e:
        console.print(f"[red]✗ {e}[/red]")


# ── COVERAGE ──────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("afl_dir", type=click.Path(exists=True))
@click.option("--source", "-s", type=click.Path(), default=".",
              help="Source directory with .gcov files (default: .)")
@click.option("--output", "-o", type=click.Path(),
              default="./coverage_reports",
              help="Output directory for HTML report")
@click.option("--model", "-m", default="qwen2.5-coder:3b")
def coverage(afl_dir, source, output, model):
    """
    Generate interactive coverage map from AFL++ findings.

    Shows which code paths were hit and which remain unexplored.
    Identifies high-priority uncovered functions for next siege.

    Requirements:
      Compile with coverage flags:
      afl-gcc -fprofile-arcs -ftest-coverage -o target target.c

    Examples:

        glitchicons coverage ./findings

        glitchicons coverage ./findings --source ./src --output ./coverage
    """
    from coverage_map import CoverageMap

    console.print(Panel(
        f"[bold purple]⬡ COVERAGE MAP[/bold purple]\n\n"
        f"[dim]AFL++ dir :[/dim] {afl_dir}\n"
        f"[dim]Source    :[/dim] {source}\n"
        f"[dim]Output    :[/dim] {output}",
        border_style="purple"
    ))

    cmap = CoverageMap(
        afl_output_dir=afl_dir,
        source_dir=source,
        output_dir=output,
        model=model,
    )

    report = cmap.collect_and_report()
    summary = cmap.get_coverage_summary()

    # Print summary table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Metric", style="dim", width=22)
    table.add_column("Value")

    color = "green" if summary["line_coverage_pct"] >= 70 \
        else "yellow" if summary["line_coverage_pct"] >= 40 else "red"

    table.add_row("Line Coverage",
        f"[{color}]{summary['line_coverage_pct']}%[/{color}] "
        f"({summary['lines_covered']}/{summary['lines_total']})"
    )
    table.add_row("Functions Hit",
        f"{summary['functions_covered']}/{summary['functions_total']}"
    )
    table.add_row("AFL++ Paths", str(summary["afl_paths"]))
    table.add_row("AFL++ Crashes", str(summary["afl_crashes"]))
    table.add_row("Total Execs", str(summary["afl_execs"]))

    console.print(table)
    console.print(f"\n[dim]Open in browser:[/dim] {report}")


# ── BRAIN ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--reset", is_flag=True, default=False,
              help="Reset all brain memory (caution: irreversible)")
def brain(reset):
    """
    Show Glitchicons brain memory statistics.

    The brain tracks which payloads caused crashes per target type
    and recalls them in future sessions.

    Examples:

        glitchicons brain

        glitchicons brain --reset
    """
    from glitchicons_brain import GlitchiconsBrain
    from pathlib import Path

    b = GlitchiconsBrain()

    if reset:
        if click.confirm("[red]Reset ALL brain memory? This cannot be undone.[/red]"):
            memory_path = Path("~/.glitchicons/brain.json").expanduser()
            if memory_path.exists():
                memory_path.unlink()
            console.print("[yellow]⬡ Brain memory reset.[/yellow]")
        return

    b.print_stats()

    # Show global effective patterns
    patterns = b.get_global_effective_patterns(top_n=5)
    if patterns:
        console.print(f"\n[bold]Global effective patterns:[/bold]")
        for p in patterns:
            console.print(f"  [cyan]{p[:80]}[/cyan]")


# ── STATUS ────────────────────────────────────────────────────────────────────

@cli.command()
def status():
    """Show full Glitchicons environment status."""
    import sys

    console.print(f"\n[bold purple]⬡ GLITCHICONS STATUS[/bold purple] "
                  f"[dim]v0.4.0-dev[/dim]\n")

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Component", style="dim", width=16)
    table.add_column("Status", width=22)
    table.add_column("Detail", style="dim")

    # System tools
    for name, cmd, fix in [
        ("AFL++",    "afl-fuzz",  "sudo apt install afl++"),
        ("GDB",      "gdb",       "sudo apt install gdb"),
        ("Valgrind", "valgrind",  "sudo apt install valgrind"),
        ("gcov",     "gcov",      "sudo apt install gcov"),
        ("Ollama",   "ollama",    "curl -fsSL https://ollama.com/install.sh | sh"),
    ]:
        found = shutil.which(cmd)
        table.add_row(
            name,
            "[green]✓ available[/green]" if found else "[red]✗ not found[/red]",
            found or fix
        )

    table.add_row("Python", "[green]✓ available[/green]", sys.version.split()[0])

    # Ollama models
    if shutil.which("ollama"):
        try:
            import ollama as ol
            names = [m.model for m in ol.list().models]
            table.add_row(
                "LLM Models",
                "[green]✓ loaded[/green]" if names else "[yellow]⚠ none[/yellow]",
                ", ".join(names) if names else "ollama pull qwen2.5-coder:3b"
            )
        except Exception:
            table.add_row("LLM Models", "[yellow]⚠ not running[/yellow]",
                          "sudo systemctl start ollama")

    # Python packages
    for pkg, fix in [
        ("requests", "pip install requests"),
        ("ollama",   "pip install ollama"),
    ]:
        try:
            mod = __import__(pkg)
            ver = getattr(mod, "__version__", "ok")
            table.add_row(pkg, "[green]✓ available[/green]", ver)
        except ImportError:
            table.add_row(pkg, "[red]✗ not found[/red]", fix)

    # Brain memory
    try:
        from glitchicons_brain import GlitchiconsBrain
        b = GlitchiconsBrain()
        s = b.stats()
        table.add_row(
            "Brain Memory",
            "[green]✓ active[/green]",
            f"{s['total_sessions']} sessions · "
            f"{s['target_types_learned']} targets learned"
        )
    except Exception:
        table.add_row("Brain Memory", "[yellow]⚠ not loaded[/yellow]", "")

    console.print(table)
    console.print()


if __name__ == "__main__":
    cli()


# ── RL AGENT ──────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--corpus", "-c", type=click.Path(), default="./corpus")
@click.option("--output", "-o", type=click.Path(), default="./findings")
@click.option("--interval", "-i", type=int, default=60,
              help="Seconds per strategy interval (default: 60)")
@click.option("--duration", "-d", type=int, default=3600,
              help="Total fuzzing duration in seconds (default: 3600)")
@click.option("--model", "-m", type=str, default="qwen2.5-coder:3b")
@click.option("--stats", is_flag=True, default=False,
              help="Show agent stats only, do not fuzz")
def siege(target, corpus, output, interval, duration, model, stats):
    """
    Launch RL-guided adaptive fuzzing siege against TARGET.

    The RL agent learns which mutation strategies yield the most
    coverage for this specific target — getting smarter over time.

    Examples:

        glitchicons siege ./binary

        glitchicons siege ./binary --interval 120 --duration 7200

        glitchicons siege ./binary --stats
    """
    from rl_agent import RLFuzzingOrchestrator, QLearningAgent

    if stats:
        agent = QLearningAgent()
        agent.print_stats()
        return

    orchestrator = RLFuzzingOrchestrator(
        target_binary=target,
        corpus_dir=corpus,
        output_dir=output,
        interval_seconds=interval,
        total_duration=duration,
        model=model,
    )
    summary = orchestrator.run()

    if summary:
        console.print(f"\n[bold]Session Summary:[/bold]")
        for k, v in summary.items():
            console.print(f"  [dim]{k}:[/dim] {v}")


# ── CODE MAPPER ───────────────────────────────────────────────────────────────

@cli.command(name="map")
@click.argument("source", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(),
              default="./cfg_reports",
              help="Output directory for CFG report")
@click.option("--model", "-m", type=str, default="qwen2.5-coder:3b")
@click.option("--seed", "gen_seeds", is_flag=True, default=False,
              help="Auto-generate targeted seeds after analysis")
def map_cmd(source, output, model, gen_seeds):
    """
    Build CFG from SOURCE and identify high-value attack paths.

    Parses source code → Control Flow Graph → attack scores →
    interactive HTML visualization → seed generation hints.

    Requirements: pip install networkx

    Examples:

        glitchicons map ./target.c

        glitchicons map ./target.c --seed

        glitchicons map ./app.py --output ./my_cfg
    """
    try:
        from code_mapper import CodeMapper
    except ImportError as e:
        console.print(f"[red]✗ {e}[/red]")
        console.print("[dim]  pip install networkx[/dim]")
        return

    mapper = CodeMapper(output_dir=output, model=model)
    results = mapper.analyze(source)

    if not results:
        return

    # Auto-generate seeds if requested
    if gen_seeds and results.get("seed_hints"):
        console.print("\n[purple]⬡ Generating targeted seeds from CFG analysis...[/purple]")
        from seed_generator import SeedGenerator

        gen = SeedGenerator(model=model, output_dir="./corpus", seed_count=15)

        # Use the source file directly for AST-guided seed gen
        gen.from_source(source)
        console.print(f"[green]⬡ Seeds generated in ./corpus[/green]")
