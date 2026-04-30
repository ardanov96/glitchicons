#!/usr/bin/env python3
"""
GLITCHICONS ⬡
Decepticons Siege Division — AI-Powered Fuzzing Intelligence

Where others probe, we siege.
Where others test, we break.
"""

import shutil
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

BANNER = """
 ██████╗ ██╗     ██╗████████╗ ██████╗██╗  ██╗██╗ ██████╗ ██████╗ ███╗  ██╗███████╗
██╔════╝ ██║     ██║╚══██╔══╝██╔════╝██║  ██║██║██╔════╝██╔═══██╗████╗ ██║██╔════╝
██║  ███╗██║     ██║   ██║   ██║     ███████║██║██║     ██║   ██║██╔██╗██║███████╗
██║   ██║██║     ██║   ██║   ██║     ██╔══██║██║██║     ██║   ██║██║╚████║╚════██║
╚██████╔╝███████╗██║   ██║   ╚██████╗██║  ██║██║╚██████╗╚██████╔╝██║ ╚███║███████║
 ╚═════╝ ╚══════╝╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚══╝╚══════╝
"""


@click.group()
@click.version_option(version="0.2.0-dev", prog_name="glitchicons")
def cli():
    """
    GLITCHICONS ⬡ — AI-Powered Fuzzing Intelligence

    Decepticons Siege Division | MIT License

    Where others probe, we siege. Where others test, we break.
    """
    pass


# ── SEED COMMAND ─────────────────────────────────────────────────────────────

@cli.command()
@click.option("--source", "-s",
              type=click.Path(),
              default=None,
              help="Path to source code file to analyze")
@click.option("--type", "-t", "input_type",
              type=click.Choice([
                  "json", "xml", "http", "binary",
                  "csv", "sql", "html", "yaml", "protobuf"
              ]),
              default=None,
              help="Input type to generate seeds for")
@click.option("--output", "-o",
              type=click.Path(),
              default="./corpus",
              help="Output directory for seed files (default: ./corpus)")
@click.option("--count", "-n",
              type=int,
              default=20,
              help="Number of seeds to generate (default: 20)")
@click.option("--model", "-m",
              type=str,
              default="qwen2.5-coder:3b",
              help="Ollama model to use (default: qwen2.5-coder:3b)")
def seed(source, input_type, output, count, model):
    """
    Generate LLM-powered mutation seeds for AFL++ fuzzing.

    Examples:

        glitchicons seed --type json --count 30

        glitchicons seed --source ./target.c --output ./my_corpus

        glitchicons seed --type http --model qwen2.5-coder:7b
    """
    from seed_generator import SeedGenerator

    if not source and not input_type:
        console.print("[red]✗ Provide either --source or --type[/red]")
        console.print("[dim]  Example: glitchicons seed --type json[/dim]")
        console.print("[dim]  Example: glitchicons seed --source ./target.c[/dim]")
        raise click.Abort()

    gen = SeedGenerator(model=model, output_dir=output, seed_count=count)

    if source:
        saved = gen.from_source(source)
    else:
        saved = gen.from_type(input_type)

    if saved:
        console.print(f"\n[bold green]⬡ SIEGE SEEDS READY — {len(saved)} files in {output}[/bold green]")
    else:
        console.print("\n[red]⬡ SEED GENERATION FAILED — check Ollama status[/red]")


# ── FUZZ COMMAND ─────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--mode", "-m",
              type=click.Choice(["ai", "basic", "protocol"]),
              default="basic",
              help="Fuzzing mode")
@click.option("--corpus", "-c",
              type=click.Path(),
              default="./corpus",
              help="Corpus directory (default: ./corpus)")
@click.option("--output", "-o",
              type=click.Path(),
              default="./findings",
              help="Output directory for crashes (default: ./findings)")
@click.option("--timeout", "-t",
              type=int,
              default=3600,
              help="Timeout in seconds (default: 3600)")
def fuzz(target, mode, corpus, output, timeout):
    """
    Launch fuzzing siege against TARGET binary.

    Examples:

        glitchicons fuzz ./target_binary

        glitchicons fuzz ./target --mode ai --corpus ./my_corpus

        glitchicons fuzz ./target --timeout 7200
    """
    console.print(f"\n[bold magenta]{BANNER}[/bold magenta]")
    console.print(Panel(
        f"[bold purple]⬡ GLITCHICONS SIEGE CORE[/bold purple] [dim]v0.2.0-dev[/dim]\n\n"
        f"[dim]Target :[/dim] {target}\n"
        f"[dim]Mode   :[/dim] {mode}\n"
        f"[dim]Corpus :[/dim] {corpus}\n"
        f"[dim]Output :[/dim] {output}\n"
        f"[dim]Timeout:[/dim] {timeout}s",
        border_style="purple"
    ))

    import subprocess
    from pathlib import Path

    corpus_path = Path(corpus)
    output_path = Path(output)

    if not corpus_path.exists() or not list(corpus_path.iterdir()):
        console.print(f"[yellow]⚠ Corpus directory empty or missing: {corpus}[/yellow]")
        console.print("[dim]  Run 'glitchicons seed' first to generate seeds.[/dim]")

        if click.confirm("Generate seeds automatically before fuzzing?"):
            console.print("\n[purple]→ Generating seeds...[/purple]")
            from seed_generator import SeedGenerator
            gen = SeedGenerator(output_dir=corpus, seed_count=20)
            gen.from_type("binary")

    output_path.mkdir(parents=True, exist_ok=True)

    if not shutil.which("afl-fuzz"):
        console.print("[red]✗ afl-fuzz not found in PATH[/red]")
        console.print("[dim]  Install: sudo apt install afl++[/dim]")
        return

    console.print("\n[bold purple]⬡ LAUNCHING AFL++ SIEGE...[/bold purple]\n")

    cmd = [
        "afl-fuzz",
        "-i", str(corpus_path),
        "-o", str(output_path),
        "-t", str(min(timeout * 1000, 5000)),  # AFL uses ms per-exec
        "--",
        target,
        "@@"
    ]

    console.print(f"[dim]Command: {' '.join(cmd)}[/dim]\n")

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        console.print("\n[yellow]⬡ Siege interrupted by operator.[/yellow]")
    except Exception as e:
        console.print(f"\n[red]✗ AFL++ error: {e}[/red]")


# ── STATUS COMMAND ────────────────────────────────────────────────────────────

@cli.command()
def status():
    """
    Show Glitchicons system status and component availability.
    """
    console.print(f"\n[bold purple]⬡ GLITCHICONS STATUS[/bold purple] [dim]v0.2.0-dev[/dim]\n")

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Component", style="dim", width=16)
    table.add_column("Status", width=20)
    table.add_column("Detail", style="dim")

    # AFL++
    afl = shutil.which("afl-fuzz")
    table.add_row(
        "AFL++",
        "[green]✓ available[/green]" if afl else "[red]✗ not found[/red]",
        afl or "sudo apt install afl++"
    )

    # Ollama
    ol = shutil.which("ollama")
    table.add_row(
        "Ollama",
        "[green]✓ available[/green]" if ol else "[red]✗ not found[/red]",
        ol or "curl -fsSL https://ollama.com/install.sh | sh"
    )

    # Check available models
    if ol:
        try:
            import ollama as ol_lib
            models = ol_lib.list()
            model_names = [m.model for m in models.models]
            table.add_row(
                "Models",
                "[green]✓ loaded[/green]" if model_names else "[yellow]⚠ none[/yellow]",
                ", ".join(model_names) if model_names else "ollama pull qwen2.5-coder:3b"
            )
        except Exception:
            table.add_row("Models", "[yellow]⚠ ollama not running[/yellow]",
                          "sudo systemctl start ollama")

    # Python
    import sys
    table.add_row("Python", "[green]✓ available[/green]",
                  f"{sys.version.split()[0]}")

    # GDB
    gdb = shutil.which("gdb")
    table.add_row(
        "GDB",
        "[green]✓ available[/green]" if gdb else "[red]✗ not found[/red]",
        gdb or "sudo apt install gdb"
    )

    # Valgrind
    vg = shutil.which("valgrind")
    table.add_row(
        "Valgrind",
        "[green]✓ available[/green]" if vg else "[red]✗ not found[/red]",
        vg or "sudo apt install valgrind"
    )

    console.print(table)
    console.print()


# ── REPORT COMMAND ────────────────────────────────────────────────────────────

@cli.command()
@click.argument("crash_dir", type=click.Path(exists=True))
@click.option("--output", "-o", default="./report.md",
              help="Output report path (default: ./report.md)")
@click.option("--model", "-m", default="qwen2.5-coder:3b",
              help="LLM model for analysis")
def report(crash_dir, output, model):
    """
    Generate vulnerability report from CRASH_DIR findings.
    """
    from pathlib import Path

    crash_path = Path(crash_dir)
    crashes = list(crash_path.glob("**/*")) if crash_path.exists() else []
    crash_files = [f for f in crashes if f.is_file()]

    console.print(Panel(
        f"[bold purple]⬡ CRASH TRIAGE[/bold purple]\n\n"
        f"[dim]Crash dir:[/dim] {crash_dir}\n"
        f"[dim]Files    :[/dim] {len(crash_files)}\n"
        f"[dim]Output   :[/dim] {output}\n"
        f"[dim]Model    :[/dim] {model}",
        border_style="purple"
    ))

    if not crash_files:
        console.print("[yellow]⚠ No crash files found.[/yellow]")
        return

    console.print(f"[yellow]→ Report generation under active development.[/yellow]")
    console.print(f"[dim]  Found {len(crash_files)} crash files to analyze.[/dim]")


if __name__ == "__main__":
    cli()
