#!/usr/bin/env python3
"""
GLITCHICONS ⬡
Decepticons Siege Division — AI-Powered Security Research Platform
v0.3.0-dev
"""

import shutil
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


@click.group()
@click.version_option(version="0.3.0-dev", prog_name="glitchicons")
def cli():
    """
    GLITCHICONS ⬡ — AI-Powered Security Research Platform

    Decepticons Siege Division | MIT License

    Where others probe, we siege. Where others test, we break.
    """
    pass


@cli.command()
@click.option("--source", "-s", type=click.Path(), default=None)
@click.option("--type", "-t", "input_type",
              type=click.Choice(["json","xml","http","binary","csv","sql","html","yaml","protobuf"]),
              default=None)
@click.option("--output", "-o", type=click.Path(), default="./corpus")
@click.option("--count", "-n", type=int, default=20)
@click.option("--model", "-m", type=str, default="qwen2.5-coder:3b")
def seed(source, input_type, output, count, model):
    """Generate LLM-powered mutation seeds for AFL++ fuzzing."""
    from seed_generator import SeedGenerator
    if not source and not input_type:
        console.print("[red]✗ Provide --source or --type[/red]")
        raise click.Abort()
    gen = SeedGenerator(model=model, output_dir=output, seed_count=count)
    saved = gen.from_source(source) if source else gen.from_type(input_type)
    if saved:
        console.print(f"\n[bold green]⬡ {len(saved)} seeds ready in {output}[/bold green]")


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

        glitchicons fuzz ./binary --corpus ./my_corpus
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
        f"[dim]Output :[/dim] {output}",
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

    cmd = ["afl-fuzz", "-i", str(corpus_path), "-o", str(output_path), "--", target, "@@"]
    console.print(f"\n[bold purple]⬡ LAUNCHING AFL++ SIEGE...[/bold purple]")
    console.print(f"[dim]{' '.join(cmd)}[/dim]\n")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        console.print("\n[yellow]⬡ Siege interrupted.[/yellow]")


@cli.command()
@click.argument("target_url")
@click.option("--endpoints", "-e", multiple=True,
              help="Endpoints to fuzz (repeatable)")
@click.option("--output", "-o", type=click.Path(), default="./protocol_findings")
@click.option("--model", "-m", type=str, default="qwen2.5-coder:3b")
@click.option("--delay", "-d", type=float, default=0.5,
              help="Delay between requests (default: 0.5s)")
@click.option("--token", type=str, default=None,
              help="Bearer auth token")
@click.option("--no-paths", is_flag=True, default=False)
@click.option("--no-headers", is_flag=True, default=False)
@click.option("--post", is_flag=True, default=False,
              help="Enable POST body fuzzing")
def protocol(target_url, endpoints, output, model, delay, token, no_paths, no_headers, post):
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


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.argument("crash_dir", type=click.Path(exists=True))
@click.option("--output", "-o", default="./reports")
@click.option("--model", "-m", default="qwen2.5-coder:3b")
@click.option("--max", "max_crashes", type=int, default=10)
def triage(target, crash_dir, output, model, max_crashes):
    """
    Triage AFL++ crashes via GDB + LLM.

    Examples:

        glitchicons triage ./binary ./findings/default/crashes

        glitchicons triage ./binary ./crashes --max 20
    """
    from crash_triage import CrashTriage
    try:
        t = CrashTriage(target_binary=target, crash_dir=crash_dir,
                        output_dir=output, model=model)
        reports = t.run(max_crashes=max_crashes)
        if reports:
            console.print(f"\n[green]⬡ {len(reports)} reports in {output}[/green]")
    except FileNotFoundError as e:
        console.print(f"[red]✗ {e}[/red]")


@cli.command()
def status():
    """Show Glitchicons environment status."""
    import sys
    console.print(f"\n[bold purple]⬡ GLITCHICONS STATUS[/bold purple] [dim]v0.3.0-dev[/dim]\n")

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Component", style="dim", width=16)
    table.add_column("Status", width=22)
    table.add_column("Detail", style="dim")

    for name, cmd, fix in [
        ("AFL++",    "afl-fuzz", "sudo apt install afl++"),
        ("GDB",      "gdb",      "sudo apt install gdb"),
        ("Valgrind", "valgrind", "sudo apt install valgrind"),
        ("Ollama",   "ollama",   "curl -fsSL https://ollama.com/install.sh | sh"),
    ]:
        found = shutil.which(cmd)
        table.add_row(name,
            "[green]✓ available[/green]" if found else "[red]✗ not found[/red]",
            found or fix)

    table.add_row("Python", "[green]✓ available[/green]", sys.version.split()[0])

    if shutil.which("ollama"):
        try:
            import ollama as ol
            names = [m.model for m in ol.list().models]
            table.add_row("LLM Models",
                "[green]✓ loaded[/green]" if names else "[yellow]⚠ none[/yellow]",
                ", ".join(names) if names else "ollama pull qwen2.5-coder:3b")
        except Exception:
            table.add_row("LLM Models", "[yellow]⚠ not running[/yellow]",
                          "sudo systemctl start ollama")

    try:
        import requests
        table.add_row("requests", "[green]✓ available[/green]", requests.__version__)
    except ImportError:
        table.add_row("requests", "[red]✗ not found[/red]", "pip install requests")

    console.print(table)
    console.print()


if __name__ == "__main__":
    cli()
