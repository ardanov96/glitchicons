#!/usr/bin/env python3
"""
GLITCHICONS ⬡
Decepticons Siege Division — AI-Powered Fuzzing Intelligence

Where others probe, we siege.
Where others test, we break.
"""

import click
from rich.console import Console
from rich.text import Text

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
@click.version_option(version="0.1.0-dev", prog_name="glitchicons")
def cli():
    """
    GLITCHICONS — AI-Powered Fuzzing Intelligence
    
    Decepticons Siege Division | MIT License
    """
    pass


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--mode", "-m",
              type=click.Choice(["ai", "basic", "protocol"]),
              default="basic",
              help="Fuzzing mode: ai (LLM-guided), basic (AFL++), protocol (network)")
@click.option("--output", "-o",
              type=click.Path(),
              default="./findings",
              help="Output directory for crashes and reports")
@click.option("--llm",
              type=click.Choice(["ollama", "claude", "openai"]),
              default="ollama",
              help="LLM backend for AI mode (default: ollama)")
@click.option("--timeout", "-t",
              type=int,
              default=3600,
              help="Fuzzing timeout in seconds (default: 3600)")
def fuzz(target, mode, output, llm, timeout):
    """
    Launch fuzzing siege against TARGET binary or source directory.
    
    Examples:
    
        glitchicons fuzz ./binary --mode ai
        
        glitchicons fuzz ./src --mode basic --timeout 7200
        
        glitchicons fuzz ./binary --mode ai --llm claude
    """
    console.print(f"\n[bold magenta]{BANNER}[/bold magenta]")
    console.print(f"[bold purple]⬡ GLITCHICONS SIEGE CORE[/bold purple] [dim]v0.1.0-dev[/dim]\n")
    console.print(f"[red]⚠  This is an early development build. Core modules not yet implemented.[/red]\n")
    
    console.print(f"[bold]Target  :[/bold] [cyan]{target}[/cyan]")
    console.print(f"[bold]Mode    :[/bold] [cyan]{mode}[/cyan]")
    console.print(f"[bold]LLM     :[/bold] [cyan]{llm}[/cyan]")
    console.print(f"[bold]Output  :[/bold] [cyan]{output}[/cyan]")
    console.print(f"[bold]Timeout :[/bold] [cyan]{timeout}s[/cyan]\n")
    
    console.print("[yellow]→ Core fuzzing engine under development.[/yellow]")
    console.print("[dim]  Track progress: https://github.com/ardanov96/glitchicons[/dim]\n")


@cli.command()
@click.argument("crash_dir", type=click.Path(exists=True))
@click.option("--output", "-o", default="./report.md", help="Output report path")
def report(crash_dir, output):
    """
    Generate vulnerability report from CRASH_DIR findings.
    """
    console.print(f"[bold purple]⬡ GLITCHICONS REPORT GENERATOR[/bold purple]\n")
    console.print(f"[bold]Crash dir :[/bold] [cyan]{crash_dir}[/cyan]")
    console.print(f"[bold]Output    :[/bold] [cyan]{output}[/cyan]\n")
    console.print("[yellow]→ Report generator under development.[/yellow]")


@cli.command()
def status():
    """
    Show Glitchicons system status and LLM backend availability.
    """
    console.print(f"[bold purple]⬡ GLITCHICONS STATUS[/bold purple]\n")

    checks = [
        ("AFL++",    _check_binary("afl-fuzz")),
        ("Ollama",   _check_binary("ollama")),
        ("Python",   True),
        ("Rich CLI", True),
    ]
    
    for name, ok in checks:
        status_str = "[green]✓ available[/green]" if ok else "[red]✗ not found[/red]"
        console.print(f"  {name:<12} {status_str}")
    
    console.print()


def _check_binary(name: str) -> bool:
    import shutil
    return shutil.which(name) is not None


if __name__ == "__main__":
    cli()
