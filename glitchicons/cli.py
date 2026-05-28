"""
glitchicons/cli.py — Main CLI entry point.

After `pip install glitchicons`, the `glitchicons` command maps here.
All sub-commands are registered via Click groups.

Usage (after install):
    glitchicons status
    glitchicons cors https://target.com
    glitchicons graphql https://target.com/graphql
    glitchicons openapi --spec api.yaml --base-url https://api.target.com
    glitchicons siege --config engagement.yaml
    glitchicons plugins list
    glitchicons version
"""

import sys
import click
from rich.console import Console
from rich.table import Table

console = Console()

ASCII_BANNER = r"""
  ____   _       _  _             _
 / ___| | |  ___| || |_  ___  | |
| |  _  | | / _ \ || __|/ __| | '_ \
| |_| | | ||  __/ || |_| (__  | | | |
 \____| |_| \___|_| \__|\___| |_| |_|
"""


@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx):
    """GLITCHICONS — AI-Powered Security Research Platform."""
    if ctx.invoked_subcommand is None:
        console.print(f"[bold cyan]{ASCII_BANNER}[/bold cyan]")
        console.print(f"  Version  : [yellow]1.0.0[/yellow]")
        console.print(f"  GitHub   : https://github.com/ardanov96/glitchicons\n")
        console.print("  Run [cyan]glitchicons --help[/cyan] to see all commands.\n")


@main.command()
def version():
    """Show version information."""
    from glitchicons import __version__, __author__, __url__
    console.print(f"glitchicons [bold cyan]{__version__}[/bold cyan]")
    console.print(f"Author : {__author__}")
    console.print(f"URL    : {__url__}")


@main.command()
def status():
    """Check tool dependencies and environment."""
    table = Table(show_header=True, header_style="bold magenta", title="Environment Status")
    table.add_column("Component",  style="cyan", width=20)
    table.add_column("Status",     width=10)
    table.add_column("Detail")

    checks = _run_status_checks()
    for name, ok, detail in checks:
        status_str = "[green]OK[/green]" if ok else "[red]MISSING[/red]"
        table.add_row(name, status_str, detail)

    console.print(table)


def _run_status_checks() -> list[tuple]:
    import importlib, shutil
    results = []

    # Python packages
    for pkg, display in [
        ("httpx",      "httpx"),
        ("click",      "click"),
        ("rich",       "rich"),
        ("yaml",       "pyyaml"),
        ("dns",        "dnspython"),
        ("grpc",       "grpcio"),
        ("websocket",  "websocket-client"),
        ("pydantic",   "pydantic"),
    ]:
        try:
            mod = importlib.import_module(pkg)
            ver = getattr(mod, "__version__", "?")
            results.append((display, True, f"v{ver}"))
        except ImportError:
            results.append((display, False, "pip install " + display))

    # CLI tools
    import shutil
    for tool in ["subfinder", "httpx", "nuclei", "katana", "afl-fuzz"]:
        path = shutil.which(tool)
        results.append((tool, bool(path), path or "not in PATH"))

    # Ollama
    try:
        import httpx as hx
        r = hx.get("http://localhost:11434/api/tags", timeout=2)
        models = [m["name"] for m in r.json().get("models", [])][:3]
        results.append(("ollama", True, f"models: {models or 'none pulled'}"))
    except Exception:
        results.append(("ollama", False, "not running — start with: ollama serve"))

    return results


# ── Web offensive commands ────────────────────────────────

@main.command()
@click.argument("target")
@click.option("--output", "-o", default="./findings/graphql", help="Output directory")
@click.option("--introspect/--no-introspect", default=True, help="Run introspection")
@click.option("--dos-test", is_flag=True, help="Enable DoS tests (aggressive)")
@click.option("--token", "-t", help="Authorization Bearer token")
def graphql(target, output, introspect, dos_test, token):
    """Fuzz a GraphQL endpoint."""
    from modules.inject.graphql_fuzzer import GraphQLFuzzer
    fuzzer = GraphQLFuzzer(target=target, output_dir=output, token=token)
    findings = fuzzer.run(introspect=introspect, dos_test=dos_test)
    console.print(f"\n  [bold]Total findings:[/bold] {len(findings)}")


@main.command()
@click.argument("target")
@click.option("--output", "-o", default="./findings/websocket")
@click.option("--token", "-t", help="Authorization Bearer token")
@click.option("--dos-test", is_flag=True)
def websocket(target, output, token, dos_test):
    """Fuzz a WebSocket endpoint."""
    from modules.inject.websocket_fuzzer import WebSocketFuzzer
    fuzzer = WebSocketFuzzer(target=target, output_dir=output, token=token)
    findings = fuzzer.run(dos_test=dos_test)
    console.print(f"\n  [bold]Total findings:[/bold] {len(findings)}")


@main.command()
@click.argument("target")
@click.option("--output", "-o", default="./findings/cors")
@click.option("--token", "-t", help="Authorization Bearer token")
def cors(target, output, token):
    """Check CORS misconfiguration."""
    from modules.inject.cors_checker import CORSChecker
    checker = CORSChecker(target=target, output_dir=output, token=token)
    findings = checker.run()
    console.print(f"\n  [bold]Total findings:[/bold] {len(findings)}")


@main.command()
@click.option("--target", "-t", required=True, help="gRPC target (host:port)")
@click.option("--output", "-o", default="./findings/grpc")
@click.option("--insecure", is_flag=True, help="Disable TLS")
@click.option("--token", help="Authorization Bearer token")
@click.option("--dos-test", is_flag=True)
def grpc(target, output, insecure, token, dos_test):
    """Fuzz a gRPC endpoint."""
    from modules.inject.grpc_fuzzer import GRPCFuzzer
    fuzzer = GRPCFuzzer(target=target, output_dir=output,
                        token=token, insecure=insecure)
    findings = fuzzer.run(dos_test=dos_test)
    console.print(f"\n  [bold]Total findings:[/bold] {len(findings)}")


@main.command()
@click.option("--spec",     help="Path to OpenAPI/Swagger spec file")
@click.option("--url",      help="URL to fetch spec from")
@click.option("--base-url", help="Override base URL from spec")
@click.option("--output", "-o", default="./findings/openapi")
@click.option("--token", "-t", help="Authorization Bearer token")
def openapi(spec, url, base_url, output, token):
    """Parse OpenAPI/Swagger spec and generate attack plan."""
    from modules.recon.openapi_parser import OpenAPIParser
    if not spec and not url:
        console.print("[red]Error: --spec or --url required[/red]")
        sys.exit(1)
    parser = OpenAPIParser(base_url=base_url or "", output_dir=output, token=token)
    plan = parser.parse_file(spec) if spec else parser.fetch_and_parse(url)
    parser.print_plan(plan)
    parser.save_plan(plan)


@main.command()
@click.option("--domain", "-d", required=True, help="Target domain")
@click.option("--wordlist", "-w", help="Custom subdomain wordlist file")
@click.option("--output", "-o", default="./findings/takeover")
@click.option("--passive", is_flag=True, help="Passive mode only")
def takeover(domain, wordlist, output, passive):
    """Check subdomains for takeover vulnerabilities."""
    from modules.recon.subdomain_takeover import SubdomainTakeoverChecker
    wl = None
    if wordlist:
        from pathlib import Path
        wl = Path(wordlist).read_text().splitlines()
    checker = SubdomainTakeoverChecker(
        domain=domain, output_dir=output,
        wordlist=wl, passive=passive,
    )
    findings = checker.run()
    console.print(f"\n  [bold]Total findings:[/bold] {len(findings)}")


@main.command()
@click.option("--target", "-t", required=True, help="MFA endpoint URL")
@click.option("--session", "-s", default="", help="Session token/ID")
@click.option("--token", help="Bearer token")
@click.option("--otp-field", default="otp", help="OTP field name")
@click.option("--output", "-o", default="./findings/mfa")
@click.option("--brute", is_flag=True, help="Full OTP brute force (slow)")
def mfa(target, session, token, otp_field, output, brute):
    """Test MFA/2FA bypass vulnerabilities."""
    from modules.auth.mfa_bypass import MFABypassTester
    tester = MFABypassTester(
        target=target, output_dir=output,
        session=session, token=token, otp_field=otp_field,
    )
    findings = tester.run(brute_force=brute)
    console.print(f"\n  [bold]Total findings:[/bold] {len(findings)}")


# ── Intelligence commands ─────────────────────────────────

@main.command()
@click.option("--url", "-u", required=True, help="Target URL")
@click.option("--param", "-p", required=True, help="Parameter to inject")
@click.option("--payload", required=True, help="Base payload")
@click.option("--type", "attack_type", default="sqli",
              type=click.Choice(["sqli", "xss", "ssti", "ssrf", "generic"]))
@click.option("--rounds", default=5, help="Max mutation rounds")
@click.option("--provider", default="ollama",
              type=click.Choice(["ollama", "anthropic", "openai"]))
@click.option("--output", "-o", default="./findings/mutations")
def mutate(url, param, payload, attack_type, rounds, provider, output):
    """Adaptive LLM payload mutation loop."""
    from modules.intelligence.llm_mutator import LLMMutator
    mutator = LLMMutator(provider=provider, output_dir=output)
    result = mutator.mutate_and_test(
        target_url=url, param=param,
        base_payload=payload, attack_type=attack_type,
        max_rounds=rounds,
    )
    if result.success:
        console.print(f"\n  [green]SUCCESS:[/green] {result.successful_payload}")
    else:
        console.print(f"\n  [yellow]No bypass found after {rounds} rounds[/yellow]")


@main.command()
@click.option("--input", "-i", required=True, help="JSON findings file to verify")
@click.option("--threshold", default=0.35, help="Confidence threshold (0.0-1.0)")
@click.option("--provider", default="ollama")
@click.option("--reprobe", is_flag=True, help="Re-probe live target to confirm")
@click.option("--output", "-o", default="./findings/verified")
def verify(input, threshold, provider, reprobe, output):
    """Reduce false positives via LLM verification."""
    import json
    from pathlib import Path
    from modules.intelligence.fp_reducer import FalsePositiveReducer
    findings = json.loads(Path(input).read_text(encoding="utf-8"))
    if isinstance(findings, dict) and "findings" in findings:
        findings = findings["findings"]
    reducer = FalsePositiveReducer(
        provider=provider, output_dir=output,
        confidence_threshold=threshold, reprobe=reprobe,
    )
    verified = reducer.verify_all(findings)
    real = sum(1 for f in verified if f.get("verdict") in ("CONFIRMED", "LIKELY"))
    console.print(f"\n  Actionable: [green]{real}[/green] / {len(verified)}")


@main.command()
@click.option("--input", "-i", required=True, help="JSON findings file")
@click.option("--provider", default="ollama")
@click.option("--rescore", is_flag=True, help="Allow LLM to challenge CVSS score")
@click.option("--output", "-o", default="./findings/reasoned")
def explain(input, provider, rescore, output):
    """Enrich findings with CVSS breakdown + narrative + executive summary."""
    import json
    from pathlib import Path
    from modules.intelligence.severity_reasoner import SeverityReasoner
    findings = json.loads(Path(input).read_text(encoding="utf-8"))
    if isinstance(findings, dict) and "findings" in findings:
        findings = findings["findings"]
    reasoner = SeverityReasoner(provider=provider, output_dir=output, rescore=rescore)
    enriched = reasoner.enrich_all(findings)
    console.print(f"\n  Enriched: [green]{len(enriched)}[/green] findings")


@main.command()
@click.argument("payload")
@click.option("--type", "attack_type", default="sqli",
              type=click.Choice(["sqli", "xss", "ssti", "ssrf", "generic"]))
@click.option("--waf", default="Generic", help="WAF type (Cloudflare, ModSecurity, etc.)")
@click.option("--list", "list_techniques", is_flag=True, help="List all techniques")
@click.option("--wordlist", "-w", help="Save variants to wordlist file")
@click.option("--max", "max_variants", default=20)
def evade(payload, attack_type, waf, list_techniques, wordlist, max_variants):
    """Generate WAF evasion variants of a payload."""
    from modules.intelligence.waf_evasion import WAFEvasionEngine
    engine = WAFEvasionEngine()

    if list_techniques:
        techniques = engine.describe_techniques(attack_type)
        for t in techniques:
            console.print(
                f"  [cyan]{t['name']:<20}[/cyan] {t['description']:<40} "
                f"rate: {t['bypass_rate']:.0%}"
            )
        return

    variants = engine.smart_bypass(payload, waf_type=waf,
                                   attack_type=attack_type, max_variants=max_variants)
    for v in variants:
        console.print(f"  [{v.technique}] {v.encoded}")

    if wordlist:
        engine.generate_wordlist([payload], attack_type=attack_type, output_file=wordlist)


# ── Config / Siege commands ───────────────────────────────

@main.group()
def config():
    """Manage engagement configuration files."""
    pass


@config.command("init")
@click.option("--domain", "-d", required=True, help="Target domain")
@click.option("--output", "-o", default="engagement.yaml", help="Output file")
def config_init(domain, output):
    """Create a new engagement config file."""
    from modules.config.config_loader import ConfigLoader
    path = ConfigLoader.create_template(output, domain=domain)
    console.print(f"  [green]Created:[/green] {path}")
    console.print(f"  Edit the file then run: glitchicons siege --config {output}")


@config.command("validate")
@click.argument("config_file")
def config_validate(config_file):
    """Validate an engagement config file."""
    from modules.config.config_loader import ConfigLoader, ConfigValidationError
    try:
        cfg = ConfigLoader.load(config_file)
        console.print(f"  [green]Valid config[/green]")
        console.print(f"  Target   : {cfg.target.domain}")
        console.print(f"  Modules  : {cfg.enabled_modules()}")
    except ConfigValidationError as e:
        console.print(f"  [red]Invalid config:[/red] {e}")
        sys.exit(1)


@main.command()
@click.option("--config", "-c", required=True, help="Engagement config YAML file")
def siege(config):
    """Run full engagement from config file."""
    from modules.config.config_loader import ConfigLoader
    from modules.config.siege_runner  import SiegeRunner
    cfg = ConfigLoader.load(config)
    runner = SiegeRunner(cfg)
    findings = runner.run()
    console.print(f"\n  [bold]Total findings:[/bold] {len(findings)}")


# ── Plugin commands ───────────────────────────────────────

@main.group()
def plugins():
    """Manage Glitchicons plugins."""
    pass


@plugins.command("list")
def plugins_list():
    """List installed plugins."""
    from glitchicons.plugin_system import PluginRegistry
    registry = PluginRegistry()
    installed = registry.discover()
    if not installed:
        console.print("  No plugins installed.")
        console.print("  Install with: pip install glitchicons-<name>")
        return
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Plugin", style="cyan")
    table.add_column("Version", width=10)
    table.add_column("Description")
    for plugin in installed:
        table.add_row(plugin.name, plugin.version, plugin.description)
    console.print(table)


if __name__ == "__main__":
    main()
