"""
GLITCHICONS ⬡ — Nuclei Wrapper v1.0
Integrates nuclei scanner dengan Glitchicons reporting
"""

import subprocess
import json
import sys
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

NUCLEI_BIN       = Path.home() / "go/bin/nuclei"
NUCLEI_TEMPLATES = Path.home() / "nuclei-templates"

SCAN_PROFILES = {
    "quick": [
        "http/technologies/",
        "http/exposed-panels/",
        "ssl/",
        "dns/",
    ],
    "standard": [
        "http/technologies/",
        "http/exposed-panels/",
        "http/exposures/",
        "http/misconfiguration/",
        "ssl/",
        "dns/",
    ],
    "deep": [
        "http/",
        "ssl/",
        "dns/",
        "network/",
    ],
    "cves": [
        "http/cves/",
        "http/vulnerabilities/",
    ],
    "auth": [
        "http/default-logins/",
        "http/exposed-panels/",
        "http/misconfiguration/",
    ],
}

SEVERITY_COLORS = {
    "critical": "[bold red]CRITICAL[/bold red]",
    "high"    : "[red]HIGH[/red]",
    "medium"  : "[yellow]MEDIUM[/yellow]",
    "low"     : "[blue]LOW[/blue]",
    "info"    : "[dim]INFO[/dim]",
}


def scan(
    target,
    profile="standard",
    severity="low,medium,high,critical",
    output_dir=None,
    extra_templates=None,
    rate_limit=50,
    timeout=30
):
    """Run nuclei scan against target."""

    console.print(Panel(
        f"[bold purple]⬡ GLITCHICONS NUCLEI SCANNER[/bold purple]\n"
        f"[dim]Target  : {target}[/dim]\n"
        f"[dim]Profile : {profile}[/dim]\n"
        f"[dim]Severity: {severity}[/dim]",
        border_style="purple"
    ))

    # Build template list
    templates = SCAN_PROFILES.get(profile, SCAN_PROFILES["standard"])
    if extra_templates:
        templates.extend(extra_templates)

    template_args = " ".join([
        f"-t {NUCLEI_TEMPLATES}/{t}" for t in templates
    ])

    # Output file
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if output_dir:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        json_out = Path(output_dir) / f"nuclei_{ts}.json"
    else:
        json_out = Path(f"/tmp/nuclei_{ts}.json")

    cmd = (
        f"{NUCLEI_BIN} "
        f"-u {target} "
        f"{template_args} "
        f"-severity {severity} "
        f"-rate-limit {rate_limit} "
        f"-timeout {timeout} "
        f"-jsonl "
        f"-o {json_out} "
        f"-silent "
        f"2>/dev/null"
    )

    console.print(f"\n[dim]Running scan...[/dim]")

    try:
        subprocess.run(
            cmd, shell=True, timeout=600
        )
    except subprocess.TimeoutExpired:
        console.print("[yellow]Scan timed out[/yellow]")

    # Parse results
    findings = []
    if json_out.exists():
        for line in json_out.read_text().splitlines():
            try:
                findings.append(json.loads(line))
            except:
                continue

    # Display results
    if findings:
        table = Table(title=f"⬡ Nuclei Findings — {target}")
        table.add_column("Severity", style="bold")
        table.add_column("Template")
        table.add_column("Name")
        table.add_column("Matched")

        sev_order = ["critical", "high", "medium", "low", "info"]
        findings.sort(
            key=lambda x: sev_order.index(
                x.get("info", {}).get("severity", "info")
            )
        )

        for f in findings:
            info     = f.get("info", {})
            sev      = info.get("severity", "info")
            name     = info.get("name", "")
            template = f.get("template-id", "")
            matched  = f.get("matched-at", "")[:60]

            table.add_row(
                SEVERITY_COLORS.get(sev, sev),
                template,
                name,
                matched
            )

        console.print(table)
    else:
        console.print("[green]✅ No findings detected[/green]")

    # Summary
    sev_count = {}
    for f in findings:
        s = f.get("info", {}).get("severity", "info")
        sev_count[s] = sev_count.get(s, 0) + 1

    console.print(f"\n[bold]Summary:[/bold]")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in sev_count:
            console.print(
                f"  {SEVERITY_COLORS.get(sev, sev)}: "
                f"{sev_count[sev]}"
            )

    if output_dir:
        console.print(f"\n[dim]Raw output: {json_out}[/dim]")

    return findings


def scan_subdomains(
    domain,
    subdomains_file,
    profile="quick",
    severity="medium,high,critical",
    output_dir=None
):
    """Scan multiple subdomains from file."""
    console.print(Panel(
        f"[bold purple]⬡ SUBDOMAIN SCAN[/bold purple]\n"
        f"[dim]Domain: {domain}[/dim]",
        border_style="purple"
    ))

    subs = Path(subdomains_file).read_text().strip().splitlines()
    console.print(f"Scanning [bold]{len(subs)}[/bold] subdomains...")

    all_findings = []
    for sub in subs[:50]:  # Limit to 50 untuk safety
        if not sub.startswith("http"):
            sub = f"https://{sub}"
        findings = scan(
            sub, profile=profile,
            severity=severity,
            output_dir=output_dir
        )
        all_findings.extend(findings)

    return all_findings


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")

    target  = sys.argv[1] if len(sys.argv) > 1 else \
              "https://target.example.com"
    profile = sys.argv[2] if len(sys.argv) > 2 else "standard"

    scan(target, profile=profile)
