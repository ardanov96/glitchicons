"""
GLITCHICONS ⬡ — Recon Engine v1.0
Integrates: subfinder, httpx, nuclei, katana
Author: ARDATRON
"""

import subprocess
import json
import sys
import time
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

TOOLS = {
    "subfinder": "~/go/bin/subfinder",
    "httpx"    : "~/go/bin/httpx",
    "nuclei"   : "~/go/bin/nuclei",
    "katana"   : "~/go/bin/katana",
}

NUCLEI_TEMPLATES = Path.home() / "nuclei-templates"


def check_tools():
    """Verifikasi semua tools terinstall."""
    console.print(Panel(
        "[bold purple]⬡ GLITCHICONS RECON ENGINE[/bold purple]\n"
        "[dim]Checking required tools...[/dim]",
        border_style="purple"
    ))
    missing = []
    for name, path in TOOLS.items():
        full = Path(path).expanduser()
        if full.exists():
            console.print(f"  [green]✅ {name}[/green]")
        else:
            console.print(f"  [red]❌ {name} — NOT FOUND[/red]")
            missing.append(name)
    return missing


def run_cmd(cmd, timeout=120):
    """Run shell command dan return output."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return ""
    except Exception as e:
        return ""


def subdomain_enum(domain, output_dir):
    """Enumerate subdomains via subfinder."""
    console.print(f"\n[bold]→ Subdomain Enumeration[/bold]: {domain}")
    cmd = f"~/go/bin/subfinder -d {domain} -silent -o {output_dir}/subdomains.txt"
    run_cmd(cmd, timeout=120)

    subdomains = []
    out_file = Path(output_dir) / "subdomains.txt"
    if out_file.exists():
        subdomains = out_file.read_text().strip().splitlines()

    console.print(f"  Found: [bold green]{len(subdomains)}[/bold green] subdomains")
    return subdomains


def http_probe(subdomains, output_dir):
    """Probe HTTP status via httpx."""
    console.print(f"\n[bold]→ HTTP Probing[/bold]: {len(subdomains)} targets")

    input_file = Path(output_dir) / "subdomains.txt"
    out_file   = Path(output_dir) / "live_hosts.txt"
    json_file  = Path(output_dir) / "http_probe.json"

    cmd = (
        f"~/go/bin/httpx -l {input_file} "
        f"-silent -status-code -title -tech-detect -json "
        f"-o {json_file} "
        f"2>/dev/null"
    )
    run_cmd(cmd, timeout=180)

    live = []
    if json_file.exists():
        for line in json_file.read_text().splitlines():
            try:
                data = json.loads(line)
                live.append(data)
            except:
                continue

    # Save live hosts
    with open(out_file, "w") as f:
        for h in live:
            f.write(h.get("url", "") + "\n")

    console.print(f"  Live hosts: [bold green]{len(live)}[/bold green]")
    return live


def nuclei_scan(target, output_dir, severity="medium,high,critical"):
    """Run nuclei scan on target."""
    console.print(f"\n[bold]→ Nuclei Scan[/bold]: {target}")

    out_file  = Path(output_dir) / "nuclei_findings.txt"
    json_file = Path(output_dir) / "nuclei_findings.json"

    templates = [
        f"{NUCLEI_TEMPLATES}/http/technologies/",
        f"{NUCLEI_TEMPLATES}/http/exposed-panels/",
        f"{NUCLEI_TEMPLATES}/http/exposures/",
        f"{NUCLEI_TEMPLATES}/http/misconfiguration/",
        f"{NUCLEI_TEMPLATES}/dns/",
        f"{NUCLEI_TEMPLATES}/ssl/",
    ]

    template_args = " ".join([f"-t {t}" for t in templates])

    cmd = (
        f"~/go/bin/nuclei -u {target} "
        f"{template_args} "
        f"-severity {severity} "
        f"-silent "
        f"-jsonl -o {json_file} "
        f"2>/dev/null"
    )
    run_cmd(cmd, timeout=300)

    findings = []
    if json_file.exists():
        for line in json_file.read_text().splitlines():
            try:
                findings.append(json.loads(line))
            except:
                continue

    console.print(f"  Findings: [bold {'red' if findings else 'green'}]{len(findings)}[/bold {'red' if findings else 'green'}]")
    return findings


def dns_recon(domain, output_dir):
    """DNS reconnaissance via nuclei."""
    console.print(f"\n[bold]→ DNS Recon[/bold]: {domain}")

    json_file = Path(output_dir) / "dns_findings.json"
    cmd = (
        f"~/go/bin/nuclei -u {domain} "
        f"-t {NUCLEI_TEMPLATES}/dns/ "
        f"-silent -jsonl -o {json_file} "
        f"2>/dev/null"
    )
    run_cmd(cmd, timeout=120)

    findings = []
    if json_file.exists():
        for line in json_file.read_text().splitlines():
            try:
                findings.append(json.loads(line))
            except:
                continue

    return findings


def crawl_urls(target, output_dir, depth=2):
    """Crawl URLs via katana."""
    console.print(f"\n[bold]→ URL Crawling[/bold]: {target}")

    out_file = Path(output_dir) / "crawled_urls.txt"
    cmd = (
        f"~/go/bin/katana -u {target} "
        f"-depth {depth} -silent "
        f"-o {out_file} "
        f"2>/dev/null"
    )
    run_cmd(cmd, timeout=120)

    urls = []
    if out_file.exists():
        urls = out_file.read_text().strip().splitlines()

    console.print(f"  URLs found: [bold green]{len(urls)}[/bold green]")
    return urls


def generate_report(domain, subdomains, live_hosts,
                    nuclei_findings, dns_findings, urls, output_dir):
    """Generate markdown report."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = Path(output_dir) / f"recon_report_{ts}.md"

    # Severity counts
    sev_count = {}
    for f in nuclei_findings:
        s = f.get("info", {}).get("severity", "info")
        sev_count[s] = sev_count.get(s, 0) + 1

    lines = [
        f"# GLITCHICONS ⬡ — Recon Report",
        f"**Target:** {domain}",
        f"**Date:** {datetime.now().strftime('%d %B %Y %H:%M')}",
        f"**Generated by:** Glitchicons Recon Engine v1.0",
        "",
        "---",
        "",
        "## Summary",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Subdomains found | {len(subdomains)} |",
        f"| Live HTTP hosts | {len(live_hosts)} |",
        f"| Nuclei findings | {len(nuclei_findings)} |",
        f"| DNS findings | {len(dns_findings)} |",
        f"| URLs crawled | {len(urls)} |",
        "",
    ]

    # Severity breakdown
    if sev_count:
        lines += [
            "## Finding Severity Breakdown",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in sev_count:
                lines.append(f"| {sev.upper()} | {sev_count[sev]} |")
        lines.append("")

    # Subdomains
    lines += [
        "## Subdomains Discovered",
        "```",
    ]
    lines += subdomains[:50]
    lines += ["```", ""]

    # Live hosts
    if live_hosts:
        lines += ["## Live HTTP Hosts", ""]
        for h in live_hosts[:20]:
            url    = h.get("url", "")
            status = h.get("status-code", "")
            title  = h.get("title", "")
            tech   = ", ".join(h.get("tech", []))
            lines.append(f"- `{url}` [{status}] — {title} | {tech}")
        lines.append("")

    # Nuclei findings
    if nuclei_findings:
        lines += ["## Nuclei Findings", ""]
        for f in nuclei_findings:
            name     = f.get("info", {}).get("name", "")
            severity = f.get("info", {}).get("severity", "")
            matched  = f.get("matched-at", "")
            lines.append(f"- [{severity.upper()}] **{name}** — `{matched}`")
        lines.append("")

    # DNS findings
    if dns_findings:
        lines += ["## DNS Intelligence", ""]
        for f in dns_findings:
            name    = f.get("info", {}).get("name", "")
            matched = f.get("matched-at", "")
            lines.append(f"- **{name}** — `{matched}`")
        lines.append("")

    # URLs sample
    if urls:
        lines += ["## Sample URLs Crawled", "```"]
        lines += urls[:30]
        lines += ["```", ""]

    lines += [
        "---",
        "*Report generated by GLITCHICONS ⬡ Recon Engine*",
        "*All testing performed with proper authorization*",
    ]

    report_file.write_text("\n".join(lines))
    return report_file


def full_recon(domain, output_dir=None, mode="passive"):
    """
    Full recon pipeline.
    mode: 'passive' (DNS only) or 'active' (requires LOA)
    """
    if not output_dir:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path.home() / f"glitchicons/recon_output/{domain}_{ts}"

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    console.print(Panel(
        f"[bold purple]⬡ GLITCHICONS FULL RECON[/bold purple]\n"
        f"[dim]Target : {domain}[/dim]\n"
        f"[dim]Mode   : {mode.upper()}[/dim]\n"
        f"[dim]Output : {output_dir}[/dim]",
        border_style="purple"
    ))

    # Always run — passive
    subdomains   = subdomain_enum(domain, output_dir)
    dns_findings = dns_recon(domain, output_dir)

    live_hosts      = []
    nuclei_findings = []
    urls            = []

    if mode == "active":
        # Only with LOA
        console.print("\n[yellow]⚠ Active mode — ensure LOA is signed[/yellow]")
        live_hosts      = http_probe(subdomains, output_dir)
        nuclei_findings = nuclei_scan(f"https://{domain}", output_dir)
        urls            = crawl_urls(f"https://{domain}", output_dir)

    # Generate report
    report = generate_report(
        domain, subdomains, live_hosts,
        nuclei_findings, dns_findings, urls, output_dir
    )

    # Summary table
    table = Table(title="⬡ Recon Complete")
    table.add_column("Metric", style="bold")
    table.add_column("Result", style="green")
    table.add_row("Subdomains",      str(len(subdomains)))
    table.add_row("DNS Findings",    str(len(dns_findings)))
    table.add_row("Live Hosts",      str(len(live_hosts)))
    table.add_row("Nuclei Findings", str(len(nuclei_findings)))
    table.add_row("URLs Crawled",    str(len(urls)))
    table.add_row("Report",          str(report))
    console.print(table)

    return report


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    mode   = sys.argv[2] if len(sys.argv) > 2 else "passive"

    missing = check_tools()
    if missing:
        console.print(f"\n[red]Missing tools: {missing}[/red]")
        console.print("Run: go install github.com/projectdiscovery/...")
        sys.exit(1)

    full_recon(domain, mode=mode)
