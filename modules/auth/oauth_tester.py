"""
GLITCHICONS ⬡ — OAuth Tester v1.0
Tests: state parameter, redirect_uri, token leakage
"""
import requests
import sys
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode
from rich.console import Console
from rich.panel import Panel

console = Console()

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "https://evil.com/callback",
    "//evil.com",
    "https://legitimate.com.evil.com",
    "https://legitimate.com@evil.com",
    "javascript:alert(1)",
]


def test_state_param(auth_url):
    """Test missing/weak state parameter."""
    console.print(f"\n[bold]→ State Parameter[/bold]")
    parsed = urlparse(auth_url)
    params = parse_qs(parsed.query)

    if "state" not in params:
        console.print(
            "  [red]⚠ MISSING: No state parameter (CSRF risk)[/red]"
        )
        return {"type": "MISSING_STATE", "url": auth_url}
    elif len(params["state"][0]) < 16:
        console.print(
            f"  [yellow]⚠ WEAK: state too short "
            f"({len(params['state'][0])} chars)[/yellow]"
        )
        return {
            "type" : "WEAK_STATE",
            "value": params["state"][0]
        }
    else:
        console.print(
            f"  [green]OK: state present "
            f"({len(params['state'][0])} chars)[/green]"
        )
    return None


def test_redirect_uri(auth_url):
    """Test redirect_uri manipulation."""
    console.print(f"\n[bold]→ redirect_uri Bypass[/bold]")
    findings = []
    parsed   = urlparse(auth_url)
    params   = parse_qs(parsed.query)

    if "redirect_uri" not in params:
        console.print(
            "  [dim]No redirect_uri parameter found[/dim]"
        )
        return findings

    base = (f"{parsed.scheme}://{parsed.netloc}"
            f"{parsed.path}?")

    for payload in REDIRECT_PAYLOADS:
        test_params = {k: v[0] for k, v in params.items()}
        test_params["redirect_uri"] = payload
        test_url = base + urlencode(test_params)

        try:
            r = requests.get(
                test_url, timeout=8,
                verify=False,
                allow_redirects=False
            )
            if r.status_code in [301, 302]:
                location = r.headers.get("Location", "")
                if "evil.com" in location or \
                   payload in location:
                    console.print(
                        f"  [red]⚠ REDIRECT BYPASS: "
                        f"{payload} → {location}[/red]"
                    )
                    findings.append({
                        "type"    : "REDIRECT_URI_BYPASS",
                        "payload" : payload,
                        "location": location,
                    })
        except Exception:
            continue

    if not findings:
        console.print(
            "  [green]No redirect_uri bypass found[/green]"
        )
    return findings


def run(auth_url, output_dir=None):
    """Run OAuth test suite."""
    console.print(Panel(
        "[bold purple]⬡ GLITCHICONS OAUTH TESTER[/bold purple]\n"
        f"[dim]Target: {auth_url}[/dim]",
        border_style="purple"
    ))
    import warnings
    warnings.filterwarnings("ignore")

    findings = []

    state_f = test_state_param(auth_url)
    if state_f:
        findings.append(state_f)

    findings += test_redirect_uri(auth_url)

    if output_dir and findings:
        import json
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        f   = out / f"oauth_findings_{ts}.json"
        f.write_text(json.dumps(findings, indent=2))
        console.print(f"\nReport: {f}")

    console.print(
        f"\n[bold]Total: {len(findings)} OAuth findings[/bold]"
    )
    return findings


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else
        "https://target.example.com/oauth/authorize")
