"""
GLITCHICONS ⬡ — Session Analyzer v1.0
Tests: fixation, cookie flags, entropy, timeout
"""
import requests, sys, math, re
from collections import Counter
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

def analyze_cookie(name, value, flags):
    issues = []
    if not flags.get("httponly"):
        issues.append("Missing HttpOnly")
    if not flags.get("secure"):
        issues.append("Missing Secure flag")
    if not flags.get("samesite"):
        issues.append("Missing SameSite")
    entropy = calculate_entropy(value)
    if entropy < 3.5:
        issues.append(f"Low entropy ({entropy:.2f})")
    if len(value) < 16:
        issues.append(f"Short token ({len(value)} chars)")
    return issues

def calculate_entropy(s):
    if not s:
        return 0
    counts = Counter(s)
    length = len(s)
    return -sum(
        (c/length) * math.log2(c/length)
        for c in counts.values()
    )

def test_session_fixation(url, cookies=None):
    """Test session fixation vulnerability."""
    console.print(f"\n[bold]→ Session Fixation[/bold]")
    session = requests.Session()
    if cookies:
        session.cookies.update(cookies)

    try:
        r1 = session.get(url, timeout=10, verify=False)
        session_before = {
            k: v for k, v in session.cookies.items()
            if "session" in k.lower() or "token" in k.lower()
        }

        # Simulate login
        r2 = session.post(
            url, data={"test": "test"},
            timeout=10, verify=False
        )
        session_after = {
            k: v for k, v in session.cookies.items()
            if "session" in k.lower() or "token" in k.lower()
        }

        for key in session_before:
            if key in session_after:
                if session_before[key] == session_after[key]:
                    console.print(
                        f"  [yellow]⚠ POSSIBLE FIXATION: "
                        f"{key} unchanged after request[/yellow]"
                    )
                    return {
                        "type"  : "SESSION_FIXATION",
                        "cookie": key,
                        "value" : session_before[key]
                    }
        console.print("  [green]OK: Session rotates[/green]")
    except Exception as e:
        console.print(f"  [dim]Error: {e}[/dim]")
    return None

def run(url, cookies=None, output_dir=None):
    """Run session analysis."""
    console.print(Panel(
        "[bold purple]⬡ SESSION ANALYZER[/bold purple]\n"
        f"[dim]Target: {url}[/dim]",
        border_style="purple"
    ))
    import warnings; warnings.filterwarnings("ignore")

    session  = requests.Session()
    findings = []

    try:
        r = session.get(url, timeout=10, verify=False)

        table = Table(title="Cookie Analysis")
        table.add_column("Cookie")
        table.add_column("Entropy")
        table.add_column("Length")
        table.add_column("Issues", style="red")

        for cookie in session.cookies:
            flags = {
                "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                "secure"  : cookie.secure,
                "samesite": cookie.has_nonstandard_attr("SameSite"),
            }
            issues  = analyze_cookie(cookie.name, cookie.value, flags)
            entropy = calculate_entropy(cookie.value)

            table.add_row(
                cookie.name,
                f"{entropy:.2f}",
                str(len(cookie.value)),
                ", ".join(issues) if issues else "✅ OK"
            )

            if issues:
                findings.append({
                    "type"  : "COOKIE_ISSUES",
                    "cookie": cookie.name,
                    "issues": issues
                })

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

    fixation = test_session_fixation(url, cookies)
    if fixation:
        findings.append(fixation)

    if output_dir and findings:
        import json
        from pathlib import Path
        from datetime import datetime
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        f   = out / f"session_{ts}.json"
        f.write_text(json.dumps(findings, indent=2))
        console.print(f"\nReport: {f}")

    console.print(f"\n[bold]Total: {len(findings)} findings[/bold]")
    return findings

if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else
        "https://target.example.com")
