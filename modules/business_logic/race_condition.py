"""
GLITCHICONS ⬡ — Race Condition Tester v1.0
Tests: concurrent requests, TOCTOU, coupon abuse
"""
import requests
import sys
import threading
import time
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

console = Console()


def concurrent_requests(
    url, method="POST", data=None,
    headers=None, cookies=None,
    count=10, timeout=10
):
    """Send concurrent requests to detect race conditions."""
    results  = []
    lock     = threading.Lock()

    def send():
        try:
            session = requests.Session()
            if cookies:
                session.cookies.update(cookies)
            if headers:
                session.headers.update(headers)

            if method.upper() == "POST":
                r = session.post(
                    url, json=data,
                    timeout=timeout, verify=False
                )
            else:
                r = session.get(
                    url, params=data,
                    timeout=timeout, verify=False
                )

            with lock:
                results.append({
                    "status": r.status_code,
                    "length": len(r.text),
                    "sample": r.text[:100]
                })
        except Exception as e:
            with lock:
                results.append({"error": str(e)})

    console.print(Panel(
        "[bold purple]⬡ RACE CONDITION TESTER[/bold purple]\n"
        f"[dim]Target : {url}[/dim]\n"
        f"[dim]Threads: {count}[/dim]",
        border_style="purple"
    ))

    # Launch all threads simultaneously
    threads = [threading.Thread(target=send)
               for _ in range(count)]

    console.print(
        f"\n[bold]→ Launching {count} concurrent requests...[/bold]"
    )
    start = time.time()

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    elapsed = time.time() - start

    # Analyze results
    statuses = [r.get("status") for r in results
                if "status" in r]
    lengths  = [r.get("length") for r in results
                if "length" in r]

    status_counts = {}
    for s in statuses:
        status_counts[s] = status_counts.get(s, 0) + 1

    length_variance = (max(lengths) - min(lengths)) \
        if lengths else 0

    console.print(f"  Duration : {elapsed:.2f}s")
    console.print(f"  Responses: {status_counts}")
    console.print(f"  Length variance: {length_variance} bytes")

    findings = []
    if len(set(statuses)) > 1:
        console.print(
            "  [yellow]⚠ Mixed status codes — "
            "possible race condition[/yellow]"
        )
        findings.append({
            "type"           : "RACE_CONDITION",
            "url"            : url,
            "status_variance": status_counts,
            "length_variance": length_variance,
        })
    elif length_variance > 100:
        console.print(
            "  [yellow]⚠ Response length variance — "
            "investigate manually[/yellow]"
        )
        findings.append({
            "type"           : "RESPONSE_VARIANCE",
            "url"            : url,
            "length_variance": length_variance,
        })
    else:
        console.print(
            "  [green]OK: Consistent responses[/green]"
        )

    return findings, results


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    url = sys.argv[1] if len(sys.argv) > 1 else \
          "https://target.example.com/api/redeem"
    concurrent_requests(url, count=10)
