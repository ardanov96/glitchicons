"""
GLITCHICONS ⬡ — Tech Fingerprint v1.0
Detects: CMS, framework, server, WAF, CDN
"""
import requests
import sys
import re
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

FINGERPRINTS = {
    "WordPress"  : ["wp-content", "wp-includes",
                    "wp-login.php", "WordPress"],
    "Laravel"    : ["laravel_session", "XSRF-TOKEN",
                    "Laravel"],
    "Joomla"     : ["/components/com_", "Joomla"],
    "Drupal"     : ["Drupal", "drupal.js"],
    "Django"     : ["csrfmiddlewaretoken", "Django"],
    "Rails"      : ["_rails_session", "X-Runtime"],
    "Cloudflare" : ["cf-ray", "__cfduid", "cloudflare"],
    "Nginx"      : ["nginx"],
    "Apache"     : ["apache"],
    "PHP"        : ["X-Powered-By: PHP", "PHPSESSID"],
    "Vue.js"     : ["__vue", "v-bind", "v-model"],
    "React"      : ["_reactRoot", "__REACT"],
    "Inertia.js" : ["X-Inertia", "inertia"],
    "Varnish"    : ["X-Varnish", "Via: varnish"],
}


def fingerprint(url, cookies=None):
    """Detect technologies used by target."""
    console.print(Panel(
        "[bold purple]⬡ TECH FINGERPRINT[/bold purple]\n"
        f"[dim]Target: {url}[/dim]",
        border_style="purple"
    ))

    import warnings
    warnings.filterwarnings("ignore")

    try:
        session = requests.Session()
        if cookies:
            session.cookies.update(cookies)
        r = session.get(url, timeout=15, verify=False)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return {}

    detected = {}
    content  = r.text.lower()
    headers  = {k.lower(): v.lower()
                for k, v in r.headers.items()}
    all_text = content + str(headers)

    for tech, signatures in FINGERPRINTS.items():
        for sig in signatures:
            if sig.lower() in all_text:
                detected[tech] = sig
                break

    # Display results
    table = Table(title="⬡ Detected Technologies")
    table.add_column("Technology", style="bold")
    table.add_column("Indicator")

    for tech, indicator in detected.items():
        table.add_row(tech, indicator)

    if detected:
        console.print(table)
    else:
        console.print("[green]No specific tech detected[/green]")

    return detected


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else \
          "https://target.example.com"
    fingerprint(url)
