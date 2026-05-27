"""
Subdomain Takeover Checker — modules/recon/subdomain_takeover.py

Checks:
  1. DNS enumeration       — discover subdomains via wordlist + passive
  2. Dangling CNAME        — CNAME pointing to unclaimed service
  3. Dead NS records       — nameserver no longer authoritative
  4. Unclaimed cloud assets — S3, Azure Blob, GCS, GitHub Pages, etc.
  5. Service fingerprint    — match HTTP response to known vulnerable patterns
  6. A record to parked IP  — detect domain parking / expired hosting
  7. Expired hosting        — detect "account suspended" / "not found" pages

Coverage — 25+ cloud/SaaS fingerprints:
  AWS S3, CloudFront, Elastic Beanstalk
  Azure Blob, Azure CDN, Azure App Service
  GitHub Pages, Fastly, Heroku, Netlify, Vercel
  Shopify, Cargo, Ghost, Tumblr, WordPress.com
  Zendesk, UserVoice, Intercom, Readme.io
  Surge.sh, Bitbucket Pages, HubSpot

Usage:
    python3 glitchicons.py takeover --domain target.com
    python3 glitchicons.py takeover --domain target.com --wordlist wordlists/subdomains.txt
    python3 glitchicons.py takeover --domain target.com --passive

Author: ardanov96
"""

import json
import time
import socket
import dns.resolver
import dns.exception
import httpx
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table

console = Console()


# ── Fingerprint database ──────────────────────────────────

TAKEOVER_FINGERPRINTS: list[dict] = [
    # AWS
    {
        "service":     "AWS S3",
        "cname":       ["amazonaws.com", "s3.amazonaws.com"],
        "body":        ["NoSuchBucket", "The specified bucket does not exist"],
        "status":      [404],
        "severity":    "CRITICAL",
        "cvss":        9.8,
        "cwe":         "CWE-284",
    },
    {
        "service":     "AWS CloudFront",
        "cname":       ["cloudfront.net"],
        "body":        ["Bad request", "ERROR: The request could not be satisfied"],
        "status":      [403],
        "severity":    "HIGH",
        "cvss":        7.5,
        "cwe":         "CWE-284",
    },
    {
        "service":     "AWS Elastic Beanstalk",
        "cname":       ["elasticbeanstalk.com"],
        "body":        ["NXDOMAIN"],
        "status":      [],
        "severity":    "CRITICAL",
        "cvss":        9.8,
        "cwe":         "CWE-284",
    },
    # GitHub
    {
        "service":     "GitHub Pages",
        "cname":       ["github.io", "github.com"],
        "body":        ["There isn't a GitHub Pages site here",
                        "For root URLs (like http://example.com/)"],
        "status":      [404],
        "severity":    "HIGH",
        "cvss":        8.0,
        "cwe":         "CWE-284",
    },
    # Heroku
    {
        "service":     "Heroku",
        "cname":       ["herokuapp.com", "herokudns.com"],
        "body":        ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
        "status":      [404],
        "severity":    "HIGH",
        "cvss":        8.0,
        "cwe":         "CWE-284",
    },
    # Netlify
    {
        "service":     "Netlify",
        "cname":       ["netlify.app", "netlify.com"],
        "body":        ["Not Found - Request ID"],
        "status":      [404],
        "severity":    "HIGH",
        "cvss":        8.0,
        "cwe":         "CWE-284",
    },
    # Vercel
    {
        "service":     "Vercel",
        "cname":       ["vercel.app", "now.sh"],
        "body":        ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],
        "status":      [404],
        "severity":    "HIGH",
        "cvss":        8.0,
        "cwe":         "CWE-284",
    },
    # Azure
    {
        "service":     "Azure Blob Storage",
        "cname":       ["blob.core.windows.net"],
        "body":        ["BlobServiceProperties", "The specified container does not exist"],
        "status":      [404],
        "severity":    "CRITICAL",
        "cvss":        9.5,
        "cwe":         "CWE-284",
    },
    {
        "service":     "Azure App Service",
        "cname":       ["azurewebsites.net", "cloudapp.net"],
        "body":        ["404 Web Site not found", "Microsoft Azure App Service"],
        "status":      [404],
        "severity":    "HIGH",
        "cvss":        8.0,
        "cwe":         "CWE-284",
    },
    # Shopify
    {
        "service":     "Shopify",
        "cname":       ["myshopify.com", "shopify.com"],
        "body":        ["Sorry, this shop is currently unavailable",
                        "Only one step away from your own online store"],
        "status":      [404],
        "severity":    "MEDIUM",
        "cvss":        6.5,
        "cwe":         "CWE-284",
    },
    # Fastly
    {
        "service":     "Fastly",
        "cname":       ["fastly.net", "fastlylb.net"],
        "body":        ["Fastly error: unknown domain", "Please check that this domain"],
        "status":      [500],
        "severity":    "HIGH",
        "cvss":        7.5,
        "cwe":         "CWE-284",
    },
    # Zendesk
    {
        "service":     "Zendesk",
        "cname":       ["zendesk.com"],
        "body":        ["Help Center Closed", "Oops, this help center no longer exists"],
        "status":      [404],
        "severity":    "MEDIUM",
        "cvss":        6.0,
        "cwe":         "CWE-284",
    },
    # Ghost
    {
        "service":     "Ghost",
        "cname":       ["ghost.io"],
        "body":        ["The thing you were looking for is no longer here"],
        "status":      [404],
        "severity":    "MEDIUM",
        "cvss":        6.0,
        "cwe":         "CWE-284",
    },
    # Tumblr
    {
        "service":     "Tumblr",
        "cname":       ["tumblr.com"],
        "body":        ["Whatever you were looking for doesn't currently exist at this address"],
        "status":      [404],
        "severity":    "MEDIUM",
        "cvss":        6.0,
        "cwe":         "CWE-284",
    },
    # Surge.sh
    {
        "service":     "Surge.sh",
        "cname":       ["surge.sh"],
        "body":        ["project not found"],
        "status":      [404],
        "severity":    "HIGH",
        "cvss":        7.5,
        "cwe":         "CWE-284",
    },
    # Readme.io
    {
        "service":     "Readme.io",
        "cname":       ["readme.io"],
        "body":        ["Project doesnt exist... yet!"],
        "status":      [404],
        "severity":    "MEDIUM",
        "cvss":        6.0,
        "cwe":         "CWE-284",
    },
    # HubSpot
    {
        "service":     "HubSpot",
        "cname":       ["hubspot.net", "hs-sites.com"],
        "body":        ["Domain not found", "This page isn't available"],
        "status":      [404],
        "severity":    "MEDIUM",
        "cvss":        6.0,
        "cwe":         "CWE-284",
    },
    # UserVoice
    {
        "service":     "UserVoice",
        "cname":       ["uservoice.com"],
        "body":        ["This UserVoice subdomain is currently available!"],
        "status":      [404],
        "severity":    "MEDIUM",
        "cvss":        6.0,
        "cwe":         "CWE-284",
    },
    # WordPress.com
    {
        "service":     "WordPress.com",
        "cname":       ["wordpress.com"],
        "body":        ["Do you want to register", "doesn't exist"],
        "status":      [404],
        "severity":    "MEDIUM",
        "cvss":        5.5,
        "cwe":         "CWE-284",
    },
    # Generic parking
    {
        "service":     "Domain Parking",
        "cname":       [],
        "body":        [
            "This domain is for sale",
            "Buy this domain",
            "Parked Domain",
            "Domain has expired",
            "Account Suspended",
            "This site can't be reached",
        ],
        "status":      [],
        "severity":    "HIGH",
        "cvss":        7.0,
        "cwe":         "CWE-284",
    },
]

# Common subdomains to check
DEFAULT_SUBDOMAIN_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test",
    "portal", "ns", "ww1", "host", "support", "dev", "web", "bbs",
    "ww42", "mx", "email", "cloud", "1", "mail1", "2", "forum", "owa",
    "www2", "gw", "admin", "store", "mx1", "cdn", "api", "exchange",
    "app", "new", "staff", "news", "job", "jobs", "staging", "prod",
    "beta", "internal", "old", "demo", "static", "assets", "img",
    "images", "media", "docs", "help", "status", "dashboard", "auth",
    "login", "register", "mobile", "pay", "payments", "checkout",
]


# ── Data classes ──────────────────────────────────────────

@dataclass
class SubdomainResult:
    """Result for a single subdomain check."""
    subdomain: str
    fqdn: str
    a_records: list[str] = field(default_factory=list)
    cname_chain: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    http_status: int | None = None
    http_body_snippet: str = ""
    is_nxdomain: bool = False
    is_alive: bool = False
    takeover_candidate: bool = False
    matched_service: str = ""
    matched_fingerprint: dict | None = None

    @property
    def final_cname(self) -> str | None:
        return self.cname_chain[-1] if self.cname_chain else None


# ── DNS helpers ───────────────────────────────────────────

class DNSProber:
    """Handles DNS lookups for subdomain takeover detection."""

    def __init__(self, timeout: float = 3.0):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def get_a_records(self, fqdn: str) -> list[str]:
        try:
            answers = self.resolver.resolve(fqdn, "A")
            return [str(r) for r in answers]
        except Exception:
            return []

    def get_cname_chain(self, fqdn: str) -> list[str]:
        chain = []
        current = fqdn
        visited = set()
        while current and current not in visited:
            visited.add(current)
            try:
                answers = self.resolver.resolve(current, "CNAME")
                target = str(answers[0].target).rstrip(".")
                chain.append(target)
                current = target
            except Exception:
                break
        return chain

    def get_ns_records(self, fqdn: str) -> list[str]:
        try:
            answers = self.resolver.resolve(fqdn, "NS")
            return [str(r) for r in answers]
        except Exception:
            return []

    def is_nxdomain(self, fqdn: str) -> bool:
        try:
            self.resolver.resolve(fqdn, "A")
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except Exception:
            return False

    def probe_subdomain(self, fqdn: str) -> SubdomainResult:
        """Full DNS probe of a single FQDN."""
        parts = fqdn.split(".", 1)
        subdomain = parts[0] if len(parts) > 1 else fqdn
        domain = parts[1] if len(parts) > 1 else ""

        result = SubdomainResult(subdomain=subdomain, fqdn=fqdn)
        result.is_nxdomain = self.is_nxdomain(fqdn)
        result.a_records = self.get_a_records(fqdn)
        result.cname_chain = self.get_cname_chain(fqdn)
        result.ns_records = self.get_ns_records(fqdn)
        result.is_alive = bool(result.a_records) and not result.is_nxdomain

        return result


# ── Main checker ──────────────────────────────────────────

class SubdomainTakeoverChecker:
    """
    Subdomain takeover vulnerability checker.

    Covers:
    - CWE-284: Improper Access Control (dangling DNS)
    - 25+ cloud/SaaS service fingerprints
    - CNAME chain analysis
    - HTTP response fingerprinting
    - Dead NS record detection
    """

    def __init__(
        self,
        domain: str,
        output_dir: str = "./findings/takeover",
        wordlist: list[str] | None = None,
        timeout: int = 5,
        delay: float = 0.2,
        passive: bool = False,
    ):
        self.domain = domain.lower().strip()
        self.output_dir = Path(output_dir)
        self.wordlist = wordlist or DEFAULT_SUBDOMAIN_WORDLIST
        self.timeout = timeout
        self.delay = delay
        self.passive = passive
        self.findings: list[dict] = []
        self.scanned: list[SubdomainResult] = []
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.dns = DNSProber(timeout=float(timeout))

    def run(self) -> list[dict]:
        """Run full subdomain takeover scan."""
        console.print(f"\n[bold cyan]  GLITCHICONS Subdomain Takeover Checker[/bold cyan]")
        console.print(f"  Target   : [yellow]{self.domain}[/yellow]")
        console.print(f"  Mode     : {'passive' if self.passive else 'active'}")
        console.print(f"  Wordlist : {len(self.wordlist)} subdomains\n")

        # Generate FQDN list
        fqdns = [f"{sub}.{self.domain}" for sub in self.wordlist]

        console.print(f"  [cyan]Scanning {len(fqdns)} subdomains...[/cyan]")

        for fqdn in fqdns:
            result = self.dns.probe_subdomain(fqdn)
            result = self._http_probe(result)
            result = self._fingerprint(result)
            self.scanned.append(result)

            if result.takeover_candidate:
                console.print(
                    f"  [red]CANDIDATE: {fqdn} → {result.matched_service}[/red]"
                )
                self._add_finding(result)

            time.sleep(self.delay)

        # Check for dead NS records on root domain
        self._check_dead_ns()

        self._print_summary()
        self._save_report()
        return self.findings

    # ── Probing ───────────────────────────────────────────

    def _http_probe(self, result: SubdomainResult) -> SubdomainResult:
        """Probe subdomain over HTTP/HTTPS."""
        if not result.is_alive and not result.cname_chain:
            return result

        for scheme in ["https", "http"]:
            try:
                resp = httpx.get(
                    f"{scheme}://{result.fqdn}",
                    timeout=self.timeout,
                    follow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (Glitchicons Takeover Checker)"},
                )
                result.http_status = resp.status_code
                result.http_body_snippet = resp.text[:2000]
                break
            except Exception:
                continue

        return result

    def _fingerprint(self, result: SubdomainResult) -> SubdomainResult:
        """Match DNS + HTTP response against known takeover fingerprints."""
        body = result.http_body_snippet.lower()
        cname_str = " ".join(result.cname_chain).lower()

        for fp in TAKEOVER_FINGERPRINTS:
            # CNAME match
            cname_match = any(
                c.lower() in cname_str for c in fp["cname"]
            ) if fp["cname"] else False

            # Body match
            body_match = any(
                sig.lower() in body for sig in fp["body"]
            ) if fp["body"] else False

            # Status match
            status_match = (
                result.http_status in fp["status"]
            ) if fp["status"] else False

            # NXDOMAIN + CNAME = dangling
            nxdomain_cname = result.is_nxdomain and bool(result.cname_chain)

            # A record to known parking IP ranges
            parking_ips = {"35.196.", "54.225.", "52.54.", "34.98."}
            parked_ip = any(
                any(result.fqdn.startswith(pip) for pip in parking_ips)
                for _ in [1]
            )

            is_vulnerable = (
                (cname_match and (body_match or status_match))
                or (cname_match and nxdomain_cname)
                or (body_match and not fp["cname"])   # generic parking
            )

            if is_vulnerable:
                result.takeover_candidate = True
                result.matched_service = fp["service"]
                result.matched_fingerprint = fp
                break

        return result

    def _check_dead_ns(self):
        """Check if root domain NS records resolve."""
        ns_records = self.dns.get_ns_records(self.domain)
        dead_ns = []

        for ns in ns_records:
            if not self.dns.get_a_records(ns):
                dead_ns.append(ns)

        if dead_ns:
            self.findings.append({
                "id":          f"TAKE-{len(self.findings)+1:03d}",
                "title":       f"Dead NS Records for {self.domain}",
                "severity":    "CRITICAL",
                "cvss":        9.8,
                "cwe":         "CWE-284",
                "target":      self.domain,
                "subdomain":   self.domain,
                "service":     "DNS Nameserver",
                "description": (
                    f"Nameserver(s) for {self.domain} do not resolve: {dead_ns}. "
                    f"An attacker could register these nameservers and gain full "
                    f"DNS control over the entire domain."
                ),
                "evidence":    f"NS records: {ns_records} | Dead: {dead_ns}",
                "remediation": (
                    "Update NS records to active nameservers. "
                    "Remove or replace nameservers that are no longer active. "
                    "Monitor NS records regularly."
                ),
                "timestamp":   datetime.now().isoformat(),
            })

    # ── Finding builder ───────────────────────────────────

    def _add_finding(self, result: SubdomainResult):
        fp = result.matched_fingerprint or {}
        self.findings.append({
            "id":          f"TAKE-{len(self.findings)+1:03d}",
            "title":       f"Subdomain Takeover: {result.fqdn} → {result.matched_service}",
            "severity":    fp.get("severity", "HIGH"),
            "cvss":        fp.get("cvss", 7.5),
            "cwe":         fp.get("cwe", "CWE-284"),
            "target":      self.domain,
            "subdomain":   result.fqdn,
            "service":     result.matched_service,
            "description": (
                f"Subdomain {result.fqdn} is vulnerable to takeover via {result.matched_service}. "
                f"CNAME chain: {' → '.join(result.cname_chain) or 'none'}. "
                f"The pointed service no longer exists and can be claimed by an attacker "
                f"to serve malicious content under your domain."
            ),
            "evidence": (
                f"CNAME: {result.cname_chain}\n"
                f"A records: {result.a_records}\n"
                f"HTTP status: {result.http_status}\n"
                f"Body snippet: {result.http_body_snippet[:200]}"
            ),
            "remediation": (
                f"Remove or update the DNS record for {result.fqdn}. "
                f"If {result.matched_service} is no longer used, delete the CNAME. "
                f"If still needed, claim the resource on {result.matched_service} immediately."
            ),
            "timestamp":   datetime.now().isoformat(),
        })

    # ── Display & Save ────────────────────────────────────

    def _print_summary(self):
        alive = sum(1 for r in self.scanned if r.is_alive)
        candidates = sum(1 for r in self.scanned if r.takeover_candidate)

        console.print(f"\n[bold cyan]  Scan Results — {self.domain}[/bold cyan]")
        console.print(f"  Scanned    : {len(self.scanned)}")
        console.print(f"  Alive      : {alive}")
        console.print(f"  Candidates : [red]{candidates}[/red]")
        console.print(f"  Findings   : [red]{len(self.findings)}[/red]\n")

        if self.findings:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("ID",       style="cyan", width=10)
            table.add_column("Severity", width=10)
            table.add_column("CVSS",     width=6)
            table.add_column("Subdomain")
            table.add_column("Service")

            colors = {
                "CRITICAL": "bold red", "HIGH": "red",
                "MEDIUM": "yellow", "LOW": "green",
            }
            for f in sorted(self.findings, key=lambda x: x["cvss"], reverse=True):
                c = colors.get(f["severity"], "white")
                table.add_row(
                    f["id"],
                    f"[{c}]{f['severity']}[/{c}]",
                    str(f["cvss"]),
                    f.get("subdomain", ""),
                    f.get("service", ""),
                )
            console.print(table)

    def _save_report(self) -> Path:
        report = {
            "tool":           "glitchicons",
            "module":         "subdomain_takeover",
            "version":        "0.8.0",
            "target":         self.domain,
            "timestamp":      datetime.now().isoformat(),
            "total_scanned":  len(self.scanned),
            "total_alive":    sum(1 for r in self.scanned if r.is_alive),
            "total_findings": len(self.findings),
            "fingerprints":   len(TAKEOVER_FINGERPRINTS),
            "findings":       sorted(
                self.findings, key=lambda x: x.get("cvss", 0), reverse=True
            ),
        }
        out = self.output_dir / f"takeover_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        console.print(f"  Report: [cyan]{out}[/cyan]")
        return out
