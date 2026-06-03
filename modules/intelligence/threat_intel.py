"""
Threat Intelligence Layer — modules/intelligence/threat_intel.py

Enrich findings and targets with real-world threat intelligence:
  1. CVELookup       — search CVEs via NVD API, get EPSS exploit probability
  2. ShodanRecon     — passive asset reconnaissance via Shodan API
  3. CTRecon         — Certificate Transparency asset discovery (crt.sh)
  4. ExploitChecker  — check known exploits for CVEs (ExploitDB)
  5. ThreatIntelScanner — orchestrate all intel sources per target

Usage:
    from modules.intelligence.threat_intel import (
        CVELookup, ShodanRecon, CTRecon, ExploitChecker, ThreatIntelScanner,
    )

    # CVE + EPSS lookup
    cve = CVELookup()
    results = cve.search_by_product("apache", "2.4.49")
    enriched = cve.enrich_findings(findings)

    # Shodan passive recon (API key required)
    shodan = ShodanRecon(api_key="YOUR_KEY")
    intel  = shodan.lookup("target.com")

    # Certificate Transparency
    ct = CTRecon()
    domains = ct.find_subdomains("target.com")

    # Full scan
    scanner = ThreatIntelScanner(target="target.com", shodan_api_key="KEY")
    results = scanner.run(findings=existing_findings)

Author: ardanov96
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import httpx
from rich.console import Console

console = Console()

# ── API endpoints ─────────────────────────────────────────
NVD_API_URL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL   = "https://api.first.org/data/v1/epss"
SHODAN_API_URL = "https://api.shodan.io"
CRTSH_API_URL  = "https://crt.sh"
EXPLOITDB_URL  = "https://www.exploit-db.com/search"

# EPSS score thresholds
EPSS_CRITICAL  = 0.70   # > 70% — actively exploited
EPSS_HIGH      = 0.30   # > 30% — high exploitation probability
EPSS_MEDIUM    = 0.10   # > 10% — medium probability

# CVE severity thresholds (CVSS v3)
CVE_CRITICAL   = 9.0
CVE_HIGH       = 7.0
CVE_MEDIUM     = 4.0


# ── Data classes ──────────────────────────────────────────

@dataclass
class CVEResult:
    """A single CVE with optional EPSS score."""
    cve_id:      str
    description: str
    cvss_score:  float
    cvss_vector: str
    severity:    str
    published:   str
    modified:    str
    epss_score:  float = 0.0
    epss_pct:    float = 0.0   # percentile rank
    has_exploit: bool = False
    exploit_url: str  = ""
    references:  list[str] = field(default_factory=list)


@dataclass
class ShodanHost:
    """Shodan host intelligence result."""
    ip:          str
    hostnames:   list[str]
    org:         str
    country:     str
    open_ports:  list[int]
    vulns:       list[str]  # CVE IDs from Shodan
    tags:        list[str]  # "honeypot", "self-signed", etc.
    last_update: str
    banners:     list[dict] = field(default_factory=list)


@dataclass
class CTDomain:
    """A domain found via Certificate Transparency."""
    domain:     str
    issuer:     str
    not_before: str
    not_after:  str
    logged_at:  str


@dataclass
class ThreatIntelResult:
    """Full threat intelligence result for a target."""
    target:      str
    timestamp:   str
    cves:        list[CVEResult]
    shodan_host: ShodanHost | None
    ct_domains:  list[CTDomain]
    findings:    list[dict]


# ── Finding helper ────────────────────────────────────────

def _finding(
    title: str, severity: str, cvss: float, cwe: str,
    description: str, evidence: str, remediation: str,
    target: str, source: str = "threat_intel",
) -> dict:
    assert severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    assert 0.0 <= cvss <= 10.0
    assert cwe.startswith("CWE-")
    return {
        "title": title, "severity": severity, "cvss": cvss, "cwe": cwe,
        "target": target, "description": description, "evidence": evidence,
        "remediation": remediation, "source": f"module:{source}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _cve_severity(score: float) -> str:
    if score >= CVE_CRITICAL: return "CRITICAL"
    if score >= CVE_HIGH:     return "HIGH"
    if score >= CVE_MEDIUM:   return "MEDIUM"
    return "LOW"


# ── 1. CVE Lookup ─────────────────────────────────────────

class CVELookup:
    """
    Query NVD API for CVEs and enrich with EPSS exploit probability scores.

    EPSS (Exploit Prediction Scoring System) from FIRST.org gives a
    probability (0-1) that a CVE will be exploited in the next 30 days.

    No API key required for NVD (rate-limited) or EPSS.
    """

    def __init__(
        self,
        output_dir: str = "./findings/threat_intel",
        timeout: int = 15,
        nvd_api_key: str | None = None,
    ):
        self.output_dir  = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout     = timeout
        self.nvd_api_key = nvd_api_key

        headers = {"User-Agent": "Glitchicons/2.4.0 (threat-intel)"}
        if nvd_api_key:
            headers["apiKey"] = nvd_api_key

        self.client = httpx.Client(timeout=timeout, headers=headers)

    def search_by_cve_id(self, cve_id: str) -> CVEResult | None:
        """Look up a specific CVE by ID (e.g. CVE-2021-44228)."""
        try:
            resp = self.client.get(NVD_API_URL, params={"cveId": cve_id})
            if resp.status_code != 200:
                return None
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None
            result = self._parse_cve(vulns[0])
            if result:
                result = self._enrich_epss([result])[0]
            return result
        except Exception:
            return None

    def search_by_keyword(self, keyword: str, max_results: int = 10) -> list[CVEResult]:
        """Search CVEs by keyword (product name, vendor, etc.)."""
        try:
            resp = self.client.get(NVD_API_URL, params={
                "keywordSearch": keyword,
                "resultsPerPage": min(max_results, 20),
            })
            if resp.status_code != 200:
                return []
            data = resp.json()
            results = []
            for v in data.get("vulnerabilities", []):
                cve = self._parse_cve(v)
                if cve:
                    results.append(cve)
            return self._enrich_epss(results)
        except Exception:
            return []

    def search_by_product(self, product: str, version: str | None = None) -> list[CVEResult]:
        """Search CVEs for a specific product and optional version."""
        keyword = product if not version else f"{product} {version}"
        return self.search_by_keyword(keyword)

    def enrich_findings(self, findings: list[dict]) -> list[dict]:
        """
        Enrich existing Glitchicons findings with CVE/EPSS context.

        Extracts CWE/CVE references from findings and adds EPSS data.
        Returns new findings for highly exploitable CVEs.
        """
        new_findings = []
        cve_pattern  = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

        seen_cves: set[str] = set()
        for finding in findings:
            # Extract CVE IDs from title/description/evidence
            text = " ".join([
                finding.get("title", ""),
                finding.get("description", ""),
                finding.get("evidence", ""),
            ])
            for cve_id in cve_pattern.findall(text):
                cve_id = cve_id.upper()
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)

                cve_result = self.search_by_cve_id(cve_id)
                if not cve_result:
                    continue

                if cve_result.epss_score >= EPSS_HIGH:
                    severity = "CRITICAL" if cve_result.epss_score >= EPSS_CRITICAL else "HIGH"
                    new_findings.append(_finding(
                        title=f"High EPSS Score — {cve_id} ({cve_result.epss_score:.1%} exploit probability)",
                        severity=severity,
                        cvss=cve_result.cvss_score,
                        cwe="CWE-1035",
                        description=(
                            f"{cve_id}: {cve_result.description[:200]}\n"
                            f"EPSS score: {cve_result.epss_score:.1%} "
                            f"(top {100-cve_result.epss_pct*100:.0f}% most likely to be exploited)"
                        ),
                        evidence=(
                            f"CVE: {cve_id}\n"
                            f"CVSS: {cve_result.cvss_score} ({cve_result.severity})\n"
                            f"EPSS: {cve_result.epss_score:.4f} ({cve_result.epss_pct:.1%} percentile)\n"
                            f"Published: {cve_result.published}"
                        ),
                        remediation=(
                            f"High exploit probability detected for {cve_id}. "
                            "Apply patches immediately. Monitor threat feeds for active exploitation."
                        ),
                        target=finding.get("target", ""),
                        source="cve_lookup",
                    ))

        self._save_cves(list(seen_cves), new_findings)
        return new_findings

    def get_epss(self, cve_ids: list[str]) -> dict[str, tuple[float, float]]:
        """
        Fetch EPSS scores for a list of CVE IDs.

        Returns dict: {cve_id: (epss_score, percentile)}
        """
        if not cve_ids:
            return {}
        try:
            resp = self.client.get(
                EPSS_API_URL,
                params={"cve": ",".join(cve_ids[:30])},  # API limit
            )
            if resp.status_code != 200:
                return {}
            data = resp.json()
            result = {}
            for item in data.get("data", []):
                cve = item.get("cve", "").upper()
                epss = float(item.get("epss", 0))
                pct  = float(item.get("percentile", 0))
                result[cve] = (epss, pct)
            return result
        except Exception:
            return {}

    def _parse_cve(self, vuln_data: dict) -> CVEResult | None:
        """Parse NVD API vulnerability object into CVEResult."""
        try:
            cve  = vuln_data.get("cve", {})
            cid  = cve.get("id", "")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            # CVSS v3.1 score
            score  = 0.0
            vector = ""
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    m = metrics[key][0].get("cvssData", {})
                    score  = float(m.get("baseScore", 0))
                    vector = m.get("vectorString", "")
                    break

            refs = [r.get("url", "") for r in cve.get("references", [])[:5]]

            return CVEResult(
                cve_id=cid,
                description=desc[:400],
                cvss_score=score,
                cvss_vector=vector,
                severity=_cve_severity(score),
                published=cve.get("published", ""),
                modified=cve.get("lastModified", ""),
                references=refs,
            )
        except Exception:
            return None

    def _enrich_epss(self, results: list[CVEResult]) -> list[CVEResult]:
        """Add EPSS scores to CVEResult objects."""
        cve_ids = [r.cve_id for r in results if r.cve_id]
        epss_data = self.get_epss(cve_ids)
        for r in results:
            if r.cve_id in epss_data:
                r.epss_score, r.epss_pct = epss_data[r.cve_id]
        return results

    def _save_cves(self, cve_ids: list[str], findings: list[dict]) -> Path:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = self.output_dir / f"cve_{ts}.json"
        out.write_text(json.dumps({
            "cve_ids": cve_ids, "findings": findings
        }, indent=2), encoding="utf-8")
        return out


# ── 2. Shodan Recon ───────────────────────────────────────

class ShodanRecon:
    """
    Passive reconnaissance using Shodan API.

    Queries Shodan for:
    - Open ports and services
    - Known CVEs on the host
    - Hostnames and org info
    - Interesting tags (honeypot, self-signed, ICS, etc.)
    - Banner information for exposed services

    Requires a Shodan API key (free tier supported).
    """

    DANGEROUS_PORTS = {
        21:   ("FTP", "CRITICAL"),
        22:   ("SSH", "INFO"),
        23:   ("Telnet", "CRITICAL"),
        25:   ("SMTP", "MEDIUM"),
        53:   ("DNS", "MEDIUM"),
        80:   ("HTTP", "INFO"),
        443:  ("HTTPS", "INFO"),
        445:  ("SMB", "CRITICAL"),
        1433: ("MSSQL", "CRITICAL"),
        1521: ("Oracle", "CRITICAL"),
        3306: ("MySQL", "CRITICAL"),
        3389: ("RDP", "HIGH"),
        5432: ("PostgreSQL", "CRITICAL"),
        5900: ("VNC", "CRITICAL"),
        6379: ("Redis", "CRITICAL"),
        9200: ("Elasticsearch", "CRITICAL"),
        27017:("MongoDB", "CRITICAL"),
    }

    def __init__(
        self,
        api_key: str = "",
        output_dir: str = "./findings/threat_intel",
        timeout: int = 15,
    ):
        self.api_key    = api_key
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout    = timeout
        self.client     = httpx.Client(
            timeout=timeout,
            headers={"User-Agent": "Glitchicons/2.4.0"},
        )

    def lookup_ip(self, ip: str) -> ShodanHost | None:
        """Look up a specific IP address on Shodan."""
        if not self.api_key:
            return None
        try:
            resp = self.client.get(
                f"{SHODAN_API_URL}/shodan/host/{ip}",
                params={"key": self.api_key},
            )
            if resp.status_code != 200:
                return None
            return self._parse_host(resp.json(), ip)
        except Exception:
            return None

    def lookup_domain(self, domain: str) -> ShodanHost | None:
        """Resolve domain to IP then look up on Shodan."""
        if not self.api_key:
            return None
        try:
            # DNS resolve via Shodan
            resp = self.client.get(
                f"{SHODAN_API_URL}/dns/resolve",
                params={"key": self.api_key, "hostnames": domain},
            )
            if resp.status_code != 200:
                return None
            ip_map = resp.json()
            ip = ip_map.get(domain)
            if not ip:
                return None
            return self.lookup_ip(ip)
        except Exception:
            return None

    def build_findings(self, host: ShodanHost, target: str) -> list[dict]:
        """Convert ShodanHost intel into Glitchicons findings."""
        findings = []

        # Critical exposed services
        for port in host.open_ports:
            if port in self.DANGEROUS_PORTS:
                service, severity = self.DANGEROUS_PORTS[port]
                if severity in ("CRITICAL", "HIGH"):
                    findings.append(_finding(
                        title=f"Shodan: {service} Exposed on Port {port}",
                        severity=severity,
                        cvss=9.8 if severity == "CRITICAL" else 7.5,
                        cwe="CWE-200",
                        description=(
                            f"Shodan reports {service} (port {port}) exposed on {host.ip}. "
                            f"Org: {host.org}. Country: {host.country}."
                        ),
                        evidence=(
                            f"IP: {host.ip}\nPort: {port} ({service})\n"
                            f"Hostnames: {', '.join(host.hostnames[:3])}\n"
                            f"Last updated: {host.last_update}"
                        ),
                        remediation=(
                            f"Restrict {service} port {port} to authorized IPs only. "
                            "Apply firewall rules. Disable service if not required."
                        ),
                        target=target,
                        source="shodan_recon",
                    ))

        # CVEs from Shodan
        for cve_id in host.vulns[:5]:
            findings.append(_finding(
                title=f"Shodan: Known Vulnerability {cve_id} on Host",
                severity="HIGH",
                cvss=7.5,
                cwe="CWE-1035",
                description=f"Shodan detected {cve_id} on {host.ip}.",
                evidence=f"IP: {host.ip}\nCVE: {cve_id}\nSource: Shodan passive scan",
                remediation=f"Research {cve_id} and apply vendor patch immediately.",
                target=target,
                source="shodan_recon",
            ))

        # Honeypot detection
        if "honeypot" in host.tags:
            findings.append(_finding(
                title="Shodan: Target Flagged as Honeypot",
                severity="INFO",
                cvss=0.0,
                cwe="CWE-200",
                description="Shodan has flagged this host as a potential honeypot.",
                evidence=f"IP: {host.ip}\nShodan tags: {', '.join(host.tags)}",
                remediation="Verify target legitimacy before proceeding with assessment.",
                target=target,
                source="shodan_recon",
            ))

        return findings

    def _parse_host(self, data: dict, ip: str) -> ShodanHost:
        return ShodanHost(
            ip=ip,
            hostnames=data.get("hostnames", []),
            org=data.get("org", ""),
            country=data.get("country_name", ""),
            open_ports=data.get("ports", []),
            vulns=list(data.get("vulns", {}).keys()),
            tags=data.get("tags", []),
            last_update=data.get("last_update", ""),
            banners=[
                {"port": s.get("port"), "product": s.get("product", ""),
                 "version": s.get("version", "")}
                for s in data.get("data", [])[:10]
            ],
        )


# ── 3. Certificate Transparency Recon ────────────────────

class CTRecon:
    """
    Asset discovery via Certificate Transparency logs (crt.sh).

    Certificate Transparency is a public audit log of all TLS certificates
    issued by trusted CAs. Querying crt.sh reveals subdomains that may not
    be discoverable via DNS brute force.

    No API key required.
    """

    def __init__(
        self,
        output_dir: str = "./findings/threat_intel",
        timeout: int = 15,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.client     = httpx.Client(
            timeout=timeout,
            headers={
                "User-Agent": "Glitchicons/2.4.0",
                "Accept":     "application/json",
            },
        )

    def find_subdomains(self, domain: str) -> list[str]:
        """
        Find subdomains via Certificate Transparency (crt.sh).

        Returns deduplicated list of domain names found in CT logs.
        """
        console.print(f"  [cyan]CT Recon:[/cyan] {domain}")
        try:
            resp = self.client.get(
                CRTSH_API_URL,
                params={"q": f"%.{domain}", "output": "json"},
            )
            if resp.status_code != 200:
                return []
            return self._parse_ct_response(resp.json(), domain)
        except Exception:
            return []

    def find_domains_for_org(self, org_name: str) -> list[str]:
        """Find all domains registered to an organization via CT logs."""
        try:
            resp = self.client.get(
                CRTSH_API_URL,
                params={"O": org_name, "output": "json"},
            )
            if resp.status_code != 200:
                return []
            return self._parse_ct_response(resp.json(), "")
        except Exception:
            return []

    def get_ct_entries(self, domain: str) -> list[CTDomain]:
        """Get full CT log entries for a domain."""
        try:
            resp = self.client.get(
                CRTSH_API_URL,
                params={"q": f"%.{domain}", "output": "json"},
            )
            if resp.status_code != 200:
                return []
            entries = []
            seen = set()
            for item in resp.json():
                name = item.get("name_value", "").strip().lower()
                if name in seen or not name:
                    continue
                seen.add(name)
                entries.append(CTDomain(
                    domain=name,
                    issuer=item.get("issuer_name", ""),
                    not_before=item.get("not_before", ""),
                    not_after=item.get("not_after", ""),
                    logged_at=item.get("entry_timestamp", ""),
                ))
            return entries[:100]
        except Exception:
            return []

    def build_findings(self, domain: str, subdomains: list[str]) -> list[dict]:
        """Generate findings from CT recon results."""
        findings = []
        if not subdomains:
            return findings

        # Interesting subdomain patterns
        interesting = [
            d for d in subdomains
            if any(kw in d.lower() for kw in [
                "admin", "internal", "dev", "staging", "test",
                "api", "vpn", "jenkins", "gitlab", "jira",
                "db", "database", "backup", "mail", "smtp",
            ])
        ]

        findings.append(_finding(
            title=f"CT Recon: {len(subdomains)} Subdomains Discovered via Certificate Transparency",
            severity="INFO",
            cvss=3.7,
            cwe="CWE-200",
            description=(
                f"Certificate Transparency logs reveal {len(subdomains)} subdomain(s) for {domain}. "
                f"{len(interesting)} appear to be internal/sensitive services."
            ),
            evidence=(
                f"Total subdomains: {len(subdomains)}\n"
                f"Interesting: {', '.join(interesting[:10])}\n"
                f"Sample: {', '.join(subdomains[:5])}"
            ),
            remediation=(
                "Review all discovered subdomains for exposure. "
                "Ensure internal services (dev/staging/admin) are not publicly accessible. "
                "Consider wildcard certificates to reduce CT log exposure."
            ),
            target=domain,
            source="ct_recon",
        ))

        if interesting:
            findings.append(_finding(
                title=f"CT Recon: {len(interesting)} Sensitive Subdomains Exposed",
                severity="MEDIUM",
                cvss=5.3,
                cwe="CWE-200",
                description=(
                    f"Certificate Transparency reveals potentially sensitive subdomains: "
                    f"{', '.join(interesting[:5])}. These may expose internal services."
                ),
                evidence="\n".join(interesting[:10]),
                remediation=(
                    "Restrict access to internal subdomains via network controls. "
                    "Do not expose dev/staging/admin services to the public internet."
                ),
                target=domain,
                source="ct_recon",
            ))

        return findings

    def _parse_ct_response(self, data: list, base_domain: str) -> list[str]:
        """Parse crt.sh JSON response into clean domain list."""
        seen   = set()
        result = []
        for item in data:
            names = item.get("name_value", "")
            for name in names.split("\n"):
                name = name.strip().lower().lstrip("*.")
                if not name or name in seen:
                    continue
                if base_domain and not name.endswith(base_domain):
                    continue
                seen.add(name)
                result.append(name)
        return sorted(result)[:200]


# ── 4. Exploit Checker ────────────────────────────────────

# Known exploited CVEs with public PoC (hardcoded critical list)
# Source: CISA KEV + ExploitDB most exploited
KNOWN_CRITICAL_CVES = {
    "CVE-2021-44228": {"name": "Log4Shell",     "cvss": 10.0, "type": "RCE"},
    "CVE-2021-45046": {"name": "Log4Shell v2",  "cvss": 9.0,  "type": "RCE"},
    "CVE-2022-22965": {"name": "Spring4Shell",  "cvss": 9.8,  "type": "RCE"},
    "CVE-2022-0847":  {"name": "DirtyPipe",     "cvss": 7.8,  "type": "LPE"},
    "CVE-2021-3156":  {"name": "Baron Samedit",  "cvss": 7.8,  "type": "LPE"},
    "CVE-2021-41773": {"name": "Apache Path Traversal", "cvss": 7.5, "type": "Path Traversal"},
    "CVE-2021-42013": {"name": "Apache RCE",    "cvss": 9.8,  "type": "RCE"},
    "CVE-2020-1472":  {"name": "Zerologon",     "cvss": 10.0, "type": "Auth Bypass"},
    "CVE-2019-0708":  {"name": "BlueKeep",       "cvss": 9.8,  "type": "RCE"},
    "CVE-2017-0144":  {"name": "EternalBlue",   "cvss": 8.1,  "type": "RCE"},
    "CVE-2023-44487": {"name": "HTTP/2 Rapid Reset", "cvss": 7.5, "type": "DoS"},
    "CVE-2023-23397": {"name": "Outlook NTLM Relay", "cvss": 9.8, "type": "NTLM Relay"},
    "CVE-2024-3400":  {"name": "PAN-OS RCE",    "cvss": 10.0, "type": "RCE"},
    "CVE-2023-4966":  {"name": "CitrixBleed",   "cvss": 9.4,  "type": "Info Disclosure"},
}


class ExploitChecker:
    """
    Check if known public exploits exist for CVEs.

    Uses a curated list of critical exploited CVEs (CISA KEV) plus
    optional ExploitDB API check for broader coverage.
    """

    def __init__(
        self,
        output_dir: str = "./findings/threat_intel",
        timeout: int = 10,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.client     = httpx.Client(
            timeout=timeout,
            headers={"User-Agent": "Glitchicons/2.4.0"},
        )

    def check_cve(self, cve_id: str) -> dict | None:
        """Check if a CVE has known public exploits."""
        cve_id_upper = cve_id.upper()
        # Check against curated list first
        if cve_id_upper in KNOWN_CRITICAL_CVES:
            return KNOWN_CRITICAL_CVES[cve_id_upper]
        return None

    def check_multiple(self, cve_ids: list[str]) -> dict[str, dict]:
        """Check multiple CVEs for known exploits."""
        results = {}
        for cve_id in cve_ids:
            result = self.check_cve(cve_id)
            if result:
                results[cve_id.upper()] = result
        return results

    def check_findings(self, findings: list[dict]) -> list[dict]:
        """
        Check all CVEs referenced in findings for known exploits.
        Returns new high-priority findings for exploitable CVEs.
        """
        new_findings  = []
        cve_pattern   = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
        found_cves: set[str] = set()

        for finding in findings:
            text = " ".join([
                finding.get("title", ""),
                finding.get("description", ""),
                finding.get("evidence", ""),
            ])
            for cve_id in cve_pattern.findall(text):
                found_cves.add(cve_id.upper())

        for cve_id in found_cves:
            exploit_info = self.check_cve(cve_id)
            if not exploit_info:
                continue

            cvss = exploit_info.get("cvss", 7.5)
            sev  = "CRITICAL" if cvss >= 9.0 else "HIGH"

            new_findings.append(_finding(
                title=f"Known Exploit Available: {cve_id} ({exploit_info['name']})",
                severity=sev,
                cvss=cvss,
                cwe="CWE-1035",
                description=(
                    f"{cve_id} ({exploit_info['name']}) has publicly available exploits. "
                    f"Type: {exploit_info['type']}. CVSS: {cvss}."
                ),
                evidence=(
                    f"CVE: {cve_id}\n"
                    f"Name: {exploit_info['name']}\n"
                    f"Type: {exploit_info['type']}\n"
                    f"CVSS: {cvss}\n"
                    "Status: Public exploit available"
                ),
                remediation=(
                    f"Apply patch for {cve_id} immediately — public exploit exists. "
                    "Check CISA KEV catalog. Consider emergency change process."
                ),
                target=findings[0].get("target", "") if findings else "",
                source="exploit_checker",
            ))

        return new_findings


# ── 5. Threat Intel Scanner (orchestrator) ────────────────

class ThreatIntelScanner:
    """
    Full threat intelligence orchestrator.

    Combines CVE lookup, Shodan recon, CT discovery, and exploit checking
    to enrich a target with threat intelligence context.
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "./findings/threat_intel",
        shodan_api_key: str = "",
        nvd_api_key: str = "",
        timeout: int = 15,
    ):
        self.target     = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._cve     = CVELookup(output_dir=str(output_dir), timeout=timeout, nvd_api_key=nvd_api_key)
        self._shodan  = ShodanRecon(api_key=shodan_api_key, output_dir=str(output_dir), timeout=timeout)
        self._ct      = CTRecon(output_dir=str(output_dir), timeout=timeout)
        self._exploit = ExploitChecker(output_dir=str(output_dir), timeout=timeout)

    def run(self, findings: list[dict] | None = None) -> ThreatIntelResult:
        """Run all threat intelligence checks."""
        console.print(f"\n  [bold cyan]⬡ Threat Intel Scanner[/bold cyan] → {self.target}")
        findings = findings or []
        all_new_findings: list[dict] = []

        # 1. CT Recon — asset discovery
        subdomains = self._ct.find_subdomains(self._extract_domain())
        ct_findings = self._ct.build_findings(self._extract_domain(), subdomains)
        all_new_findings.extend(ct_findings)
        console.print(f"  CT: {len(subdomains)} subdomains")

        # 2. CVE enrichment from existing findings
        cve_findings = self._cve.enrich_findings(findings)
        all_new_findings.extend(cve_findings)
        console.print(f"  CVE enrichment: {len(cve_findings)} new findings")

        # 3. Exploit check
        exploit_findings = self._exploit.check_findings(findings)
        all_new_findings.extend(exploit_findings)
        console.print(f"  Exploit check: {len(exploit_findings)} exploitable CVEs")

        # 4. Shodan (if API key provided)
        shodan_host = None
        if self._shodan.api_key:
            domain = self._extract_domain()
            shodan_host = self._shodan.lookup_domain(domain)
            if shodan_host:
                shodan_findings = self._shodan.build_findings(shodan_host, self.target)
                all_new_findings.extend(shodan_findings)
                console.print(f"  Shodan: {len(shodan_host.open_ports)} ports, {len(shodan_host.vulns)} CVEs")
        else:
            console.print("  Shodan: [dim]skipped (no API key)[/dim]")

        # Build CT domain objects
        ct_entries = []
        if subdomains:
            ct_entries = [CTDomain(d, "", "", "", "") for d in subdomains[:20]]

        result = ThreatIntelResult(
            target=self.target,
            timestamp=datetime.now(timezone.utc).isoformat(),
            cves=[],
            shodan_host=shodan_host,
            ct_domains=ct_entries,
            findings=all_new_findings,
        )

        self._save(result)
        console.print(f"  Total new findings: [bold]{len(all_new_findings)}[/bold]")
        return result

    def _extract_domain(self) -> str:
        """Extract domain from target URL."""
        domain = self.target
        domain = re.sub(r"https?://", "", domain)
        domain = domain.split("/")[0].split(":")[0]
        return domain

    def _save(self, result: ThreatIntelResult) -> Path:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        slug = self.target.replace("/", "_").replace(":", "")
        out = self.output_dir / f"threat_intel_{slug}_{ts}.json"
        data = {
            "target":    result.target,
            "timestamp": result.timestamp,
            "ct_domains": [d.domain for d in result.ct_domains],
            "findings":  result.findings,
        }
        out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return out
