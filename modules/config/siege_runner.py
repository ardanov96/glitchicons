"""
Siege Runner — modules/config/siege_runner.py

Orchestrator yang membaca EngagementConfig dan menjalankan
semua modul yang diaktifkan secara berurutan.

Usage:
    from modules.config.config_loader import ConfigLoader
    from modules.config.siege_runner import SiegeRunner

    cfg = ConfigLoader.load("engagement.yaml")
    runner = SiegeRunner(cfg)
    runner.run()

Author: ardanov96
"""

import json
import time
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from modules.config.config_loader import EngagementConfig

console = Console()


class SiegeRunner:
    """
    Orchestrate a full engagement from config file.
    Runs enabled modules in order: recon → scan → inject → auth → report.
    """

    MODULE_ORDER = [
        "recon",
        "scan",
        "graphql",
        "inject",
        "jwt",
        "idor",
        "auth",
        "brute_force",
        "seeds",
    ]

    def __init__(self, config: EngagementConfig):
        self.config = config
        self.findings: list[dict] = []
        self.run_log: list[dict] = []
        self.start_time = None
        self.output_dir = Path(config.output.dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self) -> list[dict]:
        """Run full engagement. Return combined findings."""
        self.start_time = datetime.now()

        self._print_banner()

        enabled = self.config.enabled_modules()
        if not enabled:
            console.print("[yellow]  No modules enabled. Edit your config and enable at least one module.[/yellow]")
            return []

        console.print(f"  Modules to run: [cyan]{', '.join(enabled)}[/cyan]\n")

        # Run each module in order
        for module_name in self.MODULE_ORDER:
            if module_name not in enabled:
                continue
            self._run_module(module_name)
            time.sleep(self.config.stealth.delay)

        # Generate combined report
        self._generate_report()
        self._print_final_summary()

        return self.findings

    def _run_module(self, name: str):
        """Dispatch to appropriate module runner."""
        console.rule(f"[bold cyan]  {name.upper()}[/bold cyan]")

        runners = {
            "recon":       self._run_recon,
            "scan":        self._run_scan,
            "graphql":     self._run_graphql,
            "inject":      self._run_inject,
            "jwt":         self._run_jwt,
            "idor":        self._run_idor,
            "auth":        self._run_auth,
            "brute_force": self._run_brute_force,
            "seeds":       self._run_seeds,
        }

        runner_fn = runners.get(name)
        if not runner_fn:
            console.print(f"  [yellow]Unknown module: {name}[/yellow]")
            return

        t_start = time.time()
        try:
            module_findings = runner_fn()
            elapsed = time.time() - t_start
            self.findings.extend(module_findings or [])
            self.run_log.append({
                "module": name,
                "status": "ok",
                "findings": len(module_findings or []),
                "elapsed_s": round(elapsed, 2),
            })
            console.print(
                f"  [green]Done[/green] — "
                f"{len(module_findings or [])} finding(s) in {elapsed:.1f}s"
            )
        except ImportError as e:
            console.print(f"  [yellow]Module not available: {e}[/yellow]")
            self.run_log.append({"module": name, "status": "skip", "reason": str(e)})
        except Exception as e:
            console.print(f"  [red]Error in {name}: {e}[/red]")
            self.run_log.append({"module": name, "status": "error", "reason": str(e)})

    # ── Module Runners ────────────────────────────────────

    def _run_recon(self) -> list[dict]:
        from modules.recon.recon_engine import ReconEngine
        cfg = self.config.modules.recon
        target_cfg = self.config.target
        engine = ReconEngine(
            domain=target_cfg.domain,
            mode=cfg.mode,
            output_dir=str(self.output_dir / "recon"),
        )
        return engine.run() or []

    def _run_scan(self) -> list[dict]:
        from modules.scanner.nuclei_wrapper import NucleiWrapper
        cfg = self.config.modules.scan
        scanner = NucleiWrapper(
            target=self.config.target.base_url,
            profile=cfg.profile,
            severity=cfg.severity,
            output_dir=str(self.output_dir / "nuclei"),
        )
        return scanner.run() or []

    def _run_graphql(self) -> list[dict]:
        from modules.inject.graphql_fuzzer import GraphQLFuzzer
        cfg = self.config.modules.graphql
        target = self.config.target.base_url
        if cfg.endpoint:
            target = target + cfg.endpoint
        fuzzer = GraphQLFuzzer(
            target=target,
            output_dir=str(self.output_dir / "graphql"),
            delay=self.config.stealth.delay,
        )
        return fuzzer.run(
            introspect=cfg.introspect,
            dos_test=cfg.dos_test,
        )

    def _run_inject(self) -> list[dict]:
        findings = []
        cfg = self.config.modules.inject
        base = self.config.target.base_url

        for endpoint in cfg.endpoints:
            url = base + endpoint

            if cfg.xss:
                from modules.inject.xss_tester import XSSTester
                findings.extend(XSSTester(url, output_dir=str(self.output_dir / "xss")).run() or [])

            if cfg.sqli:
                from modules.inject.sqli_tester import SQLiTester
                findings.extend(SQLiTester(url, output_dir=str(self.output_dir / "sqli")).run() or [])

            if cfg.ssrf:
                from modules.inject.ssrf_tester import SSRFTester
                findings.extend(SSRFTester(url, output_dir=str(self.output_dir / "ssrf")).run() or [])

            if cfg.ssti:
                from modules.inject.ssti_tester import SSTITester
                findings.extend(SSTITester(url, output_dir=str(self.output_dir / "ssti")).run() or [])

            if cfg.xxe:
                from modules.inject.xxe_tester import XXETester
                findings.extend(XXETester(url, output_dir=str(self.output_dir / "xxe")).run() or [])

        return findings

    def _run_jwt(self) -> list[dict]:
        from modules.auth.jwt_analyzer import JWTAnalyzer
        cfg = self.config.modules.jwt
        if not cfg.token:
            console.print("  [yellow]No JWT token provided in config, skip[/yellow]")
            return []
        analyzer = JWTAnalyzer(
            token=cfg.token,
            output_dir=str(self.output_dir / "jwt"),
        )
        return analyzer.run() or []

    def _run_idor(self) -> list[dict]:
        from modules.business_logic.idor_fuzzer import IDORFuzzer
        cfg = self.config.modules.idor
        base = self.config.target.base_url
        fuzzer = IDORFuzzer(
            target=base + cfg.endpoint,
            output_dir=str(self.output_dir / "idor"),
        )
        return fuzzer.run() or []

    def _run_auth(self) -> list[dict]:
        findings = []
        cfg = self.config.modules.auth
        base = self.config.target.base_url

        if cfg.oauth:
            from modules.auth.oauth_tester import OAuthTester
            findings.extend(OAuthTester(base, output_dir=str(self.output_dir / "auth")).run() or [])

        if cfg.session:
            from modules.auth.session_analyzer import SessionAnalyzer
            findings.extend(SessionAnalyzer(base, output_dir=str(self.output_dir / "auth")).run() or [])

        return findings

    def _run_brute_force(self) -> list[dict]:
        console.print(
            "  [yellow]Brute force via config: run brute_force.py directly for full control.[/yellow]"
        )
        console.print(f"  Target   : {self.config.target.base_url}")
        console.print(f"  Emails   : {self.config.modules.brute_force.emails}")
        console.print(f"  Passwords: {self.config.modules.brute_force.passwords}")
        return []

    def _run_seeds(self) -> list[dict]:
        from seed_generator import SeedGenerator
        cfg = self.config.seeds
        gen = SeedGenerator(output_dir=str(self.output_dir / "seeds"))
        for seed_type in cfg.types:
            gen.generate(seed_type=seed_type, count=cfg.count)
        return []

    # ── Reporting ─────────────────────────────────────────

    def _generate_report(self):
        """Save combined JSON + Markdown report."""
        elapsed = (datetime.now() - self.start_time).total_seconds()

        report = {
            "tool": "glitchicons",
            "version": "0.7.0",
            "target": self.config.target.domain,
            "org": self.config.output.org,
            "report_type": self.config.output.report_type,
            "timestamp": self.start_time.isoformat(),
            "duration_s": round(elapsed, 2),
            "modules_run": self.run_log,
            "total_findings": len(self.findings),
            "severity_summary": self._severity_count(),
            "findings": sorted(self.findings, key=lambda x: x.get("cvss", 0), reverse=True),
        }

        # JSON report
        if "json" in self.config.output.formats:
            json_path = self.output_dir / f"siege_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            json_path.write_text(json.dumps(report, indent=2, default=str))
            console.print(f"\n  JSON report: [cyan]{json_path}[/cyan]")

        # Markdown report
        if "markdown" in self.config.output.formats:
            md_path = self.output_dir / f"siege_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            md_path.write_text(self._build_markdown(report))
            console.print(f"  MD report  : [cyan]{md_path}[/cyan]")

    def _build_markdown(self, report: dict) -> str:
        """Generate Markdown pentest report."""
        sev = report["severity_summary"]
        lines = [
            f"# Pentest Report — {report['target']}",
            f"",
            f"**Organization:** {report['org']}",
            f"**Date:** {self.start_time.strftime('%Y-%m-%d')}",
            f"**Tool:** GLITCHICONS v{report['version']}",
            f"**Duration:** {report['duration_s']}s",
            f"**Report Type:** {report['report_type']}",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            f"Total findings: **{report['total_findings']}**",
            f"",
            f"| Severity | Count |",
            f"|---|---|",
            f"| CRITICAL | {sev.get('CRITICAL', 0)} |",
            f"| HIGH     | {sev.get('HIGH', 0)} |",
            f"| MEDIUM   | {sev.get('MEDIUM', 0)} |",
            f"| LOW      | {sev.get('LOW', 0)} |",
            f"",
            f"---",
            f"",
            f"## Findings",
            f"",
        ]

        for f in report["findings"]:
            lines += [
                f"### [{f.get('severity', 'INFO')}] {f.get('title', 'Untitled')}",
                f"",
                f"**CVSS:** {f.get('cvss', 'N/A')} | **CWE:** {f.get('cwe', 'N/A')}",
                f"",
                f"**Description:** {f.get('description', '')}",
                f"",
                f"**Evidence:**",
                f"```",
                f"{f.get('evidence', '')}",
                f"```",
                f"",
                f"**Remediation:** {f.get('remediation', '')}",
                f"",
                f"---",
                f"",
            ]

        return "\n".join(lines)

    def _severity_count(self) -> dict:
        from collections import Counter
        return dict(Counter(f.get("severity", "INFO") for f in self.findings))

    def _print_banner(self):
        cfg = self.config
        console.print(Panel(
            f"[bold cyan]GLITCHICONS SIEGE[/bold cyan] — Full Engagement\n\n"
            f"Target  : [yellow]{cfg.target.base_url}[/yellow]\n"
            f"Org     : {cfg.output.org}\n"
            f"LLM     : {cfg.llm.provider} / {cfg.llm.model}\n"
            f"Output  : {cfg.output.dir}\n"
            f"Stealth : delay={cfg.stealth.delay}s, tor={cfg.stealth.use_tor}",
            title="SIEGE MODE",
            border_style="cyan",
        ))

    def _print_final_summary(self):
        elapsed = (datetime.now() - self.start_time).total_seconds()
        sev = self._severity_count()

        table = Table(show_header=True, header_style="bold magenta", title="Final Results")
        table.add_column("Module", style="cyan")
        table.add_column("Status", width=8)
        table.add_column("Findings", width=9)
        table.add_column("Time (s)", width=9)

        for entry in self.run_log:
            status_color = {"ok": "green", "skip": "yellow", "error": "red"}.get(entry["status"], "white")
            table.add_row(
                entry["module"],
                f"[{status_color}]{entry['status']}[/{status_color}]",
                str(entry.get("findings", "-")),
                str(entry.get("elapsed_s", "-")),
            )

        console.print(table)
        console.print(
            f"\n  [bold]Total:[/bold] {len(self.findings)} findings in {elapsed:.1f}s | "
            f"[bold red]CRIT: {sev.get('CRITICAL', 0)}[/bold red] | "
            f"[red]HIGH: {sev.get('HIGH', 0)}[/red] | "
            f"[yellow]MED: {sev.get('MEDIUM', 0)}[/yellow]\n"
        )
