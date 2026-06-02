"""
Multi-Target Orchestrator — modules/core/multi_target.py

Run security scans against multiple targets concurrently.

Features:
  - Concurrent multi-target scanning
  - Per-target module configuration
  - Result aggregation across all targets
  - Target grouping (by domain, subnet, tag)
  - Progress tracking per target
  - Combined report generation
  - Rate limiting across all targets

Usage:
    from modules.core.multi_target import MultiTargetOrchestrator, Target

    mto = MultiTargetOrchestrator(concurrency=3)

    mto.add_target(Target(
        url="https://target1.com",
        name="Target Corp API",
        tags=["api", "fintech"],
    ))
    mto.add_target(Target(
        url="https://target2.com",
        name="Target Corp Web",
        tags=["web"],
    ))

    results = await mto.run(modules=["cors", "graphql", "subdomain"])
    mto.print_summary()

Author: ardanov96
"""

import asyncio
import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

console = Console()

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# ── Target definition ─────────────────────────────────────

@dataclass
class Target:
    """A single scan target."""
    url:   str
    name:  str = ""
    tags:  list[str] = field(default_factory=list)
    token: str | None = None
    extra: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.name:
            self.name = self.url


# ── Per-target result ─────────────────────────────────────

@dataclass
class TargetResult:
    """Aggregated scan result for one target."""
    target:      Target
    findings:    list[dict]
    modules_run: list[str]
    duration_s:  float
    started_at:  str
    finished_at: str
    status:      str  # "success" | "partial" | "error"
    errors:      list[str] = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def by_severity(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            sev = f.get("severity", "INFO")
            if sev in counts:
                counts[sev] += 1
        return counts

    @property
    def risk_level(self) -> str:
        for sev in SEVERITY_ORDER:
            if self.by_severity.get(sev, 0) > 0:
                return sev
        return "CLEAN"


# ── Module registry ───────────────────────────────────────

@dataclass
class ModuleSpec:
    """Specification for a scannable module."""
    name:     str
    fn:       Callable[[str, dict], list[dict]]
    timeout:  float = 120.0
    tags:     list[str] = field(default_factory=list)


class MultiTargetOrchestrator:
    """
    Run security scans against multiple targets concurrently.

    Manages:
    - Target queue with concurrent scanning
    - Per-target module execution
    - Cross-target finding aggregation
    - Progress visualization
    - Combined JSON report

    Usage:
        mto = MultiTargetOrchestrator(concurrency=3)
        mto.add_target(Target("https://target1.com"))
        mto.add_target(Target("https://target2.com"))
        mto.register_module("cors", cors_fn)
        results = await mto.run()
    """

    def __init__(
        self,
        concurrency: int = 3,
        output_dir: str = "./findings/multi",
        max_workers: int = 10,
    ):
        self.concurrency  = concurrency
        self.output_dir   = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_workers  = max_workers

        self._targets:    list[Target] = []
        self._modules:    dict[str, ModuleSpec] = {}
        self._results:    list[TargetResult] = []
        self._executor    = ThreadPoolExecutor(max_workers=max_workers)
        self._start_time  = 0.0

    # ── Registration ──────────────────────────────────────

    def add_target(self, target: Target) -> "MultiTargetOrchestrator":
        self._targets.append(target)
        return self

    def add_targets(self, targets: list[Target]) -> "MultiTargetOrchestrator":
        for t in targets:
            self.add_target(t)
        return self

    def add_targets_from_list(
        self,
        urls: list[str],
        tags: list[str] | None = None,
    ) -> "MultiTargetOrchestrator":
        """Bulk add targets from URL list."""
        for url in urls:
            self.add_target(Target(url=url, tags=tags or []))
        return self

    def register_module(
        self,
        name: str,
        fn: Callable,
        timeout: float = 120.0,
        tags: list[str] | None = None,
    ) -> "MultiTargetOrchestrator":
        """Register a scan module."""
        self._modules[name] = ModuleSpec(
            name=name, fn=fn, timeout=timeout, tags=tags or []
        )
        return self

    # ── Execution ─────────────────────────────────────────

    async def run(
        self,
        modules: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> list[TargetResult]:
        """
        Scan all targets concurrently.

        Args:
            modules: Module names to run (None = all registered)
            tags:    Filter targets by tag (None = all targets)

        Returns:
            List of TargetResult, one per target
        """
        self._start_time = time.monotonic()
        self._results    = []

        # Filter targets
        targets = self._targets
        if tags:
            targets = [t for t in targets if any(tag in t.tags for tag in tags)]

        # Filter modules
        module_specs = list(self._modules.values())
        if modules:
            module_specs = [m for m in module_specs if m.name in modules]

        if not targets:
            console.print("  [yellow]No targets to scan[/yellow]")
            return []

        if not module_specs:
            console.print("  [yellow]No modules registered[/yellow]")
            return []

        console.print(
            f"\n  [bold cyan]⬡ Multi-Target Scan[/bold cyan]\n"
            f"  Targets: {len(targets)} | Modules: {len(module_specs)} | "
            f"Concurrency: {self.concurrency}"
        )

        sem = asyncio.Semaphore(self.concurrency)

        async def scan_target(target: Target) -> TargetResult:
            async with sem:
                return await self._scan_one(target, module_specs)

        results = await asyncio.gather(*[scan_target(t) for t in targets])
        self._results = list(results)
        self._save_combined()
        return self._results

    async def _scan_one(
        self,
        target: Target,
        modules: list[ModuleSpec],
    ) -> TargetResult:
        """Scan a single target with all modules."""
        started   = datetime.now(timezone.utc).isoformat()
        t_start   = time.monotonic()
        all_finds = []
        modules_run = []
        errors    = []

        console.print(f"  [cyan]→[/cyan] {target.name} ({target.url})")

        for spec in modules:
            try:
                loop    = asyncio.get_event_loop()
                kwargs  = {"token": target.token} if target.token else {}
                future  = loop.run_in_executor(
                    self._executor,
                    lambda s=spec, t=target, kw=kwargs: s.fn(t.url, **kw),
                )
                findings = await asyncio.wait_for(future, timeout=spec.timeout)
                all_finds.extend(findings or [])
                modules_run.append(spec.name)
            except asyncio.TimeoutError:
                errors.append(f"{spec.name}: timeout ({spec.timeout}s)")
            except Exception as e:
                errors.append(f"{spec.name}: {e}")

        duration = time.monotonic() - t_start
        status   = "success" if not errors else ("partial" if all_finds else "error")

        result = TargetResult(
            target=target,
            findings=all_finds,
            modules_run=modules_run,
            duration_s=round(duration, 2),
            started_at=started,
            finished_at=datetime.now(timezone.utc).isoformat(),
            status=status,
            errors=errors,
        )

        sev = result.risk_level
        color = {"CRITICAL": "red", "HIGH": "yellow",
                 "MEDIUM": "white", "LOW": "green", "CLEAN": "dim"}.get(sev, "white")
        console.print(
            f"  [dim]✓[/dim] {target.name} — "
            f"[{color}]{sev}[/{color}] | "
            f"{result.finding_count} findings | {duration:.1f}s"
        )
        return result

    # ── Aggregation ───────────────────────────────────────

    def all_findings(self) -> list[dict]:
        """All findings across all targets."""
        return [f for r in self._results for f in r.findings]

    def findings_by_target(self) -> dict[str, list[dict]]:
        """Group findings by target URL."""
        return {r.target.url: r.findings for r in self._results}

    def findings_by_severity(self) -> dict[str, list[dict]]:
        """Group all findings by severity."""
        groups: dict[str, list[dict]] = {s: [] for s in SEVERITY_ORDER}
        for f in self.all_findings():
            sev = f.get("severity", "INFO")
            if sev in groups:
                groups[sev].append(f)
        return groups

    def top_targets(self, n: int = 5) -> list[TargetResult]:
        """Return top N targets by finding count."""
        return sorted(self._results, key=lambda r: r.finding_count, reverse=True)[:n]

    # ── Reporting ─────────────────────────────────────────

    def print_summary(self) -> None:
        elapsed = time.monotonic() - self._start_time
        all_f   = self.all_findings()
        by_sev  = self.findings_by_severity()

        console.print(f"\n  [bold cyan]⬡ Multi-Target Scan Complete[/bold cyan]")
        console.print(
            f"  Targets: {len(self._results)} | "
            f"Findings: {len(all_f)} | "
            f"Duration: {elapsed:.1f}s"
        )

        for sev in SEVERITY_ORDER:
            count = len(by_sev.get(sev, []))
            if count:
                color = {"CRITICAL":"red","HIGH":"yellow","MEDIUM":"white",
                         "LOW":"green","INFO":"blue"}[sev]
                console.print(f"  [{color}]{sev}[/{color}]: {count}")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Target",   style="cyan")
        table.add_column("Risk",     width=10)
        table.add_column("Findings", width=10)
        table.add_column("Duration", width=10)
        table.add_column("Status",   width=10)

        for r in sorted(self._results, key=lambda x: x.finding_count, reverse=True):
            sev   = r.risk_level
            color = {"CRITICAL":"red","HIGH":"yellow","MEDIUM":"white",
                     "LOW":"green","CLEAN":"dim"}.get(sev, "white")
            table.add_row(
                r.target.name[:30],
                f"[{color}]{sev}[/{color}]",
                str(r.finding_count),
                f"{r.duration_s:.1f}s",
                r.status,
            )
        console.print(table)

    def _save_combined(self) -> Path:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = self.output_dir / f"multi_scan_{ts}.json"
        data = {
            "scan_time":     datetime.now(timezone.utc).isoformat(),
            "targets":       len(self._results),
            "total_findings": len(self.all_findings()),
            "results": [
                {
                    "target":        r.target.url,
                    "name":          r.target.name,
                    "risk":          r.risk_level,
                    "finding_count": r.finding_count,
                    "by_severity":   r.by_severity,
                    "duration_s":    r.duration_s,
                    "status":        r.status,
                    "findings":      r.findings,
                    "errors":        r.errors,
                }
                for r in self._results
            ],
        }
        out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        console.print(f"  [green]Report:[/green] {out}")
        return out

    @property
    def target_count(self) -> int:
        return len(self._targets)

    @property
    def module_count(self) -> int:
        return len(self._modules)
