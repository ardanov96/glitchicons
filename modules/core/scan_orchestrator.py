"""
Scan Orchestrator — modules/core/scan_orchestrator.py

Concurrent multi-module scan orchestration for Glitchicons.

Features:
  - Run multiple scan modules in parallel (asyncio + ThreadPoolExecutor)
  - Priority queue: CRITICAL modules run first
  - Module dependency resolution (e.g. recon before injection)
  - Timeout per module
  - Finding aggregation and deduplication
  - Real-time progress reporting
  - Graceful cancellation (Ctrl+C)
  - Scan result persistence

Usage:
    from modules.core.scan_orchestrator import ScanOrchestrator, ScanModule

    orchestrator = ScanOrchestrator(target="https://target.com", concurrency=5)

    # Register modules
    orchestrator.add_module(ScanModule(
        name="cors",
        fn=lambda target: CORSChecker(target=target).run(),
        priority=1,
        timeout=60,
    ))
    orchestrator.add_module(ScanModule(
        name="graphql",
        fn=lambda target: GraphQLFuzzer(target=target).run(),
        priority=2,
        timeout=120,
    ))

    # Run all
    results = await orchestrator.run()
    orchestrator.print_summary(results)

Author: ardanov96
"""

import asyncio
import json
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from rich.console import Console
from rich.table import Table

console = Console()


# ── Scan Module Definition ────────────────────────────────

@dataclass
class ScanModule:
    """
    Definition of a single scan module for the orchestrator.

    Args:
        name:      Module identifier (e.g. "cors", "graphql")
        fn:        Callable(target: str) -> list[dict] — sync or async
        priority:  Lower = runs first (1 = highest priority)
        timeout:   Max seconds for this module (0 = no timeout)
        enabled:   Whether to run this module
        tags:      Categories for filtering (e.g. ["recon", "inject"])
        depends_on: Module names that must complete first
    """
    name:       str
    fn:         Callable[[str], list[dict]]
    priority:   int   = 5
    timeout:    float = 120.0
    enabled:    bool  = True
    tags:       list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)


# ── Module Result ─────────────────────────────────────────

@dataclass
class ModuleResult:
    """Result from a single scan module execution."""
    module:      str
    target:      str
    findings:    list[dict]
    started_at:  str
    finished_at: str
    duration_s:  float
    status:      str  # "success" | "timeout" | "error" | "skipped"
    error:       str | None = None

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.get("severity") == "CRITICAL")


# ── Finding Deduplicator ──────────────────────────────────

class FindingDeduplicator:
    """
    Deduplicate findings from multiple scan modules.

    Deduplication strategy:
    - Same title + same target → deduplicate, keep highest severity
    - Same CWE + same target (within same module) → deduplicate
    """

    def deduplicate(self, findings: list[dict]) -> list[dict]:
        """Remove duplicate findings, keeping highest severity."""
        seen:   dict[str, dict] = {}
        order   = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

        for f in findings:
            key = self._key(f)
            if key not in seen:
                seen[key] = f
            else:
                # Keep higher severity
                existing_sev = seen[key].get("severity", "INFO")
                new_sev      = f.get("severity", "INFO")
                if order.index(new_sev) < order.index(existing_sev):
                    seen[key] = f

        return list(seen.values())

    def _key(self, finding: dict) -> str:
        title  = finding.get("title", "")[:50]
        target = finding.get("target", "")[:80]
        cwe    = finding.get("cwe", "")
        return f"{title}|{target}|{cwe}"


# ── Scan Orchestrator ─────────────────────────────────────

class ScanOrchestrator:
    """
    Concurrent multi-module scan orchestrator.

    Runs registered scan modules against a target with:
    - Configurable concurrency (default: 4 modules in parallel)
    - Priority ordering (lower priority number = runs first)
    - Per-module timeout enforcement
    - Finding deduplication across modules
    - Real-time progress + summary reporting

    Usage:
        orchestrator = ScanOrchestrator(
            target="https://target.com",
            concurrency=4,
            output_dir="./findings",
        )
        orchestrator.add_module(ScanModule("cors", cors_fn, priority=1))
        orchestrator.add_module(ScanModule("graphql", graphql_fn, priority=2))
        results = await orchestrator.run()
    """

    def __init__(
        self,
        target: str,
        concurrency: int = 4,
        output_dir: str = "./findings/orchestrator",
        stop_on_critical: bool = False,
        max_workers: int = 8,
    ):
        self.target           = target
        self.concurrency      = concurrency
        self.output_dir       = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.stop_on_critical = stop_on_critical
        self.max_workers      = max_workers

        self._modules:    list[ScanModule] = []
        self._results:    list[ModuleResult] = []
        self._dedup       = FindingDeduplicator()
        self._executor    = ThreadPoolExecutor(max_workers=max_workers)
        self._start_time  = 0.0
        self._cancelled   = False

    def add_module(self, module: ScanModule) -> "ScanOrchestrator":
        """Register a scan module. Returns self for chaining."""
        self._modules.append(module)
        return self

    def add_modules(self, modules: list[ScanModule]) -> "ScanOrchestrator":
        """Register multiple modules at once."""
        for m in modules:
            self.add_module(m)
        return self

    def disable_module(self, name: str) -> "ScanOrchestrator":
        """Disable a registered module by name."""
        for m in self._modules:
            if m.name == name:
                m.enabled = False
        return self

    def enable_tags(self, tags: list[str]) -> "ScanOrchestrator":
        """Enable only modules with at least one matching tag."""
        for m in self._modules:
            m.enabled = any(t in m.tags for t in tags)
        return self

    async def run(
        self,
        tags: list[str] | None = None,
    ) -> list[ModuleResult]:
        """
        Run all enabled modules concurrently.

        Args:
            tags: If provided, run only modules with matching tags

        Returns:
            List of ModuleResult, one per executed module
        """
        self._start_time = time.monotonic()
        self._results    = []
        self._cancelled  = False

        # Filter and sort
        modules = [m for m in self._modules if m.enabled]
        if tags:
            modules = [m for m in modules if any(t in m.tags for t in tags)]

        # Sort by priority then resolve dependencies
        modules = self._resolve_order(modules)

        console.print(
            f"\n  [bold cyan]⬡ Scan Orchestrator[/bold cyan] → {self.target}\n"
            f"  Modules: {len(modules)} | Concurrency: {self.concurrency}"
        )

        # Group by priority for sequential priority execution
        priority_groups: dict[int, list[ScanModule]] = defaultdict(list)
        for m in modules:
            priority_groups[m.priority].append(m)

        for priority in sorted(priority_groups.keys()):
            if self._cancelled:
                break
            group = priority_groups[priority]
            await self._run_group(group)

            # Check stop_on_critical
            if self.stop_on_critical:
                all_findings = [f for r in self._results for f in r.findings]
                if any(f.get("severity") == "CRITICAL" for f in all_findings):
                    console.print(
                        "  [red]CRITICAL finding detected — stopping scan[/red]"
                    )
                    self._cancelled = True
                    break

        self._save_results()
        return self._results

    async def _run_group(self, modules: list[ScanModule]) -> None:
        """Run a group of same-priority modules concurrently."""
        sem = asyncio.Semaphore(self.concurrency)

        async def run_one(module: ScanModule) -> None:
            async with sem:
                result = await self._run_module(module)
                self._results.append(result)
                self._print_module_result(result)

        await asyncio.gather(*[run_one(m) for m in modules])

    async def _run_module(self, module: ScanModule) -> ModuleResult:
        """Execute a single module with timeout and error handling."""
        started = datetime.now(timezone.utc).isoformat()
        t_start = time.monotonic()

        console.print(f"  [cyan]>> {module.name}[/cyan] starting...")

        try:
            # Run sync module in thread pool
            loop   = asyncio.get_event_loop()
            future = loop.run_in_executor(
                self._executor,
                module.fn,
                self.target,
            )

            if module.timeout > 0:
                findings = await asyncio.wait_for(future, timeout=module.timeout)
            else:
                findings = await future

            findings = findings or []
            duration = time.monotonic() - t_start

            return ModuleResult(
                module=module.name, target=self.target,
                findings=findings,
                started_at=started,
                finished_at=datetime.now(timezone.utc).isoformat(),
                duration_s=round(duration, 2),
                status="success",
            )

        except asyncio.TimeoutError:
            duration = time.monotonic() - t_start
            console.print(f"  [yellow]TIMEOUT:[/yellow] {module.name} ({module.timeout}s)")
            return ModuleResult(
                module=module.name, target=self.target,
                findings=[], started_at=started,
                finished_at=datetime.now(timezone.utc).isoformat(),
                duration_s=round(duration, 2),
                status="timeout",
                error=f"Timed out after {module.timeout}s",
            )

        except Exception as e:
            duration = time.monotonic() - t_start
            console.print(f"  [red]ERROR:[/red] {module.name}: {e}")
            return ModuleResult(
                module=module.name, target=self.target,
                findings=[], started_at=started,
                finished_at=datetime.now(timezone.utc).isoformat(),
                duration_s=round(duration, 2),
                status="error",
                error=str(e),
            )

    def _resolve_order(self, modules: list[ScanModule]) -> list[ScanModule]:
        """Sort modules by priority, keeping dependency order."""
        # Simple topological sort + priority sort
        completed: set[str] = set()
        ordered:   list[ScanModule] = []
        remaining  = list(modules)

        max_iter = len(modules) * 2  # prevent infinite loop
        iterations = 0

        while remaining and iterations < max_iter:
            iterations += 1
            progress = False
            for m in list(remaining):
                deps_met = all(d in completed for d in m.depends_on)
                if deps_met:
                    ordered.append(m)
                    completed.add(m.name)
                    remaining.remove(m)
                    progress = True
            if not progress:
                # Circular dependency or unresolvable — add remaining as-is
                ordered.extend(remaining)
                break

        return sorted(ordered, key=lambda m: m.priority)

    def _print_module_result(self, result: ModuleResult) -> None:
        status_str = {
            "success": f"[green]OK[/green]",
            "timeout": f"[yellow]TIMEOUT[/yellow]",
            "error":   f"[red]ERROR[/red]",
            "skipped": f"[dim]SKIP[/dim]",
        }.get(result.status, result.status)

        console.print(
            f"  {status_str} [{result.module}] "
            f"{result.finding_count} findings "
            f"({result.duration_s:.1f}s)"
            + (f" | {result.critical_count} CRITICAL" if result.critical_count else "")
        )

    def all_findings(self, deduplicate: bool = True) -> list[dict]:
        """Get all findings from all modules, optionally deduplicated."""
        all_f = [f for r in self._results for f in r.findings]
        if deduplicate:
            return self._dedup.deduplicate(all_f)
        return all_f

    def findings_by_severity(self) -> dict[str, list[dict]]:
        """Group all deduplicated findings by severity."""
        groups: dict[str, list[dict]] = {
            "CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []
        }
        for f in self.all_findings():
            sev = f.get("severity", "INFO")
            if sev in groups:
                groups[sev].append(f)
        return groups

    def print_summary(self, results: list[ModuleResult] | None = None) -> None:
        """Print a rich formatted scan summary."""
        results = results or self._results
        elapsed = time.monotonic() - self._start_time

        all_f = self.all_findings()
        by_sev = self.findings_by_severity()

        console.print(f"\n  [bold cyan]⬡ Scan Complete[/bold cyan] — {self.target}")
        console.print(f"  Duration: {elapsed:.1f}s | Modules: {len(results)} | Findings: {len(all_f)}")

        # Severity breakdown
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = len(by_sev.get(sev, []))
            if count:
                color = {"CRITICAL": "red", "HIGH": "yellow",
                         "MEDIUM": "white", "LOW": "green", "INFO": "blue"}[sev]
                console.print(f"  [{color}]{sev}[/{color}]: {count}")

        # Module table
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Module",   style="cyan", width=18)
        table.add_column("Status",   width=10)
        table.add_column("Findings", width=10)
        table.add_column("Duration", width=10)

        for r in sorted(results, key=lambda x: x.duration_s, reverse=True):
            status_str = {
                "success": "[green]OK[/green]",
                "timeout": "[yellow]TIMEOUT[/yellow]",
                "error":   "[red]ERROR[/red]",
            }.get(r.status, r.status)
            table.add_row(
                r.module, status_str,
                str(r.finding_count),
                f"{r.duration_s:.1f}s",
            )
        console.print(table)

    def _save_results(self) -> Path:
        """Save orchestrator results to JSON."""
        slug = self.target.replace("/", "_").replace(":", "").replace(".", "_")
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        out  = self.output_dir / f"scan_{slug}_{ts}.json"

        data = {
            "target":   self.target,
            "started":  datetime.now(timezone.utc).isoformat(),
            "modules":  len(self._results),
            "findings": self.all_findings(),
            "results": [
                {
                    "module":      r.module,
                    "status":      r.status,
                    "finding_count": r.finding_count,
                    "duration_s":  r.duration_s,
                    "error":       r.error,
                }
                for r in self._results
            ],
        }
        out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return out

    @property
    def module_count(self) -> int:
        return len(self._modules)

    @property
    def enabled_count(self) -> int:
        return sum(1 for m in self._modules if m.enabled)
