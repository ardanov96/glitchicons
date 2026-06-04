"""
Scan Scheduler — modules/core/scheduler.py

APScheduler-based recurring scan scheduler.

Supports:
  - Interval schedules: "interval:6h", "interval:30m", "interval:1d"
  - Cron schedules:    "0 2 * * *" (every day at 2am)
  - One-time:          "once:2024-12-01T02:00:00Z"

Usage:
    from modules.core.scheduler import ScanScheduler, ScheduleConfig

    scheduler = ScanScheduler()
    scheduler.start()

    # Schedule recurring scan
    job_id = scheduler.add_interval_job(
        target_id="uuid-here",
        interval_hours=24,
        modules=["sqli", "xss", "cors"],
        job_name="Daily scan — Target Corp",
    )

    # Schedule cron job
    job_id = scheduler.add_cron_job(
        target_id="uuid-here",
        cron_expr="0 2 * * 1",  # Every Monday at 2am
        modules=["full"],
        job_name="Weekly full scan",
    )

    scheduler.list_jobs()
    scheduler.pause_job(job_id)
    scheduler.resume_job(job_id)
    scheduler.remove_job(job_id)
    scheduler.stop()

Author: ardanov96
"""

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Callable

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.interval import IntervalTrigger
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.date import DateTrigger
    from apscheduler.job import Job
    HAS_APScheduler = True
except ImportError:
    HAS_APScheduler = False


# ── Data classes ──────────────────────────────────────────

@dataclass
class ScheduleConfig:
    """Configuration for a scheduled scan job."""
    job_id:       str
    target_id:    str
    job_name:     str
    schedule_type: str           # "interval" | "cron" | "once"
    schedule_expr: str           # "24h" | "0 2 * * *" | ISO datetime
    modules:      list[str]
    enabled:      bool = True
    created_at:   str  = ""
    last_run:     str  = ""
    next_run:     str  = ""
    run_count:    int  = 0

    def to_dict(self) -> dict:
        return {
            "job_id":        self.job_id,
            "target_id":     self.target_id,
            "job_name":      self.job_name,
            "schedule_type": self.schedule_type,
            "schedule_expr": self.schedule_expr,
            "modules":       self.modules,
            "enabled":       self.enabled,
            "next_run":      self.next_run,
            "run_count":     self.run_count,
        }


@dataclass
class JobRunResult:
    """Result of a scheduled scan execution."""
    job_id:    str
    target_id: str
    status:    str       # "success" | "error" | "skipped"
    started_at: str
    duration_s: float
    error:     str = ""
    scan_id:   str = ""


# ── Interval parser ───────────────────────────────────────

_INTERVAL_RE = re.compile(r"^(\d+)(s|m|h|d|w)$", re.IGNORECASE)

_UNIT_SECONDS = {
    "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800,
}


def parse_interval(expr: str) -> timedelta | None:
    """
    Parse interval string to timedelta.

    Examples:
        "30m"   → timedelta(minutes=30)
        "6h"    → timedelta(hours=6)
        "1d"    → timedelta(days=1)
        "2w"    → timedelta(weeks=2)
        "invalid" → None
    """
    expr = expr.strip().lower()
    m    = _INTERVAL_RE.match(expr)
    if not m:
        return None
    value  = int(m.group(1))
    unit   = m.group(2)
    seconds = value * _UNIT_SECONDS[unit]
    return timedelta(seconds=seconds)


def parse_cron(expr: str) -> dict | None:
    """
    Parse cron expression into APScheduler kwargs.

    Standard 5-field cron: minute hour day month day_of_week
    Returns dict for CronTrigger(**kwargs) or None if invalid.
    """
    parts = expr.strip().split()
    if len(parts) != 5:
        return None
    fields = ["minute", "hour", "day", "month", "day_of_week"]
    return dict(zip(fields, parts))


def format_schedule_expr(schedule_type: str, expr: str) -> str:
    """Human-readable schedule description."""
    if schedule_type == "interval":
        m = _INTERVAL_RE.match(expr.lower())
        if m:
            val, unit = int(m.group(1)), m.group(2)
            unit_names = {"s": "seconds", "m": "minutes", "h": "hours",
                          "d": "days", "w": "weeks"}
            return f"Every {val} {unit_names.get(unit, unit)}"
    elif schedule_type == "cron":
        return f"Cron: {expr}"
    elif schedule_type == "once":
        return f"Once at: {expr}"
    return expr


# ── Scan Scheduler ────────────────────────────────────────

class ScanScheduler:
    """
    Background scan scheduler using APScheduler.

    Manages recurring and one-time scan jobs.
    Callback-based: provide a scan_callback that receives
    (target_id, modules, job_id) and runs the actual scan.
    """

    def __init__(
        self,
        scan_callback: Callable | None = None,
        timezone: str = "UTC",
    ):
        """
        Args:
            scan_callback: Called when a scheduled scan fires.
                           Signature: callback(target_id, modules, job_id) -> str (scan_id)
            timezone:      Timezone for cron jobs
        """
        self.scan_callback = scan_callback
        self._configs: dict[str, ScheduleConfig] = {}
        self._running  = False

        if HAS_APScheduler:
            self._scheduler = BackgroundScheduler(timezone=timezone)
        else:
            self._scheduler = None

    def start(self) -> None:
        """Start the background scheduler."""
        if self._scheduler and not self._running:
            self._scheduler.start()
            self._running = True

    def stop(self) -> None:
        """Stop the background scheduler."""
        if self._scheduler and self._running:
            self._scheduler.shutdown(wait=False)
            self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    def add_interval_job(
        self,
        target_id: str,
        interval_hours: float = 24,
        modules: list[str] | None = None,
        job_name: str = "",
        interval_expr: str | None = None,
    ) -> str:
        """
        Add an interval-based scan job.

        Args:
            target_id:     Target UUID
            interval_hours: Run every N hours (can be fractional, e.g. 0.5 = 30 min)
            modules:       Module list to run
            job_name:      Human-readable job name
            interval_expr: Override with string expr like "6h", "30m", "1d"

        Returns:
            job_id (str)
        """
        job_id  = str(uuid.uuid4())
        modules = modules or ["all"]

        if interval_expr:
            td = parse_interval(interval_expr)
            if td:
                total_seconds = td.total_seconds()
                expr = interval_expr
            else:
                raise ValueError(f"Invalid interval expression: {interval_expr}")
        else:
            total_seconds = interval_hours * 3600
            expr = f"{interval_hours}h"

        config = ScheduleConfig(
            job_id=job_id,
            target_id=target_id,
            job_name=job_name or f"Interval scan — {target_id[:8]}",
            schedule_type="interval",
            schedule_expr=expr,
            modules=modules,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        if self._scheduler:
            trigger = IntervalTrigger(seconds=int(total_seconds))
            self._scheduler.add_job(
                self._fire_job, trigger=trigger,
                args=[job_id], id=job_id,
                name=config.job_name,
                replace_existing=True,
            )
            next_job = self._scheduler.get_job(job_id)
            next_run_time = getattr(next_job, "next_run_time", None)
            if next_job and next_run_time:
                config.next_run = next_run_time.isoformat()

        self._configs[job_id] = config
        return job_id

    def add_cron_job(
        self,
        target_id: str,
        cron_expr: str = "0 2 * * *",
        modules: list[str] | None = None,
        job_name: str = "",
    ) -> str:
        """
        Add a cron-based scan job.

        Args:
            target_id:  Target UUID
            cron_expr:  5-field cron expression (min hour day month dow)
            modules:    Module list to run
            job_name:   Human-readable job name

        Returns:
            job_id (str)
        """
        cron_kwargs = parse_cron(cron_expr)
        if not cron_kwargs:
            raise ValueError(f"Invalid cron expression: {cron_expr}")

        job_id  = str(uuid.uuid4())
        modules = modules or ["all"]

        config = ScheduleConfig(
            job_id=job_id,
            target_id=target_id,
            job_name=job_name or f"Cron scan — {cron_expr}",
            schedule_type="cron",
            schedule_expr=cron_expr,
            modules=modules,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        if self._scheduler:
            trigger = CronTrigger(**cron_kwargs)
            self._scheduler.add_job(
                self._fire_job, trigger=trigger,
                args=[job_id], id=job_id,
                name=config.job_name,
                replace_existing=True,
            )
            next_job = self._scheduler.get_job(job_id)
            next_run_time = getattr(next_job, "next_run_time", None)
            if next_job and next_run_time:
                config.next_run = next_run_time.isoformat()

        self._configs[job_id] = config
        return job_id

    def add_once_job(
        self,
        target_id: str,
        run_at: datetime,
        modules: list[str] | None = None,
        job_name: str = "",
    ) -> str:
        """Schedule a one-time scan at a specific datetime."""
        job_id  = str(uuid.uuid4())
        modules = modules or ["all"]

        config = ScheduleConfig(
            job_id=job_id,
            target_id=target_id,
            job_name=job_name or f"One-time scan",
            schedule_type="once",
            schedule_expr=run_at.isoformat(),
            modules=modules,
            next_run=run_at.isoformat(),
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        if self._scheduler:
            trigger = DateTrigger(run_date=run_at)
            self._scheduler.add_job(
                self._fire_job, trigger=trigger,
                args=[job_id], id=job_id,
                name=config.job_name,
            )

        self._configs[job_id] = config
        return job_id

    def remove_job(self, job_id: str) -> bool:
        """Remove a scheduled job."""
        if job_id not in self._configs:
            return False
        if self._scheduler:
            try:
                self._scheduler.remove_job(job_id)
            except Exception:
                pass
        del self._configs[job_id]
        return True

    def pause_job(self, job_id: str) -> bool:
        """Pause a scheduled job."""
        if job_id in self._configs:
            self._configs[job_id].enabled = False
            if self._scheduler:
                try:
                    self._scheduler.pause_job(job_id)
                except Exception:
                    pass
            return True
        return False

    def resume_job(self, job_id: str) -> bool:
        """Resume a paused job."""
        if job_id in self._configs:
            self._configs[job_id].enabled = True
            if self._scheduler:
                try:
                    self._scheduler.resume_job(job_id)
                except Exception:
                    pass
            return True
        return False

    def get_job(self, job_id: str) -> ScheduleConfig | None:
        return self._configs.get(job_id)

    def list_jobs(self) -> list[ScheduleConfig]:
        return list(self._configs.values())

    def list_jobs_for_target(self, target_id: str) -> list[ScheduleConfig]:
        return [c for c in self._configs.values() if c.target_id == target_id]

    @property
    def job_count(self) -> int:
        return len(self._configs)

    def _fire_job(self, job_id: str) -> JobRunResult:
        """Internal callback — fires when a job triggers."""
        config = self._configs.get(job_id)
        if not config or not config.enabled:
            return JobRunResult(
                job_id=job_id, target_id="",
                status="skipped", started_at="", duration_s=0,
                error="Job not found or disabled",
            )

        started = datetime.now(timezone.utc)
        config.run_count += 1
        config.last_run   = started.isoformat()

        scan_id = ""
        error   = ""
        status  = "success"

        try:
            if self.scan_callback:
                scan_id = self.scan_callback(
                    config.target_id, config.modules, job_id
                ) or ""
        except Exception as e:
            error  = str(e)
            status = "error"

        duration = (datetime.now(timezone.utc) - started).total_seconds()
        return JobRunResult(
            job_id=job_id, target_id=config.target_id,
            status=status, started_at=started.isoformat(),
            duration_s=round(duration, 2),
            error=error, scan_id=scan_id,
        )
