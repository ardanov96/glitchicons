"""
Remediation Tracker — modules/report/remediation_tracker.py

Track remediation status per finding across multiple assessments.

Features:
  - Persistent JSON store per engagement
  - Status: OPEN → IN_PROGRESS → FIXED → ACCEPTED_RISK → WONT_FIX
  - Assignee tracking
  - Due date management
  - Progress report generation
  - Re-test verification flag
  - CLI-friendly summary

Usage:
    from modules.report.remediation_tracker import RemediationTracker

    tracker = RemediationTracker(
        engagement_id="target_corp_2026",
        findings=findings,
        output_dir="./findings/remediation",
    )

    # Load or init
    tracker.load_or_init()

    # Update status
    tracker.update("FIND-001", status="IN_PROGRESS", assignee="dev@target.com", due_days=7)
    tracker.update("FIND-002", status="FIXED", note="Deployed parameterized queries in v2.4.1")

    # Get summary
    summary = tracker.summary()
    tracker.print_summary()

    # Save
    tracker.save()

Author: ardanov96
"""

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()

VALID_STATUSES = frozenset({
    "OPEN", "IN_PROGRESS", "FIXED", "ACCEPTED_RISK", "WONT_FIX", "NEEDS_RETEST"
})

STATUS_COLORS = {
    "OPEN":          "red",
    "IN_PROGRESS":   "yellow",
    "FIXED":         "green",
    "ACCEPTED_RISK": "blue",
    "WONT_FIX":      "dim",
    "NEEDS_RETEST":  "cyan",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class RemediationTracker:
    """
    Track remediation status for Glitchicons findings.

    Persists state as JSON file — one tracker per engagement.
    Each finding gets a unique ID and tracks: status, assignee,
    due date, notes, and re-test verification.
    """

    def __init__(
        self,
        engagement_id: str,
        findings: list[dict] | None = None,
        output_dir: str = "./findings/remediation",
    ):
        self.engagement_id = engagement_id
        self.initial_findings = findings or []
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.store_path = self.output_dir / f"{engagement_id}_tracker.json"
        self._items: dict[str, dict] = {}
        self._meta: dict = {}

    # ── Init / Load / Save ────────────────────────────────

    def load_or_init(self) -> "RemediationTracker":
        """Load existing tracker or initialize from findings."""
        if self.store_path.exists():
            self._load()
            # Add any new findings not yet tracked
            for f in self.initial_findings:
                fid = self._finding_id(f)
                if fid not in self._items:
                    self._add_finding(fid, f)
            console.print(f"  [cyan]Tracker loaded:[/cyan] {len(self._items)} items")
        else:
            self._init_from_findings()
            console.print(f"  [cyan]Tracker initialized:[/cyan] {len(self._items)} items")
        return self

    def _init_from_findings(self):
        self._meta = {
            "engagement_id": self.engagement_id,
            "created_at":    datetime.now(timezone.utc).isoformat(),
            "updated_at":    datetime.now(timezone.utc).isoformat(),
        }
        self._items = {}
        for f in self.initial_findings:
            fid = self._finding_id(f)
            self._add_finding(fid, f)

    def _add_finding(self, fid: str, f: dict):
        self._items[fid] = {
            "id":           fid,
            "title":        f.get("title", "Untitled"),
            "severity":     f.get("severity", "INFO"),
            "cvss":         float(f.get("cvss", 0)),
            "cwe":          f.get("cwe", "N/A"),
            "target":       f.get("target", ""),
            "status":       "OPEN",
            "assignee":     None,
            "due_date":     None,
            "notes":        [],
            "verified":     False,
            "created_at":   datetime.now(timezone.utc).isoformat(),
            "updated_at":   datetime.now(timezone.utc).isoformat(),
        }

    def _load(self):
        data = json.loads(self.store_path.read_text(encoding="utf-8"))
        self._meta  = data.get("meta", {})
        self._items = data.get("items", {})

    def save(self) -> Path:
        """Persist tracker state to JSON."""
        if self._meta:
            self._meta["updated_at"] = datetime.now(timezone.utc).isoformat()
        data = {"meta": self._meta, "items": self._items}
        self.store_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        console.print(f"  [green]Tracker saved:[/green] {self.store_path}")
        return self.store_path

    # ── Update operations ─────────────────────────────────

    def update(
        self,
        finding_id: str,
        status: str | None = None,
        assignee: str | None = None,
        due_days: int | None = None,
        due_date: str | None = None,
        note: str | None = None,
        verified: bool | None = None,
    ) -> dict | None:
        """
        Update a finding's remediation status.

        Args:
            finding_id: Finding ID (from tracker)
            status:     New status (OPEN/IN_PROGRESS/FIXED/ACCEPTED_RISK/WONT_FIX/NEEDS_RETEST)
            assignee:   Email/name of person responsible
            due_days:   Due date as days from now
            due_date:   Due date as ISO string (overrides due_days)
            note:       Note to append to history
            verified:   Mark as re-test verified

        Returns:
            Updated item dict or None if not found
        """
        item = self._items.get(finding_id)
        if not item:
            console.print(f"  [red]Finding not found:[/red] {finding_id}")
            return None

        if status is not None:
            if status not in VALID_STATUSES:
                raise ValueError(f"Invalid status '{status}'. Must be one of {VALID_STATUSES}")
            item["status"] = status

        if assignee is not None:
            item["assignee"] = assignee

        if due_date is not None:
            item["due_date"] = due_date
        elif due_days is not None:
            due = datetime.now(timezone.utc) + timedelta(days=due_days)
            item["due_date"] = due.strftime("%Y-%m-%d")

        if note is not None:
            item["notes"].append({
                "text":      note,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        if verified is not None:
            item["verified"] = verified

        item["updated_at"] = datetime.now(timezone.utc).isoformat()
        console.print(
            f"  Updated [{finding_id}]: "
            f"status={item['status']} assignee={item.get('assignee', '-')}"
        )
        return item

    def bulk_update(self, updates: list[dict]) -> int:
        """
        Apply multiple updates at once.

        Args:
            updates: List of dicts, each with 'id' + update fields

        Returns:
            Number of successfully updated items
        """
        count = 0
        for upd in updates:
            fid = upd.pop("id", None)
            if fid and self.update(fid, **upd):
                count += 1
        return count

    def mark_fixed(self, finding_id: str, note: str = "", verified: bool = False) -> dict | None:
        """Shortcut: mark a finding as FIXED."""
        return self.update(finding_id, status="FIXED", note=note or "Marked as fixed", verified=verified)

    def accept_risk(self, finding_id: str, reason: str) -> dict | None:
        """Shortcut: accept risk for a finding with required reason."""
        if not reason:
            raise ValueError("reason is required when accepting risk")
        return self.update(finding_id, status="ACCEPTED_RISK",
                           note=f"Risk accepted: {reason}")

    # ── Query operations ──────────────────────────────────

    def get(self, finding_id: str) -> dict | None:
        """Get a single item by ID."""
        return self._items.get(finding_id)

    def by_status(self, status: str) -> list[dict]:
        """Get all items with a given status."""
        return [i for i in self._items.values() if i["status"] == status]

    def by_severity(self, severity: str) -> list[dict]:
        """Get all items with a given severity."""
        return [i for i in self._items.values() if i["severity"] == severity]

    def overdue(self) -> list[dict]:
        """Get all items past their due date and not FIXED."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return [
            i for i in self._items.values()
            if i.get("due_date") and i["due_date"] < today
            and i["status"] not in ("FIXED", "ACCEPTED_RISK", "WONT_FIX")
        ]

    def all_items(self) -> list[dict]:
        """Return all items sorted by severity."""
        return sorted(
            self._items.values(),
            key=lambda i: SEVERITY_ORDER.index(i.get("severity", "INFO"))
            if i.get("severity", "INFO") in SEVERITY_ORDER else 99,
        )

    # ── Summary / Reporting ───────────────────────────────

    def summary(self) -> dict:
        """Compute remediation progress summary."""
        total  = len(self._items)
        by_sev = {s: 0 for s in SEVERITY_ORDER}
        by_status = {s: 0 for s in VALID_STATUSES}

        for item in self._items.values():
            sev = item.get("severity", "INFO")
            if sev in by_sev:
                by_sev[sev] += 1
            st = item.get("status", "OPEN")
            if st in by_status:
                by_status[st] += 1

        fixed = by_status.get("FIXED", 0) + by_status.get("ACCEPTED_RISK", 0) + by_status.get("WONT_FIX", 0)
        pct   = round(fixed / total * 100, 1) if total > 0 else 0.0

        return {
            "engagement_id":   self.engagement_id,
            "total":           total,
            "fixed":           fixed,
            "open":            by_status.get("OPEN", 0),
            "in_progress":     by_status.get("IN_PROGRESS", 0),
            "needs_retest":    by_status.get("NEEDS_RETEST", 0),
            "accepted_risk":   by_status.get("ACCEPTED_RISK", 0),
            "wont_fix":        by_status.get("WONT_FIX", 0),
            "completion_pct":  pct,
            "by_severity":     by_sev,
            "by_status":       by_status,
            "overdue_count":   len(self.overdue()),
        }

    def print_summary(self):
        """Print a rich formatted remediation summary table."""
        s = self.summary()

        console.print(f"\n  [bold cyan]Remediation Tracker[/bold cyan] — {self.engagement_id}")
        console.print(f"  Progress: [green]{s['fixed']}/{s['total']}[/green] resolved ({s['completion_pct']}%)")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID",         style="dim",  width=14)
        table.add_column("Severity",   width=10)
        table.add_column("Status",     width=14)
        table.add_column("Assignee",   width=20)
        table.add_column("Due",        width=12)
        table.add_column("Title")

        for item in self.all_items():
            sev    = item.get("severity", "INFO")
            status = item.get("status", "OPEN")
            sev_colored = f"[{'red' if sev=='CRITICAL' else 'yellow' if sev=='HIGH' else 'white'}]{sev}[/]"
            status_colored = f"[{STATUS_COLORS.get(status, 'white')}]{status}[/]"
            table.add_row(
                item["id"][:13],
                sev_colored,
                status_colored,
                item.get("assignee") or "—",
                item.get("due_date") or "—",
                (item.get("title") or "")[:40],
            )

        console.print(table)

        if s["overdue_count"] > 0:
            console.print(f"  [red]⚠ {s['overdue_count']} item(s) overdue![/red]")

    # ── Helpers ───────────────────────────────────────────

    def _finding_id(self, finding: dict) -> str:
        """Generate a stable ID for a finding."""
        existing_id = finding.get("id", "")
        if existing_id and existing_id not in self._items:
            return existing_id
        # Generate from title + severity + cwe
        title = finding.get("title", "untitled")[:20]
        sev   = finding.get("severity", "INFO")[:3]
        cwe   = finding.get("cwe", "CWE-0").replace("CWE-", "")
        slug  = "".join(c if c.isalnum() else "-" for c in title).strip("-")[:12]
        return f"{sev}-{cwe}-{slug}".upper()

    @property
    def item_count(self) -> int:
        return len(self._items)
