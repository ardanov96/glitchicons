"""
Collaboration Features — modules/collab/collaboration.py

Multi-user security finding management:
  1. FindingWorkspace   — centralized finding view + bulk operations
  2. FindingAssignment  — assign findings to team members
  3. CommentThread      — threaded comments per finding
  4. AuditLog           — immutable audit trail for all changes
  5. RemediationTracker — track fix progress per finding

Designed to work standalone (no database required) using
in-memory state, or integrated with modules/core/database.py.

Usage:
    from modules.collab.collaboration import (
        FindingWorkspace, FindingAssignment,
        CommentThread, AuditLog, RemediationTracker,
    )

    workspace = FindingWorkspace(team=["alice", "bob", "charlie"])

    # Assign finding
    workspace.assign("finding-id", to_user="alice", by_user="lead")

    # Comment
    workspace.comment("finding-id", author="alice", body="Confirmed SQLi on /search")

    # Track remediation
    workspace.update_remediation("finding-id", status="in_progress", owner="dev-team")

    # Audit trail
    audit = workspace.get_audit_log("finding-id")

Author: ardanov96
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uuid() -> str:
    return str(uuid.uuid4())


# ── Finding severity ordering ─────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def severity_key(finding: dict) -> int:
    return SEVERITY_ORDER.get(finding.get("severity", "INFO"), 4)


# ── Data classes ──────────────────────────────────────────

@dataclass
class Assignment:
    """A finding assignment to a team member."""
    id:           str
    finding_id:   str
    assigned_to:  str
    assigned_by:  str
    assigned_at:  str
    due_date:     str = ""
    note:         str = ""
    resolved:     bool = False
    resolved_at:  str  = ""


@dataclass
class Comment:
    """A comment on a finding."""
    id:         str
    finding_id: str
    author:     str
    body:       str
    created_at: str
    edited_at:  str = ""
    edited:     bool = False
    parent_id:  str  = ""    # For threaded replies
    reactions:  dict = field(default_factory=dict)  # {"👍": ["alice", "bob"]}

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "finding_id": self.finding_id,
            "author":     self.author,
            "body":       self.body,
            "created_at": self.created_at,
            "edited":     self.edited,
            "parent_id":  self.parent_id,
            "reactions":  self.reactions,
        }


@dataclass
class AuditEntry:
    """A single immutable audit log entry."""
    id:         str
    finding_id: str
    actor:      str
    action:     str          # "assigned", "commented", "status_changed", etc.
    old_value:  str = ""
    new_value:  str = ""
    metadata:   dict = field(default_factory=dict)
    timestamp:  str  = ""

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "finding_id": self.finding_id,
            "actor":      self.actor,
            "action":     self.action,
            "old_value":  self.old_value,
            "new_value":  self.new_value,
            "metadata":   self.metadata,
            "timestamp":  self.timestamp,
        }


@dataclass
class RemediationStatus:
    """Remediation tracking for a finding."""
    finding_id:  str
    status:      str   # open | acknowledged | in_progress | resolved | wont_fix | false_positive
    owner:       str   = ""
    due_date:    str   = ""
    ticket_url:  str   = ""    # Jira/GitHub issue link
    ticket_id:   str   = ""
    notes:       str   = ""
    updated_at:  str   = ""
    updated_by:  str   = ""
    resolved_at: str   = ""
    sla_breach:  bool  = False

    @property
    def is_open(self) -> bool:
        return self.status in ("open", "acknowledged", "in_progress")

    @property
    def is_closed(self) -> bool:
        return self.status in ("resolved", "wont_fix", "false_positive")

    def to_dict(self) -> dict:
        return {
            "finding_id":  self.finding_id,
            "status":      self.status,
            "owner":       self.owner,
            "due_date":    self.due_date,
            "ticket_url":  self.ticket_url,
            "ticket_id":   self.ticket_id,
            "notes":       self.notes,
            "updated_at":  self.updated_at,
            "sla_breach":  self.sla_breach,
        }


# ── Remediation status constants ──────────────────────────

REMEDIATION_STATUSES = frozenset({
    "open", "acknowledged", "in_progress",
    "resolved", "wont_fix", "false_positive",
})

# SLA days per severity (default)
DEFAULT_SLA_DAYS = {
    "CRITICAL": 1,
    "HIGH":     7,
    "MEDIUM":   30,
    "LOW":      90,
    "INFO":     180,
}


# ── 1. Finding Assignment ─────────────────────────────────

class FindingAssignment:
    """
    Assign security findings to team members.

    Features:
    - Assign single or multiple findings
    - Transfer assignments between team members
    - Track assignment history
    - Filter unassigned / assigned-to-me
    """

    def __init__(self, team: list[str] | None = None):
        self.team: set[str]                         = set(team or [])
        self._assignments: dict[str, Assignment]    = {}  # id → Assignment
        self._by_finding:  dict[str, list[str]]     = {}  # finding_id → [assignment_ids]
        self._by_user:     dict[str, list[str]]     = {}  # user → [assignment_ids]

    def assign(
        self,
        finding_id: str,
        to_user: str,
        by_user: str = "system",
        due_date: str = "",
        note: str = "",
    ) -> Assignment:
        """Assign a finding to a team member."""
        self.team.add(to_user)
        a = Assignment(
            id=_uuid(), finding_id=finding_id,
            assigned_to=to_user, assigned_by=by_user,
            assigned_at=_now(), due_date=due_date, note=note,
        )
        self._assignments[a.id] = a
        self._by_finding.setdefault(finding_id, []).append(a.id)
        self._by_user.setdefault(to_user, []).append(a.id)
        return a

    def assign_bulk(
        self,
        finding_ids: list[str],
        to_user: str,
        by_user: str = "system",
    ) -> list[Assignment]:
        """Assign multiple findings at once."""
        return [self.assign(fid, to_user, by_user) for fid in finding_ids]

    def reassign(
        self,
        finding_id: str,
        to_user: str,
        by_user: str = "system",
    ) -> Assignment:
        """Reassign a finding (marks old assignment resolved, creates new)."""
        # Resolve existing active assignments
        for aid in self._by_finding.get(finding_id, []):
            a = self._assignments.get(aid)
            if a and not a.resolved:
                a.resolved    = True
                a.resolved_at = _now()
        return self.assign(finding_id, to_user, by_user)

    def resolve(self, finding_id: str) -> int:
        """Mark all active assignments for a finding as resolved."""
        count = 0
        for aid in self._by_finding.get(finding_id, []):
            a = self._assignments.get(aid)
            if a and not a.resolved:
                a.resolved    = True
                a.resolved_at = _now()
                count += 1
        return count

    def get_assignment(self, finding_id: str) -> Assignment | None:
        """Get current (unresolved) assignment for a finding."""
        for aid in reversed(self._by_finding.get(finding_id, [])):
            a = self._assignments.get(aid)
            if a and not a.resolved:
                return a
        return None

    def get_assignments_for_user(self, user: str) -> list[Assignment]:
        """Get all active assignments for a user."""
        result = []
        for aid in self._by_user.get(user, []):
            a = self._assignments.get(aid)
            if a and not a.resolved:
                result.append(a)
        return result

    def get_unassigned(self, finding_ids: list[str]) -> list[str]:
        """Return finding IDs that have no active assignment."""
        return [
            fid for fid in finding_ids
            if self.get_assignment(fid) is None
        ]

    def workload(self) -> dict[str, int]:
        """Return assignment count per team member."""
        return {
            user: len(self.get_assignments_for_user(user))
            for user in self.team
        }


# ── 2. Comment Thread ─────────────────────────────────────

class CommentThread:
    """
    Threaded comment system for security findings.

    Features:
    - Top-level comments + threaded replies
    - Edit and delete (soft) comments
    - Emoji reactions
    - Comment count per finding
    - Mention extraction (@username)
    """

    def __init__(self):
        self._comments:   dict[str, Comment]     = {}  # id → Comment
        self._by_finding: dict[str, list[str]]   = {}  # finding_id → [comment_ids]

    def add_comment(
        self,
        finding_id: str,
        author: str,
        body: str,
        parent_id: str = "",
    ) -> Comment:
        """Add a comment (or reply) to a finding."""
        c = Comment(
            id=_uuid(), finding_id=finding_id,
            author=author, body=body,
            created_at=_now(), parent_id=parent_id,
        )
        self._comments[c.id] = c
        self._by_finding.setdefault(finding_id, []).append(c.id)
        return c

    def edit_comment(self, comment_id: str, new_body: str, editor: str = "") -> bool:
        """Edit a comment body."""
        c = self._comments.get(comment_id)
        if not c:
            return False
        c.body      = new_body
        c.edited    = True
        c.edited_at = _now()
        return True

    def delete_comment(self, comment_id: str) -> bool:
        """Soft-delete a comment (replace body with [deleted])."""
        c = self._comments.get(comment_id)
        if not c:
            return False
        c.body      = "[deleted]"
        c.edited    = True
        c.edited_at = _now()
        return True

    def react(self, comment_id: str, user: str, emoji: str) -> bool:
        """Toggle a reaction on a comment."""
        c = self._comments.get(comment_id)
        if not c:
            return False
        if emoji not in c.reactions:
            c.reactions[emoji] = []
        if user in c.reactions[emoji]:
            c.reactions[emoji].remove(user)
        else:
            c.reactions[emoji].append(user)
        return True

    def get_comments(
        self,
        finding_id: str,
        top_level_only: bool = False,
    ) -> list[Comment]:
        """Get all comments for a finding."""
        ids      = self._by_finding.get(finding_id, [])
        comments = [self._comments[cid] for cid in ids if cid in self._comments]
        if top_level_only:
            comments = [c for c in comments if not c.parent_id]
        return sorted(comments, key=lambda c: c.created_at)

    def get_replies(self, comment_id: str) -> list[Comment]:
        """Get all replies to a comment."""
        c = self._comments.get(comment_id)
        if not c:
            return []
        return [
            co for co in self._comments.values()
            if co.parent_id == comment_id
        ]

    def get_mentions(self, finding_id: str) -> set[str]:
        """Extract all @mentions from comments on a finding."""
        mentions: set[str] = set()
        for c in self.get_comments(finding_id):
            import re
            for m in re.findall(r"@(\w+)", c.body):
                mentions.add(m)
        return mentions

    @property
    def total_comments(self) -> int:
        return len(self._comments)

    def count(self, finding_id: str) -> int:
        return len(self._by_finding.get(finding_id, []))

    def comment_count_by_finding(self, finding_ids: list[str]) -> dict[str, int]:
        return {fid: self.count(fid) for fid in finding_ids}


# ── 3. Audit Log ──────────────────────────────────────────

# Standard audit actions
class AuditAction:
    FINDING_IMPORTED    = "finding_imported"
    FINDING_ASSIGNED    = "finding_assigned"
    FINDING_REASSIGNED  = "finding_reassigned"
    FINDING_RESOLVED    = "finding_resolved"
    COMMENT_ADDED       = "comment_added"
    COMMENT_EDITED      = "comment_edited"
    COMMENT_DELETED     = "comment_deleted"
    STATUS_CHANGED      = "status_changed"
    SEVERITY_CHANGED    = "severity_changed"
    FALSE_POSITIVE      = "marked_false_positive"
    VERIFIED            = "marked_verified"
    TICKET_LINKED       = "ticket_linked"
    SLA_BREACH          = "sla_breach"


class AuditLog:
    """
    Immutable audit trail for all finding-related actions.

    Every state change (assignment, comment, status, severity)
    creates an immutable audit entry. Entries cannot be modified.

    Useful for:
    - Compliance reporting (who changed what, when)
    - Investigating incident response timelines
    - Meeting SOC2/ISO27001 audit requirements
    """

    def __init__(self):
        self._entries:    list[AuditEntry]       = []
        self._by_finding: dict[str, list[int]]   = {}  # finding_id → [indices]
        self._by_actor:   dict[str, list[int]]   = {}  # actor → [indices]

    def log(
        self,
        finding_id: str,
        actor: str,
        action: str,
        old_value: str = "",
        new_value: str = "",
        metadata: dict | None = None,
    ) -> AuditEntry:
        """Record an audit event (immutable once created)."""
        entry = AuditEntry(
            id=_uuid(),
            finding_id=finding_id,
            actor=actor,
            action=action,
            old_value=old_value,
            new_value=new_value,
            metadata=metadata or {},
            timestamp=_now(),
        )
        idx = len(self._entries)
        self._entries.append(entry)
        self._by_finding.setdefault(finding_id, []).append(idx)
        self._by_actor.setdefault(actor, []).append(idx)
        return entry

    def get_log(
        self,
        finding_id: str,
        action_filter: str | None = None,
    ) -> list[AuditEntry]:
        """Get audit trail for a finding."""
        idxs    = self._by_finding.get(finding_id, [])
        entries = [self._entries[i] for i in idxs]
        if action_filter:
            entries = [e for e in entries if e.action == action_filter]
        return sorted(entries, key=lambda e: e.timestamp)

    def get_actor_log(self, actor: str) -> list[AuditEntry]:
        """Get all actions by a specific actor."""
        idxs = self._by_actor.get(actor, [])
        return [self._entries[i] for i in idxs]

    def get_recent(self, limit: int = 20) -> list[AuditEntry]:
        """Get most recent audit entries across all findings."""
        return list(reversed(self._entries))[:limit]

    def action_count(self, action: str) -> int:
        return sum(1 for e in self._entries if e.action == action)

    @property
    def total_entries(self) -> int:
        return len(self._entries)


# ── 4. Remediation Tracker ────────────────────────────────

class RemediationTracker:
    """
    Track remediation progress for security findings.

    Features:
    - Status lifecycle: open → acknowledged → in_progress → resolved
    - SLA tracking per severity
    - Ticket integration (Jira/GitHub)
    - Progress dashboard
    - Overdue finding detection
    """

    def __init__(self, sla_days: dict[str, int] | None = None):
        self.sla_days: dict[str, int] = sla_days or dict(DEFAULT_SLA_DAYS)
        self._statuses: dict[str, RemediationStatus] = {}  # finding_id → status

    def initialize(self, finding: dict) -> RemediationStatus:
        """Initialize remediation tracking for a finding."""
        fid  = finding.get("id") or _uuid()
        status = RemediationStatus(
            finding_id=fid,
            status="open",
            updated_at=_now(),
        )
        self._statuses[fid] = status
        return status

    def initialize_bulk(self, findings: list[dict]) -> int:
        """Initialize tracking for multiple findings."""
        for f in findings:
            fid = f.get("id") or f.get("finding_id", "")
            if fid and fid not in self._statuses:
                severity = f.get("severity", "INFO")
                status = RemediationStatus(
                    finding_id=fid, status="open", updated_at=_now(),
                )
                self._statuses[fid] = status
        return len(findings)

    def update_status(
        self,
        finding_id: str,
        status: str,
        owner: str = "",
        notes: str = "",
        updated_by: str = "system",
    ) -> RemediationStatus | None:
        """Update remediation status."""
        if status not in REMEDIATION_STATUSES:
            raise ValueError(f"Invalid status: {status}. Must be one of {REMEDIATION_STATUSES}")

        if finding_id not in self._statuses:
            self._statuses[finding_id] = RemediationStatus(
                finding_id=finding_id, status=status, updated_at=_now()
            )

        s = self._statuses[finding_id]
        s.status     = status
        s.updated_at = _now()
        s.updated_by = updated_by
        if owner:
            s.owner = owner
        if notes:
            s.notes = notes
        if status == "resolved":
            s.resolved_at = _now()
        return s

    def link_ticket(
        self,
        finding_id: str,
        ticket_url: str,
        ticket_id: str = "",
    ) -> bool:
        """Link a Jira/GitHub/Linear ticket to a finding."""
        if finding_id not in self._statuses:
            self._statuses[finding_id] = RemediationStatus(
                finding_id=finding_id, status="open", updated_at=_now()
            )
        s = self._statuses[finding_id]
        s.ticket_url = ticket_url
        s.ticket_id  = ticket_id or ticket_url.split("/")[-1]
        s.updated_at = _now()
        return True

    def get_status(self, finding_id: str) -> RemediationStatus | None:
        return self._statuses.get(finding_id)

    def get_open(self) -> list[RemediationStatus]:
        return [s for s in self._statuses.values() if s.is_open]

    def get_resolved(self) -> list[RemediationStatus]:
        return [s for s in self._statuses.values() if s.is_closed]

    def get_by_status(self, status: str) -> list[RemediationStatus]:
        return [s for s in self._statuses.values() if s.status == status]

    def get_by_owner(self, owner: str) -> list[RemediationStatus]:
        return [s for s in self._statuses.values() if s.owner == owner]

    def check_sla(
        self,
        finding_id: str,
        severity: str,
        created_at: str,
    ) -> bool:
        """
        Check if a finding is within SLA.

        Returns True if within SLA, False if breached.
        """
        from datetime import timedelta
        try:
            created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        except Exception:
            return True  # Can't check, assume OK

        sla_limit = self.sla_days.get(severity, 90)
        deadline  = created + timedelta(days=sla_limit)
        now       = datetime.now(timezone.utc)

        status = self._statuses.get(finding_id)
        if status:
            # Already resolved — check if resolved within SLA
            if status.resolved_at:
                try:
                    resolved = datetime.fromisoformat(
                        status.resolved_at.replace("Z", "+00:00")
                    )
                    return resolved <= deadline
                except Exception:
                    pass
            # Still open — check current time vs deadline
            if now > deadline and status.is_open:
                if status:
                    status.sla_breach = True
                return False
        return now <= deadline

    def progress_summary(self) -> dict:
        """Get remediation progress statistics."""
        all_statuses = list(self._statuses.values())
        total    = len(all_statuses)
        if total == 0:
            return {"total": 0, "open": 0, "resolved": 0, "progress_pct": 0.0}

        resolved = sum(1 for s in all_statuses if s.is_closed)
        by_status = {}
        for status in REMEDIATION_STATUSES:
            count = sum(1 for s in all_statuses if s.status == status)
            if count:
                by_status[status] = count

        return {
            "total":        total,
            "open":         sum(1 for s in all_statuses if s.is_open),
            "resolved":     resolved,
            "progress_pct": round(resolved / total * 100, 1),
            "by_status":    by_status,
            "with_tickets": sum(1 for s in all_statuses if s.ticket_url),
            "sla_breaches": sum(1 for s in all_statuses if s.sla_breach),
        }


# ── 5. Finding Workspace (Orchestrator) ───────────────────

class FindingWorkspace:
    """
    Central collaboration hub for a security engagement.

    Combines assignment, comments, audit log, and remediation
    tracking into a unified workspace for team collaboration.

    Usage:
        ws = FindingWorkspace(team=["alice", "bob", "charlie"])
        ws.import_findings(findings_list)
        ws.assign("finding-id", to_user="alice", by_user="lead")
        ws.comment("finding-id", author="alice", body="Confirmed!")
        ws.update_remediation("finding-id", status="in_progress", owner="dev-team")
    """

    def __init__(self, team: list[str] | None = None, workspace_name: str = ""):
        self.workspace_name = workspace_name or "Default Workspace"
        self.created_at     = _now()
        self._findings:     dict[str, dict] = {}

        self.assignment     = FindingAssignment(team=team)
        self.comments       = CommentThread()
        self.audit          = AuditLog()
        self.remediation    = RemediationTracker()

    def import_findings(
        self,
        findings: list[dict],
        imported_by: str = "system",
    ) -> int:
        """Import findings into workspace from any Glitchicons module."""
        count = 0
        for f in findings:
            fid = f.get("id") or _uuid()
            f_copy = dict(f)
            f_copy["id"] = fid
            self._findings[fid] = f_copy
            self.remediation.initialize(f_copy)
            self.audit.log(fid, imported_by, AuditAction.FINDING_IMPORTED,
                           new_value=f.get("title", "")[:100])
            count += 1
        return count

    def assign(
        self,
        finding_id: str,
        to_user: str,
        by_user: str = "system",
        due_date: str = "",
        note: str = "",
    ) -> Assignment:
        """Assign a finding and log to audit trail."""
        a = self.assignment.assign(finding_id, to_user, by_user, due_date, note)
        self.audit.log(finding_id, by_user, AuditAction.FINDING_ASSIGNED,
                       new_value=to_user,
                       metadata={"due_date": due_date, "note": note})
        return a

    def reassign(
        self,
        finding_id: str,
        to_user: str,
        by_user: str = "system",
    ) -> Assignment:
        """Reassign a finding and log the transfer."""
        old = self.assignment.get_assignment(finding_id)
        old_user = old.assigned_to if old else ""
        a = self.assignment.reassign(finding_id, to_user, by_user)
        self.audit.log(finding_id, by_user, AuditAction.FINDING_REASSIGNED,
                       old_value=old_user, new_value=to_user)
        return a

    def comment(
        self,
        finding_id: str,
        author: str,
        body: str,
        parent_id: str = "",
    ) -> Comment:
        """Add a comment and log to audit trail."""
        c = self.comments.add_comment(finding_id, author, body, parent_id)
        self.audit.log(finding_id, author, AuditAction.COMMENT_ADDED,
                       new_value=body[:100])
        return c

    def update_remediation(
        self,
        finding_id: str,
        status: str,
        owner: str = "",
        notes: str = "",
        updated_by: str = "system",
    ) -> RemediationStatus | None:
        """Update remediation status and log change."""
        old = self.remediation.get_status(finding_id)
        old_status = old.status if old else "open"
        s = self.remediation.update_status(finding_id, status, owner, notes, updated_by)
        if s:
            self.audit.log(finding_id, updated_by, AuditAction.STATUS_CHANGED,
                           old_value=old_status, new_value=status,
                           metadata={"owner": owner})
        return s

    def link_ticket(
        self,
        finding_id: str,
        ticket_url: str,
        linked_by: str = "system",
    ) -> bool:
        """Link a ticket and log to audit trail."""
        ok = self.remediation.link_ticket(finding_id, ticket_url)
        if ok:
            self.audit.log(finding_id, linked_by, AuditAction.TICKET_LINKED,
                           new_value=ticket_url)
        return ok

    def get_audit_log(self, finding_id: str) -> list[AuditEntry]:
        return self.audit.get_log(finding_id)

    def get_finding(self, finding_id: str) -> dict | None:
        return self._findings.get(finding_id)

    def list_findings(
        self,
        severity: str | None = None,
        assigned_to: str | None = None,
        status: str | None = None,
    ) -> list[dict]:
        """Filter findings by severity, assignee, or remediation status."""
        findings = list(self._findings.values())

        if severity:
            findings = [f for f in findings if f.get("severity") == severity]

        if assigned_to:
            assigned_ids = {
                a.finding_id for a in self.assignment.get_assignments_for_user(assigned_to)
            }
            findings = [f for f in findings if f["id"] in assigned_ids]

        if status:
            findings = [
                f for f in findings
                if self.remediation.get_status(f["id"]) and
                   self.remediation.get_status(f["id"]).status == status
            ]

        return sorted(findings, key=severity_key)

    def dashboard(self) -> dict:
        """Get workspace dashboard summary."""
        findings = list(self._findings.values())
        severity_counts = {}
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            severity_counts[sev] = sum(1 for f in findings
                                       if f.get("severity") == sev)
        return {
            "workspace":        self.workspace_name,
            "total_findings":   len(findings),
            "severity_counts":  severity_counts,
            "team_size":        len(self.assignment.team),
            "workload":         self.assignment.workload(),
            "total_comments":   self.comments.total_comments,
            "remediation":      self.remediation.progress_summary(),
            "audit_entries":    self.audit.total_entries,
        }

    @property
    def finding_count(self) -> int:
        return len(self._findings)
