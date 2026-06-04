# tests/test_collaboration.py
"""
Unit tests untuk modules/collab/collaboration.py
No network calls — pure in-memory state.
"""

import pytest
from datetime import datetime, timezone, timedelta

from modules.collab.collaboration import (
    FindingWorkspace, FindingAssignment, CommentThread,
    AuditLog, AuditAction, RemediationTracker,
    Assignment, Comment, AuditEntry, RemediationStatus,
    REMEDIATION_STATUSES, DEFAULT_SLA_DAYS, severity_key,
)


# ── Sample data ───────────────────────────────────────────

def make_finding(fid="f001", severity="HIGH", title="Test Finding"):
    return {
        "id":          fid,
        "title":       title,
        "severity":    severity,
        "cvss":        7.5,
        "cwe":         "CWE-89",
        "target":      "https://target.com",
        "description": "Test finding description",
        "evidence":    "Test evidence",
        "remediation": "Fix it",
    }


SAMPLE_FINDINGS = [
    make_finding("f001", "CRITICAL", "SQL Injection"),
    make_finding("f002", "HIGH",     "XSS Reflected"),
    make_finding("f003", "MEDIUM",   "CORS Wildcard"),
    make_finding("f004", "LOW",      "Missing CSP"),
    make_finding("f005", "HIGH",     "JWT Weak Secret"),
]


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def workspace():
    ws = FindingWorkspace(
        team=["alice", "bob", "charlie"],
        workspace_name="Test Workspace",
    )
    ws.import_findings(SAMPLE_FINDINGS, imported_by="lead")
    return ws


@pytest.fixture
def assignment():
    return FindingAssignment(team=["alice", "bob", "charlie"])


@pytest.fixture
def thread():
    return CommentThread()


@pytest.fixture
def audit():
    return AuditLog()


@pytest.fixture
def tracker():
    return RemediationTracker()


# ── Tests: severity_key ───────────────────────────────────

class TestSeverityKey:

    @pytest.mark.unit
    def test_critical_lowest(self):
        assert severity_key(make_finding(severity="CRITICAL")) == 0

    @pytest.mark.unit
    def test_info_highest(self):
        assert severity_key(make_finding(severity="INFO")) == 4

    @pytest.mark.unit
    def test_sort_by_severity(self):
        findings = [
            make_finding(severity="LOW"),
            make_finding(severity="CRITICAL"),
            make_finding(severity="MEDIUM"),
        ]
        sorted_f = sorted(findings, key=severity_key)
        assert sorted_f[0]["severity"] == "CRITICAL"
        assert sorted_f[-1]["severity"] == "LOW"


# ── Tests: FindingAssignment ──────────────────────────────

class TestFindingAssignment:

    @pytest.mark.unit
    def test_assign(self, assignment):
        a = assignment.assign("f001", to_user="alice", by_user="lead")
        assert a.finding_id  == "f001"
        assert a.assigned_to == "alice"
        assert a.assigned_by == "lead"

    @pytest.mark.unit
    def test_assign_adds_to_team(self, assignment):
        assignment.assign("f001", to_user="newuser")
        assert "newuser" in assignment.team

    @pytest.mark.unit
    def test_get_assignment(self, assignment):
        assignment.assign("f001", to_user="alice")
        a = assignment.get_assignment("f001")
        assert a is not None
        assert a.assigned_to == "alice"

    @pytest.mark.unit
    def test_get_assignment_none(self, assignment):
        assert assignment.get_assignment("nonexistent") is None

    @pytest.mark.unit
    def test_reassign(self, assignment):
        assignment.assign("f001", to_user="alice")
        assignment.reassign("f001", to_user="bob")
        a = assignment.get_assignment("f001")
        assert a.assigned_to == "bob"

    @pytest.mark.unit
    def test_reassign_resolves_old(self, assignment):
        assignment.assign("f001", to_user="alice")
        assignment.reassign("f001", to_user="bob")
        # Old assignment should be resolved
        all_assignments = assignment._assignments
        alice_assignments = [a for a in all_assignments.values()
                             if a.assigned_to == "alice"]
        assert all(a.resolved for a in alice_assignments)

    @pytest.mark.unit
    def test_resolve(self, assignment):
        assignment.assign("f001", to_user="alice")
        count = assignment.resolve("f001")
        assert count == 1
        assert assignment.get_assignment("f001") is None

    @pytest.mark.unit
    def test_assign_bulk(self, assignment):
        assignments = assignment.assign_bulk(["f001", "f002", "f003"], to_user="alice")
        assert len(assignments) == 3

    @pytest.mark.unit
    def test_get_assignments_for_user(self, assignment):
        assignment.assign("f001", to_user="alice")
        assignment.assign("f002", to_user="alice")
        assignment.assign("f003", to_user="bob")
        alice_assignments = assignment.get_assignments_for_user("alice")
        assert len(alice_assignments) == 2

    @pytest.mark.unit
    def test_get_unassigned(self, assignment):
        assignment.assign("f001", to_user="alice")
        unassigned = assignment.get_unassigned(["f001", "f002", "f003"])
        assert "f001" not in unassigned
        assert "f002" in unassigned

    @pytest.mark.unit
    def test_workload(self, assignment):
        assignment.assign("f001", to_user="alice")
        assignment.assign("f002", to_user="alice")
        assignment.assign("f003", to_user="bob")
        wl = assignment.workload()
        assert wl["alice"] == 2
        assert wl["bob"]   == 1

    @pytest.mark.unit
    def test_assignment_with_due_date(self, assignment):
        a = assignment.assign("f001", to_user="alice", due_date="2025-12-31")
        assert a.due_date == "2025-12-31"


# ── Tests: CommentThread ──────────────────────────────────

class TestCommentThread:

    @pytest.mark.unit
    def test_add_comment(self, thread):
        c = thread.add_comment("f001", "alice", "Found SQLi confirmed!")
        assert c.finding_id == "f001"
        assert c.author     == "alice"
        assert c.body       == "Found SQLi confirmed!"

    @pytest.mark.unit
    def test_add_reply(self, thread):
        parent = thread.add_comment("f001", "alice", "Found it")
        reply  = thread.add_comment("f001", "bob", "Confirmed", parent_id=parent.id)
        assert reply.parent_id == parent.id

    @pytest.mark.unit
    def test_get_comments(self, thread):
        thread.add_comment("f001", "alice", "C1")
        thread.add_comment("f001", "bob",   "C2")
        thread.add_comment("f002", "alice", "Other finding")
        comments = thread.get_comments("f001")
        assert len(comments) == 2

    @pytest.mark.unit
    def test_get_top_level_only(self, thread):
        parent = thread.add_comment("f001", "alice", "Parent")
        thread.add_comment("f001", "bob", "Reply", parent_id=parent.id)
        top = thread.get_comments("f001", top_level_only=True)
        assert len(top) == 1

    @pytest.mark.unit
    def test_edit_comment(self, thread):
        c = thread.add_comment("f001", "alice", "Original")
        thread.edit_comment(c.id, "Edited body")
        assert c.body   == "Edited body"
        assert c.edited is True

    @pytest.mark.unit
    def test_delete_comment(self, thread):
        c = thread.add_comment("f001", "alice", "To delete")
        thread.delete_comment(c.id)
        assert c.body == "[deleted]"

    @pytest.mark.unit
    def test_react(self, thread):
        c = thread.add_comment("f001", "alice", "Comment")
        thread.react(c.id, "alice", "👍")
        assert "alice" in c.reactions.get("👍", [])

    @pytest.mark.unit
    def test_react_toggle(self, thread):
        c = thread.add_comment("f001", "alice", "Comment")
        thread.react(c.id, "alice", "👍")
        thread.react(c.id, "alice", "👍")  # Toggle off
        assert "alice" not in c.reactions.get("👍", [])

    @pytest.mark.unit
    def test_get_replies(self, thread):
        parent = thread.add_comment("f001", "alice", "Parent")
        thread.add_comment("f001", "bob", "Reply 1", parent_id=parent.id)
        thread.add_comment("f001", "charlie", "Reply 2", parent_id=parent.id)
        replies = thread.get_replies(parent.id)
        assert len(replies) == 2

    @pytest.mark.unit
    def test_get_mentions(self, thread):
        thread.add_comment("f001", "alice", "Hey @bob, can you check this?")
        thread.add_comment("f001", "bob", "@charlie please verify")
        mentions = thread.get_mentions("f001")
        assert "bob"     in mentions
        assert "charlie" in mentions

    @pytest.mark.unit
    def test_count(self, thread):
        thread.add_comment("f001", "alice", "C1")
        thread.add_comment("f001", "bob", "C2")
        assert thread.count("f001") == 2

    @pytest.mark.unit
    def test_total_comments(self, thread):
        thread.add_comment("f001", "alice", "C1")
        thread.add_comment("f002", "bob", "C2")
        assert thread.total_comments == 2


# ── Tests: AuditLog ───────────────────────────────────────

class TestAuditLog:

    @pytest.mark.unit
    def test_log_entry(self, audit):
        e = audit.log("f001", "alice", AuditAction.FINDING_ASSIGNED, new_value="bob")
        assert e.finding_id == "f001"
        assert e.actor      == "alice"
        assert e.action     == AuditAction.FINDING_ASSIGNED

    @pytest.mark.unit
    def test_get_log(self, audit):
        audit.log("f001", "alice", AuditAction.FINDING_ASSIGNED)
        audit.log("f001", "bob",   AuditAction.COMMENT_ADDED)
        audit.log("f002", "alice", AuditAction.STATUS_CHANGED)
        log = audit.get_log("f001")
        assert len(log) == 2

    @pytest.mark.unit
    def test_get_log_with_filter(self, audit):
        audit.log("f001", "alice", AuditAction.FINDING_ASSIGNED)
        audit.log("f001", "bob",   AuditAction.COMMENT_ADDED)
        comments = audit.get_log("f001", action_filter=AuditAction.COMMENT_ADDED)
        assert len(comments) == 1

    @pytest.mark.unit
    def test_get_actor_log(self, audit):
        audit.log("f001", "alice", AuditAction.FINDING_ASSIGNED)
        audit.log("f002", "alice", AuditAction.COMMENT_ADDED)
        audit.log("f003", "bob",   AuditAction.STATUS_CHANGED)
        alice_log = audit.get_actor_log("alice")
        assert len(alice_log) == 2

    @pytest.mark.unit
    def test_get_recent(self, audit):
        for i in range(5):
            audit.log(f"f{i:03}", "alice", AuditAction.FINDING_IMPORTED)
        recent = audit.get_recent(limit=3)
        assert len(recent) == 3

    @pytest.mark.unit
    def test_total_entries(self, audit):
        audit.log("f001", "alice", AuditAction.FINDING_ASSIGNED)
        audit.log("f002", "bob",   AuditAction.COMMENT_ADDED)
        assert audit.total_entries == 2

    @pytest.mark.unit
    def test_action_count(self, audit):
        audit.log("f001", "alice", AuditAction.COMMENT_ADDED)
        audit.log("f002", "alice", AuditAction.COMMENT_ADDED)
        audit.log("f003", "bob",   AuditAction.STATUS_CHANGED)
        assert audit.action_count(AuditAction.COMMENT_ADDED) == 2

    @pytest.mark.unit
    def test_audit_immutable_order(self, audit):
        audit.log("f001", "alice", AuditAction.FINDING_ASSIGNED)
        audit.log("f001", "bob",   AuditAction.COMMENT_ADDED)
        log = audit.get_log("f001")
        # Should be in chronological order
        assert log[0].action == AuditAction.FINDING_ASSIGNED
        assert log[1].action == AuditAction.COMMENT_ADDED

    @pytest.mark.unit
    def test_audit_action_constants(self):
        assert AuditAction.FINDING_ASSIGNED   == "finding_assigned"
        assert AuditAction.STATUS_CHANGED     == "status_changed"
        assert AuditAction.COMMENT_ADDED      == "comment_added"
        assert AuditAction.TICKET_LINKED      == "ticket_linked"


# ── Tests: RemediationTracker ─────────────────────────────

class TestRemediationTracker:

    @pytest.mark.unit
    def test_initialize(self, tracker):
        f = make_finding("f001")
        s = tracker.initialize(f)
        assert s.status     == "open"
        assert s.finding_id == "f001"

    @pytest.mark.unit
    def test_initialize_bulk(self, tracker):
        count = tracker.initialize_bulk(SAMPLE_FINDINGS)
        assert count == 5

    @pytest.mark.unit
    def test_update_status(self, tracker):
        tracker.initialize(make_finding("f001"))
        s = tracker.update_status("f001", "in_progress", owner="dev-team")
        assert s.status == "in_progress"
        assert s.owner  == "dev-team"

    @pytest.mark.unit
    def test_invalid_status_raises(self, tracker):
        tracker.initialize(make_finding("f001"))
        with pytest.raises(ValueError):
            tracker.update_status("f001", "invalid_status")

    @pytest.mark.unit
    def test_resolve_sets_resolved_at(self, tracker):
        tracker.initialize(make_finding("f001"))
        s = tracker.update_status("f001", "resolved")
        assert s.resolved_at != ""

    @pytest.mark.unit
    def test_link_ticket(self, tracker):
        tracker.initialize(make_finding("f001"))
        ok = tracker.link_ticket("f001", "https://jira.corp.com/VULN-123", "VULN-123")
        assert ok is True
        s = tracker.get_status("f001")
        assert s.ticket_url == "https://jira.corp.com/VULN-123"
        assert s.ticket_id  == "VULN-123"

    @pytest.mark.unit
    def test_get_open(self, tracker):
        tracker.initialize_bulk(SAMPLE_FINDINGS)
        tracker.update_status("f001", "resolved")
        open_statuses = tracker.get_open()
        assert all(s.is_open for s in open_statuses)
        assert len(open_statuses) == 4

    @pytest.mark.unit
    def test_get_by_owner(self, tracker):
        tracker.initialize_bulk(SAMPLE_FINDINGS)
        tracker.update_status("f001", "in_progress", owner="alice")
        tracker.update_status("f002", "in_progress", owner="alice")
        tracker.update_status("f003", "in_progress", owner="bob")
        alice_items = tracker.get_by_owner("alice")
        assert len(alice_items) == 2

    @pytest.mark.unit
    def test_is_open_property(self, tracker):
        tracker.initialize(make_finding("f001"))
        s = tracker.get_status("f001")
        assert s.is_open   is True
        assert s.is_closed is False

    @pytest.mark.unit
    def test_is_closed_after_resolve(self, tracker):
        tracker.initialize(make_finding("f001"))
        tracker.update_status("f001", "resolved")
        s = tracker.get_status("f001")
        assert s.is_closed is True
        assert s.is_open   is False

    @pytest.mark.unit
    def test_progress_summary(self, tracker):
        tracker.initialize_bulk(SAMPLE_FINDINGS)
        tracker.update_status("f001", "resolved")
        tracker.update_status("f002", "resolved")
        summary = tracker.progress_summary()
        assert summary["total"]        == 5
        assert summary["resolved"]     == 2
        assert summary["progress_pct"] == 40.0

    @pytest.mark.unit
    def test_check_sla_within(self, tracker):
        tracker.initialize(make_finding("f001"))
        created = datetime.now(timezone.utc).isoformat()
        ok = tracker.check_sla("f001", "HIGH", created)
        assert ok is True

    @pytest.mark.unit
    def test_check_sla_breach(self, tracker):
        tracker.initialize(make_finding("f001"))
        old_created = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        ok = tracker.check_sla("f001", "CRITICAL", old_created)  # SLA = 1 day
        assert ok is False

    @pytest.mark.unit
    def test_default_sla_days(self):
        assert DEFAULT_SLA_DAYS["CRITICAL"] == 1
        assert DEFAULT_SLA_DAYS["HIGH"]     == 7
        assert DEFAULT_SLA_DAYS["CRITICAL"] < DEFAULT_SLA_DAYS["HIGH"]

    @pytest.mark.unit
    def test_remediation_statuses_complete(self):
        assert "open" in REMEDIATION_STATUSES
        assert "in_progress" in REMEDIATION_STATUSES
        assert "resolved" in REMEDIATION_STATUSES
        assert "wont_fix" in REMEDIATION_STATUSES


# ── Tests: FindingWorkspace ───────────────────────────────

class TestFindingWorkspace:

    @pytest.mark.unit
    def test_init(self, workspace):
        assert workspace.workspace_name == "Test Workspace"
        assert workspace.finding_count  == 5

    @pytest.mark.unit
    def test_import_findings(self, workspace):
        new_findings = [make_finding("f999", "HIGH", "New Finding")]
        count = workspace.import_findings(new_findings, imported_by="bob")
        assert count == 1
        assert workspace.finding_count == 6

    @pytest.mark.unit
    def test_import_adds_audit_entry(self, workspace):
        log = workspace.get_audit_log("f001")
        imported = [e for e in log if e.action == AuditAction.FINDING_IMPORTED]
        assert len(imported) >= 1

    @pytest.mark.unit
    def test_assign_finding(self, workspace):
        a = workspace.assign("f001", to_user="alice", by_user="lead")
        assert a.assigned_to == "alice"

    @pytest.mark.unit
    def test_assign_creates_audit(self, workspace):
        workspace.assign("f001", to_user="alice", by_user="lead")
        log = workspace.get_audit_log("f001")
        assigned = [e for e in log if e.action == AuditAction.FINDING_ASSIGNED]
        assert len(assigned) == 1
        assert assigned[0].new_value == "alice"

    @pytest.mark.unit
    def test_reassign_finding(self, workspace):
        workspace.assign("f001", to_user="alice")
        workspace.reassign("f001", to_user="bob", by_user="lead")
        current = workspace.assignment.get_assignment("f001")
        assert current.assigned_to == "bob"

    @pytest.mark.unit
    def test_comment_finding(self, workspace):
        c = workspace.comment("f001", author="alice", body="Verified on prod")
        assert c.author == "alice"
        assert c.body   == "Verified on prod"

    @pytest.mark.unit
    def test_comment_creates_audit(self, workspace):
        workspace.comment("f001", author="alice", body="Test comment")
        log = workspace.get_audit_log("f001")
        commented = [e for e in log if e.action == AuditAction.COMMENT_ADDED]
        assert len(commented) == 1

    @pytest.mark.unit
    def test_update_remediation(self, workspace):
        s = workspace.update_remediation("f001", status="in_progress",
                                         owner="dev-team", updated_by="alice")
        assert s.status == "in_progress"
        assert s.owner  == "dev-team"

    @pytest.mark.unit
    def test_update_remediation_creates_audit(self, workspace):
        workspace.update_remediation("f001", status="in_progress", updated_by="alice")
        log = workspace.get_audit_log("f001")
        status_changes = [e for e in log if e.action == AuditAction.STATUS_CHANGED]
        assert len(status_changes) == 1
        assert status_changes[0].new_value == "in_progress"

    @pytest.mark.unit
    def test_link_ticket(self, workspace):
        ok = workspace.link_ticket("f001", "https://jira.corp/VULN-1", linked_by="alice")
        assert ok is True

    @pytest.mark.unit
    def test_list_findings_by_severity(self, workspace):
        critical = workspace.list_findings(severity="CRITICAL")
        assert all(f["severity"] == "CRITICAL" for f in critical)

    @pytest.mark.unit
    def test_list_findings_by_assignee(self, workspace):
        workspace.assign("f001", to_user="alice")
        workspace.assign("f002", to_user="alice")
        alice_findings = workspace.list_findings(assigned_to="alice")
        assert len(alice_findings) == 2

    @pytest.mark.unit
    def test_list_findings_by_status(self, workspace):
        workspace.update_remediation("f001", status="in_progress")
        in_progress = workspace.list_findings(status="in_progress")
        assert len(in_progress) == 1

    @pytest.mark.unit
    def test_list_findings_sorted_by_severity(self, workspace):
        from modules.collab.collaboration import SEVERITY_ORDER
        all_findings = workspace.list_findings()
        severities   = [f["severity"] for f in all_findings]
        order = [SEVERITY_ORDER.get(s, 99) for s in severities]
        assert order == sorted(order)

    @pytest.mark.unit
    def test_get_finding(self, workspace):
        f = workspace.get_finding("f001")
        assert f is not None
        assert f["title"] == "SQL Injection"

    @pytest.mark.unit
    def test_get_finding_unknown(self, workspace):
        assert workspace.get_finding("nonexistent") is None

    @pytest.mark.unit
    def test_dashboard(self, workspace):
        workspace.assign("f001", to_user="alice")
        workspace.comment("f001", "alice", "Test comment")
        d = workspace.dashboard()
        assert d["total_findings"]  == 5
        assert d["team_size"]       >= 3
        assert "severity_counts"    in d
        assert "remediation"        in d
        assert "workload"           in d

    @pytest.mark.unit
    def test_dashboard_severity_counts(self, workspace):
        d = workspace.dashboard()
        assert d["severity_counts"]["CRITICAL"] == 1
        assert d["severity_counts"]["HIGH"]     == 2

    @pytest.mark.unit
    def test_full_workflow(self, workspace):
        """Integration: assign → comment → update → link → audit."""
        workspace.assign("f001", to_user="alice", by_user="lead")
        workspace.comment("f001", author="alice", body="Verified SQLi at /search")
        workspace.update_remediation("f001", status="in_progress",
                                     owner="dev-backend", updated_by="alice")
        workspace.link_ticket("f001", "https://jira.corp/VULN-42", linked_by="alice")
        log = workspace.get_audit_log("f001")
        actions = [e.action for e in log]
        assert AuditAction.FINDING_IMPORTED in actions
        assert AuditAction.FINDING_ASSIGNED in actions
        assert AuditAction.COMMENT_ADDED    in actions
        assert AuditAction.STATUS_CHANGED   in actions
        assert AuditAction.TICKET_LINKED    in actions


# ── Tests: SEVERITY_ORDER ────────────────────────────────

class TestSeverityOrder:

    @pytest.mark.unit
    def test_critical_before_high(self):
        from modules.collab.collaboration import SEVERITY_ORDER
        assert SEVERITY_ORDER["CRITICAL"] < SEVERITY_ORDER["HIGH"]

    @pytest.mark.unit
    def test_info_last(self):
        from modules.collab.collaboration import SEVERITY_ORDER
        assert SEVERITY_ORDER["INFO"] == max(SEVERITY_ORDER.values())
