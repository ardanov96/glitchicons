# tests/test_v300_backend.py
"""
Unit tests untuk v3.0.0 Persistent Backend:
  - modules/core/database.py  (SQLAlchemy ORM)
  - modules/core/scheduler.py (APScheduler scan scheduler)
  - modules/core/webhooks.py  (Webhook notifications)

Database tests use SQLite in-memory for isolation.
Scheduler tests use APScheduler without starting background thread.
Webhook tests mock HTTP delivery.
"""

import json
import time
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from modules.core.database import (
    Database, Target, Scan, Finding,
    WebhookConfig, ScheduledScan, HAS_SQLALCHEMY,
)
from modules.core.scheduler import (
    ScanScheduler, ScheduleConfig, JobRunResult,
    parse_interval, parse_cron, format_schedule_expr,
)
from modules.core.webhooks import (
    WebhookManager, WebhookEndpoint, WebhookPayload,
    WebhookEvent, DeliveryResult, FireResult,
    sign_payload, verify_signature, ALL_EVENTS,
)


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def db():
    d = Database("sqlite:///:memory:")
    d.init()
    yield d
    d.drop_all()


@pytest.fixture
def scheduler():
    """Scheduler without starting background thread."""
    fired = []

    def mock_callback(target_id, modules, job_id):
        fired.append({"target_id": target_id, "modules": modules})
        return "scan-id-123"

    s = ScanScheduler(scan_callback=mock_callback)
    # Don't start — avoid background threads in tests
    yield s, fired


@pytest.fixture
def webhook_manager():
    wm = WebhookManager(timeout=5, max_retries=0)
    return wm


@pytest.fixture
def db_with_data(db):
    """Database with a target and scan pre-populated."""
    with db.session() as s:
        target = db.create_target(s, url="https://target.com", name="Target Corp",
                                  tags=["web", "prod"])
        scan   = db.create_scan(s, target_id=target.id, modules=["sqli", "xss"])
        db.start_scan(s, scan.id)
        db.add_finding(s, scan.id, "SQL Injection", "CRITICAL", cvss=9.8, cwe="CWE-89",
                       target_url="https://target.com/search")
        db.add_finding(s, scan.id, "XSS Reflected", "HIGH", cvss=7.4, cwe="CWE-79")
        db.add_finding(s, scan.id, "Missing HSTS", "MEDIUM", cvss=5.9, cwe="CWE-319")
        db.complete_scan(s, scan.id)
        return target.id, scan.id


# ── Tests: Database ───────────────────────────────────────

class TestDatabase:

    @pytest.mark.unit
    def test_init(self, db):
        assert db.engine is not None

    @pytest.mark.unit
    def test_session_context_manager(self, db):
        with db.session() as s:
            assert s is not None

    @pytest.mark.unit
    def test_create_target(self, db):
        with db.session() as s:
            t = db.create_target(s, url="https://target.com", name="Test")
        assert t.id is not None
        assert t.url == "https://target.com"
        assert t.name == "Test"

    @pytest.mark.unit
    def test_create_target_with_tags(self, db):
        with db.session() as s:
            t = db.create_target(s, url="https://t.com", tags=["web", "api"])
        assert "web" in t.tags_list

    @pytest.mark.unit
    def test_get_target(self, db):
        with db.session() as s:
            t1 = db.create_target(s, url="https://t.com")
            t2 = db.get_target(s, t1.id)
        assert t2.id == t1.id

    @pytest.mark.unit
    def test_get_target_by_url(self, db):
        with db.session() as s:
            db.create_target(s, url="https://specific.com")
            found = db.get_target_by_url(s, "https://specific.com")
        assert found is not None

    @pytest.mark.unit
    def test_get_unknown_target_none(self, db):
        with db.session() as s:
            assert db.get_target(s, "nonexistent-id") is None

    @pytest.mark.unit
    def test_list_targets(self, db):
        with db.session() as s:
            db.create_target(s, url="https://a.com")
            db.create_target(s, url="https://b.com")
            targets = db.list_targets(s)
        assert len(targets) >= 2

    @pytest.mark.unit
    def test_delete_target_soft(self, db):
        with db.session() as s:
            t = db.create_target(s, url="https://del.com")
            db.delete_target(s, t.id)
            active = db.list_targets(s, active_only=True)
        assert not any(t2.url == "https://del.com" for t2 in active)

    @pytest.mark.unit
    def test_create_scan(self, db):
        with db.session() as s:
            t    = db.create_target(s, url="https://t.com")
            scan = db.create_scan(s, t.id, modules=["sqli", "xss"])
        assert scan.id is not None
        assert scan.status == "pending"
        assert "sqli" in scan.modules_list

    @pytest.mark.unit
    def test_start_scan(self, db):
        with db.session() as s:
            t    = db.create_target(s, url="https://t.com")
            scan = db.create_scan(s, t.id)
            ok   = db.start_scan(s, scan.id)
        assert ok is True
        assert scan.status == "running"
        assert scan.started_at is not None

    @pytest.mark.unit
    def test_complete_scan(self, db):
        with db.session() as s:
            t    = db.create_target(s, url="https://t.com")
            scan = db.create_scan(s, t.id)
            db.start_scan(s, scan.id)
            ok   = db.complete_scan(s, scan.id)
        assert ok is True
        assert scan.status == "completed"
        assert scan.completed_at is not None

    @pytest.mark.unit
    def test_complete_scan_updates_duration(self, db):
        with db.session() as s:
            t    = db.create_target(s, url="https://t.com")
            scan = db.create_scan(s, t.id)
            db.start_scan(s, scan.id)
            db.complete_scan(s, scan.id)
        assert scan.duration_s >= 0

    @pytest.mark.unit
    def test_cancel_scan(self, db):
        with db.session() as s:
            t    = db.create_target(s, url="https://t.com")
            scan = db.create_scan(s, t.id)
            ok   = db.cancel_scan(s, scan.id)
        assert ok is True
        assert scan.status == "cancelled"

    @pytest.mark.unit
    def test_list_scans_by_target(self, db):
        with db.session() as s:
            t = db.create_target(s, url="https://t.com")
            db.create_scan(s, t.id)
            db.create_scan(s, t.id)
            scans = db.list_scans(s, target_id=t.id)
        assert len(scans) == 2

    @pytest.mark.unit
    def test_add_finding(self, db):
        with db.session() as s:
            t = db.create_target(s, url="https://t.com")
            scan = db.create_scan(s, t.id)
            f = db.add_finding(s, scan.id, "SQLi", "CRITICAL", cvss=9.8, cwe="CWE-89")
        assert f.id is not None
        assert f.severity == "CRITICAL"
        assert f.cvss == 9.8

    @pytest.mark.unit
    def test_add_finding_invalid_severity(self, db):
        with db.session() as s:
            t = db.create_target(s, url="https://t.com")
            scan = db.create_scan(s, t.id)
            with pytest.raises(AssertionError):
                db.add_finding(s, scan.id, "Bad", "EXTREME")

    @pytest.mark.unit
    def test_add_findings_bulk(self, db):
        with db.session() as s:
            t = db.create_target(s, url="https://t.com")
            scan = db.create_scan(s, t.id)
            findings = [
                {"title": "F1", "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-79"},
                {"title": "F2", "severity": "MEDIUM", "cvss": 5.0, "cwe": "CWE-89"},
                {"title": "F3", "severity": "INVALID", "cvss": 0.0, "cwe": ""},  # skipped
            ]
            count = db.add_findings_bulk(s, scan.id, findings)
        assert count == 2

    @pytest.mark.unit
    def test_list_findings_by_scan(self, db, db_with_data):
        target_id, scan_id = db_with_data
        with db.session() as s:
            findings = db.list_findings(s, scan_id=scan_id)
        assert len(findings) >= 2

    @pytest.mark.unit
    def test_list_findings_by_severity(self, db, db_with_data):
        target_id, scan_id = db_with_data
        with db.session() as s:
            critical = db.list_findings(s, scan_id=scan_id, severity="CRITICAL")
        assert all(f.severity == "CRITICAL" for f in critical)

    @pytest.mark.unit
    def test_mark_false_positive(self, db):
        with db.session() as s:
            t = db.create_target(s, url="https://t.com")
            scan = db.create_scan(s, t.id)
            f = db.add_finding(s, scan.id, "FP Finding", "LOW", cvss=0.0)
            db.mark_false_positive(s, f.id, True)
        assert f.false_positive is True

    @pytest.mark.unit
    def test_mark_verified(self, db):
        with db.session() as s:
            t = db.create_target(s, url="https://t.com")
            scan = db.create_scan(s, t.id)
            f = db.add_finding(s, scan.id, "Verified F", "HIGH", cvss=7.5)
            db.mark_verified(s, f.id)
        assert f.verified is True

    @pytest.mark.unit
    def test_finding_to_dict(self, db):
        with db.session() as s:
            t = db.create_target(s, url="https://t.com")
            scan = db.create_scan(s, t.id)
            f = db.add_finding(s, scan.id, "Test", "HIGH", cvss=7.5, cwe="CWE-79")
            d = f.to_dict()
        assert "id" in d
        assert d["severity"] == "HIGH"

    @pytest.mark.unit
    def test_create_webhook(self, db):
        with db.session() as s:
            wh = db.create_webhook(s, name="Slack", url="https://hooks.slack.com/xxx")
        assert wh.id is not None
        assert wh.name == "Slack"

    @pytest.mark.unit
    def test_list_webhooks_enabled(self, db):
        with db.session() as s:
            db.create_webhook(s, name="W1", url="https://w1.com")
            db.create_webhook(s, name="W2", url="https://w2.com")
            whs = db.list_webhooks(s)
        assert len(whs) >= 2

    @pytest.mark.unit
    def test_stats(self, db, db_with_data):
        with db.session() as s:
            stats = db.stats(s)
        assert stats["targets"] >= 1
        assert stats["scans"] >= 1
        assert stats["findings"] >= 3

    @pytest.mark.unit
    def test_complete_scan_counts_findings(self, db, db_with_data):
        target_id, scan_id = db_with_data
        with db.session() as s:
            scan = db.get_scan(s, scan_id)
        assert scan.finding_count >= 3
        assert scan.critical_count >= 1

    @pytest.mark.unit
    def test_severity_breakdown(self, db, db_with_data):
        target_id, scan_id = db_with_data
        with db.session() as s:
            breakdown = db.finding_severity_breakdown(s, scan_id)
        assert "CRITICAL" in breakdown
        assert "HIGH" in breakdown

    @pytest.mark.unit
    def test_scan_is_running(self, db):
        with db.session() as s:
            t    = db.create_target(s, url="https://t.com")
            scan = db.create_scan(s, t.id)
            db.start_scan(s, scan.id)
        assert scan.is_running is True

    @pytest.mark.unit
    def test_scan_is_complete(self, db):
        with db.session() as s:
            t    = db.create_target(s, url="https://t.com")
            scan = db.create_scan(s, t.id)
            db.start_scan(s, scan.id)
            db.complete_scan(s, scan.id)
        assert scan.is_complete is True


# ── Tests: Scheduler ─────────────────────────────────────

class TestScheduler:

    @pytest.mark.unit
    def test_parse_interval_minutes(self):
        td = parse_interval("30m")
        assert td == timedelta(minutes=30)

    @pytest.mark.unit
    def test_parse_interval_hours(self):
        td = parse_interval("6h")
        assert td == timedelta(hours=6)

    @pytest.mark.unit
    def test_parse_interval_days(self):
        td = parse_interval("1d")
        assert td == timedelta(days=1)

    @pytest.mark.unit
    def test_parse_interval_weeks(self):
        td = parse_interval("2w")
        assert td == timedelta(weeks=2)

    @pytest.mark.unit
    def test_parse_interval_invalid(self):
        assert parse_interval("invalid") is None
        assert parse_interval("") is None
        assert parse_interval("5x") is None

    @pytest.mark.unit
    def test_parse_cron_valid(self):
        result = parse_cron("0 2 * * 1")
        assert result == {"minute": "0", "hour": "2", "day": "*",
                          "month": "*", "day_of_week": "1"}

    @pytest.mark.unit
    def test_parse_cron_invalid(self):
        assert parse_cron("0 2 *") is None
        assert parse_cron("") is None

    @pytest.mark.unit
    def test_format_schedule_interval(self):
        result = format_schedule_expr("interval", "6h")
        assert "6" in result and "hour" in result.lower()

    @pytest.mark.unit
    def test_format_schedule_cron(self):
        result = format_schedule_expr("cron", "0 2 * * *")
        assert "cron" in result.lower() or "0 2" in result

    @pytest.mark.unit
    def test_init(self, scheduler):
        s, fired = scheduler
        assert s.job_count == 0
        assert s.is_running is False

    @pytest.mark.unit
    def test_add_interval_job(self, scheduler):
        s, fired = scheduler
        job_id = s.add_interval_job("target-uuid", interval_hours=24,
                                    modules=["sqli"], job_name="Daily Scan")
        assert job_id in s._configs
        config = s.get_job(job_id)
        assert config.schedule_type == "interval"
        assert config.target_id == "target-uuid"
        assert "sqli" in config.modules

    @pytest.mark.unit
    def test_add_interval_job_with_expr(self, scheduler):
        s, fired = scheduler
        job_id = s.add_interval_job("target-uuid", interval_expr="6h")
        config = s.get_job(job_id)
        assert config.schedule_expr == "6h"

    @pytest.mark.unit
    def test_add_interval_job_invalid_expr(self, scheduler):
        s, fired = scheduler
        with pytest.raises(ValueError):
            s.add_interval_job("target-uuid", interval_expr="invalid")

    @pytest.mark.unit
    def test_add_cron_job(self, scheduler):
        s, fired = scheduler
        job_id = s.add_cron_job("target-uuid", cron_expr="0 2 * * 1",
                                modules=["all"], job_name="Weekly")
        config = s.get_job(job_id)
        assert config.schedule_type == "cron"
        assert config.schedule_expr == "0 2 * * 1"

    @pytest.mark.unit
    def test_add_cron_job_invalid(self, scheduler):
        s, fired = scheduler
        with pytest.raises(ValueError):
            s.add_cron_job("target-uuid", cron_expr="not a cron")

    @pytest.mark.unit
    def test_remove_job(self, scheduler):
        s, fired = scheduler
        job_id = s.add_interval_job("target-uuid")
        assert s.remove_job(job_id) is True
        assert s.get_job(job_id) is None

    @pytest.mark.unit
    def test_remove_unknown_job(self, scheduler):
        s, fired = scheduler
        assert s.remove_job("nonexistent") is False

    @pytest.mark.unit
    def test_pause_resume_job(self, scheduler):
        s, fired = scheduler
        job_id = s.add_interval_job("target-uuid")
        assert s.pause_job(job_id) is True
        assert s.get_job(job_id).enabled is False
        assert s.resume_job(job_id) is True
        assert s.get_job(job_id).enabled is True

    @pytest.mark.unit
    def test_list_jobs(self, scheduler):
        s, fired = scheduler
        s.add_interval_job("t1", interval_hours=24)
        s.add_interval_job("t2", interval_hours=12)
        jobs = s.list_jobs()
        assert len(jobs) == 2

    @pytest.mark.unit
    def test_list_jobs_for_target(self, scheduler):
        s, fired = scheduler
        s.add_interval_job("target-A")
        s.add_interval_job("target-A")
        s.add_interval_job("target-B")
        jobs = s.list_jobs_for_target("target-A")
        assert len(jobs) == 2

    @pytest.mark.unit
    def test_fire_job_calls_callback(self, scheduler):
        s, fired = scheduler
        job_id = s.add_interval_job("target-uuid", modules=["sqli"])
        result = s._fire_job(job_id)
        assert result.status == "success"
        assert len(fired) == 1
        assert fired[0]["target_id"] == "target-uuid"

    @pytest.mark.unit
    def test_fire_job_increments_run_count(self, scheduler):
        s, fired = scheduler
        job_id = s.add_interval_job("target-uuid")
        s._fire_job(job_id)
        s._fire_job(job_id)
        assert s.get_job(job_id).run_count == 2

    @pytest.mark.unit
    def test_fire_disabled_job_skipped(self, scheduler):
        s, fired = scheduler
        job_id = s.add_interval_job("target-uuid")
        s.pause_job(job_id)
        result = s._fire_job(job_id)
        assert result.status == "skipped"
        assert len(fired) == 0

    @pytest.mark.unit
    def test_schedule_config_to_dict(self, scheduler):
        s, fired = scheduler
        job_id = s.add_interval_job("target-uuid", job_name="Test Job")
        d = s.get_job(job_id).to_dict()
        assert "job_id" in d
        assert "target_id" in d
        assert d["job_name"] == "Test Job"


# ── Tests: Webhooks ───────────────────────────────────────

class TestWebhooks:

    @pytest.mark.unit
    def test_sign_payload(self):
        sig = sign_payload("test body", "secret123")
        assert sig.startswith("sha256=")
        assert len(sig) > 10

    @pytest.mark.unit
    def test_sign_payload_empty_secret(self):
        sig = sign_payload("test body", "")
        assert sig == ""

    @pytest.mark.unit
    def test_verify_signature_valid(self):
        body = '{"event":"test"}'
        sig  = sign_payload(body, "secret123")
        assert verify_signature(body, "secret123", sig) is True

    @pytest.mark.unit
    def test_verify_signature_invalid(self):
        assert verify_signature("body", "secret", "sha256=wrong") is False

    @pytest.mark.unit
    def test_webhook_payload_to_json(self):
        p = WebhookPayload(event="scan_completed", timestamp="2024-01-01T00:00:00Z",
                           data={"scan_id": "123"})
        raw  = p.to_json()
        data = json.loads(raw)
        assert data["event"] == "scan_completed"
        assert data["data"]["scan_id"] == "123"

    @pytest.mark.unit
    def test_add_endpoint(self, webhook_manager):
        ep_id = webhook_manager.add_endpoint(
            name="Slack", url="https://hooks.slack.com/xxx",
            events=["scan_completed"],
        )
        assert ep_id is not None
        ep = webhook_manager.get_endpoint(ep_id)
        assert ep.name == "Slack"

    @pytest.mark.unit
    def test_add_endpoint_default_events(self, webhook_manager):
        ep_id = webhook_manager.add_endpoint("Test", "https://test.com")
        ep    = webhook_manager.get_endpoint(ep_id)
        assert len(ep.events) == len(ALL_EVENTS)

    @pytest.mark.unit
    def test_remove_endpoint(self, webhook_manager):
        ep_id = webhook_manager.add_endpoint("Test", "https://test.com")
        assert webhook_manager.remove_endpoint(ep_id) is True
        assert webhook_manager.get_endpoint(ep_id) is None

    @pytest.mark.unit
    def test_enable_disable_endpoint(self, webhook_manager):
        ep_id = webhook_manager.add_endpoint("Test", "https://test.com")
        webhook_manager.disable_endpoint(ep_id)
        assert webhook_manager.get_endpoint(ep_id).enabled is False
        webhook_manager.enable_endpoint(ep_id)
        assert webhook_manager.get_endpoint(ep_id).enabled is True

    @pytest.mark.unit
    def test_listens_to_event(self, webhook_manager):
        ep_id = webhook_manager.add_endpoint("T", "https://t.com",
                                             events=["scan_completed"])
        ep    = webhook_manager.get_endpoint(ep_id)
        assert ep.listens_to("scan_completed") is True
        assert ep.listens_to("finding_critical") is False

    @pytest.mark.unit
    def test_listens_to_wildcard(self):
        ep = WebhookEndpoint(id="x", name="x", url="x", events=["*"])
        assert ep.listens_to("any_event") is True

    @pytest.mark.unit
    def test_fire_success(self, webhook_manager):
        ep_id = webhook_manager.add_endpoint("Test", "https://test.com",
                                             events=["scan_completed"])
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch.object(webhook_manager._client, "post", return_value=mock_resp):
            result = webhook_manager.fire(WebhookEvent.SCAN_COMPLETED, {"scan_id": "123"})
        assert result.delivered == 1
        assert result.failed == 0

    @pytest.mark.unit
    def test_fire_skips_unsubscribed(self, webhook_manager):
        webhook_manager.add_endpoint("Test", "https://test.com",
                                     events=["scan_completed"])
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch.object(webhook_manager._client, "post", return_value=mock_resp):
            result = webhook_manager.fire(WebhookEvent.FINDING_CRITICAL, {})
        assert result.delivered == 0
        assert result.skipped == 1

    @pytest.mark.unit
    def test_fire_http_error(self, webhook_manager):
        webhook_manager.add_endpoint("Test", "https://test.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        with patch.object(webhook_manager._client, "post", return_value=mock_resp):
            result = webhook_manager.fire(WebhookEvent.SCAN_COMPLETED, {})
        assert result.failed == 1

    @pytest.mark.unit
    def test_fire_connection_error(self, webhook_manager):
        webhook_manager.add_endpoint("Test", "https://test.com")
        with patch.object(webhook_manager._client, "post",
                          side_effect=Exception("Connection refused")):
            result = webhook_manager.fire(WebhookEvent.SCAN_COMPLETED, {})
        assert result.failed == 1

    @pytest.mark.unit
    def test_fire_disabled_endpoint_skipped(self, webhook_manager):
        ep_id = webhook_manager.add_endpoint("Test", "https://test.com")
        webhook_manager.disable_endpoint(ep_id)
        result = webhook_manager.fire(WebhookEvent.SCAN_COMPLETED, {})
        assert result.delivered == 0
        assert result.skipped == 1

    @pytest.mark.unit
    def test_fire_updates_history(self, webhook_manager):
        webhook_manager.add_endpoint("Test", "https://test.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch.object(webhook_manager._client, "post", return_value=mock_resp):
            webhook_manager.fire(WebhookEvent.SCAN_COMPLETED, {})
        history = webhook_manager.get_history()
        assert len(history) == 1

    @pytest.mark.unit
    def test_fire_scan_started(self, webhook_manager):
        webhook_manager.add_endpoint("Test", "https://test.com",
                                     events=["scan_started"])
        mock_resp = MagicMock(status_code=200)
        with patch.object(webhook_manager._client, "post", return_value=mock_resp):
            result = webhook_manager.fire_scan_started("scan-id", "https://t.com", ["sqli"])
        assert result.delivered == 1

    @pytest.mark.unit
    def test_fire_scan_completed(self, webhook_manager):
        webhook_manager.add_endpoint("Test", "https://test.com",
                                     events=["scan_completed"])
        mock_resp = MagicMock(status_code=200)
        with patch.object(webhook_manager._client, "post", return_value=mock_resp):
            result = webhook_manager.fire_scan_completed(
                "scan-id", "https://t.com", 10, 2, 45.0)
        assert result.delivered == 1

    @pytest.mark.unit
    def test_fire_finding(self, webhook_manager):
        webhook_manager.add_endpoint("Test", "https://test.com",
                                     events=["finding_critical"])
        mock_resp = MagicMock(status_code=200)
        finding = {"title": "SQLi", "severity": "CRITICAL", "cvss": 9.8}
        with patch.object(webhook_manager._client, "post", return_value=mock_resp):
            result = webhook_manager.fire_finding(finding)
        assert result.delivered == 1

    @pytest.mark.unit
    def test_get_stats(self, webhook_manager):
        webhook_manager.add_endpoint("W1", "https://w1.com")
        stats = webhook_manager.get_stats()
        assert stats["endpoints"] == 1
        assert "total_deliveries" in stats

    @pytest.mark.unit
    def test_fire_increments_endpoint_count(self, webhook_manager):
        ep_id = webhook_manager.add_endpoint("Test", "https://test.com")
        mock_resp = MagicMock(status_code=200)
        with patch.object(webhook_manager._client, "post", return_value=mock_resp):
            webhook_manager.fire(WebhookEvent.SCAN_COMPLETED, {})
        ep = webhook_manager.get_endpoint(ep_id)
        assert ep.fire_count == 1

    @pytest.mark.unit
    def test_webhook_events_enum(self):
        assert WebhookEvent.SCAN_STARTED.value    == "scan_started"
        assert WebhookEvent.SCAN_COMPLETED.value  == "scan_completed"
        assert WebhookEvent.FINDING_CRITICAL.value == "finding_critical"

    @pytest.mark.unit
    def test_all_events_not_empty(self):
        assert len(ALL_EVENTS) >= 4
        assert "scan_completed" in ALL_EVENTS
        assert "finding_critical" in ALL_EVENTS
