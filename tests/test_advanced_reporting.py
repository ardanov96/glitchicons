# tests/test_advanced_reporting.py
"""
Unit tests untuk v1.6.0 Advanced Reporting:
  - modules/report/pdf_reporter.py
  - modules/report/executive_dashboard.py
  - modules/report/remediation_tracker.py
"""

import json
import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta

from modules.report.pdf_reporter import (
    PDFReporter, SEVERITY_COLORS_HEX, SEVERITY_ORDER, _hex_to_rgb,
)
from modules.report.executive_dashboard import (
    ExecutiveDashboard, SEVERITY_COLORS, SEVERITY_BG,
)
from modules.report.remediation_tracker import (
    RemediationTracker, VALID_STATUSES, STATUS_COLORS,
)


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def sample_findings():
    return [
        {
            "id":          "FIND-001",
            "title":       "SQL Injection in /api/search",
            "severity":    "CRITICAL",
            "cvss":        9.8,
            "cwe":         "CWE-89",
            "target":      "https://target.com/api/search",
            "description": "SQLi found in q parameter.",
            "evidence":    "MySQL error: syntax near '",
            "remediation": "Use parameterized queries.",
        },
        {
            "id":          "FIND-002",
            "title":       "Reflected XSS in /search",
            "severity":    "HIGH",
            "cvss":        7.5,
            "cwe":         "CWE-79",
            "target":      "https://target.com/search",
            "description": "XSS reflected in q parameter.",
            "evidence":    "<script>alert(1)</script>",
            "remediation": "Sanitize output with escaping.",
        },
        {
            "id":          "FIND-003",
            "title":       "Missing Security Headers",
            "severity":    "MEDIUM",
            "cvss":        5.3,
            "cwe":         "CWE-693",
            "target":      "https://target.com",
            "description": "X-Frame-Options missing.",
            "evidence":    "HTTP headers missing",
            "remediation": "Add security headers.",
        },
        {
            "id":          "FIND-004",
            "title":       "Verbose Error Messages",
            "severity":    "LOW",
            "cvss":        2.7,
            "cwe":         "CWE-209",
            "target":      "https://target.com/api",
            "description": "Stack traces exposed.",
            "evidence":    "Django traceback visible",
            "remediation": "Set DEBUG=False.",
        },
    ]


@pytest.fixture
def pdf_reporter(sample_findings, tmp_path):
    return PDFReporter(
        findings=sample_findings,
        target="target.com",
        output_dir=str(tmp_path),
        engagement_name="Test Engagement",
    )


@pytest.fixture
def dashboard(sample_findings, tmp_path):
    return ExecutiveDashboard(
        findings=sample_findings,
        target="target.com",
        output_dir=str(tmp_path),
        engagement_name="Test Engagement",
    )


@pytest.fixture
def tracker(sample_findings, tmp_path):
    t = RemediationTracker(
        engagement_id="test_eng_2026",
        findings=sample_findings,
        output_dir=str(tmp_path),
    )
    t.load_or_init()
    return t


# ── Tests: _hex_to_rgb ────────────────────────────────────

class TestHexToRgb:

    @pytest.mark.unit
    def test_white(self):
        assert _hex_to_rgb("#FFFFFF") == (1.0, 1.0, 1.0)

    @pytest.mark.unit
    def test_black(self):
        assert _hex_to_rgb("#000000") == (0.0, 0.0, 0.0)

    @pytest.mark.unit
    def test_red(self):
        r, g, b = _hex_to_rgb("#FF0000")
        assert r == 1.0
        assert g == 0.0
        assert b == 0.0

    @pytest.mark.unit
    def test_strips_hash(self):
        assert _hex_to_rgb("#A855F7") == _hex_to_rgb("A855F7")

    @pytest.mark.unit
    def test_values_in_range(self):
        for hex_color in SEVERITY_COLORS_HEX.values():
            r, g, b = _hex_to_rgb(hex_color)
            assert 0.0 <= r <= 1.0
            assert 0.0 <= g <= 1.0
            assert 0.0 <= b <= 1.0


# ── Tests: PDFReporter ────────────────────────────────────

class TestPDFReporter:

    @pytest.mark.unit
    def test_init(self, pdf_reporter, sample_findings):
        assert pdf_reporter.target == "target.com"
        assert len(pdf_reporter.findings) == len(sample_findings)

    @pytest.mark.unit
    def test_counts_computed(self, pdf_reporter):
        assert pdf_reporter.counts["CRITICAL"] == 1
        assert pdf_reporter.counts["HIGH"] == 1
        assert pdf_reporter.counts["MEDIUM"] == 1
        assert pdf_reporter.counts["LOW"] == 1

    @pytest.mark.unit
    def test_findings_sorted_by_severity(self, pdf_reporter):
        severities = [f["severity"] for f in pdf_reporter.sorted_findings]
        assert severities[0] == "CRITICAL"
        assert severities[-1] == "LOW"

    @pytest.mark.unit
    def test_overall_risk_critical(self, pdf_reporter):
        assert pdf_reporter._overall_risk() == "CRITICAL"

    @pytest.mark.unit
    def test_overall_risk_no_critical(self, tmp_path):
        findings = [{"severity": "HIGH", "cvss": 7.5, "cwe": "CWE-89",
                     "title": "T", "description": "d", "evidence": "e",
                     "remediation": "r", "target": "t"}]
        reporter = PDFReporter(findings=findings, target="t", output_dir=str(tmp_path))
        assert reporter._overall_risk() == "HIGH"

    @pytest.mark.unit
    def test_overall_risk_empty(self, tmp_path):
        reporter = PDFReporter(findings=[], target="t", output_dir=str(tmp_path))
        assert reporter._overall_risk() == "INFO"

    @pytest.mark.unit
    def test_risk_label_critical(self, pdf_reporter):
        label = pdf_reporter._risk_label("CRITICAL")
        assert "Immediate" in label or "required" in label

    @pytest.mark.unit
    def test_risk_label_all_severities(self, pdf_reporter):
        for sev in SEVERITY_ORDER:
            label = pdf_reporter._risk_label(sev)
            assert isinstance(label, str)

    @pytest.mark.unit
    def test_generate_falls_back_to_json(self, pdf_reporter, tmp_path):
        """_generate_json_fallback always works regardless of reportlab."""
        path = pdf_reporter._generate_json_fallback()
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "findings" in data

    @pytest.mark.unit
    def test_json_fallback_structure(self, pdf_reporter, tmp_path):
        path = pdf_reporter._generate_json_fallback()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["target"] == "target.com"
        assert data["engagement"] == "Test Engagement"
        assert "severity_counts" in data
        assert "overall_risk" in data
        assert len(data["findings"]) == 4

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path, sample_findings):
        out = tmp_path / "subdir" / "reports"
        PDFReporter(findings=sample_findings, target="t", output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_engagement_name_default(self, tmp_path, sample_findings):
        r = PDFReporter(findings=sample_findings, target="target.com",
                        output_dir=str(tmp_path))
        assert "target.com" in r.engagement_name

    @pytest.mark.unit
    def test_severity_colors_complete(self):
        for sev in SEVERITY_ORDER:
            assert sev in SEVERITY_COLORS_HEX
            assert SEVERITY_COLORS_HEX[sev].startswith("#")


# ── Tests: ExecutiveDashboard ─────────────────────────────

class TestExecutiveDashboard:

    @pytest.mark.unit
    def test_init(self, dashboard, sample_findings):
        assert dashboard.target == "target.com"
        assert len(dashboard.findings) == len(sample_findings)

    @pytest.mark.unit
    def test_counts_computed(self, dashboard):
        assert dashboard.counts["CRITICAL"] == 1
        assert dashboard.counts["HIGH"] == 1

    @pytest.mark.unit
    def test_generate_creates_html_file(self, dashboard):
        path = dashboard.generate()
        assert path.exists()
        assert path.suffix == ".html"

    @pytest.mark.unit
    def test_html_contains_chart_js(self, dashboard):
        html = dashboard._build_html()
        assert "chart.umd.min.js" in html or "Chart.js" in html.lower()

    @pytest.mark.unit
    def test_html_contains_target(self, dashboard):
        html = dashboard._build_html()
        assert "target.com" in html

    @pytest.mark.unit
    def test_html_contains_engagement_name(self, dashboard):
        html = dashboard._build_html()
        assert "Test Engagement" in html

    @pytest.mark.unit
    def test_html_contains_all_severities(self, dashboard):
        html = dashboard._build_html()
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            assert sev in html

    @pytest.mark.unit
    def test_html_contains_finding_titles(self, dashboard):
        html = dashboard._build_html()
        assert "SQL Injection" in html
        assert "Reflected XSS" in html

    @pytest.mark.unit
    def test_finding_card_structure(self, dashboard, sample_findings):
        card = dashboard._finding_card(1, sample_findings[0])
        assert "CRITICAL" in card
        assert "SQL Injection" in card
        assert "finding-card" in card

    @pytest.mark.unit
    def test_stat_cards_generated(self, dashboard):
        stats = dashboard._stat_cards()
        assert "CRITICAL" in stats
        assert "HIGH" in stats

    @pytest.mark.unit
    def test_overall_risk_critical(self, dashboard):
        assert dashboard._overall_risk() == "CRITICAL"

    @pytest.mark.unit
    def test_top5_row_structure(self, dashboard, sample_findings):
        row = dashboard._top5_row(sample_findings[0])
        assert "CRITICAL" in row
        assert "SQL Injection" in row

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path, sample_findings):
        out = tmp_path / "sub" / "dash"
        ExecutiveDashboard(findings=sample_findings, target="t", output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_html_is_valid_structure(self, dashboard):
        html = dashboard._build_html()
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html
        assert "<body>" in html
        assert "</body>" in html

    @pytest.mark.unit
    def test_empty_findings_still_generates(self, tmp_path):
        dash = ExecutiveDashboard(findings=[], target="t", output_dir=str(tmp_path))
        html = dash._build_html()
        assert "0" in html  # Zero findings shown
        assert "<!DOCTYPE html>" in html


# ── Tests: RemediationTracker ─────────────────────────────

class TestRemediationTracker:

    @pytest.mark.unit
    def test_init_creates_output_dir(self, tmp_path):
        out = tmp_path / "remediation"
        RemediationTracker("eng", output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_load_or_init_creates_items(self, tracker):
        assert tracker.item_count == 4

    @pytest.mark.unit
    def test_all_items_open_initially(self, tracker):
        for item in tracker.all_items():
            assert item["status"] == "OPEN"

    @pytest.mark.unit
    def test_update_status(self, tracker):
        items = tracker.all_items()
        fid = items[0]["id"]
        result = tracker.update(fid, status="IN_PROGRESS")
        assert result is not None
        assert result["status"] == "IN_PROGRESS"

    @pytest.mark.unit
    def test_update_invalid_status_raises(self, tracker):
        items = tracker.all_items()
        fid = items[0]["id"]
        with pytest.raises(ValueError):
            tracker.update(fid, status="INVALID_STATUS")

    @pytest.mark.unit
    def test_update_nonexistent_returns_none(self, tracker):
        result = tracker.update("NONEXISTENT-ID")
        assert result is None

    @pytest.mark.unit
    def test_update_assignee(self, tracker):
        items = tracker.all_items()
        fid = items[0]["id"]
        tracker.update(fid, assignee="dev@target.com")
        assert tracker.get(fid)["assignee"] == "dev@target.com"

    @pytest.mark.unit
    def test_update_due_days(self, tracker):
        items = tracker.all_items()
        fid = items[0]["id"]
        tracker.update(fid, due_days=7)
        due = tracker.get(fid)["due_date"]
        assert due is not None
        assert len(due) == 10  # YYYY-MM-DD

    @pytest.mark.unit
    def test_update_note_appended(self, tracker):
        items = tracker.all_items()
        fid = items[0]["id"]
        tracker.update(fid, note="First note")
        tracker.update(fid, note="Second note")
        notes = tracker.get(fid)["notes"]
        assert len(notes) == 2
        assert notes[0]["text"] == "First note"

    @pytest.mark.unit
    def test_mark_fixed(self, tracker):
        items = tracker.all_items()
        fid = items[0]["id"]
        tracker.mark_fixed(fid, note="Fixed in v2.1.0")
        assert tracker.get(fid)["status"] == "FIXED"

    @pytest.mark.unit
    def test_accept_risk_requires_reason(self, tracker):
        items = tracker.all_items()
        fid = items[0]["id"]
        with pytest.raises(ValueError):
            tracker.accept_risk(fid, reason="")

    @pytest.mark.unit
    def test_accept_risk_with_reason(self, tracker):
        items = tracker.all_items()
        fid = items[0]["id"]
        tracker.accept_risk(fid, reason="Cost-benefit analysis")
        assert tracker.get(fid)["status"] == "ACCEPTED_RISK"

    @pytest.mark.unit
    def test_by_status_filter(self, tracker):
        items = tracker.all_items()
        tracker.update(items[0]["id"], status="FIXED")
        fixed = tracker.by_status("FIXED")
        assert len(fixed) == 1

    @pytest.mark.unit
    def test_by_severity_filter(self, tracker):
        critical = tracker.by_severity("CRITICAL")
        assert len(critical) == 1
        assert critical[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_overdue_detection(self, tracker):
        items = tracker.all_items()
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
        tracker.update(items[0]["id"], due_date=yesterday)
        overdue = tracker.overdue()
        assert len(overdue) >= 1

    @pytest.mark.unit
    def test_fixed_not_in_overdue(self, tracker):
        items = tracker.all_items()
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
        fid = items[0]["id"]
        tracker.update(fid, due_date=yesterday, status="FIXED")
        overdue = tracker.overdue()
        assert not any(i["id"] == fid for i in overdue)

    @pytest.mark.unit
    def test_summary_structure(self, tracker):
        s = tracker.summary()
        assert "total" in s
        assert "fixed" in s
        assert "open" in s
        assert "completion_pct" in s
        assert "by_severity" in s

    @pytest.mark.unit
    def test_summary_total_correct(self, tracker):
        assert tracker.summary()["total"] == 4

    @pytest.mark.unit
    def test_summary_completion_zero_initially(self, tracker):
        assert tracker.summary()["completion_pct"] == 0.0

    @pytest.mark.unit
    def test_completion_100_when_all_fixed(self, tracker):
        for item in tracker.all_items():
            tracker.update(item["id"], status="FIXED")
        s = tracker.summary()
        assert s["completion_pct"] == 100.0

    @pytest.mark.unit
    def test_save_creates_file(self, tracker, tmp_path):
        path = tracker.save()
        assert path.exists()

    @pytest.mark.unit
    def test_save_load_roundtrip(self, sample_findings, tmp_path):
        t1 = RemediationTracker("eng", findings=sample_findings, output_dir=str(tmp_path))
        t1.load_or_init()
        items = t1.all_items()
        t1.update(items[0]["id"], status="FIXED", note="Patched")
        t1.save()

        t2 = RemediationTracker("eng", output_dir=str(tmp_path))
        t2.load_or_init()
        loaded_item = t2.get(items[0]["id"])
        assert loaded_item["status"] == "FIXED"
        assert loaded_item["notes"][0]["text"] == "Patched"

    @pytest.mark.unit
    def test_bulk_update(self, tracker):
        items = tracker.all_items()
        updates = [
            {"id": items[0]["id"], "status": "IN_PROGRESS"},
            {"id": items[1]["id"], "status": "FIXED"},
        ]
        count = tracker.bulk_update(updates)
        assert count == 2
        assert tracker.get(items[0]["id"])["status"] == "IN_PROGRESS"
        assert tracker.get(items[1]["id"])["status"] == "FIXED"

    @pytest.mark.unit
    def test_all_statuses_valid(self):
        assert "OPEN" in VALID_STATUSES
        assert "FIXED" in VALID_STATUSES
        assert "ACCEPTED_RISK" in VALID_STATUSES

    @pytest.mark.unit
    def test_status_colors_complete(self):
        for status in VALID_STATUSES:
            assert status in STATUS_COLORS
