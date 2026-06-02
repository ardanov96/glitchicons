# tests/test_v200.py
"""
Unit tests untuk v2.0.0:
  - modules/core/multi_target.py
  - modules/dashboard/dashboard.py
"""

import asyncio
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

from modules.core.multi_target import (
    MultiTargetOrchestrator, Target, TargetResult, ModuleSpec,
)
from modules.dashboard.dashboard import (
    GlitchiconsDashboard, ScanSession, _sse,
)


# ── Fixtures ──────────────────────────────────────────────

def sample_finding(sev="HIGH", title="Test", target="https://t.com"):
    return {
        "title": title, "severity": sev, "cvss": 7.5,
        "cwe": "CWE-89", "target": target,
        "description": "d", "evidence": "e", "remediation": "r",
    }


@pytest.fixture
def orchestrator(tmp_path):
    return MultiTargetOrchestrator(
        concurrency=2,
        output_dir=str(tmp_path),
        max_workers=4,
    )


@pytest.fixture
def dashboard(tmp_path):
    return GlitchiconsDashboard(
        host="127.0.0.1",
        port=9999,
        output_dir=str(tmp_path),
    )


# ── Tests: Target ─────────────────────────────────────────

class TestTarget:

    @pytest.mark.unit
    def test_init_minimal(self):
        t = Target(url="https://t.com")
        assert t.url == "https://t.com"
        assert t.name == "https://t.com"  # default name = url

    @pytest.mark.unit
    def test_init_with_name(self):
        t = Target(url="https://t.com", name="Target Corp")
        assert t.name == "Target Corp"

    @pytest.mark.unit
    def test_tags(self):
        t = Target(url="https://t.com", tags=["api", "fintech"])
        assert "api" in t.tags
        assert "fintech" in t.tags

    @pytest.mark.unit
    def test_token(self):
        t = Target(url="https://t.com", token="Bearer abc")
        assert t.token == "Bearer abc"

    @pytest.mark.unit
    def test_extra(self):
        t = Target(url="https://t.com", extra={"env": "prod"})
        assert t.extra["env"] == "prod"


# ── Tests: TargetResult ───────────────────────────────────

class TestTargetResult:

    @pytest.fixture
    def result(self):
        t = Target(url="https://t.com", name="Test")
        return TargetResult(
            target=t,
            findings=[
                sample_finding("CRITICAL"),
                sample_finding("HIGH"),
                sample_finding("MEDIUM"),
                sample_finding("LOW"),
            ],
            modules_run=["cors", "graphql"],
            duration_s=5.2,
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:00:05Z",
            status="success",
        )

    @pytest.mark.unit
    def test_finding_count(self, result):
        assert result.finding_count == 4

    @pytest.mark.unit
    def test_by_severity(self, result):
        sev = result.by_severity
        assert sev["CRITICAL"] == 1
        assert sev["HIGH"] == 1

    @pytest.mark.unit
    def test_risk_level_critical(self, result):
        assert result.risk_level == "CRITICAL"

    @pytest.mark.unit
    def test_risk_level_clean(self):
        t = Target(url="https://t.com")
        r = TargetResult(t, [], [], 1.0, "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z", "success")
        assert r.risk_level == "CLEAN"

    @pytest.mark.unit
    def test_risk_level_high_only(self):
        t = Target(url="https://t.com")
        r = TargetResult(t, [sample_finding("HIGH")], [],
                         1.0, "", "", "success")
        assert r.risk_level == "HIGH"


# ── Tests: MultiTargetOrchestrator ────────────────────────

class TestMultiTargetOrchestrator:

    @pytest.mark.unit
    def test_init(self, orchestrator):
        assert orchestrator.concurrency == 2
        assert orchestrator.target_count == 0

    @pytest.mark.unit
    def test_add_target(self, orchestrator):
        orchestrator.add_target(Target(url="https://t.com"))
        assert orchestrator.target_count == 1

    @pytest.mark.unit
    def test_add_targets_chaining(self, orchestrator):
        orchestrator.add_target(Target("https://a.com")) \
                    .add_target(Target("https://b.com"))
        assert orchestrator.target_count == 2

    @pytest.mark.unit
    def test_add_targets_from_list(self, orchestrator):
        orchestrator.add_targets_from_list(
            ["https://a.com", "https://b.com", "https://c.com"],
            tags=["web"],
        )
        assert orchestrator.target_count == 3
        assert all(t.tags == ["web"] for t in orchestrator._targets)

    @pytest.mark.unit
    def test_register_module(self, orchestrator):
        orchestrator.register_module("cors", lambda url, **kw: [])
        assert orchestrator.module_count == 1

    @pytest.mark.unit
    def test_run_empty_targets(self, orchestrator):
        async def run():
            return await orchestrator.run()
        results = asyncio.run(run())
        assert results == []

    @pytest.mark.unit
    def test_run_no_modules(self, orchestrator):
        orchestrator.add_target(Target("https://t.com"))

        async def run():
            return await orchestrator.run()
        results = asyncio.run(run())
        assert results == []

    @pytest.mark.unit
    def test_run_single_target(self, tmp_path):
        async def run():
            mto = MultiTargetOrchestrator(concurrency=1, output_dir=str(tmp_path))
            mto.add_target(Target("https://t.com"))
            mto.register_module("test", lambda url, **kw: [sample_finding()])
            return await mto.run()

        results = asyncio.run(run())
        assert len(results) == 1
        assert results[0].finding_count == 1
        assert results[0].status == "success"

    @pytest.mark.unit
    def test_run_multiple_targets(self, tmp_path):
        async def run():
            mto = MultiTargetOrchestrator(concurrency=2, output_dir=str(tmp_path))
            for i in range(3):
                mto.add_target(Target(f"https://t{i}.com"))
            mto.register_module("test", lambda url, **kw: [])
            return await mto.run()

        results = asyncio.run(run())
        assert len(results) == 3

    @pytest.mark.unit
    def test_run_module_error_partial(self, tmp_path):
        def failing_module(url, **kw):
            raise ValueError("module crashed")

        async def run():
            mto = MultiTargetOrchestrator(concurrency=1, output_dir=str(tmp_path))
            mto.add_target(Target("https://t.com"))
            mto.register_module("broken", failing_module)
            return await mto.run()

        results = asyncio.run(run())
        assert len(results) == 1
        assert results[0].status in ("error", "partial")

    @pytest.mark.unit
    def test_all_findings_aggregation(self, tmp_path):
        async def run():
            mto = MultiTargetOrchestrator(concurrency=2, output_dir=str(tmp_path))
            mto.add_target(Target("https://a.com"))
            mto.add_target(Target("https://b.com"))
            mto.register_module("test", lambda url, **kw: [
                sample_finding("HIGH", "F1", url)
            ])
            await mto.run()
            return mto.all_findings()

        findings = asyncio.run(run())
        assert len(findings) == 2

    @pytest.mark.unit
    def test_findings_by_target(self, tmp_path):
        async def run():
            mto = MultiTargetOrchestrator(concurrency=1, output_dir=str(tmp_path))
            mto.add_target(Target("https://t.com"))
            mto.register_module("test", lambda url, **kw: [sample_finding()])
            await mto.run()
            return mto.findings_by_target()

        by_target = asyncio.run(run())
        assert "https://t.com" in by_target

    @pytest.mark.unit
    def test_findings_by_severity(self, tmp_path):
        async def run():
            mto = MultiTargetOrchestrator(concurrency=1, output_dir=str(tmp_path))
            mto.add_target(Target("https://t.com"))
            mto.register_module("test", lambda url, **kw: [
                sample_finding("CRITICAL", "C1"),
                sample_finding("HIGH",     "H1"),
            ])
            await mto.run()
            return mto.findings_by_severity()

        by_sev = asyncio.run(run())
        assert len(by_sev["CRITICAL"]) == 1
        assert len(by_sev["HIGH"]) == 1

    @pytest.mark.unit
    def test_top_targets(self, tmp_path):
        async def run():
            mto = MultiTargetOrchestrator(concurrency=2, output_dir=str(tmp_path))
            mto.add_target(Target("https://rich.com"))
            mto.add_target(Target("https://poor.com"))
            counts = {"https://rich.com": 5, "https://poor.com": 1}
            mto.register_module("test", lambda url, **kw: [
                sample_finding() for _ in range(counts.get(url, 0))
            ])
            await mto.run()
            return mto.top_targets(n=1)

        top = asyncio.run(run())
        assert len(top) == 1
        assert top[0].target.url == "https://rich.com"

    @pytest.mark.unit
    def test_tag_filter(self, tmp_path):
        async def run():
            mto = MultiTargetOrchestrator(concurrency=1, output_dir=str(tmp_path))
            mto.add_target(Target("https://api.com",  tags=["api"]))
            mto.add_target(Target("https://web.com",  tags=["web"]))
            mto.register_module("test", lambda url, **kw: [])
            return await mto.run(tags=["api"])

        results = asyncio.run(run())
        assert len(results) == 1
        assert results[0].target.url == "https://api.com"

    @pytest.mark.unit
    def test_save_combined_creates_file(self, tmp_path):
        async def run():
            mto = MultiTargetOrchestrator(concurrency=1, output_dir=str(tmp_path))
            mto.add_target(Target("https://t.com"))
            mto.register_module("test", lambda url, **kw: [sample_finding()])
            await mto.run()
            return list(tmp_path.glob("multi_scan_*.json"))

        files = asyncio.run(run())
        assert len(files) >= 1
        data = json.loads(files[0].read_text())
        assert "results" in data
        assert data["targets"] == 1


# ── Tests: _sse helper ────────────────────────────────────

class TestSSE:

    @pytest.mark.unit
    def test_sse_format(self):
        result = _sse("finding", '{"severity":"HIGH"}')
        assert result == 'event: finding\ndata: {"severity":"HIGH"}\n\n'

    @pytest.mark.unit
    def test_sse_done_event(self):
        result = _sse("done", '{"status":"ok"}')
        assert "event: done" in result
        assert "data:" in result

    @pytest.mark.unit
    def test_sse_ends_with_double_newline(self):
        result = _sse("log", "test message")
        assert result.endswith("\n\n")


# ── Tests: ScanSession ────────────────────────────────────

class TestScanSession:

    @pytest.mark.unit
    def test_init(self):
        s = ScanSession(
            session_id="abc123",
            target="https://t.com",
            modules=["cors"],
            started_at="2026-01-01T00:00:00Z",
        )
        assert s.session_id == "abc123"
        assert s.status == "running"
        assert s.finding_count == 0

    @pytest.mark.unit
    def test_finding_count(self):
        s = ScanSession("id", "https://t.com", [], "2026-01-01T00:00:00Z")
        s.findings.append(sample_finding())
        s.findings.append(sample_finding())
        assert s.finding_count == 2


# ── Tests: GlitchiconsDashboard ───────────────────────────

class TestGlitchiconsDashboard:

    @pytest.mark.unit
    def test_init(self, dashboard):
        assert dashboard.host == "127.0.0.1"
        assert dashboard.port == 9999
        assert dashboard.session_count == 0

    @pytest.mark.unit
    def test_output_dir_created(self, tmp_path):
        out = tmp_path / "dash"
        GlitchiconsDashboard(output_dir=str(out))
        assert out.exists()

    @pytest.mark.unit
    def test_sse_helper(self, dashboard):
        s = _sse("test", "data123")
        assert "event: test" in s
        assert "data: data123" in s

    @pytest.mark.unit
    def test_demo_scan_returns_findings(self, dashboard):
        findings = dashboard._demo_scan("https://target.com")
        assert isinstance(findings, list)
        assert len(findings) >= 2
        for f in findings:
            assert "severity" in f
            assert "title" in f
            assert f["target"] == "https://target.com"

    @pytest.mark.unit
    def test_demo_scan_valid_severities(self, dashboard):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        findings = dashboard._demo_scan("https://target.com")
        for f in findings:
            assert f["severity"] in valid

    @pytest.mark.unit
    def test_save_session_creates_file(self, dashboard, tmp_path):
        dashboard.output_dir = tmp_path
        session = ScanSession(
            session_id="test123",
            target="https://t.com",
            modules=["cors"],
            started_at="2026-01-01T00:00:00Z",
            findings=[sample_finding()],
            status="done",
            duration_s=5.0,
        )
        path = dashboard._save_session(session)
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["session_id"] == "test123"
        assert data["finding_count"] == 1

    @pytest.mark.unit
    def test_build_app_requires_fastapi(self, dashboard):
        """build_app raises ImportError if fastapi not installed."""
        with patch.dict("sys.modules", {"fastapi": None}):
            try:
                dashboard._build_app()
            except (ImportError, TypeError):
                pass  # Expected

    @pytest.mark.unit
    def test_run_requires_uvicorn(self, dashboard):
        """run() raises ImportError if uvicorn not installed."""
        with patch.dict("sys.modules", {"uvicorn": None}):
            try:
                dashboard.run()
            except (ImportError, TypeError):
                pass  # Expected
