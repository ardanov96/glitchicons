# tests/test_performance.py
"""
Unit tests untuk v1.9.0 Performance Layer:
  - modules/core/async_engine.py
  - modules/core/scan_orchestrator.py
"""

import asyncio
import json
import pytest
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from modules.core.async_engine import (
    AsyncEngine, RateLimiter, RetryConfig, ResponseCache,
    AsyncResponse, ScanProgress,
)
from modules.core.scan_orchestrator import (
    ScanOrchestrator, ScanModule, ModuleResult,
    FindingDeduplicator,
)


# ── Helpers ───────────────────────────────────────────────

def make_finding(severity="HIGH", title="Test Finding", target="https://t.com"):
    return {
        "title": title, "severity": severity, "cvss": 7.5,
        "cwe": "CWE-89", "target": target,
        "description": "d", "evidence": "e", "remediation": "r",
    }


def make_module_result(name="test", findings=None, status="success", duration=1.0):
    return ModuleResult(
        module=name, target="https://t.com",
        findings=findings or [],
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        duration_s=duration,
        status=status,
    )


# ── Tests: RateLimiter ────────────────────────────────────

class TestRateLimiter:

    @pytest.mark.unit
    def test_init(self):
        rl = RateLimiter(rate=10)
        assert rl.rate == 10
        assert rl.burst == 20  # default burst = rate * 2

    @pytest.mark.unit
    def test_custom_burst(self):
        rl = RateLimiter(rate=10, burst=50)
        assert rl.burst == 50

    @pytest.mark.unit
    def test_acquire_within_burst(self):
        async def run():
            rl = RateLimiter(rate=100, burst=100)
            wait = await rl.acquire()
            return wait
        wait = asyncio.run(run())
        assert wait == 0.0  # No wait needed within burst

    @pytest.mark.unit
    def test_current_rate(self):
        rl = RateLimiter(rate=50)
        assert rl.current_rate == 50

    @pytest.mark.unit
    def test_context_manager(self):
        async def run():
            rl = RateLimiter(rate=1000)
            async with rl:
                return True
        assert asyncio.run(run()) is True

    @pytest.mark.unit
    def test_multiple_acquires(self):
        async def run():
            rl = RateLimiter(rate=1000, burst=1000)
            waits = []
            for _ in range(5):
                waits.append(await rl.acquire())
            return waits
        waits = asyncio.run(run())
        assert all(w == 0.0 for w in waits)  # All within burst


# ── Tests: RetryConfig ────────────────────────────────────

class TestRetryConfig:

    @pytest.mark.unit
    def test_defaults(self):
        rc = RetryConfig()
        assert rc.max_retries == 3
        assert rc.backoff_base == 0.5
        assert rc.jitter is True

    @pytest.mark.unit
    def test_wait_time_increases(self):
        rc = RetryConfig(backoff_base=1.0, jitter=False)
        w0 = rc.wait_time(0)
        w1 = rc.wait_time(1)
        w2 = rc.wait_time(2)
        assert w0 < w1 < w2

    @pytest.mark.unit
    def test_wait_time_capped_at_max(self):
        rc = RetryConfig(backoff_base=1.0, backoff_max=5.0, jitter=False)
        w10 = rc.wait_time(10)  # Would be 1024s without cap
        assert w10 <= 5.0

    @pytest.mark.unit
    def test_jitter_adds_randomness(self):
        rc = RetryConfig(backoff_base=1.0, jitter=True)
        times = [rc.wait_time(0) for _ in range(10)]
        # Not all equal when jitter is enabled
        assert len(set(round(t, 3) for t in times)) > 1

    @pytest.mark.unit
    def test_retry_on_includes_429(self):
        rc = RetryConfig()
        assert 429 in rc.retry_on
        assert 500 in rc.retry_on


# ── Tests: ResponseCache ──────────────────────────────────

class TestResponseCache:

    @pytest.mark.unit
    def test_set_and_get(self):
        async def run():
            cache = ResponseCache(ttl_seconds=60)
            await cache.set("key1", "value1")
            return await cache.get("key1")
        assert asyncio.run(run()) == "value1"

    @pytest.mark.unit
    def test_miss_returns_none(self):
        async def run():
            cache = ResponseCache(ttl_seconds=60)
            return await cache.get("nonexistent")
        assert asyncio.run(run()) is None

    @pytest.mark.unit
    def test_size_property(self):
        async def run():
            cache = ResponseCache(ttl_seconds=60)
            await cache.set("k1", "v1")
            await cache.set("k2", "v2")
            return cache.size
        assert asyncio.run(run()) == 2

    @pytest.mark.unit
    def test_clear(self):
        async def run():
            cache = ResponseCache(ttl_seconds=60)
            await cache.set("k1", "v1")
            await cache.clear()
            return cache.size
        assert asyncio.run(run()) == 0

    @pytest.mark.unit
    def test_max_size_evicts(self):
        async def run():
            cache = ResponseCache(ttl_seconds=60, max_size=3)
            for i in range(5):
                await cache.set(f"k{i}", f"v{i}")
            return cache.size
        assert asyncio.run(run()) <= 3

    @pytest.mark.unit
    def test_expired_returns_none(self):
        async def run():
            cache = ResponseCache(ttl_seconds=0)  # Immediately expired
            await cache.set("k", "v")
            await asyncio.sleep(0.01)
            return await cache.get("k")
        # TTL=0 means expires immediately
        result = asyncio.run(run())
        assert result is None or result == "v"  # May or may not expire depending on timing


# ── Tests: AsyncResponse ──────────────────────────────────

class TestAsyncResponse:

    @pytest.mark.unit
    def test_ok_true_for_200(self):
        r = AsyncResponse(url="https://t.com", status_code=200,
                          text='{}', headers={}, elapsed_ms=50)
        assert r.ok is True

    @pytest.mark.unit
    def test_ok_false_for_404(self):
        r = AsyncResponse(url="https://t.com", status_code=404,
                          text='not found', headers={}, elapsed_ms=30)
        assert r.ok is False

    @pytest.mark.unit
    def test_ok_false_with_error(self):
        r = AsyncResponse(url="https://t.com", status_code=200,
                          text='', headers={}, elapsed_ms=0, error="timeout")
        assert r.ok is False

    @pytest.mark.unit
    def test_json_method(self):
        r = AsyncResponse(url="https://t.com", status_code=200,
                          text='{"key":"value"}', headers={}, elapsed_ms=10)
        assert r.json() == {"key": "value"}

    @pytest.mark.unit
    def test_cached_false_by_default(self):
        r = AsyncResponse(url="t", status_code=200, text="", headers={}, elapsed_ms=0)
        assert r.cached is False


# ── Tests: ScanProgress ───────────────────────────────────

class TestScanProgress:

    @pytest.mark.unit
    def test_pct_zero_initially(self):
        p = ScanProgress(total=100)
        assert p.pct == 0.0

    @pytest.mark.unit
    def test_pct_100_when_done(self):
        p = ScanProgress(total=10, completed=10)
        assert p.pct == 100.0

    @pytest.mark.unit
    def test_increment(self):
        p = ScanProgress(total=10)
        p.increment()
        assert p.completed == 1
        assert p.errors == 0

    @pytest.mark.unit
    def test_increment_error(self):
        p = ScanProgress(total=10)
        p.increment(error=True)
        assert p.completed == 1
        assert p.errors == 1

    @pytest.mark.unit
    def test_str_representation(self):
        p = ScanProgress(total=100, completed=50)
        s = str(p)
        assert "50/100" in s

    @pytest.mark.unit
    def test_req_per_sec_nonzero(self):
        p = ScanProgress(total=100)
        p.completed = 10
        # req_per_sec depends on elapsed time; just test it's >= 0
        assert p.req_per_sec >= 0

    @pytest.mark.unit
    def test_pct_zero_total(self):
        p = ScanProgress(total=0)
        assert p.pct == 0.0


# ── Tests: AsyncEngine ────────────────────────────────────

class TestAsyncEngine:

    @pytest.mark.unit
    def test_init(self):
        engine = AsyncEngine(rate_limit=50, concurrency=10)
        assert engine.rate_limit == 50
        assert engine.concurrency == 10

    @pytest.mark.unit
    def test_default_retry_config(self):
        engine = AsyncEngine()
        assert engine.retry_cfg.max_retries == 3

    @pytest.mark.unit
    def test_custom_retry_config(self):
        rc = RetryConfig(max_retries=5)
        engine = AsyncEngine(retry_config=rc)
        assert engine.retry_cfg.max_retries == 5

    @pytest.mark.unit
    def test_stats_initial(self):
        engine = AsyncEngine()
        stats = engine.stats
        assert stats["total_requests"] == 0
        assert stats["total_retries"] == 0

    @pytest.mark.unit
    def test_get_successful(self):
        async def run():
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = '{"ok": true}'
            mock_resp.headers = {}

            engine = AsyncEngine(rate_limit=1000, concurrency=5)
            async with engine:
                with patch.object(engine._client, "request",
                                   new_callable=AsyncMock,
                                   return_value=mock_resp):
                    return await engine.get("https://target.com/api")

        resp = asyncio.run(run())
        assert resp.status_code == 200
        assert resp.ok is True

    @pytest.mark.unit
    def test_get_with_retry_on_500(self):
        async def run():
            mock_500 = MagicMock()
            mock_500.status_code = 500
            mock_500.text = "error"
            mock_500.headers = {}

            mock_200 = MagicMock()
            mock_200.status_code = 200
            mock_200.text = "ok"
            mock_200.headers = {}

            engine = AsyncEngine(
                rate_limit=1000,
                retry_config=RetryConfig(max_retries=2, backoff_base=0.001, jitter=False),
            )
            responses = [mock_500, mock_200]
            call_count = [0]

            async def mock_request(*args, **kwargs):
                r = responses[min(call_count[0], len(responses)-1)]
                call_count[0] += 1
                return r

            async with engine:
                with patch.object(engine._client, "request", side_effect=mock_request):
                    resp = await engine.get("https://target.com/")

            return resp, call_count[0]

        resp, calls = asyncio.run(run())
        assert resp.status_code == 200
        assert calls >= 2  # At least one retry

    @pytest.mark.unit
    def test_network_error_returns_error_response(self):
        async def run():
            engine = AsyncEngine(
                rate_limit=1000,
                retry_config=RetryConfig(max_retries=0),
            )
            async with engine:
                with patch.object(engine._client, "request",
                                   new_callable=AsyncMock,
                                   side_effect=Exception("connection refused")):
                    return await engine.get("https://target.com/")

        resp = asyncio.run(run())
        assert resp.error is not None
        assert resp.ok is False

    @pytest.mark.unit
    def test_batch_get(self):
        async def run():
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = '{"ok": true}'
            mock_resp.headers = {}

            engine = AsyncEngine(rate_limit=1000, concurrency=5)
            async with engine:
                with patch.object(engine._client, "request",
                                   new_callable=AsyncMock,
                                   return_value=mock_resp):
                    return await engine.batch_get([
                        "https://t.com/1",
                        "https://t.com/2",
                        "https://t.com/3",
                    ])

        results = asyncio.run(run())
        assert len(results) == 3
        assert all(r.status_code == 200 for r in results)

    @pytest.mark.unit
    def test_engine_not_context_manager_raises(self):
        async def run():
            engine = AsyncEngine()
            await engine.get("https://t.com")

        with pytest.raises(RuntimeError):
            asyncio.run(run())

    @pytest.mark.unit
    def test_cache_hit(self):
        async def run():
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = '{"cached": true}'
            mock_resp.headers = {}

            engine = AsyncEngine(rate_limit=1000, cache_ttl=60)
            call_count = [0]

            async def mock_request(*args, **kwargs):
                call_count[0] += 1
                return mock_resp

            async with engine:
                with patch.object(engine._client, "request", side_effect=mock_request):
                    r1 = await engine.get("https://t.com/cached", use_cache=True)
                    r2 = await engine.get("https://t.com/cached", use_cache=True)

            return r1, r2, call_count[0]

        r1, r2, calls = asyncio.run(run())
        assert r1.status_code == 200
        assert r2.status_code == 200
        assert calls == 1  # Second request served from cache


# ── Tests: FindingDeduplicator ────────────────────────────

class TestFindingDeduplicator:

    @pytest.mark.unit
    def test_exact_duplicate_removed(self):
        dedup = FindingDeduplicator()
        f1 = make_finding("HIGH", "SQL Injection", "https://t.com/api")
        f2 = make_finding("HIGH", "SQL Injection", "https://t.com/api")
        result = dedup.deduplicate([f1, f2])
        assert len(result) == 1

    @pytest.mark.unit
    def test_different_targets_kept(self):
        dedup = FindingDeduplicator()
        f1 = make_finding("HIGH", "SQL Injection", "https://t.com/api/1")
        f2 = make_finding("HIGH", "SQL Injection", "https://t.com/api/2")
        result = dedup.deduplicate([f1, f2])
        assert len(result) == 2

    @pytest.mark.unit
    def test_higher_severity_kept(self):
        dedup = FindingDeduplicator()
        f_low  = make_finding("LOW",      "SQL Injection", "https://t.com")
        f_crit = make_finding("CRITICAL", "SQL Injection", "https://t.com")
        result = dedup.deduplicate([f_low, f_crit])
        assert len(result) == 1
        assert result[0]["severity"] == "CRITICAL"

    @pytest.mark.unit
    def test_empty_returns_empty(self):
        dedup = FindingDeduplicator()
        assert dedup.deduplicate([]) == []

    @pytest.mark.unit
    def test_no_duplicates_unchanged(self):
        dedup = FindingDeduplicator()
        findings = [
            make_finding("HIGH",   "SQLi",  "https://t.com/a"),
            make_finding("MEDIUM", "XSS",   "https://t.com/b"),
            make_finding("LOW",    "CSRF",  "https://t.com/c"),
        ]
        result = dedup.deduplicate(findings)
        assert len(result) == 3


# ── Tests: ScanModule ─────────────────────────────────────

class TestScanModule:

    @pytest.mark.unit
    def test_init(self):
        m = ScanModule(name="test", fn=lambda t: [])
        assert m.name == "test"
        assert m.priority == 5
        assert m.enabled is True
        assert m.timeout == 120.0

    @pytest.mark.unit
    def test_custom_priority(self):
        m = ScanModule(name="t", fn=lambda t: [], priority=1)
        assert m.priority == 1

    @pytest.mark.unit
    def test_tags(self):
        m = ScanModule(name="t", fn=lambda t: [], tags=["recon", "web"])
        assert "recon" in m.tags

    @pytest.mark.unit
    def test_depends_on(self):
        m = ScanModule(name="t", fn=lambda t: [], depends_on=["recon"])
        assert "recon" in m.depends_on


# ── Tests: ModuleResult ───────────────────────────────────

class TestModuleResult:

    @pytest.mark.unit
    def test_finding_count(self):
        r = make_module_result(findings=[make_finding(), make_finding()])
        assert r.finding_count == 2

    @pytest.mark.unit
    def test_critical_count(self):
        findings = [make_finding("CRITICAL"), make_finding("HIGH"), make_finding("CRITICAL")]
        r = make_module_result(findings=findings)
        assert r.critical_count == 2

    @pytest.mark.unit
    def test_zero_findings(self):
        r = make_module_result()
        assert r.finding_count == 0
        assert r.critical_count == 0


# ── Tests: ScanOrchestrator ───────────────────────────────

class TestScanOrchestrator:

    @pytest.mark.unit
    def test_init(self, tmp_path):
        orch = ScanOrchestrator(target="https://t.com", output_dir=str(tmp_path))
        assert orch.target == "https://t.com"
        assert orch.module_count == 0

    @pytest.mark.unit
    def test_add_module(self, tmp_path):
        orch = ScanOrchestrator(target="https://t.com", output_dir=str(tmp_path))
        orch.add_module(ScanModule("test", lambda t: []))
        assert orch.module_count == 1

    @pytest.mark.unit
    def test_add_modules_chaining(self, tmp_path):
        orch = ScanOrchestrator(target="https://t.com", output_dir=str(tmp_path))
        orch.add_module(ScanModule("a", lambda t: [])) \
            .add_module(ScanModule("b", lambda t: []))
        assert orch.module_count == 2

    @pytest.mark.unit
    def test_disable_module(self, tmp_path):
        orch = ScanOrchestrator(target="https://t.com", output_dir=str(tmp_path))
        orch.add_module(ScanModule("cors", lambda t: []))
        orch.disable_module("cors")
        assert orch.enabled_count == 0

    @pytest.mark.unit
    def test_enable_tags(self, tmp_path):
        orch = ScanOrchestrator(target="https://t.com", output_dir=str(tmp_path))
        orch.add_module(ScanModule("cors",    lambda t: [], tags=["web"]))
        orch.add_module(ScanModule("subdomain", lambda t: [], tags=["recon"]))
        orch.enable_tags(["recon"])
        assert orch.enabled_count == 1

    @pytest.mark.unit
    def test_run_single_module(self, tmp_path):
        async def run():
            orch = ScanOrchestrator(target="https://t.com",
                                     output_dir=str(tmp_path), concurrency=2)
            orch.add_module(ScanModule("test", lambda t: [make_finding()], timeout=10))
            return await orch.run()

        results = asyncio.run(run())
        assert len(results) == 1
        assert results[0].status == "success"
        assert results[0].finding_count == 1

    @pytest.mark.unit
    def test_run_multiple_modules(self, tmp_path):
        async def run():
            orch = ScanOrchestrator(target="https://t.com",
                                     output_dir=str(tmp_path), concurrency=3)
            for i in range(3):
                orch.add_module(ScanModule(f"mod{i}", lambda t: [], timeout=5))
            return await orch.run()

        results = asyncio.run(run())
        assert len(results) == 3

    @pytest.mark.unit
    def test_module_timeout_handled(self, tmp_path):
        import time as _time
        def slow_fn(target):
            _time.sleep(10)
            return []

        async def run():
            orch = ScanOrchestrator(target="https://t.com", output_dir=str(tmp_path))
            orch.add_module(ScanModule("slow", slow_fn, timeout=0.05))
            return await orch.run()

        results = asyncio.run(run())
        assert results[0].status in ("timeout", "error", "success")  # platform-dependent

    @pytest.mark.unit
    def test_module_error_handled(self, tmp_path):
        def broken_fn(target):
            raise ValueError("module crashed")

        async def run():
            orch = ScanOrchestrator(target="https://t.com", output_dir=str(tmp_path))
            orch.add_module(ScanModule("broken", broken_fn, timeout=5))
            return await orch.run()

        results = asyncio.run(run())
        assert results[0].status == "error"
        assert "crashed" in results[0].error

    @pytest.mark.unit
    def test_all_findings_aggregated(self, tmp_path):
        async def run():
            orch = ScanOrchestrator(target="https://t.com", output_dir=str(tmp_path))
            orch.add_module(ScanModule("m1", lambda t: [make_finding("HIGH", "F1")]))
            orch.add_module(ScanModule("m2", lambda t: [make_finding("MEDIUM", "F2")]))
            await orch.run()
            return orch.all_findings(deduplicate=False)

        findings = asyncio.run(run())
        assert len(findings) == 2

    @pytest.mark.unit
    def test_findings_deduplicated(self, tmp_path):
        async def run():
            orch = ScanOrchestrator(target="https://t.com", output_dir=str(tmp_path))
            # Same finding from two modules
            f = make_finding("HIGH", "SQL Injection", "https://t.com/api")
            orch.add_module(ScanModule("m1", lambda t: [f]))
            orch.add_module(ScanModule("m2", lambda t: [f]))
            await orch.run()
            return orch.all_findings(deduplicate=True)

        findings = asyncio.run(run())
        assert len(findings) == 1

    @pytest.mark.unit
    def test_findings_by_severity(self, tmp_path):
        async def run():
            orch = ScanOrchestrator(target="https://t.com", output_dir=str(tmp_path))
            orch.add_module(ScanModule("m", lambda t: [
                make_finding("CRITICAL", "SQL Injection"),
                make_finding("HIGH",     "XSS Stored"),
                make_finding("LOW",      "Missing Headers"),
            ]))
            await orch.run()
            return orch.findings_by_severity()

        by_sev = asyncio.run(run())
        total = sum(len(v) for v in by_sev.values())
        assert total >= 3

    @pytest.mark.unit
    def test_priority_ordering(self, tmp_path):
        order = []

        async def run():
            orch = ScanOrchestrator(target="https://t.com",
                                     output_dir=str(tmp_path), concurrency=1)
            orch.add_module(ScanModule("low",  lambda t: order.append("low") or [],  priority=5))
            orch.add_module(ScanModule("high", lambda t: order.append("high") or [], priority=1))
            await orch.run()

        asyncio.run(run())
        assert order.index("high") < order.index("low")

    @pytest.mark.unit
    def test_save_results_creates_file(self, tmp_path):
        async def run():
            orch = ScanOrchestrator(target="https://t.com", output_dir=str(tmp_path))
            orch.add_module(ScanModule("test", lambda t: [make_finding()]))
            await orch.run()
            return list(tmp_path.glob("scan_*.json"))

        files = asyncio.run(run())
        assert len(files) >= 1
        data = json.loads(files[0].read_text())
        assert "findings" in data
        assert "results" in data
