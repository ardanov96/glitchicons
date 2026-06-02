"""
Async HTTP Engine — modules/core/async_engine.py

High-performance async HTTP client for Glitchicons.

Features:
  - httpx AsyncClient with connection pooling
  - Token bucket rate limiter (requests/second)
  - Exponential backoff retry with jitter
  - Concurrent request batching
  - Response caching (in-memory, TTL-based)
  - Progress tracking
  - Semaphore-based concurrency control

Usage:
    import asyncio
    from modules.core.async_engine import AsyncEngine, RateLimiter, RetryConfig

    async def scan():
        engine = AsyncEngine(
            rate_limit=50,       # 50 req/sec
            concurrency=20,      # 20 concurrent
            retry_config=RetryConfig(max_retries=3, backoff_base=0.5),
        )
        async with engine:
            # Single request
            resp = await engine.get("https://target.com/api/users")

            # Batch requests
            urls = [f"https://target.com/api/users/{i}" for i in range(100)]
            responses = await engine.batch_get(urls)

    asyncio.run(scan())

Author: ardanov96
"""

import asyncio
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable

import httpx
from rich.console import Console

console = Console()


# ── Rate Limiter (Token Bucket) ───────────────────────────

class RateLimiter:
    """
    Token bucket rate limiter for async HTTP requests.

    Allows bursting up to `burst` tokens, refills at `rate` tokens/second.
    Thread-safe via asyncio.Lock.

    Usage:
        limiter = RateLimiter(rate=50, burst=100)
        async with limiter:
            # rate-limited section
            pass
    """

    def __init__(self, rate: float, burst: float | None = None):
        """
        Args:
            rate:  Maximum requests per second
            burst: Maximum burst size (default: rate * 2)
        """
        self.rate   = rate
        self.burst  = burst or rate * 2
        self._tokens = self.burst
        self._last   = time.monotonic()
        self._lock   = asyncio.Lock()

    async def acquire(self) -> float:
        """
        Acquire one token. Waits if rate limit exceeded.
        Returns wait time in seconds.
        """
        async with self._lock:
            now   = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
            self._last = now

            if self._tokens >= 1:
                self._tokens -= 1
                return 0.0

            # Need to wait
            wait = (1 - self._tokens) / self.rate
            self._tokens = 0
            return wait

    async def __aenter__(self):
        wait = await self.acquire()
        if wait > 0:
            await asyncio.sleep(wait)
        return self

    async def __aexit__(self, *args):
        pass

    @property
    def current_rate(self) -> float:
        return self.rate


# ── Retry Configuration ───────────────────────────────────

@dataclass
class RetryConfig:
    """Configuration for exponential backoff retry."""
    max_retries:  int   = 3
    backoff_base: float = 0.5    # seconds
    backoff_max:  float = 30.0   # max wait seconds
    jitter:       bool  = True   # add random jitter
    retry_on:     tuple = (429, 500, 502, 503, 504)

    def wait_time(self, attempt: int) -> float:
        """Calculate wait time for attempt N (0-indexed)."""
        wait = min(self.backoff_base * (2 ** attempt), self.backoff_max)
        if self.jitter:
            wait *= (0.5 + random.random() * 0.5)
        return wait


# ── Response Cache ────────────────────────────────────────

class ResponseCache:
    """
    Simple in-memory response cache with TTL.

    Caches GET responses by URL to avoid redundant requests
    during multi-module scans of the same target.
    """

    def __init__(self, ttl_seconds: int = 300, max_size: int = 1000):
        self.ttl      = ttl_seconds
        self.max_size = max_size
        self._store:  dict[str, tuple[Any, float]] = {}
        self._lock    = asyncio.Lock()

    async def get(self, key: str) -> Any | None:
        async with self._lock:
            if key not in self._store:
                return None
            value, expires = self._store[key]
            if time.monotonic() > expires:
                del self._store[key]
                return None
            return value

    async def set(self, key: str, value: Any) -> None:
        async with self._lock:
            if len(self._store) >= self.max_size:
                # Evict oldest entry
                oldest = min(self._store, key=lambda k: self._store[k][1])
                del self._store[oldest]
            self._store[key] = (value, time.monotonic() + self.ttl)

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()

    @property
    def size(self) -> int:
        return len(self._store)


# ── Request Result ────────────────────────────────────────

@dataclass
class AsyncResponse:
    """Wrapper around httpx response with metadata."""
    url:         str
    status_code: int
    text:        str
    headers:     dict
    elapsed_ms:  float
    attempts:    int = 1
    error:       str | None = None
    cached:      bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code < 400

    def json(self) -> Any:
        import json
        return json.loads(self.text)


# ── Progress Tracker ──────────────────────────────────────

@dataclass
class ScanProgress:
    """Track progress of concurrent scan operations."""
    total:     int
    completed: int = 0
    errors:    int = 0
    start_time: float = field(default_factory=time.monotonic)

    @property
    def pct(self) -> float:
        return (self.completed / self.total * 100) if self.total > 0 else 0.0

    @property
    def elapsed_s(self) -> float:
        return time.monotonic() - self.start_time

    @property
    def req_per_sec(self) -> float:
        elapsed = self.elapsed_s
        return self.completed / elapsed if elapsed > 0 else 0.0

    @property
    def eta_s(self) -> float:
        remaining = self.total - self.completed
        rps = self.req_per_sec
        return remaining / rps if rps > 0 else 0.0

    def increment(self, error: bool = False) -> None:
        self.completed += 1
        if error:
            self.errors += 1

    def __str__(self) -> str:
        return (
            f"{self.completed}/{self.total} ({self.pct:.1f}%) "
            f"| {self.req_per_sec:.1f} req/s "
            f"| ETA {self.eta_s:.0f}s "
            f"| errors: {self.errors}"
        )


# ── Async Engine ──────────────────────────────────────────

class AsyncEngine:
    """
    High-performance async HTTP engine for Glitchicons scanning.

    Combines:
    - httpx AsyncClient (connection pooling, HTTP/2)
    - Token bucket rate limiter
    - Exponential backoff retry
    - In-memory response cache
    - Semaphore concurrency control
    - Progress tracking

    Usage:
        async with AsyncEngine(rate_limit=100, concurrency=50) as engine:
            resp = await engine.get("https://target.com/api")
            resps = await engine.batch_get(url_list)
    """

    def __init__(
        self,
        rate_limit: float = 50.0,
        concurrency: int = 20,
        timeout: float = 10.0,
        retry_config: RetryConfig | None = None,
        cache_ttl: int = 0,  # 0 = no cache
        headers: dict | None = None,
        verify_ssl: bool = False,
    ):
        self.rate_limit  = rate_limit
        self.concurrency = concurrency
        self.timeout     = timeout
        self.retry_cfg   = retry_config or RetryConfig()
        self.cache_ttl   = cache_ttl
        self._headers    = headers or {"User-Agent": "Glitchicons/1.9.0"}
        self._verify_ssl = verify_ssl

        self._limiter    = RateLimiter(rate=rate_limit)
        self._semaphore  = asyncio.Semaphore(concurrency)
        self._cache      = ResponseCache(ttl_seconds=cache_ttl) if cache_ttl > 0 else None
        self._client: httpx.AsyncClient | None = None

        # Stats
        self._total_requests  = 0
        self._total_retries   = 0
        self._total_cached    = 0
        self._start_time      = time.monotonic()

    async def __aenter__(self) -> "AsyncEngine":
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            headers=self._headers,
            verify=self._verify_ssl,
                        limits=httpx.Limits(
                max_connections=self.concurrency * 2,
                max_keepalive_connections=self.concurrency,
            ),
        )
        self._start_time = time.monotonic()
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()
            self._client = None

    async def get(
        self,
        url: str,
        params: dict | None = None,
        headers: dict | None = None,
        use_cache: bool = True,
    ) -> AsyncResponse:
        """Make a rate-limited, retry-enabled GET request."""
        return await self._request("GET", url, params=params, headers=headers,
                                   use_cache=use_cache)

    async def post(
        self,
        url: str,
        json: dict | None = None,
        data: dict | None = None,
        headers: dict | None = None,
    ) -> AsyncResponse:
        """Make a rate-limited, retry-enabled POST request."""
        return await self._request("POST", url, json=json, data=data, headers=headers)

    async def request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> AsyncResponse:
        """Make a rate-limited, retry-enabled request with any method."""
        return await self._request(method, url, **kwargs)

    async def _request(
        self,
        method: str,
        url: str,
        use_cache: bool = False,
        **kwargs,
    ) -> AsyncResponse:
        """Core request method with rate limiting, caching, and retry."""
        if not self._client:
            raise RuntimeError("AsyncEngine must be used as async context manager")

        # Cache check (GET only)
        cache_key = f"{method}:{url}:{str(kwargs.get('params', ''))}"
        if use_cache and method == "GET" and self._cache:
            cached = await self._cache.get(cache_key)
            if cached:
                self._total_cached += 1
                cached.cached = True
                return cached

        async with self._semaphore:
            await self._limiter.acquire()

            for attempt in range(self.retry_cfg.max_retries + 1):
                start = time.monotonic()
                try:
                    self._total_requests += 1
                    resp = await self._client.request(method, url, **kwargs)
                    elapsed = (time.monotonic() - start) * 1000

                    result = AsyncResponse(
                        url=url,
                        status_code=resp.status_code,
                        text=resp.text,
                        headers=dict(resp.headers),
                        elapsed_ms=elapsed,
                        attempts=attempt + 1,
                    )

                    # Cache successful GET responses
                    if use_cache and method == "GET" and self._cache and resp.status_code == 200:
                        await self._cache.set(cache_key, result)

                    # Retry on configured status codes
                    if resp.status_code in self.retry_cfg.retry_on and attempt < self.retry_cfg.max_retries:
                        wait = self.retry_cfg.wait_time(attempt)
                        self._total_retries += 1
                        await asyncio.sleep(wait)
                        continue

                    return result

                except (httpx.TimeoutException, httpx.NetworkError) as e:
                    elapsed = (time.monotonic() - start) * 1000
                    if attempt < self.retry_cfg.max_retries:
                        wait = self.retry_cfg.wait_time(attempt)
                        self._total_retries += 1
                        await asyncio.sleep(wait)
                        continue
                    return AsyncResponse(
                        url=url, status_code=0, text="", headers={},
                        elapsed_ms=elapsed, attempts=attempt + 1,
                        error=str(e),
                    )
                except Exception as e:
                    elapsed = (time.monotonic() - start) * 1000
                    return AsyncResponse(
                        url=url, status_code=0, text="", headers={},
                        elapsed_ms=elapsed, attempts=attempt + 1,
                        error=str(e),
                    )

        # Should not reach here
        return AsyncResponse(url=url, status_code=0, text="", headers={},
                             elapsed_ms=0, error="Unexpected engine exit")

    async def batch_get(
        self,
        urls: list[str],
        params: dict | None = None,
        headers: dict | None = None,
        use_cache: bool = True,
        progress_cb: Callable[[ScanProgress], None] | None = None,
    ) -> list[AsyncResponse]:
        """
        Fetch multiple URLs concurrently with rate limiting.

        Args:
            urls:        List of URLs to fetch
            params:      Query params applied to all requests
            headers:     Headers applied to all requests
            use_cache:   Cache successful responses
            progress_cb: Optional callback called after each response

        Returns:
            List of AsyncResponse (same order as input URLs)
        """
        progress = ScanProgress(total=len(urls))
        results  = [None] * len(urls)

        async def fetch_one(idx: int, url: str) -> None:
            resp = await self.get(url, params=params, headers=headers, use_cache=use_cache)
            results[idx] = resp
            progress.increment(error=bool(resp.error))
            if progress_cb:
                progress_cb(progress)

        tasks = [fetch_one(i, url) for i, url in enumerate(urls)]
        await asyncio.gather(*tasks)
        return results

    async def batch_post(
        self,
        requests: list[dict],  # [{"url": ..., "json": ..., "data": ...}]
        progress_cb: Callable[[ScanProgress], None] | None = None,
    ) -> list[AsyncResponse]:
        """
        POST to multiple endpoints concurrently.

        Args:
            requests: List of dicts with keys: url, json (optional), data (optional)

        Returns:
            List of AsyncResponse (same order as input)
        """
        progress = ScanProgress(total=len(requests))
        results  = [None] * len(requests)

        async def post_one(idx: int, req: dict) -> None:
            url  = req.pop("url")
            resp = await self.post(url, **req)
            results[idx] = resp
            progress.increment(error=bool(resp.error))
            if progress_cb:
                progress_cb(progress)

        tasks = [post_one(i, dict(req)) for i, req in enumerate(requests)]
        await asyncio.gather(*tasks)
        return results

    @property
    def stats(self) -> dict:
        elapsed = time.monotonic() - self._start_time
        return {
            "total_requests": self._total_requests,
            "total_retries":  self._total_retries,
            "total_cached":   self._total_cached,
            "elapsed_s":      round(elapsed, 2),
            "req_per_sec":    round(self._total_requests / elapsed, 1) if elapsed > 0 else 0,
            "rate_limit":     self.rate_limit,
            "concurrency":    self.concurrency,
        }

    def print_stats(self) -> None:
        s = self.stats
        console.print(
            f"  [cyan]AsyncEngine stats:[/cyan] "
            f"{s['total_requests']} req | "
            f"{s['req_per_sec']} req/s | "
            f"{s['total_retries']} retries | "
            f"{s['total_cached']} cached | "
            f"{s['elapsed_s']}s"
        )
