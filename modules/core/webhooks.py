"""
Webhook Manager — modules/core/webhooks.py

Send security event notifications to external endpoints.

Events:
  scan_started      — scan begins
  scan_completed    — scan finishes (includes finding summary)
  scan_failed       — scan error
  finding_critical  — CRITICAL severity finding detected
  finding_high      — HIGH severity finding detected

Payload format:
  {
    "event":      "finding_critical",
    "timestamp":  "2024-01-01T02:00:00Z",
    "source":     "glitchicons",
    "version":    "3.0.0",
    "data": {
      "scan_id":   "...",
      "target":    "https://target.com",
      "finding":   {...}
    }
  }

HMAC-SHA256 signature in X-Glitchicons-Signature header.

Usage:
    from modules.core.webhooks import WebhookManager, WebhookEvent

    manager = WebhookManager()
    manager.add_endpoint(
        name="Slack",
        url="https://hooks.slack.com/xxx",
        events=["finding_critical", "scan_completed"],
        secret="my_secret",
    )

    manager.fire(WebhookEvent.FINDING_CRITICAL, data={
        "scan_id": "...", "target": "...", "finding": {...}
    })

Author: ardanov96
"""

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import httpx

VERSION = "3.0.0"


# ── Event types ───────────────────────────────────────────

class WebhookEvent(str, Enum):
    SCAN_STARTED    = "scan_started"
    SCAN_COMPLETED  = "scan_completed"
    SCAN_FAILED     = "scan_failed"
    FINDING_CRITICAL = "finding_critical"
    FINDING_HIGH    = "finding_high"


ALL_EVENTS = [e.value for e in WebhookEvent]


# ── Data classes ──────────────────────────────────────────

@dataclass
class WebhookEndpoint:
    """A configured webhook destination."""
    id:         str
    name:       str
    url:        str
    events:     list[str]
    secret:     str = ""
    enabled:    bool = True
    timeout_s:  int  = 10
    created_at: str  = ""
    last_fired: str  = ""
    fire_count: int  = 0
    error_count: int = 0

    def listens_to(self, event: str) -> bool:
        return event in self.events or "*" in self.events


@dataclass
class WebhookPayload:
    """A webhook delivery payload."""
    event:     str
    timestamp: str
    source:    str = "glitchicons"
    version:   str = VERSION
    data:      dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps({
            "event":     self.event,
            "timestamp": self.timestamp,
            "source":    self.source,
            "version":   self.version,
            "data":      self.data,
        }, default=str)


@dataclass
class DeliveryResult:
    """Result of a webhook delivery attempt."""
    endpoint_id:  str
    endpoint_name: str
    event:        str
    success:      bool
    status_code:  int  = 0
    response_ms:  int  = 0
    error:        str  = ""
    timestamp:    str  = ""


@dataclass
class FireResult:
    """Aggregated result of firing an event to all endpoints."""
    event:     str
    delivered: int   = 0
    failed:    int   = 0
    skipped:   int   = 0
    results:   list[DeliveryResult] = field(default_factory=list)


# ── Signature ─────────────────────────────────────────────

def sign_payload(body: str, secret: str) -> str:
    """
    Generate HMAC-SHA256 signature for webhook payload.

    Returns: "sha256=<hex_digest>"
    """
    if not secret:
        return ""
    sig = hmac.new(
        secret.encode("utf-8"),
        body.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"sha256={sig}"


def verify_signature(body: str, secret: str, signature: str) -> bool:
    """Verify an incoming webhook signature."""
    expected = sign_payload(body, secret)
    if not expected or not signature:
        return False
    return hmac.compare_digest(expected, signature)


# ── Webhook Manager ───────────────────────────────────────

class WebhookManager:
    """
    Manage webhook endpoints and deliver event notifications.

    Features:
    - Multiple endpoints per event type
    - HMAC-SHA256 request signing
    - Retry on failure (configurable)
    - Delivery history per endpoint
    - Filtering by event type
    """

    def __init__(
        self,
        timeout: int = 10,
        max_retries: int = 2,
        retry_delay: float = 1.0,
    ):
        self.timeout      = timeout
        self.max_retries  = max_retries
        self.retry_delay  = retry_delay
        self._endpoints:  dict[str, WebhookEndpoint] = {}
        self._history:    list[DeliveryResult] = []
        self._client = httpx.Client(timeout=timeout)

    def add_endpoint(
        self,
        name: str,
        url: str,
        events: list[str] | None = None,
        secret: str = "",
        timeout_s: int = 10,
    ) -> str:
        """
        Register a webhook endpoint.

        Args:
            name:     Human-readable endpoint name
            url:      Webhook URL (HTTPS recommended)
            events:   Events to subscribe to (default: all)
            secret:   HMAC secret for request signing
            timeout_s: Request timeout in seconds

        Returns:
            endpoint_id (str)
        """
        endpoint_id = str(uuid.uuid4())
        self._endpoints[endpoint_id] = WebhookEndpoint(
            id=endpoint_id,
            name=name,
            url=url,
            events=events or ALL_EVENTS,
            secret=secret,
            timeout_s=timeout_s,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        return endpoint_id

    def remove_endpoint(self, endpoint_id: str) -> bool:
        """Remove a webhook endpoint."""
        if endpoint_id in self._endpoints:
            del self._endpoints[endpoint_id]
            return True
        return False

    def enable_endpoint(self, endpoint_id: str) -> bool:
        if endpoint_id in self._endpoints:
            self._endpoints[endpoint_id].enabled = True
            return True
        return False

    def disable_endpoint(self, endpoint_id: str) -> bool:
        if endpoint_id in self._endpoints:
            self._endpoints[endpoint_id].enabled = False
            return True
        return False

    def get_endpoint(self, endpoint_id: str) -> WebhookEndpoint | None:
        return self._endpoints.get(endpoint_id)

    def list_endpoints(self, enabled_only: bool = False) -> list[WebhookEndpoint]:
        eps = list(self._endpoints.values())
        if enabled_only:
            eps = [e for e in eps if e.enabled]
        return eps

    def fire(
        self,
        event: str | WebhookEvent,
        data: dict | None = None,
        sync: bool = True,
    ) -> FireResult:
        """
        Fire an event to all subscribed endpoints.

        Args:
            event: Event name (WebhookEvent enum or string)
            data:  Event payload data
            sync:  If True, deliver synchronously (default)

        Returns:
            FireResult with delivery counts and per-endpoint results
        """
        event_str = event.value if isinstance(event, WebhookEvent) else event
        payload   = WebhookPayload(
            event=event_str,
            timestamp=datetime.now(timezone.utc).isoformat(),
            data=data or {},
        )

        result = FireResult(event=event_str)
        subscribed = [
            ep for ep in self._endpoints.values()
            if ep.enabled and ep.listens_to(event_str)
        ]

        result.skipped = len(self._endpoints) - len(subscribed)

        for ep in subscribed:
            delivery = self._deliver(ep, payload)
            result.results.append(delivery)
            self._history.append(delivery)

            ep.fire_count += 1
            ep.last_fired  = payload.timestamp
            if delivery.success:
                result.delivered += 1
            else:
                result.failed    += 1
                ep.error_count   += 1

        return result

    def fire_scan_started(self, scan_id: str, target: str, modules: list[str]) -> FireResult:
        return self.fire(WebhookEvent.SCAN_STARTED, {
            "scan_id": scan_id, "target": target, "modules": modules,
        })

    def fire_scan_completed(
        self,
        scan_id: str,
        target: str,
        finding_count: int,
        critical_count: int,
        duration_s: float,
    ) -> FireResult:
        return self.fire(WebhookEvent.SCAN_COMPLETED, {
            "scan_id":       scan_id,
            "target":        target,
            "finding_count": finding_count,
            "critical_count": critical_count,
            "duration_s":    duration_s,
        })

    def fire_finding(self, finding: dict, event: WebhookEvent | None = None) -> FireResult:
        """Fire a finding event based on severity."""
        severity = finding.get("severity", "INFO")
        if event is None:
            event = (WebhookEvent.FINDING_CRITICAL
                     if severity == "CRITICAL"
                     else WebhookEvent.FINDING_HIGH)
        return self.fire(event, {"finding": finding})

    def get_history(
        self,
        limit: int = 50,
        event: str | None = None,
        endpoint_id: str | None = None,
    ) -> list[DeliveryResult]:
        """Get delivery history."""
        history = list(reversed(self._history))
        if event:
            history = [h for h in history if h.event == event]
        if endpoint_id:
            history = [h for h in history if h.endpoint_id == endpoint_id]
        return history[:limit]

    def get_stats(self) -> dict:
        """Get webhook delivery statistics."""
        total    = len(self._history)
        success  = sum(1 for h in self._history if h.success)
        return {
            "endpoints":       len(self._endpoints),
            "enabled":         sum(1 for e in self._endpoints.values() if e.enabled),
            "total_deliveries": total,
            "successful":      success,
            "failed":          total - success,
            "success_rate":    round(success / total * 100, 1) if total else 0.0,
        }

    def _deliver(
        self,
        endpoint: WebhookEndpoint,
        payload: WebhookPayload,
        attempt: int = 0,
    ) -> DeliveryResult:
        """Deliver payload to a single endpoint with retry."""
        body = payload.to_json()
        sig  = sign_payload(body, endpoint.secret)

        headers = {
            "Content-Type":              "application/json",
            "User-Agent":                f"Glitchicons/{VERSION}",
            "X-Glitchicons-Event":       payload.event,
            "X-Glitchicons-Delivery":    str(uuid.uuid4()),
        }
        if sig:
            headers["X-Glitchicons-Signature"] = sig

        start = datetime.now(timezone.utc)
        try:
            resp = self._client.post(
                endpoint.url,
                content=body,
                headers=headers,
                timeout=endpoint.timeout_s,
            )
            ms   = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
            ok   = resp.status_code < 300
            return DeliveryResult(
                endpoint_id=endpoint.id,
                endpoint_name=endpoint.name,
                event=payload.event,
                success=ok,
                status_code=resp.status_code,
                response_ms=ms,
                timestamp=payload.timestamp,
                error="" if ok else f"HTTP {resp.status_code}",
            )
        except Exception as e:
            ms = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
            # Retry on connection error
            if attempt < self.max_retries:
                import time
                time.sleep(self.retry_delay * (attempt + 1))
                return self._deliver(endpoint, payload, attempt + 1)
            return DeliveryResult(
                endpoint_id=endpoint.id,
                endpoint_name=endpoint.name,
                event=payload.event,
                success=False,
                status_code=0,
                response_ms=ms,
                timestamp=payload.timestamp,
                error=str(e),
            )
