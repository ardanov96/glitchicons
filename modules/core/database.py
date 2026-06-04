"""
Database ORM — modules/core/database.py

Persistent storage layer for Glitchicons scan history.
Supports SQLite (dev/solo) and PostgreSQL (team/production).

Models:
  Target         — scan target (URL, name, tags, metadata)
  Scan           — scan session (target, status, timestamps, config)
  Finding        — individual security finding (severity, cvss, cwe)
  WebhookConfig  — webhook endpoint configuration
  ScheduledScan  — recurring scan schedule

Usage:
    from modules.core.database import Database, Target, Scan, Finding

    # SQLite (dev)
    db = Database("sqlite:///glitchicons.db")
    db.init()

    # PostgreSQL (production)
    db = Database("postgresql://user:pass@localhost/glitchicons")
    db.init()

    # CRUD
    with db.session() as s:
        target = db.create_target(s, url="https://target.com", name="Target Corp")
        scan   = db.create_scan(s, target_id=target.id, modules=["sqli", "xss"])
        db.add_finding(s, scan_id=scan.id, title="SQLi Found", severity="HIGH")
        db.complete_scan(s, scan.id, status="completed")

Author: ardanov96
"""

import json
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Generator

try:
    from sqlalchemy import (
        Column, String, Integer, Float, Boolean, Text,
        DateTime, ForeignKey, create_engine, Index,
        func, text,
    )
    from sqlalchemy.orm import (
        DeclarativeBase, relationship, Session,
        sessionmaker, mapped_column,
    )
    from sqlalchemy.pool import StaticPool
    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


# ── ORM Models ────────────────────────────────────────────

if HAS_SQLALCHEMY:
    class Base(DeclarativeBase):
        pass

    class Target(Base):
        """A scan target — URL, name, metadata."""
        __tablename__ = "targets"

        id          = Column(String(36), primary_key=True, default=_uuid)
        url         = Column(String(2048), nullable=False, index=True)
        name        = Column(String(255), nullable=False, default="")
        tags        = Column(Text, default="[]")      # JSON list
        notes       = Column(Text, default="")
        created_at  = Column(DateTime(timezone=True), default=_now)
        updated_at  = Column(DateTime(timezone=True), default=_now, onupdate=_now)
        active      = Column(Boolean, default=True)

        scans = relationship("Scan", back_populates="target",
                             cascade="all, delete-orphan")

        @property
        def tags_list(self) -> list[str]:
            try:
                return json.loads(self.tags or "[]")
            except Exception:
                return []

        def __repr__(self) -> str:
            return f"<Target id={self.id[:8]} url={self.url}>"

    class Scan(Base):
        """A scan session — links target to findings."""
        __tablename__ = "scans"

        id          = Column(String(36), primary_key=True, default=_uuid)
        target_id   = Column(String(36), ForeignKey("targets.id"), nullable=False, index=True)
        status      = Column(String(20), default="pending", index=True)
        # pending | running | completed | failed | cancelled
        modules     = Column(Text, default="[]")       # JSON list of module names
        config      = Column(Text, default="{}")       # JSON config dict
        started_at  = Column(DateTime(timezone=True), nullable=True)
        completed_at= Column(DateTime(timezone=True), nullable=True)
        created_at  = Column(DateTime(timezone=True), default=_now)
        error_msg   = Column(Text, default="")
        finding_count = Column(Integer, default=0)
        critical_count = Column(Integer, default=0)
        high_count  = Column(Integer, default=0)
        duration_s  = Column(Float, default=0.0)

        target   = relationship("Target", back_populates="scans")
        findings = relationship("Finding", back_populates="scan",
                                cascade="all, delete-orphan")

        @property
        def modules_list(self) -> list[str]:
            try:
                return json.loads(self.modules or "[]")
            except Exception:
                return []

        @property
        def is_running(self) -> bool:
            return self.status == "running"

        @property
        def is_complete(self) -> bool:
            return self.status in ("completed", "failed", "cancelled")

        def __repr__(self) -> str:
            return f"<Scan id={self.id[:8]} status={self.status}>"

    class Finding(Base):
        """A single security finding from a scan."""
        __tablename__ = "findings"

        id          = Column(String(36), primary_key=True, default=_uuid)
        scan_id     = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
        title       = Column(String(512), nullable=False)
        severity    = Column(String(20), nullable=False, index=True)
        cvss        = Column(Float, default=0.0)
        cwe         = Column(String(20), default="")
        target_url  = Column(String(2048), default="")
        description = Column(Text, default="")
        evidence    = Column(Text, default="")
        remediation = Column(Text, default="")
        source      = Column(String(100), default="")
        false_positive = Column(Boolean, default=False, index=True)
        verified    = Column(Boolean, default=False)
        created_at  = Column(DateTime(timezone=True), default=_now)
        resolved_at = Column(DateTime(timezone=True), nullable=True)

        scan = relationship("Scan", back_populates="findings")

        __table_args__ = (
            Index("ix_findings_severity_scan", "severity", "scan_id"),
        )

        def to_dict(self) -> dict:
            return {
                "id":          self.id,
                "scan_id":     self.scan_id,
                "title":       self.title,
                "severity":    self.severity,
                "cvss":        self.cvss,
                "cwe":         self.cwe,
                "target":      self.target_url,
                "description": self.description,
                "evidence":    self.evidence,
                "remediation": self.remediation,
                "source":      self.source,
                "false_positive": self.false_positive,
                "verified":    self.verified,
                "created_at":  self.created_at.isoformat() if self.created_at else "",
            }

        def __repr__(self) -> str:
            return f"<Finding [{self.severity}] {self.title[:40]}>"

    class WebhookConfig(Base):
        """Webhook endpoint configuration."""
        __tablename__ = "webhook_configs"

        id          = Column(String(36), primary_key=True, default=_uuid)
        name        = Column(String(100), nullable=False)
        url         = Column(String(2048), nullable=False)
        secret      = Column(String(256), default="")
        events      = Column(Text, default='["scan_completed","finding_critical"]')
        enabled     = Column(Boolean, default=True)
        created_at  = Column(DateTime(timezone=True), default=_now)
        last_fired  = Column(DateTime(timezone=True), nullable=True)
        fire_count  = Column(Integer, default=0)
        error_count = Column(Integer, default=0)

        @property
        def events_list(self) -> list[str]:
            try:
                return json.loads(self.events or "[]")
            except Exception:
                return []

    class ScheduledScan(Base):
        """Recurring scan schedule."""
        __tablename__ = "scheduled_scans"

        id          = Column(String(36), primary_key=True, default=_uuid)
        target_id   = Column(String(36), ForeignKey("targets.id"), nullable=False)
        name        = Column(String(255), nullable=False)
        schedule    = Column(String(100), nullable=False)  # "interval:24h" or cron "0 2 * * *"
        modules     = Column(Text, default="[]")
        enabled     = Column(Boolean, default=True)
        created_at  = Column(DateTime(timezone=True), default=_now)
        last_run    = Column(DateTime(timezone=True), nullable=True)
        next_run    = Column(DateTime(timezone=True), nullable=True)
        run_count   = Column(Integer, default=0)

        target = relationship("Target")


# ── Database class ────────────────────────────────────────

class Database:
    """
    Database connection and CRUD operations.

    Supports SQLite (default) and PostgreSQL.
    Tests use in-memory SQLite for isolation.
    """

    def __init__(self, url: str = "sqlite:///glitchicons.db"):
        if not HAS_SQLALCHEMY:
            raise ImportError("sqlalchemy required: pip install sqlalchemy")

        self.url = url
        kwargs: dict = {}

        # SQLite in-memory needs special pooling for tests
        if url == "sqlite:///:memory:":
            kwargs = {
                "connect_args": {"check_same_thread": False},
                "poolclass":    StaticPool,
            }
        elif url.startswith("sqlite"):
            kwargs = {"connect_args": {"check_same_thread": False}}

        self.engine  = create_engine(url, **kwargs)
        self._Session = sessionmaker(bind=self.engine, expire_on_commit=False)

    def init(self) -> None:
        """Create all tables."""
        Base.metadata.create_all(self.engine)

    def drop_all(self) -> None:
        """Drop all tables (useful for testing)."""
        Base.metadata.drop_all(self.engine)

    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        """Context manager for database sessions."""
        s = self._Session()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    # ── Target CRUD ───────────────────────────────────────

    def create_target(
        self,
        session: Session,
        url: str,
        name: str = "",
        tags: list[str] | None = None,
        notes: str = "",
    ) -> "Target":
        target = Target(
            id=_uuid(), url=url, name=name or url,
            tags=json.dumps(tags or []), notes=notes,
        )
        session.add(target)
        session.flush()
        return target

    def get_target(self, session: Session, target_id: str) -> "Target | None":
        return session.get(Target, target_id)

    def get_target_by_url(self, session: Session, url: str) -> "Target | None":
        return session.query(Target).filter(Target.url == url).first()

    def list_targets(self, session: Session, active_only: bool = True) -> list["Target"]:
        q = session.query(Target)
        if active_only:
            q = q.filter(Target.active == True)
        return q.order_by(Target.created_at.desc()).all()

    def delete_target(self, session: Session, target_id: str) -> bool:
        target = self.get_target(session, target_id)
        if target:
            target.active = False
            return True
        return False

    # ── Scan CRUD ─────────────────────────────────────────

    def create_scan(
        self,
        session: Session,
        target_id: str,
        modules: list[str] | None = None,
        config: dict | None = None,
    ) -> "Scan":
        scan = Scan(
            id=_uuid(),
            target_id=target_id,
            status="pending",
            modules=json.dumps(modules or []),
            config=json.dumps(config or {}),
        )
        session.add(scan)
        session.flush()
        return scan

    def start_scan(self, session: Session, scan_id: str) -> bool:
        scan = session.get(Scan, scan_id)
        if scan and scan.status == "pending":
            scan.status     = "running"
            scan.started_at = _now()
            return True
        return False

    def complete_scan(
        self,
        session: Session,
        scan_id: str,
        status: str = "completed",
        error_msg: str = "",
    ) -> bool:
        scan = session.get(Scan, scan_id)
        if scan:
            scan.status       = status
            scan.completed_at = _now()
            scan.error_msg    = error_msg
            if scan.started_at:
                delta = (scan.completed_at - scan.started_at).total_seconds()
                scan.duration_s = round(delta, 2)
            # Update counts
            scan.finding_count  = session.query(func.count(Finding.id)).filter(
                Finding.scan_id == scan_id,
                Finding.false_positive == False
            ).scalar() or 0
            scan.critical_count = session.query(func.count(Finding.id)).filter(
                Finding.scan_id == scan_id,
                Finding.severity == "CRITICAL",
                Finding.false_positive == False
            ).scalar() or 0
            scan.high_count = session.query(func.count(Finding.id)).filter(
                Finding.scan_id == scan_id,
                Finding.severity == "HIGH",
                Finding.false_positive == False
            ).scalar() or 0
            return True
        return False

    def get_scan(self, session: Session, scan_id: str) -> "Scan | None":
        return session.get(Scan, scan_id)

    def list_scans(
        self,
        session: Session,
        target_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> list["Scan"]:
        q = session.query(Scan)
        if target_id:
            q = q.filter(Scan.target_id == target_id)
        if status:
            q = q.filter(Scan.status == status)
        return q.order_by(Scan.created_at.desc()).limit(limit).all()

    def cancel_scan(self, session: Session, scan_id: str) -> bool:
        scan = session.get(Scan, scan_id)
        if scan and scan.status in ("pending", "running"):
            scan.status       = "cancelled"
            scan.completed_at = _now()
            return True
        return False

    # ── Finding CRUD ──────────────────────────────────────

    def add_finding(
        self,
        session: Session,
        scan_id: str,
        title: str,
        severity: str,
        cvss: float = 0.0,
        cwe: str = "",
        target_url: str = "",
        description: str = "",
        evidence: str = "",
        remediation: str = "",
        source: str = "",
    ) -> "Finding":
        assert severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        finding = Finding(
            id=_uuid(), scan_id=scan_id,
            title=title, severity=severity, cvss=cvss, cwe=cwe,
            target_url=target_url, description=description,
            evidence=evidence, remediation=remediation, source=source,
        )
        session.add(finding)
        session.flush()
        return finding

    def add_findings_bulk(
        self, session: Session, scan_id: str, findings: list[dict]
    ) -> int:
        """Bulk import findings from Glitchicons finding dicts."""
        added = 0
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for f in findings:
            sev = f.get("severity", "INFO")
            if sev not in valid_severities:
                continue
            finding = Finding(
                id=_uuid(), scan_id=scan_id,
                title=f.get("title", "")[:500],
                severity=sev,
                cvss=float(f.get("cvss", 0.0)),
                cwe=f.get("cwe", ""),
                target_url=f.get("target", ""),
                description=f.get("description", ""),
                evidence=f.get("evidence", ""),
                remediation=f.get("remediation", ""),
                source=f.get("source", ""),
            )
            session.add(finding)
            added += 1
        session.flush()
        return added

    def get_finding(self, session: Session, finding_id: str) -> "Finding | None":
        return session.get(Finding, finding_id)

    def list_findings(
        self,
        session: Session,
        scan_id: str | None = None,
        severity: str | None = None,
        false_positive: bool = False,
        limit: int = 200,
    ) -> list["Finding"]:
        q = session.query(Finding)
        if scan_id:
            q = q.filter(Finding.scan_id == scan_id)
        if severity:
            q = q.filter(Finding.severity == severity)
        if not false_positive:
            q = q.filter(Finding.false_positive == False)
        return q.order_by(Finding.cvss.desc()).limit(limit).all()

    def mark_false_positive(
        self, session: Session, finding_id: str, is_fp: bool = True
    ) -> bool:
        finding = session.get(Finding, finding_id)
        if finding:
            finding.false_positive = is_fp
            return True
        return False

    def mark_verified(self, session: Session, finding_id: str) -> bool:
        finding = session.get(Finding, finding_id)
        if finding:
            finding.verified = True
            return True
        return False

    # ── Webhook CRUD ──────────────────────────────────────

    def create_webhook(
        self,
        session: Session,
        name: str,
        url: str,
        events: list[str] | None = None,
        secret: str = "",
    ) -> "WebhookConfig":
        default_events = events or ["scan_completed", "finding_critical"]
        wh = WebhookConfig(
            id=_uuid(), name=name, url=url,
            events=json.dumps(default_events), secret=secret,
        )
        session.add(wh)
        session.flush()
        return wh

    def list_webhooks(
        self, session: Session, enabled_only: bool = True
    ) -> list["WebhookConfig"]:
        q = session.query(WebhookConfig)
        if enabled_only:
            q = q.filter(WebhookConfig.enabled == True)
        return q.all()

    # ── Statistics ────────────────────────────────────────

    def stats(self, session: Session) -> dict:
        """Get database statistics."""
        return {
            "targets":       session.query(func.count(Target.id)).scalar() or 0,
            "scans":         session.query(func.count(Scan.id)).scalar() or 0,
            "findings":      session.query(func.count(Finding.id)).scalar() or 0,
            "critical":      session.query(func.count(Finding.id)).filter(
                                 Finding.severity == "CRITICAL").scalar() or 0,
            "false_positives": session.query(func.count(Finding.id)).filter(
                                 Finding.false_positive == True).scalar() or 0,
            "webhooks":      session.query(func.count(WebhookConfig.id)).scalar() or 0,
        }

    def finding_severity_breakdown(self, session: Session, scan_id: str) -> dict:
        """Count findings by severity for a scan."""
        rows = session.query(
            Finding.severity, func.count(Finding.id)
        ).filter(
            Finding.scan_id == scan_id,
            Finding.false_positive == False,
        ).group_by(Finding.severity).all()
        return {sev: count for sev, count in rows}
