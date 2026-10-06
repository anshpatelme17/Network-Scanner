"""Controlled Nmap scan-job model (Step 2, hardened in Step 14).

A ``ScanJob`` records the lifecycle of one operator-requested scan:
queued -> running -> completed | failed (or cancelled while queued).
Only the *normalized* outcome (counts + normalized assets/services) is
stored; raw Nmap XML is transport, never the source of truth, and is
discarded after parsing. Every lifecycle step appends a ``ScanAudit``
row (requested/started/completed/failed/cancelled).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def _utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class ScanStatus:
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    ALL = (QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED)


class ScanEvent:
    REQUESTED = "SCAN_REQUESTED"
    STARTED = "SCAN_STARTED"
    COMPLETED = "SCAN_COMPLETED"
    FAILED = "SCAN_FAILED"
    CANCELLED = "SCAN_CANCELLED"


# Scan engine identifier. Only "nmap" exists; the column pins the engine
# so a future async/scheduler layer can distinguish job origins.
SCAN_TYPE_NMAP = "nmap"


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # Normalized target exactly as validated (IP or CIDR string).
    target: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # Allow-listed profile name ("quick" | "standard" for Nmap;
    # BASELINE/SERVICE_VULNERABILITY_ASSESSMENT for assessments).
    profile: Mapped[str] = mapped_column(String(64), nullable=False)
    # Engine that ran the job; "nmap" for discovery, "vulnerability" for assessments.
    scan_type: Mapped[str] = mapped_column(String(16), nullable=False, default=SCAN_TYPE_NMAP)
    # Asset under assessment (vulnerability scans); null for target-based discovery scans.
    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    # Operator label. Defaults to "operator" (local-operator default, documented).
    requested_by: Mapped[str] = mapped_column(String(128), nullable=False, default="operator")
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=ScanStatus.QUEUED, index=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)

    # Short, operator-safe failure reason. Never a traceback.
    error: Mapped[str | None] = mapped_column(String(512), nullable=True)

    assets_found: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    services_found: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Human-readable outcome, e.g. "1 hosts, 2 ports". Informational only.
    result_summary: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Nmap version that performed the scan (informational, nullable when
    # the job never reached execution).
    nmap_version: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Step 22 (additive, nullable): adapter that ran an assessment job
    # ("fixture-scanner" for MOCK/TEST runs, "nmap-vuln" for LIVE runs).
    # Distinguishes live results from test results on every job row.
    scanner: Mapped[str | None] = mapped_column(String(64), nullable=True)

    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    audit: Mapped[list[ScanAudit]] = relationship(
        "ScanAudit",
        back_populates="job",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class ScanAudit(Base):
    """Append-only lifecycle record for one scan job."""

    __tablename__ = "scan_audit"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    detail: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Client-side microsecond default (not server now()): audit order must
    # distinguish rapid successive events, which SQLite's second-precision
    # CURRENT_TIMESTAMP cannot. The migration keeps a server default only
    # as a fallback for non-ORM inserts.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, default=_utcnow_naive
    )

    job: Mapped[ScanJob] = relationship("ScanJob", back_populates="audit")
