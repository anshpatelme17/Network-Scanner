"""Normalized vulnerability findings (Step 15, assessment inventory only).

A ``Vulnerability`` is a normalized finding about an asset (optionally
tied to one discovered service), produced by assessing already-
discovered inventory — never by live exploitation, which does not exist
in this platform. Findings are DATA ONLY: an open port is never
automatically a vulnerability; only explicit normalized findings exist.

Identity is deterministic: ``sha256("vulnerability:v1" | scanner |
scanner_finding_id | asset_id | service_id or "")`` — repeats update
``last_seen`` (and refreshed metadata) instead of duplicating. Status
moves only through explicit API transitions (OPEN ↔ ACCEPTED_RISK →
RESOLVED semantics in ``vulnerability_service``); disappearance from a
later scan never auto-resolves. Per-finding history lives in
``VulnerabilityAudit`` rows, which are never rewritten.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def _utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    # Deterministic identity (see module docstring).
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    service_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("discovered_services.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    scanner: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    scanner_finding_id: Mapped[str] = mapped_column(String(128), nullable=False)
    # Step 22 (additive, nullable): adapter version, observed product
    # version, and vendor-supplied fix version. Absent data stays NULL
    # and is rendered as missing — never guessed.
    scanner_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detected_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    cwe_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    affected_component: Mapped[str | None] = mapped_column(String(256), nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Unmapped input fields preserved verbatim as JSON (never interpreted).
    extra_data: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="OPEN", index=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, default=_utcnow_naive
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, default=_utcnow_naive, onupdate=_utcnow_naive
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    audit: Mapped[list[VulnerabilityAudit]] = relationship(
        "VulnerabilityAudit",
        back_populates="vulnerability",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class VulnerabilityAudit(Base):
    """Append-only history for one finding (opened, updated, status changes)."""

    __tablename__ = "vulnerability_audits"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vulnerability_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    previous_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    new_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Client-side microsecond default so rapid successive events order
    # deterministically (same SQLite lesson as prior audit tables).
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, default=_utcnow_naive
    )
    detail: Mapped[str | None] = mapped_column(String(512), nullable=True)

    vulnerability: Mapped[Vulnerability] = relationship("Vulnerability", back_populates="audit")
