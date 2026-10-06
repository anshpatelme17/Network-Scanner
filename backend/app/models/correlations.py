"""Correlation records (Step 9, analysis only).

A ``Correlation`` groups related ``SecurityEvent`` rows found by a
deterministic rule — it is *evidence grouping*, never proof of
compromise and never an incident. Severity is inherited as the maximum
of the evidence severities; confidence is a fixed per-rule value
(documented in ``correlation_rules``); the explanation names the rule
and the matched pivot values. The identity is
``sha256("correlation:v1" | rule_id | sorted event ids)`` — the same
evidence set always yields the same row, so reprocessing is idempotent
(no timestamps or randomness in the identity).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def _utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class Correlation(Base):
    __tablename__ = "correlations"

    # Deterministic identity (see module docstring); not a random UUID.
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    rule_name: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open", index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    explanation: Mapped[str] = mapped_column(Text, nullable=False, default="")

    primary_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)

    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    evidence: Mapped[list[CorrelationEvidence]] = relationship(
        "CorrelationEvidence",
        back_populates="correlation",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class CorrelationEvidence(Base):
    """One evidence link: which event, in which correlation, in what role/order."""

    __tablename__ = "correlation_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    correlation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("correlations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("security_events.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # "related" | "vulnerability" | "activity" — descriptive only.
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="related")
    # Zero-based position in event_time order.
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    correlation: Mapped[Correlation] = relationship("Correlation", back_populates="evidence")

    __table_args__ = (
        UniqueConstraint("correlation_id", "event_id", name="uq_correlation_event"),
        Index("ix_evidence_correlation_position", "correlation_id", "position"),
    )


class CorrelationAudit(Base):
    """Correlation-run lifecycle facts (Step 24, append-only).

    Actions: ``RUN_STARTED`` (one per recompute), ``CORRELATION_MATCHED``
    (one per created correlation; refreshes are routine replays, not
    matches), ``RUN_COMPLETED`` (counts summary). ``correlation_id`` is
    NULL for run-level rows. Never contains secrets — actor, rule, and
    counts only.
    """

    __tablename__ = "correlation_audits"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    correlation_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("correlations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now()
    )
