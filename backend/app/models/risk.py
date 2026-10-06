"""Risk assessments (Steps 10 + 25, analysis only).

A ``RiskAssessment`` scores one platform entity — an ``asset``, a
vulnerability finding (a ``VULNERABILITY_FINDING`` event), a
``correlation``, or (Step 25) an ``incident`` — using only data already
stored in the platform. The score is a neutral, reproducible number
(0–100) with structured factors and a plain-language explanation; it is
never proof of compromise and drives no automated action.

Determinism: the identity is
``sha256("risk-assessment:v1" | scoring_version | entity_type |
entity_id)`` — the same entity under the same scoring version always
maps to the same row, so recomputation updates in place instead of
duplicating. ``calculated_at`` records generation time but never enters
the mathematics. Including ``scoring_version`` in the identity preserves
history across future formula revisions.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


def _utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    # Deterministic identity (see module docstring).
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    entity_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    score: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    # Step 25 (additive, nullable for pre-existing rows): priority band
    # derived from the score (P1–P4). Readers fall back to computing it
    # from the stored score, which is always equivalent.
    priority: Mapped[str | None] = mapped_column(String(8), nullable=True, index=True)
    # Structured factors as JSON text (inputs + point breakdown).
    factors: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    explanation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    calculated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, default=_utcnow_naive
    )
    scoring_version: Mapped[str] = mapped_column(String(16), nullable=False, index=True)

    __table_args__ = (Index("ix_risk_entity", "entity_type", "entity_id"),)


class RiskAudit(Base):
    """Risk calculation facts (Step 25, append-only).

    One row per stored calculation that created an assessment or changed
    its score/severity/priority; repeat calculations with identical
    outcomes write nothing. Records actor, old→new score, resulting
    classification, and reason. Never contains secrets — identifiers and
    numbers only.
    """

    __tablename__ = "risk_audits"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    assessment_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("risk_assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    previous_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    new_score: Mapped[int] = mapped_column(Integer, nullable=False)
    classification: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now()
    )
