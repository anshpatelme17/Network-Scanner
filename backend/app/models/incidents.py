"""Incident records (Steps 11 + 17, recording and management only).

An ``Incident`` is a persistent, auditable record opened from existing
platform data — a ``Correlation`` plus an optional ``RiskAssessment``.
It references source records by ID; it never copies event payloads and
never acts on anything. Severity comes from the linked risk assessment
when present, otherwise from the correlation (documented fallback).
``risk_score`` is the linked assessment's score verbatim (Step 10
formula; NULL when no assessment is linked — never a second formula).
Confidence comes from the correlation and represents evidence strength,
not probability of compromise. Status moves only through explicit API
transitions (see ``incident_service.TRANSITIONS``); there is no workflow
automation of any kind.

Step 17 additions (all additive): ``incident_type`` is a controlled
classification derived deterministically from the correlation's
``rule_id`` (see ``incident_detection.RULE_TYPE_MAP``); ``resolved_at``
records first entry into RESOLVED/CLOSED; ``detection_reason`` is the
deterministic explanation of why the incident was opened or updated.
``IncidentAudit`` rows record lifecycle changes using the same
actor/action/detail conventions as vulnerability audits.
``IncidentEvidence`` rows are idempotent reference links (never payload
copies) to the correlation, its events, and related vulnerability
findings.

Identity is deterministic: ``sha256("incident:v1" | correlation_id |
risk_assessment_id or "")`` — the same logical incident always maps to
the same row, so repeated creation is idempotent. No timestamps or
randomness enter the identity. ``incident_key`` (``INC-`` + 12 hex
chars) is a human-readable alias derived from the same hash.

Step 29 (additive): ``IncidentRelationship`` rows record deterministic
rule-produced links between an incident's stored evidence events and
existing assets/users/indicators (see the class docstring). Nothing in
Steps 1-28 reads or writes them.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


def _utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class Incident(Base):
    __tablename__ = "incidents"

    # Deterministic identity (see module docstring).
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_key: Mapped[str] = mapped_column(String(16), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="OPEN", index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    confidence: Mapped[int] = mapped_column(default=0, nullable=False)

    primary_asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    primary_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)

    correlation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("correlations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    risk_assessment_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("risk_assessments.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0.0")

    # Step 17 (additive): controlled classification, linked-assessment
    # score verbatim, and the deterministic open/update explanation.
    incident_type: Mapped[str] = mapped_column(String(32), nullable=False, default="OTHER")
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class IncidentAudit(Base):
    """One auditable lifecycle fact about an incident (Step 17).

    Actions are a controlled vocabulary: ``OPENED``, ``EVIDENCE_ATTACHED``,
    ``STATUS_CHANGED``, ``UPDATED``. Same actor/action/detail conventions
    as vulnerability audits; rows are append-only and ordered by
    ``created_at`` (id tiebreak).
    """

    __tablename__ = "incident_audits"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Step 31: index on created_at because every audit read orders by it
    # (id tiebreak) and an unindexed sort is a full scan + filesort that
    # grows with the audit history.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now(), index=True
    )
    # Step 31: correlation id of the originating request (nullable; rows
    # written outside a request have none). Sanitised, never caller text.
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)


class IncidentEvidence(Base):
    """One idempotent evidence reference (Step 17, links only, never copies).

    ``evidence_kind`` is ``correlation`` | ``event`` | ``vulnerability``;
    ``evidence_id`` is the referenced row's primary key. ``reason`` states
    why the link exists. Uniqueness on (incident, kind, id) makes
    reprocessing idempotent by construction.
    """

    __tablename__ = "incident_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    evidence_id: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "incident_id", "evidence_kind", "evidence_id", name="uq_incident_evidence"
        ),
    )


class IncidentRelationship(Base):
    """One incident-intelligence relationship (Step 29, stored data only).

    A row links two real stored records (event, asset, user field value,
    network indicator, or another event) through one deterministic
    Step 29 analysis rule. Rows are produced only by
    ``app.services.incident_analysis`` from the incident's own evidence
    events plus existing ``Asset`` rows — never from client input, never
    from missing data, and never inventing an entity: absent fields mean
    no row is created.

    Identity is deterministic: ``sha256("incident-relationship:v1" |
    incident_id | rule_id | source_kind | source_id | target_kind |
    target_id)`` — no timestamps or randomness, so repeated analysis
    upserts instead of duplicating. ``confidence`` is the rule's fixed
    0-100 evidence strength and ``confidence_label`` the deterministic
    DIRECT/STRONG/MODERATE/WEAK translation of it (see
    ``incident_rules.confidence_label``) — a relationship description,
    not a machine-learning prediction. ``evidence_json`` holds the sorted
    backing event ids (reference ids only, never payload copies).
    """

    __tablename__ = "incident_relationships"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rule_name: Mapped[str] = mapped_column(String(128), nullable=False)
    relation: Mapped[str] = mapped_column(String(64), nullable=False)
    source_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    source_id: Mapped[str] = mapped_column(String(255), nullable=False)
    source_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    target_id: Mapped[str] = mapped_column(String(255), nullable=False)
    target_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    confidence_label: Mapped[str] = mapped_column(String(16), nullable=False, default="WEAK")
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "incident_id",
            "rule_id",
            "source_kind",
            "source_id",
            "target_kind",
            "target_id",
            name="uq_incident_relationship",
        ),
    )
