"""Canonical security event model (Step 3).

``SecurityEvent`` is the single normalized shape every future source
adapts into. All descriptive fields are nullable: the normalizer stores
what the source reported and leaves the rest ``None`` — never fake
values. Timestamps are naive UTC, consistent with the rest of the schema.

Idempotency: ``(source_type, source_name, external_event_id)`` is unique
when ``external_event_id`` is present (``source_name`` is required, so the
triple is never null). Re-ingesting the same triple returns the existing
row instead of inserting a duplicate. Similar-looking events WITHOUT a
matching triple are always stored — nothing is silently discarded.

``fingerprint`` is a deterministic SHA-256 over stable attributes
(excluding ingest timestamps) for future correlation use; it is
informational only and never triggers deduplication by itself.
``raw_event`` is the original payload as JSON text — data only, never
interpreted or executed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    event_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, index=True
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, default=_utcnow
    )

    source_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source_name: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    # Step 23 (additive, nullable): source-supplied confidence 0-100.
    # NULL means unknown — never inferred, never defaulted.
    confidence: Mapped[int | None] = mapped_column(Integer, nullable=True)

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(8), nullable=True)

    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    action: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Original payload, JSON-serialized. Data only.
    raw_event: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Normalized canonical snapshot, JSON-serialized (mirrors the columns).
    normalized_data: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    correlation_key: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    external_event_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Step 23 (additive): dedup replay accounting. occurrence_count
    # starts at 1 and increments per idempotent replay; last_seen_at
    # tracks the most recent observation (received_at stays first-seen).
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "source_type",
            "source_name",
            "external_event_id",
            name="uq_event_source_external_id",
        ),
        Index("ix_event_time_severity", "event_time", "severity"),
    )


class EventAudit(Base):
    """Ingestion lifecycle facts (Step 23, append-only).

    Actions: ``EVENT_RECEIVED`` (stored), ``EVENT_NORMALIZED``
    (validation+normalization passed), ``EVENT_DEDUPLICATED`` (idempotent
    replay), ``EVENT_REJECTED`` (validation/adapter failure). ``event_id``
    is NULL for rejections that never produced a row. Never contains
    secrets — actor, identifiers, and outcomes only.
    """

    __tablename__ = "event_audits"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("security_events.id", ondelete="CASCADE"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now()
    )
