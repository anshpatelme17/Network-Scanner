"""Ingestion checkpoint model (Step 28).

A checkpoint is the server-controlled record of *how far a bounded poll
got* for one connector source. It exists so a future continuous/
streaming ingest can resume deterministically, and so today's bounded
polls can prove (and audit) that a checkpoint advanced only after the
records were successfully processed.

Contract:

- One row per source (``source`` is unique); the server creates and
  updates rows. No API accepts a client-supplied checkpoint, cursor, or
  advancement — reads are the only client-visible surface.
- ``cursor`` is a JSON document **built by the server** from fetch
  provenance (page counts, termination reason, byte offset, file
  identity). It is validated by ``app.services.checkpoints`` before it
  is stored: bounded size, no secret-looking keys or values. Credentials
  and tokens are never part of a checkpoint.
- ``last_event_time`` / ``last_external_event_id`` describe the last
  successfully processed event of the most recent advancement (NULL when
  the source produced none — never guessed).
- Advancement is counted (``advance_count``) and timestamped
  (``updated_at``); ``last_rejected_at`` records that an advancement was
  refused (failed poll, invalid cursor) while the previous cursor stayed
  in place.

Checkpoints never grant access: they hold no tokens and are only
reachable through RBAC-protected read endpoints.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class IngestionCheckpoint(Base):
    __tablename__ = "ingestion_checkpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    source: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    # Server-built, sanitized JSON cursor. Never contains credentials.
    cursor: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_event_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=False), nullable=True
    )
    last_external_event_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    advance_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_rejected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=False), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, default=_utcnow, onupdate=_utcnow
    )


__all__ = ["IngestionCheckpoint"]
