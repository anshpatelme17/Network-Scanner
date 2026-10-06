"""Checkpoint persistence + cursor sanitization (Step 28).

A checkpoint is only ever written by the server, after a bounded poll
has processed its records successfully. This module is the single
read/write surface for ``ingestion_checkpoints`` so both the connector
file reader (rotation detection) and the ingestion pipeline (advancement)
see exactly the same stored state.

Safety contract:

- Cursors are JSON documents built by the server from fetch provenance.
  :func:`sanitize_cursor` validates them before storage: bounded size,
  scalar-only values, and no secret-looking key or value (tokens,
  passwords, authorization/cookie material). A rejected cursor raises
  :class:`CheckpointRejected` — the previous cursor stays in place and
  the caller audits ``INGESTION_CHECKPOINT_REJECTED``.
- No client input ever reaches these functions: API callers can only
  *read* checkpoints through RBAC-protected endpoints.
- Nothing here performs network I/O or reads the filesystem.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.ingestion import IngestionCheckpoint

# Cursors are provenance summaries, not payloads: keep them tiny.
MAX_CURSOR_BYTES = 4096

# Names/values that must never appear inside a stored cursor.
_FORBIDDEN_KEY_PARTS = (
    "token",
    "secret",
    "password",
    "passwd",
    "authorization",
    "cookie",
    "credential",
    "api_key",
    "apikey",
    "bearer",
    "private_key",
    "session",
)
_FORBIDDEN_VALUE_PARTS = (
    "bearer ",
    "authorization:",
    "password=",
    "token=",
    "secret=",
    "set-cookie",
)


class CheckpointRejected(ValueError):
    """The candidate cursor failed validation; keep the stored one."""


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def sanitize_cursor(cursor: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate a server-built cursor and return a normalized copy.

    Raises :class:`CheckpointRejected` when the cursor is not a flat
    JSON-safe mapping, exceeds :data:`MAX_CURSOR_BYTES`, or carries a
    secret-looking key or value. Rejection messages name the offending
    key only — never the value.
    """
    if cursor is None:
        return {}
    if not isinstance(cursor, Mapping):
        raise CheckpointRejected("cursor must be an object.")
    cleaned: dict[str, Any] = {}
    for raw_key, value in cursor.items():
        if not isinstance(raw_key, str) or not raw_key:
            raise CheckpointRejected("cursor keys must be non-empty strings.")
        key = raw_key.strip().lower()
        if any(part in key for part in _FORBIDDEN_KEY_PARTS):
            raise CheckpointRejected(f"cursor key {raw_key!r} looks like a secret.")
        if value is None or isinstance(value, bool | int | float):
            cleaned[raw_key] = value
            continue
        if isinstance(value, str):
            lowered = value.lower()
            if any(part in lowered for part in _FORBIDDEN_VALUE_PARTS):
                raise CheckpointRejected(f"cursor key {raw_key!r} carries secret material.")
            if len(value) > 512:
                raise CheckpointRejected(f"cursor key {raw_key!r} exceeds the 512-char limit.")
            cleaned[raw_key] = value
            continue
        raise CheckpointRejected(f"cursor key {raw_key!r} must hold a scalar value.")
    blob = json.dumps(cleaned, sort_keys=True, separators=(",", ":"))
    if len(blob.encode("utf-8")) > MAX_CURSOR_BYTES:
        raise CheckpointRejected("cursor exceeds the size limit.")
    return cleaned


def load(db: Session, source: str) -> IngestionCheckpoint | None:
    """Return the stored checkpoint row for a source, if any."""
    return db.scalar(select(IngestionCheckpoint).where(IngestionCheckpoint.source == source))


def load_cursor(db: Session, source: str) -> dict[str, Any] | None:
    """Return the stored cursor mapping (``None`` when absent/unparseable)."""
    row = load(db, source)
    if row is None or not row.cursor:
        return None
    try:
        parsed = json.loads(row.cursor)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def advance(
    db: Session,
    source: str,
    *,
    cursor: Mapping[str, Any] | None = None,
    last_event_time: datetime | None = None,
    last_external_event_id: str | None = None,
) -> IngestionCheckpoint:
    """Upsert the checkpoint after successful processing.

    Validates the cursor first (raising :class:`CheckpointRejected`
    before any write), then creates or updates the single row for the
    source. Callers commit.
    """
    cleaned = sanitize_cursor(cursor)
    row = load(db, source)
    if row is None:
        row = IngestionCheckpoint(source=source)
        db.add(row)
    row.cursor = json.dumps(cleaned, sort_keys=True, separators=(",", ":")) or None
    row.last_event_time = last_event_time
    row.last_external_event_id = (
        str(last_external_event_id)[:255] if last_external_event_id else None
    )
    row.advance_count = (row.advance_count or 0) + 1
    row.updated_at = _utcnow()
    return row


def mark_rejected(db: Session, source: str) -> None:
    """Record that an advancement was refused (stored cursor unchanged).

    Only an existing checkpoint is stamped: a failed poll never *creates*
    a checkpoint, so "no row" keeps meaning "no successful poll yet".
    """
    row = load(db, source)
    if row is None:
        return
    row.last_rejected_at = _utcnow()
    row.updated_at = _utcnow()


def list_all(db: Session) -> list[IngestionCheckpoint]:
    """All checkpoint rows in stable source order."""
    return list(db.scalars(select(IngestionCheckpoint).order_by(IngestionCheckpoint.source)).all())


def to_status(row: IngestionCheckpoint | None) -> dict[str, Any] | None:
    """Safe API view of one checkpoint (no secrets by construction)."""
    if row is None:
        return None
    cursor: dict[str, Any] | None = None
    if row.cursor:
        try:
            parsed = json.loads(row.cursor)
            cursor = parsed if isinstance(parsed, dict) else None
        except ValueError:
            cursor = None
    return {
        "source": row.source,
        "cursor": cursor,
        "last_event_time": row.last_event_time.isoformat() if row.last_event_time else None,
        "last_external_event_id": row.last_external_event_id,
        "advance_count": row.advance_count or 0,
        "last_rejected_at": row.last_rejected_at.isoformat() if row.last_rejected_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


__all__ = [
    "MAX_CURSOR_BYTES",
    "CheckpointRejected",
    "advance",
    "list_all",
    "load",
    "load_cursor",
    "mark_rejected",
    "sanitize_cursor",
    "to_status",
]
