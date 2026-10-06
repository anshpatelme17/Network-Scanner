"""Bounded ingestion pipeline (Step 28).

Turns the Step 26–27 connector poll into a production-oriented, still
operator-initiated, ingestion run::

    SOURCE -> CONNECTOR -> FETCH -> VALIDATE -> NORMALIZE
           -> DEDUPLICATE -> CORRELATE -> STORE -> AUDIT

Nothing here is a second event model: FETCH is the existing connector
fetch (file read or allow-listed API read), while VALIDATE / NORMALIZE /
DEDUPLICATE / CORRELATE / STORE are the unchanged Step 23 adapter
registry, normalizer, dedup triple, and inventory correlation. This
module adds the *shape* around that work:

- **Bounded queue (backpressure).** Retrieved records are offered to an
  in-process queue capped at ``ingestion_queue_max``. Overflow policy is
  explicit and deterministic: the *new* record is rejected, counted, and
  audited ``INGESTION_BACKPRESSURE`` — never silently lost, never an
  unbounded in-memory queue. When anything was rejected the checkpoint
  does **not** advance, so the next bounded poll re-reads the window and
  the dedup triple absorbs what was already stored.
- **Bounded batches.** The queue is drained in chunks of at most
  ``ingestion_max_batch_size``; every batch is audited
  (STARTED/COMPLETED/FAILED). Each event is still committed
  individually, so transactions stay small and a mid-batch failure
  leaves a replayable state instead of one giant transaction.
- **Checkpoints.** The server-built cursor from the fetch is sanitized
  and stored *only after* every batch processed successfully
  (``INGESTION_CHECKPOINT_ADVANCED``). Any failure records
  ``INGESTION_CHECKPOINT_REJECTED`` and leaves the stored cursor
  untouched — failed polls never advance a checkpoint.
- **Bounded retry.** Transient fetch failures (timeout / connection)
  are retried at most ``ingestion_retry_max`` extra times with linear
  backoff, each attempt audited ``INGESTION_RETRY``. Authentication and
  configuration failures are never retried.
- **Replay.** ``replay=True`` re-runs the same bounded, audited
  pipeline for one source; the Step 3 dedup triple absorbs repeats, so
  replay can never create duplicate canonical events.

Explicitly *not* here: background loops, schedulers, daemons, automatic
external calls, client-supplied cursors/URLs/paths, and any response
action. Every run starts from one RBAC-gated API request and stops at a
deterministic upper bound.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.services import checkpoints, connectors, event_adapters, event_service
from app.services.ingestion_audits import (
    AUDIT_INGESTION_BACKPRESSURE,
    AUDIT_INGESTION_BATCH_COMPLETED,
    AUDIT_INGESTION_BATCH_FAILED,
    AUDIT_INGESTION_BATCH_STARTED,
    AUDIT_INGESTION_CHECKPOINT_ADVANCED,
    AUDIT_INGESTION_CHECKPOINT_REJECTED,
    AUDIT_INGESTION_REPLAY,
    AUDIT_INGESTION_STARTED,
)

# The documented pipeline stages (Step 28 §1) — reported by the status
# endpoint so the UI and operators see the same fixed shape.
PIPELINE_STAGES: tuple[str, ...] = (
    "SOURCE",
    "CONNECTOR",
    "FETCH",
    "VALIDATE",
    "NORMALIZE",
    "DEDUPLICATE",
    "CORRELATE",
    "STORE",
    "AUDIT",
)

# Explicit, deterministic overflow policy for the bounded queue: when it
# is full, the *incoming* record is rejected (counted + audited). The
# already-queued records are always processed.
QUEUE_OVERFLOW = "REJECT_NEW"

# Streaming/worker activation state. Step 28 ships the architecture
# only: no scheduler, thread, timer, or daemon exists, and nothing
# polls without an explicit operator request.
STREAMING_MODE = "MANUAL"
STREAMING_ENABLED = False
STREAMING_DETAIL = (
    "Manual, operator-initiated polls only. Bounded worker/stream "
    "interfaces exist for a future step; automatic streaming is not enabled."
)


class IngestionError(connectors.ConnectorError):
    """Base class for Step 28 pipeline failures."""


class IngestionFailedError(IngestionError):
    """Processing failed; results may be partial and no checkpoint moved."""


def _utcnow_iso() -> str:
    return datetime.now(UTC).replace(tzinfo=None).isoformat()


def _audit(db: Session, action: str, actor: str, detail: str) -> None:
    """One pipeline audit row through the existing append-only model."""
    event_service.record_event_audit(db, action, None, actor, detail)


class BoundedQueue:
    """In-process FIFO with a hard cap and explicit overflow behavior.

    Deterministic and testable: ``offer`` either accepts the item or
    rejects it while at capacity (policy :data:`QUEUE_OVERFLOW`), and
    ``drain`` hands out everything in insertion order in chunks of at
    most ``batch_size``. Module-level totals are updated so the status
    endpoint can report enqueue/dequeue/drop counters.
    """

    def __init__(self, maxsize: int) -> None:
        self.maxsize = max(1, int(maxsize))
        self._items: list[Any] = []
        self.dropped = 0

    def __len__(self) -> int:
        return len(self._items)

    @property
    def depth(self) -> int:
        return len(self._items)

    def offer(self, item: Any) -> bool:
        if len(self._items) >= self.maxsize:
            self.dropped += 1
            _QUEUE["dropped"] += 1
            return False
        self._items.append(item)
        self.dropped_ok = True
        _QUEUE["enqueued"] += 1
        return True

    def drain(self, batch_size: int) -> list[list[Any]]:
        """Remove and return every queued item as bounded chunks."""
        size = max(1, int(batch_size))
        items, self._items = self._items, []
        _QUEUE["dequeued"] += len(items)
        return [items[index : index + size] for index in range(0, len(items), size)]


@dataclass
class SourceMetrics:
    """Per-process ingestion counters for one source (no secrets)."""

    fetched: int = 0
    normalized: int = 0
    accepted: int = 0
    deduplicated: int = 0
    rejected: int = 0
    failed: int = 0
    dropped: int = 0
    retries: int = 0
    batches: int = 0
    last_poll_at: str | None = None
    last_success_at: str | None = None
    last_failure_at: str | None = None
    last_failure_reason: str | None = None
    checkpoint_advanced: bool = field(default=False)


# Per-process registries. Reset with the app process (documented) and
# between tests via ``reset_runtime()``.
_metrics: dict[str, SourceMetrics] = {}
_QUEUE: dict[str, int] = {"depth": 0, "enqueued": 0, "dequeued": 0, "dropped": 0}


def _metrics_for(source: str) -> SourceMetrics:
    if source not in _metrics:
        _metrics[source] = SourceMetrics()
    return _metrics[source]


def reset_runtime() -> None:
    """TEST/ops helper: drop ephemeral ingestion metrics and counters."""
    _metrics.clear()
    _QUEUE.update(depth=0, enqueued=0, dequeued=0, dropped=0)


def _note_success(
    source: str,
    *,
    fetched: int,
    normalized: int,
    accepted: int,
    deduplicated: int,
    rejected: int,
    dropped: int,
    batches: int,
    attempts: int,
    checkpoint_advanced: bool,
) -> None:
    metrics = _metrics_for(source)
    metrics.fetched += fetched
    metrics.normalized += normalized
    metrics.accepted += accepted
    metrics.deduplicated += deduplicated
    metrics.rejected += rejected
    metrics.dropped += dropped
    metrics.batches += batches
    metrics.retries += max(0, attempts - 1)
    metrics.last_poll_at = _utcnow_iso()
    metrics.last_success_at = metrics.last_poll_at
    metrics.last_failure_at = None
    metrics.last_failure_reason = None
    metrics.checkpoint_advanced = checkpoint_advanced


def _note_failure(source: str, reason: str, attempts: int | None = None) -> None:
    metrics = _metrics_for(source)
    metrics.failed += 1
    if attempts is not None:
        metrics.retries += max(0, attempts - 1)
    metrics.last_poll_at = _utcnow_iso()
    metrics.last_failure_at = metrics.last_poll_at
    metrics.last_failure_reason = reason
    metrics.checkpoint_advanced = False


def _reject_checkpoint(db: Session, source: str, actor: str, detail: str) -> None:
    """Stamp the stored checkpoint (if any) as not advanced + audit it."""
    checkpoints.mark_rejected(db, source)
    _audit(db, AUDIT_INGESTION_CHECKPOINT_REJECTED, actor, detail)
    db.commit()


def poll_source(db: Session, source: str, actor: str, *, replay: bool = False) -> dict[str, object]:
    """Run one bounded, audited ingestion for one connector source.

    Raises ``KeyError`` for unknown sources (structured 422 upstream),
    ``connectors.ConnectorUnavailableError`` when the connector cannot
    run (structured 422, existing code), and ``IngestionFailedError``
    when a processing batch failed (structured 422 ``INGESTION_FAILED``).
    The checkpoint advances only on the success path.
    """
    if source not in connectors.SOURCES:
        raise KeyError(f"Unknown connector source: {source!r}.")
    settings = get_settings()
    registration = event_adapters.resolve_adapter(source)
    _audit(
        db,
        AUDIT_INGESTION_STARTED,
        actor,
        (
            f"{source}: ingestion started (batch_size={settings.ingestion_max_batch_size}, "
            f"queue_max={settings.ingestion_queue_max}, retry_max={settings.ingestion_retry_max})."
        ),
    )
    if replay:
        _audit(
            db,
            AUDIT_INGESTION_REPLAY,
            actor,
            f"{source}: replay requested; same bounded pipeline, dedup absorbs repeats.",
        )
    db.commit()

    tracker: dict[str, Any] = {}
    queue = BoundedQueue(settings.ingestion_queue_max)
    state = {"batches": 0, "dropped": 0}

    def processor(
        records: list[tuple[int, object]], errors: list[dict[str, object]]
    ) -> tuple[int, int, int]:
        for record in records:
            if not queue.offer(record):
                state["dropped"] += 1
        if state["dropped"]:
            _audit(
                db,
                AUDIT_INGESTION_BACKPRESSURE,
                actor,
                (
                    f"{source}: bounded queue full ({queue.maxsize}); "
                    f"{state['dropped']} record(s) rejected, none silently dropped."
                ),
            )
            db.commit()
        chunks = queue.drain(settings.ingestion_max_batch_size)
        total = len(chunks)
        accepted = 0
        duplicates = 0
        rejected = 0
        for number, chunk in enumerate(chunks, start=1):
            state["batches"] = number
            _audit(
                db,
                AUDIT_INGESTION_BATCH_STARTED,
                actor,
                f"{source}: batch {number}/{total} ({len(chunk)} record(s)).",
            )
            db.commit()
            try:
                batch_accepted, batch_duplicates, batch_rejected = connectors.ingest_records(
                    db, registration, chunk, source, actor, errors, tracker
                )
            except Exception as exc:  # noqa: BLE001 - one bad batch must fail safely
                _audit(
                    db,
                    AUDIT_INGESTION_BATCH_FAILED,
                    actor,
                    f"{source}: batch {number}/{total} failed ({type(exc).__name__}).",
                )
                db.commit()
                raise IngestionFailedError(
                    f"{source}: ingestion failed in batch {number}/{total}; "
                    "checkpoint not advanced."
                ) from exc
            _audit(
                db,
                AUDIT_INGESTION_BATCH_COMPLETED,
                actor,
                (
                    f"{source}: batch {number}/{total} accepted {batch_accepted}, "
                    f"duplicates {batch_duplicates}, rejected {batch_rejected}."
                ),
            )
            db.commit()
            accepted += batch_accepted
            duplicates += batch_duplicates
            rejected += batch_rejected
        return accepted, duplicates, rejected

    try:
        result = connectors.poll_source(db, source, actor, processor=processor)
    except IngestionFailedError as exc:
        _note_failure(source, "batch failed", connectors.fetch_attempts(source))
        _reject_checkpoint(db, source, actor, f"{source}: {exc}")
        raise
    except connectors.ConnectorUnavailableError:
        _note_failure(source, "connector unavailable", connectors.fetch_attempts(source))
        _reject_checkpoint(db, source, actor, f"{source}: poll failed; checkpoint left unchanged.")
        raise

    cursor = result.get("cursor")
    cursor_map = cursor if isinstance(cursor, Mapping) else {}
    attempts = int(result.get("fetch_attempts", 1) or 1)
    counts = {
        "fetched": int(result.get("retrieved", 0) or 0),
        "accepted": int(result.get("accepted", 0) or 0),
        "deduplicated": int(result.get("duplicates", 0) or 0),
        # Phase 2 Step 6: records that produced a canonical event, i.e.
        # accepted (new) plus deduplicated (already known). Reported
        # explicitly so received / normalized / accepted / rejected /
        # duplicated are each distinguishable rather than inferred.
        "normalized": (int(result.get("accepted", 0) or 0) + int(result.get("duplicates", 0) or 0)),
        "rejected": int(result.get("rejected", 0) or 0),
        "batches": int(state["batches"]),
        "attempts": attempts,
    }
    dropped = int(state["dropped"])

    if dropped:
        # Backpressure: the checkpoint must not move past records the
        # bounded queue refused. The next poll re-reads the bounded
        # window and the Step 3 dedup triple absorbs what was already
        # stored, so nothing is lost and nothing is silently dropped.
        _reject_checkpoint(
            db,
            source,
            actor,
            f"{source}: {dropped} record(s) rejected by the bounded queue "
            f"({queue.maxsize}); checkpoint left unchanged for replay.",
        )
        _note_success(source, dropped=dropped, checkpoint_advanced=False, **counts)
        result.update(
            {
                "batches": counts["batches"],
                "normalized": counts["normalized"],
                "queue_dropped": dropped,
                "checkpoint_advanced": False,
            }
        )
        return result

    try:
        sanitized = checkpoints.sanitize_cursor(cursor_map)
    except checkpoints.CheckpointRejected as exc:
        _note_failure(source, "cursor rejected", attempts)
        _reject_checkpoint(db, source, actor, f"{source}: cursor rejected ({exc}).")
        raise IngestionFailedError(
            f"{source}: checkpoint cursor was rejected; events were stored but the "
            "checkpoint did not advance."
        ) from exc

    row = checkpoints.advance(
        db,
        source,
        cursor=sanitized,
        last_event_time=tracker.get("last_event_time"),
        last_external_event_id=tracker.get("last_external_event_id"),
    )
    _audit(
        db,
        AUDIT_INGESTION_CHECKPOINT_ADVANCED,
        actor,
        f"{source}: checkpoint advanced (#{row.advance_count}); cursor={row.cursor}.",
    )
    db.commit()

    _note_success(source, dropped=dropped, checkpoint_advanced=True, **counts)
    result.update(
        {
            "batches": counts["batches"],
            "normalized": counts["normalized"],
            "queue_dropped": dropped,
            "checkpoint_advanced": True,
        }
    )
    return result


def status(db: Session) -> dict[str, Any]:
    """Safe, read-only ingestion observability (no network, no secrets).

    Reports configured bounds, queue/backpressure counters, streaming
    mode (manual — never enabled), per-source counters, connector state
    as evaluated by the Step 27 truth machine, and checkpoint state.
    Configuration is never presented as connectivity: a connector only
    shows CONNECTED when an actual check/poll verified it.
    """
    settings = get_settings()
    rows = {row.source: row for row in checkpoints.list_all(db)}
    sources: list[dict[str, Any]] = []
    totals = {
        "fetched": 0,
        "normalized": 0,
        "accepted": 0,
        "deduplicated": 0,
        "rejected": 0,
        "failed": 0,
        "dropped": 0,
        "retries": 0,
        "batches": 0,
    }
    for source in connectors.SOURCES:
        health = connectors.health(source)
        metrics = _metrics.get(source) or SourceMetrics()
        totals["fetched"] += metrics.fetched
        totals["normalized"] += metrics.normalized
        totals["accepted"] += metrics.accepted
        totals["deduplicated"] += metrics.deduplicated
        totals["rejected"] += metrics.rejected
        totals["failed"] += metrics.failed
        totals["dropped"] += metrics.dropped
        totals["retries"] += metrics.retries
        totals["batches"] += metrics.batches
        sources.append(
            {
                "source": source,
                "mode": health.mode,
                "state": health.state,
                "connector_state": health.connector_state,
                "last_poll_at": metrics.last_poll_at,
                "last_success_at": metrics.last_success_at,
                "last_failure_at": metrics.last_failure_at,
                "last_failure_reason": metrics.last_failure_reason,
                "events_fetched": metrics.fetched,
                "events_normalized": metrics.normalized,
                "events_accepted": metrics.accepted,
                "events_deduplicated": metrics.deduplicated,
                "events_rejected": metrics.rejected,
                "events_failed": metrics.failed,
                "events_dropped": metrics.dropped,
                "retries": metrics.retries,
                "batches": metrics.batches,
                # The queue is drained synchronously inside each poll, so
                # the in-process depth is 0 whenever an operator reads it.
                "queue_depth": 0,
                "checkpoint": checkpoints.to_status(rows.get(source)),
            }
        )
    return {
        "generated_at": _utcnow_iso(),
        "pipeline": list(PIPELINE_STAGES),
        "limits": {
            "max_pages": settings.connector_max_pages,
            "max_events": settings.connector_max_events,
            "max_poll_lines": connectors.MAX_POLL_LINES,
            "batch_size": settings.ingestion_max_batch_size,
            "queue_max": settings.ingestion_queue_max,
            "retry_max": settings.ingestion_retry_max,
            "timeout_seconds": settings.connector_timeout_seconds,
            "file_resume": settings.connector_file_resume,
        },
        "queue": {
            "max": settings.ingestion_queue_max,
            "depth": _QUEUE["depth"],
            "enqueued_total": _QUEUE["enqueued"],
            "dequeued_total": _QUEUE["dequeued"],
            "dropped_total": _QUEUE["dropped"],
            "overflow": QUEUE_OVERFLOW,
        },
        "streaming": {
            "enabled": STREAMING_ENABLED,
            "mode": STREAMING_MODE,
            "detail": STREAMING_DETAIL,
        },
        "totals": totals,
        "sources": sources,
    }


def list_checkpoints(db: Session) -> list[dict[str, Any]]:
    """All stored checkpoints (server-written cursor state only)."""
    return [checkpoints.to_status(row) for row in checkpoints.list_all(db)]


def checkpoint_for(db: Session, source: str) -> dict[str, Any] | None:
    """One source's checkpoint, or ``None`` when no poll has succeeded."""
    return checkpoints.to_status(checkpoints.load(db, source))


__all__ = [
    "BoundedQueue",
    "IngestionError",
    "IngestionFailedError",
    "PIPELINE_STAGES",
    "QUEUE_OVERFLOW",
    "STREAMING_DETAIL",
    "STREAMING_ENABLED",
    "STREAMING_MODE",
    "SourceMetrics",
    "checkpoint_for",
    "list_checkpoints",
    "poll_source",
    "reset_runtime",
    "status",
]
