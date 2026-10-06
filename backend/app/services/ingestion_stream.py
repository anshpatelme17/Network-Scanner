"""Controlled streaming foundation (Step 28) — ARCHITECTURE ONLY, NOT ENABLED.

Step 28 ships the *shape* a future step would need for continuous
ingestion, and ships it inert:

- ``ConnectorStream`` — the protocol a source stream must satisfy
  (source-scoped, one-shot, closable, bounded by contract).
- ``BoundedPollStream`` — a concrete bounded iterator over one
  operator-initiated poll's records. Iteration is lazy and stops at the
  caller's bound; closing it discards the remainder. It is created from
  an already-fetched list: it never opens sockets, files, or URLs
  itself.
- ``PollWorker`` — a one-shot worker. ``run_once`` executes exactly one
  synchronous, audited, RBAC-gated poll and returns its result. The
  *background* activation (``start``) raises
  ``StreamingDisabledError``: no scheduler, thread, timer, daemon, or
  queue consumer exists anywhere in this codebase, and automatic
  streaming is deliberately not enabled in this step.

Enabled state lives in :mod:`app.services.ingestion` so status reporting
and this module cannot disagree. Nothing here runs on import.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from sqlalchemy.orm import Session

from app.services import ingestion
from app.services.ingestion import STREAMING_DETAIL, STREAMING_ENABLED, STREAMING_MODE

__all__ = [
    "BoundedPollStream",
    "ConnectorStream",
    "PollWorker",
    "StreamingDisabledError",
    "STREAMING_DETAIL",
    "STREAMING_ENABLED",
    "STREAMING_MODE",
]


class StreamingDisabledError(RuntimeError):
    """Background/continuous streaming is deliberately not enabled."""


@runtime_checkable
class ConnectorStream(Protocol):
    """Contract for a bounded, single-run connector stream."""

    source: str

    def __iter__(self) -> Iterator[dict]:
        """Yield already-normalized records, never beyond the bound."""
        ...

    def close(self) -> None:
        """Release any remaining items; safe to call twice."""
        ...


@dataclass
class BoundedPollStream:
    """Bounded, one-shot iterator over one poll's records (no I/O).

    ``max_items`` is a hard upper bound on yielded records; anything
    past the bound is dropped from the stream (and therefore never
    processed). ``closed`` streams yield nothing further.
    """

    source: str
    records: list[tuple[int, object]] = field(default_factory=list)
    max_items: int = 100
    closed: bool = False
    emitted: int = 0

    def __iter__(self) -> Iterator[dict]:
        if self.closed:
            return
        bound = max(0, int(self.max_items))
        for index, record in self.records:
            if self.emitted >= bound or self.closed:
                break
            self.emitted += 1
            yield {"index": index, "record": record}

    def close(self) -> None:
        self.closed = True
        self.records = []


@dataclass
class PollWorker:
    """One-shot ingestion worker for exactly one source.

    ``run_once`` is synchronous and returns the ordinary Step 28 poll
    result (bounded fetch, bounded queue, bounded batches, checkpoint,
    audits). It is invoked only from the RBAC-gated API handler — there
    is no code path that calls it automatically.
    """

    source: str
    enabled: bool = STREAMING_ENABLED

    def run_once(self, db: Session, actor: str, *, replay: bool = False) -> dict[str, object]:
        """Execute exactly one bounded poll now (synchronous)."""
        return ingestion.poll_source(db, self.source, actor, replay=replay)

    def start(self) -> None:
        """Background activation — always refused in this step."""
        raise StreamingDisabledError(
            "Continuous/background streaming is not enabled; polls are "
            "manual and operator-initiated only."
        )

    @property
    def status(self) -> dict[str, object]:
        """Worker view of the streaming activation state (never enabled)."""
        return {
            "enabled": STREAMING_ENABLED,
            "mode": STREAMING_MODE,
            "detail": STREAMING_DETAIL,
            "source": self.source,
        }
