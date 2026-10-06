"""Pydantic schemas for Step 28 ingestion observability.

Read-only shapes for the ingestion status/checkpoint endpoints. Every
field is server-computed counters, bounds, or cursor provenance —
configuration and secrets are never part of these responses, and no
field is ever client-writable.
"""

from pydantic import BaseModel, Field


class CheckpointStatus(BaseModel):
    """Server-written cursor state for one source (read-only)."""

    source: str
    cursor: dict[str, str | int | float | bool | None] | None = None
    last_event_time: str | None = None
    last_external_event_id: str | None = None
    advance_count: int = 0
    last_rejected_at: str | None = None
    updated_at: str | None = None
    created_at: str | None = None


class CheckpointPage(BaseModel):
    items: list[CheckpointStatus] = Field(default_factory=list)


class IngestionLimits(BaseModel):
    """Configured bounds governing one ingestion run."""

    max_pages: int
    max_events: int
    max_poll_lines: int
    batch_size: int
    queue_max: int
    retry_max: int
    timeout_seconds: float
    file_resume: bool


class IngestionQueueStatus(BaseModel):
    """Bounded-queue counters (overflow policy is deterministic)."""

    max: int
    depth: int
    enqueued_total: int
    dequeued_total: int
    dropped_total: int
    overflow: str


class IngestionStreamStatus(BaseModel):
    """Streaming activation state — never enabled in this step."""

    enabled: bool
    mode: str
    detail: str


class IngestionTotals(BaseModel):
    """Cross-source pipeline counters for this process."""

    fetched: int = 0
    normalized: int = 0
    accepted: int = 0
    deduplicated: int = 0
    rejected: int = 0
    failed: int = 0
    dropped: int = 0
    retries: int = 0
    batches: int = 0


class IngestionSourceStatus(BaseModel):
    """Per-source pipeline view: connector truth, counters, checkpoint."""

    source: str
    mode: str
    state: str
    connector_state: str
    last_poll_at: str | None = None
    last_success_at: str | None = None
    last_failure_at: str | None = None
    last_failure_reason: str | None = None
    events_fetched: int = 0
    events_normalized: int = 0
    events_accepted: int = 0
    events_deduplicated: int = 0
    events_rejected: int = 0
    events_failed: int = 0
    events_dropped: int = 0
    retries: int = 0
    batches: int = 0
    queue_depth: int = 0
    checkpoint: CheckpointStatus | None = None


class IngestionStatusResponse(BaseModel):
    """Full, safe ingestion observability payload (no network, no I/O)."""

    generated_at: str
    pipeline: list[str] = Field(default_factory=list)
    limits: IngestionLimits
    queue: IngestionQueueStatus
    streaming: IngestionStreamStatus
    totals: IngestionTotals
    sources: list[IngestionSourceStatus] = Field(default_factory=list)


__all__ = [
    "CheckpointPage",
    "CheckpointStatus",
    "IngestionLimits",
    "IngestionQueueStatus",
    "IngestionSourceStatus",
    "IngestionStatusResponse",
    "IngestionStreamStatus",
    "IngestionTotals",
]
