"""Pydantic schemas for live event connectors (Steps 26–28).

Status responses carry presence booleans for sensitive configuration —
never secret values — plus the Step 27 runtime health fields
(connector state, last check/poll, error category, retrieved count,
latency). Poll results mirror the bounded-batch shape used by the
fixture ingest endpoints, the API pagination provenance
(pages/retrieved/termination), and the Step 28 ingestion provenance
(batches executed, backpressure drops, checkpoint movement). The
server-built checkpoint cursor is internal to the pipeline and is
deliberately never part of the response model.
"""

from pydantic import BaseModel, Field


class PollHealthResponse(BaseModel):
    """Safe polling metadata for one connector (Phase 2 Step 5).

    Every field is a timestamp, a count, a bounded duration or a stable
    category label. No credential, token or secret is representable here.
    """

    last_poll_started_at: str | None = None
    last_poll_completed_at: str | None = None
    last_successful_poll_at: str | None = None
    last_error_category: str | None = None
    events_received: int = 0
    events_accepted: int = 0
    events_deduplicated: int = 0
    next_permitted_poll_at: str | None = None
    in_flight: bool = False
    polls: int = 0
    failures: int = 0


class ConnectorStatusResponse(BaseModel):
    source: str
    mode: str
    state: str
    detail: str
    configured: dict[str, bool] = Field(default_factory=dict)
    last_success_at: str | None = None
    # Step 27: richer live vocabulary + runtime health (all optional so
    # older consumers keep working).
    connector_state: str = "NOT_CONFIGURED"
    last_check_at: str | None = None
    last_poll_at: str | None = None
    last_error_category: str | None = None
    events_retrieved: int = 0
    latency_ms: int | None = None
    # Phase 2 Step 5: safe polling metadata. Optional and default-constructible
    # so older consumers keep working. Contains no secret by construction.
    polling: PollHealthResponse = Field(default_factory=PollHealthResponse)


class ConnectorsPage(BaseModel):
    items: list[ConnectorStatusResponse]


class PollError(BaseModel):
    index: int
    code: str
    message: str


class PollResult(BaseModel):
    source: str
    accepted: int
    duplicates: int
    rejected: int
    truncated: bool
    errors: list[PollError] = Field(default_factory=list)
    # Step 27: bounded-API-poll provenance (file polls report 1 page).
    pages: int = 0
    retrieved: int = 0
    termination: str | None = None
    # Step 28: pipeline provenance (always reported, never secret).
    batches: int = 0
    # Phase 2 Step 6: records that produced a canonical event (accepted +
    # deduplicated), so received/normalized/accepted/rejected/duplicated are
    # each distinguishable. Additive; defaults keep older clients working.
    normalized: int = 0
    queue_dropped: int = 0
    checkpoint_advanced: bool = False
