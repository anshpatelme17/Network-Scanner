"""Schemas for Zeek event ingestion (Step 5).

Mirrors the Suricata ingest schemas: declared source name plus the raw
record(s). No flags, paths, commands, or management fields — ingestion
only. Batch size bounded at the schema level (same limit as Suricata).
"""

from typing import Any

from pydantic import BaseModel, Field

from app.schemas.events import EventResponse
from app.schemas.suricata import BatchItemError

MAX_BATCH_EVENTS = 100


class ZeekIngestRequest(BaseModel):
    source_name: str = Field(
        default="zeek",
        min_length=1,
        max_length=128,
        description="Declared Zeek sensor/source name.",
    )
    event: dict[str, Any] = Field(description="One Zeek-style event object.")

    model_config = {"extra": "forbid"}


class ZeekBatchRequest(BaseModel):
    source_name: str = Field(default="zeek", min_length=1, max_length=128)
    events: list[dict[str, Any]] = Field(
        min_length=1, max_length=MAX_BATCH_EVENTS, description="Up to 100 Zeek events."
    )

    model_config = {"extra": "forbid"}


class ZeekBatchResponse(BaseModel):
    accepted: int
    duplicates: int
    rejected: int
    errors: list[BatchItemError] = Field(default_factory=list)
    items: list[EventResponse] = Field(default_factory=list)
