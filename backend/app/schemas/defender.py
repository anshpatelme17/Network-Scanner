"""Schemas for Defender event ingestion (Step 7).

Mirrors the Suricata/Zeek/Wazuh ingest schemas: declared source name
plus the raw record(s). No credentials, tenant IDs, client secrets, or
management fields — ingestion of synthetic/local records only. Batch
size bounded at the schema level (same limit).
"""

from typing import Any

from pydantic import BaseModel, Field

from app.schemas.events import EventResponse
from app.schemas.suricata import BatchItemError

MAX_BATCH_EVENTS = 100


class DefenderIngestRequest(BaseModel):
    source_name: str = Field(
        default="defender",
        min_length=1,
        max_length=128,
        description="Declared Defender source name.",
    )
    event: dict[str, Any] = Field(description="One Defender-style record.")

    model_config = {"extra": "forbid"}


class DefenderBatchRequest(BaseModel):
    source_name: str = Field(default="defender", min_length=1, max_length=128)
    events: list[dict[str, Any]] = Field(
        min_length=1, max_length=MAX_BATCH_EVENTS, description="Up to 100 Defender records."
    )

    model_config = {"extra": "forbid"}


class DefenderBatchResponse(BaseModel):
    accepted: int
    duplicates: int
    rejected: int
    errors: list[BatchItemError] = Field(default_factory=list)
    items: list[EventResponse] = Field(default_factory=list)
