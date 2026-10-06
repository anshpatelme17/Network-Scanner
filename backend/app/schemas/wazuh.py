"""Schemas for Wazuh event ingestion (Step 6).

Mirrors the Suricata/Zeek ingest schemas: declared source name plus the
raw record(s). No flags, paths, commands, or management fields —
ingestion only. Batch size bounded at the schema level (same limit).
"""

from typing import Any

from pydantic import BaseModel, Field

from app.schemas.events import EventResponse
from app.schemas.suricata import BatchItemError

MAX_BATCH_EVENTS = 100


class WazuhIngestRequest(BaseModel):
    source_name: str = Field(
        default="wazuh",
        min_length=1,
        max_length=128,
        description="Declared Wazuh manager/source name.",
    )
    event: dict[str, Any] = Field(description="One Wazuh-style alert object.")

    model_config = {"extra": "forbid"}


class WazuhBatchRequest(BaseModel):
    source_name: str = Field(default="wazuh", min_length=1, max_length=128)
    events: list[dict[str, Any]] = Field(
        min_length=1, max_length=MAX_BATCH_EVENTS, description="Up to 100 Wazuh alerts."
    )

    model_config = {"extra": "forbid"}


class WazuhBatchResponse(BaseModel):
    accepted: int
    duplicates: int
    rejected: int
    errors: list[BatchItemError] = Field(default_factory=list)
    items: list[EventResponse] = Field(default_factory=list)
