"""Schemas for Suricata EVE ingestion (Step 4).

The request carries the declared source name plus the raw EVE object(s).
No flags, paths, commands, or rule-management fields exist — ingestion
only. Batch size is bounded at the schema level.
"""

from typing import Any

from pydantic import BaseModel, Field

from app.schemas.events import EventResponse

MAX_BATCH_EVENTS = 100


class SuricataIngestRequest(BaseModel):
    source_name: str = Field(
        default="suricata",
        min_length=1,
        max_length=128,
        description="Declared Suricata sensor/source name.",
    )
    event: dict[str, Any] = Field(description="One Suricata EVE JSON object.")

    model_config = {"extra": "forbid"}


class SuricataBatchRequest(BaseModel):
    source_name: str = Field(default="suricata", min_length=1, max_length=128)
    events: list[dict[str, Any]] = Field(
        min_length=1, max_length=MAX_BATCH_EVENTS, description="Up to 100 EVE objects."
    )

    model_config = {"extra": "forbid"}


class BatchItemError(BaseModel):
    index: int
    code: str
    message: str


class SuricataBatchResponse(BaseModel):
    accepted: int
    duplicates: int
    rejected: int
    errors: list[BatchItemError] = Field(default_factory=list)
    items: list[EventResponse] = Field(default_factory=list, description="Created/existing events.")
