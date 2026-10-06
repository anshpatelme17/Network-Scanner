"""Pydantic schemas for security event ingestion (Step 3).

``EventIngest`` is the vendor-neutral envelope every source submits.
Enums are closed; string lengths match the columns (oversize is a 422,
never silent truncation); ``extra="forbid"`` blocks smuggled fields.
``raw_event`` must be a JSON object when present — never a string that
could be confused with code.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.event_enums import Severity, SourceType


class EventIngest(BaseModel):
    source_type: SourceType = Field(description="Controlled source vocabulary")
    source_name: str = Field(min_length=1, max_length=128, description="Sending sensor/tool name")
    event_type: str = Field(min_length=1, max_length=64)
    severity: Severity = Field(default=Severity.INFO)
    confidence: int | None = Field(
        default=None, ge=0, le=100, description="Source-supplied confidence; unknown stays null."
    )
    title: str = Field(min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=4000)
    event_time: datetime | None = Field(
        default=None, description="When the event happened (UTC assumed); defaults to now."
    )
    source_ip: str | None = Field(default=None, max_length=45)
    destination_ip: str | None = Field(default=None, max_length=45)
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=8)
    asset_id: str | None = Field(default=None, max_length=36)
    hostname: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=128)
    process_name: str | None = Field(default=None, max_length=255)
    action: str | None = Field(default=None, max_length=64)
    status: str | None = Field(default=None, max_length=32)
    raw_event: dict[str, Any] | None = Field(
        default=None, description="Original payload as JSON object; stored as data only."
    )
    correlation_key: str | None = Field(default=None, max_length=64)
    external_event_id: str | None = Field(
        default=None,
        max_length=255,
        description="Source-side ID enabling idempotent re-ingestion.",
    )

    model_config = {"extra": "forbid", "use_enum_values": True}


class EventResponse(BaseModel):
    id: str
    event_time: datetime
    received_at: datetime
    source_type: str
    source_name: str
    event_type: str
    severity: str
    title: str
    description: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    asset_id: str | None = None
    hostname: str | None = None
    username: str | None = None
    process_name: str | None = None
    action: str | None = None
    status: str | None = None
    confidence: int | None = None
    occurrence_count: int = 1
    last_seen_at: datetime | None = None
    ingest_mode: str = "FIXTURE"
    raw_event: dict[str, Any] | None = None
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    correlation_key: str | None = None
    fingerprint: str
    external_event_id: str | None = None
    created_at: datetime


class EventPage(BaseModel):
    items: list[EventResponse]
    total: int
    limit: int
    offset: int


class EventSummary(BaseModel):
    total_events: int
    critical_events: int
    high_events: int
    last_24h_events: int
