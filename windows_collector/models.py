"""Shared collector data models."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

COLLECTOR_NAME = "windows-event-collector"
COLLECTOR_VERSION = "0.1.0"


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class RawWindowsEvent:
    record_id: int
    event_id: int
    channel: str
    event_time: str
    provider: str | None = None
    level: int | None = None
    task: int | None = None
    opcode: int | None = None
    keywords: str | None = None
    computer: str | None = None
    user_id: str | None = None
    event_data: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SourceBatch:
    events: tuple[RawWindowsEvent, ...]
    newest_record_id: int | None
    reset_detected: bool = False


@dataclass
class CollectionStatus:
    channel: str
    source_available: bool | None = None
    authenticated: bool | None = None
    last_source_read_at: str | None = None
    last_upload_success_at: str | None = None
    last_error: str | None = None
    last_error_at: str | None = None
    events_read: int = 0
    events_uploaded: int = 0
    events_duplicate: int = 0
    checkpoint: int = 0
    checkpoint_reset: bool = False

    @property
    def ok(self) -> bool:
        return self.last_error is None

    def record_error(self, message: str) -> None:
        self.last_error = message
        self.last_error_at = utc_now_iso()

    def clear_error(self) -> None:
        self.last_error = None
        self.last_error_at = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "collector_name": COLLECTOR_NAME,
            "collector_version": COLLECTOR_VERSION,
            "ok": self.ok,
            "channel": self.channel,
            "source_available": self.source_available,
            "authenticated": self.authenticated,
            "last_source_read_at": self.last_source_read_at,
            "last_upload_success_at": self.last_upload_success_at,
            "last_error": self.last_error,
            "last_error_at": self.last_error_at,
            "events_read": self.events_read,
            "events_uploaded": self.events_uploaded,
            "events_duplicate": self.events_duplicate,
            "checkpoint": self.checkpoint,
            "checkpoint_reset": self.checkpoint_reset,
        }
