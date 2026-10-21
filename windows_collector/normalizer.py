"""Map Windows event records to the backend-neutral ingestion envelope."""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import UTC, datetime
from typing import Any

from .errors import NormalizationError
from .models import COLLECTOR_NAME, COLLECTOR_VERSION, RawWindowsEvent

_LEVEL_SEVERITY = {
    1: "CRITICAL",
    2: "HIGH",
    3: "MEDIUM",
    4: "LOW",
    5: "INFO",
}


def _clip(value: str, limit: int) -> str:
    return value[:limit]


def _clean(value: object, limit: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return _clip(text, limit) if text else None


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NormalizationError("Windows event has an invalid timestamp.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _source_ip(event_data: dict[str, str]) -> str | None:
    candidate = event_data.get("IpAddress") or event_data.get("SourceIp")
    if not candidate:
        return None
    try:
        value = str(ipaddress.ip_address(candidate))
    except ValueError:
        return None
    return value if len(value) <= 45 else None


def _source_port(event_data: dict[str, str]) -> int | None:
    candidate = event_data.get("IpPort")
    if candidate is None:
        return None
    try:
        port = int(candidate)
    except ValueError:
        return None
    return port if 0 <= port <= 65535 else None


def _external_event_id(event: RawWindowsEvent) -> str:
    identity = f"{event.channel}\x1f{event.record_id}\x1f{event.event_time}"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    value = f"windows:{event.channel}:{event.record_id}:{digest}"
    if len(value) <= 255:
        return value
    full_digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return f"windows:sha256:{full_digest}"


def _title(event: RawWindowsEvent) -> str:
    provider = (event.provider or "Windows").strip() or "Windows"
    hostname = (event.computer or "unknown host").strip() or "unknown host"
    return _clip(f"{provider} event {event.event_id} on {hostname}", 512)


def _description(event: RawWindowsEvent) -> str:
    parts = [
        f"Channel: {event.channel}",
        f"Record ID: {event.record_id}",
        f"Event ID: {event.event_id}",
        f"Provider: {event.provider or 'unknown'}",
        f"Level: {event.level if event.level is not None else 'unknown'}",
    ]
    if event.task is not None:
        parts.append(f"Task: {event.task}")
    if event.opcode is not None:
        parts.append(f"Opcode: {event.opcode}")
    if event.keywords:
        parts.append(f"Keywords: {event.keywords}")
    return _clip("\n".join(parts), 4000)


def _raw_event(event: RawWindowsEvent) -> dict[str, Any]:
    event_data = event.event_data if isinstance(event.event_data, dict) else {}
    safe_data = {str(key): str(value)[:512] for key, value in list(event_data.items())[:32]}
    return {
        "collector": COLLECTOR_NAME,
        "collector_version": COLLECTOR_VERSION,
        "provenance": "windows_event_log",
        "channel": event.channel,
        "record_id": event.record_id,
        "event_id": event.event_id,
        "provider": event.provider,
        "level": event.level,
        "task": event.task,
        "opcode": event.opcode,
        "keywords": event.keywords,
        "computer": event.computer,
        "user_id": event.user_id,
        "event_data": safe_data,
    }


def normalize_event(event: RawWindowsEvent, source_name: str) -> dict[str, Any]:
    if not isinstance(event, RawWindowsEvent):
        raise NormalizationError("Windows event type is invalid.")
    if not isinstance(event.record_id, int) or isinstance(event.record_id, bool):
        raise NormalizationError("Windows event identifiers are invalid.")
    if not isinstance(event.event_id, int) or isinstance(event.event_id, bool):
        raise NormalizationError("Windows event identifiers are invalid.")
    if event.record_id < 0 or event.event_id < 0:
        raise NormalizationError("Windows event identifiers are invalid.")
    if not event.channel.strip():
        raise NormalizationError("Windows event channel is missing.")
    if not isinstance(event.event_time, str):
        raise NormalizationError("Windows event has an invalid timestamp.")
    if not source_name.strip():
        raise NormalizationError("Collector source name is missing.")
    if len(source_name) > 128:
        raise NormalizationError("Collector source name is too long.")
    event_time = _parse_time(event.event_time)
    event_data = event.event_data if isinstance(event.event_data, dict) else {}
    payload: dict[str, Any] = {
        "source_type": "WINDOWS",
        "source_name": source_name,
        "event_type": f"WINDOWS_EVENT_{event.event_id}",
        "severity": _LEVEL_SEVERITY.get(event.level, "INFO"),
        "title": _title(event),
        "description": _description(event),
        "event_time": event_time.isoformat().replace("+00:00", "Z"),
        "raw_event": _raw_event(event),
        "external_event_id": _external_event_id(event),
    }
    hostname = _clean(event.computer, 255)
    username = _clean(event_data.get("TargetUserName"), 128)
    if username is None:
        username = _clean(event_data.get("SubjectUserName"), 128)
    process_name = _clean(
        event_data.get("Image")
        or event_data.get("NewProcessName")
        or event_data.get("ProcessName"),
        255,
    )
    source_ip = _source_ip(event_data)
    source_port = _source_port(event_data)
    optional = {
        "hostname": hostname,
        "username": username,
        "process_name": process_name,
        "source_ip": source_ip,
        "source_port": source_port,
    }
    payload.update({key: value for key, value in optional.items() if value is not None})
    return payload


__all__ = ["normalize_event"]
