"""Zeek event adapter (Step 5).

Maps ONE Zeek-style structured event into the vendor-neutral ingest
envelope consumed by the existing ``event_service`` pipeline, following
the ``suricata_adapter`` pattern. Vendor-specific parsing stays isolated
here; the canonical layer never sees Zeek field names.

Platform contract (documented): raw Zeek logs do not self-identify, so
each submitted record must carry an explicit ``event_type`` naming the
source Zeek log (``conn``, ``dns``, ``http``, ``ssl``, ``x509``, ``ssh``,
``notice``). Supported types map to ``ZEEK_<TYPE>``; any other *string*
type is accepted as ``ZEEK_UNKNOWN`` (never a crash, never silently
dropped). A missing/non-string ``event_type`` is rejected as malformed.

Design decisions:

- ``ts`` may be epoch seconds (int/float, Zeek's native form) or an ISO
  string; unparseable/missing timestamps default to now (documented) so a
  missing clock never loses the observation.
- Addresses accept both ``id.orig_h``/``id.resp_h`` (conn-style logs) and
  ``src``/``dst`` (notice-style). Ports likewise (``id.orig_p``/``id.resp_p``,
  else ``src_p``/``dst_p``). Absent network fields stay NULL — never faked.
- Severity: Zeek has no universal severity model. Only an explicitly
  supplied integer ``severity`` in 1..4 is mapped (1→CRITICAL, 2→HIGH,
  3→MEDIUM, 4→LOW, the documented platform table); everything else uses
  the platform default INFO. Nothing is invented.
- ``source_name`` is caller-declared (default ``"zeek"``) — never a fake
  sensor hostname.
- ``external_event_id`` is deterministic:
  ``zeek:<sha256(event_type|uid|ts|addrs|ports)>``. Without a ``uid`` the
  hash covers the stable canonical content instead. Never ingest time.
  The Step 3 triple deduplicates replays.
- All values are DATA: copied into strings/JSON only. No execution,
  evaluation, imports, shells, file or network access — no code path here
  could do so.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

SUPPORTED_ZEEK_TYPES = ("conn", "dns", "http", "ssl", "x509", "ssh", "notice")

DEFAULT_SOURCE_NAME = "zeek"

# Explicit integer severity only (1 = highest); see module docstring.
SEVERITY_MAP = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}


class ZeekAdapterError(ValueError):
    """A Zeek record cannot be adapted (structural problem)."""


def _str(value: object, limit: int = 255) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, str | int | float):
        text = " ".join(str(value).split())
        return text[:limit] or None
    return None


def _int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and 0 <= value <= 65535:
        return value
    if isinstance(value, float) and value.is_integer() and 0 <= value <= 65535:
        return int(value)
    return None


def _parse_time(value: object) -> datetime | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        if value < 0 or value > 4102444800:  # sanity: 1970..2100
            return None
        return datetime.fromtimestamp(value, tz=UTC).replace(tzinfo=None)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is not None:
            return parsed.astimezone(UTC).replace(tzinfo=None)
        return parsed
    return None


def _first_present(record: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in record and record[key] is not None:
            return record[key]
    return None


def _byte_count(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and 0 <= value <= 2**63:
        return value
    return None


def _severity_for(record: dict[str, Any]) -> str:
    raw = record.get("severity")
    number: int | None = None
    if isinstance(raw, int) and not isinstance(raw, bool):
        number = raw
    elif isinstance(raw, str) and raw.strip().isdigit():
        number = int(raw.strip())
    if number in SEVERITY_MAP:
        return SEVERITY_MAP[number]
    return "INFO"


def _external_id(zeek_type: str, record: dict[str, Any], timestamp: str | None) -> str:
    stable = [
        zeek_type,
        _str(record.get("uid"), 128),
        timestamp,
        _str(_first_present(record, "id.orig_h", "src"), 45),
        _str(_first_present(record, "id.resp_h", "dst"), 45),
        _str(_first_present(record, "id.orig_p", "src_p"), 8),
        _str(_first_present(record, "id.resp_p", "dst_p"), 8),
    ]
    if stable[1] is None:
        # No stable UID: hash the stable canonical content instead.
        stable.append(_str(json.dumps(record, sort_keys=True, default=str), 4000))
    digest = hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()[:32]
    return f"zeek:{digest}"


def _bounded_subobject(
    record: dict[str, Any], key: str, limit_keys: int = 40
) -> dict[str, Any] | None:
    value = record.get(key)
    if not isinstance(value, dict):
        return None
    return {str(item_key)[:64]: item for item_key, item in list(value.items())[:limit_keys]}


def adapt_zeek_event(record: object, source_name: str = DEFAULT_SOURCE_NAME) -> dict[str, Any]:
    """Adapt one Zeek record into the generic ingest envelope.

    Raises :class:`ZeekAdapterError` for non-objects or missing/non-string
    ``event_type``.
    """
    if not isinstance(record, dict):
        raise ZeekAdapterError("Zeek event must be a JSON object.")
    raw_type = record.get("event_type")
    if not isinstance(raw_type, str) or not raw_type.strip():
        raise ZeekAdapterError("Zeek event is missing a usable 'event_type' (conn, dns, ...).")
    zeek_type = raw_type.strip().lower()

    canonical_type = (
        f"ZEEK_{zeek_type.upper()}" if zeek_type in SUPPORTED_ZEEK_TYPES else "ZEEK_UNKNOWN"
    )
    timestamp = _str(record.get("ts"), 64)
    severity = _severity_for(record)

    src_ip = _str(_first_present(record, "id.orig_h", "src"), 45)
    dest_ip = _str(_first_present(record, "id.resp_h", "dst"), 45)
    src_port = _int(_first_present(record, "id.orig_p", "src_p"))
    dest_port = _int(_first_present(record, "id.resp_p", "dst_p"))
    protocol = _str(record.get("proto"), 8)
    if protocol is not None:
        protocol = protocol.lower()

    if zeek_type == "notice":
        note = _str(record.get("note"), 256)
        msg = _str(record.get("msg"), 512)
        title = f"Zeek notice: {note}" if note else "Zeek notice"
        description = msg
    elif zeek_type == "conn":
        service = _str(record.get("service"), 64)
        state = _str(record.get("conn_state"), 32)
        title = f"Zeek conn {src_ip or '?'} → {dest_ip or '?'}"
        description = f"service={service} state={state}" if service or state else None
    elif zeek_type in ("http", "dns", "ssl", "x509", "ssh"):
        title = f"Zeek {zeek_type} event ({src_ip or '?'} → {dest_ip or '?'})"
        description = None
    else:
        title = f"Zeek {zeek_type} event ({src_ip or '?'} → {dest_ip or '?'})"
        description = None

    action: str | None = None
    if zeek_type == "http":
        action = _str(record.get("method"), 64)
    elif zeek_type == "notice":
        action = _str(record.get("actions"), 64)

    vendor: dict[str, Any] = {
        "zeek_type": zeek_type,
        "uid": _str(record.get("uid"), 128),
        "service": _str(record.get("service"), 64),
        "duration": record.get("duration")
        if isinstance(record.get("duration"), int | float)
        else None,
        "orig_bytes": _byte_count(record.get("orig_bytes")),
        "resp_bytes": _byte_count(record.get("resp_bytes")),
        "conn_state": _str(record.get("conn_state"), 32),
    }
    for key in (
        "query",
        "answers",
        "qtype",
        "uri",
        "status_code",
        "user_agent",
        "server",
        "version",
        "note",
        "msg",
        "src",
        "dst",
        "certificate",
        "ja3",
    ):
        value = record.get(key)
        if isinstance(value, dict):
            nested = _bounded_subobject(record, key)
            if nested is not None:
                vendor[key] = nested
        elif isinstance(value, str | int | float | bool | list) and value != []:
            vendor[key] = _str(value, 512) if not isinstance(value, list) else value[:20]

    return {
        "source_type": "ZEEK",
        "source_name": source_name,
        "event_type": canonical_type,
        "severity": severity,
        "title": title,
        "description": description,
        "event_time": _parse_time(record.get("ts")),
        "source_ip": src_ip,
        "destination_ip": dest_ip,
        "source_port": src_port,
        "destination_port": dest_port,
        "protocol": protocol,
        "hostname": _str(record.get("host"), 255),
        "action": action,
        "status": None,
        "raw_event": record,
        "correlation_key": _str(record.get("uid"), 64),
        "external_event_id": _external_id(zeek_type, record, timestamp),
        "normalized_extras": vendor,
    }
