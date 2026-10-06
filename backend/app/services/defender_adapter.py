"""Microsoft Defender / Windows telemetry adapter (Step 7).

Maps ONE Defender-style record into the vendor-neutral ingest envelope
consumed by the existing ``event_service`` pipeline, following the
``suricata_adapter`` / ``zeek_adapter`` / ``wazuh_adapter`` pattern.
Vendor-specific parsing stays isolated here; the canonical layer never
sees Defender field names. No live Defender connectivity exists —
synthetic/local records only, by design.

Platform contract (documented): each submitted record must declare an
explicit ``event_type`` naming the Defender category (``alert``,
``incident``, ``malware``, ``authentication``, ``device``, ``process``).
Raw Defender exports do not self-categorize, and the platform never
guesses. Supported types map to ``DEFENDER_*``; any other *string* type
is accepted as ``DEFENDER_UNKNOWN`` (never a crash, never silently
dropped). A missing/non-string ``event_type`` is rejected.

Design decisions:

- Timestamps: ``timestamp`` or ``eventTime``; ISO-8601 (with offsets),
  epoch seconds, or epoch milliseconds (values > 1e12). Unparseable or
  missing timestamps fall back to current UTC (documented) so a missing
  clock never loses the observation. Never ingest time as identity.
- ``source_name`` is caller-declared (default ``"defender"``) — never
  fake tenant/sensor credentials (none are required or accepted).
- Severity: textual (case-insensitive) critical→CRITICAL, high→HIGH,
  medium→MEDIUM, low→LOW, informational/info→INFO; numeric 0–100 scores
  map >=80→CRITICAL, >=50→HIGH, >=20→MEDIUM, >=1→LOW, 0→INFO;
  missing/malformed/unknown → INFO. Never derived from title/description
  wording. Central constants below.
- Title: ``title``/``name`` → ``description`` → ``threatName`` →
  generic fallback. ``description`` carries the next-best text when it
  differs from the title.
- Network: ``sourceIp``/``destinationIp`` (plus ``src_ip``/``srcip`` and
  ``dst_ip``/``dstip`` spellings), ports likewise. Absent → NULL.
- Device/user/process/file/threat detail → namespaced ``normalized_data``
  sections; the full record → ``raw_event`` untouched.
- ``external_event_id`` is deterministic:
  ``defender:<sha256(type|alert_id|timestamp)>``, content-hash fallback
  without stable parts. The Step 3 triple deduplicates replays.
- All values are DATA: copied into strings/JSON only. No execution of
  command lines, PowerShell, URLs, files, imports, or evaluation — no
  code path here could do so, and no remediation action is ever taken.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

SUPPORTED_DEFENDER_TYPES = (
    "alert",
    "incident",
    "malware",
    "authentication",
    "device",
    "process",
)

DEFAULT_SOURCE_NAME = "defender"

TEXT_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "informational": "INFO",
    "info": "INFO",
}

# Numeric severity scores are 0–100 (documented, inclusive bounds).
NUMERIC_CRITICAL_MIN = 80
NUMERIC_HIGH_MIN = 50
NUMERIC_MEDIUM_MIN = 20
NUMERIC_LOW_MIN = 1


class DefenderAdapterError(ValueError):
    """A Defender record cannot be adapted (structural problem)."""


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


def _dict(value: object) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _first_present(record: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in record and record[key] is not None:
            return record[key]
    return None


def _utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _parse_time(value: object) -> datetime:
    """Parse ISO / epoch / epoch-millis; fall back to now when unusable."""
    if isinstance(value, bool):
        return _utcnow_naive()
    if isinstance(value, int | float):
        epoch = float(value)
        if epoch > 1e12:  # epoch milliseconds
            epoch /= 1000.0
        if 0 <= epoch <= 4102444800:  # sanity: 1970..2100
            return datetime.fromtimestamp(epoch, tz=UTC).replace(tzinfo=None)
        return _utcnow_naive()
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return _utcnow_naive()
        if parsed.tzinfo is not None:
            return parsed.astimezone(UTC).replace(tzinfo=None)
        return parsed
    return _utcnow_naive()


def _severity_for(record: dict[str, Any]) -> str:
    raw = record.get("severity")
    if isinstance(raw, bool):
        return "INFO"
    if isinstance(raw, str):
        mapped = TEXT_SEVERITY_MAP.get(raw.strip().lower())
        return mapped if mapped is not None else "INFO"
    if isinstance(raw, int | float):
        score = float(raw)
        if score >= NUMERIC_CRITICAL_MIN:
            return "CRITICAL"
        if score >= NUMERIC_HIGH_MIN:
            return "HIGH"
        if score >= NUMERIC_MEDIUM_MIN:
            return "MEDIUM"
        if score >= NUMERIC_LOW_MIN:
            return "LOW"
    return "INFO"


def _external_id(defender_type: str, record: dict[str, Any], timestamp: str | None) -> str:
    stable_id = _str(_first_present(record, "id", "alertId", "incidentId"), 128)
    stable = [defender_type, stable_id, timestamp]
    if stable_id is None:
        stable.append(_str(json.dumps(record, sort_keys=True, default=str), 4000))
    digest = hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()[:32]
    return f"defender:{digest}"


def _bounded(value: object, limit_keys: int = 40) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return {str(key)[:64]: item for key, item in list(value.items())[:limit_keys]}


def adapt_defender_event(record: object, source_name: str = DEFAULT_SOURCE_NAME) -> dict[str, Any]:
    """Adapt one Defender record into the generic ingest envelope.

    Raises :class:`DefenderAdapterError` for non-objects or
    missing/non-string ``event_type``.
    """
    if not isinstance(record, dict):
        raise DefenderAdapterError("Defender event must be a JSON object.")
    raw_type = record.get("event_type")
    if not isinstance(raw_type, str) or not raw_type.strip():
        raise DefenderAdapterError("Defender event is missing a usable 'event_type' (alert, ...).")
    defender_type = raw_type.strip().lower()

    canonical_type = (
        f"DEFENDER_{defender_type.upper()}"
        if defender_type in SUPPORTED_DEFENDER_TYPES
        else "DEFENDER_UNKNOWN"
    )
    timestamp = _str(_first_present(record, "timestamp", "eventTime"), 64)
    severity = _severity_for(record)

    title = (
        _str(_first_present(record, "title", "name"), 512)
        or _str(record.get("description"), 512)
        or _str(record.get("threatName"), 512)
        or "Defender security event"
    )
    description = _str(record.get("description"), 4000)
    if description == title:
        description = None

    src_ip = _str(_first_present(record, "sourceIp", "remoteIp", "src_ip", "srcip"), 45)
    dest_ip = _str(_first_present(record, "destinationIp", "dst_ip", "dstip"), 45)

    device_name = _str(_first_present(record, "deviceName", "machineName", "hostname"), 255)
    username = _str(_first_present(record, "user", "account", "accountName"), 128)
    process_name = _str(record.get("processName"), 255)

    vendor: dict[str, Any] = {
        "defender_type": defender_type,
        "device_id": _str(record.get("deviceId"), 128),
        "device_name": device_name,
        "alert_id": _str(_first_present(record, "id", "alertId"), 128),
        "incident_id": _str(record.get("incidentId"), 128),
        "threat_name": _str(record.get("threatName"), 256),
        "process_name": process_name,
        "process_id": _str(record.get("processId"), 64),
        "command_line": _str(record.get("commandLine"), 2000),
        "file_name": _str(record.get("fileName"), 512),
        "file_hash": _str(record.get("fileHash"), 256),
        "detection_source": _str(record.get("detectionSource"), 128),
        "remediation_status": _str(record.get("remediationStatus"), 64),
        "category": _str(record.get("category"), 128),
        "status": _str(record.get("status"), 32),
        "url": _str(_first_present(record, "url", "domain"), 512),
        "action": _str(record.get("action"), 64),
    }
    extra = _bounded(_first_present(record, "additionalFields", "extra"))
    if extra is not None:
        vendor["additional"] = extra

    return {
        "source_type": "DEFENDER",
        "source_name": source_name,
        "event_type": canonical_type,
        "severity": severity,
        "title": title,
        "description": description,
        "event_time": _parse_time(_first_present(record, "timestamp", "eventTime")),
        "source_ip": src_ip,
        "destination_ip": dest_ip,
        "source_port": _int(_first_present(record, "sourcePort", "src_port", "srcport")),
        "destination_port": _int(_first_present(record, "destinationPort", "dst_port", "dstport")),
        "protocol": None,
        "hostname": device_name,
        "username": username,
        "process_name": process_name,
        "action": _str(record.get("action"), 64),
        "status": _str(record.get("status"), 32),
        "raw_event": record,
        "correlation_key": _str(_first_present(record, "id", "alertId"), 64),
        "external_event_id": _external_id(defender_type, record, timestamp),
        "normalized_extras": vendor,
    }
