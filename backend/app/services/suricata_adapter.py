"""Suricata EVE JSON adapter (Step 4).

Maps ONE Suricata EVE JSON object into the vendor-neutral ingest envelope
consumed by the existing ``event_service`` pipeline. Vendor-specific
parsing stays isolated here; nothing else in the codebase knows EVE
field names.

Design decisions (documented per spec):

- Supported types: ``alert``, ``dns``, ``http``, ``tls``, ``flow``,
  ``fileinfo`` → canonical ``SURICATA_<TYPE>``. Unknown ``event_type``
  values are **accepted** as ``SURICATA_UNKNOWN`` (never silently
  dropped, never a crash); a missing ``event_type`` is rejected as
  ``INVALID_EVE`` because identity cannot be established.
- Severity: Suricata ``alert.severity`` 1→CRITICAL, 2→HIGH, 3→MEDIUM,
  4→LOW; absent/invalid/non-alert events use the platform default INFO.
  No new severity vocabulary is created.
- ``source_name`` is caller-declared (ingest request), default
  ``"suricata"`` — a declared default, never a fake sensor hostname.
- ``external_event_id`` is deterministic:
  ``suricata:<sha256(event_type|flow_id|timestamp|sig_id|sig_rev|addrs|ports)>``.
  Stable across replays, never based on ingest time. The Step 3
  ``(source_type, source_name, external_event_id)`` triple deduplicates.
- All EVE values are DATA: copied into strings/JSON only, never
  executed, evaluated, imported, or shelled — there is no code path here
  that could do so.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

SUPPORTED_EVE_TYPES = ("alert", "dns", "http", "tls", "flow", "fileinfo")

DEFAULT_SOURCE_NAME = "suricata"

# Suricata alert.severity (1 = highest) → canonical Severity.
SEVERITY_MAP = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}


class SuricataAdapterError(ValueError):
    """A single EVE object cannot be adapted (structural problem)."""


def _str(value: object, limit: int = 255) -> str | None:
    if not isinstance(value, str | int | float | bool):
        return None
    text = " ".join(str(value).split())
    return text[:limit] or None


def _int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and 0 <= value <= 65535:
        return value
    return None


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        return parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed


def _severity_for(eve_type: str, eve: dict[str, Any]) -> str:
    if eve_type == "alert":
        alert = eve.get("alert")
        if isinstance(alert, dict):
            raw = alert.get("severity")
            number = raw if isinstance(raw, int) and not isinstance(raw, bool) else None
            if number is None and isinstance(raw, str) and raw.strip().isdigit():
                number = int(raw.strip())
            if number in SEVERITY_MAP:
                return SEVERITY_MAP[number]
    return "INFO"


def _external_id(eve_type: str, eve: dict[str, Any], timestamp: str | None) -> str:
    alert = eve.get("alert") if isinstance(eve.get("alert"), dict) else {}
    parts = [
        eve_type,
        _str(eve.get("flow_id"), 64),
        timestamp,
        _str(alert.get("signature_id"), 32),
        _str(alert.get("rev"), 16),
        _str(alert.get("gid"), 16),
        _str(eve.get("src_ip"), 45),
        _str(eve.get("dest_ip"), 45),
        _str(eve.get("src_port"), 8),
        _str(eve.get("dest_port"), 8),
    ]
    digest = hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()[:32]
    return f"suricata:{digest}"


def _bounded_subobject(
    eve: dict[str, Any], key: str, limit_keys: int = 40
) -> dict[str, Any] | None:
    value = eve.get(key)
    if not isinstance(value, dict):
        return None
    items = list(value.items())[:limit_keys]
    return {str(key)[:64]: item for key, item in items}


def adapt_eve_event(eve: object, source_name: str = DEFAULT_SOURCE_NAME) -> dict[str, Any]:
    """Adapt one EVE JSON object into the generic ingest envelope.

    Raises :class:`SuricataAdapterError` for non-objects, missing
    ``event_type``, or non-string ``event_type``.
    """
    if not isinstance(eve, dict):
        raise SuricataAdapterError("EVE event must be a JSON object.")
    raw_type = eve.get("event_type")
    if not isinstance(raw_type, str) or not raw_type.strip():
        raise SuricataAdapterError("EVE event is missing a usable 'event_type'.")
    eve_type = raw_type.strip().lower()

    canonical_type = (
        f"SURICATA_{eve_type.upper()}" if eve_type in SUPPORTED_EVE_TYPES else "SURICATA_UNKNOWN"
    )
    timestamp = _str(eve.get("timestamp"), 64)
    severity = _severity_for(eve_type, eve)

    src_ip = _str(eve.get("src_ip"), 45)
    dest_ip = _str(eve.get("dest_ip"), 45)
    src_port = _int(eve.get("src_port"))
    dest_port = _int(eve.get("dest_port"))
    protocol = _str(eve.get("proto"), 8)
    if protocol is not None:
        protocol = protocol.lower()

    alert = eve.get("alert") if isinstance(eve.get("alert"), dict) else None
    if alert is not None:
        signature = _str(alert.get("signature"), 512) or "Suricata alert"
        title = signature
        description = _str(alert.get("category"), 512)
    else:
        endpoints = f"{src_ip or '?'} → {dest_ip or '?'}"
        title = f"Suricata {eve_type} event ({endpoints})"
        description = None

    normalized_extras: dict[str, Any] = {
        "eve_event_type": eve_type,
        "app_proto": _str(eve.get("app_proto"), 32),
    }
    if alert is not None:
        normalized_extras["alert"] = {
            "signature": _str(alert.get("signature"), 512),
            "signature_id": _str(alert.get("signature_id"), 32),
            "rev": _str(alert.get("rev"), 16),
            "gid": _str(alert.get("gid"), 16),
            "category": _str(alert.get("category"), 128),
            "severity": alert.get("severity"),
            "action": _str(alert.get("action"), 32),
            "metadata": alert.get("metadata") if isinstance(alert.get("metadata"), dict) else None,
        }
    for key in ("http", "dns", "tls", "flow", "fileinfo"):
        subobject = _bounded_subobject(eve, key)
        if subobject is not None:
            normalized_extras[key] = subobject

    return {
        "source_type": "SURICATA",
        "source_name": source_name,
        "event_type": canonical_type,
        "severity": severity,
        "title": title,
        "description": description,
        "event_time": _parse_time(timestamp),
        "source_ip": src_ip,
        "destination_ip": dest_ip,
        "source_port": src_port,
        "destination_port": dest_port,
        "protocol": protocol,
        "hostname": _str(eve.get("host"), 255),
        "action": _str(alert.get("action"), 64) if alert is not None else None,
        "status": None,
        "raw_event": eve,
        "correlation_key": _str(eve.get("flow_id"), 64),
        "external_event_id": _external_id(eve_type, eve, timestamp),
        "normalized_extras": normalized_extras,
    }
