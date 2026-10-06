"""Wazuh alert adapter (Step 6).

Maps ONE Wazuh-style alert object into the vendor-neutral ingest envelope
consumed by the existing ``event_service`` pipeline, following the
``suricata_adapter`` / ``zeek_adapter`` pattern. Vendor-specific parsing
stays isolated here; the canonical layer never sees Wazuh field names.

Platform contract (documented): each submitted record must declare an
explicit ``event_type`` naming the Wazuh category (``alert``, ``fim``,
``auth``, ``syscheck``, ``sca``, ``vulnerability``, ``rootcheck``,
``command``). Raw Wazuh manager output does not self-categorize, and the
platform never guesses. Supported types map to ``WAZUH_*``; any other
*string* type is accepted as ``WAZUH_UNKNOWN`` (never a crash, never
silently dropped). A missing/non-string ``event_type`` is rejected.

Design decisions:

- Timestamps: ``timestamp`` or ``@timestamp``; ISO-8601 (with offsets),
  epoch seconds, or epoch milliseconds (values > 1e12). Unparseable or
  missing timestamps fall back to current UTC (documented) so a missing
  clock never loses the observation. Never ingest time as identity.
- ``source_name`` is caller-declared (default ``"wazuh"``) — never a fake
  manager hostname.
- Severity from numeric ``rule.level`` only: 12–16→CRITICAL,
  9–11→HIGH, 5–8→MEDIUM, 1–4→LOW (central ``*_MIN_LEVEL`` constants);
  missing/invalid/below-1 → INFO. Nothing invented from text.
- Title: ``rule.description`` → first line of ``full_log`` → decoder
  info → generic fallback. ``description`` carries ``full_log`` when it
  differs from the title.
- Network fields: ``data.srcip``/``data.dstip`` (fallback top-level
  ``srcip``/``dstip``) → canonical IP columns; ports likewise. Absent →
  NULL, never faked.
- Agent/manager/rule/decoder/FIM/vulnerability/auth detail → namespaced
  ``normalized_data`` sections; the full record → ``raw_event`` untouched.
- ``external_event_id`` is deterministic:
  ``wazuh:<sha256(type|alert_id|timestamp|agent.id|rule.id|addrs)>``,
  content-hash fallback without stable parts. The Step 3 triple
  deduplicates replays.
- All values are DATA: copied into strings/JSON only. No execution,
  evaluation, imports, shells, file or network access — no code path here
  could do so.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

SUPPORTED_WAZUH_TYPES = (
    "alert",
    "fim",
    "auth",
    "syscheck",
    "sca",
    "vulnerability",
    "rootcheck",
    "command",
)

DEFAULT_SOURCE_NAME = "wazuh"

# Central severity thresholds on numeric rule.level (inclusive bounds).
# CRITICAL covers 12–16; anything above the known maximum is treated as
# at least as severe.
CRITICAL_MIN_LEVEL = 12
CRITICAL_MAX_LEVEL = 16
HIGH_MIN_LEVEL = 9
MEDIUM_MIN_LEVEL = 5
LOW_MIN_LEVEL = 1


class WazuhAdapterError(ValueError):
    """A Wazuh record cannot be adapted (structural problem)."""


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


def _severity_for(rule: dict[str, Any] | None) -> str:
    level: int | None = None
    if rule is not None:
        raw = rule.get("level")
        if isinstance(raw, int) and not isinstance(raw, bool):
            level = raw
        elif isinstance(raw, str) and raw.strip().isdigit():
            level = int(raw.strip())
    if level is None or level < LOW_MIN_LEVEL:
        return "INFO"
    if level >= CRITICAL_MIN_LEVEL:
        # Documented 12–16 band; anything above the known maximum is
        # treated as at least as severe.
        return "CRITICAL"
    if level >= HIGH_MIN_LEVEL:
        return "HIGH"
    if level >= MEDIUM_MIN_LEVEL:
        return "MEDIUM"
    if level >= LOW_MIN_LEVEL:
        return "LOW"
    return "INFO"


def _external_id(wazuh_type: str, record: dict[str, Any], timestamp: str | None) -> str:
    agent = _dict(record.get("agent")) or {}
    rule = _dict(record.get("rule")) or {}
    stable = [
        wazuh_type,
        _str(record.get("id"), 64),
        timestamp,
        _str(agent.get("id"), 16),
        _str(rule.get("id"), 32),
        _str(_first_ip(record, "src"), 45),
        _str(_first_ip(record, "dst"), 45),
    ]
    if stable[1] is None and stable[3] is None and stable[4] is None:
        stable.append(_str(json.dumps(record, sort_keys=True, default=str), 4000))
    digest = hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()[:32]
    return f"wazuh:{digest}"


def _first_ip(record: dict[str, Any], direction: str) -> Any:
    data = _dict(record.get("data")) or {}
    if direction == "src":
        return data.get("srcip", record.get("srcip"))
    return data.get("dstip", record.get("dstip"))


def _first_port(record: dict[str, Any], direction: str) -> Any:
    data = _dict(record.get("data")) or {}
    if direction == "src":
        return data.get("srcport", record.get("srcport"))
    return data.get("dstport", record.get("dstport"))


def _first_present(data: dict[str, Any], *names: str) -> Any:
    """First key in ``names`` that is present and non-empty (Step 6)."""
    for name in names:
        value = data.get(name)
        if value is not None and value != "":
            return value
    return None


def _bounded(value: object, limit_keys: int = 40) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return {str(key)[:64]: item for key, item in list(value.items())[:limit_keys]}


def adapt_wazuh_event(record: object, source_name: str = DEFAULT_SOURCE_NAME) -> dict[str, Any]:
    """Adapt one Wazuh record into the generic ingest envelope.

    Raises :class:`WazuhAdapterError` for non-objects or missing/non-string
    ``event_type``.
    """
    if not isinstance(record, dict):
        raise WazuhAdapterError("Wazuh event must be a JSON object.")
    raw_type = record.get("event_type")
    if not isinstance(raw_type, str) or not raw_type.strip():
        raise WazuhAdapterError("Wazuh event is missing a usable 'event_type' (alert, fim, ...).")
    wazuh_type = raw_type.strip().lower()

    canonical_type = (
        f"WAZUH_{wazuh_type.upper()}" if wazuh_type in SUPPORTED_WAZUH_TYPES else "WAZUH_UNKNOWN"
    )
    timestamp = _str(record.get("timestamp", record.get("@timestamp")), 64)

    agent = _dict(record.get("agent")) or {}
    rule = _dict(record.get("rule")) or {}
    decoder = _dict(record.get("decoder")) or {}
    data = _dict(record.get("data")) or {}
    manager = _dict(record.get("manager")) or {}

    severity = _severity_for(rule)

    rule_description = _str(rule.get("description"), 512)
    full_log = _str(record.get("full_log"), 4000)
    decoder_name = _str(decoder.get("name"), 128)
    if rule_description is not None:
        title = rule_description
    elif full_log is not None:
        title = full_log.splitlines()[0][:512] if full_log.splitlines() else "Wazuh security event"
    elif decoder_name is not None:
        title = f"Wazuh event from decoder {decoder_name}"
    else:
        title = "Wazuh security event"
    description = full_log if full_log is not None and full_log != title else None

    src_ip = _str(_first_ip(record, "src"), 45)
    dest_ip = _str(_first_ip(record, "dst"), 45)
    # Phase 2 Step 6: map the same two canonical identity fields the
    # Defender adapter sets, so both vendor sources normalize identically
    # for correlation. Absent fields stay None - never inferred, never
    # defaulted. The full vendor values remain in the extras below.
    event_username = _str(_first_present(data, "uname", "srcuser", "dstuser", "user"), 128)
    event_process = _str(_first_present(data, "process_name", "cmdline", "program", "exe"), 255)

    fim = _dict(record.get("syscheck"))
    fim_section = None
    if fim is not None:
        fim_section = {
            "path": _str(fim.get("path"), 512),
            "event": _str(fim.get("event"), 32),
            "md5_after": _str(fim.get("md5_after"), 64),
            "sha256_after": _str(fim.get("sha256_after"), 128),
            "size_after": fim.get("size_after") if isinstance(fim.get("size_after"), int) else None,
        }
    vulnerability = _dict(record.get("vulnerability"))
    vulnerability_section = None
    if vulnerability is not None:
        vulnerability_section = {
            "id": _str(vulnerability.get("id"), 64),
            "severity": _str(vulnerability.get("severity"), 32),
            "package": _bounded(vulnerability.get("package")),
            "reference": _str(vulnerability.get("reference"), 512),
        }
    auth_section = None
    auth_keys = ("dstuser", "srcuser", "srcip", "action", "result", "program")
    present_auth = {key: data.get(key) for key in auth_keys if key in data}
    if wazuh_type == "auth" or present_auth:
        auth_section = {key: _str(value, 256) for key, value in present_auth.items()}

    vendor: dict[str, Any] = {
        "wazuh_type": wazuh_type,
        "agent": {
            "id": _str(agent.get("id"), 16),
            "name": _str(agent.get("name"), 128),
            "ip": _str(agent.get("ip"), 45),
        },
        "manager": {"name": _str(manager.get("name"), 128)},
        "rule": {
            "id": _str(rule.get("id"), 32),
            "level": rule.get("level"),
            "description": rule_description,
            "groups": rule.get("groups") if isinstance(rule.get("groups"), list) else None,
            "mitre": _bounded(rule.get("mitre")),
        },
        "decoder": {"name": decoder_name, "parent": _str(decoder.get("parent"), 128)},
        "location": _str(record.get("location"), 256),
        "source": _str(record.get("location"), 256),
        "full_log": full_log,
        "ports": {
            "srcport": _int(_first_port(record, "src")),
            "dstport": _int(_first_port(record, "dst")),
        },
        "fim": fim_section,
        "vulnerability": vulnerability_section,
        "authentication": auth_section,
    }

    return {
        "source_type": "WAZUH",
        "source_name": source_name,
        "event_type": canonical_type,
        "severity": severity,
        "title": title,
        "description": description,
        "event_time": _parse_time(record.get("timestamp", record.get("@timestamp"))),
        "source_ip": src_ip,
        "destination_ip": dest_ip,
        "source_port": _int(_first_port(record, "src")),
        "destination_port": _int(_first_port(record, "dst")),
        "protocol": None,
        "hostname": _str(agent.get("name"), 255),
        "username": event_username,
        "process_name": event_process,
        "action": None,
        "status": None,
        "raw_event": record,
        "correlation_key": _str(record.get("id"), 64) or _str(agent.get("id"), 64),
        "external_event_id": _external_id(wazuh_type, record, timestamp),
        "normalized_extras": vendor,
    }
