"""Static server-side telemetry adapter registry (Step 23).

Maps a source key to its parsing entry point. The server — never the
client — selects the adapter: each ingest endpoint resolves its own
fixed key, and unknown keys raise ``KeyError`` (mapped to a structured
422). No dynamic imports, no client-influenceable selection.

Every registered adapter is FIXTURE-grade in Step 23: each parses
operator-supplied test/fixture payloads only. No live sensor
connections exist anywhere; ``mode`` documents that truthfully and
backs the FIXTURE badges in API responses and the UI.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.services.defender_adapter import DefenderAdapterError, adapt_defender_event
from app.services.suricata_adapter import SuricataAdapterError, adapt_eve_event
from app.services.wazuh_adapter import WazuhAdapterError, adapt_wazuh_event
from app.services.zeek_adapter import ZeekAdapterError, adapt_zeek_event

FIXTURE_MODE = "FIXTURE"


@dataclass(frozen=True)
class AdapterRegistration:
    """One allowlisted telemetry source (Step 23)."""

    key: str
    source_type: str
    mode: str
    description: str
    adapt: Callable[[object, str], dict[str, Any]]
    error: type[ValueError]


ADAPTERS: dict[str, AdapterRegistration] = {
    "suricata": AdapterRegistration(
        key="suricata",
        source_type="SURICATA",
        mode=FIXTURE_MODE,
        description="Suricata EVE JSON fixture objects (alert/flow/dns/http/tls/fileinfo).",
        adapt=adapt_eve_event,
        error=SuricataAdapterError,
    ),
    "zeek": AdapterRegistration(
        key="zeek",
        source_type="ZEEK",
        mode=FIXTURE_MODE,
        description="Zeek log fixture objects (conn/dns/http/ssl/x509/notice, ...).",
        adapt=adapt_zeek_event,
        error=ZeekAdapterError,
    ),
    "wazuh": AdapterRegistration(
        key="wazuh",
        source_type="WAZUH",
        mode=FIXTURE_MODE,
        description="Wazuh alert fixture objects (rule/agent/network context).",
        adapt=adapt_wazuh_event,
        error=WazuhAdapterError,
    ),
    "defender": AdapterRegistration(
        key="defender",
        source_type="DEFENDER",
        mode=FIXTURE_MODE,
        description="Defender telemetry fixture objects (alert/device/process/file).",
        adapt=adapt_defender_event,
        error=DefenderAdapterError,
    ),
}


def resolve_adapter(key: str) -> AdapterRegistration:
    """Return the registration for a source key or raise KeyError."""
    return ADAPTERS[key]


def describe_adapters() -> list[dict[str, str]]:
    """Stable adapter catalog for docs and UI (no client input)."""
    return [
        {
            "key": registration.key,
            "source_type": registration.source_type,
            "mode": registration.mode,
            "description": registration.description,
        }
        for registration in sorted(ADAPTERS.values(), key=lambda item: item.key)
    ]


__all__ = [
    "ADAPTERS",
    "FIXTURE_MODE",
    "AdapterRegistration",
    "describe_adapters",
    "resolve_adapter",
]
