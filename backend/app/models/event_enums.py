"""Controlled vocabularies for security events (Step 3).

Severity and source type are closed allow-lists validated by Pydantic —
never arbitrary strings. ``SourceType`` values double as documented
extension points: each future integration (Suricata, Zeek, Wazuh, …)
will get its own *adapter* mapping vendor payloads into the canonical
``SecurityEvent``. No adapters exist yet.
"""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SourceType(str, Enum):
    NMAP = "NMAP"
    GENERIC = "GENERIC"
    WINDOWS = "WINDOWS"
    DEFENDER = "DEFENDER"
    SURICATA = "SURICATA"
    ZEEK = "ZEEK"
    WAZUH = "WAZUH"
    VULNERABILITY_SCANNER = "VULNERABILITY_SCANNER"
    FIREWALL = "FIREWALL"
