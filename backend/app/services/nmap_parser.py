"""Nmap XML output parser (Step 2).

Parses ONLY machine-readable ``-oX`` XML — never human-readable terminal
output. Every field is optional except the host address: missing
hostnames, MACs, OS data, or ports yield ``None``/empty values, and
malformed XML raises :class:`NmapParseError` (a controlled failure that
the scan service maps to a failed job, never a 500 with a traceback).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from xml.etree import ElementTree


class NmapParseError(ValueError):
    """Nmap output could not be parsed as XML."""


@dataclass
class ParsedService:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None


@dataclass
class ParsedHost:
    ip_address: str
    hostname: str | None = None
    mac_address: str | None = None
    operating_system: str | None = None
    state: str = "up"
    services: list[ParsedService] = field(default_factory=list)


def _text(value: str | None, limit: int = 255) -> str | None:
    if value is None:
        return None
    cleaned = " ".join(value.split())
    if not cleaned:
        return None
    return cleaned[:limit]


def _best_os_name(host_el: ElementTree.Element) -> str | None:
    best: str | None = None
    best_accuracy = -1
    for match in host_el.findall("./os/osmatch"):
        name = _text(match.get("name"))
        if name is None:
            continue
        try:
            accuracy = int(match.get("accuracy", "0"))
        except (TypeError, ValueError):
            accuracy = 0
        if accuracy > best_accuracy:
            best, best_accuracy = name, accuracy
    return best


def parse_nmap_xml(xml_text: str) -> list[ParsedHost]:
    """Parse Nmap ``-oX`` XML into normalized host records.

    Only hosts reported ``up`` are returned; ``down`` hosts carry no
    inventory value. Unusable port entries (missing/invalid port id) are
    skipped rather than failing the whole parse.
    """
    if not xml_text or not xml_text.strip():
        raise NmapParseError("Empty Nmap output.")
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        raise NmapParseError(f"Invalid Nmap XML: {exc}.") from None
    if root.tag != "nmaprun":
        raise NmapParseError("XML is not Nmap output (missing <nmaprun> root).")

    hosts: list[ParsedHost] = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        state = (status_el.get("state") if status_el is not None else "up") or "up"
        if state != "up":
            continue
        ip_address: str | None = None
        mac_address: str | None = None
        for addr_el in host_el.findall("address"):
            addr_type = (addr_el.get("addrtype") or "").lower()
            if addr_type in ("ipv4", "ipv6") and ip_address is None:
                ip_address = addr_el.get("addr")
            elif addr_type == "mac" and mac_address is None:
                mac_address = _text(addr_el.get("addr"), 17)
        if not ip_address:
            continue

        hostname: str | None = None
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            name_el = hostnames_el.find("hostname")
            if name_el is not None:
                hostname = _text(name_el.get("name"))

        services: list[ParsedService] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                try:
                    port_id = int(port_el.get("portid", ""))
                except (TypeError, ValueError):
                    continue
                if not 0 < port_id <= 65535:
                    continue
                state_el = port_el.find("state")
                port_state = (state_el.get("state") if state_el is not None else "open") or "open"
                if port_state != "open":
                    continue
                service_el = port_el.find("service")
                services.append(
                    ParsedService(
                        port=port_id,
                        protocol=(port_el.get("protocol") or "tcp").lower()[:8],
                        state=port_state,
                        service_name=_text(service_el.get("name"), 64)
                        if service_el is not None
                        else None,
                        product=_text(service_el.get("product"), 128)
                        if service_el is not None
                        else None,
                        version=_text(service_el.get("version"), 64)
                        if service_el is not None
                        else None,
                        extra_info=_text(service_el.get("extrainfo"), 2000)
                        if service_el is not None
                        else None,
                    )
                )

        hosts.append(
            ParsedHost(
                ip_address=ip_address,
                hostname=hostname,
                mac_address=mac_address,
                operating_system=_best_os_name(host_el),
                state=state,
                services=services,
            )
        )
    return hosts
