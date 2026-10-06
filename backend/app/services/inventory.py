"""Asset inventory upsert (Step 2).

The database is a continuously updated inventory keyed by IP address:

- first observation creates the ``Asset`` (sets ``first_seen``);
- later scans update metadata and ``last_seen`` — never duplicate rows;
- the asset's service set is *replaced* with the latest observation
  (stale ports disappear, matching the scan's current view).
  Per-service ``discovered_at`` therefore marks when a port row was
  (re)created; long-term host history lives on ``Asset.first_seen``.

The ``(asset_id, port, protocol)`` unique constraint backs this up at
the database level.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.models.assets import Asset, DiscoveredService
from app.services.nmap_parser import ParsedHost


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def upsert_scan_results(
    db: Session,
    hosts: list[ParsedHost],
    *,
    source: str | None = None,
    scan_id: str | None = None,
    replace_services: bool = True,
) -> tuple[int, int]:
    """Merge parsed hosts into the inventory. Returns (assets, services).

    ``source``/``scan_id`` stamp discovery provenance on created rows and
    fill it in where a previous scan left it unknown; they never blank
    out existing values.

    ``replace_services=False`` (host-discovery-only profiles such as
    DISCOVERY_PING) keeps previously observed services: a scan that
    never probed ports must not delete port knowledge, and service
    counts then reflect preserved rows rather than new observations.
    """
    now = _utcnow()
    asset_count = 0
    service_count = 0
    for parsed in hosts:
        asset = db.scalar(select(Asset).where(Asset.ip_address == parsed.ip_address))
        if asset is None:
            asset = Asset(
                ip_address=parsed.ip_address,
                hostname=parsed.hostname,
                mac_address=parsed.mac_address,
                operating_system=parsed.operating_system,
                state=parsed.state,
                first_seen=now,
                last_seen=now,
                discovery_source=source,
                discovery_scan_id=scan_id,
            )
            db.add(asset)
            db.flush()  # assign id for the service rows below
        else:
            # Update only metadata Nmap actually observed; never blank out
            # fields the scan did not report (None = unknown, not empty).
            if parsed.hostname is not None:
                asset.hostname = parsed.hostname
            if parsed.mac_address is not None:
                asset.mac_address = parsed.mac_address
            if parsed.operating_system is not None:
                asset.operating_system = parsed.operating_system
            if source is not None and asset.discovery_source is None:
                asset.discovery_source = source
            if scan_id is not None:
                asset.discovery_scan_id = scan_id
            asset.state = parsed.state
            asset.last_seen = now

        # Replace the service set with the latest observation, unless
        # this profile never probed ports (then there is nothing new to
        # say about services, so preserve what earlier scans found).
        if replace_services:
            db.execute(delete(DiscoveredService).where(DiscoveredService.asset_id == asset.id))
            for service in parsed.services:
                db.add(
                    DiscoveredService(
                        asset_id=asset.id,
                        port=service.port,
                        protocol=service.protocol,
                        state=service.state,
                        service_name=service.service_name,
                        product=service.product,
                        version=service.version,
                        extra_info=service.extra_info,
                        last_seen=now,
                        discovery_scan_id=scan_id,
                    )
                )
            service_count += len(parsed.services)
        else:
            service_count += (
                db.scalar(
                    select(func.count(DiscoveredService.id)).where(
                        DiscoveredService.asset_id == asset.id
                    )
                )
                or 0
            )
        asset_count += 1
    db.commit()
    return asset_count, service_count
