"""Inventory upsert tests: create once, update on rescan, replace services."""

from sqlalchemy import func, select

from app.database import session as session_module
from app.models.assets import Asset, DiscoveredService
from app.services.inventory import upsert_scan_results
from app.services.nmap_parser import ParsedHost, ParsedService


def _host(ip, services=(), **kwargs):
    return ParsedHost(ip_address=ip, services=list(services), **kwargs)


def _service(port, name="ssh"):
    return ParsedService(port=port, protocol="tcp", state="open", service_name=name)


def _db():
    return session_module.get_session_factory()()


def test_new_asset_creation(clean_db, _sqlite_engine):
    db = _db()
    try:
        assets, services = upsert_scan_results(
            db, [_host("192.168.1.10", [_service(22), _service(80, "http")], hostname="web1")]
        )
        assert (assets, services) == (1, 2)
        asset = db.scalar(select(Asset).where(Asset.ip_address == "192.168.1.10"))
        assert asset.hostname == "web1"
        assert asset.first_seen is not None and asset.last_seen is not None
        ports = sorted(
            db.scalars(
                select(DiscoveredService.port).where(DiscoveredService.asset_id == asset.id)
            ).all()
        )
        assert ports == [22, 80]
    finally:
        db.close()


def test_repeat_scan_does_not_duplicate(clean_db, _sqlite_engine):
    db = _db()
    try:
        host = _host("192.168.1.10", [_service(22), _service(80, "http")])
        upsert_scan_results(db, [host])
        first = db.scalar(select(Asset).where(Asset.ip_address == "192.168.1.10"))
        first_seen = first.first_seen
        upsert_scan_results(db, [host])
        assert db.scalar(select(func.count(Asset.id))) == 1
        assert db.scalar(select(func.count(DiscoveredService.id))) == 2
        again = db.scalar(select(Asset).where(Asset.ip_address == "192.168.1.10"))
        assert again.first_seen == first_seen  # history preserved
        assert again.last_seen >= first_seen
    finally:
        db.close()


def test_rescan_updates_metadata_and_replaces_services(clean_db, _sqlite_engine):
    db = _db()
    try:
        upsert_scan_results(
            db,
            [_host("192.168.1.10", [_service(22), _service(80, "http")], hostname="old-name")],
        )
        asset = db.scalar(select(Asset).where(Asset.ip_address == "192.168.1.10"))
        old_last_seen = asset.last_seen
        # Second scan: renamed host, port 80 gone, 443 appeared.
        upsert_scan_results(
            db,
            [
                _host(
                    "192.168.1.10",
                    [_service(22), _service(443, "https")],
                    hostname="new-name",
                    operating_system="Linux 6.X",
                )
            ],
        )
        asset = db.scalar(select(Asset).where(Asset.ip_address == "192.168.1.10"))
        assert asset.hostname == "new-name"
        assert asset.operating_system == "Linux 6.X"
        assert asset.last_seen >= old_last_seen
        ports = sorted(
            db.scalars(
                select(DiscoveredService.port).where(DiscoveredService.asset_id == asset.id)
            ).all()
        )
        assert ports == [22, 443]  # current state, no stale 80, no duplicates
    finally:
        db.close()


def test_unknown_fields_never_blank_existing_metadata(clean_db, _sqlite_engine):
    db = _db()
    try:
        upsert_scan_results(db, [_host("192.168.1.10", hostname="known")])
        upsert_scan_results(db, [_host("192.168.1.10")])  # scan without hostname
        asset = db.scalar(select(Asset).where(Asset.ip_address == "192.168.1.10"))
        assert asset.hostname == "known"
    finally:
        db.close()
