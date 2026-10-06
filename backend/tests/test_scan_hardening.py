"""Step 14 hardening tests: authorization scope, cancel, audit, provenance."""

import ipaddress

import pytest

from app.services import scan_service
from app.services.target_validation import (
    TargetNotAuthorizedError,
    authorize_target,
    parse_allowed_networks,
)

MOCK_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <status state="up" reason="localhost-response"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="localhost" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="8000">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="TestServer" version="1.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def _mock_run(monkeypatch):
    monkeypatch.setattr(scan_service.nmap_runner, "is_available", lambda: True)
    monkeypatch.setattr(
        scan_service.nmap_runner, "run_scan", lambda profile, target: (MOCK_XML, "7.95")
    )


def _allow(monkeypatch, networks):
    class _Settings:
        scan_allowed_networks = networks

    monkeypatch.setattr(scan_service, "get_settings", lambda: _Settings())


def test_parse_allowed_networks():
    parsed = parse_allowed_networks("127.0.0.1/32, ::1/128")
    assert len(parsed) == 2
    assert parse_allowed_networks("") == []
    assert parse_allowed_networks("not-a-network, , 10.0.0.0/8") == [
        ipaddress.ip_network("10.0.0.0/8")
    ]


def test_authorize_single_ip():
    allowed = parse_allowed_networks("127.0.0.1/32,10.0.0.0/8")
    assert authorize_target("127.0.0.1", allowed) == "127.0.0.1"
    assert authorize_target("10.1.2.3", allowed) == "10.1.2.3"
    with pytest.raises(TargetNotAuthorizedError):
        authorize_target("192.168.1.10", allowed)
    with pytest.raises(TargetNotAuthorizedError):
        authorize_target("8.8.8.8", allowed)
    with pytest.raises(TargetNotAuthorizedError):
        authorize_target("127.0.0.1", [])


def test_authorize_cidr_containment_not_expansion():
    allowed = parse_allowed_networks("192.168.0.0/16,2001:db8::/32")
    assert authorize_target("192.168.1.0/24", allowed) == "192.168.1.0/24"
    with pytest.raises(TargetNotAuthorizedError):
        authorize_target("192.167.0.0/16", allowed)  # overlapping, not contained
    with pytest.raises(TargetNotAuthorizedError):
        authorize_target("10.0.0.0/8", allowed)
    with pytest.raises(TargetNotAuthorizedError):
        authorize_target("2001:db9::/32", allowed)
    # Versions never cross-match: v4 target is not "in" a v6 network and vice versa.
    with pytest.raises(TargetNotAuthorizedError):
        authorize_target("::1", parse_allowed_networks("0.0.0.0/0"))


def test_api_rejects_out_of_scope_target(client, clean_db, monkeypatch):
    _mock_run(monkeypatch)
    response = client.post(
        "/api/v1/network/scans", json={"target": "192.168.1.10", "scan_profile": "quick"}
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "TARGET_NOT_AUTHORIZED"


def test_api_honors_custom_scope(client, clean_db, monkeypatch):
    _mock_run(monkeypatch)
    _allow(monkeypatch, "10.0.0.0/8")
    denied = client.post(
        "/api/v1/network/scans", json={"target": "127.0.0.1", "scan_profile": "quick"}
    )
    assert denied.status_code == 403
    allowed = client.post(
        "/api/v1/network/scans", json={"target": "10.1.2.3", "scan_profile": "quick"}
    )
    assert allowed.status_code == 202


def test_scan_records_actor_summary_and_audit(client, clean_db, monkeypatch):
    _mock_run(monkeypatch)
    created = client.post(
        "/api/v1/network/scans",
        json={"target": "127.0.0.1", "scan_profile": "quick", "requested_by": "tester-1"},
    )
    assert created.status_code == 202
    job = client.get(f"/api/v1/network/scans/{created.json()['id']}").json()
    assert job["requested_by"] == "tester-1"
    assert job["scan_type"] == "nmap"
    assert job["result_summary"] == "1 hosts, 1 ports"
    assert [entry["event"] for entry in job["audit"]] == [
        "SCAN_REQUESTED",
        "SCAN_STARTED",
        "SCAN_COMPLETED",
    ]
    assert all(entry["actor"] == "tester-1" for entry in job["audit"])


def test_cancel_queued_scan(client, clean_db):
    from app.database import session as session_module
    from app.models.scans import ScanJob, ScanStatus

    db = session_module.get_session_factory()()
    try:
        db.add(ScanJob(target="127.0.0.1", profile="quick", status=ScanStatus.QUEUED))
        db.commit()
        job_id = db.query(ScanJob).first().id
    finally:
        db.close()
    response = client.post(f"/api/v1/network/scans/{job_id}/cancel")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "cancelled"
    assert [entry["event"] for entry in body["audit"]][-1] == "SCAN_CANCELLED"


def test_cancel_non_queued_reports_409(client, clean_db, monkeypatch):
    _mock_run(monkeypatch)
    job_id = client.post(
        "/api/v1/network/scans", json={"target": "127.0.0.1", "scan_profile": "quick"}
    ).json()["id"]
    # BackgroundTasks run inline in tests: the job is already completed.
    response = client.post(f"/api/v1/network/scans/{job_id}/cancel")
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "SCAN_NOT_CANCELLABLE"
    assert client.post("/api/v1/network/scans/nope/cancel").status_code == 404


def test_asset_provenance_fields(client, clean_db, monkeypatch):
    _mock_run(monkeypatch)
    job_id = client.post(
        "/api/v1/network/scans", json={"target": "127.0.0.1", "scan_profile": "quick"}
    ).json()["id"]
    assets = client.get("/api/v1/assets").json()["items"]
    assert len(assets) == 1
    assert assets[0]["asset_type"] == "UNKNOWN"  # never guessed
    assert assets[0]["discovery_source"] == "nmap"
    detail = client.get(f"/api/v1/assets/{assets[0]['id']}").json()
    assert detail["discovery_source"] == "nmap"

    from app.database import session as session_module
    from app.models.assets import Asset, DiscoveredService
    from app.services import inventory as inventory_service
    from app.services.nmap_parser import parse_nmap_xml

    db = session_module.get_session_factory()()
    try:
        # A later scan without provenance must not blank the asset's values.
        # (Service rows are recreated per scan, so an unknown scan honestly
        # records an unknown scan id on the fresh rows.)
        inventory_service.upsert_scan_results(db, parse_nmap_xml(MOCK_XML))
        asset = db.query(Asset).filter_by(ip_address="127.0.0.1").one()
        assert asset.discovery_source == "nmap"
        assert asset.discovery_scan_id == job_id
        service = db.query(DiscoveredService).first()
        assert service.discovery_scan_id is None
    finally:
        db.close()
