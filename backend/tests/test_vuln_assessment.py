"""Vulnerability assessment tests (Step 15, fixture data only)."""

import json
from pathlib import Path

from app.services import vulnerability_service
from app.services.vulnerability_scanners import (
    BASELINE_PROFILE,
    SERVICE_PROFILE,
    AssetView,
    FixtureVulnerabilityScanner,
    ScannedFinding,
    ServiceView,
    get_scanner,
)

FIXTURES = Path(__file__).parent / "fixtures" / "vuln_assessment"
MOCK_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <status state="up" reason="localhost-response"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="localhost" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="TestSSH" version="9.3"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def finding_from_fixture(name, **overrides):
    """Test-only mapping of a fixture document into a ScannedFinding.

    Unknown document fields land in ``extra`` (preservation path).
    """
    document = dict(load(name))
    document.update(overrides)
    known = {
        "scanner_finding_id",
        "title",
        "description",
        "severity",
        "cvss_score",
        "cves",
        "cwe_id",
        "port",
        "protocol",
        "service",
        "product",
        "version",
        "evidence",
        "solution",
        "references",
    }
    cves = document.get("cves", document.get("cve"))
    references = document.get("references", document.get("reference"))
    return ScannedFinding(
        scanner_finding_id=str(document.get("scanner_finding_id", "FIX-TEST")),
        title=str(document.get("title", "")),
        description=document.get("description"),
        severity=document.get("severity", "INFO"),
        cvss_score=document.get("cvss_score"),
        cves=tuple(cves) if isinstance(cves, list) else ((cves,) if cves is not None else ()),
        cwe_id=document.get("cwe_id"),
        port=document.get("port"),
        protocol=document.get("protocol"),
        service_name=document.get("service"),
        product=document.get("product"),
        product_version=document.get("version"),
        evidence=document.get("evidence"),
        solution=document.get("solution"),
        references=tuple(references) if isinstance(references, list) else (),
        extra={key: value for key, value in document.items() if key not in known},
    )


def _mock_nmap(monkeypatch):
    from app.services import scan_service

    monkeypatch.setattr(scan_service.nmap_runner, "is_available", lambda: True)
    monkeypatch.setattr(
        scan_service.nmap_runner, "run_scan", lambda profile, target: (MOCK_XML, "7.95")
    )


def _db_session():
    from app.database import session as session_module

    return session_module.get_session_factory()()


def _seed_asset(client):
    """Inventory 127.0.0.1 with 22/tcp + 80/tcp via a mocked discovery scan."""
    response = client.post(
        "/api/v1/network/scans", json={"target": "127.0.0.1", "scan_profile": "quick"}
    )
    assert response.status_code == 202
    return client.get("/api/v1/assets").json()["items"][0]


def test_adapter_matches_inventory_and_profiles():
    scanner = get_scanner("fixture-scanner")
    assert isinstance(scanner, FixtureVulnerabilityScanner)
    asset = AssetView(ip_address="192.0.2.10")
    services = [
        ServiceView(port=22, protocol="tcp", service_name="ssh"),
        ServiceView(port=80, protocol="tcp", service_name="http"),
        ServiceView(port=9999, protocol="tcp", service_name="unknown-svc"),
    ]
    baseline = scanner.scan(asset, services, BASELINE_PROFILE)
    assert [finding.scanner_finding_id for finding in baseline] == [
        "FIX-SSH-LEGACY",
        "FIX-HTTP-INFO",
        "FIX-BASELINE",
    ]
    assert all(finding.title.startswith("TEST ") for finding in baseline)
    service_only = scanner.scan(asset, services, SERVICE_PROFILE)
    assert [finding.scanner_finding_id for finding in service_only] == [
        "FIX-SSH-LEGACY",
        "FIX-HTTP-INFO",
    ]
    assert scanner.scan(asset, [], BASELINE_PROFILE)[0].scanner_finding_id == "FIX-BASELINE"


def test_adapter_unknown_scanner_rejected():
    import pytest as _pytest

    with _pytest.raises(KeyError):
        get_scanner("real-nessus")


def test_fixture_mapping_edges(clean_db):
    from app.models.assets import Asset, DiscoveredService

    db = _db_session()
    try:
        db.add(Asset(ip_address="192.0.2.10", state="up"))
        db.commit()
        asset = db.query(Asset).filter_by(ip_address="192.0.2.10").one()
        db.add(DiscoveredService(asset_id=asset.id, port=443, protocol="tcp", state="open"))
        db.commit()
        services = db.query(DiscoveredService).all()

        created, refreshed = vulnerability_service.upsert_findings(
            db, asset, services, BASELINE_PROFILE, "tester"
        )
        assert (created, refreshed) == (2, 0)  # tls finding + asset baseline
    finally:
        db.close()


def test_cve_cvss_severity_normalization(clean_db):
    from app.services.vulnerability_service import (
        _normalize_cves,
        _normalize_cvss,
        _normalize_severity,
    )

    assert _normalize_severity("Critical") == "CRITICAL"
    assert _normalize_severity("bogus") == "UNKNOWN"
    assert _normalize_cvss(9.8) == 9.8
    assert _normalize_cvss("7.5") == 7.5
    assert _normalize_cvss("junk") is None
    assert _normalize_cvss(99) is None
    assert _normalize_cves(["cve-2024-9010", "CVE-2024-9011", "not-a-cve", "CVE-2024-9010"]) == [
        "CVE-2024-9010",
        "CVE-2024-9011",
    ]
    cases = [
        ("critical.json", "CRITICAL", 9.8, ["CVE-2024-9001"]),
        ("high_cvss.json", "HIGH", 7.5, []),
        ("medium.json", "MEDIUM", None, []),
        ("low.json", "LOW", None, []),
        ("info.json", "INFO", None, []),
    ]
    for fixture, severity, cvss, cves in cases:
        finding = finding_from_fixture(fixture)
        assert _normalize_severity(finding.severity) == severity, fixture
        assert _normalize_cvss(finding.cvss_score) == cvss, fixture
        assert _normalize_cves(finding.cves) == cves, fixture


def test_valid_assessment_by_asset(client, clean_db, monkeypatch):
    _mock_nmap(monkeypatch)
    asset = _seed_asset(client)
    response = client.post(
        "/api/v1/vulnerability-scans",
        json={"asset_id": asset["id"], "profile": BASELINE_PROFILE, "requested_by": "tester-1"},
    )
    assert response.status_code == 202
    job_id = response.json()["id"]
    job = client.get(f"/api/v1/vulnerability-scans/{job_id}").json()
    assert job["status"] == "completed"
    assert job["requested_by"] == "tester-1"
    assert job["asset_id"] == asset["id"]
    assert "findings" in (job["result_summary"] or "")
    assert [entry["event"] for entry in job["audit"]] == [
        "SCAN_REQUESTED",
        "SCAN_STARTED",
        "SCAN_COMPLETED",
    ]
    findings = client.get("/api/v1/vulnerabilities").json()
    assert findings["total"] == 3  # ssh + http + baseline
    titles = [item["title"] for item in findings["items"]]
    assert all(title.startswith("TEST ") for title in titles)


def test_assessment_by_target_and_service_profile(client, clean_db, monkeypatch):
    _mock_nmap(monkeypatch)
    _seed_asset(client)
    response = client.post(
        "/api/v1/vulnerability-scans",
        json={"target": "127.0.0.1", "profile": SERVICE_PROFILE},
    )
    assert response.status_code == 202
    job = client.get(f"/api/v1/vulnerability-scans/{response.json()['id']}").json()
    assert job["status"] == "completed"
    assert client.get("/api/v1/vulnerabilities").json()["total"] == 2  # no baseline


def test_invalid_asset_unauthorized_and_profile(client, clean_db, monkeypatch):
    _mock_nmap(monkeypatch)
    assert client.post("/api/v1/vulnerability-scans", json={"asset_id": "nope"}).status_code == 404
    assert (
        client.post("/api/v1/vulnerability-scans", json={"target": "192.168.1.10"}).status_code
        == 403
    )
    _seed_asset(client)
    assert (
        client.post(
            "/api/v1/vulnerability-scans", json={"target": "127.0.0.1", "profile": "FULL_AUDIT"}
        ).status_code
        == 422
    )
    assert client.post("/api/v1/vulnerability-scans", json={}).status_code == 422
    both = client.post(
        "/api/v1/vulnerability-scans",
        json={"asset_id": "x", "target": "127.0.0.1", "profile": BASELINE_PROFILE},
    )
    assert both.status_code == 422


def test_dedup_repeat_assessment(client, clean_db, monkeypatch):
    _mock_nmap(monkeypatch)
    asset = _seed_asset(client)
    first = client.post("/api/v1/vulnerability-scans", json={"asset_id": asset["id"]}).json()["id"]
    second = client.post("/api/v1/vulnerability-scans", json={"asset_id": asset["id"]}).json()["id"]
    assert first != second  # scans are distinct records
    assert client.get("/api/v1/vulnerabilities").json()["total"] == 3  # findings are not
    findings = client.get("/api/v1/vulnerabilities").json()["items"]
    assert len({item["id"] for item in findings}) == 3


def test_asset_service_relationship(client, clean_db, monkeypatch):
    _mock_nmap(monkeypatch)
    asset = _seed_asset(client)
    client.post("/api/v1/vulnerability-scans", json={"asset_id": asset["id"]})
    items = client.get("/api/v1/vulnerabilities").json()["items"]
    by_title = {item["title"]: item for item in items}
    ssh = by_title["TEST SSH legacy configuration"]
    assert ssh["asset_id"] == asset["id"]
    assert ssh["service_id"] is not None
    baseline = by_title["TEST baseline hardening review"]
    assert baseline["service_id"] is None
    scoped = client.get(f"/api/v1/assets/{asset['id']}/vulnerabilities").json()
    assert scoped["total"] == 3
    assert client.get("/api/v1/assets/nope/vulnerabilities").status_code == 404


def test_status_lifecycle_and_audit(client, clean_db, monkeypatch):
    _mock_nmap(monkeypatch)
    asset = _seed_asset(client)
    client.post("/api/v1/vulnerability-scans", json={"asset_id": asset["id"]})
    vuln_id = client.get("/api/v1/vulnerabilities").json()["items"][0]["id"]
    assert (
        client.post(
            f"/api/v1/vulnerabilities/{vuln_id}/status", json={"status": "RESOLVED"}
        ).json()["status"]
        == "RESOLVED"
    )
    illegal = client.post(f"/api/v1/vulnerabilities/{vuln_id}/status", json={"status": "OPEN"})
    assert illegal.status_code == 200  # RESOLVED -> OPEN reopen is allowed
    bad = client.post(f"/api/v1/vulnerabilities/{vuln_id}/status", json={"status": "BOGUS"})
    assert bad.status_code == 409
    detail = client.get(f"/api/v1/vulnerabilities/{vuln_id}").json()
    assert [entry["event"] for entry in detail["audit"]] == [
        "VULNERABILITY_OPENED",
        "VULNERABILITY_STATUS_CHANGED",
        "VULNERABILITY_STATUS_CHANGED",
    ]
    assert client.get("/api/v1/vulnerabilities/nope").status_code == 404


def test_filters_and_lookup(client, clean_db, monkeypatch):
    _mock_nmap(monkeypatch)
    asset = _seed_asset(client)
    client.post("/api/v1/vulnerability-scans", json={"asset_id": asset["id"]})
    assert client.get("/api/v1/vulnerabilities", params={"severity": "MEDIUM"}).json()["total"] == 1
    assert client.get("/api/v1/vulnerabilities", params={"severity": "NOPE"}).status_code == 422
    assert (
        client.get("/api/v1/vulnerabilities", params={"asset_id": asset["id"]}).json()["total"] == 3
    )
    assert (
        client.get("/api/v1/vulnerabilities", params={"scanner": "fixture-scanner"}).json()["total"]
        == 3
    )
    assert client.get("/api/v1/vulnerabilities", params={"status": "OPEN"}).json()["total"] == 3


def test_malicious_strings_stay_inert(clean_db):
    from app.models.assets import Asset
    from app.models.vulnerabilities import Vulnerability

    class _EvilScanner:
        name = "evil-test-scanner"

        def __init__(self, finding):
            self._finding = finding

        def scan(self, asset, services, profile):
            return [self._finding]

    db = _db_session()
    try:
        db.add(Asset(ip_address="192.0.2.20", state="up"))
        db.commit()
        asset = db.query(Asset).filter_by(ip_address="192.0.2.20").one()
        fixture = finding_from_fixture("evidence.json")
        created, _ = vulnerability_service.upsert_findings(
            db, asset, [], BASELINE_PROFILE, "t", scanner=_EvilScanner(fixture)
        )
        assert created == 1
        row = db.query(Vulnerability).filter_by(asset_id=asset.id).one()
        assert row.scanner == "evil-test-scanner"
        assert "$(whoami)" in (row.description or "")
        assert "<script>alert(1)</script>" in (row.description or "")
        assert "' OR 1=1 --" in (row.description or "")
        assert db.query(Vulnerability).count() == 1  # table intact, nothing executed
    finally:
        db.close()


def test_unknown_fields_preserved(clean_db):
    from app.models.assets import Asset
    from app.models.vulnerabilities import Vulnerability

    db = _db_session()
    try:
        db.add(Asset(ip_address="192.0.2.21", state="up"))
        db.commit()
        asset = db.query(Asset).filter_by(ip_address="192.0.2.21").one()
        vulnerability_service.upsert_findings(db, asset, [], BASELINE_PROFILE, "t")
        row = db.query(Vulnerability).filter_by(asset_id=asset.id).one()
        assert row.extra_data is not None
    finally:
        db.close()
    finding = finding_from_fixture("unknown_fields.json")
    assert finding.extra == {"custom_field": "kept in extra_data only", "nested": {"extra": True}}


def test_no_execution_paths_in_new_modules():
    """AST-level proof for Step 15 modules (established pattern)."""
    import ast as _ast
    import inspect as _inspect

    import app.api.v1.endpoints.vuln_assessment as endpoints
    import app.services.vulnerability_scanners as scanners
    import app.services.vulnerability_service as service

    for module in (scanners, service, endpoints):
        tree = _ast.parse(_inspect.getsource(module))
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
                assert not (
                    set(names)
                    & {
                        "subprocess",
                        "os",
                        "pty",
                        "shutil",
                        "importlib",
                        "socket",
                        "requests",
                        "httpx",
                        "urllib",
                    }
                ), names
            elif isinstance(node, _ast.ImportFrom):
                module_name = (node.module or "").split(".")[0]
                assert module_name not in {
                    "subprocess",
                    "os",
                    "socket",
                    "requests",
                    "httpx",
                    "urllib",
                }, module_name
            if isinstance(node, _ast.Call):
                func = node.func
                if isinstance(func, _ast.Name):
                    assert func.id not in {"eval", "exec", "compile", "open", "__import__"}, func.id
                elif isinstance(func, _ast.Attribute):
                    assert func.attr not in {"system", "popen", "connect", "request", "urlopen"}, (
                        func.attr
                    )
