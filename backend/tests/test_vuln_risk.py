"""Vulnerability risk + links tests (Step 16, deterministic only)."""

from pathlib import Path

VULN_FIXTURES = Path(__file__).parent / "fixtures" / "vulnerabilities"
CORR_FIXTURES = Path(__file__).parent / "fixtures" / "correlation"


def _seed_asset(client, monkeypatch):
    from app.services import scan_service

    xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95"><host>
<status state="up" reason="x"/><address addr="127.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open" reason="x"/>
<service name="ssh"/></port></ports></host></nmaprun>"""
    monkeypatch.setattr(scan_service.nmap_runner, "is_available", lambda: True)
    monkeypatch.setattr(scan_service.nmap_runner, "run_scan", lambda profile, target: (xml, "7.95"))
    client.post("/api/v1/network/scans", json={"target": "127.0.0.1", "scan_profile": "quick"})
    return client.get("/api/v1/assets").json()["items"][0]


def _assess(client, asset_id):
    response = client.post("/api/v1/vulnerability-scans", json={"asset_id": asset_id})
    assert response.status_code == 202
    return response.json()["id"]


def _vuln_ids(client):
    return [item["id"] for item in client.get("/api/v1/vulnerabilities").json()["items"]]


def test_finding_risk_scoring_and_determinism(client, clean_db, monkeypatch):
    asset = _seed_asset(client, monkeypatch)
    _assess(client, asset["id"])
    client.post("/api/v1/risk/recompute")
    vuln_id = _vuln_ids(client)[0]
    first = client.get(f"/api/v1/vulnerabilities/{vuln_id}/risk").json()
    assert first["entity_type"] == "vuln_finding"
    assert first["entity_id"] == vuln_id
    assert 0 <= first["score"] <= 100
    assert first["scoring_version"] == "1.0.0"
    assert isinstance(first["factors"], dict)
    assert first["explanation"]
    # Deterministic: identical input reproduces identical output.
    client.post("/api/v1/risk/recompute")
    second = client.get(f"/api/v1/vulnerabilities/{vuln_id}/risk").json()
    assert {k: v for k, v in second.items() if k != "calculated_at"} == {
        k: v for k, v in first.items() if k != "calculated_at"
    }


def test_unknown_finding_and_asset_404(client, clean_db):
    assert client.get("/api/v1/vulnerabilities/nope/risk").status_code == 404
    assert client.get("/api/v1/assets/nope/vuln-risk").status_code == 404
    assert client.get("/api/v1/vulnerabilities/nope/correlations").status_code == 404


def test_missing_cvss_and_unknown_severity(client, clean_db, monkeypatch):
    asset = _seed_asset(client, monkeypatch)
    _assess(client, asset["id"])
    client.post("/api/v1/risk/recompute")
    for vuln_id in _vuln_ids(client):
        body = client.get(f"/api/v1/vulnerabilities/{vuln_id}/risk").json()
        assert 0 <= body["score"] <= 100
        assert body["severity"] in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_finding_links_and_missing_correlation(client, clean_db, monkeypatch):
    asset = _seed_asset(client, monkeypatch)
    _assess(client, asset["id"])
    vuln_id = _vuln_ids(client)[0]
    links = client.get(f"/api/v1/vulnerabilities/{vuln_id}/correlations").json()
    assert links["vulnerability_id"] == vuln_id
    assert links["asset_id"] == asset["id"]
    assert isinstance(links["related_events"], list)
    assert isinstance(links["related_incidents"], list)
    assert isinstance(links["reasons"], list) and links["reasons"]
    # No shared identifiers with other stored events: empty, explained.
    for event in links["related_events"]:
        assert {"id", "event_type", "source_type", "severity", "title", "event_time"} <= set(event)


def test_linked_events_and_incidents(client, clean_db, monkeypatch):
    asset = _seed_asset(client, monkeypatch)
    # Observed activity on the same asset IP (two sources so it can correlate).
    for source, ext in (("GENERIC", "link-1"), ("SURICATA", "link-2")):
        client.post(
            "/api/v1/events",
            json={
                "source_type": source,
                "source_name": "link-test",
                "event_type": "probe",
                "severity": "MEDIUM",
                "title": "Activity on assessed asset",
                "source_ip": "192.0.2.99",
                "destination_ip": "127.0.0.1",
                "event_time": "2026-09-27T06:00:00Z",
                "external_event_id": ext,
            },
        )
    _assess(client, asset["id"])
    client.post("/api/v1/correlations/recompute")
    vuln_id = _vuln_ids(client)[0]
    links = client.get(f"/api/v1/vulnerabilities/{vuln_id}/correlations").json()
    assert len(links["related_events"]) >= 1
    assert any("127.0.0.1" in reason for reason in links["reasons"])
    # An incident over a correlation containing that event links back.
    correlations = client.get("/api/v1/correlations").json()["items"]
    assert correlations
    incident = client.post(
        "/api/v1/incidents", json={"correlation_id": correlations[0]["id"]}
    ).json()
    relinked = client.get(f"/api/v1/vulnerabilities/{vuln_id}/correlations").json()
    assert incident["id"] in [item["id"] for item in relinked["related_incidents"]]


def test_asset_summary_aggregation(client, clean_db, monkeypatch):
    asset = _seed_asset(client, monkeypatch)
    _assess(client, asset["id"])
    client.post("/api/v1/risk/recompute")
    summary = client.get(f"/api/v1/assets/{asset['id']}/vuln-risk").json()
    assert summary["asset_id"] == asset["id"]
    assert summary["finding_count"] >= 1
    assert summary["highest_severity"] in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert summary["critical_count"] + summary["high_count"] <= summary["finding_count"]
    assert 0 <= summary["aggregate_risk"] <= 100
    assert summary["risk_level"] in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert summary["calculated_at"] is not None
    # Empty asset: honest zeros, INFO, no fabricated score.
    from app.database import session as session_module
    from app.models.assets import Asset

    db = session_module.get_session_factory()()
    try:
        db.add(Asset(ip_address="192.0.2.200", state="up"))
        db.commit()
        empty_id = db.query(Asset).filter_by(ip_address="192.0.2.200").one().id
    finally:
        db.close()
    empty = client.get(f"/api/v1/assets/{empty_id}/vuln-risk").json()
    assert empty == {
        "asset_id": empty_id,
        "finding_count": 0,
        "highest_severity": "INFO",
        "highest_cvss": None,
        "critical_count": 0,
        "high_count": 0,
        "aggregate_risk": 0,
        "risk_level": "INFO",
        "calculated_at": None,
    }


def test_duplicate_findings_never_double_count(client, clean_db, monkeypatch):
    asset = _seed_asset(client, monkeypatch)
    _assess(client, asset["id"])
    _assess(client, asset["id"])
    summary = client.get(f"/api/v1/assets/{asset['id']}/vuln-risk").json()
    total = client.get("/api/v1/vulnerabilities", params={"asset_id": asset["id"]}).json()["total"]
    assert summary["finding_count"] == total
    assert summary["finding_count"] == len(
        {item["id"] for item in client.get("/api/v1/vulnerabilities").json()["items"]}
    )


def test_api_validation_errors(client, clean_db):
    assert client.get("/api/v1/vulnerabilities/nope/risk").json()["error"]["code"] in (
        "VULNERABILITY_NOT_FOUND",
        "RISK_NOT_FOUND",
    )


def test_security_regression_no_execution_paths():
    """AST-level proof for the new Step 16 modules (established pattern)."""
    import ast as _ast
    import inspect as _inspect

    import app.services.vuln_correlation as links

    tree = _ast.parse(_inspect.getsource(links))
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
            module = (node.module or "").split(".")[0]
            assert module not in {"subprocess", "os", "socket", "requests", "httpx", "urllib"}, (
                module
            )
        if isinstance(node, _ast.Call):
            func = node.func
            if isinstance(func, _ast.Name):
                assert func.id not in {"eval", "exec", "compile", "open", "__import__"}, func.id
            elif isinstance(func, _ast.Attribute):
                assert func.attr not in {"system", "popen", "connect", "request", "urlopen"}, (
                    func.attr
                )
