"""Deterministic risk scoring tests (Step 10, analysis only)."""

import json
from pathlib import Path

from app.services.risk_service import (
    SCORING_VERSION,
    assessment_id,
    band_for,
    clamp_score,
    cvss_points,
    recency_points,
    score_asset,
    score_correlation,
    score_vulnerability,
    severity_points,
)

VULN_FIXTURES = Path(__file__).parent / "fixtures" / "vulnerabilities"
CORR_FIXTURES = Path(__file__).parent / "fixtures" / "correlation"


def load_vuln(name):
    return json.loads((VULN_FIXTURES / name).read_text(encoding="utf-8"))


def load_corr(name):
    return json.loads((CORR_FIXTURES / name).read_text(encoding="utf-8"))


def test_score_boundaries():
    assert [(band_for(score), clamp_score(score)) for score in (-5, 0)] == [
        ("INFO", 0),
        ("INFO", 0),
    ]
    assert [(band_for(score), clamp_score(score)) for score in (19, 20)] == [
        ("INFO", 19),
        ("LOW", 20),
    ]
    assert [(band_for(score), clamp_score(score)) for score in (39, 40)] == [
        ("LOW", 39),
        ("MEDIUM", 40),
    ]
    assert [(band_for(score), clamp_score(score)) for score in (59, 60)] == [
        ("MEDIUM", 59),
        ("HIGH", 60),
    ]
    assert [(band_for(score), clamp_score(score)) for score in (79, 80)] == [
        ("HIGH", 79),
        ("CRITICAL", 80),
    ]
    assert [(band_for(score), clamp_score(score)) for score in (100, 150)] == [
        ("CRITICAL", 100),
        ("CRITICAL", 100),
    ]


def test_severity_cvss_recency_points():
    assert severity_points("CRITICAL") == 55
    assert severity_points("critical") == 55
    assert severity_points("MEDIUM") == 25
    assert severity_points("bogus") == 0
    assert severity_points(None) == 0
    assert cvss_points(9.8) == 14
    assert cvss_points(10) == 15
    assert cvss_points("7.5") == 11
    assert cvss_points(None) == 0
    assert cvss_points("junk") == 0
    assert cvss_points(True) == 0
    assert cvss_points(-1) == 0
    assert recency_points(None) == 0
    assert recency_points(0) == 10
    assert recency_points(7) == 10
    assert recency_points(8) == 5
    assert recency_points(30) == 5
    assert recency_points(31) == 0


def test_score_vulnerability_exact_math():
    # 10 + 40 (HIGH) + 14 (cvss 9.8) + 5 (known) + 6 (2 covering) + 10 (3d) = 85.
    result = score_vulnerability("HIGH", 9.8, True, 2, 3)
    assert result["score"] == 85
    assert result["severity"] == "CRITICAL"
    assert result["factors"]["severity_pts"] == 40
    assert result["factors"]["cvss_pts"] == 14
    assert "85" in result["explanation"] and "CRITICAL" in result["explanation"]


def test_score_correlation_exact_math():
    # 10 + 25 (MEDIUM) + min(2*3,10)=6 + 70//10=7 + 5 (20d) = 53.
    result = score_correlation("MEDIUM", 3, 70, 20)
    assert result["score"] == 53
    assert result["severity"] == "MEDIUM"


def test_score_asset_exact_math_and_clamp():
    # 10 + 55 + 10 + 12 + 10 + 10 = 117 -> clamped to 100 CRITICAL.
    result = score_asset("CRITICAL", 9, 9, 9, 2)
    assert result["score"] == 100
    assert result["severity"] == "CRITICAL"
    # Bare asset: 10 + 0 + 0 + recency only.
    bare = score_asset(None, 0, 0, 0, None)
    assert bare["score"] == 10
    assert bare["severity"] == "INFO"


def test_assessment_id_deterministic():
    first = assessment_id("asset", "abc")
    assert first == assessment_id("asset", "abc")
    assert len(first) == 64
    assert assessment_id("asset", "abc") != assessment_id("vulnerability", "abc")
    assert assessment_id("asset", "abc") != assessment_id("asset", "abc", version="9.9.9")
    assert SCORING_VERSION == "1.0.0"


def _seed_state(client):
    """One asset (2 ports), one CRITICAL finding on it, one correlation over it."""
    from app.database import session as session_module
    from app.models.assets import Asset, DiscoveredService

    db = session_module.get_session_factory()()
    try:
        db.add(
            Asset(
                ip_address="192.0.2.10",
                hostname="risk-host",
                state="up",
            )
        )
        db.commit()
        asset = db.query(Asset).filter_by(ip_address="192.0.2.10").one()
        db.add_all(
            [
                DiscoveredService(asset_id=asset.id, port=22, protocol="tcp", state="open"),
                DiscoveredService(asset_id=asset.id, port=80, protocol="tcp", state="open"),
            ]
        )
        db.commit()
        asset_id = asset.id
    finally:
        db.close()
    finding = client.post(
        "/api/v1/events/ingest/vulnerabilities",
        json={"source_name": "risk-test", "event": load_vuln("critical.json")},
    ).json()
    for name in ("chain_a_1.json", "chain_a_2.json"):
        client.post("/api/v1/events", json=json.loads((CORR_FIXTURES / name).read_text()))
    client.post("/api/v1/correlations/recompute")
    return asset_id, finding["id"]


def test_recompute_persists_and_repeats_identically(client, clean_db):
    asset_id, finding_id = _seed_state(client)
    first = client.post("/api/v1/risk/recompute").json()
    assert first["scoring_version"] == "1.0.0"
    assert first["assessed"] >= 3  # asset + finding + correlation
    assert first["created"] == first["assessed"]
    listed = client.get("/api/v1/risk").json()
    assert listed["total"] == first["assessed"]
    snapshot = {
        (item["entity_type"], item["entity_id"]): (
            item["id"],
            item["score"],
            item["severity"],
            item["factors"],
            item["explanation"],
            item["scoring_version"],
        )
        for item in listed["items"]
    }
    # Deterministic expected IDs from entity identity alone.
    assert snapshot[("asset", asset_id)][0] == assessment_id("asset", asset_id)
    assert snapshot[("vulnerability", finding_id)][0] == assessment_id("vulnerability", finding_id)

    second = client.post("/api/v1/risk/recompute").json()
    assert second["created"] == 0
    assert second["updated"] == first["assessed"]
    relisted = client.get("/api/v1/risk").json()
    resnapshot = {
        (item["entity_type"], item["entity_id"]): (
            item["id"],
            item["score"],
            item["severity"],
            item["factors"],
            item["explanation"],
            item["scoring_version"],
        )
        for item in relisted["items"]
    }
    assert resnapshot == snapshot  # identical input -> identical output (calculated_at excluded)


def test_detail_filters_and_errors(client, clean_db):
    asset_id, _ = _seed_state(client)
    client.post("/api/v1/risk/recompute")
    detail = client.get(f"/api/v1/risk/asset/{asset_id}").json()
    assert detail["entity_type"] == "asset"
    assert 0 <= detail["score"] <= 100
    assert detail["scoring_version"] == "1.0.0"
    assert isinstance(detail["factors"], dict)
    assert detail["explanation"]
    assert client.get("/api/v1/risk/bogus/x").status_code == 422
    missing = client.get("/api/v1/risk/asset/does-not-exist")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "RISK_NOT_FOUND"
    assert client.get("/api/v1/risk", params={"entity_type": "asset"}).json()["total"] >= 1
    assert client.get("/api/v1/risk", params={"entity_type": "nope"}).status_code == 422
    assert client.get("/api/v1/risk", params={"severity": "NOPE"}).status_code == 422
    page = client.get("/api/v1/risk", params={"limit": 1, "offset": 1}).json()
    assert page["total"] >= 1 and len(page["items"]) == 1


def test_stale_assessments_removed(client, clean_db):
    from app.database import session as session_module
    from app.models.assets import Asset

    asset_id, _ = _seed_state(client)
    client.post("/api/v1/risk/recompute")
    assert client.get(f"/api/v1/risk/asset/{asset_id}").status_code == 200
    db = session_module.get_session_factory()()
    try:
        db.query(Asset).filter_by(id=asset_id).delete()
        db.commit()
    finally:
        db.close()
    client.post("/api/v1/risk/recompute")
    assert client.get(f"/api/v1/risk/asset/{asset_id}").status_code == 404


def test_finding_without_cvss_or_asset_scores_base(client, clean_db):
    body = client.post(
        "/api/v1/events/ingest/vulnerabilities",
        json={"event": {"title": "Bare finding", "severity": "low"}},
    ).json()
    client.post("/api/v1/risk/recompute")
    detail = client.get(f"/api/v1/risk/vulnerability/{body['id']}").json()
    # 10 + 10 (LOW) + 0 (no CVSS) + 0 (unknown host) + 0 (uncovered) + recency.
    assert detail["score"] >= 20
    assert detail["factors"]["cvss_pts"] == 0
    assert detail["factors"]["asset_known"] is False


def test_security_regression_no_execution_paths():
    """AST-level proof for the new Step 10 modules (established pattern)."""
    import ast as _ast
    import inspect as _inspect

    import app.services.risk_service as service

    tree = _ast.parse(_inspect.getsource(service))
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Import):
            names = [alias.name.split(".")[0] for alias in node.names]
            assert not (
                set(names) & {"subprocess", "os", "pty", "shutil", "importlib", "socket"}
            ), names
        elif isinstance(node, _ast.ImportFrom):
            module = (node.module or "").split(".")[0]
            assert module not in {"subprocess", "os", "socket"}, module
        if isinstance(node, _ast.Call):
            func = node.func
            if isinstance(func, _ast.Name):
                assert func.id not in {"eval", "exec", "compile", "open", "__import__"}, func.id
            elif isinstance(func, _ast.Attribute):
                assert func.attr not in {"system", "popen"}, func.attr
