"""Incident risk scoring + prioritization tests (Step 25, advisory only).

Covers: determinism, boundaries, severity/priority bands, unknown
factors, invalid input, repeat calculation, policy version, factor
breakdown, incident integration, auth/RBAC, audit, no-duplicate
guarantees, no state-changing response, malformed/formula input —
without weakening Steps 1–24.
"""

import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "correlation"


def _ingest(client, *names):
    for name in names:
        payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
        assert client.post("/api/v1/events", json=payload).status_code in (200, 201)


def _incident(client):
    _ingest(client, "chain_a_1.json", "chain_a_2.json")
    assert client.post("/api/v1/correlations/recompute", json={}).status_code == 200
    detected = client.post("/api/v1/incidents/detect", json={}).json()
    assert detected["created"] == 1
    return detected["outcomes"][0]["incident_id"]


def _tokens(client):
    client.post(
        "/api/v1/users",
        json={
            "username": "admin",
            "password": "admin-pass-word-1",
            "display_name": "A",
            "roles": ["ADMIN"],
        },
    )
    admin = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "admin-pass-word-1"}
    ).json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin}"}
    client.post(
        "/api/v1/users",
        json={
            "username": "viewer1",
            "password": "viewer-pass-1234",
            "display_name": "V",
            "roles": ["VIEWER"],
        },
        headers=admin_headers,
    )
    viewer = client.post(
        "/api/v1/auth/login", json={"username": "viewer1", "password": "viewer-pass-1234"}
    ).json()["access_token"]
    return admin_headers, {"Authorization": f"Bearer {viewer}"}


def test_deterministic_scoring():
    from app.services import risk_service

    first = risk_service.score_incident("HIGH", 70, 2, 1, 0)
    second = risk_service.score_incident("HIGH", 70, 2, 1, 0)
    assert first == second
    assert first["score"] == 10 + 40 + (4 + 3 + 7) + 10
    assert first["severity"] == "HIGH"
    assert first["priority"] == "P2"


def test_boundaries_and_bands():
    from app.services import risk_service

    minimum = risk_service.score_incident("INFO", None, 0, 0, None)
    assert (minimum["score"], minimum["severity"], minimum["priority"]) == (10, "INFO", "P4")
    maximum = risk_service.score_incident("CRITICAL", 100, 50, 50, 0)
    assert (maximum["score"], maximum["severity"], maximum["priority"]) == (100, "CRITICAL", "P1")
    assert risk_service.band_for(80) == "CRITICAL"
    assert risk_service.band_for(60) == "HIGH"
    assert risk_service.band_for(40) == "MEDIUM"
    assert risk_service.band_for(20) == "LOW"
    assert risk_service.band_for(0) == "INFO"
    assert risk_service.priority_for(80) == "P1"
    assert risk_service.priority_for(60) == "P2"
    assert risk_service.priority_for(40) == "P3"
    assert risk_service.priority_for(0) == "P4"
    medium = risk_service.score_incident("MEDIUM", 50, 5, 3, None)
    assert (medium["severity"], medium["priority"]) == ("MEDIUM", "P3")


def test_unknown_factors_scored_zero():
    from app.services import risk_service

    result = risk_service.score_incident(None, None, -4, -2, None)
    assert result["score"] == 10  # base only; negatives clamped, unknowns zero
    assert result["factors"]["confidence"] == 0
    assert result["factors"]["observation_count"] == 0
    assert result["factors"]["recency_days"] is None


def test_invalid_incident_and_methods(client, clean_db):
    missing = client.post("/api/v1/risk/incidents/does-not-exist/calculate", json={})
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "INCIDENT_NOT_FOUND"
    incident_id = _incident(client)
    assert client.get(f"/api/v1/risk/incidents/{incident_id}/calculate").status_code == 405
    assert (
        client.post(
            f"/api/v1/risk/incidents/{incident_id}/calculate", json={"score": 100}
        ).status_code
        == 422
    )
    assert (
        client.post(
            f"/api/v1/risk/incidents/{incident_id}/calculate", json={"formula": "severity * 100"}
        ).status_code
        == 422
    )


def test_calculate_repeat_idempotent_with_audit(client, clean_db):
    from sqlalchemy import func, select

    from app.database import session as session_module
    from app.models.risk import RiskAudit

    incident_id = _incident(client)
    first = client.post(f"/api/v1/risk/incidents/{incident_id}/calculate", json={})
    assert first.status_code == 201
    body = first.json()
    assert body["entity_type"] == "incident"
    assert body["entity_id"] == incident_id
    assert body["scoring_version"] == "1.0.0"
    assert set(body["factors"]) >= {
        "severity",
        "severity_pts",
        "observation_count",
        "vulnerability_count",
        "confidence",
        "signal_pts",
        "recency_days",
        "recency_pts",
    }
    assert str(body["score"]) in body["explanation"] and body["priority"] in body["explanation"]
    second = client.post(f"/api/v1/risk/incidents/{incident_id}/calculate", json={})
    assert second.json()["score"] == body["score"]
    assert second.json()["id"] == body["id"]  # same snapshot row, no duplicate

    def audit_count():
        db = session_module.get_session_factory()()
        try:
            return (
                db.scalar(
                    select(func.count(RiskAudit.id)).where(RiskAudit.assessment_id == body["id"])
                )
                or 0
            )
        finally:
            db.close()

    assert audit_count() == 1  # creation audited once; identical repeat writes nothing
    fetched = client.get(f"/api/v1/risk/incident/{incident_id}").json()
    assert fetched["score"] == body["score"]
    assert fetched["priority"] == body["priority"]


def test_policy_version_recorded(client, clean_db):
    from app.services import risk_service

    incident_id = _incident(client)
    body = client.post(f"/api/v1/risk/incidents/{incident_id}/calculate", json={}).json()
    assert body["scoring_version"] == risk_service.SCORING_VERSION == "1.0.0"
    assert risk_service.assessment_id("incident", incident_id) == body["id"]


def test_incident_integration_no_duplicates(client, clean_db):
    incident_id = _incident(client)
    before = client.get("/api/v1/incidents").json()["total"]
    client.post("/api/v1/risk/recompute", json={})
    listed = client.get("/api/v1/risk", params={"entity_type": "incident"}).json()
    assert listed["total"] == 1
    assert listed["items"][0]["entity_id"] == incident_id
    assert listed["items"][0]["priority"] in ("P1", "P2", "P3", "P4")
    assert client.get("/api/v1/incidents").json()["total"] == before  # scoring creates nothing
    incident = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert incident["status"] == "OPEN"  # lifecycle untouched
    assert client.get("/api/v1/responses").json()["total"] == 0  # no response triggered


def test_auth_rbac(client, clean_db):
    incident_id = _incident(client)
    admin_headers, viewer_headers = _tokens(client)
    assert (
        client.post(f"/api/v1/risk/incidents/{incident_id}/calculate", json={}).status_code == 401
    )
    denied = client.post(
        f"/api/v1/risk/incidents/{incident_id}/calculate", json={}, headers=viewer_headers
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "PERMISSION_DENIED"
    assert client.get("/api/v1/risk", headers=viewer_headers).status_code == 200
    assert (
        client.post(
            f"/api/v1/risk/incidents/{incident_id}/calculate", json={}, headers=admin_headers
        ).status_code
        == 201
    )


def test_audit_change_and_legacy_fallback(client, clean_db):
    from sqlalchemy import select

    from app.database import session as session_module
    from app.models.risk import RiskAssessment

    incident_id = _incident(client)
    first = client.post(f"/api/v1/risk/incidents/{incident_id}/calculate", json={}).json()
    db = session_module.get_session_factory()()
    try:
        row = db.scalar(select(RiskAssessment).where(RiskAssessment.id == first["id"]))
        row.score = 10
        row.severity = "INFO"
        row.priority = None  # simulate a pre-Step-25 row
        db.commit()
    finally:
        db.close()
    # Readers derive the band deterministically from the stored score.
    assert client.get(f"/api/v1/risk/incident/{incident_id}").json()["priority"] == "P4"
    recalculated = client.post(f"/api/v1/risk/incidents/{incident_id}/calculate", json={}).json()
    assert recalculated["score"] == first["score"]  # inputs unchanged: same outcome
    db = session_module.get_session_factory()()
    try:
        from app.models.risk import RiskAudit

        audits = db.scalars(select(RiskAudit).where(RiskAudit.assessment_id == first["id"])).all()
    finally:
        db.close()
    assert [audit.new_score for audit in audits] == [first["score"], first["score"]]
    assert audits[0].previous_score is None  # creation
    assert audits[1].previous_score == 10  # genuine change recorded
    assert all(audit.actor for audit in audits)


def test_no_secrets_in_risk_records(client, clean_db):
    import json as _json

    incident_id = _incident(client)
    _tokens(client)
    body = client.post(f"/api/v1/risk/incidents/{incident_id}/calculate", json={}).json()
    blob = _json.dumps(body).lower()
    assert "password" not in blob
    assert "eyJ" not in blob
    assert "access_token" not in blob


def test_security_regression_step25_modules():
    """AST-level proof for the Step 25 modules (established pattern)."""
    import ast as _ast
    import inspect as _inspect

    import app.api.v1.endpoints.risk as endpoints
    import app.services.risk_service as service

    for module in (service, endpoints):
        tree = _ast.parse(_inspect.getsource(module))
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
                assert not (
                    set(names) & {"subprocess", "os", "pty", "shutil", "importlib", "socket"}
                ), names
            elif isinstance(node, _ast.ImportFrom):
                mod = (node.module or "").split(".")[0]
                assert mod not in {"subprocess", "os", "socket"}, mod
            if isinstance(node, _ast.Call):
                func = node.func
                if isinstance(func, _ast.Name):
                    assert func.id not in {
                        "eval",
                        "exec",
                        "compile",
                        "open",
                        "__import__",
                    }, func.id
                elif isinstance(func, _ast.Attribute):
                    assert func.attr not in {"system", "popen"}, func.attr
