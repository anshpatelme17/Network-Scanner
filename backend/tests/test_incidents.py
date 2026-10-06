"""Incident management tests (Step 11, recording only)."""

import json
from pathlib import Path

BACKEND_DIR = Path(__file__).parent.parent
CORR_FIXTURES = Path(__file__).parent / "fixtures" / "correlation"


def _corr(name):
    return json.loads((CORR_FIXTURES / name).read_text(encoding="utf-8"))


def _seed_correlation(client):
    """Ingest a correlating pair and recompute; returns the correlation id."""
    client.post("/api/v1/events", json=_corr("chain_a_1.json"))
    client.post("/api/v1/events", json=_corr("chain_a_2.json"))
    client.post("/api/v1/correlations/recompute")
    items = client.get("/api/v1/correlations").json()["items"]
    assert len(items) == 1
    return items[0]["id"]


def _risk_for_correlation(client, correlation_id):
    """Score the correlation's evidence and return the correlation's risk id (if any)."""
    client.post("/api/v1/risk/recompute")
    listed = client.get("/api/v1/risk", params={"entity_type": "correlation"}).json()["items"]
    matches = [item for item in listed if item["entity_id"] == correlation_id]
    return matches[0]["id"] if matches else None


def test_incident_creation_and_retrieval(client, clean_db):
    correlation_id = _seed_correlation(client)
    created = client.post("/api/v1/incidents", json={"correlation_id": correlation_id})
    assert created.status_code == 201
    body = created.json()
    assert body["correlation_id"] == correlation_id
    assert body["status"] == "OPEN"
    assert body["incident_key"].startswith("INC-")
    assert body["version"] == "1.0.0"
    assert body["risk_assessment_id"] is None
    assert (
        "not proof of compromise" in (body["description"] or "").lower()
        or "review" in (body["description"] or "").lower()
    )

    fetched = client.get(f"/api/v1/incidents/{body['id']}").json()
    assert fetched["id"] == body["id"]
    assert isinstance(fetched["evidence_event_ids"], list)
    assert len(fetched["evidence_event_ids"]) == 2


def test_incident_uses_risk_severity_when_linked(client, clean_db):
    correlation_id = _seed_correlation(client)
    risk_id = _risk_for_correlation(client, correlation_id)
    assert risk_id is not None
    body = client.post(
        "/api/v1/incidents", json={"correlation_id": correlation_id, "risk_assessment_id": risk_id}
    ).json()
    assert body["risk_assessment_id"] == risk_id
    risk = client.get(f"/api/v1/risk/correlation/{correlation_id}").json()
    assert body["severity"] == risk["severity"]
    assert (
        body["confidence"]
        == client.get(f"/api/v1/correlations/{correlation_id}").json()["confidence"]
    )


def test_missing_references_return_404(client, clean_db):
    absent_corr = client.post("/api/v1/incidents", json={"correlation_id": "nope"})
    assert absent_corr.status_code == 404
    assert absent_corr.json()["error"]["code"] == "REFERENCE_NOT_FOUND"
    correlation_id = _seed_correlation(client)
    absent_risk = client.post(
        "/api/v1/incidents", json={"correlation_id": correlation_id, "risk_assessment_id": "nope"}
    )
    assert absent_risk.status_code == 404


def test_duplicate_creation_is_idempotent(client, clean_db):
    correlation_id = _seed_correlation(client)
    first = client.post("/api/v1/incidents", json={"correlation_id": correlation_id})
    assert first.status_code == 201
    second = client.post("/api/v1/incidents", json={"correlation_id": correlation_id})
    assert second.status_code == 200
    assert second.json()["id"] == first.json()["id"]
    assert client.get("/api/v1/incidents").json()["total"] == 1
    # Same correlation with an explicit (different) risk context is a separate record.
    risk_id = _risk_for_correlation(client, correlation_id)
    third = client.post(
        "/api/v1/incidents", json={"correlation_id": correlation_id, "risk_assessment_id": risk_id}
    )
    assert third.status_code == 201
    assert third.json()["id"] != first.json()["id"]
    assert client.get("/api/v1/incidents").json()["total"] == 2


def test_different_correlation_separate_incident(client, clean_db):
    first_id = _seed_correlation(client)
    client.post("/api/v1/events", json=_corr("chain_d_1.json"))
    client.post("/api/v1/events", json=_corr("chain_d_2.json"))
    client.post("/api/v1/correlations/recompute")
    assert client.get("/api/v1/incidents").json()["total"] == 0
    client.post("/api/v1/incidents", json={"correlation_id": first_id})
    second_id = next(
        item["id"]
        for item in client.get("/api/v1/correlations").json()["items"]
        if item["id"] != first_id
    )
    other = client.post("/api/v1/incidents", json={"correlation_id": second_id})
    assert other.status_code == 201
    assert other.json()["id"] != first_id
    assert client.get("/api/v1/incidents").json()["total"] == 2


def test_status_lifecycle_and_invalid_transitions(client, clean_db):
    correlation_id = _seed_correlation(client)
    incident_id = client.post("/api/v1/incidents", json={"correlation_id": correlation_id}).json()[
        "id"
    ]

    illegal = client.patch(f"/api/v1/incidents/{incident_id}/status", json={"status": "RESOLVED"})
    assert illegal.status_code == 422
    assert illegal.json()["error"]["code"] == "INVALID_TRANSITION"

    for expected in ("ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "CLOSED"):
        response = client.patch(
            f"/api/v1/incidents/{incident_id}/status", json={"status": expected}
        )
        assert response.status_code == 200, expected
        assert response.json()["status"] == expected

    terminal = client.patch(f"/api/v1/incidents/{incident_id}/status", json={"status": "OPEN"})
    assert terminal.status_code == 422
    unknown = client.patch(f"/api/v1/incidents/{incident_id}/status", json={"status": "ESCALATED"})
    assert unknown.status_code == 422


def test_update_title_description_and_status(client, clean_db):
    correlation_id = _seed_correlation(client)
    incident_id = client.post("/api/v1/incidents", json={"correlation_id": correlation_id}).json()[
        "id"
    ]
    updated = client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={
            "title": "Renamed incident",
            "description": "Analyst note.",
            "status": "ACKNOWLEDGED",
        },
    )
    assert updated.status_code == 200
    body = updated.json()
    assert body["title"] == "Renamed incident"
    assert body["description"] == "Analyst note."
    assert body["status"] == "ACKNOWLEDGED"


def test_listing_filters_pagination_ordering(client, clean_db):
    correlation_id = _seed_correlation(client)
    incident_id = client.post("/api/v1/incidents", json={"correlation_id": correlation_id}).json()[
        "id"
    ]
    client.patch(f"/api/v1/incidents/{incident_id}/status", json={"status": "ACKNOWLEDGED"})

    assert client.get("/api/v1/incidents", params={"status": "OPEN"}).json()["total"] == 0
    assert client.get("/api/v1/incidents", params={"status": "ACKNOWLEDGED"}).json()["total"] == 1
    assert client.get("/api/v1/incidents", params={"status": "bogus"}).status_code == 422
    severity = client.get(f"/api/v1/incidents/{incident_id}").json()["severity"]
    assert client.get("/api/v1/incidents", params={"severity": severity}).json()["total"] == 1
    assert client.get("/api/v1/incidents", params={"severity": "NOPE"}).status_code == 422
    page = client.get("/api/v1/incidents", params={"limit": 1, "offset": 1}).json()
    assert page["total"] == 1 and len(page["items"]) == 0
    first_listing = [item["id"] for item in client.get("/api/v1/incidents").json()["items"]]
    second_listing = [item["id"] for item in client.get("/api/v1/incidents").json()["items"]]
    assert first_listing == second_listing  # deterministic order


def test_404_and_validation_errors(client, clean_db):
    assert client.get("/api/v1/incidents/does-not-exist").status_code == 404
    assert (
        client.get("/api/v1/incidents/does-not-exist").json()["error"]["code"]
        == "INCIDENT_NOT_FOUND"
    )
    assert client.post("/api/v1/incidents", json={}).status_code == 422
    assert (
        client.post("/api/v1/incidents", json={"correlation_id": "x", "extra": 1}).status_code
        == 422
    )
    missing = client.patch("/api/v1/incidents/does-not-exist/status", json={"status": "CLOSED"})
    assert missing.status_code == 404


def test_evidence_references_original_records(client, clean_db):
    correlation_id = _seed_correlation(client)
    body = client.post("/api/v1/incidents", json={"correlation_id": correlation_id}).json()
    detail = client.get(f"/api/v1/incidents/{body['id']}").json()
    assert detail["correlation_id"] == correlation_id
    assert len(detail["evidence_event_ids"]) == 2
    for event_id in detail["evidence_event_ids"]:
        assert client.get(f"/api/v1/events/{event_id}").status_code == 200


def test_migration_reaches_head(tmp_path, monkeypatch):
    from sqlalchemy import create_engine, inspect

    from alembic import command
    from alembic.config import Config

    db_file = tmp_path / "mig.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    command.upgrade(config, "head")
    inspector = inspect(create_engine(f"sqlite:///{db_file}"))
    assert "incidents" in inspector.get_table_names()
    columns = {column["name"] for column in inspector.get_columns("incidents")}
    assert {"incident_key", "status", "severity", "correlation_id", "risk_assessment_id"} <= columns


def test_security_regression_no_execution_paths():
    """AST-level proof for the new Step 11 modules (established pattern)."""
    import ast as _ast
    import inspect as _inspect

    import app.services.incident_service as service

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
