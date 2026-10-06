"""Dry-run response proposal tests (Step 12, no executors anywhere)."""

import json
from pathlib import Path

CORR_FIXTURES = Path(__file__).parent / "fixtures" / "correlation"


def _seed_incident(client):
    """Ingest a correlating pair, recompute, open an incident; return its id."""
    for name in ("chain_a_1.json", "chain_a_2.json"):
        payload = json.loads((CORR_FIXTURES / name).read_text(encoding="utf-8"))
        client.post("/api/v1/events", json=payload)
    client.post("/api/v1/correlations/recompute")
    correlation_id = client.get("/api/v1/correlations").json()["items"][0]["id"]
    incident = client.post("/api/v1/incidents", json={"correlation_id": correlation_id}).json()
    return incident["id"]


def _proposal(client, incident_id, **overrides):
    body = {
        "incident_id": incident_id,
        "action_type": "BLOCK_IP",
        "target_type": "IP",
        "target_reference": "203.0.113.9",
        "reason": "Repeat offender observed in correlated activity.",
        "requested_by": "analyst-1",
        "dry_run": True,
    }
    body.update(overrides)
    return client.post("/api/v1/responses", json=body)


def test_valid_proposal(client, clean_db):
    incident_id = _seed_incident(client)
    response = _proposal(client, incident_id)
    assert response.status_code == 201
    body = response.json()
    assert body["incident_id"] == incident_id
    assert body["status"] == "PROPOSED"
    assert body["dry_run"] is True
    assert body["policy_version"] == "1.0.0"
    assert body["approved_at"] is None


def test_invalid_incident(client, clean_db):
    response = _proposal(client, "does-not-exist")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "INCIDENT_NOT_FOUND"


def test_invalid_action_type(client, clean_db):
    incident_id = _seed_incident(client)
    response = _proposal(client, incident_id, action_type="FORMAT_DISK")
    assert response.status_code == 422


def test_missing_target(client, clean_db):
    incident_id = _seed_incident(client)
    assert _proposal(client, incident_id, target_reference="   ").status_code == 422
    assert (
        _proposal(client, incident_id, target_type="IP", target_reference="not-an-ip").status_code
        == 422
    )


def test_deterministic_identity_and_duplicates(client, clean_db):
    from app.services import response_service

    incident_id = _seed_incident(client)
    first = _proposal(client, incident_id)
    assert first.status_code == 201
    expected = response_service.action_id(incident_id, "BLOCK_IP", "IP", "203.0.113.9", "analyst-1")
    assert first.json()["id"] == expected
    second = _proposal(client, incident_id)
    assert second.status_code == 200
    assert second.json()["id"] == expected
    assert client.get("/api/v1/responses").json()["total"] == 1
    # Same logical action, different requester: separate proposal by design.
    third = _proposal(client, incident_id, requested_by="analyst-2")
    assert third.status_code == 201
    assert third.json()["id"] != expected


def test_approve_reject_cancel_transitions(client, clean_db):
    incident_id = _seed_incident(client)
    action_id = _proposal(client, incident_id).json()["id"]

    approved = client.post(f"/api/v1/responses/{action_id}/approve", json={"actor": "lead-1"})
    assert approved.status_code == 200
    body = approved.json()
    assert body["status"] == "APPROVED"
    assert body["approved_at"] is not None
    assert body["expires_at"] is not None

    # APPROVED proposals can still be cancelled (nothing was executed).
    cancelled = client.post(f"/api/v1/responses/{action_id}/cancel", json={})
    assert cancelled.json()["status"] == "CANCELLED"

    other_id = _proposal(client, incident_id, requested_by="analyst-2").json()["id"]
    rejected = client.post(f"/api/v1/responses/{other_id}/reject", json={"actor": "lead-2"})
    assert rejected.json()["status"] == "REJECTED"


def test_invalid_state_transition_is_409(client, clean_db):
    incident_id = _seed_incident(client)
    action_id = _proposal(client, incident_id).json()["id"]
    client.post(f"/api/v1/responses/{action_id}/approve", json={})
    second_approve = client.post(f"/api/v1/responses/{action_id}/approve", json={})
    assert second_approve.status_code == 409
    assert second_approve.json()["error"]["code"] == "INVALID_TRANSITION"
    reject_after_approve = client.post(f"/api/v1/responses/{action_id}/reject", json={})
    assert reject_after_approve.status_code == 409


def test_dry_run_output_never_reports_execution(client, clean_db):
    incident_id = _seed_incident(client)
    action_id = _proposal(client, incident_id).json()["id"]
    result = client.post(f"/api/v1/responses/{action_id}/dry-run").json()
    assert result["dry_run"] is True
    assert result["would_execute"] is False
    assert result["result"] == "SIMULATED"
    assert result["policy_version"] == "1.0.0"
    assert "No action was executed" in result["explanation"]
    assert "BLOCK_IP" in result["explanation"] or "blocking" in result["explanation"]
    serialized = json.dumps(result)
    for forbidden in ("EXECUTED", "success", "firewall-id", "endpoint-id", "command output"):
        assert forbidden not in serialized
    # Dry run moves PROPOSED forward but approve still works afterwards.
    assert client.get(f"/api/v1/responses/{action_id}").json()["status"] == "DRY_RUN_COMPLETED"
    assert client.post(f"/api/v1/responses/{action_id}/approve", json={}).status_code == 200


def test_policy_version_persisted(client, clean_db):
    from app.services import response_service

    assert response_service.POLICY_VERSION == "1.0.0"
    incident_id = _seed_incident(client)
    body = _proposal(client, incident_id).json()
    assert body["policy_version"] == "1.0.0"
    dry = client.post(f"/api/v1/responses/{body['id']}/dry-run").json()
    assert dry["policy_version"] == "1.0.0"


def test_audit_records_and_ordering(client, clean_db):
    incident_id = _seed_incident(client)
    action_id = _proposal(client, incident_id).json()["id"]
    client.post(f"/api/v1/responses/{action_id}/dry-run")
    client.post(f"/api/v1/responses/{action_id}/approve", json={"actor": "lead-1"})
    detail = client.get(f"/api/v1/responses/{action_id}").json()
    events = [entry["event"] for entry in detail["audit"]]
    assert events == ["ACTION_PROPOSED", "DRY_RUN_COMPLETED", "ACTION_APPROVED"]
    first = detail["audit"][0]
    assert first["actor"] == "analyst-1"
    assert first["previous_status"] is None
    assert first["new_status"] == "PROPOSED"
    assert first["policy_version"] == "1.0.0"
    approval = detail["audit"][2]
    assert approval["actor"] == "lead-1"
    assert approval["previous_status"] == "DRY_RUN_COMPLETED"
    assert approval["new_status"] == "APPROVED"


def test_incident_relationship(client, clean_db):
    incident_id = _seed_incident(client)
    body = _proposal(client, incident_id).json()
    assert body["incident_id"] == incident_id
    listed = client.get("/api/v1/responses", params={"incident_id": incident_id}).json()
    assert listed["total"] == 1
    assert client.get("/api/v1/responses", params={"incident_id": "nope"}).json()["total"] == 0


def test_pagination_and_filters(client, clean_db):
    incident_id = _seed_incident(client)
    _proposal(client, incident_id)
    _proposal(client, incident_id, requested_by="analyst-2", target_reference="198.51.100.9")
    assert client.get("/api/v1/responses", params={"status": "PROPOSED"}).json()["total"] == 2
    assert client.get("/api/v1/responses", params={"status": "bogus"}).status_code == 422
    assert client.get("/api/v1/responses", params={"action_type": "BLOCK_IP"}).json()["total"] == 2
    page = client.get("/api/v1/responses", params={"limit": 1, "offset": 1}).json()
    assert page["total"] == 2 and len(page["items"]) == 1
    first = [item["id"] for item in client.get("/api/v1/responses").json()["items"]]
    second = [item["id"] for item in client.get("/api/v1/responses").json()["items"]]
    assert first == second


def test_validation_errors(client, clean_db):
    assert client.post("/api/v1/responses", json={}).status_code == 422
    incident_id = _seed_incident(client)
    assert _proposal(client, incident_id, dry_run=False).status_code == 422
    assert _proposal(client, incident_id, requested_by="").status_code == 422
    assert _proposal(client, incident_id, reason="").status_code == 422
    # Step 19: HOSTNAME is a supported simulated target type, so it now
    # validates (with a hostname reference); genuinely unknown types stay 422.
    assert _proposal(
        client, incident_id, target_type="HOSTNAME", target_reference="host-01.example"
    ).status_code in (200, 201)
    assert _proposal(client, incident_id, target_type="URL").status_code == 422
    assert client.get("/api/v1/responses/does-not-exist").status_code == 404
    assert (
        client.get("/api/v1/responses/does-not-exist").json()["error"]["code"]
        == "RESPONSE_NOT_FOUND"
    )
    assert client.post("/api/v1/responses/does-not-exist/approve", json={}).status_code == 404
    assert client.get("/api/v1/responses", params={"limit": 0}).status_code == 422


def test_status_and_event_values_fit_columns():
    """Regression test: every lifecycle/event string must fit its column.

    SQLite ignores VARCHAR(n); PostgreSQL enforces it — this is what
    caught the 17-char DRY_RUN_COMPLETED in a 16-char column.
    """
    from app.models.responses import ResponseAction, ResponseAudit
    from app.services import response_service

    status_length = ResponseAction.__table__.c.status.type.length
    for value in response_service.STATUSES:
        assert len(value) <= status_length, value
    for column in ("previous_status", "new_status"):
        length = ResponseAudit.__table__.c[column].type.length
        for value in response_service.STATUSES:
            assert len(value) <= length, (column, value)
    for event in (
        response_service.EVENT_PROPOSED,
        response_service.EVENT_APPROVED,
        response_service.EVENT_REJECTED,
        response_service.EVENT_CANCELLED,
        response_service.EVENT_DRY_RUN_COMPLETED,
    ):
        assert len(event) <= ResponseAudit.__table__.c.event.type.length, event


def test_no_real_execution_endpoints_exist(client):
    """Only the simulation execute endpoint may exist; no real-action paths."""
    openapi = client.get("/openapi.json").json()
    paths = " ".join(openapi["paths"].keys())
    for forbidden in (
        "/block",
        "/isolate",
        "/quarantine",
        "/remediate",
        "/firewall",
        "/disable-account",
    ):
        assert forbidden not in paths
    assert "/api/v1/responses/{action_id}/execute" in openapi["paths"]


def test_security_regression_no_execution_paths():
    """AST-level proof for the new Step 12 modules (established pattern)."""
    import ast as _ast
    import inspect as _inspect

    import app.services.response_service as service

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
