"""Response adapter foundation tests (Step 19, simulation only).

Covers: valid/invalid adapter selection, valid/invalid targets,
approval gating, dry-run guarantees, truthful simulation results,
would_execute correctness, idempotency, audit events, forbidden
actions, arbitrary-command rejection, no-shell structural proof,
registry integrity — without weakening any Steps 1–18 test.
"""

import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "correlation"


def _seed_incident(client):
    for name in ("chain_a_1.json", "chain_a_2.json"):
        payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
        assert client.post("/api/v1/events", json=payload).status_code in (200, 201)
    client.post("/api/v1/correlations/recompute")
    correlation_id = client.get("/api/v1/correlations").json()["items"][0]["id"]
    incident = client.post("/api/v1/incidents", json={"correlation_id": correlation_id})
    assert incident.status_code in (200, 201)
    return incident.json()


def _propose(client, incident_id, action_type="BLOCK_IP", target_type="IP", target="203.0.113.9"):
    return client.post(
        "/api/v1/responses",
        json={
            "incident_id": incident_id,
            "action_type": action_type,
            "target_type": target_type,
            "target_reference": target,
            "reason": "adapter check",
            "requested_by": "analyst",
        },
    )


def _approve_preview(client, action_id):
    client.post(f"/api/v1/responses/{action_id}/approve", json={"actor": "lead"})
    client.post(f"/api/v1/responses/{action_id}/dry-run")


def test_valid_adapter_selection(client, clean_db):
    incident = _seed_incident(client)
    firewall_id = _propose(client, incident["id"]).json()["id"]
    _approve_preview(client, firewall_id)
    firewall = client.post(f"/api/v1/responses/{firewall_id}/preview", json={})
    assert firewall.status_code == 200
    assert firewall.json()["adapter_type"] == "FIREWALL_SIMULATION"

    evidence_id = client.post(
        f"/api/v1/incidents/{incident['id']}/responses",
        json={"action_type": "COLLECT_EVIDENCE", "reason": "r", "requested_by": "analyst"},
    ).json()["id"]
    client.post(f"/api/v1/responses/{evidence_id}/approve", json={"actor": "lead"})
    evidence = client.post(f"/api/v1/responses/{evidence_id}/preview", json={})
    assert evidence.json()["adapter_type"] == "EVIDENCE_COLLECTION_SIMULATION"

    review_id = client.post(
        f"/api/v1/incidents/{incident['id']}/responses",
        json={"action_type": "REVIEW", "reason": "r", "requested_by": "analyst"},
    ).json()["id"]
    client.post(f"/api/v1/responses/{review_id}/approve", json={"actor": "lead"})
    review = client.post(f"/api/v1/responses/{review_id}/preview", json={})
    assert review.json()["adapter_type"] == "SIMULATION"


def test_invalid_adapter_rejected():
    from app.services.response_executors import EXECUTORS, get_executor

    assert set(EXECUTORS) == {
        "simulation",
        "SIMULATION",
        "EVIDENCE_COLLECTION_SIMULATION",
        "FIREWALL_SIMULATION",
        "ISOLATION_SIMULATION",
    }
    import pytest

    for unknown in ("real-firewall", "SIMULATON", "", "simulation;rm -rf", "../evil"):
        with pytest.raises(KeyError):
            get_executor(unknown)


def test_valid_hostname_target(client, clean_db):
    incident = _seed_incident(client)
    created = _propose(
        client,
        incident["id"],
        action_type="BLOCK_DOMAIN",
        target_type="HOSTNAME",
        target="host-01.example",
    )
    assert created.status_code == 201
    assert created.json()["target_type"] == "HOSTNAME"


def test_invalid_target_rejected(client, clean_db):
    from app.services.response_executors import get_executor
    from app.services.response_service import InvalidResponseError

    incident = _seed_incident(client)
    for bad in ("http://evil.example/x", "host with space", "user@host", "x" * 300):
        rejected = _propose(
            client, incident["id"], action_type="BLOCK_DOMAIN", target_type="HOSTNAME", target=bad
        )
        assert rejected.status_code == 422, bad
    # The adapter contract enforces the same validator (unit level).
    executor = get_executor("FIREWALL_SIMULATION")
    import pytest

    with pytest.raises(InvalidResponseError):
        executor.validate_target("HOSTNAME", "https://evil.example/run")
    executor.validate_target("HOSTNAME", "host-01.example")  # no raise
    # No resolution is ever attempted: even unresolvable names validate
    # purely syntactically.
    executor.validate_target("HOSTNAME", "nonexistent-xyz-123.invalid")


def test_unapproved_response_rejected_from_preview(client, clean_db):
    incident = _seed_incident(client)
    action_id = _propose(client, incident["id"]).json()["id"]
    refused = client.post(f"/api/v1/responses/{action_id}/preview", json={})
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "REQUIRE_APPROVAL"
    client.post(f"/api/v1/responses/{action_id}/reject", json={"actor": "lead"})
    denied = client.post(f"/api/v1/responses/{action_id}/preview", json={})
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "EXECUTION_DENIED"
    assert client.get(f"/api/v1/responses/{action_id}").json()["execution"] is None


def test_approved_response_accepted(client, clean_db):
    incident = _seed_incident(client)
    action_id = client.post(
        f"/api/v1/incidents/{incident['id']}/responses",
        json={"action_type": "REVIEW", "reason": "r", "requested_by": "analyst"},
    ).json()["id"]
    client.post(f"/api/v1/responses/{action_id}/approve", json={"actor": "lead"})
    body = client.post(f"/api/v1/responses/{action_id}/preview", json={"actor": "lead"}).json()
    assert body["accepted"] is True
    assert body["executed"] is False
    assert body["simulated"] is True
    assert body["would_execute"] is True
    assert body["status"] == "SIMULATED"
    assert body["policy_decision"] == "ALLOW_SAFE_EXECUTION"
    assert body["policy_version"] == "1.0.0"


def test_preview_changes_nothing_external(client, clean_db):
    incident = _seed_incident(client)
    action_id = _propose(client, incident["id"]).json()["id"]
    _approve_preview(client, action_id)
    before = client.get(f"/api/v1/responses/{action_id}").json()
    first = client.post(f"/api/v1/responses/{action_id}/preview", json={}).json()
    second = client.post(f"/api/v1/responses/{action_id}/preview", json={}).json()
    assert first == second  # deterministic, byte-identical
    after = client.get(f"/api/v1/responses/{action_id}").json()
    assert after["status"] == before["status"] == "DRY_RUN_COMPLETED"
    assert after["execution"] is None  # preview never creates execution rows
    assert first["executed"] is False
    assert client.get(f"/api/v1/incidents/{incident['id']}").json()["status"] == "OPEN"


def test_simulation_result_is_truthful(client, clean_db):
    incident = _seed_incident(client)
    action_id = _propose(client, incident["id"]).json()["id"]
    _approve_preview(client, action_id)
    body = client.post(f"/api/v1/responses/{action_id}/preview", json={}).json()
    assert "no external system was modified" in body["result_summary"].lower()
    lowered = body["result_summary"].lower()
    for forbidden in ("threat neutralized", "host isolated", "firewall rule applied"):
        assert forbidden not in lowered, forbidden


def test_would_execute_matches_policy(client, clean_db):
    incident = _seed_incident(client)
    # Previewed dangerous proposal: policy ALLOW -> would execute (simulation).
    sim_id = _propose(client, incident["id"]).json()["id"]
    _approve_preview(client, sim_id)
    assert (
        client.post(f"/api/v1/responses/{sim_id}/preview", json={}).json()["would_execute"] is True
    )
    # Approved-but-unpreviewed dangerous proposal: preview itself is refused.
    sim2_id = _propose(client, incident["id"], target="203.0.113.10").json()["id"]
    client.post(f"/api/v1/responses/{sim2_id}/approve", json={"actor": "lead"})
    refused = client.post(f"/api/v1/responses/{sim2_id}/preview", json={})
    assert refused.status_code == 403


def test_preview_audit_exactly_once_per_call(client, clean_db):
    incident = _seed_incident(client)
    action_id = _propose(client, incident["id"]).json()["id"]
    _approve_preview(client, action_id)
    client.post(f"/api/v1/responses/{action_id}/preview", json={"actor": "lead"})
    audits = client.get(f"/api/v1/responses/{action_id}").json()["audit"]
    previews = [entry for entry in audits if entry["event"] == "RESPONSE_PREVIEWED"]
    assert len(previews) == 1
    assert previews[0]["actor"] == "lead"
    assert previews[0]["previous_status"] == previews[0]["new_status"] == "DRY_RUN_COMPLETED"


def test_forbidden_action_rejected(client, clean_db):
    incident = _seed_incident(client)
    unknown = _propose(client, incident["id"], action_type="ISOLATE_HOST_NOW")
    assert unknown.status_code == 422
    # A rejected proposal can never be previewed as executable.
    action_id = _propose(client, incident["id"]).json()["id"]
    client.post(f"/api/v1/responses/{action_id}/reject", json={"actor": "lead"})
    denied = client.post(f"/api/v1/responses/{action_id}/preview", json={})
    assert denied.status_code == 403


def test_arbitrary_command_field_rejected(client, clean_db):
    incident = _seed_incident(client)
    base = {
        "incident_id": incident["id"],
        "action_type": "BLOCK_IP",
        "target_type": "IP",
        "target_reference": "203.0.113.9",
        "reason": "x",
        "requested_by": "analyst",
        "command": "shutdown /s /t 0",
    }
    assert client.post("/api/v1/responses", json=base).status_code == 422
    action_id = _propose(client, incident["id"]).json()["id"]
    _approve_preview(client, action_id)
    assert (
        client.post(
            f"/api/v1/responses/{action_id}/preview", json={"command": "whoami"}
        ).status_code
        == 422
    )
    assert (
        client.post(
            f"/api/v1/responses/{action_id}/execute", json={"command": "whoami"}
        ).status_code
        == 422
    )


def test_typed_contracts():
    from app.schemas.responses import AdapterRequest, AdapterResult

    request = AdapterRequest(
        adapter_type="FIREWALL_SIMULATION",
        action_type="BLOCK_IP",
        target_type="IP",
        target_reference="203.0.113.9",
        incident_id="i",
        response_id="r",
        dry_run=True,
        requested_by="analyst",
        approved_by="lead",
        policy_version="1.0.0",
    )
    assert request.adapter_type == "FIREWALL_SIMULATION"
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        AdapterRequest.model_validate({**request.model_dump(), "command": "x"})
    result = AdapterResult(
        accepted=True,
        executed=False,
        simulated=True,
        status="SIMULATED",
        adapter_type="FIREWALL_SIMULATION",
        action_type="BLOCK_IP",
        target="IP:203.0.113.9",
        result_summary="s",
        would_execute=True,
    )
    assert result.executed is False and result.simulated is True


def test_registry_selection_is_static(client, clean_db):
    from app.services.response_executors import select_adapter_name

    assert select_adapter_name("BLOCK_IP") == "FIREWALL_SIMULATION"
    assert select_adapter_name("ISOLATE_ASSET") == "ISOLATION_SIMULATION"
    assert select_adapter_name("COLLECT_EVIDENCE") == "EVIDENCE_COLLECTION_SIMULATION"
    assert select_adapter_name("REVIEW") == "SIMULATION"
    assert select_adapter_name("SOMETHING_ELSE") == "SIMULATION"
    # Client input cannot influence selection: the previewed adapter
    # comes from the stored action type, never the request body.
    incident = _seed_incident(client)
    action_id = _propose(client, incident["id"]).json()["id"]
    _approve_preview(client, action_id)
    body = client.post(
        f"/api/v1/responses/{action_id}/preview",
        json={"adapter": "ISOLATION_SIMULATION"},
    )
    assert body.status_code == 422  # unknown field rejected; selection stayed static


def test_preview_evidence_uses_stored_references(client, clean_db):
    # Detection-attached evidence links (correlation + events) back the preview.
    for name in ("chain_b_1.json", "chain_b_2.json", "chain_b_3.json"):
        payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
        assert client.post("/api/v1/events", json=payload).status_code in (200, 201)
    client.post("/api/v1/correlations/recompute")
    detected = client.post("/api/v1/incidents/detect", json={}).json()
    assert detected["created"] >= 1
    incident_id = next(
        outcome["incident_id"] for outcome in detected["outcomes"] if outcome["created"]
    )
    action_id = client.post(
        f"/api/v1/incidents/{incident_id}/responses",
        json={"action_type": "COLLECT_EVIDENCE", "reason": "r", "requested_by": "analyst"},
    ).json()["id"]
    client.post(f"/api/v1/responses/{action_id}/approve", json={"actor": "lead"})
    body = client.post(f"/api/v1/responses/{action_id}/preview", json={}).json()
    assert body["adapter_type"] == "EVIDENCE_COLLECTION_SIMULATION"
    assert len(body["evidence"]) >= 1  # stored correlation + event links
    for item in body["evidence"]:
        assert set(item) == {"kind", "reference", "detail"}
        assert item["kind"] in ("correlation", "event", "vulnerability")


def test_security_regression_step19_modules():
    """AST-level proof for the Step 19 modules (established pattern)."""
    import ast as _ast
    import inspect as _inspect

    import app.api.v1.endpoints.responses as endpoints
    import app.services.response_executors as executors

    for module in (executors, endpoints):
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
