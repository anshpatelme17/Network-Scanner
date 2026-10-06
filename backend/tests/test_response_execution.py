"""Simulation execution tests (Step 13 — nothing real ever runs)."""

import json
from pathlib import Path

from app.services import response_policy
from app.services.response_executors import (
    SIMULATION_ADAPTER,
    SimulationResponseExecutor,
    get_executor,
)
from app.services.response_policy import (
    DECISION_ALLOW,
    DECISION_DENY,
    DECISION_REQUIRE_APPROVAL,
    evaluate_for_execution,
)

CORR_FIXTURES = Path(__file__).parent / "fixtures" / "correlation"


def _seed_action(client, action_type="BLOCK_IP", target_type="IP", target="203.0.113.9"):
    for name in ("chain_a_1.json", "chain_a_2.json"):
        payload = json.loads((CORR_FIXTURES / name).read_text(encoding="utf-8"))
        client.post("/api/v1/events", json=payload)
    client.post("/api/v1/correlations/recompute")
    correlation_id = client.get("/api/v1/correlations").json()["items"][0]["id"]
    incident_id = client.post("/api/v1/incidents", json={"correlation_id": correlation_id}).json()[
        "id"
    ]
    created = client.post(
        "/api/v1/responses",
        json={
            "incident_id": incident_id,
            "action_type": action_type,
            "target_type": target_type,
            "target_reference": target,
            "reason": "Step 13 verification.",
            "requested_by": "analyst-1",
            "dry_run": True,
        },
    )
    assert created.status_code == 201
    return created.json()["id"]


def _advance_to_previewed(client, action_id, actor="lead-1"):
    assert (
        client.post(f"/api/v1/responses/{action_id}/approve", json={"actor": actor}).status_code
        == 200
    )
    assert client.post(f"/api/v1/responses/{action_id}/dry-run").status_code == 200


def test_valid_action_creation(client, clean_db):
    action_id = _seed_action(client)
    body = client.get(f"/api/v1/responses/{action_id}").json()
    assert body["status"] == "PROPOSED"
    assert body["execution_status"] is None


def test_invalid_action_type_and_target(client, clean_db):
    from app.services import response_service

    assert "TERMINATE_PROCESS" not in response_service.ACTION_TYPES
    assert client.post("/api/v1/responses", json={}).status_code == 422


def test_missing_incident(client, clean_db):
    response = client.post(
        "/api/v1/responses",
        json={
            "incident_id": "nope",
            "action_type": "BLOCK_IP",
            "target_type": "IP",
            "target_reference": "10.0.0.1",
            "reason": "x",
            "requested_by": "a",
        },
    )
    assert response.status_code == 404


def test_policy_decisions():
    assert response_policy.POLICY_VERSION == "1.0.0"

    class _Fake:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    assert evaluate_for_execution(None)["decision"] == DECISION_DENY
    assert (
        evaluate_for_execution(_Fake(status="PROPOSED", action_type="BLOCK_IP", dry_run=True))[
            "decision"
        ]
        == DECISION_REQUIRE_APPROVAL
    )
    assert (
        evaluate_for_execution(_Fake(status="APPROVED", action_type="BLOCK_IP", dry_run=True))[
            "decision"
        ]
        == DECISION_REQUIRE_APPROVAL
    )
    assert (
        evaluate_for_execution(
            _Fake(status="DRY_RUN_COMPLETED", action_type="BLOCK_IP", dry_run=True)
        )["decision"]
        == DECISION_ALLOW
    )
    assert (
        evaluate_for_execution(_Fake(status="REJECTED", action_type="BLOCK_IP", dry_run=True))[
            "decision"
        ]
        == DECISION_DENY
    )
    assert (
        evaluate_for_execution(
            _Fake(status="DRY_RUN_COMPLETED", action_type="FORMAT_DISK", dry_run=True)
        )["decision"]
        == DECISION_DENY
    )
    assert (
        evaluate_for_execution(
            _Fake(status="DRY_RUN_COMPLETED", action_type="BLOCK_IP", dry_run=False)
        )["decision"]
        == DECISION_DENY
    )


def test_approval_requirement_enforced(client, clean_db):
    action_id = _seed_action(client)
    refused = client.post(f"/api/v1/responses/{action_id}/execute", json={})
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "REQUIRE_APPROVAL"


def test_denied_execution_recorded(client, clean_db):
    action_id = _seed_action(client)
    client.post(f"/api/v1/responses/{action_id}/reject", json={})
    refused = client.post(f"/api/v1/responses/{action_id}/execute", json={})
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "EXECUTION_DENIED"
    detail = client.get(f"/api/v1/responses/{action_id}").json()
    assert detail["execution_status"] is None
    assert detail["execution"] is None
    events = [entry["event"] for entry in detail["audit"]]
    assert "EXECUTION_DENIED" in events


def test_simulation_execution_end_to_end(client, clean_db):
    action_id = _seed_action(client)
    _advance_to_previewed(client, action_id)
    executed = client.post(f"/api/v1/responses/{action_id}/execute", json={})
    assert executed.status_code == 201
    body = executed.json()
    assert body["adapter"] == SIMULATION_ADAPTER
    assert body["dry_run"] is True
    assert body["would_execute"] is False
    assert body["result"] == "SIMULATED"
    assert body["policy_version"] == "1.0.0"
    assert "No real action was executed" in body["explanation"]
    assert "SIMULATED" in body["explanation"] or "Simulation only" in body["explanation"]

    detail = client.get(f"/api/v1/responses/{action_id}").json()
    assert detail["status"] == "READY_FOR_EXECUTION"
    assert detail["execution_status"] == "SIMULATED"
    assert detail["execution"]["id"] == body["id"]
    events = [entry["event"] for entry in detail["audit"]]
    assert events == [
        "ACTION_PROPOSED",
        "ACTION_APPROVED",
        "DRY_RUN_COMPLETED",
        "EXECUTION_REQUESTED",
        "EXECUTION_COMPLETED",
    ]


def test_repeated_execution_idempotent(client, clean_db):
    action_id = _seed_action(client)
    _advance_to_previewed(client, action_id)
    first = client.post(f"/api/v1/responses/{action_id}/execute", json={})
    assert first.status_code == 201
    second = client.post(f"/api/v1/responses/{action_id}/execute", json={})
    assert second.status_code == 200
    assert second.json() == first.json()
    from app.database import session as session_module
    from app.models.responses import ResponseExecution

    db = session_module.get_session_factory()()
    try:
        rows = db.query(ResponseExecution).filter_by(action_id=action_id).all()
        assert len(rows) == 1
    finally:
        db.close()


def test_simulation_executor_is_pure_and_allowlisted():
    executor = get_executor(SIMULATION_ADAPTER)
    assert isinstance(executor, SimulationResponseExecutor)

    class _Fake:
        id = "a" * 64
        action_type = "BLOCK_IP"
        target_type = "IP"
        target_reference = "203.0.113.9"

    first = executor.execute(_Fake())
    second = executor.execute(_Fake())
    assert first["would_execute"] is False
    assert first["result"] == "SIMULATED"
    assert first["dry_run"] is True
    assert first["adapter"] == SIMULATION_ADAPTER
    first.pop("simulated_at")
    second.pop("simulated_at")
    assert first == second  # deterministic apart from the generation timestamp

    import pytest

    with pytest.raises(KeyError):
        get_executor("real-firewall")


def test_no_os_or_network_side_effects():
    """AST-level proof for the new Step 13 modules (established pattern)."""
    import ast as _ast
    import inspect as _inspect

    import app.services.response_executors as executors
    import app.services.response_policy as policy

    for module in (executors, policy):
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
