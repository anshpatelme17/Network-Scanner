"""Controlled response foundation tests (Step 18, safe actions only).

Covers: creation, invalid action types, missing incidents/targets,
retrieval, approval, rejection, valid/invalid transitions,
cancellation, dry-run previews, safe execution, idempotency, replay
prevention, audit trail, failure handling, actor identity, incident
response listing, migration, and structural security — without
weakening any Steps 1–17 test.
"""

import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "correlation"


def _seed_incident(client, first="chain_a_1.json", second="chain_a_2.json", exclude=None):
    """One incident from an event pair (manual creation path)."""
    for name in (first, second):
        payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
        assert client.post("/api/v1/events", json=payload).status_code in (200, 201)
    client.post("/api/v1/correlations/recompute")
    items = client.get("/api/v1/correlations").json()["items"]
    correlation_id = next(item["id"] for item in items if item["id"] not in (exclude or ()))
    incident = client.post("/api/v1/incidents", json={"correlation_id": correlation_id})
    assert incident.status_code == 201
    return incident.json()


def _propose(client, incident_id, action_type="REVIEW", reason="review needed"):
    return client.post(
        f"/api/v1/incidents/{incident_id}/responses",
        json={"action_type": action_type, "reason": reason, "requested_by": "analyst"},
    )


def _approve(client, action_id, actor="lead"):
    return client.post(f"/api/v1/responses/{action_id}/approve", json={"actor": actor})


def _execute(client, action_id, actor="lead"):
    return client.post(f"/api/v1/responses/{action_id}/execute", json={"actor": actor})


def test_response_creation(client, clean_db):
    incident = _seed_incident(client)
    created = _propose(client, incident["id"])
    assert created.status_code == 201
    body = created.json()
    assert body["incident_id"] == incident["id"]
    assert body["action_type"] == "REVIEW"
    assert body["target_type"] == "INCIDENT"
    assert body["target_reference"] == incident["id"]
    assert body["status"] == "PROPOSED"
    assert body["dry_run"] is True
    assert body["approved_by"] is None
    assert body["result_summary"] is None
    assert body["failure_reason"] is None


def test_invalid_action_type(client, clean_db):
    incident = _seed_incident(client)
    dangerous = _propose(client, incident["id"], action_type="BLOCK_IP")
    assert dangerous.status_code == 422
    assert dangerous.json()["error"]["code"] == "INVALID_PROPOSAL"
    unknown = _propose(client, incident["id"], action_type="REBOOT_EVERYTHING")
    assert unknown.status_code == 422
    malformed = client.post(f"/api/v1/incidents/{incident['id']}/responses", json={"reason": "x"})
    assert malformed.status_code == 422


def test_missing_incident(client, clean_db):
    missing = _propose(client, "nope")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "INCIDENT_NOT_FOUND"
    missing_list = client.get("/api/v1/incidents/nope/responses")
    assert missing_list.status_code == 404
    assert missing_list.json()["error"]["code"] == "INCIDENT_NOT_FOUND"
    missing_action = client.get("/api/v1/responses/nope")
    assert missing_action.status_code == 404
    assert missing_action.json()["error"]["code"] == "RESPONSE_NOT_FOUND"


def test_target_validation_preserved(client, clean_db):
    incident = _seed_incident(client)
    empty_target = client.post(
        "/api/v1/responses",
        json={
            "incident_id": incident["id"],
            "action_type": "BLOCK_IP",
            "target_type": "IP",
            "target_reference": "   ",
            "reason": "needs a target",
            "requested_by": "analyst",
        },
    )
    assert empty_target.status_code == 422
    bad_ip = client.post(
        "/api/v1/responses",
        json={
            "incident_id": incident["id"],
            "action_type": "BLOCK_IP",
            "target_type": "IP",
            "target_reference": "not-an-ip",
            "reason": "needs a target",
            "requested_by": "analyst",
        },
    )
    assert bad_ip.status_code == 422


def test_response_retrieval(client, clean_db):
    incident = _seed_incident(client)
    action_id = _propose(client, incident["id"]).json()["id"]
    detail = client.get(f"/api/v1/responses/{action_id}").json()
    assert detail["id"] == action_id
    assert detail["audit"][0]["event"] == "ACTION_PROPOSED"
    assert detail["execution"] is None


def test_approval_records_actor_once(client, clean_db):
    incident = _seed_incident(client)
    action_id = _propose(client, incident["id"]).json()["id"]
    approved = _approve(client, action_id, actor="lead")
    assert approved.status_code == 200
    body = approved.json()
    assert body["status"] == "APPROVED"
    assert body["approved_by"] == "lead"
    assert body["approved_at"] is not None
    # Approval identity cannot be silently rewritten: no re-entry to APPROVED.
    again = _approve(client, action_id, actor="someone-else")
    assert again.status_code == 409
    assert client.get(f"/api/v1/responses/{action_id}").json()["approved_by"] == "lead"


def test_rejection_blocks_execution(client, clean_db):
    incident = _seed_incident(client)
    action_id = _propose(client, incident["id"]).json()["id"]
    rejected = client.post(f"/api/v1/responses/{action_id}/reject", json={"actor": "lead"})
    assert rejected.json()["status"] == "REJECTED"
    denied = _execute(client, action_id)
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "EXECUTION_DENIED"


def test_review_lifecycle_to_completed(client, clean_db):
    incident = _seed_incident(client)
    action_id = _propose(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).json()["status"] == "APPROVED"
    executed = _execute(client, action_id)
    assert executed.status_code == 201
    body = executed.json()
    assert body["result"] == "COMPLETED"
    assert body["adapter"] == "safe-record"
    assert body["would_execute"] is True
    assert body["dry_run"] is True
    assert "No external system change was performed" in body["explanation"]
    action = client.get(f"/api/v1/responses/{action_id}").json()
    assert action["status"] == "COMPLETED"
    assert action["started_at"] is not None
    assert action["completed_at"] is not None
    assert "reviewed" in (action["result_summary"] or "")
    # REVIEW touches no incident state: the record is only read.
    assert client.get(f"/api/v1/incidents/{incident['id']}").json()["status"] == "OPEN"


def test_invalid_transitions_rejected(client, clean_db):
    incident = _seed_incident(client)
    action_id = _propose(client, incident["id"]).json()["id"]
    # Execution without approval is refused, not run.
    refused = _execute(client, action_id)
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "REQUIRE_APPROVAL"
    # Unknown status values are rejected by validation.
    bad = client.post(
        f"/api/v1/incidents/{incident['id']}/responses",
        json={"action_type": "REVIEW", "requested_by": "analyst"},
    )
    assert bad.status_code == 422


def test_cancellation(client, clean_db):
    incident = _seed_incident(client)
    action_id = _propose(client, incident["id"]).json()["id"]
    cancelled = client.post(f"/api/v1/responses/{action_id}/cancel", json={"actor": "lead"})
    assert cancelled.json()["status"] == "CANCELLED"
    denied = _execute(client, action_id)
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "EXECUTION_DENIED"
    # Terminal states accept no further moves.
    again = client.post(f"/api/v1/responses/{action_id}/cancel", json={"actor": "lead"})
    assert again.status_code == 409


def test_dry_run_preview_changes_nothing(client, clean_db):
    incident = _seed_incident(client)
    action_id = _propose(client, incident["id"], action_type="ACKNOWLEDGE").json()["id"]
    preview = client.post(f"/api/v1/responses/{action_id}/dry-run")
    assert preview.status_code == 200
    body = preview.json()
    assert body["would_execute"] is False
    assert body["dry_run"] is True
    assert "No action was executed" in body["explanation"]
    # Preview only advances the preview state; the incident is untouched.
    assert client.get(f"/api/v1/incidents/{incident['id']}").json()["status"] == "OPEN"
    # A previewed safe action remains executable after approval.
    assert _approve(client, action_id).json()["status"] == "APPROVED"
    executed = _execute(client, action_id)
    assert executed.json()["result"] == "COMPLETED"
    assert client.get(f"/api/v1/incidents/{incident['id']}").json()["status"] == "ACKNOWLEDGED"


def test_acknowledge_and_close_effects(client, clean_db):
    incident = _seed_incident(client)
    ack_id = _propose(client, incident["id"], action_type="ACKNOWLEDGE").json()["id"]
    _approve(client, ack_id)
    assert _execute(client, ack_id).json()["result"] == "COMPLETED"
    assert client.get(f"/api/v1/incidents/{incident['id']}").json()["status"] == "ACKNOWLEDGED"

    mark_id = _propose(client, incident["id"], action_type="MARK_FOR_INVESTIGATION").json()["id"]
    _approve(client, mark_id)
    assert _execute(client, mark_id).json()["result"] == "COMPLETED"
    assert client.get(f"/api/v1/incidents/{incident['id']}").json()["status"] == "INVESTIGATING"

    close_id = _propose(client, incident["id"], action_type="CLOSE").json()["id"]
    _approve(client, close_id)
    assert _execute(client, close_id).json()["result"] == "COMPLETED"
    closed = client.get(f"/api/v1/incidents/{incident['id']}").json()
    assert closed["status"] == "CLOSED"
    assert closed["resolved_at"] is not None


def test_collect_evidence_reports_references(client, clean_db):
    incident = _seed_incident(client)
    action_id = _propose(client, incident["id"], action_type="COLLECT_EVIDENCE").json()["id"]
    _approve(client, action_id)
    body = _execute(client, action_id).json()
    assert body["result"] == "COMPLETED"
    assert "evidence reference(s)" in body["explanation"]
    assert "No external system change was performed" in body["explanation"]


def test_duplicate_proposal_is_idempotent(client, clean_db):
    incident = _seed_incident(client)
    first = _propose(client, incident["id"])
    assert first.status_code == 201
    second = _propose(client, incident["id"])
    assert second.status_code == 200
    assert second.json()["id"] == first.json()["id"]
    listed = client.get(f"/api/v1/incidents/{incident['id']}/responses").json()
    assert listed["total"] == 1


def test_repeated_execution_replays_stored_result(client, clean_db):
    incident = _seed_incident(client)
    action_id = _propose(client, incident["id"]).json()["id"]
    _approve(client, action_id)
    first = _execute(client, action_id)
    assert first.status_code == 201
    second = _execute(client, action_id)
    assert second.status_code == 200  # replay, not a second execution
    assert second.json()["id"] == first.json()["id"]
    audits = client.get(f"/api/v1/responses/{action_id}").json()["audit"]
    completions = [entry for entry in audits if entry["event"] == "EXECUTION_COMPLETED"]
    assert len(completions) == 1
    assert client.get(f"/api/v1/responses/{action_id}").json()["status"] == "COMPLETED"


def test_audit_trail_covers_lifecycle(client, clean_db):
    incident = _seed_incident(client)
    action_id = _propose(client, incident["id"]).json()["id"]
    _approve(client, action_id)
    _execute(client, action_id)
    audits = client.get(f"/api/v1/responses/{action_id}").json()["audit"]
    events = [entry["event"] for entry in audits]
    assert events == [
        "ACTION_PROPOSED",
        "ACTION_APPROVED",
        "EXECUTION_STARTED",
        "EXECUTION_COMPLETED",
    ]
    for entry in audits:
        assert entry["actor"]
        assert entry["policy_version"] == "1.0.0"


def test_failure_handling_without_leak(client, clean_db):
    incident = _seed_incident(client)
    # ACKNOWLEDGE is only valid from OPEN; pre-acknowledge the incident
    # through the incident API so the safe effect honestly fails.
    client.post(f"/api/v1/incidents/{incident['id']}/status", json={"status": "ACKNOWLEDGED"})
    action_id = _propose(client, incident["id"], action_type="ACKNOWLEDGE").json()["id"]
    _approve(client, action_id)
    executed = _execute(client, action_id)
    assert executed.status_code == 201
    assert executed.json()["result"] == "FAILED"
    action = client.get(f"/api/v1/responses/{action_id}").json()
    assert action["status"] == "FAILED"
    assert "ACKNOWLEDGED" in (action["failure_reason"] or "")
    assert action["completed_at"] is not None
    # No 500, no traceback, incident untouched by the failed effect.
    assert client.get(f"/api/v1/incidents/{incident['id']}").json()["status"] == "ACKNOWLEDGED"


def test_incident_response_listing(client, clean_db):
    incident = _seed_incident(client)
    other = _seed_incident(
        client, "chain_d_1.json", "chain_d_2.json", exclude=(incident["correlation_id"],)
    )
    assert other["id"] != incident["id"]
    _propose(client, incident["id"], action_type="REVIEW")
    _propose(client, incident["id"], action_type="CLOSE")
    _propose(client, other["id"], action_type="REVIEW")
    listed = client.get(f"/api/v1/incidents/{incident['id']}/responses").json()
    assert listed["total"] == 2
    assert {item["incident_id"] for item in listed["items"]} == {incident["id"]}
    filtered = client.get(
        f"/api/v1/incidents/{incident['id']}/responses", params={"status": "PROPOSED"}
    ).json()
    assert filtered["total"] == 2
    bad_filter = client.get(
        f"/api/v1/incidents/{incident['id']}/responses", params={"status": "NOPE"}
    )
    assert bad_filter.status_code == 422


def test_simulation_path_unchanged(client, clean_db):
    incident = _seed_incident(client)
    created = client.post(
        "/api/v1/responses",
        json={
            "incident_id": incident["id"],
            "action_type": "BLOCK_IP",
            "target_type": "IP",
            "target_reference": "203.0.113.9",
            "reason": "simulation only",
            "requested_by": "analyst",
        },
    )
    assert created.status_code == 201
    action_id = created.json()["id"]
    _approve(client, action_id)
    client.post(f"/api/v1/responses/{action_id}/dry-run")
    executed = _execute(client, action_id)
    assert executed.json()["result"] == "SIMULATED"
    assert executed.json()["adapter"] == "simulation"
    assert executed.json()["would_execute"] is False


def test_migration_includes_step18_columns(tmp_path, monkeypatch):
    from sqlalchemy import create_engine, inspect

    from alembic import command
    from alembic.config import Config

    db_file = tmp_path / "mig18.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    config = Config(str(Path(__file__).parent.parent / "alembic.ini"))
    config.set_main_option("script_location", str(Path(__file__).parent.parent / "alembic"))
    command.upgrade(config, "head")
    inspector = inspect(create_engine(f"sqlite:///{db_file}"))
    columns = {column["name"] for column in inspector.get_columns("response_actions")}
    assert {
        "approved_by",
        "started_at",
        "completed_at",
        "failure_reason",
        "result_summary",
    } <= columns


def test_security_regression_step18_modules():
    """AST-level proof for the Step 18 modules (established pattern)."""
    import ast as _ast
    import inspect as _inspect

    import app.api.v1.endpoints.incidents as incident_endpoints
    import app.api.v1.endpoints.responses as response_endpoints
    import app.services.response_policy as policy
    import app.services.response_service as service

    for module in (service, policy, response_endpoints, incident_endpoints):
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
