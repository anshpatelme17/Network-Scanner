"""Controlled defensive-response governance tests (Step 30).

Covers the Step 30 contract end to end without weakening Steps 1-29:
action creation, allow-list validation, evidence-backed target
validation, provider dry run, RBAC separation of duties, approval,
rejection, cancellation, expiration, execution, provider success and
controlled failure, rollback (supported and honestly unsupported),
idempotency and duplicate-execution prevention, invalid transitions,
authorization-bypass attempts, secret redaction, the audit trail, mock
provider behaviour, risk/policy integration, and structural (AST) proof
that no command execution or arbitrary transport can exist here.
"""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "correlation"

# A destination address that the seeded chain A events genuinely
# observed, and one that appears in no stored event at all.
OBSERVED_IP = "198.51.100.23"
UNOBSERVED_IP = "203.0.113.250"
OBSERVED_SOURCE_IP = "192.0.2.10"
OBSERVED_ACCOUNT = "chain-user"


def _post_event(client, **overrides):
    payload = {
        "source_type": "WAZUH",
        "source_name": "step30-sensor",
        "event_type": "AUTH_FAILURE",
        "severity": "HIGH",
        "title": "Step 30 chain event",
        "event_time": "2026-09-27T06:00:00Z",
        "source_ip": OBSERVED_SOURCE_IP,
        "destination_ip": OBSERVED_IP,
        "status": "failed",
        "action": "logon",
        "username": OBSERVED_ACCOUNT,
        "external_event_id": overrides.pop("external_event_id"),
    }
    payload.update(overrides)
    assert client.post("/api/v1/events", json=payload).status_code in (200, 201)
    return payload


def _seed(client):
    """One incident whose correlation evidence covers an IP and accounts.

    The Step 24 multi-source-target rule needs at least two distinct
    source types sharing one destination inside its window, so the seed
    posts three events from three sources. Everything the Step 30 target
    proof reads therefore comes from stored correlation evidence rather
    than from anything the request supplies.
    """
    from app.services.response_providers import FAILURE_SENTINEL

    for index, source in enumerate(("WAZUH", "SURICATA", "ZEEK"), start=1):
        _post_event(
            client,
            source_type=source,
            external_event_id=f"step30-evt-{index}",
            event_time=f"2026-09-27T06:0{index}:00Z",
            # The documented provider-failure sentinel is a genuinely
            # observed account, so its request passes target validation
            # and evidence checking and fails at the provider instead.
            username=FAILURE_SENTINEL if index == 3 else OBSERVED_ACCOUNT,
        )
    assert client.post("/api/v1/correlations/recompute").status_code == 200
    items = client.get("/api/v1/correlations").json()["items"]
    assert items, "seed must produce a Step 24 correlation"
    incident = client.post("/api/v1/incidents", json={"correlation_id": items[0]["id"]})
    assert incident.status_code == 201
    return incident.json()


def _request(client, incident_id, **overrides):
    body = {
        "incident_id": incident_id,
        "action_type": "BLOCK_INDICATOR",
        "target_type": "IP",
        "target_reference": OBSERVED_IP,
        "reason": "Confirmed malicious destination in incident evidence.",
        "requested_by": "analyst-1",
    }
    body.update(overrides)
    return client.post("/api/v1/responses/controlled", json=body)


def _approve(client, action_id, actor="operator-1"):
    return client.post(f"/api/v1/responses/{action_id}/approve", json={"actor": actor})


# ---------------------------------------------------------------------------
# 1-3: creation, allow-list, target validation
# ---------------------------------------------------------------------------


def test_controlled_action_creation(client, clean_db):
    incident = _seed(client)
    created = _request(client, incident["id"])
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["incident_id"] == incident["id"]
    assert body["action_type"] == "BLOCK_INDICATOR"
    assert body["status"] == "PENDING_APPROVAL"
    assert body["provider"] == "MOCK"
    assert body["approval_required"] is True
    assert body["dry_run"] is True
    assert body["target_evidence"], "target proof must be server-derived evidence ids"
    assert body["expires_at"] is not None
    assert body["approved_by"] is None
    assert body["result_summary"] is None


def test_allowlist_rejects_invented_action_type(client, clean_db):
    incident = _seed(client)
    for invented in ("WIPE_ENDPOINT", "FORMAT_DISK", "RUN_COMMAND", "SHUTDOWN_HOST"):
        body = _request(client, incident["id"], action_type=invented)
        assert body.status_code == 422, invented
        assert body.json()["error"]["code"] == "ACTION_NOT_PERMITTED"


def test_allowlist_rejects_action_target_mismatch(client, clean_db):
    incident = _seed(client)
    # An account action cannot be pointed at an IP, and an indicator
    # block cannot be pointed at an account.
    mismatch = _request(client, incident["id"], action_type="DISABLE_ACCOUNT", target_type="IP")
    assert mismatch.status_code == 422
    assert mismatch.json()["error"]["code"] == "TARGET_NOT_SUPPORTED"
    other = _request(client, incident["id"], target_type="ACCOUNT")
    assert other.status_code == 422
    assert other.json()["error"]["code"] == "TARGET_NOT_SUPPORTED"


def test_target_must_be_supported_by_stored_evidence(client, clean_db):
    incident = _seed(client)
    response = _request(client, incident["id"], target_reference=UNOBSERVED_IP)
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "TARGET_NOT_SUPPORTED"
    assert UNOBSERVED_IP in body["error"]["message"]
    # Nothing was created for a refused target.
    assert client.get("/api/v1/responses").json()["total"] == 0


def test_account_target_uses_observed_identity(client, clean_db):
    incident = _seed(client)
    accepted = _request(
        client,
        incident["id"],
        action_type="DISABLE_ACCOUNT",
        target_type="ACCOUNT",
        target_reference=OBSERVED_ACCOUNT,
    )
    assert accepted.status_code == 201, accepted.text
    assert accepted.json()["target_evidence"]
    refused = _request(
        client,
        incident["id"],
        action_type="DISABLE_ACCOUNT",
        target_type="ACCOUNT",
        target_reference="never-seen-user",
    )
    assert refused.status_code == 422


def test_hash_target_is_honestly_unsupported(client, clean_db):
    # Steps 1-29 store no indicator-hash field, so a hash target cannot
    # be evidenced. The platform must say so rather than match loosely.
    incident = _seed(client)
    response = _request(
        client,
        incident["id"],
        action_type="BLOCK_INDICATOR",
        target_type="HASH",
        target_reference="a" * 64,
    )
    assert response.status_code == 422
    assert "TARGET_NOT_SUPPORTED" == response.json()["error"]["code"]


# ---------------------------------------------------------------------------
# 4: dry run
# ---------------------------------------------------------------------------


def test_provider_dry_run_validates_and_performs_nothing(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    preview = client.post(f"/api/v1/responses/{action_id}/provider-preview")
    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert body["dry_run"] is True
    assert body["executed"] is False
    assert body["would_execute"] is True
    assert body["result"] == "SIMULATED"
    assert body["provider"] == "MOCK"
    assert "no firewall" in body["explanation"].lower()
    assert "No external" not in body["explanation"] or "was contacted" in body["explanation"]
    # The preview changed nothing about the request's state.
    detail = client.get(f"/api/v1/responses/{action_id}").json()
    assert detail["status"] == "PENDING_APPROVAL"
    assert detail["execution"] is None
    assert detail["rollback"] is None


def test_dry_run_is_audited(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    client.post(f"/api/v1/responses/{action_id}/provider-preview")
    events = [row["event"] for row in client.get(f"/api/v1/responses/{action_id}").json()["audit"]]
    assert "RESPONSE_DRY_RUN" in events


# ---------------------------------------------------------------------------
# 5-8: RBAC, approval, rejection, cancellation
# ---------------------------------------------------------------------------


def test_separation_of_duties_blocks_self_approval(client, clean_db):
    from tests.test_auth import _admin_headers, _auth_header, _seed_incident_auth

    incident = _seed_incident_auth(client, _admin_headers(client))
    analyst = _auth_header(client, "analyst-b", "analyst-pass-5678", roles=("SECURITY_ANALYST",))
    operator = _auth_header(client, "operator-b", "operator-pass-1234", roles=("OPERATOR",))

    # An analyst holds REQUEST_RESPONSE but not APPROVE_RESPONSE.
    created = client.post(
        "/api/v1/responses/controlled",
        json={
            "incident_id": incident["id"],
            "action_type": "BLOCK_INDICATOR",
            "target_type": "IP",
            "target_reference": OBSERVED_IP,
            "reason": "evidence-backed block",
            "requested_by": "analyst-b",
        },
        headers=analyst,
    )
    assert created.status_code == 201, created.text
    action_id = created.json()["id"]
    # The token identity wins over the body, so this is analyst-b acting.
    assert created.json()["requested_by"] == "analyst-b"
    denied = client.post(
        f"/api/v1/responses/{action_id}/approve", json={"actor": "operator-b"}, headers=analyst
    )
    assert denied.status_code == 403
    assert "APPROVE_RESPONSE" in denied.json()["error"]["message"]
    # A different operator with the permission may approve it.
    allowed = client.post(
        f"/api/v1/responses/{action_id}/approve", json={"actor": "operator-b"}, headers=operator
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["approved_by"] == "operator-b"

    # Now the operator raises their own request and tries to approve it.
    own = client.post(
        "/api/v1/responses/controlled",
        json={
            "incident_id": incident["id"],
            "action_type": "BLOCK_INDICATOR",
            "target_type": "IP",
            "target_reference": OBSERVED_SOURCE_IP,
            "reason": "self approval attempt",
            "requested_by": "operator-b",
        },
        headers=operator,
    )
    assert own.status_code == 201, own.text
    own_id = own.json()["id"]
    assert own.json()["requested_by"] == "operator-b"
    self_approve = client.post(
        f"/api/v1/responses/{own_id}/approve", json={"actor": "mallory"}, headers=operator
    )
    assert self_approve.status_code == 409
    assert "different user" in self_approve.json()["error"]["message"]


def test_viewer_cannot_request_and_analyst_cannot_approve(client, clean_db):
    from tests.test_auth import _auth_header

    viewer = _auth_header(client, "viewer-x", "viewer-pass-1234")
    refused = client.post(
        "/api/v1/responses/controlled",
        json={
            "incident_id": "whatever",
            "action_type": "BLOCK_INDICATOR",
            "target_type": "IP",
            "target_reference": OBSERVED_IP,
            "reason": "nope",
            "requested_by": "viewer-x",
        },
        headers=viewer,
    )
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "PERMISSION_DENIED"
    assert "REQUEST_RESPONSE" in refused.json()["error"]["message"]


def test_anonymous_is_401(client, clean_db):
    from tests.test_auth import _admin_headers

    _admin_headers(client)  # enforcement active
    assert client.get("/api/v1/responses").status_code == 401
    assert client.post("/api/v1/responses/controlled", json={}).status_code == 401


def test_approval_records_approver_and_expiry(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    approved = _approve(client, action_id)
    assert approved.status_code == 200, approved.text
    body = approved.json()
    assert body["status"] == "APPROVED"
    assert body["approved_by"] == "operator-1"
    assert body["approved_at"] is not None
    assert body["expires_at"] is not None
    # Approving again is a conflict, and the approver is never rewritten.
    again = _approve(client, action_id)
    assert again.status_code == 409
    assert client.get(f"/api/v1/responses/{action_id}").json()["approved_by"] == "operator-1"


def test_rejection_blocks_execution(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    rejected = client.post(f"/api/v1/responses/{action_id}/reject", json={"actor": "operator-1"})
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "REJECTED"
    executed = client.post(f"/api/v1/responses/{action_id}/execute", json={"actor": "operator-1"})
    assert executed.status_code == 409
    assert executed.json()["error"]["code"] == "INVALID_TRANSITION"


def test_cancellation(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    cancelled = client.post(f"/api/v1/responses/{action_id}/cancel", json={"actor": "analyst-1"})
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "CANCELLED"
    # A cancelled request can never be approved or executed afterwards.
    assert _approve(client, action_id).status_code == 409
    assert (
        client.post(
            f"/api/v1/responses/{action_id}/execute", json={"actor": "operator-1"}
        ).status_code
        == 409
    )
    assert (
        client.post(
            f"/api/v1/responses/{action_id}/cancel", json={"actor": "analyst-1"}
        ).status_code
        == 409
    )


# ---------------------------------------------------------------------------
# 9: expiration / TTL
# ---------------------------------------------------------------------------


def test_ttl_is_bounded_by_the_server_ceiling(client, clean_db, monkeypatch):
    from app.core.config import get_settings

    incident = _seed(client)
    monkeypatch.setenv("RESPONSE_MAX_TTL_MINUTES", "120")
    get_settings.cache_clear()
    try:
        body = _request(client, incident["id"], ttl_minutes=100000).json()
        created = datetime.fromisoformat(body["created_at"])
        expires = datetime.fromisoformat(body["expires_at"])
        # Clamped down to the server ceiling, never honoured as asked.
        assert timedelta(0) < (expires - created) <= timedelta(minutes=121)
    finally:
        get_settings.cache_clear()


def test_expired_request_cannot_be_approved_or_executed(client, clean_db, monkeypatch):
    from app.models.responses import ResponseAction
    from app.services.response_governance import expire_due

    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]

    from app.database.session import get_session_factory

    db = get_session_factory()()
    try:
        row = db.get(ResponseAction, action_id)
        row.expires_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=1)
        db.commit()
        expired = expire_due(db, incident["id"])
        assert action_id in expired
    finally:
        db.close()

    detail = client.get(f"/api/v1/responses/{action_id}").json()
    assert detail["status"] == "EXPIRED"
    events = [row["event"] for row in detail["audit"]]
    assert "RESPONSE_EXPIRED" in events
    assert _approve(client, action_id).status_code == 409
    assert (
        client.post(f"/api/v1/responses/{action_id}/execute", json={"actor": "op"}).status_code
        == 409
    )


def test_expiry_is_enforced_on_read_paths(client, clean_db):
    from app.database.session import get_session_factory
    from app.models.responses import ResponseAction

    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    db = get_session_factory()()
    try:
        row = db.get(ResponseAction, action_id)
        row.expires_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()
    # No explicit expire call: the list read retires the overdue request.
    listed = client.get("/api/v1/responses", params={"status": "EXPIRED"}).json()
    assert listed["total"] == 1
    assert listed["items"][0]["id"] == action_id


# ---------------------------------------------------------------------------
# 10-12: execution, provider success, provider failure
# ---------------------------------------------------------------------------


def test_execution_requires_prior_approval(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    premature = client.post(f"/api/v1/responses/{action_id}/execute", json={"actor": "operator-1"})
    assert premature.status_code == 409
    assert premature.json()["error"]["code"] == "INVALID_TRANSITION"
    assert client.get(f"/api/v1/responses/{action_id}").json()["execution"] is None


def test_mock_provider_execution_records_platform_side_only(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    _approve(client, action_id, actor="operator-2")
    executed = client.post(f"/api/v1/responses/{action_id}/execute", json={"actor": "operator-2"})
    assert executed.status_code == 201, executed.text
    body = executed.json()
    assert body["adapter"] == "MOCK"
    assert body["result"] == "COMPLETED"
    assert body["would_execute"] is True
    assert "no firewall" in body["explanation"].lower()
    detail = client.get(f"/api/v1/responses/{action_id}").json()
    assert detail["status"] == "COMPLETED"
    assert detail["started_at"] is not None
    assert detail["completed_at"] is not None
    assert detail["rollback_supported"] is True
    assert detail["rollback_reference"]


def test_provider_controlled_failure_is_recorded_honestly(client, clean_db):
    from app.services.response_providers import FAILURE_SENTINEL

    incident = _seed(client)
    # A valid, evidenced account target that the mock provider is
    # documented to fail on, so the FAILED path is testable.
    action_id = _request(
        client,
        incident["id"],
        action_type="DISABLE_ACCOUNT",
        target_type="ACCOUNT",
        target_reference=FAILURE_SENTINEL,
    ).json()["id"]
    _approve(client, action_id, actor="operator-2")
    executed = client.post(f"/api/v1/responses/{action_id}/execute", json={"actor": "operator-2"})
    assert executed.status_code == 201, executed.text
    assert executed.json()["result"] == "FAILED"
    detail = client.get(f"/api/v1/responses/{action_id}").json()
    assert detail["status"] == "FAILED"
    assert detail["failure_reason"]
    # A failed action must not advertise a rollback it cannot perform.
    assert detail["rollback_supported"] is False
    assert detail["rollback_reference"] is None
    events = [row["event"] for row in detail["audit"]]
    assert "RESPONSE_EXECUTION_FAILED" in events
    # And rollback reports honestly rather than fabricating prior state.
    rolled = client.post(f"/api/v1/responses/{action_id}/rollback", json={"actor": "op-3"})
    assert rolled.status_code == 409


# ---------------------------------------------------------------------------
# 11-13: rollback
# ---------------------------------------------------------------------------


def test_rollback_of_completed_action(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    _approve(client, action_id, actor="operator-2")
    client.post(f"/api/v1/responses/{action_id}/execute", json={"actor": "operator-2"})
    rolled = client.post(f"/api/v1/responses/{action_id}/rollback", json={"actor": "operator-3"})
    assert rolled.status_code == 200, rolled.text
    body = rolled.json()
    assert body["result"] == "COMPLETED"
    assert "rolled back" in body["explanation"]
    detail = client.get(f"/api/v1/responses/{action_id}").json()
    assert detail["status"] == "ROLLED_BACK"
    assert detail["rollback"]["id"] == body["id"]
    events = [row["event"] for row in detail["audit"]]
    assert "RESPONSE_ROLLBACK_STARTED" in events
    assert "RESPONSE_ROLLBACK_COMPLETED" in events


def test_rollback_is_idempotent(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    _approve(client, action_id, actor="operator-2")
    client.post(f"/api/v1/responses/{action_id}/execute", json={"actor": "operator-2"})
    first = client.post(f"/api/v1/responses/{action_id}/rollback", json={"actor": "op-3"})
    second = client.post(f"/api/v1/responses/{action_id}/rollback", json={"actor": "op-3"})
    assert first.status_code == second.status_code == 200
    assert first.json()["id"] == second.json()["id"]


def test_rollback_rejected_before_execution(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    _approve(client, action_id, actor="operator-2")
    refused = client.post(f"/api/v1/responses/{action_id}/rollback", json={"actor": "op-3"})
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "INVALID_TRANSITION"


def test_rollback_after_rollback_replays_and_cannot_be_re_executed(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    _approve(client, action_id, actor="operator-2")
    client.post(f"/api/v1/responses/{action_id}/execute", json={"actor": "operator-2"})
    first = client.post(f"/api/v1/responses/{action_id}/rollback", json={"actor": "op-3"})
    assert first.status_code == 200
    # A repeat rollback replays the stored record rather than rolling
    # back twice.
    second = client.post(f"/api/v1/responses/{action_id}/rollback", json={"actor": "op-3"})
    assert second.status_code == 200
    assert second.json()["id"] == first.json()["id"]
    assert client.get(f"/api/v1/responses/{action_id}").json()["status"] == "ROLLED_BACK"
    # The rolled-back action can never be performed again.
    again = client.post(f"/api/v1/responses/{action_id}/execute", json={"actor": "op-2"})
    assert again.status_code == 409
    assert "rolled back" in again.json()["error"]["message"]


# ---------------------------------------------------------------------------
# 12: idempotency / duplicate execution
# ---------------------------------------------------------------------------


def test_repeated_execution_replays_instead_of_acting_twice(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    _approve(client, action_id, actor="operator-2")
    first = client.post(f"/api/v1/responses/{action_id}/execute", json={"actor": "operator-2"})
    assert first.status_code == 201
    second = client.post(f"/api/v1/responses/{action_id}/execute", json={"actor": "operator-2"})
    assert second.status_code == 200
    assert second.json()["id"] == first.json()["id"]
    events = [row["event"] for row in client.get(f"/api/v1/responses/{action_id}").json()["audit"]]
    # Exactly one completion, no matter how many execute calls arrive.
    assert events.count("RESPONSE_EXECUTION_COMPLETED") == 1


def test_duplicate_request_is_idempotent(client, clean_db):
    incident = _seed(client)
    first = _request(client, incident["id"])
    second = _request(client, incident["id"])
    assert first.status_code == 201
    assert second.status_code == 200
    assert first.json()["id"] == second.json()["id"]
    assert client.get("/api/v1/responses").json()["total"] == 1


def test_idempotency_key_header_is_accepted_and_bounded(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    _approve(client, action_id, actor="operator-2")
    headers = {"Idempotency-Key": "step30-attempt-1"}
    first = client.post(
        f"/api/v1/responses/{action_id}/execute", json={"actor": "op-2"}, headers=headers
    )
    second = client.post(
        f"/api/v1/responses/{action_id}/execute", json={"actor": "op-2"}, headers=headers
    )
    assert first.status_code == 201
    assert second.status_code == 200
    assert first.json()["id"] == second.json()["id"]


# ---------------------------------------------------------------------------
# 13/17: concurrency and invalid transitions
# ---------------------------------------------------------------------------


def test_concurrent_execution_records_exactly_one_execution(client, clean_db):
    from sqlalchemy import func
    from sqlalchemy import select as sa_select

    from app.database.session import get_session_factory
    from app.models.responses import ResponseExecution
    from app.services import response_governance

    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    _approve(client, action_id, actor="operator-2")
    session = get_session_factory()()
    try:
        # Two independent sessions attempt the same execution. The
        # UNIQUE constraint on response_executions.action_id plus the
        # stored-status guard must mean only one provider call happens.
        results = []
        for _ in range(2):
            other = get_session_factory()()
            try:
                row, created = response_governance.execute(other, action_id, "operator-2")
                results.append((row.id, created))
            except Exception:
                results.append(("refused", False))
            finally:
                other.close()
        db = get_session_factory()()
        try:
            count = db.scalar(
                sa_select(func.count(ResponseExecution.id)).where(
                    ResponseExecution.action_id == action_id
                )
            )
        finally:
            db.close()
    finally:
        session.close()
    assert count == 1, results
    # At most one attempt actually performed the action; the other was
    # either refused or replayed the same stored row.
    assert sum(1 for _, created in results if created) <= 1
    assert all(item[0] == "refused" or isinstance(item[0], str) for item in results)


def test_invalid_state_transitions_return_safe_errors(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    # Reject twice.
    client.post(f"/api/v1/responses/{action_id}/reject", json={"actor": "op"})
    second = client.post(f"/api/v1/responses/{action_id}/reject", json={"actor": "op"})
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "INVALID_TRANSITION"
    # Approve after reject.
    assert _approve(client, action_id).status_code == 409
    # Execute after reject.
    assert client.post(f"/api/v1/responses/{action_id}/execute", json={}).status_code == 409


def test_execute_after_rollback_is_blocked(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    _approve(client, action_id, actor="operator-2")
    client.post(f"/api/v1/responses/{action_id}/execute", json={"actor": "op-2"})
    client.post(f"/api/v1/responses/{action_id}/rollback", json={"actor": "op-3"})
    again = client.post(f"/api/v1/responses/{action_id}/execute", json={"actor": "op-2"})
    assert again.status_code == 409


# ---------------------------------------------------------------------------
# 18-20: bypass attempts, redaction, audit
# ---------------------------------------------------------------------------


def test_client_cannot_supply_policy_provider_or_state(client, clean_db):
    incident = _seed(client)
    for extra in (
        {"provider": "FIREWALL"},
        {"command": "shutdown /s"},
        {"policy_decision": "ALLOWED_WITH_APPROVAL"},
        {"status": "APPROVED"},
        {"approved_by": "me"},
        {"risk_score": 100},
        {"approval_required": False},
        {"expires_at": "2099-01-01T00:00:00"},
    ):
        body = _request(client, incident["id"], **extra)
        assert body.status_code == 422, extra
    assert client.get("/api/v1/responses").json()["total"] == 0


def test_audit_trail_covers_the_whole_governed_lifecycle(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    client.post(f"/api/v1/responses/{action_id}/provider-preview")
    _approve(client, action_id, actor="operator-2")
    client.post(f"/api/v1/responses/{action_id}/execute", json={"actor": "operator-2"})
    client.post(f"/api/v1/responses/{action_id}/rollback", json={"actor": "operator-3"})
    rows = client.get(f"/api/v1/responses/{action_id}").json()["audit"]
    events = [row["event"] for row in rows]
    assert events == [
        "RESPONSE_REQUESTED",
        "RESPONSE_APPROVAL_REQUIRED",
        "RESPONSE_DRY_RUN",
        "RESPONSE_APPROVED",
        "RESPONSE_EXECUTION_STARTED",
        "RESPONSE_EXECUTION_COMPLETED",
        "RESPONSE_ROLLBACK_STARTED",
        "RESPONSE_ROLLBACK_COMPLETED",
    ]
    for row in rows:
        assert row["actor"]
        assert row["policy_version"] == "1.0.0"
    approver_row = next(r for r in rows if r["event"] == "RESPONSE_APPROVED")
    assert approver_row["actor"] == "operator-2"
    assert approver_row["new_status"] == "APPROVED"


def test_audit_and_provider_output_never_leak_secrets(client, clean_db):
    incident = _seed(client)
    # The operator's own free text is echoed back verbatim (the platform
    # does not silently rewrite what a human typed), so the guarantee
    # under test is narrower and precise: nothing the platform RECORDS or
    # GENERATES - audit rows, policy verdicts, provider results - may
    # contain a credential, and no response field may be named like one.
    action_id = _request(
        client, incident["id"], reason="token=abc123secret password=hunter2"
    ).json()["id"]
    client.post(f"/api/v1/responses/{action_id}/provider-preview")
    detail = client.get(f"/api/v1/responses/{action_id}").json()
    recorded = json.dumps(
        {
            "audit": detail["audit"],
            "policy": client.get(f"/api/v1/responses/{action_id}/policy").json(),
            "target_evidence": detail["target_evidence"],
        }
    ).lower()
    for forbidden in ("password", "token", "authorization", "bearer", "api_key", "cookie"):
        assert forbidden not in recorded, forbidden
    # No response field is named like a credential carrier.
    for key in detail:
        assert not any(
            part in key.lower() for part in ("password", "token", "secret", "credential", "key")
        ), key
    assert "eyj" not in detail["result_summary"].lower() if detail["result_summary"] else True


def test_audit_event_names_fit_the_column(client, clean_db):
    from app.models.responses import ResponseAction, ResponseAudit
    from app.services import response_service

    audit_columns = ResponseAudit.__table__.c
    action_columns = ResponseAction.__table__.c
    assert audit_columns["event"].type.length >= 32
    for event in response_service.RESPONSE_AUDIT_EVENTS:
        assert len(event) <= audit_columns["event"].type.length, event
    for status in response_service.STATUSES:
        assert len(status) <= action_columns["status"].type.length, status
        assert len(status) <= audit_columns["previous_status"].type.length, status
        assert len(status) <= audit_columns["new_status"].type.length, status
    for action in response_service.ACTION_TYPES:
        assert len(action) <= action_columns["action_type"].type.length, action
    for target in response_service.TARGET_TYPES:
        assert len(target) <= action_columns["target_type"].type.length, target


# ---------------------------------------------------------------------------
# 9/22: policy and risk integration
# ---------------------------------------------------------------------------


def test_policy_endpoint_reports_a_deterministic_verdict(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    first = client.get(f"/api/v1/responses/{action_id}/policy")
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["decision"] == "APPROVAL_REQUIRED"
    assert body["approval_required"] is True
    assert body["provider"] == "MOCK"
    assert body["provider_capable"] is True
    assert body["target_proven"] is True
    assert body["evidence_event_ids"]
    assert "approval" in body["reason"].lower()
    # Deterministic: the same inputs give the same verdict.
    assert client.get(f"/api/v1/responses/{action_id}/policy").json() == body


def test_policy_not_allowed_for_unproven_target(client, clean_db):
    from app.database.session import get_session_factory
    from app.models.responses import ResponseAction
    from app.services import response_governance

    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    db = get_session_factory()()
    try:
        row = db.get(ResponseAction, action_id)
        row.target_evidence = json.dumps([])
        db.commit()
        verdict = response_governance.evaluate_policy(db, row)
    finally:
        db.close()
    assert verdict["decision"] == "NOT_ALLOWED"
    assert verdict["target_proven"] is False


def test_risk_score_never_triggers_execution(client, clean_db):
    incident = _seed(client)
    scored = client.post(f"/api/v1/risk/incidents/{incident['id']}/calculate", json={})
    assert scored.status_code in (200, 201), scored.text
    assert scored.json()["priority"].startswith("P")
    # A scored, high-priority incident still has no action until a human
    # requests one against evidenced data.
    assert client.get("/api/v1/responses").json()["total"] == 0
    action_id = _request(client, incident["id"]).json()["id"]
    assert client.post(f"/api/v1/responses/{action_id}/execute", json={}).status_code == 409


def test_recommendations_are_deterministic_and_never_automatic(client, clean_db):
    incident = _seed(client)
    response = client.get(f"/api/v1/incidents/{incident['id']}/response-recommendations")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["incident_id"] == incident["id"]
    assert body["total"] >= 1
    assert body["items"], "stored evidence must yield at least one suggestion"
    for item in body["items"]:
        assert item["requires_approval"] is True
        assert item["automatic"] is False
        # No machine-learning framing, and never a bare "AI recommends".
        lowered = item["reason"].lower()
        for phrase in ("ai recommend", "artificial intelligence", "machine learning", " ml "):
            assert phrase not in lowered, phrase
        assert "policy" in lowered or "evidence" in lowered
        if item["available"]:
            assert item["evidence_event_ids"]
    first = client.get(f"/api/v1/incidents/{incident['id']}/response-recommendations").json()
    assert first["items"] == body["items"]


def test_recommendations_absent_without_evidence(client, clean_db):
    from app.models.correlations import Correlation, CorrelationEvidence

    incident = _seed(client)
    from app.database.session import get_session_factory

    db = get_session_factory()()
    try:
        db.query(CorrelationEvidence).delete()
        db.query(Correlation).delete()
        db.commit()
    finally:
        db.close()
    body = client.get(f"/api/v1/incidents/{incident['id']}/response-recommendations").json()
    assert body["items"] == []
    assert body["total"] == 0


# ---------------------------------------------------------------------------
# 21: mock provider behaviour
# ---------------------------------------------------------------------------


def test_mock_provider_is_pure_and_deterministic():
    from app.services.response_providers import MockResponseProvider, get_provider

    provider = get_provider("MOCK")
    assert isinstance(provider, MockResponseProvider)
    request = {
        "action_id": "a" * 64,
        "incident_id": "i" * 64,
        "action_type": "BLOCK_INDICATOR",
        "target_type": "IP",
        "target_reference": "198.51.100.23",
    }
    first = provider.preview_action(request)
    second = provider.preview_action(request)
    assert first == second, "a preview must be a pure function of its request"
    assert first.executed is False
    assert first.simulated is True
    assert first.status == "SIMULATED"
    done = provider.execute_action(request)
    assert done.executed is True
    assert done.status == "COMPLETED"
    assert done.rollback_supported is True
    assert done.rollback_reference
    assert provider.execute_action(request).rollback_reference == done.rollback_reference
    assert provider.get_action_status(request).executed is False


def test_mock_provider_validates_target_shapes():
    from app.services.response_providers import ProviderTargetRejected, get_provider

    provider = get_provider("MOCK")
    provider.validate_target("IP", "198.51.100.23")
    provider.validate_target("HASH", "b" * 64)
    provider.validate_target("ACCOUNT", "some.user")
    for target_type, value in (
        ("IP", "not-an-ip"),
        ("HASH", "zzz"),
        ("ACCOUNT", "has space"),
        ("ACCOUNT", "a" * 200),
        ("NONSENSE", "whatever"),
    ):
        try:
            provider.validate_target(target_type, value)
        except ProviderTargetRejected:
            continue
        raise AssertionError(f"{target_type}:{value} should have been rejected")


def test_provider_registry_is_server_side_only():
    from app.services.response_providers import PROVIDERS, get_provider

    assert set(PROVIDERS) == {"MOCK", "NOT_CONFIGURED"}
    for invented in ("real-firewall", "MOCK;rm -rf", "../evil", "", "SHELL"):
        try:
            get_provider(invented)
        except KeyError:
            continue
        raise AssertionError(f"{invented!r} should not be resolvable")


def test_not_configured_provider_refuses_everything():
    from app.services.response_providers import get_provider

    provider = get_provider("NOT_CONFIGURED")
    for outcome in (
        provider.preview_action({}),
        provider.execute_action({}),
        provider.rollback_action({}),
        provider.get_action_status({}),
    ):
        assert outcome.accepted is False
        assert outcome.executed is False
        assert outcome.status == "NOT_CONFIGURED"
        assert "no real defensive provider is configured" in outcome.result_summary.lower()


# ---------------------------------------------------------------------------
# Structural security
# ---------------------------------------------------------------------------


def test_security_regression_step30_modules():
    """AST proof that the Step 30 layer cannot execute or fetch anything.

    The two NEW service modules are held to the strict rule set. The two
    endpoint modules are already covered by the narrower Step 18/19 scans
    and are re-checked here for the imports Step 30 added, so this test
    adds scrutiny instead of loosening what came before.
    """
    import ast as _ast
    import inspect as _inspect

    import app.api.v1.endpoints.incidents as incidents_endpoints
    import app.api.v1.endpoints.responses as responses_endpoints
    import app.services.response_governance as governance
    import app.services.response_providers as providers

    banned_imports = {
        "subprocess",
        "os",
        "pty",
        "shutil",
        "importlib",
        "socket",
        "requests",
        "httpx",
        "urllib",
        "http",
        "ctypes",
        "multiprocessing",
        "asyncio",
        "signal",
        "ftplib",
        "smtplib",
        "telnetlib",
        "webbrowser",
    }
    # Bare builtins that would execute caller-supplied code.
    banned_names = {"eval", "exec", "compile", "open", "__import__", "getattr", "setattr"}
    # Attribute calls that would reach a transport or a shell.
    banned_attrs = {
        "system",
        "popen",
        "Popen",
        "call",
        "check_output",
        "check_call",
        "connect",
        "request",
        "urlopen",
        "urlretrieve",
        "getattr",
        "setattr",
    }

    def check_imports(module, label):
        for node in _ast.walk(_ast.parse(_inspect.getsource(module))):
            if isinstance(node, _ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    assert root not in banned_imports, f"{label} imports {root}"
            if isinstance(node, _ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                assert root not in banned_imports, f"{label} imports from {root}"

    def check_calls(module, label, strict):
        for node in _ast.walk(_ast.parse(_inspect.getsource(module))):
            if not isinstance(node, _ast.Call):
                continue
            func = node.func
            if isinstance(func, _ast.Name):
                assert func.id not in banned_names, f"{label} calls {func.id}()"
            if isinstance(func, _ast.Attribute) and strict:
                assert func.attr not in banned_attrs, f"{label} calls .{func.attr}()"

    # New code: strictest possible rule set.
    for module in (providers, governance):
        label = module.__name__
        check_imports(module, label)
        check_calls(module, label, strict=True)
    # Already-scanned endpoints: imports plus the dangerous builtins.
    for module in (responses_endpoints, incidents_endpoints):
        label = module.__name__
        check_imports(module, label)
        check_calls(module, label, strict=False)


def test_no_step30_endpoint_offers_a_command_or_direct_block_interface(client, clean_db):
    """No /block, /isolate, /wipe, /command style route may exist."""
    paths = client.get("/openapi.json").json()["paths"]
    forbidden = (
        "/block",
        "/isolate",
        "/wipe",
        "/command",
        "/remediate",
        "/firewall",
        "/execute-raw",
    )
    for path in paths:
        lowered = path.lower()
        for needle in forbidden:
            assert needle not in lowered, f"{path} exposes a forbidden response interface"
    assert "/api/v1/responses/{action_id}/execute" in paths
    assert "/api/v1/responses/{action_id}/rollback" in paths


def test_step30_keeps_legacy_proposal_surface_intact(client, clean_db):
    """Steps 12/18/19 behavior is unchanged by the Step 30 additions."""
    from tests.test_response_foundation import _propose
    from tests.test_response_foundation import _seed_incident as _legacy_seed

    incident = _legacy_seed(client)
    body = _propose(client, incident["id"], action_type="REVIEW", reason="legacy review").json()
    assert body["status"] == "PROPOSED"
    # A pre-Step-30 row reports the dry-run-only defaults, never a
    # controlled capability it does not have.
    assert body["provider"] == "MOCK"
    assert body["policy_decision"] == "DRY_RUN_ONLY"
    assert body["rollback_supported"] is False
    assert body["target_evidence"] == []
    legacy_dry = client.post(f"/api/v1/responses/{body['id']}/dry-run")
    assert legacy_dry.status_code == 200
    assert legacy_dry.json()["would_execute"] is False
    assert legacy_dry.json()["result"] == "SIMULATED"
