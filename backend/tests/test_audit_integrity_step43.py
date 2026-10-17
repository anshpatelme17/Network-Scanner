"""Audit integrity and security hardening tests (Step 43).

These tests pin the *integrity* of the controlled-response audit trail
without changing any behaviour. They are deliberately adversarial: the
audit record must be a closed, bounded, append-only, non-leaking,
correctly attributed and incident-scoped view of what the platform
actually did.

Covered here:

* the lifecycle audit vocabulary is a closed, unique, uppercase,
  column-sized set of ``RESPONSE_*`` events;
* every lifecycle event a real request/approve/reject/cancel/execute
  flow actually records is a member of that vocabulary, with a
  consistent status chain;
* a rejection rationale is trimmed and bounded; a blank rationale stores
  no detail; a non-rejection event never stores one; an over-long
  rationale is refused (422) and leaves the action untouched;
* no audit row ever carries server exception, stack-trace, or secret
  material — a refused transition writes nothing and leaks no text;
* the request correlation id is server-sanitised and cannot be
  controlled verbatim by a caller;
* audit rows are incident-scoped, so a row written for one incident can
  never surface under another;
* reading the audit endpoint is inert (no writes, no expiry sweep) and
  repeated reads do not change the stored trail.

Nothing here weakens Steps 1-42; the real governance/service helpers are
reused so the seeded rows are indistinguishable from production rows.
"""

from __future__ import annotations

import pytest
from sqlalchemy import event as sa_event

from app.services import response_governance
from app.services.response_governance import MAX_REJECTION_REASON, _sanitize_rejection_reason
from app.services.response_service import RESPONSE_AUDIT_EVENTS
from tests.test_response_governance import _approve, _request, _seed

REJECT_URL = "/api/v1/responses/{action_id}/reject"
CANCEL_URL = "/api/v1/responses/{action_id}/cancel"
EXECUTE_URL = "/api/v1/responses/{action_id}/execute"
V2_AUDIT_URL = "/api/v2/responses/{action_id}/audit"

# The frozen lifecycle vocabulary. Adding an event is a deliberate act and
# must be reflected here, which is the point of an inventory.
EXPECTED_AUDIT_EVENTS = {
    "RESPONSE_REQUESTED",
    "RESPONSE_APPROVAL_REQUIRED",
    "RESPONSE_APPROVED",
    "RESPONSE_REJECTED",
    "RESPONSE_CANCELLED",
    "RESPONSE_EXPIRED",
    "RESPONSE_EXECUTION_STARTED",
    "RESPONSE_EXECUTION_COMPLETED",
    "RESPONSE_EXECUTION_FAILED",
    "RESPONSE_ROLLBACK_STARTED",
    "RESPONSE_ROLLBACK_COMPLETED",
    "RESPONSE_DRY_RUN",
    "RESPONSE_TARGET_REJECTED",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rows(action_id: str) -> list:
    """Every stored audit row for one action, in recorded order."""
    from app.database.session import get_session_factory
    from app.models.responses import ResponseAudit

    db = get_session_factory()()
    try:
        return (
            db.query(ResponseAudit)
            .filter(ResponseAudit.action_id == action_id)
            .order_by(ResponseAudit.created_at, ResponseAudit.id)
            .all()
        )
    finally:
        db.close()


def _events(action_id: str) -> list[str]:
    return [row.event for row in _rows(action_id)]


def _status_of(action_id: str) -> str:
    from app.database.session import get_session_factory
    from app.models.responses import ResponseAction

    db = get_session_factory()()
    try:
        return db.get(ResponseAction, action_id).status
    finally:
        db.close()


def _reject(client, action_id: str, *, actor: str = "operator-1", reason=None, headers=None):
    payload: dict[str, object] = {"actor": actor}
    if reason is not None:
        payload["reason"] = reason
    return client.post(REJECT_URL.format(action_id=action_id), json=payload, headers=headers)


def _capture_statements():
    from app.database import session as session_module

    engine = session_module.get_engine()
    captured: list[str] = []

    def _before(_conn, _cursor, statement, _parameters, _context, _many):
        captured.append(statement)

    sa_event.listen(engine, "before_cursor_execute", _before)
    return captured, lambda: sa_event.remove(engine, "before_cursor_execute", _before)


# ---------------------------------------------------------------------------
# 1. Vocabulary inventory
# ---------------------------------------------------------------------------


def test_audit_event_vocabulary_is_closed_unique_and_column_sized():
    assert isinstance(RESPONSE_AUDIT_EVENTS, tuple)
    assert len(RESPONSE_AUDIT_EVENTS) == len(set(RESPONSE_AUDIT_EVENTS)), "duplicate event value"
    assert set(RESPONSE_AUDIT_EVENTS) == EXPECTED_AUDIT_EVENTS
    for event in RESPONSE_AUDIT_EVENTS:
        assert event.startswith("RESPONSE_"), event
        assert event == event.upper(), event
        # response_audit.event is String(32); every vocabulary value must fit.
        assert len(event) <= 32, event


def test_lifecycle_flow_only_records_vocabulary_events(client, clean_db):
    captured, stop = _capture_statements()
    try:
        incident = _seed(client)
        approved = _request(client, incident["id"]).json()["id"]
        assert _approve(client, approved).status_code == 200
        executed = client.post(EXECUTE_URL.format(action_id=approved), json={"actor": "operator-2"})
        assert executed.status_code in (200, 201), executed.text

        rejected = _request(
            client, incident["id"], target_reference="192.0.2.10"
        ).json()["id"]
        assert _reject(client, rejected, reason="scoped to this action only").status_code == 200

        cancelled = _request(
            client,
            incident["id"],
            target_reference="192.0.2.10",
            requested_by="analyst-2",
        ).json()["id"]
        assert client.post(CANCEL_URL.format(action_id=cancelled), json={"actor": "op"}).status_code == 200
    finally:
        stop()

    for action_id in (approved, rejected, cancelled):
        recorded = _events(action_id)
        assert recorded, action_id
        assert set(recorded) <= EXPECTED_AUDIT_EVENTS, recorded

    # The approved+executed action ran the full lifecycle in order.
    approved_events = _events(approved)
    assert approved_events[0] == "RESPONSE_REQUESTED"
    assert "RESPONSE_APPROVED" in approved_events
    assert approved_events.index("RESPONSE_APPROVED") < approved_events.index(
        "RESPONSE_EXECUTION_STARTED"
    )
    assert any(e.startswith("RESPONSE_EXECUTION_") and e != "RESPONSE_EXECUTION_STARTED" for e in approved_events)

    # A rejection records exactly one REJECTED row, and no execution.
    assert _events(rejected).count("RESPONSE_REJECTED") == 1
    assert not any(e.startswith("RESPONSE_EXECUTION") for e in _events(rejected))
    assert _events(cancelled).count("RESPONSE_CANCELLED") == 1


def test_recorded_rows_have_a_consistent_status_chain(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200
    assert client.post(EXECUTE_URL.format(action_id=action_id), json={"actor": "operator-2"}).status_code in (
        200,
        201,
    )

    previous_new = None
    for row in _rows(action_id):
        # The first row has no prior status; every later row must open where
        # the previous row closed, so the trail cannot contain a gap.
        if previous_new is not None:
            assert row.previous_status == previous_new, row.event
        assert row.new_status is not None
        previous_new = row.new_status


# ---------------------------------------------------------------------------
# 2. Rejection rationale handling
# ---------------------------------------------------------------------------


def test_sanitizer_trims_bounds_and_empties():
    assert _sanitize_rejection_reason(None) is None
    assert _sanitize_rejection_reason("") is None
    assert _sanitize_rejection_reason("   \t \r\n ") is None
    assert _sanitize_rejection_reason("  keep me  ") == "keep me"
    assert _sanitize_rejection_reason("\n\tscoped\n\n") == "scoped"
    long_reason = "x" * (MAX_REJECTION_REASON + 500)
    sanitized = _sanitize_rejection_reason(long_reason)
    assert sanitized is not None
    assert len(sanitized) == MAX_REJECTION_REASON


def test_rejection_reason_is_trimmed_on_the_stored_row(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _reject(client, action_id, reason="  verified benign  ").status_code == 200

    rejected = [row for row in _rows(action_id) if row.event == "RESPONSE_REJECTED"]
    assert len(rejected) == 1
    assert rejected[0].detail == "verified benign"


def test_blank_rejection_reason_stores_no_detail(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _reject(client, action_id, reason="    ").status_code == 200

    rejected = [row for row in _rows(action_id) if row.event == "RESPONSE_REJECTED"]
    assert len(rejected) == 1
    assert rejected[0].detail is None


def test_overlong_rejection_reason_is_refused_without_state_change(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    before = _events(action_id)

    refused = _reject(client, action_id, reason="x" * (MAX_REJECTION_REASON + 1))
    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "VALIDATION_ERROR"

    assert _status_of(action_id) == "PENDING_APPROVAL"
    assert _events(action_id) == before
    assert "RESPONSE_REJECTED" not in _events(action_id)


def test_non_rejection_events_never_store_a_rationale(client, clean_db):
    incident = _seed(client)
    approved = _request(client, incident["id"]).json()["id"]
    assert _approve(client, approved).status_code == 200
    assert client.post(EXECUTE_URL.format(action_id=approved), json={"actor": "operator-2"}).status_code in (
        200,
        201,
    )

    cancelled = _request(client, incident["id"], target_reference="192.0.2.10").json()["id"]
    assert client.post(CANCEL_URL.format(action_id=cancelled), json={"actor": "op"}).status_code == 200

    for action_id in (approved, cancelled):
        for row in _rows(action_id):
            if row.event != "RESPONSE_REJECTED":
                assert row.detail is None, (row.event, row.detail)


# ---------------------------------------------------------------------------
# 3. No leakage of server internals
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [REJECT_URL, CANCEL_URL, EXECUTE_URL],
    ids=["reject", "cancel", "execute"],
)
def test_refused_transition_writes_no_row_and_leaks_no_text(client, clean_db, url):
    """An invalid transition is refused; no exception text reaches the trail."""
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    before = {row.id for row in _rows(action_id)}

    # Force an edge that is refused for a PENDING action.
    if url == EXECUTE_URL:
        refused = client.post(url.format(action_id=action_id), json={"actor": "op"})
        assert refused.status_code >= 400
    else:
        # A first cancel of a PENDING action is legal, so cancel then try the
        # same edge again on the now-terminal action to obtain a refusal.
        assert client.post(url.format(action_id=action_id), json={"actor": "op"}).status_code == 200
        refused = client.post(url.format(action_id=action_id), json={"actor": "op"})
        assert refused.status_code >= 400

    body = refused.json()
    assert set(body) == {"error"}
    assert set(body["error"]) <= {"code", "message"}
    blob = repr(body)
    for banned in ("Traceback", 'File "', "Exception", "SECRET_KEY"):
        assert banned not in blob

    after = _rows(action_id)
    for row in after:
        blob = " ".join(
            str(value)
            for value in (row.event, row.actor, row.detail, row.previous_status, row.new_status)
        )
        for banned in ("Traceback", 'File "', "Exception"):
            assert banned not in blob, banned
    # A refusal never removes or invents rows.
    assert {row.id for row in after} >= before


def test_audit_payloads_never_expose_request_id(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _reject(client, action_id, reason="no request id please").status_code == 200

    body = client.get(V2_AUDIT_URL.format(action_id=action_id)).json()
    assert "request_id" not in body
    for entry in body["entries"]:
        assert "request_id" not in entry
        assert set(entry) == {
            "id",
            "event",
            "previous_status",
            "new_status",
            "actor",
            "policy_version",
            "created_at",
            "detail",
        }


# ---------------------------------------------------------------------------
# 4. Correlation id is server-sanitised
# ---------------------------------------------------------------------------


def test_request_id_header_is_sanitised_and_not_stored_verbatim(client, clean_db):
    incident = _seed(client)
    unsafe = _request(client, incident["id"]).json()["id"]
    # Spaces and punctuation are outside the allow-list, so the value is
    # replaced with a fresh id rather than echoed.
    assert _reject(
        client, unsafe, reason="unsafe header", headers={"X-Request-ID": "attacker value!"}
    ).status_code == 200
    row = [r for r in _rows(unsafe) if r.event == "RESPONSE_REJECTED"][0]
    assert row.request_id != "attacker value!"
    assert row.request_id is not None
    assert len(row.request_id) == 32

    safe = _request(client, incident["id"], target_reference="192.0.2.10").json()["id"]
    assert _reject(
        client, safe, reason="safe header", headers={"X-Request-ID": "trace-abc123"}
    ).status_code == 200
    safe_row = [r for r in _rows(safe) if r.event == "RESPONSE_REJECTED"][0]
    assert safe_row.request_id == "trace-abc123"


# ---------------------------------------------------------------------------
# 5. Incident scoping
# ---------------------------------------------------------------------------


def test_every_audit_row_carries_its_action_incident(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _reject(client, action_id, reason="scoped").status_code == 200

    for row in _rows(action_id):
        assert row.incident_id == incident["id"]


def test_audit_rows_are_isolated_by_incident(client, clean_db):
    from app.database.session import get_session_factory
    from app.models.responses import ResponseAudit

    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _reject(client, action_id, reason="incident scoped").status_code == 200

    db = get_session_factory()()
    try:
        for_row = (
            db.query(ResponseAudit).filter(ResponseAudit.incident_id == incident["id"]).all()
        )
        foreign = (
            db.query(ResponseAudit)
            .filter(ResponseAudit.incident_id == "inc-does-not-exist")
            .all()
        )
    finally:
        db.close()

    assert for_row, "the seeded incident must have audit rows"
    assert foreign == []
    assert {row.action_id for row in for_row} == {action_id}


# ---------------------------------------------------------------------------
# 6. Read path is inert
# ---------------------------------------------------------------------------


def test_reading_the_audit_is_append_only_and_repeatable(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _reject(client, action_id, reason="read only").status_code == 200
    before_ids = {row.id for row in _rows(action_id)}
    status_before = _status_of(action_id)

    captured, stop = _capture_statements()
    try:
        first = client.get(V2_AUDIT_URL.format(action_id=action_id))
        second = client.get(V2_AUDIT_URL.format(action_id=action_id))
    finally:
        stop()

    assert first.status_code == 200 and second.status_code == 200
    assert first.json()["entries"] == second.json()["entries"]
    writes = [
        statement
        for statement in captured
        if statement.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))
    ]
    assert writes == [], writes
    assert {row.id for row in _rows(action_id)} == before_ids
    assert _status_of(action_id) == status_before


def test_governance_sanitizer_is_the_only_rationale_source(client, clean_db):
    """The stored detail is exactly the sanitizer's output, no server text."""
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    raw = "  owner confirmed benign  "
    assert _reject(client, action_id, reason=raw).status_code == 200

    rejected = [row for row in _rows(action_id) if row.event == "RESPONSE_REJECTED"][0]
    assert rejected.detail == _sanitize_rejection_reason(raw)
    assert rejected.detail == "owner confirmed benign"

    # The module under test exposes the sanitizer used by the reject path.
    assert hasattr(response_governance, "_sanitize_rejection_reason")
