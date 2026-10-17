"""Response audit history endpoint tests (Step 42A, v2, read-only).

Covers the additive ``GET /api/v2/responses/{id}/audit`` contract without
weakening any earlier step:

* the endpoint is mounted at the real v2 URL (and v1 is unchanged);
* chronological ordering with an id tie-break;
* pagination defaults, bounds, ``total`` and ``truncated`` semantics;
* empty history and the established ``RESPONSE_NOT_FOUND`` behaviour;
* ``READ_RESPONSES`` authorization (401/403/allow);
* per-action isolation;
* the rejection ``detail`` is returned, and no other event carries a
  rationale (execute, approve, cancel);
* the read path performs no INSERT/UPDATE/DELETE and no governance
  transition — in particular it does not call ``expire_due()``;
* the response exposes no ``request_id`` or unrelated fields.

The real governance/service helpers are reused from ``test_response_governance``
so the seeded rows are indistinguishable from production rows.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import event as sa_event

from tests.test_response_governance import OBSERVED_IP, _approve, _request, _seed

CONTROLLED_URL = "/api/v1/responses/controlled"
REJECT_URL = "/api/v1/responses/{action_id}/reject"
APPROVE_URL = "/api/v1/responses/{action_id}/approve"
EXECUTE_URL = "/api/v1/responses/{action_id}/execute"

V2_AUDIT_URL = "/api/v2/responses/{action_id}/audit"

ENTRY_FIELDS = {
    "id",
    "event",
    "previous_status",
    "new_status",
    "actor",
    "policy_version",
    "created_at",
    "detail",
}
PAGE_FIELDS = {"action_id", "incident_id", "entries", "total", "limit", "offset", "truncated"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _audit_url(action_id: str, **params: object) -> str:
    url = V2_AUDIT_URL.format(action_id=action_id)
    if params:
        query = "&".join(f"{key}={value}" for key, value in params.items())
        return f"{url}?{query}"
    return url


def _get(client, action_id: str, **params: object):
    return client.get(_audit_url(action_id, **params))


def _reject(client, action_id: str, actor: str = "operator-1", reason: str | None = None):
    payload: dict[str, object] = {"actor": actor}
    if reason is not None:
        payload["reason"] = reason
    return client.post(REJECT_URL.format(action_id=action_id), json=payload)


def _events(entries: list[dict]) -> list[str]:
    return [entry["event"] for entry in entries]


def _bare_action(*, status: str = "PENDING_APPROVAL", expires_at=None) -> str:
    """Insert one ResponseAction directly, with no audit rows at all."""
    from app.database.session import get_session_factory
    from app.models.responses import ResponseAction

    row_id = f"bare-{uuid.uuid4().hex[:12]}"
    db = get_session_factory()()
    try:
        db.add(
            ResponseAction(
                id=row_id,
                incident_id="inc-bare",
                action_type="BLOCK_INDICATOR",
                target_type="IP",
                target_reference=OBSERVED_IP,
                reason="Bare audit fixture row.",
                requested_by="analyst-1",
                status=status,
                dry_run=True,
                policy_version="1.0.0",
                provider="MOCK",
                approval_required=True,
                expires_at=expires_at,
            )
        )
        db.commit()
    finally:
        db.close()
    return row_id


def _add_audit(
    action_id: str,
    *,
    event: str,
    created_at: datetime,
    audit_id: str | None = None,
    actor: str = "analyst-1",
    detail: str | None = None,
    previous_status: str | None = None,
    new_status: str | None = None,
) -> str:
    """Insert one audit row directly, with a chosen id and timestamp."""
    from app.database.session import get_session_factory
    from app.models.responses import ResponseAudit

    row_id = audit_id or str(uuid.uuid4())
    db = get_session_factory()()
    try:
        db.add(
            ResponseAudit(
                id=row_id,
                action_id=action_id,
                incident_id="inc-bare",
                event=event,
                previous_status=previous_status,
                new_status=new_status,
                actor=actor,
                policy_version="1.0.0",
                created_at=created_at,
                detail=detail,
            )
        )
        db.commit()
    finally:
        db.close()
    return row_id


def _audit_rows(action_id: str) -> list:
    from app.database.session import get_session_factory
    from app.models.responses import ResponseAudit

    db = get_session_factory()()
    try:
        return (
            db.query(ResponseAudit)
            .filter(ResponseAudit.action_id == action_id)
            .all()
        )
    finally:
        db.close()


def _status_of(action_id: str) -> str:
    from app.database.session import get_session_factory
    from app.models.responses import ResponseAction

    db = get_session_factory()()
    try:
        return db.get(ResponseAction, action_id).status
    finally:
        db.close()


def _capture_statements():
    """Capture every SQL statement the test database executes."""
    from app.database import session as session_module

    engine = session_module.get_engine()
    captured: list[str] = []

    def _before(_conn, _cursor, statement, _parameters, _context, _many):
        captured.append(statement)

    sa_event.listen(engine, "before_cursor_execute", _before)
    return captured, lambda: sa_event.remove(engine, "before_cursor_execute", _before)


# ---------------------------------------------------------------------------
# 1. Mounted route
# ---------------------------------------------------------------------------


def test_v2_audit_route_is_mounted_at_the_real_url(client, clean_db):
    """The endpoint answers on the v2 prefix; v1 exposes no such route."""
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]

    mounted = _get(client, action_id)
    assert mounted.status_code == 200, mounted.text
    body = mounted.json()
    assert set(body) == PAGE_FIELDS
    assert body["action_id"] == action_id
    assert body["incident_id"] == incident["id"]
    assert body["limit"] == 50 and body["offset"] == 0

    # The sibling v1 path was never defined, so it is a 404 — the v2 mount
    # is a real second surface, not an alias.
    assert client.get(f"/api/v1/responses/{action_id}/audit").status_code == 404


def test_entry_shape_exposes_no_request_id_or_unrelated_fields(client, clean_db):
    """Every entry carries exactly the contract fields; no request_id."""
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]

    body = _get(client, action_id).json()
    assert body["entries"], "a requested action has lifecycle audit rows"
    for entry in body["entries"]:
        assert set(entry) == ENTRY_FIELDS
        assert "request_id" not in entry
    assert "request_id" not in body


# ---------------------------------------------------------------------------
# 2. Ordering
# ---------------------------------------------------------------------------


def test_ordering_is_chronological_then_id(client, clean_db):
    """created_at ASC, then id ASC, so equal timestamps stay deterministic."""
    action_id = _bare_action()
    early = datetime(2026, 10, 1, 9, 0, 0)
    middle = datetime(2026, 10, 1, 9, 5, 0)
    late = datetime(2026, 10, 1, 9, 10, 0)

    # The two `middle` rows share a timestamp; only the id breaks the tie.
    _add_audit(action_id, event="RESPONSE_REQUESTED", created_at=middle, audit_id="b-audit-2")
    _add_audit(action_id, event="RESPONSE_APPROVED", created_at=late, audit_id="c-audit-3")
    _add_audit(action_id, event="RESPONSE_CANCELLED", created_at=early, audit_id="a-audit-1")
    _add_audit(action_id, event="RESPONSE_EXPIRED", created_at=middle, audit_id="b-audit-1")

    entries = _get(client, action_id).json()["entries"]
    assert [entry["id"] for entry in entries] == [
        "a-audit-1",
        "b-audit-1",
        "b-audit-2",
        "c-audit-3",
    ]


# ---------------------------------------------------------------------------
# 3. Pagination, total, truncated
# ---------------------------------------------------------------------------


def test_pagination_defaults_and_bounds(client, clean_db):
    action_id = _bare_action()
    assert _get(client, action_id).status_code == 200
    assert _get(client, action_id, limit=1).status_code == 200
    assert _get(client, action_id, limit=200, offset=0).status_code == 200
    # Invalid bounds follow the standard FastAPI validation behaviour.
    assert _get(client, action_id, limit=0).status_code == 422
    assert _get(client, action_id, limit=201).status_code == 422
    assert _get(client, action_id, offset=-1).status_code == 422


def test_total_and_truncated_semantics(client, clean_db):
    action_id = _bare_action()
    base = datetime(2026, 10, 1, 9, 0, 0)
    for index in range(3):
        _add_audit(
            action_id,
            event="RESPONSE_REQUESTED",
            created_at=base + timedelta(minutes=index),
            audit_id=f"t-{index}",
        )

    first = _get(client, action_id, limit=2, offset=0).json()
    assert first["total"] == 3
    assert len(first["entries"]) == 2
    assert first["limit"] == 2 and first["offset"] == 0
    assert first["truncated"] is True

    last = _get(client, action_id, limit=2, offset=2).json()
    assert last["total"] == 3
    assert len(last["entries"]) == 1
    assert last["truncated"] is False

    beyond = _get(client, action_id, limit=2, offset=3).json()
    assert beyond["entries"] == []
    assert beyond["total"] == 3
    assert beyond["truncated"] is False


# ---------------------------------------------------------------------------
# 4. Empty and missing
# ---------------------------------------------------------------------------


def test_empty_audit_history(client, clean_db):
    action_id = _bare_action()
    body = _get(client, action_id).json()
    assert body["entries"] == []
    assert body["total"] == 0
    assert body["truncated"] is False


def test_missing_action_follows_not_found_convention(client, clean_db):
    missing = client.get(_audit_url("no-such-action"))
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "RESPONSE_NOT_FOUND"


# ---------------------------------------------------------------------------
# 5. Authorization
# ---------------------------------------------------------------------------


def test_anonymous_is_401_once_enforcement_is_active(client, clean_db):
    from tests.test_auth import _admin_headers

    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    _admin_headers(client)  # bootstrap an admin; enforcement now active

    assert client.get(_audit_url(action_id)).status_code == 401


def test_authenticated_without_read_responses_is_403(client, clean_db, monkeypatch):
    """The permission gate itself produces the 403, not a role lookup."""
    from app.api.v1 import auth_deps
    from app.services.auth_service import AuthContext

    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]

    def _without_permission(_db, _authorization):
        return AuthContext(
            authenticated=True,
            enforcement=True,
            username="no-read-responses",
            user_id="no-read-responses",
            roles=("VIEWER",),
            permissions=frozenset({"READ_INCIDENTS"}),
        )

    monkeypatch.setattr(auth_deps.auth_service, "resolve_context", _without_permission)
    refused = client.get(_audit_url(action_id))
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "PERMISSION_DENIED"
    assert "READ_RESPONSES" in refused.json()["error"]["message"]


@pytest.mark.parametrize("roles", ["VIEWER", "SECURITY_ANALYST", "OPERATOR", "ADMIN"])
def test_every_defined_role_may_read_history(client, clean_db, roles):
    from tests.test_auth import _auth_header

    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    headers = _auth_header(client, f"audit-{roles.lower()}", f"{roles.lower()}-pass-1234", (roles,))
    assert client.get(_audit_url(action_id), headers=headers).status_code == 200


# ---------------------------------------------------------------------------
# 6. Per-action isolation
# ---------------------------------------------------------------------------


def test_history_is_isolated_per_action(client, clean_db):
    incident = _seed(client)
    first = _request(client, incident["id"]).json()["id"]
    second = _request(
        client, incident["id"], target_reference="192.0.2.10"
    ).json()["id"]

    _reject(client, first, reason="Belongs only to the first action.")
    _approve(client, second)

    first_ids = {row.id for row in _audit_rows(first)}
    second_ids = {row.id for row in _audit_rows(second)}
    assert first_ids and second_ids and not (first_ids & second_ids)

    first_body = _get(client, first).json()
    assert first_body["action_id"] == first
    assert {entry["id"] for entry in first_body["entries"]} == first_ids
    assert {entry["id"] for entry in first_body["entries"]} <= first_ids

    second_body = _get(client, second).json()
    assert {entry["id"] for entry in second_body["entries"]} == second_ids


# ---------------------------------------------------------------------------
# 7. Rejection detail vs. every other event
# ---------------------------------------------------------------------------


def test_rejection_detail_is_returned(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    reason = "Confirmed benign after review with the asset owner."
    assert _reject(client, action_id, reason=reason).status_code == 200

    rejected = [e for e in _get(client, action_id).json()["entries"] if e["event"] == "RESPONSE_REJECTED"]
    assert len(rejected) == 1
    assert rejected[0]["detail"] == reason
    assert rejected[0]["actor"] == "operator-1"


def test_approval_and_cancellation_carry_no_rationale(client, clean_db):
    incident = _seed(client)
    approved_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, approved_id).status_code == 200

    cancelled_id = _request(client, incident["id"], target_reference="192.0.2.10").json()["id"]
    assert (
        client.post(
            f"/api/v1/responses/{cancelled_id}/cancel", json={"actor": "analyst-1"}
        ).status_code
        == 200
    )

    for action_id, event in (
        (approved_id, "RESPONSE_APPROVED"),
        (cancelled_id, "RESPONSE_CANCELLED"),
    ):
        rows = [e for e in _get(client, action_id).json()["entries"] if e["event"] == event]
        assert len(rows) == 1, event
        assert rows[0]["detail"] is None, f"{event} must never carry a rationale"


def test_execute_and_request_events_carry_no_rationale(client, clean_db):
    """No execute/request/approval-required entry ever shows a reason."""
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200
    executed = client.post(EXECUTE_URL.format(action_id=action_id), json={"actor": "operator-2"})
    assert executed.status_code in (200, 201), executed.text

    entries = _get(client, action_id).json()["entries"]
    assert entries
    for entry in entries:
        if entry["event"] != "RESPONSE_REJECTED":
            assert entry["detail"] is None, entry["event"]
    # The execution events are present and rational-free.
    assert any(e["event"].startswith("RESPONSE_EXECUTION") for e in entries)


# ---------------------------------------------------------------------------
# 8. Read-only guarantee
# ---------------------------------------------------------------------------


def test_read_performs_no_writes(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    before = {row.id for row in _audit_rows(action_id)}
    status_before = _status_of(action_id)

    captured, stop = _capture_statements()
    try:
        response = _get(client, action_id)
    finally:
        stop()

    assert response.status_code == 200
    writes = [
        statement
        for statement in captured
        if statement.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))
    ]
    assert writes == [], writes
    assert {row.id for row in _audit_rows(action_id)} == before
    assert _status_of(action_id) == status_before


def test_read_does_not_expire_an_overdue_action(client, clean_db):
    """The v2 read must not call ``expire_due()``: the row stays untouched."""
    from app.database.session import get_session_factory
    from app.models.responses import ResponseAction

    overdue = _bare_action(status="PENDING_APPROVAL", expires_at=datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=1))

    body = _get(client, overdue).json()
    assert body["action_id"] == overdue

    # No expiry transition happened on the read path.
    assert _status_of(overdue) == "PENDING_APPROVAL"
    assert "RESPONSE_EXPIRED" not in _events(body["entries"])
    assert _audit_rows(overdue) == []

    # Control: the v1 detail read *does* run the read-path sweep, proving
    # the fixture was genuinely expirable and the v2 read alone is inert.
    assert client.get(f"/api/v1/responses/{overdue}").status_code == 200
    db = get_session_factory()()
    try:
        refreshed = db.get(ResponseAction, overdue)
        assert refreshed.status == "EXPIRED"
    finally:
        db.close()
