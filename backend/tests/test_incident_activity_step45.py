"""Incident activity / accountability feed tests (Step 45).

Covers the new incident-scoped ``GET /api/v1/incidents/{id}/activity``
contract without weakening any earlier step:

* the endpoint is mounted at the real incident URL and 404s for an
  unknown incident;
* the page and item shapes match the contract exactly (no ``request_id``);
* both ``READ_INCIDENTS`` and ``READ_RESPONSES`` are required (401/403);
* activity is incident-scoped — a row written for another incident can
  never surface here;
* exact-match filters (event, actor, action_id, since, until) apply to
  both ``items`` and ``total``; an unknown event is a 422;
* ordering is ``created_at`` then ``id``; pagination bounds, ``total`` and
  ``truncated`` follow the established convention;
* the rejection rationale is exposed only on the rejection row;
* the endpoint is strictly read-only (no writes, no expiry sweep).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from tests.test_response_governance import OBSERVED_IP, _approve, _request, _seed

ACTIVITY_URL = "/api/v1/incidents/{incident_id}/activity"

PAGE_FIELDS = {
    "incident_id",
    "incident_key",
    "items",
    "total",
    "limit",
    "offset",
    "truncated",
    "filters",
}
ITEM_FIELDS = {
    "id",
    "action_id",
    "action_type",
    "event",
    "actor",
    "previous_status",
    "new_status",
    "policy_version",
    "created_at",
    "detail",
}
FILTER_FIELDS = {"event", "actor", "since", "until", "action_id"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get(client, incident_id: str, **params: object):
    url = ACTIVITY_URL.format(incident_id=incident_id)
    if params:
        query = "&".join(f"{key}={value}" for key, value in params.items())
        return client.get(f"{url}?{query}")
    return client.get(url)


def _add_row(
    incident_id: str,
    action_id: str,
    event: str,
    created_at: datetime,
    *,
    actor: str = "analyst-1",
    detail: str | None = None,
    previous_status: str | None = None,
    new_status: str | None = None,
    audit_id: str | None = None,
) -> str:
    from app.database.session import get_session_factory
    from app.models.responses import ResponseAudit

    row_id = audit_id or str(uuid.uuid4())
    db = get_session_factory()()
    try:
        db.add(
            ResponseAudit(
                id=row_id,
                action_id=action_id,
                incident_id=incident_id,
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


def _bare_overdue_action(incident_id: str) -> str:
    from datetime import UTC

    from app.database.session import get_session_factory
    from app.models.responses import ResponseAction

    row_id = f"overdue-{uuid.uuid4().hex[:12]}"
    db = get_session_factory()()
    try:
        db.add(
            ResponseAction(
                id=row_id,
                incident_id=incident_id,
                action_type="BLOCK_INDICATOR",
                target_type="IP",
                target_reference=OBSERVED_IP,
                reason="Overdue fixture row.",
                requested_by="analyst-1",
                status="PENDING_APPROVAL",
                dry_run=True,
                policy_version="1.0.0",
                provider="MOCK",
                approval_required=True,
                expires_at=datetime.now(UTC).replace(tzinfo=None),
            )
        )
        db.commit()
    finally:
        db.close()
    return row_id


def _status_of(action_id: str) -> str:
    from app.database.session import get_session_factory
    from app.models.responses import ResponseAction

    db = get_session_factory()()
    try:
        return db.get(ResponseAction, action_id).status
    finally:
        db.close()


def _audit_count(action_id: str) -> int:
    from app.database.session import get_session_factory
    from app.models.responses import ResponseAudit

    db = get_session_factory()()
    try:
        return db.query(ResponseAudit).filter(ResponseAudit.action_id == action_id).count()
    finally:
        db.close()


def _capture_statements():
    from sqlalchemy import event as sa_event

    from app.database import session as session_module

    engine = session_module.get_engine()
    captured: list[str] = []

    def _before(_conn, _cursor, statement, _parameters, _context, _many):
        captured.append(statement)

    sa_event.listen(engine, "before_cursor_execute", _before)
    return captured, lambda: sa_event.remove(engine, "before_cursor_execute", _before)


# ---------------------------------------------------------------------------
# 1. Mounted route and shape
# ---------------------------------------------------------------------------


def test_activity_route_is_mounted_and_shaped(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200

    response = _get(client, incident["id"])
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == PAGE_FIELDS
    assert body["incident_id"] == incident["id"]
    assert body["incident_key"] == incident["incident_key"]
    assert body["limit"] == 50 and body["offset"] == 0
    assert set(body["filters"]) == FILTER_FIELDS
    assert body["items"], "an approved request has lifecycle rows"
    for item in body["items"]:
        assert set(item) == ITEM_FIELDS
        assert "request_id" not in item
    assert all(item["action_id"] == action_id for item in body["items"])
    assert all(item["action_type"] == "BLOCK_INDICATOR" for item in body["items"])


def test_unknown_incident_is_404(client, clean_db):
    missing = _get(client, "no-such-incident")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "INCIDENT_NOT_FOUND"


# ---------------------------------------------------------------------------
# 2. Authorization
# ---------------------------------------------------------------------------


def test_anonymous_is_401_once_enforcement_is_active(client, clean_db):
    from tests.test_auth import _admin_headers

    incident = _seed(client)
    _admin_headers(client)
    assert _get(client, incident["id"]).status_code == 401


def _context_with(**permissions: bool):
    from app.services.auth_service import AuthContext

    granted = frozenset(name for name, on in permissions.items() if on)
    return AuthContext(
        authenticated=True,
        enforcement=True,
        username="tester",
        user_id="tester",
        roles=("VIEWER",),
        permissions=granted,
    )


def test_requires_read_responses(client, clean_db, monkeypatch):
    from app.api.v1 import auth_deps

    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200

    monkeypatch.setattr(
        auth_deps.auth_service,
        "resolve_context",
        lambda _db, _authorization: _context_with(READ_INCIDENTS=True),
    )
    refused = _get(client, incident["id"])
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "PERMISSION_DENIED"
    assert "READ_RESPONSES" in refused.json()["error"]["message"]


def test_requires_read_incidents(client, clean_db, monkeypatch):
    from app.api.v1 import auth_deps

    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200

    monkeypatch.setattr(
        auth_deps.auth_service,
        "resolve_context",
        lambda _db, _authorization: _context_with(READ_RESPONSES=True),
    )
    refused = _get(client, incident["id"])
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "PERMISSION_DENIED"
    assert "READ_INCIDENTS" in refused.json()["error"]["message"]


def test_both_permissions_are_sufficient(client, clean_db, monkeypatch):
    from app.api.v1 import auth_deps

    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200

    monkeypatch.setattr(
        auth_deps.auth_service,
        "resolve_context",
        lambda _db, _authorization: _context_with(READ_INCIDENTS=True, READ_RESPONSES=True),
    )
    assert _get(client, incident["id"]).status_code == 200


# ---------------------------------------------------------------------------
# 3. Incident scoping
# ---------------------------------------------------------------------------


def test_rows_from_another_incident_never_surface(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200
    before = _get(client, incident["id"]).json()["total"]

    # A row written for a different incident must not leak into this feed.
    _add_row(
        "inc-foreign",
        action_id,
        "RESPONSE_APPROVED",
        datetime(2026, 10, 1, 9, 0, 0),
        audit_id="foreign-row",
    )

    body = _get(client, incident["id"]).json()
    assert body["total"] == before
    assert all(item["id"] != "foreign-row" for item in body["items"])
    assert all(item["action_id"] == action_id for item in body["items"])


def test_activity_excludes_other_actions_of_the_same_incident_when_filtered(client, clean_db):
    incident = _seed(client)
    first = _request(client, incident["id"]).json()["id"]
    _request(
        client, incident["id"], target_reference="192.0.2.10", requested_by="analyst-2"
    ).json()["id"]
    assert _approve(client, first).status_code == 200

    body = _get(client, incident["id"], action_id=first).json()
    assert body["items"]
    assert {item["action_id"] for item in body["items"]} == {first}
    assert body["total"] == len(body["items"])


# ---------------------------------------------------------------------------
# 4. Filters
# ---------------------------------------------------------------------------


def test_event_filter_and_unknown_event_validation(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200

    approved = _get(client, incident["id"], event="RESPONSE_APPROVED").json()
    assert approved["items"]
    assert {item["event"] for item in approved["items"]} == {"RESPONSE_APPROVED"}
    assert approved["total"] == len(approved["items"])

    bad = _get(client, incident["id"], event="RESPONSE_INVENTED")
    assert bad.status_code == 422
    assert bad.json()["error"]["code"] == "VALIDATION_ERROR"


def test_actor_and_action_filters(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200

    by_actor = _get(client, incident["id"], actor="operator-1").json()
    assert by_actor["items"]
    assert {item["actor"] for item in by_actor["items"]} == {"operator-1"}

    none = _get(client, incident["id"], actor="nobody").json()
    assert none["items"] == [] and none["total"] == 0 and none["truncated"] is False

    by_action = _get(client, incident["id"], action_id=action_id).json()
    assert by_action["total"] == by_action["total"] >= 1


def test_time_window_filters(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    early = datetime(2026, 10, 1, 9, 0, 0)
    late = datetime(2026, 10, 1, 23, 0, 0)
    _add_row(incident["id"], action_id, "RESPONSE_REQUESTED", early, audit_id="w-early")
    _add_row(incident["id"], action_id, "RESPONSE_APPROVED", late, audit_id="w-late")

    window = _get(
        client,
        incident["id"],
        since=early.isoformat(),
        until=late.isoformat(),
        action_id=action_id,
    ).json()
    ids = {item["id"] for item in window["items"]}
    assert {"w-early", "w-late"} <= ids

    after = _get(
        client, incident["id"], since="2026-10-01T12:00:00", action_id=action_id
    ).json()
    ids_after = {item["id"] for item in after["items"]}
    assert "w-early" not in ids_after and "w-late" in ids_after

    before = _get(
        client, incident["id"], until="2026-10-01T12:00:00", action_id=action_id
    ).json()
    ids_before = {item["id"] for item in before["items"]}
    assert "w-early" in ids_before and "w-late" not in ids_before


def test_filters_are_echoed(client, clean_db):
    incident = _seed(client)
    body = _get(client, incident["id"], event="RESPONSE_APPROVED", actor="operator-1").json()
    assert body["filters"]["event"] == "RESPONSE_APPROVED"
    assert body["filters"]["actor"] == "operator-1"
    assert body["filters"]["action_id"] is None


# ---------------------------------------------------------------------------
# 5. Ordering and pagination
# ---------------------------------------------------------------------------


def test_ordering_is_chronological_then_id(client, clean_db):
    incident = _seed(client)
    action_id = f"act-{uuid.uuid4().hex[:10]}"
    middle = datetime(2026, 10, 1, 9, 5, 0)
    _add_row(incident["id"], action_id, "RESPONSE_REQUESTED", middle, audit_id="o-b2")
    _add_row(incident["id"], action_id, "RESPONSE_APPROVED", middle, audit_id="o-b1")
    _add_row(incident["id"], action_id, "RESPONSE_CANCELLED", datetime(2026, 10, 1, 8, 0), audit_id="o-a")

    items = _get(client, incident["id"], action_id=action_id, limit=200).json()["items"]
    ordered = [(item["created_at"], item["id"]) for item in items]
    assert ordered == sorted(ordered)
    assert [item["id"] for item in items] == ["o-a", "o-b1", "o-b2"]


def test_pagination_total_and_truncated(client, clean_db):
    incident = _seed(client)
    action_id = f"act-{uuid.uuid4().hex[:10]}"
    base = datetime(2026, 10, 1, 9, 0, 0)
    for index in range(3):
        _add_row(
            incident["id"],
            action_id,
            "RESPONSE_REQUESTED",
            base.replace(minute=index),
            audit_id=f"p-{index}",
        )

    total = _get(client, incident["id"], action_id=action_id).json()["total"]
    assert total == 3

    first = _get(client, incident["id"], action_id=action_id, limit=2, offset=0).json()
    assert first["total"] == 3
    assert len(first["items"]) == 2
    assert first["truncated"] is True

    last = _get(client, incident["id"], action_id=action_id, limit=2, offset=2).json()
    assert last["total"] == 3
    assert len(last["items"]) == 1
    assert last["truncated"] is False

    beyond = _get(client, incident["id"], action_id=action_id, limit=2, offset=3).json()
    assert beyond["items"] == []
    assert beyond["truncated"] is False


def test_pagination_bounds(client, clean_db):
    incident = _seed(client)
    assert _get(client, incident["id"], limit=0).status_code == 422
    assert _get(client, incident["id"], limit=201).status_code == 422
    assert _get(client, incident["id"], offset=-1).status_code == 422
    assert _get(client, incident["id"], limit=200).status_code == 200


# ---------------------------------------------------------------------------
# 6. Rationale exposure
# ---------------------------------------------------------------------------


def test_detail_is_exposed_only_on_the_rejection_row(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    reason = "Confirmed benign after owner review."
    assert (
        client.post(
            f"/api/v1/responses/{action_id}/reject", json={"actor": "operator-1", "reason": reason}
        ).status_code
        == 200
    )

    items = _get(client, incident["id"], action_id=action_id).json()["items"]
    assert items
    for item in items:
        if item["event"] == "RESPONSE_REJECTED":
            assert item["detail"] == reason
        else:
            assert item["detail"] is None, item["event"]


# ---------------------------------------------------------------------------
# 7. Read-only
# ---------------------------------------------------------------------------


def test_activity_read_is_inert(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200
    before = _audit_count(action_id)
    status_before = _status_of(action_id)

    captured, stop = _capture_statements()
    try:
        first = _get(client, incident["id"])
        second = _get(client, incident["id"])
    finally:
        stop()

    assert first.status_code == 200 and second.status_code == 200
    assert first.json() == second.json()
    writes = [
        statement
        for statement in captured
        if statement.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))
    ]
    assert writes == [], writes
    assert _audit_count(action_id) == before
    assert _status_of(action_id) == status_before


def test_activity_does_not_expire_an_overdue_action(client, clean_db):
    incident = _seed(client)
    overdue = _bare_overdue_action(incident["id"])

    body = _get(client, incident["id"], action_id=overdue).json()
    assert body["items"] == [] and body["total"] == 0

    # No expiry transition and no audit row was written by the read.
    assert _status_of(overdue) == "PENDING_APPROVAL"
    assert _audit_count(overdue) == 0
