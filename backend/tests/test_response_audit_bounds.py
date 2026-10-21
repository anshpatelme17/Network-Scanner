"""Bounded embedded response-audit history on the v1 response detail.

``GET /api/v1/responses/{id}`` used to read every ``ResponseAudit`` row for
the action with no ceiling. The detail response now returns one bounded page,
ordered ``(created_at, id)``, plus additive metadata so a caller can tell a
complete short history from a capped page. The dedicated v2 audit endpoint
and its ``ResponseAuditPage`` contract are unchanged.

These tests prove the SQL bound and count, the default page and ceiling,
offset/truncation semantics across an oversized history, deterministic
ordering when timestamps tie, the empty-history shape, compatibility of the
existing detail/entry fields, and the unchanged ``READ_RESPONSES`` gate.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from app.database import session as session_module

TS = datetime(2026, 1, 5, 12, 0, 0)
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


def _seed_action(action_id: str, count: int = 0, *, same_timestamp: bool = False) -> None:
    """Insert one response action and ``count`` stored audit rows."""
    from app.models.responses import ResponseAction, ResponseAudit

    db = session_module.get_session_factory()()
    try:
        db.add(
            ResponseAction(
                id=action_id,
                incident_id="inc-response-audit-bounds",
                action_type="BLOCK_INDICATOR",
                target_type="IP",
                target_reference="192.0.2.60",
                reason="Bounded response-audit fixture.",
                requested_by="analyst-1",
                status="PENDING_APPROVAL",
                dry_run=True,
                policy_version="1.0.0",
                provider="MOCK",
                approval_required=True,
            )
        )
        db.flush()
        indexes = reversed(range(count)) if same_timestamp else range(count)
        for index in indexes:
            db.add(
                ResponseAudit(
                    id=f"ra-{index:04d}",
                    action_id=action_id,
                    incident_id="inc-response-audit-bounds",
                    event="RESPONSE_REQUESTED",
                    previous_status=None,
                    new_status="PENDING_APPROVAL",
                    actor="analyst-1",
                    policy_version="1.0.0",
                    created_at=TS if same_timestamp else TS + timedelta(seconds=index),
                )
            )
        db.commit()
    finally:
        db.close()


def _detail(client, action_id: str, **params: object):
    return client.get(f"/api/v1/responses/{action_id}", params=params)


def _capture_statements():
    from sqlalchemy import event as sa_event

    engine = session_module.get_engine()
    captured: list[str] = []

    def _before(_conn, _cursor, statement, _parameters, _context, _many):
        captured.append(statement)

    sa_event.listen(engine, "before_cursor_execute", _before)
    return captured, lambda: sa_event.remove(engine, "before_cursor_execute", _before)


def test_embedded_audit_read_is_bounded_in_sql(client, clean_db):
    action_id = "resp-audit-sql"
    _seed_action(action_id, 55)

    captured, stop = _capture_statements()
    try:
        response = _detail(client, action_id)
    finally:
        stop()

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["audit_total"] == 55
    assert body["audit_limit"] == 50
    assert body["audit_offset"] == 0
    assert body["audit_truncated"] is True
    assert len(body["audit"]) == 50
    assert body["audit"][0]["id"] == "ra-0000"

    audit_statements = [
        statement for statement in captured if "from response_audit" in statement.lower()
    ]
    page_statements = [
        statement for statement in audit_statements if "order by" in statement.lower()
    ]
    count_statements = [
        statement for statement in audit_statements if "order by" not in statement.lower()
    ]
    assert len(page_statements) == 1
    assert len(count_statements) == 1
    page = " ".join(page_statements[0].split()).upper()
    count = " ".join(count_statements[0].split()).upper()
    assert "LIMIT" in page
    assert "OFFSET" in page
    assert "COUNT(" in count


def test_embedded_audit_pages_an_oversized_history(client, clean_db):
    count = 205
    action_id = "resp-audit-page"
    _seed_action(action_id, count)

    first = _detail(client, action_id).json()
    assert first["audit_total"] == count
    assert first["audit_limit"] == 50
    assert first["audit_offset"] == 0
    assert first["audit_truncated"] is True
    assert [entry["id"] for entry in first["audit"]] == [f"ra-{i:04d}" for i in range(50)]

    middle = _detail(client, action_id, limit=100, offset=100).json()
    assert middle["audit_total"] == count
    assert middle["audit_limit"] == 100
    assert middle["audit_offset"] == 100
    assert middle["audit_truncated"] is True
    assert [entry["id"] for entry in middle["audit"]] == [f"ra-{i:04d}" for i in range(100, 200)]

    tail = _detail(client, action_id, limit=100, offset=200).json()
    assert tail["audit_total"] == count
    assert tail["audit_offset"] == 200
    assert tail["audit_truncated"] is False
    assert [entry["id"] for entry in tail["audit"]] == [f"ra-{i:04d}" for i in range(200, 205)]

    beyond = _detail(client, action_id, limit=100, offset=300).json()
    assert beyond["audit"] == []
    assert beyond["audit_total"] == count
    assert beyond["audit_truncated"] is False


def test_embedded_audit_pagination_parameters_are_validated(client, clean_db):
    action_id = "resp-audit-invalid"
    _seed_action(action_id, 1)

    assert _detail(client, action_id, limit=0).status_code == 422
    assert _detail(client, action_id, limit=201).status_code == 422
    assert _detail(client, action_id, offset=-1).status_code == 422
    assert _detail(client, action_id, limit=200).status_code == 200


def test_embedded_audit_order_is_deterministic_when_timestamps_tie(client, clean_db):
    action_id = "resp-audit-tied"
    _seed_action(action_id, 5, same_timestamp=True)

    body = _detail(client, action_id).json()
    assert [entry["id"] for entry in body["audit"]] == [f"ra-{i:04d}" for i in range(5)]


def test_empty_embedded_audit_history_is_an_empty_page(client, clean_db):
    action_id = "resp-audit-empty"
    _seed_action(action_id)

    response = _detail(client, action_id)
    assert response.status_code == 200
    body = response.json()
    assert body["audit"] == []
    assert body["audit_total"] == 0
    assert body["audit_limit"] == 50
    assert body["audit_offset"] == 0
    assert body["audit_truncated"] is False
    assert body["status"] == "PENDING_APPROVAL"


def test_existing_detail_and_audit_entry_shape_are_preserved(client, clean_db):
    action_id = "resp-audit-shape"
    _seed_action(action_id, 1)

    body = _detail(client, action_id).json()
    assert set(body["audit"][0]) == ENTRY_FIELDS
    assert body["audit"][0]["event"] == "RESPONSE_REQUESTED"
    assert body["audit"][0]["actor"] == "analyst-1"
    assert {
        "id",
        "incident_id",
        "action_type",
        "status",
        "audit",
        "execution",
        "rollback",
        "audit_total",
        "audit_limit",
        "audit_offset",
        "audit_truncated",
    } <= set(body)
    assert body["execution"] is None
    assert body["rollback"] is None


def test_embedded_audit_read_preserves_read_responses_gate(client, clean_db, monkeypatch):
    from app.api.v1 import auth_deps
    from app.services.auth_service import AuthContext
    from tests.test_auth import _admin_headers

    action_id = "resp-audit-auth"
    _seed_action(action_id, 1)
    headers = _admin_headers(client)

    assert client.get(f"/api/v1/responses/{action_id}").status_code == 401
    assert client.get(f"/api/v1/responses/{action_id}", headers=headers).status_code == 200

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
    refused = client.get(f"/api/v1/responses/{action_id}", headers=headers)
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "PERMISSION_DENIED"
    assert "READ_RESPONSES" in refused.json()["error"]["message"]
