"""Incident audit-trail integrity and hardening (Step 49).

Step 43 hardens the *controlled-response* audit trail. Step 49 does the
same for the *incident* lifecycle trail (``IncidentAudit``), which the
incident timeline projects: the incident record must be an attributed,
incident-scoped, append-only, non-leaking account of what actually
happened, with no transition invented and none silently dropped.

Covered here, adversarially:

* opening an incident appends exactly one attributed ``OPENED`` row scoped
  to that incident, and no row of one incident is visible under another;
* an accepted sequence of status changes appends an ordered, attributed
  ``STATUS_CHANGED`` chain whose detail records each real old -> new edge;
* a refused transition (unknown status, or an edge the transition table
  forbids) is a 422 that writes no row and leaves the incident untouched;
* editing only records an audit row when something actually changed; a
  no-op edit appends nothing;
* the stored actor is bounded to the column size and defaults to
  ``system`` when omitted;
* reading the timeline is inert and repeatable (no write statement, no
  history drift) and never exposes the internal ``request_id``;
* an unrecognised stored action still renders as the generic ``audit``
  kind with the full, fixed entry contract rather than being dropped or
  crashing the projection.

Test-only: it asserts behaviour the incident service and timeline already
implement, reusing the real API/service paths so the rows are
indistinguishable from production ones.
"""

from __future__ import annotations

import json
import re
from datetime import datetime

from tests.test_audit_integrity_step43 import _capture_statements
from tests.test_incident_timeline_response_step44 import ENTRY_FIELDS
from tests.test_response_governance import _seed

PATCH_URL = "/api/v1/incidents/{incident_id}"
STATUS_URL = "/api/v1/incidents/{incident_id}/status"
TIMELINE_URL = "/api/v1/incidents/{incident_id}/timeline"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rows(incident_id: str, action: str | None = None) -> list:
    from app.database.session import get_session_factory
    from app.models.incidents import IncidentAudit

    db = get_session_factory()()
    try:
        query = db.query(IncidentAudit).filter(IncidentAudit.incident_id == incident_id)
        if action is not None:
            query = query.filter(IncidentAudit.action == action)
        return query.order_by(IncidentAudit.created_at, IncidentAudit.id).all()
    finally:
        db.close()


def _incident_state(incident_id: str):
    from app.database.session import get_session_factory
    from app.models.incidents import Incident

    db = get_session_factory()()
    try:
        row = db.get(Incident, incident_id)
        return row.status, row.resolved_at
    finally:
        db.close()


def _add_audit_row(incident_id: str, action: str, *, actor="operator-9", detail=None) -> str:
    from app.database.session import get_session_factory
    from app.models.incidents import IncidentAudit

    db = get_session_factory()()
    try:
        row = IncidentAudit(
            incident_id=incident_id,
            action=action,
            actor=actor,
            detail=detail,
            created_at=datetime(2026, 10, 1, 12, 0, 0),
        )
        db.add(row)
        db.commit()
        return row.id
    finally:
        db.close()


def _timeline(client, incident_id: str) -> dict:
    response = client.get(TIMELINE_URL.format(incident_id=incident_id))
    assert response.status_code == 200, response.text
    return response.json()


# ---------------------------------------------------------------------------
# 1. Opening is attributed and scoped
# ---------------------------------------------------------------------------


def test_incident_open_audit_is_attributed_and_scoped(client, clean_db):
    incident = _seed(client)

    rows = _rows(incident["id"])
    assert len(rows) == 1
    opened = rows[0]
    assert opened.action == "OPENED"
    assert opened.incident_id == incident["id"]
    assert opened.actor, "an audit row must carry an actor"
    assert opened.detail and "correlation" in opened.detail

    # No incident's rows may surface under another incident's id.
    assert _rows("inc-incident-does-not-exist") == []

    body = _timeline(client, incident["id"])
    opened_entries = [entry for entry in body["entries"] if entry["kind"] == "opened"]
    assert len(opened_entries) == 1
    assert opened_entries[0]["label"] == "Opened"
    # The projection contract is complete and identical for every entry.
    assert set(opened_entries[0]) == ENTRY_FIELDS
    # The internal correlation id never reaches the client.
    assert "request_id" not in json.dumps(body)


# ---------------------------------------------------------------------------
# 2. Status changes append an ordered, attributed chain
# ---------------------------------------------------------------------------


def test_status_changes_append_an_ordered_attributed_chain(client, clean_db):
    incident = _seed(client)

    for target in ("ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"):
        changed = client.patch(
            STATUS_URL.format(incident_id=incident["id"]),
            json={"status": target, "actor": "operator-1"},
        )
        assert changed.status_code == 200, changed.text

    rows = _rows(incident["id"], action="STATUS_CHANGED")
    assert len(rows) == 3
    assert all(row.actor == "operator-1" for row in rows)
    assert len({row.id for row in rows}) == 3

    # The stored rows are ordered by (created_at, id); a same-second tie makes
    # the id tiebreak decide the returned order, so the *chain* (not the row
    # order) is what must be coherent: the three edges must join OPEN to
    # RESOLVED with no gap or invented step.
    edges = {}
    for row in rows:
        match = re.fullmatch(r"Status changed from (\w+) to (\w+)\.", row.detail or "")
        assert match, row.detail
        edges[match.group(1)] = match.group(2)
    assert edges == {
        "OPEN": "ACKNOWLEDGED",
        "ACKNOWLEDGED": "INVESTIGATING",
        "INVESTIGATING": "RESOLVED",
    }

    status, resolved_at = _incident_state(incident["id"])
    assert status == "RESOLVED"
    assert resolved_at is not None

    status_entries = [
        entry for entry in _timeline(client, incident["id"])["entries"] if entry["kind"] == "status"
    ]
    assert [entry["label"] for entry in status_entries] == ["Status changed"] * 3


# ---------------------------------------------------------------------------
# 3. Refused transitions write nothing (hostile)
# ---------------------------------------------------------------------------


def test_refused_transition_writes_no_audit_row(client, clean_db):
    incident = _seed(client)
    before = {row.id for row in _rows(incident["id"])}

    # INVESTIGATING is not reachable directly from OPEN, and the second value
    # is not a status at all; both must fail closed.
    for bad in ("INVESTIGATING", "NOT_A_STATUS"):
        refused = client.patch(
            STATUS_URL.format(incident_id=incident["id"]),
            json={"status": bad, "actor": "operator-1"},
        )
        assert refused.status_code == 422, refused.text
        assert refused.json()["error"]["code"] == "INVALID_TRANSITION"

    assert {row.id for row in _rows(incident["id"])} == before
    assert _rows(incident["id"], action="STATUS_CHANGED") == []
    assert _incident_state(incident["id"])[0] == "OPEN"


# ---------------------------------------------------------------------------
# 4. Edits only audit a real change
# ---------------------------------------------------------------------------


def test_edit_only_records_a_real_change(client, clean_db):
    incident = _seed(client)
    base = _rows(incident["id"])

    noop = client.patch(
        PATCH_URL.format(incident_id=incident["id"]), json={"actor": "operator-1"}
    )
    assert noop.status_code == 200
    assert len(_rows(incident["id"])) == len(base)

    edited = client.patch(
        PATCH_URL.format(incident_id=incident["id"]),
        json={"title": "Reviewed title", "actor": "operator-1"},
    )
    assert edited.status_code == 200
    rows = _rows(incident["id"])
    assert len(rows) == len(base) + 1
    updated = [row for row in rows if row.action == "UPDATED"]
    assert len(updated) == 1
    assert updated[0].actor == "operator-1"
    assert updated[0].detail == "Title/description edited."


# ---------------------------------------------------------------------------
# 5. Actor attribution is bounded and defaulted
# ---------------------------------------------------------------------------


def test_actor_is_bounded_and_defaults_to_system(client, clean_db):
    incident = _seed(client)
    from app.database.session import get_session_factory
    from app.models.incidents import Incident
    from app.services import incident_service

    db = get_session_factory()()
    try:
        row = db.get(Incident, incident["id"])
        incident_service.set_status(db, row, "ACKNOWLEDGED", "x" * 300)
        row = db.get(Incident, incident["id"])
        incident_service.set_status(db, row, "INVESTIGATING", "")
    finally:
        db.close()

    rows = _rows(incident["id"], action="STATUS_CHANGED")
    actors = [row.actor for row in rows]
    assert len(actors) == 2
    # Order is decided by the (created_at, id) tiebreak on a same-second tie,
    # so assert the actor *set*: one defaulted, one bounded to the column.
    assert "system" in actors
    bounded = [actor for actor in actors if actor != "system"]
    assert len(bounded) == 1
    assert len(bounded[0]) == 128
    assert set(bounded[0]) == {"x"}


# ---------------------------------------------------------------------------
# 6. The read path is inert (stateful)
# ---------------------------------------------------------------------------


def test_timeline_reads_are_inert_and_repeatable(client, clean_db):
    incident = _seed(client)
    assert (
        client.patch(
            STATUS_URL.format(incident_id=incident["id"]),
            json={"status": "ACKNOWLEDGED", "actor": "operator-1"},
        ).status_code
        == 200
    )
    before = {row.id for row in _rows(incident["id"])}

    captured, stop = _capture_statements()
    try:
        first = client.get(TIMELINE_URL.format(incident_id=incident["id"]))
        second = client.get(TIMELINE_URL.format(incident_id=incident["id"]))
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
    assert {row.id for row in _rows(incident["id"])} == before


# ---------------------------------------------------------------------------
# 7. An unknown stored action still projects safely
# ---------------------------------------------------------------------------


def test_unknown_audit_action_renders_as_generic_kind(client, clean_db):
    incident = _seed(client)
    _add_audit_row(incident["id"], "OPAQUE_ACTION", actor="operator-9", detail="synthetic")

    body = _timeline(client, incident["id"])
    matches = [
        entry
        for entry in body["entries"]
        if entry["kind"] == "audit" and entry["label"] == "Opaque action"
    ]
    assert len(matches) == 1
    assert matches[0]["detail"].startswith("operator-9:")
    assert set(matches[0]) == ENTRY_FIELDS
