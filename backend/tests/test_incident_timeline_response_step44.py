"""Incident timeline response-lifecycle tests (Step 44).

The Step 29/35 incident timeline is extended additively: controlled
response lifecycle rows for the incident now appear as ``kind ==
"response"`` entries, interleaved chronologically with the existing
observation, event, audit and resolution entries. This suite proves the
new surface is additive, deterministic, bounded, permission-gated and
read-only, without weakening any earlier step.
"""

from __future__ import annotations

from app.api.v1 import auth_deps
from app.core.config import get_settings
from app.services.auth_service import AuthContext
from tests.test_response_governance import _approve, _request, _seed

TIMELINE_URL = "/api/v1/incidents/{incident_id}/timeline"
REJECT_URL = "/api/v1/responses/{action_id}/reject"
CANCEL_URL = "/api/v1/responses/{action_id}/cancel"
EXECUTE_URL = "/api/v1/responses/{action_id}/execute"

# The complete TimelineEntry contract (Step 44 is additive; no field is
# dropped and no unrelated field is introduced).
ENTRY_FIELDS = {
    "at",
    "kind",
    "label",
    "detail",
    "event_id",
    "event_type",
    "source",
    "severity",
    "entity",
    "explanation",
    "action_id",
    "action_type",
    "event",
    "actor",
    "previous_status",
    "new_status",
}

def _timeline(client, incident_id: str):
    response = client.get(TIMELINE_URL.format(incident_id=incident_id))
    assert response.status_code == 200, response.text
    return response.json()


def _response_entries(payload: dict) -> list[dict]:
    return [entry for entry in payload["entries"] if entry["kind"] == "response"]


def _stamps(payload: dict) -> list:
    return [entry["at"] for entry in payload["entries"] if entry["at"]]


def _configure(monkeypatch, **overrides):
    for key, value in overrides.items():
        monkeypatch.setenv(key, str(value))
    get_settings.cache_clear()
    return get_settings()


def _audit_rows(action_id: str) -> list:
    from app.database.session import get_session_factory
    from app.models.responses import ResponseAudit

    db = get_session_factory()()
    try:
        return (
            db.query(ResponseAudit).filter(ResponseAudit.action_id == action_id).all()
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
    from sqlalchemy import event as sa_event

    from app.database import session as session_module

    engine = session_module.get_engine()
    captured: list[str] = []

    def _before(_conn, _cursor, statement, _parameters, _context, _many):
        captured.append(statement)

    sa_event.listen(engine, "before_cursor_execute", _before)
    return captured, lambda: sa_event.remove(engine, "before_cursor_execute", _before)


# ---------------------------------------------------------------------------
# 1. Entry shape and content
# ---------------------------------------------------------------------------


def test_response_lifecycle_appears_as_response_entries(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200
    assert client.post(EXECUTE_URL.format(action_id=action_id), json={"actor": "operator-2"}).status_code in (
        200,
        201,
    )

    payload = _timeline(client, incident["id"])
    responses = _response_entries(payload)
    events = [entry["event"] for entry in responses]

    assert "RESPONSE_REQUESTED" in events
    assert "RESPONSE_APPROVED" in events
    assert any(event.startswith("RESPONSE_EXECUTION") and event != "RESPONSE_EXECUTION_STARTED" for event in events)

    for entry in responses:
        assert set(entry) == ENTRY_FIELDS
        assert entry["label"].startswith("Response ")
        assert entry["action_id"] == action_id
        assert entry["action_type"] == "BLOCK_INDICATOR"
        assert entry["actor"]
        assert entry["event"]
        assert entry["new_status"]
        # Only the opening event has no prior status; every later event does.
        if entry["event"] == "RESPONSE_REQUESTED":
            assert entry["previous_status"] is None
        else:
            assert entry["previous_status"] is not None
        # Response-scoped fields are populated; event-scoped ones are not.
        for field in ("event_id", "event_type", "source", "severity", "entity"):
            assert entry[field] is None, field


def test_response_entries_are_chronological_with_the_rest(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200

    payload = _timeline(client, incident["id"])
    stamps = _stamps(payload)
    assert stamps == sorted(stamps), stamps

    kinds = [entry["kind"] for entry in payload["entries"]]
    # The first-seen marker leads and any response entries follow it.
    assert kinds[0] == "observation"
    if "response" in kinds:
        assert kinds.index("observation") < kinds.index("response")


def test_response_entries_are_deterministic_across_reads(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200

    first = _timeline(client, incident["id"])
    second = _timeline(client, incident["id"])
    assert first == second


# ---------------------------------------------------------------------------
# 2. Additivity
# ---------------------------------------------------------------------------


def test_incident_without_responses_has_no_response_entries(client, clean_db):
    incident = _seed(client)
    payload = _timeline(client, incident["id"])
    assert payload["entries"], "the seed incident always has a timeline"
    assert all(entry["kind"] != "response" for entry in payload["entries"])


def test_every_entry_still_satisfies_the_original_contract(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200

    payload = _timeline(client, incident["id"])
    for entry in payload["entries"]:
        assert set(entry) == ENTRY_FIELDS
        assert entry["label"] and entry["kind"]


# ---------------------------------------------------------------------------
# 3. Permission gating
# ---------------------------------------------------------------------------


def test_response_entries_hidden_without_read_responses(client, clean_db, monkeypatch):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200

    def _read_incidents_only(_db, _authorization):
        return AuthContext(
            authenticated=True,
            enforcement=True,
            username="incidents-only",
            user_id="incidents-only",
            roles=("VIEWER",),
            permissions=frozenset({"READ_INCIDENTS"}),
        )

    monkeypatch.setattr(auth_deps.auth_service, "resolve_context", _read_incidents_only)

    payload = _timeline(client, incident["id"])
    assert payload["entries"], "READ_INCIDENTS still sees the base timeline"
    assert _response_entries(payload) == []


def test_response_entries_visible_with_read_responses(client, clean_db, monkeypatch):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200

    def _both(_db, _authorization):
        return AuthContext(
            authenticated=True,
            enforcement=True,
            username="reader",
            user_id="reader",
            roles=("SECURITY_ANALYST",),
            permissions=frozenset({"READ_INCIDENTS", "READ_RESPONSES"}),
        )

    monkeypatch.setattr(auth_deps.auth_service, "resolve_context", _both)

    payload = _timeline(client, incident["id"])
    assert _response_entries(payload), "READ_RESPONSES sees response lifecycle entries"


def test_timeline_still_requires_read_incidents(client, clean_db, monkeypatch):
    from tests.test_auth import _admin_headers

    incident = _seed(client)
    _admin_headers(client)  # enforcement active
    assert client.get(TIMELINE_URL.format(incident_id=incident["id"])).status_code == 401


# ---------------------------------------------------------------------------
# 4. No rationale duplication
# ---------------------------------------------------------------------------


def test_timeline_does_not_duplicate_the_rejection_rationale(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    rationale = "unique-rationale-marker-9f2d"
    assert (
        client.post(REJECT_URL.format(action_id=action_id), json={"actor": "op", "reason": rationale}).status_code
        == 200
    )

    payload = _timeline(client, incident["id"])
    rejected = [entry for entry in _response_entries(payload) if entry["event"] == "RESPONSE_REJECTED"]
    assert len(rejected) == 1
    assert rejected[0]["previous_status"] == "PENDING_APPROVAL"
    assert rejected[0]["new_status"] == "REJECTED"
    # The rationale belongs to the per-action audit endpoint, not here.
    assert rationale not in str(payload)


# ---------------------------------------------------------------------------
# 5. Bounded and read-only
# ---------------------------------------------------------------------------


def test_timeline_truncation_keeps_observation_and_resolution(client, clean_db, monkeypatch):
    from tests.test_incident_intelligence import _recalc, _seed_auth_chain

    incident_id, _ = _seed_auth_chain(client)
    client.post(f"/api/v1/incidents/{incident_id}/status", json={"status": "ACKNOWLEDGED"})
    client.post(f"/api/v1/incidents/{incident_id}/status", json={"status": "CLOSED"})
    _recalc(client, incident_id)

    _configure(monkeypatch, CORRELATION_TIMELINE_MAX_ENTRIES="10")
    payload = _timeline(client, incident_id)
    assert payload["truncated"] is True
    assert len(payload["entries"]) == 10
    assert payload["entries"][0]["kind"] == "observation"
    assert payload["entries"][-1]["kind"] == "resolution"


def test_reading_the_timeline_never_mutates_response_state(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200
    before_rows = {row.id for row in _audit_rows(action_id)}
    before_status = _status_of(action_id)

    captured, stop = _capture_statements()
    try:
        payload = _timeline(client, incident["id"])
    finally:
        stop()

    assert _response_entries(payload)
    writes = [
        statement
        for statement in captured
        if statement.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))
    ]
    assert writes == [], writes
    assert {row.id for row in _audit_rows(action_id)} == before_rows
    assert _status_of(action_id) == before_status


def test_response_entries_carry_no_request_id(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200

    payload = _timeline(client, incident["id"])
    for entry in _response_entries(payload):
        assert "request_id" not in entry
        assert "request_id" not in str(entry.values())
