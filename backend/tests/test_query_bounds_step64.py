"""Step 64 - bounded audit histories for events and incidents.

The event ingest audit trail (``GET /events/{id}/audit``) and the incident
audit trail (``GET /incidents/{id}/audit``) read *every* fact for their
subject with no ceiling. The event trail grows on every ingest/replay pass
(``EventAudit`` is appended per pass), so an unbounded select there is a read
whose cost is set by data volume rather than by the caller - the mirror of
the deterministic-pagination fixes in Step 57.

Step 64 bounds and pages both trails: rows stay ordered ``(created_at, id)``,
``limit``/``offset`` select the page (``limit`` defaults to 50 and is capped
at 200), and ``total`` reports the full count so the complete history stays
reachable by paging. ``entries`` keeps its existing shape and field names.

These tests seed more facts than the default ceiling allows and assert the
cap, the page walk (no duplicates, no omissions), the deterministic order,
and the unchanged entry shape. No ``sleep``; timestamps are explicit.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from app.database import session as session_module

TS = datetime(2026, 1, 5, 12, 0, 0)


def _seed_event_with_audit(db, event_id: str, count: int) -> None:  # noqa: ANN001
    from app.models.events import EventAudit, SecurityEvent

    db.add(
        SecurityEvent(
            id=event_id,
            event_time=TS,
            source_type="SURICATA",
            source_name="fixture",
            event_type="audit.bound",
            severity="LOW",
            title="bounded audit subject",
            fingerprint=f"fp-{event_id}",
            normalized_data="{}",
        )
    )
    for index in range(count):
        db.add(
            EventAudit(
                id=f"ea-{index:04d}",
                event_id=event_id,
                action="EVENT_NORMALIZED",
                actor="system",
                detail=f"fact {index}",
                created_at=TS + timedelta(seconds=index),
            )
        )


def _seed_incident_with_audit(db, incident_id: str, count: int) -> None:  # noqa: ANN001
    from app.models.correlations import Correlation
    from app.models.incidents import Incident, IncidentAudit

    db.add(
        Correlation(
            id="corr-bound",
            rule_id="bound-rule",
            rule_name="Bound rule",
            title="bounded subject",
            severity="LOW",
            window_start=TS,
            window_end=TS,
        )
    )
    db.add(
        Incident(
            id=incident_id,
            incident_key="INC-BOUND-000001",
            title="bounded audit subject",
            severity="LOW",
            correlation_id="corr-bound",
            risk_assessment_id=None,
            first_seen=TS,
            last_seen=TS,
        )
    )
    for index in range(count):
        db.add(
            IncidentAudit(
                id=f"ia-{index:04d}",
                incident_id=incident_id,
                action="OPENED" if index == 0 else "UPDATED",
                actor="system",
                detail=f"fact {index}",
                created_at=TS + timedelta(seconds=index),
            )
        )


def _walk(client, path: str, page: int) -> list[str]:
    """Page the whole trail; return every entry's ``detail`` in order."""
    details: list[str] = []
    offset = 0
    while True:
        body = client.get(path, params={"limit": page, "offset": offset}).json()
        batch = [entry["detail"] for entry in body["entries"]]
        details.extend(batch)
        offset += page
        if not batch or offset >= body["total"]:
            return details


# ---------------------------------------------------------------------------
# Event ingest audit trail
# ---------------------------------------------------------------------------


def test_event_audit_is_bounded_by_default(client, clean_db):
    from app.api.v1.endpoints.events import MAX_LIMIT

    count = MAX_LIMIT + 5
    db = session_module.get_session_factory()()
    try:
        _seed_event_with_audit(db, "evt-bound", count)
        db.commit()
    finally:
        db.close()

    body = client.get("/api/v1/events/evt-bound/audit").json()
    assert body["total"] == count
    assert body["limit"] == 50
    assert body["offset"] == 0
    assert body["truncated"] is True
    assert len(body["entries"]) == 50  # the default ceiling, not the world
    assert body["entries"][0]["detail"] == "fact 0"  # oldest first, deterministic


def test_event_audit_pages_the_full_history(client, clean_db):
    from app.api.v1.endpoints.events import MAX_LIMIT

    count = MAX_LIMIT + 5
    db = session_module.get_session_factory()()
    try:
        _seed_event_with_audit(db, "evt-bound", count)
        db.commit()
    finally:
        db.close()

    page = client.get(
        "/api/v1/events/evt-bound/audit", params={"limit": 10}
    ).json()
    assert page["total"] == count
    assert page["truncated"] is True
    assert [entry["detail"] for entry in page["entries"]] == [f"fact {i}" for i in range(10)]

    tail = client.get(
        "/api/v1/events/evt-bound/audit", params={"limit": MAX_LIMIT, "offset": MAX_LIMIT}
    ).json()
    assert [entry["detail"] for entry in tail["entries"]] == [f"fact {i}" for i in range(count - 5, count)]
    assert tail["truncated"] is False  # the last page is the end of the trail

    walked = _walk(client, "/api/v1/events/evt-bound/audit", 100)
    assert walked == [f"fact {i}" for i in range(count)]
    assert len(set(walked)) == count  # no duplicates, no omissions


def test_event_audit_entry_shape_is_unchanged(client, clean_db):
    db = session_module.get_session_factory()()
    try:
        _seed_event_with_audit(db, "evt-shape", 1)
        db.commit()
    finally:
        db.close()

    body = client.get("/api/v1/events/evt-shape/audit").json()
    assert set(body["entries"][0]) == {"action", "actor", "detail", "created_at"}
    assert body["event_id"] == "evt-shape"


# ---------------------------------------------------------------------------
# Incident audit trail
# ---------------------------------------------------------------------------


def test_incident_audit_is_bounded_and_pageable(client, clean_db):
    from app.api.v1.endpoints.incidents import MAX_LIMIT

    count = MAX_LIMIT + 5
    db = session_module.get_session_factory()()
    try:
        _seed_incident_with_audit(db, "inc-bound", count)
        db.commit()
    finally:
        db.close()

    body = client.get("/api/v1/incidents/inc-bound/audit").json()
    assert body["total"] == count
    assert body["limit"] == 50 and body["offset"] == 0
    assert body["truncated"] is True
    assert len(body["entries"]) == 50
    assert body["entries"][0]["action"] == "OPENED"

    page = client.get(
        "/api/v1/incidents/inc-bound/audit", params={"limit": 3, "offset": 1}
    ).json()
    assert [entry["detail"] for entry in page["entries"]] == ["fact 1", "fact 2", "fact 3"]
    assert page["truncated"] is True

    walked = _walk(client, "/api/v1/incidents/inc-bound/audit", 100)
    assert walked == [f"fact {i}" for i in range(count)]
    assert len(set(walked)) == count


# ---------------------------------------------------------------------------
# The page-size ceiling is enforced at validation time
# ---------------------------------------------------------------------------


def test_audit_limit_above_ceiling_is_rejected(client, clean_db):
    """``limit=201`` (one past the 200 cap) is refused with 422 on both trails."""
    from app.api.v1.endpoints.events import MAX_LIMIT as EVENTS_MAX_LIMIT
    from app.api.v1.endpoints.incidents import MAX_LIMIT as INCIDENTS_MAX_LIMIT

    # Guard the documented cap both endpoints share.
    assert EVENTS_MAX_LIMIT == INCIDENTS_MAX_LIMIT == 200

    db = session_module.get_session_factory()()
    try:
        _seed_event_with_audit(db, "evt-limit", 1)
        _seed_incident_with_audit(db, "inc-limit", 1)
        db.commit()
    finally:
        db.close()

    paths = ("/api/v1/events/evt-limit/audit", "/api/v1/incidents/inc-limit/audit")
    for path in paths:
        # One past the ceiling: rejected by query-param validation (422), so the
        # handler never runs. The cap itself stays inclusive.
        assert client.get(path, params={"limit": 201}).status_code == 422, path
        assert client.get(path, params={"limit": 200}).status_code == 200, path

