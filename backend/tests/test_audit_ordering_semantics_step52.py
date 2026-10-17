"""Audit ordering and temporal semantics (Step 52).

Step 52 pins the *ordering* contract the Phase 4 accountability surfaces
already rely on and, just as importantly, states its limits honestly. It
adds no production code: every rule asserted here is the behaviour the
models, services and read endpoints already have.

What the investigation established:

* **Where the timestamp comes from.** ``ResponseAudit.created_at`` is
  assigned by the application (a Python-side column default,
  ``_utcnow_naive``, with microsecond resolution and no database
  default); ``IncidentAudit.created_at`` is assigned by the database
  (``server_default=func.now()``, no Python default). On the SQLite test
  engine ``CURRENT_TIMESTAMP`` is second-precision, so incident audit
  rows written in the same second carry an identical ``created_at``.

* **The read contract.** Every raw audit feed (``GET .../audit``,
  ``.../activity`` and the v2 ``/responses/{action_id}/audit``) orders by
  ``created_at`` ascending and then by ``id`` (the stored string id) as a
  total-order tiebreak. The order is therefore deterministic and stable
  across reads, but it is **not** insertion order: when timestamps
  collide the tie is resolved by the ``id`` value, which for the
  application-generated UUID ids carries no chronological meaning.

* **The timeline is a different view.** ``GET .../timeline`` is a merged
  record (observations, evidence events, lifecycle audits, response
  lifecycle) and sorts by its own deterministic key — timestamp, then a
  fixed source rank, then insertion sequence — not by ``id``. It is
  deterministic and repeatable, but it is not the same ``(created_at,
  id)`` order as the raw feeds.

* **Concurrency.** Ordering does not depend on how concurrent requests
  interleave: each row's ``created_at`` is fixed when it is inserted and
  every read re-derives the order from the stored columns. Concurrent
  lifecycle transitions are serialised by the governance layer (Step 41 /
  the gated concurrency tests), which is a separate guarantee from the
  ordering asserted here.

* **No fabricated times.** ``created_at`` is never caller-supplied: the
  request schemas forbid unknown fields, so a client cannot inject or
  forge an event time.
"""

from __future__ import annotations

from datetime import UTC, datetime

from tests.test_incident_activity_step45 import ACTIVITY_URL
from tests.test_response_governance import _approve, _request, _seed


def _add_incident_audit(
    incident_id: str,
    action: str,
    actor: str,
    detail: str | None,
    created_at: datetime,
    audit_id: str,
) -> None:
    from app.database.session import get_session_factory
    from app.models.incidents import IncidentAudit

    db = get_session_factory()()
    try:
        db.add(
            IncidentAudit(
                id=audit_id,
                incident_id=incident_id,
                action=action,
                actor=actor,
                detail=detail,
                created_at=created_at,
            )
        )
        db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 1. Assignment side and precision
# ---------------------------------------------------------------------------


def test_response_audit_timestamp_is_application_assigned(client, clean_db):
    """The response audit clock is the app's, not the database's."""
    from app.database.session import get_session_factory
    from app.models.responses import ResponseAudit

    column = ResponseAudit.__table__.c.created_at
    assert column.server_default is None, "no database default: the app supplies the value"
    assert column.default is not None and callable(column.default.arg)

    db = get_session_factory()()
    try:
        row = ResponseAudit(
            id="ts-app-1",
            action_id="act-ts-app",
            incident_id="inc-ts-app",
            event="RESPONSE_REQUESTED",
            actor="analyst-1",
            policy_version="1.0.0",
        )
        db.add(row)
        db.flush()
        assert row.created_at is not None
        now = datetime.now(UTC).replace(tzinfo=None)
        assert abs((now - row.created_at).total_seconds()) < 5
    finally:
        db.close()


def test_incident_audit_timestamp_is_database_assigned(client, clean_db):
    """The incident audit clock is the database's, and it is second-precise."""
    from app.database.session import get_session_factory
    from app.models.incidents import IncidentAudit
    from app.services.incident_service import record_audit

    column = IncidentAudit.__table__.c.created_at
    assert column.server_default is not None, "the database supplies the value"
    assert column.default is None

    db = get_session_factory()()
    try:
        row = record_audit(db, "inc-ts-db", "OPENED", "system")
        db.commit()
        db.refresh(row)
        assert row.created_at is not None
        # SQLite CURRENT_TIMESTAMP has whole-second resolution; the value the
        # app-side response-audit default can carry microseconds, this cannot.
        assert row.created_at.microsecond == 0
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 2. Deterministic, but not insertion-ordered
# ---------------------------------------------------------------------------


def test_same_timestamp_incident_audits_order_by_id_not_insertion(client, clean_db):
    """A timestamp collision is settled by ``id``, so insertion order is lost."""
    incident = _seed(client)
    fixed = datetime(2001, 1, 1, 0, 0, 0)

    # Inserted zzz first, aaa second; both share one created_at. The endpoint
    # orders by (created_at, id), so aaa must come first regardless.
    _add_incident_audit(incident["id"], "OPENED", "system", "zzz-marker", fixed, "zzz-sort-key")
    _add_incident_audit(incident["id"], "UPDATED", "system", "aaa-marker", fixed, "aaa-sort-key")

    entries = client.get(f"/api/v1/incidents/{incident['id']}/audit").json()["entries"]
    markers = [entry for entry in entries if entry["detail"] in ("aaa-marker", "zzz-marker")]

    assert [entry["detail"] for entry in markers] == ["aaa-marker", "zzz-marker"]
    # Both rows really do collide on the timestamp, so id is the only tiebreak.
    assert markers[0]["created_at"] == markers[1]["created_at"]


def test_appending_events_never_reorders_earlier_history(client, clean_db):
    """History is append-only: later events never move earlier rows."""
    incident = _seed(client)
    created = _request(client, incident["id"])
    assert created.status_code == 201, created.text
    action_id = created.json()["id"]

    url = ACTIVITY_URL.format(incident_id=incident["id"])
    params = {"action_id": action_id, "limit": 200}
    first_ids = [item["id"] for item in client.get(url, params=params).json()["items"]]
    assert first_ids, "the request itself writes audit rows"

    approved = _approve(client, action_id)
    assert approved.status_code == 200, approved.text

    second_ids = [item["id"] for item in client.get(url, params=params).json()["items"]]
    assert len(second_ids) > len(first_ids)
    assert second_ids[: len(first_ids)] == first_ids


# ---------------------------------------------------------------------------
# 3. The timeline's own deterministic merge order
# ---------------------------------------------------------------------------


def test_timeline_merge_order_is_deterministic_and_repeatable(client, clean_db):
    """The merged timeline reads the same way twice and never goes backwards."""
    incident = _seed(client)
    url = f"/api/v1/incidents/{incident['id']}/timeline"

    first = client.get(url).json()["entries"]
    second = client.get(url).json()["entries"]

    def shape(entry):
        return (entry["kind"], entry["label"], entry["at"])

    assert [shape(entry) for entry in first] == [shape(entry) for entry in second]

    stamps = [entry["at"] for entry in first]
    assert stamps == sorted(stamps)
    assert first[0]["kind"] == "observation"


# ---------------------------------------------------------------------------
# 4. No fabricated event times
# ---------------------------------------------------------------------------


def test_created_at_is_not_caller_supplied(client, clean_db):
    """A client cannot inject a timestamp: request schemas forbid it."""
    from app.schemas.incidents import IncidentCreate
    from app.schemas.responses import ResponseProposalRequest

    assert "created_at" not in IncidentCreate.model_fields
    assert "created_at" not in ResponseProposalRequest.model_fields

    response = client.post(
        "/api/v1/incidents",
        json={"correlation_id": "x", "created_at": "1999-01-01T00:00:00"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
