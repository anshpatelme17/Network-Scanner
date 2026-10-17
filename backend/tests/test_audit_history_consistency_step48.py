"""Incident audit-history consistency (Step 48).

Step 48 verifies that the three read surfaces that project the *same*
``ResponseAudit`` rows agree with one another for one incident:

* the per-action audit feed, ``GET /api/v2/responses/{action_id}/audit``;
* the incident timeline response entries, ``GET /api/v1/incidents/{id}/timeline``
  (``kind == "response"``);
* the incident activity feed, ``GET /api/v1/incidents/{id}/activity``.

All three are projections of one append-only table, so a returned row must
carry the same event, actor, status transition and timestamp everywhere —
a divergence would mean one surface is fabricating or dropping history.
The tests also pin the properties the plan calls out: no invented
transitions for a still-pending action, a shared deterministic ordering,
and the rejection rationale staying identical between the per-action audit
and the activity feed while not being duplicated onto the timeline.

Test-only: it asserts behaviour the three endpoints already implement.
"""

from __future__ import annotations

import json

from tests.test_incident_activity_step45 import ACTIVITY_URL
from tests.test_response_governance import _approve, _request, _seed

V2_AUDIT_URL = "/api/v2/responses/{action_id}/audit"
TIMELINE_URL = "/api/v1/incidents/{incident_id}/timeline"

# Fields shared by the per-action audit entry and the activity item. The
# timeline projection deliberately omits ``id``/``policy_version``/``detail``
# (rationale stays on the per-action audit), so it is compared field-wise.
SHARED = ("event", "actor", "previous_status", "new_status", "policy_version", "created_at", "detail")


def _audit_row(entry: dict):
    return tuple(entry[field] for field in SHARED)


def _activity_row(item: dict):
    return tuple(item[field] for field in SHARED)


def _v2_audit(client, action_id: str) -> dict:
    response = client.get(V2_AUDIT_URL.format(action_id=action_id))
    assert response.status_code == 200, response.text
    return response.json()


def _activity(client, incident_id: str, **params: object) -> dict:
    response = client.get(ACTIVITY_URL.format(incident_id=incident_id), params=params or {})
    assert response.status_code == 200, response.text
    return response.json()


def _timeline(client, incident_id: str) -> dict:
    response = client.get(TIMELINE_URL.format(incident_id=incident_id))
    assert response.status_code == 200, response.text
    return response.json()


def _response_entries(timeline: dict, action_id: str) -> list[dict]:
    return [
        entry
        for entry in timeline["entries"]
        if entry["kind"] == "response" and entry["action_id"] == action_id
    ]


# ---------------------------------------------------------------------------
# 1. Cross-surface agreement
# ---------------------------------------------------------------------------


def test_per_action_audit_and_activity_are_identical(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200

    audit = _v2_audit(client, action_id)
    activity = _activity(client, incident["id"], action_id=action_id)

    assert audit["action_id"] == action_id
    assert audit["incident_id"] == activity["incident_id"] == incident["id"]
    assert [entry["id"] for entry in audit["entries"]] == [
        item["id"] for item in activity["items"]
    ]
    assert [_audit_row(entry) for entry in audit["entries"]] == [
        _activity_row(item) for item in activity["items"]
    ]
    assert audit["total"] == activity["total"] == len(audit["entries"])


def test_timeline_response_entries_agree_with_activity(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200

    activity = _activity(client, incident["id"], action_id=action_id)
    entries = _response_entries(_timeline(client, incident["id"]), action_id)

    assert len(entries) == len(activity["items"])
    for entry, item in zip(entries, activity["items"]):
        assert entry["event"] == item["event"]
        assert entry["actor"] == item["actor"]
        assert entry["previous_status"] == item["previous_status"]
        assert entry["new_status"] == item["new_status"]
        assert entry["action_type"] == item["action_type"]
        # The timeline timestamp is the same stored ``created_at``.
        assert entry["at"] == item["created_at"]


# ---------------------------------------------------------------------------
# 2. No fabricated transitions
# ---------------------------------------------------------------------------


def test_pending_action_has_no_fabricated_transitions(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]

    audit = _v2_audit(client, action_id)
    activity = _activity(client, incident["id"], action_id=action_id)
    entries = _response_entries(_timeline(client, incident["id"]), action_id)

    allowed = {"RESPONSE_REQUESTED", "RESPONSE_APPROVAL_REQUIRED"}
    for surface in (audit["entries"], activity["items"], entries):
        events = {row["event"] for row in surface}
        assert events <= allowed, events
        assert "RESPONSE_APPROVED" not in events

    # Every recorded transition stays in the pending status; no surface
    # invents an approval or execution the lifecycle never produced.
    assert all(row["new_status"] == "PENDING_APPROVAL" for row in audit["entries"])
    assert {entry["new_status"] for entry in entries} == {"PENDING_APPROVAL"}
    assert [_audit_row(e) for e in audit["entries"]] == [
        _activity_row(i) for i in activity["items"]
    ]


# ---------------------------------------------------------------------------
# 3. Rejection rationale
# ---------------------------------------------------------------------------


def test_rejection_rationale_is_consistent_and_not_duplicated(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    reason = "Step48 rationale 3f9c1a"
    rejected = client.post(
        f"/api/v1/responses/{action_id}/reject",
        json={"actor": "operator-1", "reason": reason},
    )
    assert rejected.status_code == 200, rejected.text

    audit = _v2_audit(client, action_id)
    activity = _activity(client, incident["id"], action_id=action_id)

    def _rejected(rows: list[dict]) -> dict:
        matches = [row for row in rows if row["event"] == "RESPONSE_REJECTED"]
        assert len(matches) == 1
        return matches[0]

    audit_rejected = _rejected(audit["entries"])
    activity_rejected = _rejected(activity["items"])
    assert audit_rejected["detail"] == reason
    assert activity_rejected["detail"] == reason
    assert audit_rejected["new_status"] == activity_rejected["new_status"]
    # Only the rejection carries a rationale; every other row stays NULL.
    assert all(
        row["detail"] is None
        for row in audit["entries"]
        if row["event"] != "RESPONSE_REJECTED"
    )
    assert [_audit_row(e) for e in audit["entries"]] == [
        _activity_row(i) for i in activity["items"]
    ]

    timeline = _timeline(client, incident["id"])

    # The rationale is not duplicated onto the timeline (it stays on the
    # per-action audit), and never leaks through the derived ``detail``.
    assert reason not in json.dumps(timeline)
    entry = _rejected(_response_entries(timeline, action_id))
    assert entry["new_status"] == audit_rejected["new_status"]


# ---------------------------------------------------------------------------
# 4. Shared ordering
# ---------------------------------------------------------------------------


def test_history_ordering_is_shared_and_monotonic(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200

    audit = _v2_audit(client, action_id)
    keys = [(entry["created_at"], entry["id"]) for entry in audit["entries"]]
    assert keys == sorted(keys)
    assert len(keys) >= 2

    activity = _activity(client, incident["id"], action_id=action_id)
    akeys = [(item["created_at"], item["id"]) for item in activity["items"]]
    assert akeys == sorted(akeys)
    # The per-action audit and the activity feed project the same rows in
    # the same (created_at, id) order.
    assert keys == akeys

    entries = _response_entries(_timeline(client, incident["id"]), action_id)
    stamps = [entry["at"] for entry in entries]
    assert stamps == sorted(stamps)
    assert len(entries) == len(audit["entries"])
