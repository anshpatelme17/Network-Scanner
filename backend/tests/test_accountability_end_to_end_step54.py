"""End-to-end incident accountability regression (Step 54).

Step 54 walks a real incident through a full controlled-response
lifecycle over the HTTP API and then reads every accountability surface
back, asserting they tell one consistent, read-only, permission-scoped
story. It adds no production code.

Two actions are driven on one incident:

* action A runs the whole lifecycle - request, approve, execute, roll
  back - so every controlled-response event is exercised at least once;
* action B is requested and then rejected with an operator rationale, so
  the rejection-only ``detail`` path is covered.

Then four surfaces are compared:

* ``GET /api/v2/responses/{action_id}/audit`` per action,
* ``GET /api/v1/incidents/{id}/activity``,
* ``GET /api/v1/incidents/{id}/timeline``,
* ``GET /api/v1/incidents/{id}/audit`` (the incident lifecycle trail).

The tests assert that the incident activity feed is exactly the union of
the two per-action feeds on the shared stored fields, that the timeline's
response entries correspond one-for-one with the activity rows, that the
rejection rationale lives only where it belongs, that the incident trail
never contains response lifecycle events, that every read is static
(no new audit rows, identical payloads), that filtering and pagination
behave over real data, and that the permission gate splits the surfaces
the way the role map says it should.
"""

from __future__ import annotations

from tests.test_auth import _admin_headers, _auth_header, _seed_incident_auth
from tests.test_incident_activity_step45 import ACTIVITY_URL
from tests.test_response_governance import _approve, _request, _seed


def _full_lifecycle(client, incident_id: str) -> str:
    """Request -> approve -> execute -> roll back one controlled action."""
    created = _request(client, incident_id)
    assert created.status_code == 201, created.text
    action_id = created.json()["id"]

    assert _approve(client, action_id, actor="approver-1").status_code == 200
    executed = client.post(
        f"/api/v1/responses/{action_id}/execute", json={"actor": "executor-1"}
    )
    assert executed.status_code in (200, 201), executed.text
    rolled = client.post(
        f"/api/v1/responses/{action_id}/rollback", json={"actor": "rollbacker-1"}
    )
    assert rolled.status_code in (200, 201), rolled.text
    return action_id


def _rejected(client, incident_id: str, reason: str) -> str:
    """Request -> reject one controlled action, recording a rationale.

    A distinct action type keeps the deterministic action id different from
    the full-lifecycle action's, so both live on the one incident.
    """
    created = _request(client, incident_id, action_type="DISABLE_INDICATOR_BLOCK")
    assert created.status_code == 201, created.text
    action_id = created.json()["id"]
    rejected = client.post(
        f"/api/v1/responses/{action_id}/reject",
        json={"actor": "approver-1", "reason": reason},
    )
    assert rejected.status_code == 200, rejected.text
    return action_id


def _surfaces(client, incident_id: str, action_ids: list[str]) -> dict:
    audit_url = f"/api/v1/incidents/{incident_id}/audit"
    return {
        "v2": {
            action_id: client.get(
                f"/api/v2/responses/{action_id}/audit", params={"limit": 200}
            ).json()
            for action_id in action_ids
        },
        "activity": client.get(
            ACTIVITY_URL.format(incident_id=incident_id), params={"limit": 200}
        ).json(),
        "timeline": client.get(f"/api/v1/incidents/{incident_id}/timeline").json(),
        "audit": client.get(audit_url).json(),
    }


def _audit_count() -> tuple[int, int]:
    from sqlalchemy import func, select

    from app.database.session import get_session_factory
    from app.models.incidents import IncidentAudit
    from app.models.responses import ResponseAudit

    db = get_session_factory()()
    try:
        responses = db.scalar(select(func.count(ResponseAudit.id))) or 0
        incidents = db.scalar(select(func.count(IncidentAudit.id))) or 0
    finally:
        db.close()
    return responses, incidents


# ---------------------------------------------------------------------------
# 1. One incident, two actions, four surfaces, one story
# ---------------------------------------------------------------------------


def test_lifecycle_is_consistent_across_all_accountability_surfaces(client, clean_db):
    incident = _seed(client)
    rationale = "Target is a confirmed false positive."
    action_a = _full_lifecycle(client, incident["id"])
    action_b = _rejected(client, incident["id"], rationale)

    surfaces = _surfaces(client, incident["id"], [action_a, action_b])
    activity = surfaces["activity"]

    # The activity feed is exactly the union of the two per-action feeds.
    by_id: dict[str, dict] = {}
    for page in surfaces["v2"].values():
        for entry in page["entries"]:
            assert entry["id"] not in by_id  # actions never share audit rows
            by_id[entry["id"]] = entry

    activity_ids = [item["id"] for item in activity["items"]]
    assert sorted(activity_ids) == sorted(by_id)
    assert activity["total"] == len(activity_ids)

    for item in activity["items"]:
        entry = by_id[item["id"]]
        assert item["event"] == entry["event"]
        assert item["actor"] == entry["actor"]
        assert item["previous_status"] == entry["previous_status"]
        assert item["new_status"] == entry["new_status"]
        assert item["policy_version"] == entry["policy_version"]
        assert item["created_at"] == entry["created_at"]
        assert item["detail"] == entry["detail"]

    # The activity feed is in created_at/id order.
    ordered = [(item["created_at"], item["id"]) for item in activity["items"]]
    assert ordered == sorted(ordered)

    # The timeline's response entries mirror the activity rows exactly.
    timeline_response = sorted(
        (entry["action_id"], entry["event"], entry["actor"], entry["at"])
        for entry in surfaces["timeline"]["entries"]
        if entry["kind"] == "response"
    )
    activity_response = sorted(
        (item["action_id"], item["event"], item["actor"], item["created_at"])
        for item in activity["items"]
    )
    assert timeline_response == activity_response
    stamps = [entry["at"] for entry in surfaces["timeline"]["entries"]]
    assert stamps == sorted(stamps)

    # The rejection rationale lives on the stored row and its read surfaces,
    # never duplicated onto the derived timeline transition string.
    rejections = [item for item in activity["items"] if item["event"] == "RESPONSE_REJECTED"]
    assert len(rejections) == 1
    assert rejections[0]["detail"] == rationale
    assert by_id[rejections[0]["id"]]["detail"] == rationale
    timeline_rejection = [
        entry for entry in surfaces["timeline"]["entries"] if entry.get("event") == "RESPONSE_REJECTED"
    ][0]
    assert rationale not in (timeline_rejection["detail"] or "")

    # The incident trail holds the incident lifecycle only - never a response event.
    incident_actions = {entry["action"] for entry in surfaces["audit"]["entries"]}
    assert "OPENED" in incident_actions
    assert not any(action.startswith("RESPONSE_") for action in incident_actions)


# ---------------------------------------------------------------------------
# 2. Reads are static: no writes, identical payloads
# ---------------------------------------------------------------------------


def test_accountability_reads_are_read_only_and_repeatable(client, clean_db):
    incident = _seed(client)
    action = _full_lifecycle(client, incident["id"])

    before = _audit_count()
    first = _surfaces(client, incident["id"], [action])
    second = _surfaces(client, incident["id"], [action])
    after = _audit_count()

    assert before == after, "reading accountability must write no audit rows"
    assert first == second, "the same read must return the same payload"


# ---------------------------------------------------------------------------
# 3. Filtering and pagination over a real lifecycle
# ---------------------------------------------------------------------------


def test_activity_filters_and_pagination_over_real_data(client, clean_db):
    incident = _seed(client)
    action_a = _full_lifecycle(client, incident["id"])
    _rejected(client, incident["id"], "Not a real threat.")
    base = ACTIVITY_URL.format(incident_id=incident["id"])

    full = client.get(base, params={"limit": 200}).json()
    assert full["total"] == len(full["items"]) > 0

    only_a = client.get(base, params={"action_id": action_a, "limit": 200}).json()
    assert {item["action_id"] for item in only_a["items"]} == {action_a}
    v2_total = client.get(
        f"/api/v2/responses/{action_a}/audit", params={"limit": 200}
    ).json()["total"]
    assert only_a["total"] == v2_total == len(only_a["items"])

    approved = client.get(base, params={"event": "RESPONSE_APPROVED", "limit": 200}).json()
    assert approved["items"]
    assert {item["event"] for item in approved["items"]} == {"RESPONSE_APPROVED"}

    first_at = full["items"][0]["created_at"]
    last_at = full["items"][-1]["created_at"]
    windowed = client.get(
        base, params={"since": first_at, "until": last_at, "limit": 200}
    ).json()
    assert windowed["total"] == full["total"]

    walked = []
    for offset in range(full["total"]):
        page = client.get(base, params={"limit": 1, "offset": offset}).json()
        assert len(page["items"]) == 1
        walked.append(page["items"][0]["id"])
    assert walked == [item["id"] for item in full["items"]]


# ---------------------------------------------------------------------------
# 4. The permission gate splits the surfaces
# ---------------------------------------------------------------------------


def test_permission_scoping_end_to_end(client, clean_db):
    admin = _admin_headers(client)
    incident = _seed_incident_auth(client, admin)
    viewer = _auth_header(client, "viewer-e2e", "viewer-e2e-pass-1", ("VIEWER",))
    analyst = _auth_header(client, "analyst-e2e", "analyst-e2e-pass-1", ("SECURITY_ANALYST",))

    activity_url = ACTIVITY_URL.format(incident_id=incident["id"])
    audit_url = f"/api/v1/incidents/{incident['id']}/audit"

    # A VIEWER holds READ_INCIDENTS + READ_RESPONSES, so the response-backed
    # activity feed is readable...
    assert client.get(activity_url, headers=viewer).status_code == 200
    # ...and so is the per-action audit surface (permission precedes the 404).
    assert client.get("/api/v2/responses/does-not-exist/audit", headers=viewer).status_code == 404

    # ...but the incident audit trail needs VIEW_AUDIT, which a VIEWER lacks.
    denied = client.get(audit_url, headers=viewer)
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "PERMISSION_DENIED"

    # An analyst holds VIEW_AUDIT and may read the incident trail.
    assert client.get(audit_url, headers=analyst).status_code == 200
