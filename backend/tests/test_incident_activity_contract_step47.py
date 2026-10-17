"""Incident activity contract hardening (Step 47).

Step 47 hardens the ``GET /api/v1/incidents/{id}/activity`` contract with
focused regression tests for the parameter boundaries and precedence the
planned Step 45 suite left uncovered. It adds no production code: the
endpoint already enforces every rule asserted here.

Covered gaps:

* the ``actor`` and ``action_id`` query bounds (128 and 64) accept the
  exact maximum and reject one character more with the standard 422;
* a malformed ``since``/``until`` is a 422, never a 500 or a silent
  unbounded read;
* a timezone-carrying ``since``/``until`` is normalised to naive UTC
  before comparison, so an offset window is honoured rather than compared
  literally against the naive column;
* multiple filters combine (``event`` + ``actor``) and narrow both
  ``items`` and ``total``;
* ``filters`` echoes the applied ``action_id``/``since``/``until``;
* an unknown incident is a 404 even when the filter itself is invalid —
  the incident check precedes filter validation.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from tests.test_incident_activity_step45 import ACTIVITY_URL, _add_row
from tests.test_response_governance import _seed


def _get(client, incident_id: str, params: dict[str, object] | None = None):
    # Use the client's own query encoding so an offset-bearing ISO instant
    # (``+02:00``) is sent verbatim rather than decoded as a space.
    return client.get(ACTIVITY_URL.format(incident_id=incident_id), params=params or {})


# ---------------------------------------------------------------------------
# 1. Query-parameter bounds
# ---------------------------------------------------------------------------


def test_actor_length_boundary(client, clean_db):
    incident = _seed(client)

    at_max = _get(client, incident["id"], {"actor": "a" * 128})
    assert at_max.status_code == 200, at_max.text
    assert at_max.json()["items"] == []

    over = _get(client, incident["id"], {"actor": "a" * 129})
    assert over.status_code == 422
    assert over.json()["error"]["code"] == "VALIDATION_ERROR"


def test_action_id_length_boundary(client, clean_db):
    incident = _seed(client)

    at_max = _get(client, incident["id"], {"action_id": "x" * 64})
    assert at_max.status_code == 200, at_max.text
    assert at_max.json()["items"] == []

    over = _get(client, incident["id"], {"action_id": "x" * 65})
    assert over.status_code == 422
    assert over.json()["error"]["code"] == "VALIDATION_ERROR"


def test_malformed_datetime_filters_are_422(client, clean_db):
    incident = _seed(client)

    bad_since = _get(client, incident["id"], {"since": "not-a-date"})
    assert bad_since.status_code == 422
    assert bad_since.json()["error"]["code"] == "VALIDATION_ERROR"

    bad_until = _get(client, incident["id"], {"until": "2026-13-40T00:00:00"})
    assert bad_until.status_code == 422
    assert bad_until.json()["error"]["code"] == "VALIDATION_ERROR"


# ---------------------------------------------------------------------------
# 2. Timezone normalisation
# ---------------------------------------------------------------------------


def test_tz_aware_window_is_normalised_to_utc(client, clean_db):
    incident = _seed(client)
    action_id = f"act-{uuid.uuid4().hex[:10]}"
    # A naive-UTC stored row at 10:00. The offset instant below is 09:00 UTC,
    # one hour before it, so a correct (normalised) comparison includes the
    # row for ``since`` and excludes it for ``until``; a literal comparison
    # against 11:00 would do the opposite.
    _add_row(
        incident["id"],
        action_id,
        "RESPONSE_REQUESTED",
        datetime(2026, 10, 1, 10, 0, 0),
        audit_id="tz-row",
    )
    aware = "2026-10-01T11:00:00+02:00"

    after = _get(client, incident["id"], {"action_id": action_id, "since": aware}).json()
    assert [item["id"] for item in after["items"]] == ["tz-row"]
    assert after["total"] == 1

    before = _get(client, incident["id"], {"action_id": action_id, "until": aware}).json()
    assert before["items"] == []
    assert before["total"] == 0


# ---------------------------------------------------------------------------
# 3. Combined filters and echo
# ---------------------------------------------------------------------------


def test_combined_filters_narrow_items_and_total(client, clean_db):
    incident = _seed(client)
    first = f"act-{uuid.uuid4().hex[:8]}"
    second = f"act-{uuid.uuid4().hex[:8]}"
    moment = datetime(2026, 10, 1, 9, 0, 0)
    _add_row(
        incident["id"], first, "RESPONSE_REQUESTED", moment, actor="analyst-1", audit_id="c-a1"
    )
    _add_row(
        incident["id"], second, "RESPONSE_APPROVED", moment, actor="analyst-2", audit_id="c-a2"
    )

    body = _get(
        client, incident["id"], {"event": "RESPONSE_REQUESTED", "actor": "analyst-1"}
    ).json()
    assert [item["id"] for item in body["items"]] == ["c-a1"]
    assert body["total"] == 1
    assert body["filters"]["event"] == "RESPONSE_REQUESTED"
    assert body["filters"]["actor"] == "analyst-1"


def test_filters_echo_window_and_action(client, clean_db):
    incident = _seed(client)
    action_id = f"act-{uuid.uuid4().hex[:8]}"

    body = _get(
        client,
        incident["id"],
        {
            "action_id": action_id,
            "since": "2026-10-01T00:00:00",
            "until": "2026-10-02T00:00:00",
        },
    ).json()

    echoed = body["filters"]
    assert echoed["action_id"] == action_id
    assert echoed["since"] is not None and echoed["since"].startswith("2026-10-01")
    assert echoed["until"] is not None and echoed["until"].startswith("2026-10-02")
    assert body["total"] == len(body["items"])


# ---------------------------------------------------------------------------
# 4. Check precedence
# ---------------------------------------------------------------------------


def test_unknown_incident_precedes_filter_validation(client, clean_db):
    # The incident lookup runs first, so an unknown incident is a 404 even
    # when an invalid filter would otherwise be a 422.
    missing = _get(client, "no-such-incident", {"event": "RESPONSE_INVENTED"})
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "INCIDENT_NOT_FOUND"
