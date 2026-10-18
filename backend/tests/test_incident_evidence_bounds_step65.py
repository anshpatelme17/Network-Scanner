"""Step 65 - bounded incident evidence and paged observation links.

The incident evidence overview used to read every ``incident_evidence``
link for an incident and its vulnerability sub-list had no ceiling at all.
Two smaller reads were also unbounded: the correlation-evidence role
lookup fetched every row for the correlation although only rendered events
are used, and the observations endpoint returned every link.

Step 65 bounds each read per evidence kind (events and vulnerabilities
keep independent budgets), reports the true per-kind totals from one
grouped count, and pages ``GET /incidents/{id}/observations`` in stable
``(evidence_kind, evidence_id)`` order so the complete link set remains
reachable. Ordering is deterministic and counts stay truthful even when
the returned rows are capped.

Query volume is measured with the repository's established SQLAlchemy
``before_cursor_execute`` instrumentation (as in ``test_query_bounds_step58``
and ``test_incident_activity_step45``), not with mocks.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from app.core.config import get_settings
from app.database import session as session_module

TS = datetime(2026, 1, 5, 12, 0, 0)
ROLES = ("vulnerability", "activity", "related")


def _configure(monkeypatch, **overrides):  # noqa: ANN001, ANN201
    for key, value in overrides.items():
        monkeypatch.setenv(key, str(value))
    get_settings.cache_clear()
    return get_settings()


def _seed(  # noqa: ANN001
    db,
    incident_id,
    *,
    event_count=0,
    vuln_count=0,
    correlation_link=True,
    asset_ip="10.0.0.1",
):
    from app.models.assets import Asset
    from app.models.correlations import Correlation, CorrelationEvidence
    from app.models.events import SecurityEvent
    from app.models.incidents import Incident, IncidentEvidence
    from app.models.vulnerabilities import Vulnerability

    correlation_id = f"corr-{incident_id}"
    db.add(
        Correlation(
            id=correlation_id,
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
            incident_key=f"INC-{incident_id}"[:16],
            title="bounded subject",
            severity="LOW",
            correlation_id=correlation_id,
            first_seen=TS,
            last_seen=TS,
        )
    )
    if correlation_link:
        db.add(
            IncidentEvidence(
                incident_id=incident_id,
                evidence_kind="correlation",
                evidence_id=correlation_id,
                reason="source correlation",
            )
        )
    for index in range(event_count):
        event_id = f"{incident_id}-evt-{index:04d}"
        db.add(
            SecurityEvent(
                id=event_id,
                event_time=TS + timedelta(seconds=index),
                source_type="WAZUH",
                source_name="fixture",
                event_type="auth.bound",
                severity="LOW",
                title=f"event {index}",
                fingerprint=f"fp-{incident_id}-{index}",
                normalized_data="{}",
            )
        )
        db.add(
            CorrelationEvidence(
                correlation_id=correlation_id,
                event_id=event_id,
                role=ROLES[index % len(ROLES)],
                position=index,
            )
        )
        db.add(
            IncidentEvidence(
                incident_id=incident_id,
                evidence_kind="event",
                evidence_id=event_id,
                reason=f"event {index}",
            )
        )
    if vuln_count:
        asset_id = f"asset-{incident_id}"
        db.add(
            Asset(
                id=asset_id,
                ip_address=asset_ip,
                state="up",
                first_seen=TS,
                last_seen=TS,
            )
        )
        for index in range(vuln_count):
            vuln_id = f"{incident_id}-vln-{index:04d}"
            db.add(
                Vulnerability(
                    id=vuln_id,
                    asset_id=asset_id,
                    scanner="fixture",
                    scanner_finding_id=f"{incident_id}-{index}",
                    title=f"finding {index}",
                    severity="HIGH",
                )
            )
            db.add(
                IncidentEvidence(
                    incident_id=incident_id,
                    evidence_kind="vulnerability",
                    evidence_id=vuln_id,
                    reason=f"finding {index}",
                )
            )


def _seed_db(*seeds):  # noqa: ANN001, ANN202
    db = session_module.get_session_factory()()
    try:
        for seed in seeds:
            _seed(db, **seed)
        db.commit()
    finally:
        db.close()


def _capture_statements():  # noqa: ANN202
    from sqlalchemy import event as sa_event

    engine = session_module.get_engine()
    captured: list[str] = []

    def _before(_conn, _cursor, statement, _parameters, _context, _many):
        captured.append(statement)

    sa_event.listen(engine, "before_cursor_execute", _before)
    return captured, lambda: sa_event.remove(engine, "before_cursor_execute", _before)


def _statements_for(client, path, **params):  # noqa: ANN001, ANN201
    captured, stop = _capture_statements()
    try:
        response = client.get(path, params=params)
    finally:
        stop()
    return response, captured


def _walk_observations(client, incident_id, page):  # noqa: ANN001, ANN201
    collected: list[tuple[str, str]] = []
    offset = 0
    while True:
        body = client.get(
            f"/api/v1/incidents/{incident_id}/observations",
            params={"limit": page, "offset": offset},
        ).json()
        batch = [
            (item["observation_type"], item["observation_id"])
            for item in body["observations"]
        ]
        collected.extend(batch)
        offset += page
        if not batch or offset >= body["total"]:
            return collected, body


# ---------------------------------------------------------------------------
# Finding C - role_by_event
# ---------------------------------------------------------------------------


def test_roles_are_available_for_every_displayed_event(client, clean_db):
    _seed_db({"incident_id": "inc-roles", "event_count": 5})
    body = client.get("/api/v1/incidents/inc-roles/evidence").json()
    assert len(body["events"]) == 5
    assert body["evidence_count"] == 5
    assert body["truncated"] is False
    expected = {
        f"inc-roles-evt-{index:04d}": ROLES[index % len(ROLES)] for index in range(5)
    }
    assert {event["id"]: event["role"] for event in body["events"]} == expected


def test_role_lookup_reads_only_displayed_events(client, clean_db, monkeypatch):
    _configure(monkeypatch, CORRELATION_EVIDENCE_MAX="3")
    _seed_db({"incident_id": "inc-filter", "event_count": 6})
    response, statements = _statements_for(client, "/api/v1/incidents/inc-filter/evidence")
    body = response.json()
    assert len(body["events"]) == 3
    assert body["evidence_count"] == 6
    assert body["truncated"] is True
    role_statements = [s for s in statements if "correlation_evidence" in s.lower()]
    assert len(role_statements) == 1
    normalized = " ".join(role_statements[0].split())
    assert "correlation_evidence.event_id IN" in normalized


def test_role_lookup_is_one_batched_query_regardless_of_event_count(client, clean_db):
    _seed_db(
        {"incident_id": "inc-small", "event_count": 3},
        {"incident_id": "inc-large", "event_count": 30},
    )
    _, small_statements = _statements_for(client, "/api/v1/incidents/inc-small/evidence")
    _, large_statements = _statements_for(client, "/api/v1/incidents/inc-large/evidence")
    small_roles = [s for s in small_statements if "correlation_evidence" in s.lower()]
    large_roles = [s for s in large_statements if "correlation_evidence" in s.lower()]
    assert len(small_roles) == len(large_roles) == 1
    assert len(small_statements) == len(large_statements)


def test_empty_displayed_events_skips_the_role_query(client, clean_db):
    _seed_db({"incident_id": "inc-norole", "event_count": 0, "vuln_count": 2})
    response, statements = _statements_for(client, "/api/v1/incidents/inc-norole/evidence")
    assert response.status_code == 200
    assert response.json()["events"] == []
    assert not [s for s in statements if "correlation_evidence" in s.lower()]


# ---------------------------------------------------------------------------
# Finding B - vulnerability evidence
# ---------------------------------------------------------------------------


def test_vulnerability_evidence_is_bounded_with_true_count(client, clean_db, monkeypatch):
    _configure(monkeypatch, CORRELATION_EVIDENCE_MAX="3")
    _seed_db({"incident_id": "inc-vuln", "vuln_count": 5})
    body = client.get("/api/v1/incidents/inc-vuln/evidence").json()
    assert [item["id"] for item in body["vulnerabilities"]] == [
        "inc-vuln-vln-0000",
        "inc-vuln-vln-0001",
        "inc-vuln-vln-0002",
    ]
    assert body["vulnerability_count"] == 5
    assert body["vulnerabilities_truncated"] is True
    # ``truncated`` keeps its Step 29 meaning: event truncation only.
    assert body["truncated"] is False
    assert body["evidence_count"] == 0


def test_event_and_vulnerability_budgets_are_independent(client, clean_db, monkeypatch):
    _configure(monkeypatch, CORRELATION_EVIDENCE_MAX="2")
    _seed_db({"incident_id": "inc-budget", "event_count": 4, "vuln_count": 4})
    body = client.get("/api/v1/incidents/inc-budget/evidence").json()
    assert len(body["events"]) == 2
    assert len(body["vulnerabilities"]) == 2
    assert body["evidence_count"] == 4
    assert body["vulnerability_count"] == 4
    assert body["truncated"] is True
    assert body["vulnerabilities_truncated"] is True


def test_vulnerability_count_zero_is_not_truncated(client, clean_db):
    _seed_db({"incident_id": "inc-novuln", "event_count": 1})
    body = client.get("/api/v1/incidents/inc-novuln/evidence").json()
    assert body["vulnerabilities"] == []
    assert body["vulnerability_count"] == 0
    assert body["vulnerabilities_truncated"] is False


def test_vulnerability_order_is_deterministic(client, clean_db, monkeypatch):
    _configure(monkeypatch, CORRELATION_EVIDENCE_MAX="4")
    _seed_db({"incident_id": "inc-order", "vuln_count": 6})
    first = client.get("/api/v1/incidents/inc-order/evidence").json()
    second = client.get("/api/v1/incidents/inc-order/evidence").json()
    ids = [item["id"] for item in first["vulnerabilities"]]
    assert ids == sorted(ids)
    assert second["vulnerabilities"] == first["vulnerabilities"]


# ---------------------------------------------------------------------------
# Finding A - bounded reads and grouped counts
# ---------------------------------------------------------------------------


def test_grouped_counts_match_link_totals(client, clean_db):
    _seed_db({"incident_id": "inc-counts", "event_count": 3, "vuln_count": 5})
    evidence = client.get("/api/v1/incidents/inc-counts/evidence").json()
    observations = client.get("/api/v1/incidents/inc-counts/observations").json()
    assert evidence["evidence_count"] == observations["event_count"] == 3
    assert evidence["vulnerability_count"] == observations["vulnerability_count"] == 5
    assert observations["correlation_count"] == 1
    assert observations["total"] == 9


def test_evidence_reads_are_batched_per_kind(client, clean_db):
    _seed_db(
        {"incident_id": "inc-q-small", "event_count": 2, "vuln_count": 2},
        {
            "incident_id": "inc-q-large",
            "event_count": 20,
            "vuln_count": 20,
            "asset_ip": "10.0.0.2",
        },
    )
    _, small_statements = _statements_for(client, "/api/v1/incidents/inc-q-small/evidence")
    _, large_statements = _statements_for(client, "/api/v1/incidents/inc-q-large/evidence")
    assert len(small_statements) == len(large_statements)
    assert sum("incident_evidence" in s.lower() for s in small_statements) == 3


def test_observations_query_count_does_not_grow_with_links(client, clean_db):
    _seed_db(
        {"incident_id": "inc-obs-small", "event_count": 2},
        {"incident_id": "inc-obs-large", "event_count": 20},
    )
    _, small_statements = _statements_for(
        client, "/api/v1/incidents/inc-obs-small/observations", limit=50
    )
    _, large_statements = _statements_for(
        client, "/api/v1/incidents/inc-obs-large/observations", limit=50
    )
    assert len(small_statements) == len(large_statements)
    assert sum("incident_evidence" in s.lower() for s in small_statements) == 2


# ---------------------------------------------------------------------------
# Observations pagination - complete retrieval
# ---------------------------------------------------------------------------


def test_observations_pages_every_link_exactly_once(client, clean_db):
    _seed_db({"incident_id": "inc-pages", "event_count": 4, "vuln_count": 4})
    expected = (
        [("correlation", "corr-inc-pages")]
        + [("event", f"inc-pages-evt-{index:04d}") for index in range(4)]
        + [("vulnerability", f"inc-pages-vln-{index:04d}") for index in range(4)]
    )
    collected, last = _walk_observations(client, "inc-pages", 2)
    assert collected == expected
    assert len(collected) == len(set(collected)) == 9
    assert last["total"] == 9
    assert last["event_count"] == 4
    assert last["vulnerability_count"] == 4
    assert last["correlation_count"] == 1


def test_observations_page_boundaries(client, clean_db):
    _seed_db({"incident_id": "inc-edge", "event_count": 3})  # correlation + 3 events
    path = "/api/v1/incidents/inc-edge/observations"

    full = client.get(path, params={"limit": 4, "offset": 0}).json()
    assert full["total"] == 4
    assert len(full["observations"]) == 4
    assert full["truncated"] is False

    tail = client.get(path, params={"limit": 4, "offset": 4}).json()
    assert tail["observations"] == []
    assert tail["truncated"] is False

    first = client.get(path, params={"limit": 3, "offset": 0}).json()
    assert len(first["observations"]) == 3
    assert first["truncated"] is True

    last = client.get(path, params={"limit": 3, "offset": 3}).json()
    assert len(last["observations"]) == 1
    assert last["truncated"] is False


def test_observations_are_stable_across_calls(client, clean_db):
    _seed_db({"incident_id": "inc-stable", "event_count": 2, "vuln_count": 2})
    path = "/api/v1/incidents/inc-stable/observations"
    first = client.get(path, params={"limit": 2, "offset": 1}).json()
    second = client.get(path, params={"limit": 2, "offset": 1}).json()
    assert second == first


def test_observations_limit_is_validated(client, clean_db):
    _seed_db({"incident_id": "inc-limit", "event_count": 1})
    path = "/api/v1/incidents/inc-limit/observations"
    assert client.get(path, params={"limit": 200}).status_code == 200
    assert client.get(path, params={"limit": 201}).status_code == 422
    assert client.get(path, params={"limit": 0}).status_code == 422
    assert client.get(path, params={"offset": -1}).status_code == 422


def test_observations_empty_incident(client, clean_db):
    _seed_db({"incident_id": "inc-empty", "correlation_link": False})
    body = client.get("/api/v1/incidents/inc-empty/observations").json()
    assert body["total"] == 0
    assert body["observations"] == []
    assert body["truncated"] is False
    assert body["event_count"] == body["vulnerability_count"] == body["correlation_count"] == 0


# ---------------------------------------------------------------------------
# Server-side bounds - the SQL itself must carry LIMIT/OFFSET
# ---------------------------------------------------------------------------


def test_evidence_per_kind_queries_apply_a_sql_limit(client, clean_db, monkeypatch):
    """Bounding must happen in SQL, not by slicing a fully loaded link list.

    The filtered count is exactly the two per-kind selects; if either ever
    loses ``.limit()`` the assertion fails even though the response would
    still be short after a Python-side slice.
    """
    _configure(monkeypatch, CORRELATION_EVIDENCE_MAX="3")
    _seed_db({"incident_id": "inc-sql-kind", "event_count": 6, "vuln_count": 6})
    _, statements = _statements_for(client, "/api/v1/incidents/inc-sql-kind/evidence")
    per_kind = [
        statement
        for statement in statements
        if "from incident_evidence" in statement.lower()
        and "order by incident_evidence.evidence_id" in statement.lower()
    ]
    assert len(per_kind) == 2
    for statement in per_kind:
        assert "LIMIT" in statement.upper()


def test_observations_page_query_applies_sql_limit_and_offset(client, clean_db):
    """The page select must bound rows server-side, with an offset window."""
    _seed_db({"incident_id": "inc-sql-page", "event_count": 4, "vuln_count": 4})
    _, statements = _statements_for(
        client, "/api/v1/incidents/inc-sql-page/observations", limit=3, offset=2
    )
    pages = [
        statement
        for statement in statements
        if "from incident_evidence" in statement.lower()
        and "order by incident_evidence.evidence_kind" in statement.lower()
    ]
    assert len(pages) == 1
    normalized = pages[0].upper()
    assert "LIMIT" in normalized
    assert "OFFSET" in normalized


# ---------------------------------------------------------------------------
# Exact-at-cap boundaries and mixed truncation
# ---------------------------------------------------------------------------


def test_event_count_at_cap_is_not_truncated(client, clean_db, monkeypatch):
    settings = _configure(monkeypatch, CORRELATION_EVIDENCE_MAX="3")
    _seed_db(
        {"incident_id": "inc-cap-evt", "event_count": settings.correlation_evidence_max}
    )
    body = client.get("/api/v1/incidents/inc-cap-evt/evidence").json()
    assert len(body["events"]) == settings.correlation_evidence_max
    assert body["evidence_count"] == settings.correlation_evidence_max
    assert body["truncated"] is False


def test_vulnerability_count_at_cap_is_not_truncated(client, clean_db, monkeypatch):
    settings = _configure(monkeypatch, CORRELATION_EVIDENCE_MAX="3")
    _seed_db(
        {"incident_id": "inc-cap-vln", "vuln_count": settings.correlation_evidence_max}
    )
    body = client.get("/api/v1/incidents/inc-cap-vln/evidence").json()
    assert len(body["vulnerabilities"]) == settings.correlation_evidence_max
    assert body["vulnerability_count"] == settings.correlation_evidence_max
    assert body["vulnerabilities_truncated"] is False
    assert body["truncated"] is False


def test_events_truncate_while_vulnerabilities_do_not(client, clean_db, monkeypatch):
    _configure(monkeypatch, CORRELATION_EVIDENCE_MAX="2")
    _seed_db({"incident_id": "inc-mixed", "event_count": 5, "vuln_count": 2})
    body = client.get("/api/v1/incidents/inc-mixed/evidence").json()
    assert len(body["events"]) == 2
    assert body["truncated"] is True
    assert body["evidence_count"] == 5
    assert len(body["vulnerabilities"]) == 2
    assert body["vulnerabilities_truncated"] is False
    assert body["vulnerability_count"] == 2


# ---------------------------------------------------------------------------
# Default observations page size
# ---------------------------------------------------------------------------


def test_observations_default_page_is_fifty_and_complete_by_paging(client, clean_db):
    _seed_db({"incident_id": "inc-default", "event_count": 40, "vuln_count": 20})
    path = "/api/v1/incidents/inc-default/observations"

    first = client.get(path).json()
    assert first["limit"] == 50
    assert first["offset"] == 0
    assert first["total"] == 61
    assert len(first["observations"]) == 50
    assert first["truncated"] is True
    # Counts describe the collection, never the page.
    assert first["event_count"] == 40
    assert first["vulnerability_count"] == 20
    assert first["correlation_count"] == 1

    tail = client.get(path, params={"offset": 50}).json()
    assert tail["limit"] == 50
    assert tail["offset"] == 50
    assert len(tail["observations"]) == 11
    assert tail["truncated"] is False

    expected = (
        [("correlation", "corr-inc-default")]
        + [("event", f"inc-default-evt-{index:04d}") for index in range(40)]
        + [("vulnerability", f"inc-default-vln-{index:04d}") for index in range(20)]
    )
    collected, last = _walk_observations(client, "inc-default", 50)
    assert collected == expected
    assert len(collected) == len(set(collected)) == 61
    assert last["total"] == 61
