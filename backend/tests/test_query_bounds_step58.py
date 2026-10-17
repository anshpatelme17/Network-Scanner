"""Step 58 - bounded asset service counts and aggregated SOC priority buckets.

Two query-performance issues are covered, each with a correctness test and a
query-count test:

* ``GET /api/v1/assets`` used to issue one ``COUNT`` per asset on the page
  (an N+1). It now runs a single grouped aggregate for the whole page.
* ``soc_overview`` priority buckets used to load every incident row into
  Python. They are now aggregated database-side in one grouped query.

Query volume is measured with the repository's established SQLAlchemy
``before_cursor_execute`` instrumentation (as in ``test_hardening_step31``),
not with mocks. No production behaviour, schema, permission or response field
changes; only the query strategy.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import event as sa_event

from app.database import session as session_module

TS = datetime(2026, 1, 5, 12, 0, 0)


def _count_queries(db, fn):  # noqa: ANN001, ANN201
    """Run ``fn`` and return (result, number of SQL statements executed)."""
    counter = {"n": 0}
    bind = db.get_bind()

    def _before(*_args, **_kwargs):
        counter["n"] += 1

    sa_event.listen(bind, "before_cursor_execute", _before)
    try:
        return fn(), counter["n"]
    finally:
        sa_event.remove(bind, "before_cursor_execute", _before)


def _statements(db, fn):  # noqa: ANN001, ANN201
    """Run ``fn`` and return (result, list of SQL statements executed)."""
    captured: list[str] = []
    bind = db.get_bind()

    def _before(_conn, _cursor, statement, _params, _context, _many):
        captured.append(statement)

    sa_event.listen(bind, "before_cursor_execute", _before)
    try:
        return fn(), captured
    finally:
        sa_event.remove(bind, "before_cursor_execute", _before)


def _add_asset(db, asset_id: str, ip: str, services: int = 0) -> None:  # noqa: ANN001
    from app.models.assets import Asset, DiscoveredService

    db.add(Asset(id=asset_id, ip_address=ip, state="up", first_seen=TS, last_seen=TS))
    for offset in range(services):
        db.add(DiscoveredService(asset_id=asset_id, port=1000 + offset, protocol="tcp"))


# ---------------------------------------------------------------------------
# A. Asset listing service counts
# ---------------------------------------------------------------------------


def test_asset_list_reports_accurate_service_counts(client, clean_db):
    """Zero-service, single-service and multi-service assets are all counted."""
    db = session_module.get_session_factory()()
    try:
        _add_asset(db, "asset-none", "10.0.0.1", services=0)
        _add_asset(db, "asset-one", "10.0.0.2", services=1)
        _add_asset(db, "asset-many", "10.0.0.3", services=5)
        db.commit()
    finally:
        db.close()

    items = client.get("/api/v1/assets", params={"limit": 50}).json()["items"]
    counts = {item["id"]: item["service_count"] for item in items}
    assert counts == {"asset-none": 0, "asset-one": 1, "asset-many": 5}


def test_asset_service_counts_survive_filters_and_paging(client, clean_db):
    """Grouped counts stay correct when the page is filtered and offset."""
    db = session_module.get_session_factory()()
    try:
        _add_asset(db, "asset-a", "10.9.0.1", services=2)
        _add_asset(db, "asset-b", "10.9.0.2", services=0)
        _add_asset(db, "asset-c", "10.9.0.3", services=4)
        db.commit()
    finally:
        db.close()

    page = client.get(
        "/api/v1/assets", params={"ip": "10.9.0", "limit": 1, "offset": 1}
    ).json()
    assert page["total"] == 3 and len(page["items"]) == 1
    # The returned asset's own count is exact regardless of what the other
    # assets on the filtered set would have contributed.
    only = page["items"][0]
    assert only["service_count"] == {"asset-a": 2, "asset-b": 0, "asset-c": 4}[only["id"]]


def test_asset_list_query_count_does_not_grow_with_page_size(clean_db):
    """The list endpoint is constant-cost in page size (no per-asset query)."""
    from app.api.v1.endpoints.assets import list_assets

    db = session_module.get_session_factory()()
    try:
        _add_asset(db, "asset-1", "10.0.1.1", services=2)
        db.commit()
        (one, queries_one) = _count_queries(
            db,
            lambda: list_assets(
                db=db, auth=None, ip=None, hostname=None, state=None, limit=50, offset=0
            ),
        )
        assert len(one["items"]) == 1

        for index in range(2, 26):
            _add_asset(db, f"asset-{index}", f"10.0.2.{index}", services=3)
        db.commit()

        (many, queries_many) = _count_queries(
            db,
            lambda: list_assets(
                db=db, auth=None, ip=None, hostname=None, state=None, limit=50, offset=0
            ),
        )
        assert len(many["items"]) == 25
        # count(*) + page + one grouped service count = 3, independent of N.
        assert queries_many == queries_one, (
            f"asset listing grew with page size: {queries_one} -> {queries_many}"
        )
        assert queries_many <= 3
    finally:
        db.close()


# ---------------------------------------------------------------------------
# B. SOC overview priority buckets
# ---------------------------------------------------------------------------


def _seed_incidents_with_scores(db, scores: list[int]) -> None:  # noqa: ANN001
    """Create one incident + linked assessment per score, plus one unscored."""
    from app.models.correlations import Correlation
    from app.models.incidents import Incident
    from app.models.risk import RiskAssessment

    db.add(
        Correlation(
            id="corr-seed",
            rule_id="seed",
            rule_name="Seed",
            title="seed",
            severity="LOW",
            window_start=TS,
            window_end=TS,
        )
    )
    for index, score in enumerate(scores):
        incident_id = f"inc-{index}"
        assessment_id = f"ra-{index}"
        db.add(
            RiskAssessment(
                id=assessment_id,
                entity_type="incident",
                entity_id=incident_id,
                score=score,
                severity="LOW",
                scoring_version="1.0.0",
            )
        )
        db.add(
            Incident(
                id=incident_id,
                incident_key=f"INC-{index:06d}",
                title="scored incident",
                severity="LOW",
                correlation_id="corr-seed",
                risk_assessment_id=assessment_id,
                first_seen=TS,
                last_seen=TS,
            )
        )
    # An incident with no linked assessment must land in UNSCORED.
    db.add(
        Incident(
            id="inc-unscored",
            incident_key="INC-999999",
            title="unscored incident",
            severity="LOW",
            correlation_id="corr-seed",
            risk_assessment_id=None,
            first_seen=TS,
            last_seen=TS,
        )
    )


def test_priority_buckets_match_priority_for_at_boundaries(client, clean_db):
    """Boundary scores, plus a null assessment, bucket exactly as priority_for."""
    from app.services import soc_overview
    from app.services.risk_service import priority_for

    scores = [80, 100, 79, 60, 59, 40, 39, 0]
    expected = {"P1": 0, "P2": 0, "P3": 0, "P4": 0, "UNSCORED": 0}
    for score in scores:
        expected[priority_for(score)] += 1
    expected["UNSCORED"] += 1

    db = session_module.get_session_factory()()
    try:
        _seed_incidents_with_scores(db, scores)
        db.commit()
        assert soc_overview._priority_buckets(db) == expected
        assert soc_overview.build_overview(db, limit=1)["incidents_by_priority"] == expected
    finally:
        db.close()

    # The public payload is unchanged in shape and value.
    assert client.get("/api/v1/overview").json()["incidents_by_priority"] == expected


def test_priority_buckets_aggregate_database_side(clean_db):
    """Bucketing is a single grouped aggregate, not a per-row Python scan.

    The previous implementation issued one query too, but it projected one
    ``score`` row per incident and bucketed in Python. Asserting the executed
    SQL aggregates (``GROUP BY`` + ``count``) distinguishes the fix and holds
    regardless of how many incidents exist.
    """
    from app.models.correlations import Correlation
    from app.models.incidents import Incident
    from app.models.risk import RiskAssessment
    from app.services import soc_overview

    db = session_module.get_session_factory()()
    try:
        db.add(
            Correlation(
                id="corr-seed",
                rule_id="seed",
                rule_name="Seed",
                title="seed",
                severity="LOW",
                window_start=TS,
                window_end=TS,
            )
        )
        db.add(
            RiskAssessment(
                id="ra-1",
                entity_type="incident",
                entity_id="inc-1",
                score=50,
                severity="LOW",
                scoring_version="1.0.0",
            )
        )
        db.add(
            Incident(
                id="inc-1",
                incident_key="INC-000001",
                title="t",
                severity="LOW",
                correlation_id="corr-seed",
                risk_assessment_id="ra-1",
                first_seen=TS,
                last_seen=TS,
            )
        )
        db.commit()
        (first, statements_one) = _statements(db, lambda: soc_overview._priority_buckets(db))

        for index in range(2, 51):
            incident_id = f"inc-{index}"
            assessment_id = f"ra-{index}"
            db.add(
                RiskAssessment(
                    id=assessment_id,
                    entity_type="incident",
                    entity_id=incident_id,
                    score=50,
                    severity="LOW",
                    scoring_version="1.0.0",
                )
            )
            db.add(
                Incident(
                    id=incident_id,
                    incident_key=f"INC-{index:06d}",
                    title="t",
                    severity="LOW",
                    correlation_id="corr-seed",
                    risk_assessment_id=assessment_id,
                    first_seen=TS,
                    last_seen=TS,
                )
            )
        db.commit()

        (second, statements_many) = _statements(db, lambda: soc_overview._priority_buckets(db))
        assert len(statements_one) == len(statements_many) == 1
        sql = statements_many[0].lower()
        # Database-side aggregation: the incident table is grouped, not read
        # row-by-row into Python.
        assert "group by" in sql
        assert "count(" in sql
        assert first["P3"] == 1 and second["P3"] == 50
    finally:
        db.close()
