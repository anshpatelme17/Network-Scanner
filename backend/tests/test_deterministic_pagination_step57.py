"""Step 57 - deterministic list pagination ordering.

The ``GET /assets``, ``GET /events`` and ``GET /correlations`` list endpoints
ordered rows by a single timestamp column with no unique tie-breaker, so two
records sharing that timestamp could be returned in an arbitrary order. With
offset pagination that lets an item appear on one page and be skipped on the
next, even when the underlying data is unchanged.

Each test seeds rows that share the exact primary ordering timestamp, and the
primary-key ids are inserted in the *reverse* of their ascending order so a
missing tie-break is observable (the natural storage order differs from the
expected order). The tests then check that:

* the returned order is the documented ``<primary> DESC, id ASC`` order;
* paging with a small ``limit`` reproduces the full sequence with no
  duplicates and no omissions;
* repeating the requests returns the identical sequence.

Scope: deterministic ordering for an **unchanged** dataset only. This is not
cursor pagination - rows inserted or deleted between requests still shift
offsets. No production behaviour changes beyond tie resolution, and no test
uses ``sleep`` (timestamps are set explicitly).
"""

from __future__ import annotations

from datetime import datetime, timedelta

from app.database import session as session_module

# One shared timestamp: every seeded row ties on the primary ordering column.
TS = datetime(2026, 1, 5, 12, 0, 0)

# Insertion orders are deliberately chosen so that the natural order produced
# without a tie-breaker differs from the expected ascending-id order (verified
# against this repository's SQLite engine): events are inserted in ascending id
# order (the DESC primary scan then returns them reversed), while assets and
# correlations are inserted in descending id order (the DESC primary scan
# returns them in insertion order). A missing tie-break therefore changes the
# result the tests assert.
ASSET_IDS = ["asset-e", "asset-d", "asset-c", "asset-b", "asset-a"]
EVENT_IDS = ["evt-a", "evt-b", "evt-c", "evt-d", "evt-e"]
CORRELATION_IDS = ["corr-e", "corr-d", "corr-c", "corr-b", "corr-a"]


def _seed_assets() -> None:
    from app.models.assets import Asset

    db = session_module.get_session_factory()()
    try:
        for index, asset_id in enumerate(ASSET_IDS):
            db.add(
                Asset(
                    id=asset_id,
                    ip_address=f"10.10.0.{index + 1}",
                    state="up",
                    first_seen=TS,
                    last_seen=TS,
                )
            )
        db.commit()
    finally:
        db.close()


def _seed_events() -> None:
    db = session_module.get_session_factory()()
    try:
        for event_id in EVENT_IDS:
            db.add(_event(event_id, TS))
        db.commit()
    finally:
        db.close()


def _seed_correlations() -> None:
    from app.models.correlations import Correlation

    db = session_module.get_session_factory()()
    try:
        for correlation_id in CORRELATION_IDS:
            db.add(
                Correlation(
                    id=correlation_id,
                    rule_id="tie-rule",
                    rule_name="Tie rule",
                    title="tied correlation",
                    severity="LOW",
                    window_start=TS,
                    window_end=TS,
                    updated_at=TS,
                )
            )
        db.commit()
    finally:
        db.close()


def _event(event_id: str, event_time: datetime):
    from app.models.events import SecurityEvent

    return SecurityEvent(
        id=event_id,
        event_time=event_time,
        source_type="SURICATA",
        source_name="fixture",
        event_type="pagination.tie",
        severity="LOW",
        title="tied event",
        fingerprint=f"fp-{event_id}",
        normalized_data="{}",
    )


def _page_ids(client, path: str, limit: int) -> list[str]:
    """Walk every page with ``limit`` and return the concatenated ids."""
    ids: list[str] = []
    offset = 0
    while True:
        page = client.get(path, params={"limit": limit, "offset": offset}).json()
        batch = [item["id"] for item in page["items"]]
        ids.extend(batch)
        offset += limit
        if not batch or offset >= page["total"]:
            return ids


# ---------------------------------------------------------------------------
# Deterministic ordering across page boundaries, repeated requests included
# ---------------------------------------------------------------------------


def test_assets_list_pagination_is_deterministic(client, clean_db):
    _seed_assets()
    expected = ["asset-a", "asset-b", "asset-c", "asset-d", "asset-e"]

    listing = client.get("/api/v1/assets", params={"limit": 50}).json()
    assert listing["total"] == 5
    assert [item["id"] for item in listing["items"]] == expected

    # Repeated full walks are byte-for-byte identical.
    assert _page_ids(client, "/api/v1/assets", 2) == expected
    assert _page_ids(client, "/api/v1/assets", 2) == expected

    # Adjacent pages neither overlap nor omit: every id appears exactly once.
    paged = _page_ids(client, "/api/v1/assets", 2)
    assert len(paged) == 5
    assert len(set(paged)) == 5
    assert sorted(paged) == sorted(expected)


def test_events_list_pagination_is_deterministic(client, clean_db):
    _seed_events()
    expected = ["evt-a", "evt-b", "evt-c", "evt-d", "evt-e"]

    listing = client.get("/api/v1/events", params={"limit": 50}).json()
    assert listing["total"] == 5
    assert [item["id"] for item in listing["items"]] == expected

    assert _page_ids(client, "/api/v1/events", 2) == expected
    assert _page_ids(client, "/api/v1/events", 2) == expected

    first = client.get("/api/v1/events", params={"limit": 2, "offset": 0}).json()["items"]
    second = client.get("/api/v1/events", params={"limit": 2, "offset": 2}).json()["items"]
    first_ids = {item["id"] for item in first}
    second_ids = {item["id"] for item in second}
    assert first_ids.isdisjoint(second_ids)
    assert first_ids | second_ids == {"evt-a", "evt-b", "evt-c", "evt-d"}


def test_correlations_list_pagination_is_deterministic(client, clean_db):
    _seed_correlations()
    expected = ["corr-a", "corr-b", "corr-c", "corr-d", "corr-e"]

    listing = client.get("/api/v1/correlations", params={"limit": 50}).json()
    assert listing["total"] == 5
    assert [item["id"] for item in listing["items"]] == expected

    assert _page_ids(client, "/api/v1/correlations", 2) == expected
    assert _page_ids(client, "/api/v1/correlations", 2) == expected

    paged = _page_ids(client, "/api/v1/correlations", 2)
    assert len(set(paged)) == 5
    assert paged == expected


# ---------------------------------------------------------------------------
# The primary sort direction is preserved; only ties are resolved by id
# ---------------------------------------------------------------------------


def test_event_order_keeps_primary_direction_then_id(client, clean_db):
    """A newer event_time still sorts first; ties fall back to ascending id."""
    db = session_module.get_session_factory()()
    try:
        # Insertion order is deliberately not the expected order.
        db.add(_event("evt-tie-b", TS))
        db.add(_event("evt-newest", TS + timedelta(hours=1)))
        db.add(_event("evt-tie-a", TS))
        db.commit()
    finally:
        db.close()

    items = client.get("/api/v1/events", params={"limit": 50}).json()["items"]
    assert [item["id"] for item in items] == ["evt-newest", "evt-tie-a", "evt-tie-b"]
