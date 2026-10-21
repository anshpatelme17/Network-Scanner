"""Regression tests for constant-cost scan-list audit loading."""

from datetime import datetime, timedelta

from sqlalchemy import event as sa_event

from app.database import session as session_module


def _count_queries(db, fn):  # noqa: ANN001, ANN201
    counter = {"n": 0}
    bind = db.get_bind()

    def _before(*_args, **_kwargs):
        counter["n"] += 1

    sa_event.listen(bind, "before_cursor_execute", _before)
    try:
        return fn(), counter["n"]
    finally:
        sa_event.remove(bind, "before_cursor_execute", _before)


def _seed_jobs(db, count, start=0):  # noqa: ANN001
    from app.models.scans import ScanAudit, ScanJob

    base = datetime(2026, 1, 1, 12, 0, 0)
    for index in range(start, start + count):
        job = ScanJob(
            id=f"scan-{index:03d}",
            target=f"10.0.0.{index + 1}",
            profile="quick",
            created_at=base + timedelta(seconds=index),
        )
        db.add(job)
        db.flush()
        for event in ("SCAN_REQUESTED", "SCAN_STARTED"):
            db.add(
                ScanAudit(
                    scan_id=job.id,
                    event=event,
                    actor="tester",
                    created_at=base + timedelta(seconds=index),
                )
            )


def test_scan_list_query_count_does_not_grow_with_page_size(clean_db):
    from app.api.v1.endpoints.network import list_scans

    db = session_module.get_session_factory()()
    try:
        _seed_jobs(db, 1)
        db.commit()
        (one, queries_one) = _count_queries(
            db, lambda: list_scans(db=db, auth=None, limit=100)
        )
        assert len(one) == 1

        _seed_jobs(db, 24, start=1)
        db.commit()
        (many, queries_many) = _count_queries(
            db, lambda: list_scans(db=db, auth=None, limit=100)
        )
        assert len(many) == 25
        assert queries_many == queries_one, (
            f"scan listing grew with page size: {queries_one} -> {queries_many}"
        )
        assert queries_many <= 2
    finally:
        db.close()


def test_scan_list_returns_each_jobs_audits_in_order(client, clean_db):
    from app.models.scans import ScanAudit, ScanJob

    base = datetime(2026, 1, 1, 12, 0, 0)
    db = session_module.get_session_factory()()
    try:
        db.add_all(
            [
                ScanJob(
                    id="scan-b",
                    target="10.0.0.2",
                    profile="quick",
                    created_at=base,
                ),
                ScanJob(
                    id="scan-a",
                    target="10.0.0.1",
                    profile="quick",
                    created_at=base + timedelta(seconds=1),
                ),
            ]
        )
        db.flush()
        db.add_all(
            [
                ScanAudit(
                    scan_id="scan-a",
                    event="SCAN_COMPLETED",
                    actor="tester",
                    created_at=base + timedelta(seconds=3),
                ),
                ScanAudit(
                    scan_id="scan-a",
                    event="SCAN_REQUESTED",
                    actor="tester",
                    created_at=base + timedelta(seconds=1),
                ),
                ScanAudit(
                    scan_id="scan-a",
                    event="SCAN_STARTED",
                    actor="tester",
                    created_at=base + timedelta(seconds=2),
                ),
                ScanAudit(
                    scan_id="scan-b",
                    event="SCAN_REQUESTED",
                    actor="tester",
                    created_at=base,
                ),
            ]
        )
        db.commit()
    finally:
        db.close()

    body = client.get("/api/v1/network/scans", params={"limit": 100}).json()
    by_id = {item["id"]: item for item in body}

    assert [item["id"] for item in body] == ["scan-a", "scan-b"]
    assert [entry["event"] for entry in by_id["scan-a"]["audit"]] == [
        "SCAN_REQUESTED",
        "SCAN_STARTED",
        "SCAN_COMPLETED",
    ]
    assert [entry["event"] for entry in by_id["scan-b"]["audit"]] == ["SCAN_REQUESTED"]
