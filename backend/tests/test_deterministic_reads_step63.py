"""Step 63 - deterministic ordering for scan-job reads.

``GET /network/scans`` and ``GET /vulnerability-scans`` ordered rows by
``ScanJob.created_at`` alone, and ``GET /assets/summary`` picked the "last"
scan the same way - neither carried a unique tie-breaker. Two jobs sharing a
timestamp could therefore be listed (or selected as "last") in an arbitrary
order: the same class of bug fixed for assets/events/correlations in Step 57,
and a problem for the offset-less ``limit`` these routes already expose.

Each test seeds scan jobs that share the exact primary ordering timestamp and
inserts their ids in the *reverse* of the expected ascending order, so the
natural storage order differs from the documented ``created_at DESC, id ASC``
order and a missing tie-break is observable. The tests assert the documented
order, that repeated requests are identical, and that the primary direction
(a newer timestamp) still wins over the id tie-break.

Scope: deterministic ordering for an unchanged dataset only. No production
behaviour changes beyond tie resolution; no test uses ``sleep`` (timestamps
are set explicitly).
"""

from __future__ import annotations

from datetime import datetime, timedelta

from app.database import session as session_module

# One shared timestamp: every seeded row ties on the primary ordering column.
TS = datetime(2026, 1, 5, 12, 0, 0)

# Descending insertion order: without the id tie-break the DESC primary scan
# returns these in insertion order (descending ids), while the documented
# order is ascending ids.
SCAN_IDS = ["scan-e", "scan-d", "scan-c", "scan-b", "scan-a"]
VULN_IDS = ["vscn-e", "vscn-d", "vscn-c", "vscn-b", "vscn-a"]
NMAP_DECOY_IDS = ["decoy-c", "decoy-b", "decoy-a"]

SCAN_TYPE_VULN = "vulnerability"


def _job(job_id: str, created_at: datetime, scan_type: str = "nmap", status: str = "completed"):
    from app.models.scans import ScanJob

    return ScanJob(
        id=job_id,
        target="10.20.0.0/24",
        profile="quick",
        scan_type=scan_type,
        requested_by="operator",
        status=status,
        created_at=created_at,
    )


def _seed(jobs) -> None:  # noqa: ANN001
    db = session_module.get_session_factory()()
    try:
        for job in jobs:
            db.add(job)
        db.commit()
    finally:
        db.close()


def _ids(client, path: str, **params) -> list[str]:
    return [item["id"] for item in client.get(path, params=params).json()]


# ---------------------------------------------------------------------------
# List endpoints resolve ties by ascending id
# ---------------------------------------------------------------------------


def test_network_scan_list_is_deterministic(client, clean_db):
    _seed([_job(job_id, TS) for job_id in SCAN_IDS])
    expected = ["scan-a", "scan-b", "scan-c", "scan-d", "scan-e"]

    assert _ids(client, "/api/v1/network/scans", limit=50) == expected
    # Repeated identical requests and a smaller page agree on the same prefix.
    assert _ids(client, "/api/v1/network/scans", limit=2) == expected[:2]
    assert _ids(client, "/api/v1/network/scans", limit=2) == expected[:2]


def test_vulnerability_scan_list_is_deterministic(client, clean_db):
    _seed([_job(job_id, TS, scan_type=SCAN_TYPE_VULN) for job_id in VULN_IDS])
    # Discovery jobs must never appear in the vulnerability list.
    _seed([_job(job_id, TS) for job_id in NMAP_DECOY_IDS])
    expected = ["vscn-a", "vscn-b", "vscn-c", "vscn-d", "vscn-e"]

    assert _ids(client, "/api/v1/vulnerability-scans", limit=50) == expected
    assert _ids(client, "/api/v1/vulnerability-scans", limit=2) == expected[:2]
    assert _ids(client, "/api/v1/vulnerability-scans", limit=2) == expected[:2]


# ---------------------------------------------------------------------------
# The primary sort direction is preserved; only ties are resolved by id
# ---------------------------------------------------------------------------


def test_scan_list_keeps_recency_before_id(client, clean_db):
    """A newer created_at still sorts first; ties fall back to ascending id."""
    _seed(
        [
            _job("scan-old-a", TS),
            _job("scan-new", TS + timedelta(hours=1)),
            _job("scan-old-b", TS),
        ]
    )
    assert _ids(client, "/api/v1/network/scans", limit=50) == [
        "scan-new",
        "scan-old-a",
        "scan-old-b",
    ]


# ---------------------------------------------------------------------------
# Inventory summary "last scan" is deterministic too
# ---------------------------------------------------------------------------


def test_inventory_summary_last_scan_resolves_ties_by_id(client, clean_db):
    """All jobs tie on created_at; the smallest id is the documented "last"."""
    statuses = {
        "scan-e": "queued",
        "scan-d": "running",
        "scan-c": "cancelled",
        "scan-b": "failed",
        "scan-a": "completed",
    }
    _seed([_job(job_id, TS, status=statuses[job_id]) for job_id in SCAN_IDS])

    body = client.get("/api/v1/assets/summary").json()
    assert body["last_scan_status"] == "completed"  # scan-a, the smallest id
    assert body["last_scan_at"] is not None


def test_inventory_summary_last_scan_prefers_newest(client, clean_db):
    _seed(
        [
            _job("scan-old", TS, status="completed"),
            _job("scan-new", TS + timedelta(hours=1), status="failed"),
        ]
    )
    body = client.get("/api/v1/assets/summary").json()
    assert body["last_scan_status"] == "failed"  # scan-new, regardless of id
