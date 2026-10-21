"""REL-06 - bounded, pageable vulnerability audit history on finding detail.

``GET /vulnerabilities/{id}`` used to load every ``VulnerabilityAudit`` row for
the finding with no ceiling, so the detail read grew with the audit history.
The endpoint now counts the history and returns one bounded page, ordered
``(created_at, id)``, with additive metadata so clients can page the complete
history without guessing whether a short list is complete.

These tests prove the SQL bound and count, the default ceiling, the
exactly-at-cap and over-cap boundaries, a full page walk, deterministic
ordering when timestamps tie, validation of the paging parameters, the empty
history shape, and that the existing detail payload is unchanged.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from app.api.v1.endpoints.vuln_assessment import MAX_LIMIT
from app.database import session as session_module

TS = datetime(2026, 1, 5, 12, 0, 0)
ASSET_IP = "192.0.2.60"


def _seed_finding(vuln_id: str, count: int, *, same_timestamp: bool = False) -> None:
    from app.models.assets import Asset
    from app.models.vulnerabilities import Vulnerability, VulnerabilityAudit

    asset_id = f"asset-{vuln_id}"
    db = session_module.get_session_factory()()
    try:
        db.add(
            Asset(
                id=asset_id,
                ip_address=ASSET_IP,
                state="up",
                first_seen=TS,
                last_seen=TS,
            )
        )
        db.add(
            Vulnerability(
                id=vuln_id,
                asset_id=asset_id,
                scanner="fixture-scanner",
                scanner_finding_id=f"finding-{vuln_id}",
                title="bounded audit finding",
                severity="HIGH",
                status="OPEN",
                extra_data="{}",
                first_seen=TS,
                last_seen=TS,
            )
        )
        indexes = reversed(range(count)) if same_timestamp else range(count)
        for index in indexes:
            db.add(
                VulnerabilityAudit(
                    id=f"va-{index:04d}",
                    vulnerability_id=vuln_id,
                    event="VULNERABILITY_OPENED" if index == 0 else "VULNERABILITY_UPDATED",
                    actor="tester",
                    previous_status=None,
                    new_status="OPEN",
                    created_at=TS if same_timestamp else TS + timedelta(seconds=index),
                    detail=f"fact {index}",
                )
            )
        db.commit()
    finally:
        db.close()


def _statements_for(client, path: str, **params):  # noqa: ANN001, ANN201
    from sqlalchemy import event as sa_event

    engine = session_module.get_engine()
    captured: list[str] = []

    def _before(_conn, _cursor, statement, _parameters, _context, _many):
        captured.append(statement)

    sa_event.listen(engine, "before_cursor_execute", _before)
    try:
        response = client.get(path, params=params)
    finally:
        sa_event.remove(engine, "before_cursor_execute", _before)
    return response, captured


def test_audit_page_and_count_are_bounded_in_sql(client, clean_db):
    _seed_finding("vuln-sql-bound", MAX_LIMIT + 5)

    response, statements = _statements_for(
        client,
        "/api/v1/vulnerabilities/vuln-sql-bound",
        limit=100,
        offset=100,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["audit_total"] == MAX_LIMIT + 5
    assert body["audit_limit"] == 100
    assert body["audit_offset"] == 100
    assert body["audit_truncated"] is True
    assert len(body["audit"]) == 100
    assert body["audit"][0]["detail"] == "fact 100"

    audit_statements = [
        statement for statement in statements if "from vulnerability_audits" in statement.lower()
    ]
    page_statements = [
        statement for statement in audit_statements if "order by" in statement.lower()
    ]
    count_statements = [
        statement for statement in audit_statements if "order by" not in statement.lower()
    ]
    assert len(page_statements) == 1
    assert len(count_statements) == 1
    page = " ".join(page_statements[0].split()).upper()
    count = " ".join(count_statements[0].split()).upper()
    assert "LIMIT" in page
    assert "OFFSET" in page
    assert "COUNT(" in count


def test_exactly_at_the_cap_is_reported_complete(client, clean_db):
    _seed_finding("vuln-at-cap", MAX_LIMIT)

    body = client.get("/api/v1/vulnerabilities/vuln-at-cap").json()
    assert body["audit_total"] == MAX_LIMIT
    assert body["audit_limit"] == MAX_LIMIT
    assert body["audit_offset"] == 0
    assert body["audit_truncated"] is False
    assert len(body["audit"]) == MAX_LIMIT


def test_default_page_truncates_a_history_one_over_the_cap(client, clean_db):
    _seed_finding("vuln-over-cap", MAX_LIMIT + 1)

    body = client.get("/api/v1/vulnerabilities/vuln-over-cap").json()
    assert len(body["audit"]) == MAX_LIMIT
    assert body["audit_total"] == MAX_LIMIT + 1
    assert body["audit_limit"] == MAX_LIMIT
    assert body["audit_offset"] == 0
    assert body["audit_truncated"] is True
    assert body["audit"][-1]["detail"] == f"fact {MAX_LIMIT - 1}"


def test_pages_walk_the_complete_history_without_duplicates(client, clean_db):
    count = 205
    _seed_finding("vuln-walk", count)

    details: list[str] = []
    pages = []
    for offset in (0, 100, 200):
        body = client.get(
            "/api/v1/vulnerabilities/vuln-walk",
            params={"limit": 100, "offset": offset},
        ).json()
        pages.append(body)
        details.extend(entry["detail"] for entry in body["audit"])

    assert [len(page["audit"]) for page in pages] == [100, 100, 5]
    assert [page["audit_offset"] for page in pages] == [0, 100, 200]
    assert [page["audit_truncated"] for page in pages] == [True, True, False]
    assert all(page["audit_total"] == count for page in pages)
    assert details == [f"fact {index}" for index in range(count)]
    assert len(set(details)) == count


def test_invalid_audit_pagination_parameters_are_rejected(client, clean_db):
    _seed_finding("vuln-invalid", 1)
    path = "/api/v1/vulnerabilities/vuln-invalid"

    assert client.get(path, params={"limit": 0}).status_code == 422
    assert client.get(path, params={"limit": MAX_LIMIT + 1}).status_code == 422
    assert client.get(path, params={"offset": -1}).status_code == 422
    assert client.get(path, params={"limit": MAX_LIMIT}).status_code == 200


def test_audit_order_is_deterministic_when_timestamps_tie(client, clean_db):
    _seed_finding("vuln-tied", 5, same_timestamp=True)

    body = client.get("/api/v1/vulnerabilities/vuln-tied").json()
    assert [entry["detail"] for entry in body["audit"]] == [f"fact {index}" for index in range(5)]


def test_empty_audit_history_is_an_empty_page(client, clean_db):
    _seed_finding("vuln-no-audit", 0)

    response = client.get("/api/v1/vulnerabilities/vuln-no-audit")
    assert response.status_code == 200
    body = response.json()
    assert body["audit"] == []
    assert body["audit_total"] == 0
    assert body["audit_limit"] == MAX_LIMIT
    assert body["audit_offset"] == 0
    assert body["audit_truncated"] is False
    assert body["title"] == "bounded audit finding"


def test_detail_payload_and_audit_entry_shape_are_unchanged(client, clean_db):
    _seed_finding("vuln-shape", 2)

    body = client.get("/api/v1/vulnerabilities/vuln-shape").json()
    assert body["id"] == "vuln-shape"
    assert body["status"] == "OPEN"
    assert [entry["detail"] for entry in body["audit"]] == ["fact 0", "fact 1"]
    assert set(body["audit"][0]) == {
        "event",
        "actor",
        "previous_status",
        "new_status",
        "created_at",
        "detail",
    }
    assert body["audit"][0]["event"] == "VULNERABILITY_OPENED"
    assert body["audit"][1]["event"] == "VULNERABILITY_UPDATED"
    assert body["audit"][0]["actor"] == "tester"


def test_missing_vulnerability_still_returns_not_found(client, clean_db):
    response = client.get("/api/v1/vulnerabilities/does-not-exist")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "VULNERABILITY_NOT_FOUND"
