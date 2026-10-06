"""Bounded asset-detail summary (Step 32 Remediation 5).

Finding: ``GET /assets/{id}/vuln-risk`` read **every** ``vuln_finding`` risk
row in the database and filtered it in Python, so one asset's summary cost
an O(global) scan whose result grew with the size of the installation. No
``LIMIT`` was applied anywhere on the path.

The fix scopes the risk read to the asset's own findings (indexed) and caps
both reads server-side. These tests prove the bound holds at the boundary
and on an oversized asset, and that no client input can widen it.
"""

import pytest
from sqlalchemy import select

from app.api.v1.endpoints.assets import (
    MAX_ASSET_FINDINGS,
    _asset_findings_query,
    _scored_assessment_query,
)
from app.models.assets import Asset
from app.models.risk import RiskAssessment
from app.models.vulnerabilities import Vulnerability
from app.services.risk_service import ENTITY_VULN_FINDING

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _session():
    from app.database import session as session_module

    return session_module.get_session_factory()()


def _make_asset(ip: str) -> str:
    db = _session()
    try:
        asset = Asset(ip_address=ip, state="up")
        db.add(asset)
        db.commit()
        return asset.id
    finally:
        db.close()


def _seed_findings(asset_id: str, count: int, severity: str = "HIGH") -> list[str]:
    """Bulk-insert ``count`` findings for one asset (no HTTP round-trips)."""
    db = _session()
    try:
        rows = [
            Vulnerability(
                asset_id=asset_id,
                scanner="seed",
                scanner_finding_id=f"seed-{index}",
                title=f"finding {index}",
                severity=severity,
                cvss_score=7.5,
            )
            for index in range(count)
        ]
        db.add_all(rows)
        db.commit()
        return [row.id for row in rows]
    finally:
        db.close()


def _seed_assessments(finding_ids: list[str], score: int = 40) -> None:
    db = _session()
    try:
        db.add_all(
            [
                RiskAssessment(
                    entity_type=ENTITY_VULN_FINDING,
                    entity_id=finding_id,
                    score=score,
                    severity="HIGH",
                    scoring_version="1.0.0",
                )
                for finding_id in finding_ids
            ]
        )
        db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Structural: both queries carry a server-side bound
# ---------------------------------------------------------------------------


def test_findings_query_is_limited():
    sql = str(_asset_findings_query("a").compile(compile_kwargs={"literal_binds": False}))
    assert "LIMIT" in sql.upper()
    assert "ORDER BY" in sql.upper(), "truncation must be deterministic"


def test_assessment_query_is_limited_and_scoped_to_the_findings():
    sql = str(
        _scored_assessment_query(["f1", "f2"]).compile(compile_kwargs={"literal_binds": False})
    )
    assert "LIMIT" in sql.upper()
    # The global read is gone: the risk rows are filtered to these findings.
    assert "entity_id IN" in sql
    assert "entity_type" in sql


def test_every_asset_detail_query_is_bounded():
    """Structural guard: the cap exists and no query parameter can raise it.

    ``GET /vuln-risk`` takes only ``asset_id``; if a size parameter is ever
    added it must arrive clamped, so assert the bound is a module constant
    rather than anything derived from the request.
    """
    from app.api.v1.endpoints import assets as assets_endpoint

    assert isinstance(MAX_ASSET_FINDINGS, int)
    assert MAX_ASSET_FINDINGS > 0
    routes = [route for route in assets_endpoint.router.routes if route.path.endswith("/vuln-risk")]
    assert len(routes) == 1
    dependant = routes[0].dependant
    query_params = {parameter.name for parameter in dependant.query_params}
    path_params = {parameter.name for parameter in dependant.path_params}
    assert query_params == set(), (
        f"vuln-risk must not accept client-controlled sizing: {query_params}"
    )
    assert path_params == {"asset_id"}


# ---------------------------------------------------------------------------
# Behaviour: normal
# ---------------------------------------------------------------------------


def test_normal_asset_summary_is_unchanged(client, clean_db):
    asset_id = _make_asset("192.0.2.10")
    finding_ids = _seed_findings(asset_id, 3)
    _seed_assessments(finding_ids, score=55)

    response = client.get(f"/api/v1/assets/{asset_id}/vuln-risk")
    assert response.status_code == 200
    body = response.json()
    assert body["asset_id"] == asset_id
    assert body["finding_count"] == 3
    assert body["highest_severity"] == "HIGH"
    assert body["high_count"] == 3
    assert body["highest_cvss"] == 7.5
    assert body["aggregate_risk"] == 55


def test_asset_with_no_findings_reports_no_risk(client, clean_db):
    asset_id = _make_asset("192.0.2.11")
    body = client.get(f"/api/v1/assets/{asset_id}/vuln-risk").json()
    assert body["finding_count"] == 0
    assert body["aggregate_risk"] == 0
    assert body["risk_level"] == "INFO"
    assert body["calculated_at"] is None


def test_other_assets_rows_do_not_leak_into_the_summary(client, clean_db):
    """Global risk rows must not influence another asset's aggregate."""
    first = _make_asset("192.0.2.12")
    second = _make_asset("192.0.2.13")
    _seed_assessments(_seed_findings(first, 1), score=10)
    _seed_assessments(_seed_findings(second, 1), score=99)

    assert client.get(f"/api/v1/assets/{first}/vuln-risk").json()["aggregate_risk"] == 10
    assert client.get(f"/api/v1/assets/{second}/vuln-risk").json()["aggregate_risk"] == 99


# ---------------------------------------------------------------------------
# Behaviour: the boundary
# ---------------------------------------------------------------------------


def test_asset_exactly_at_the_maximum_is_summarised_in_full(client, clean_db):
    asset_id = _make_asset("192.0.2.14")
    _seed_findings(asset_id, MAX_ASSET_FINDINGS)
    _seed_assessments(_seed_findings(asset_id, 0), score=1)  # no-op, keeps intent explicit

    body = client.get(f"/api/v1/assets/{asset_id}/vuln-risk").json()
    assert body["finding_count"] == MAX_ASSET_FINDINGS


def test_one_row_over_the_maximum_is_capped(client, clean_db):
    """The oversized case: the response is bounded, not the full set."""
    asset_id = _make_asset("192.0.2.15")
    _seed_findings(asset_id, MAX_ASSET_FINDINGS + 1)

    body = client.get(f"/api/v1/assets/{asset_id}/vuln-risk").json()
    assert body["finding_count"] == MAX_ASSET_FINDINGS, "the cap did not hold"


# ---------------------------------------------------------------------------
# Behaviour: the client cannot widen the maximum
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 100000},
        {"limit": MAX_ASSET_FINDINGS + 1},
        {"limit": -1},
        {"page_size": 100000},
        {"max_findings": 100000},
    ],
)
def test_client_cannot_widen_the_bound(client, clean_db, params):
    """A size parameter is not part of this API and is not honoured."""
    asset_id = _make_asset("192.0.2.16")
    _seed_findings(asset_id, 2)

    response = client.get(f"/api/v1/assets/{asset_id}/vuln-risk", params=params)
    # Unknown parameters are ignored, not obeyed; the result stays correct
    # and bounded either way.
    assert response.status_code == 200
    assert response.json()["finding_count"] == 2
    assert response.json()["finding_count"] <= MAX_ASSET_FINDINGS


def test_the_bound_is_a_constant_not_a_request_value():
    """Structural: the cap cannot be influenced by client input at all."""
    import inspect

    from app.api.v1.endpoints import assets as assets_endpoint

    signature = inspect.signature(assets_endpoint.get_asset_vuln_risk)
    assert [p.name for p in signature.parameters.values()] == ["asset_id", "db", "auth"]
    assert assets_endpoint.MAX_ASSET_FINDINGS == 1000


# ---------------------------------------------------------------------------
# Scope: the read is no longer global
# ---------------------------------------------------------------------------


def test_unrelated_risk_rows_are_not_loaded(client, clean_db):
    """Count rows actually loaded for one asset, whatever else exists.

    A global read would load every vuln_finding row in the database; the
    scoped read loads at most this asset's own.
    """
    asset_id = _make_asset("192.0.2.17")
    for index in range(5):
        other = _make_asset(f"198.51.100.{index}")
        _seed_assessments(_seed_findings(other, 2), score=50)

    loaded: list[int] = []
    db = _session()
    try:
        target = db.scalars(
            _asset_findings_query(asset_id).with_only_columns(Vulnerability.id)
        ).all()
        loaded.append(len(target))
        scoped = db.scalars(
            _scored_assessment_query([row.id for row in target]).with_only_columns(
                RiskAssessment.id
            )
        ).all()
        loaded.append(len(scoped))
        total = len(db.scalars(select(RiskAssessment.id)).all())
    finally:
        db.close()

    assert total >= 10, "the fixture must contain plenty of unrelated rows"
    assert loaded == [0, 0], "an empty asset loads nothing"
    assert loaded[0] <= MAX_ASSET_FINDINGS
    assert loaded[1] <= MAX_ASSET_FINDINGS
