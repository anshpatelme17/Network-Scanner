"""Asset inventory endpoints (Step 2).

Read-only views over the continuously updated inventory built from
authorized Nmap scans. No scan triggering here — see ``/network/scans``.
"""

from collections.abc import Sequence

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.api.v1.auth_deps import require_permission
from app.core.errors import error_response
from app.database.session import get_db
from app.models.assets import Asset, DiscoveredService
from app.models.risk import RiskAssessment
from app.models.scans import ScanJob
from app.models.vulnerabilities import Vulnerability
from app.schemas.assets import (
    AssetDetailResponse,
    AssetPage,
    AssetResponse,
    InventorySummary,
    ServiceResponse,
)
from app.schemas.vuln_assessment import AssetVulnRisk
from app.services.auth_service import AuthContext
from app.services.risk_service import ENTITY_VULN_FINDING, band_for

router = APIRouter(prefix="/assets", tags=["assets"])

MAX_LIMIT = 200


def _to_asset_response(asset: Asset, service_count: int) -> AssetResponse:
    return AssetResponse(
        id=asset.id,
        ip_address=asset.ip_address,
        hostname=asset.hostname,
        mac_address=asset.mac_address,
        operating_system=asset.operating_system,
        state=asset.state,
        asset_type=asset.asset_type,
        discovery_source=asset.discovery_source,
        service_count=service_count,
        first_seen=asset.first_seen,
        last_seen=asset.last_seen,
    )


@router.get("", response_model=AssetPage, summary="List assets")
def list_assets(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_ASSETS")),
    ip: str | None = Query(default=None, description="Substring filter on IP address"),
    hostname: str | None = Query(default=None, description="Substring filter on hostname"),
    state: str | None = Query(default=None, description="'up' or 'down'"),
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
):
    query = select(Asset)
    count_query = select(func.count(Asset.id))
    if ip:
        query = query.where(Asset.ip_address.contains(ip))
        count_query = count_query.where(Asset.ip_address.contains(ip))
    if hostname:
        query = query.where(Asset.hostname.contains(hostname))
        count_query = count_query.where(Asset.hostname.contains(hostname))
    if state in ("up", "down"):
        query = query.where(Asset.state == state)
        count_query = count_query.where(Asset.state == state)
    total = db.scalar(count_query) or 0
    assets = db.scalars(
        query.order_by(desc(Asset.last_seen), Asset.id).limit(limit).offset(offset)
    ).all()
    items = []
    for asset in assets:
        service_count = (
            db.scalar(
                select(func.count(DiscoveredService.id)).where(
                    DiscoveredService.asset_id == asset.id
                )
            )
            or 0
        )
        items.append(_to_asset_response(asset, service_count))
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/summary", response_model=InventorySummary, summary="Inventory totals")
def inventory_summary(
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("READ_ASSETS"))
):
    total_assets = db.scalar(select(func.count(Asset.id))) or 0
    active_assets = db.scalar(select(func.count(Asset.id)).where(Asset.state == "up")) or 0
    total_services = db.scalar(select(func.count(DiscoveredService.id))) or 0
    last_scan = db.scalar(select(ScanJob).order_by(desc(ScanJob.created_at)).limit(1))
    return {
        "total_assets": total_assets,
        "active_assets": active_assets,
        "total_services": total_services,
        "last_scan_at": last_scan.created_at if last_scan else None,
        "last_scan_status": last_scan.status if last_scan else None,
    }


@router.get("/{asset_id}", response_model=AssetDetailResponse, summary="Asset detail")
def get_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_ASSETS")),
):
    asset = db.scalar(select(Asset).where(Asset.id == asset_id))
    if asset is None:
        return error_response(
            "ASSET_NOT_FOUND", f"No asset with id {asset_id}.", status.HTTP_404_NOT_FOUND
        )
    services = db.scalars(
        select(DiscoveredService)
        .where(DiscoveredService.asset_id == asset.id)
        .order_by(DiscoveredService.port)
    ).all()
    detail = _to_asset_response(asset, len(services)).model_dump()
    detail["services"] = [ServiceResponse.model_validate(service) for service in services]
    return detail


@router.get("/{asset_id}/services", response_model=list[ServiceResponse], summary="Asset services")
def get_asset_services(
    asset_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_ASSETS")),
):
    asset = db.scalar(select(Asset).where(Asset.id == asset_id))
    if asset is None:
        return error_response(
            "ASSET_NOT_FOUND", f"No asset with id {asset_id}.", status.HTTP_404_NOT_FOUND
        )
    return list(
        db.scalars(
            select(DiscoveredService)
            .where(DiscoveredService.asset_id == asset.id)
            .order_by(DiscoveredService.port)
        ).all()
    )


_SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": -1}

# Hard ceiling on the rows any single asset-detail response may consider
# (Step 32). Server-side only: there is no query parameter that can raise
# it, so the result cannot grow with the size of the database. The
# alternative -- reading every risk row and filtering in Python -- made
# one asset's summary cost an O(global) scan, and any cap applied after
# that read silently dropped *other* assets' data from this asset's
# summary.
MAX_ASSET_FINDINGS = 1000


def _asset_findings_query(asset_id: str):
    """Findings for one asset, deterministically capped.

    ``order_by`` is required for the ``LIMIT`` to be meaningful: without a
    total order, which rows survive truncation is undefined.
    """
    return (
        select(Vulnerability)
        .where(Vulnerability.asset_id == asset_id)
        .order_by(Vulnerability.id)
        .limit(MAX_ASSET_FINDINGS)
    )


def _scored_assessment_query(finding_ids: Sequence[str]):
    """Risk rows for exactly these findings, hard-bounded.

    Scoping by ``entity_id`` (indexed) is what removes the global read;
    the ``LIMIT`` is what makes the row count independent of how many
    findings exist elsewhere. Both are server-side and not client-tunable.
    """
    return (
        select(RiskAssessment)
        .where(
            RiskAssessment.entity_type == ENTITY_VULN_FINDING,
            RiskAssessment.entity_id.in_(finding_ids),
        )
        .order_by(RiskAssessment.entity_id)
        .limit(MAX_ASSET_FINDINGS)
    )


@router.get(
    "/{asset_id}/vuln-risk", response_model=AssetVulnRisk, summary="Asset finding risk summary"
)
def get_asset_vuln_risk(
    asset_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_ASSETS")),
):
    """Aggregate stored findings for one asset, enriched by risk rows.

    Counts/severities come from all findings; the aggregate score comes
    from scored findings only (maximum). Empty (all zeros, INFO) when the
    asset has no findings — never a fabricated score.

    Bounded by :data:`MAX_ASSET_FINDINGS`. An asset with more findings than
    that reports a summary over the first ``MAX_ASSET_FINDINGS`` by id —
    a deliberate, documented ceiling rather than an O(global) read.
    """
    asset = db.scalar(select(Asset).where(Asset.id == asset_id))
    if asset is None:
        return error_response(
            "ASSET_NOT_FOUND", f"No asset with id {asset_id}.", status.HTTP_404_NOT_FOUND
        )
    findings = db.scalars(_asset_findings_query(asset_id)).all()
    by_finding: dict[str, RiskAssessment] = {}
    finding_ids = [finding.id for finding in findings]
    if finding_ids:
        by_finding = {
            row.entity_id: row for row in db.scalars(_scored_assessment_query(finding_ids)).all()
        }
    scored = [(finding, by_finding[finding.id]) for finding in findings if finding.id in by_finding]
    severities = [finding.severity for finding in findings]
    highest_severity = max(
        severities, key=lambda level: _SEVERITY_ORDER.get(level, -1), default="INFO"
    )
    cvss_values = [
        finding.cvss_score for finding in findings if isinstance(finding.cvss_score, int | float)
    ]
    aggregate = max((row.score for _, row in scored), default=0)
    calculated = [row.calculated_at for _, row in scored if row.calculated_at is not None]
    return {
        "asset_id": asset.id,
        "finding_count": len(findings),
        "highest_severity": highest_severity,
        "highest_cvss": max(cvss_values) if cvss_values else None,
        "critical_count": sum(1 for finding in findings if finding.severity == "CRITICAL"),
        "high_count": sum(1 for finding in findings if finding.severity == "HIGH"),
        "aggregate_risk": aggregate,
        "risk_level": band_for(aggregate),
        "calculated_at": max(calculated) if calculated else None,
    }
