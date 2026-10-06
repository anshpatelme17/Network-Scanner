"""Vulnerability assessment endpoints (Step 15, inventory only).

Assessments run the fixture scanner over already-inventoried assets and
upsert normalized findings. No live scanners, no exploitation, no
remediation — findings are data for review, and status moves only
through explicit transitions.
"""

import json

from fastapi import APIRouter, BackgroundTasks, Depends, Query, status
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.api.v1.auth_deps import require_permission
from app.api.v1.limits import rate_limit
from app.core.errors import error_response
from app.database.session import get_db
from app.models.risk import RiskAssessment
from app.models.scans import ScanAudit, ScanJob
from app.models.vulnerabilities import Vulnerability, VulnerabilityAudit
from app.schemas.risk import RiskAssessmentResponse
from app.schemas.vuln_assessment import (
    FindingCorrelations,
    LinkedEvent,
    LinkedIncident,
    VulnerabilityDetailResponse,
    VulnerabilityPage,
    VulnerabilityResponse,
    VulnFindingAuditEntry,
    VulnScanAuditEntry,
    VulnScanRequest,
    VulnScanResponse,
    VulnStatusUpdate,
)
from app.services import vuln_correlation, vulnerability_service
from app.services.auth_service import AuthContext
from app.services.risk_service import ENTITY_VULN_FINDING
from app.services.target_validation import InvalidTargetError, TargetNotAuthorizedError

router = APIRouter(tags=["vulnerabilities"])

MAX_LIMIT = 200
VULN_SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN")
VULN_STATUSES = ("OPEN", "RESOLVED", "ACCEPTED_RISK")


def _scan_response(db: Session, job: ScanJob) -> dict:
    body = VulnScanResponse.model_validate(job).model_dump()
    audit = db.scalars(
        select(ScanAudit)
        .where(ScanAudit.scan_id == job.id)
        .order_by(ScanAudit.created_at, ScanAudit.id)
    ).all()
    body["audit"] = [VulnScanAuditEntry.model_validate(entry).model_dump() for entry in audit]
    return body


def _vuln_response(row: Vulnerability) -> dict:
    try:
        parsed = json.loads(row.extra_data or "{}")
        extra = parsed if isinstance(parsed, dict) else {}
    except (ValueError, TypeError):
        extra = {}
    return {
        "id": row.id,
        "asset_id": row.asset_id,
        "service_id": row.service_id,
        "scanner": row.scanner,
        "scanner_version": row.scanner_version,
        "scanner_finding_id": row.scanner_finding_id,
        "title": row.title,
        "description": row.description,
        "severity": row.severity,
        "cvss_score": row.cvss_score,
        "cve_id": row.cve_id,
        "cwe_id": row.cwe_id,
        "affected_component": row.affected_component,
        "detected_version": row.detected_version,
        "fixed_version": row.fixed_version,
        "evidence": row.evidence,
        "remediation_reference": row.remediation_reference,
        "extra_data": extra,
        "status": row.status,
        "first_seen": row.first_seen,
        "last_seen": row.last_seen,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def _finding_or_404(db: Session, vulnerability_id: str):
    row = db.scalar(select(Vulnerability).where(Vulnerability.id == vulnerability_id))
    if row is None:
        return None
    return row


@router.post(
    "/vulnerability-scans",
    response_model=VulnScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request a vulnerability assessment of an inventoried asset",
)
def create_vuln_scan(
    request: VulnScanRequest,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("MANAGE_VULNERABILITIES")),
    _limit: None = Depends(rate_limit("vuln_scan_start", "rate_limit_scan_start")),
):
    """Queue a vulnerability assessment of an authorized target.

    Shares the ``RATE_LIMIT_SCAN_START`` budget with network scan starts
    (Step 32). It is a separate operation key, so the two routes are
    budgeted independently and the log names the route that was limited.
    The limit is listed last so an unauthorized caller is refused before
    any budget is consumed.
    """
    try:
        job = vulnerability_service.create_assessment(
            db, background, request.profile, request.requested_by, request.asset_id, request.target
        )
    except InvalidTargetError as exc:
        return error_response("INVALID_TARGET", str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY)
    except TargetNotAuthorizedError as exc:
        return error_response("TARGET_NOT_AUTHORIZED", str(exc), status.HTTP_403_FORBIDDEN)
    except LookupError as exc:
        return error_response("ASSET_NOT_FOUND", str(exc), status.HTTP_404_NOT_FOUND)
    return _scan_response(db, job)


@router.get(
    "/vulnerability-scans", response_model=list[VulnScanResponse], summary="List assessments"
)
def list_vuln_scans(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_VULNERABILITIES")),
    limit: int = Query(default=20, ge=1, le=100),
):
    jobs = db.scalars(
        select(ScanJob)
        .where(ScanJob.scan_type == vulnerability_service.SCAN_TYPE_VULNERABILITY_VALUE)
        .order_by(desc(ScanJob.created_at))
        .limit(limit)
    ).all()
    return [_scan_response(db, job) for job in jobs]


@router.get(
    "/vulnerability-scans/{scan_id}", response_model=VulnScanResponse, summary="Assessment status"
)
def get_vuln_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_VULNERABILITIES")),
):
    job = db.scalar(select(ScanJob).where(ScanJob.id == scan_id))
    if job is None or job.scan_type != vulnerability_service.SCAN_TYPE_VULNERABILITY_VALUE:
        return error_response(
            "SCAN_NOT_FOUND", f"No vulnerability scan with id {scan_id}.", status.HTTP_404_NOT_FOUND
        )
    return _scan_response(db, job)


@router.get("/vulnerabilities", response_model=VulnerabilityPage, summary="List findings")
def list_vulnerabilities(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_VULNERABILITIES")),
    severity: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    asset_id: str | None = Query(default=None),
    scanner: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
):
    if severity is not None and severity not in VULN_SEVERITIES:
        return error_response(
            "INVALID_FILTER",
            f"Unknown severity filter: {severity!r}.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    if status_filter is not None and status_filter not in vulnerability_service.VULN_STATUSES:
        return error_response(
            "INVALID_FILTER",
            f"Unknown status filter: {status_filter!r}.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    query = select(Vulnerability)
    count_query = select(func.count(Vulnerability.id))
    if severity is not None:
        query = query.where(Vulnerability.severity == severity)
        count_query = count_query.where(Vulnerability.severity == severity)
    if status_filter is not None:
        query = query.where(Vulnerability.status == status_filter)
        count_query = count_query.where(Vulnerability.status == status_filter)
    if asset_id is not None:
        query = query.where(Vulnerability.asset_id == asset_id)
        count_query = count_query.where(Vulnerability.asset_id == asset_id)
    if scanner is not None:
        query = query.where(Vulnerability.scanner == scanner)
        count_query = count_query.where(Vulnerability.scanner == scanner)
    total = db.scalar(count_query) or 0
    rows = db.scalars(
        query.order_by(desc(Vulnerability.severity), Vulnerability.id).limit(limit).offset(offset)
    ).all()
    return {
        "items": [_vuln_response(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get(
    "/vulnerabilities/{vulnerability_id}",
    response_model=VulnerabilityDetailResponse,
    summary="Finding detail",
)
def get_vulnerability(
    vulnerability_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_VULNERABILITIES")),
):
    row = _finding_or_404(db, vulnerability_id)
    if row is None:
        return error_response(
            "VULNERABILITY_NOT_FOUND",
            f"No vulnerability with id {vulnerability_id}.",
            status.HTTP_404_NOT_FOUND,
        )
    detail = _vuln_response(row)
    audit = db.scalars(
        select(VulnerabilityAudit)
        .where(VulnerabilityAudit.vulnerability_id == row.id)
        .order_by(VulnerabilityAudit.created_at, VulnerabilityAudit.id)
    ).all()
    detail["audit"] = [VulnFindingAuditEntry.model_validate(entry).model_dump() for entry in audit]
    return detail


@router.get(
    "/assets/{asset_id}/vulnerabilities", response_model=VulnerabilityPage, summary="Asset findings"
)
def get_asset_vulnerabilities(
    asset_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_VULNERABILITIES")),
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
):
    from app.models.assets import Asset

    asset = db.scalar(select(Asset).where(Asset.id == asset_id))
    if asset is None:
        return error_response(
            "ASSET_NOT_FOUND", f"No asset with id {asset_id}.", status.HTTP_404_NOT_FOUND
        )
    count_query = select(func.count(Vulnerability.id)).where(Vulnerability.asset_id == asset_id)
    total = db.scalar(count_query) or 0
    rows = db.scalars(
        select(Vulnerability)
        .where(Vulnerability.asset_id == asset_id)
        .order_by(desc(Vulnerability.severity), Vulnerability.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return {
        "items": [_vuln_response(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.post(
    "/vulnerabilities/{vulnerability_id}/status",
    response_model=VulnerabilityResponse,
    summary="Change finding status",
)
def change_vuln_status(
    payload: VulnStatusUpdate,
    vulnerability_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("MANAGE_VULNERABILITIES")),
):
    row = _finding_or_404(db, vulnerability_id)
    if row is None:
        return error_response(
            "VULNERABILITY_NOT_FOUND",
            f"No vulnerability with id {vulnerability_id}.",
            status.HTTP_404_NOT_FOUND,
        )
    try:
        updated = vulnerability_service.change_vuln_status(db, row, payload.status, payload.actor)
    except vulnerability_service.VulnStateError as exc:
        return error_response("INVALID_TRANSITION", str(exc), status.HTTP_409_CONFLICT)
    return _vuln_response(updated)


@router.get(
    "/vulnerabilities/{vulnerability_id}/risk",
    response_model=RiskAssessmentResponse,
    summary="Risk assessment for one finding",
)
def get_vulnerability_risk(
    vulnerability_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_VULNERABILITIES")),
):
    row = _finding_or_404(db, vulnerability_id)
    if row is None:
        return error_response(
            "VULNERABILITY_NOT_FOUND",
            f"No vulnerability with id {vulnerability_id}.",
            status.HTTP_404_NOT_FOUND,
        )
    assessment = db.scalar(
        select(RiskAssessment).where(
            RiskAssessment.entity_type == ENTITY_VULN_FINDING,
            RiskAssessment.entity_id == vulnerability_id,
        )
    )
    if assessment is None:
        return error_response(
            "RISK_NOT_FOUND",
            f"No risk assessment for vulnerability {vulnerability_id}; run risk recompute first.",
            status.HTTP_404_NOT_FOUND,
        )
    return _risk_response(assessment)


def _risk_response(assessment: RiskAssessment) -> dict:
    try:
        factors = json.loads(assessment.factors or "{}")
        factors = factors if isinstance(factors, dict) else {}
    except (ValueError, TypeError):
        factors = {}
    return {
        "id": assessment.id,
        "entity_type": assessment.entity_type,
        "entity_id": assessment.entity_id,
        "score": assessment.score,
        "severity": assessment.severity,
        "factors": factors,
        "explanation": assessment.explanation,
        "calculated_at": assessment.calculated_at,
        "scoring_version": assessment.scoring_version,
    }


@router.get(
    "/vulnerabilities/{vulnerability_id}/correlations",
    response_model=FindingCorrelations,
    summary="Records linked to one finding",
)
def get_vulnerability_correlations(
    vulnerability_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_VULNERABILITIES")),
):
    row = _finding_or_404(db, vulnerability_id)
    if row is None:
        return error_response(
            "VULNERABILITY_NOT_FOUND",
            f"No vulnerability with id {vulnerability_id}.",
            status.HTTP_404_NOT_FOUND,
        )
    links = vuln_correlation.describe_links(db, row)
    events = vuln_correlation.related_events(db, row)
    incidents = vuln_correlation.related_incidents(db, row)
    return {
        "vulnerability_id": row.id,
        "asset_id": row.asset_id,
        "service_id": row.service_id,
        "related_events": [LinkedEvent.model_validate(event) for event in events],
        "related_incidents": [LinkedIncident.model_validate(incident) for incident in incidents],
        "reasons": links["reasons"],
    }
