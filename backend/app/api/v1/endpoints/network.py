"""Network endpoints: Nmap capability + controlled scan jobs (Steps 2, 14 & 21).

Scan ONLY systems/networks you are authorized to assess. Targets are
strictly validated (IP/CIDR, configurable bounded size) AND must fall
inside the configured SCAN_ALLOWED_NETWORKS scope; Nmap flags are never
accepted from clients — only the profile name, mapped server-side to
fixed args. Step 21 adds discovery profiles (ping / TCP-common) and a
read-only preview endpoint.
"""

from fastapi import APIRouter, BackgroundTasks, Depends, Query, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.api.v1.auth_deps import require_permission
from app.api.v1.limits import rate_limit
from app.core.errors import error_response
from app.database.session import get_db
from app.models.scans import ScanAudit, ScanJob
from app.schemas.network import (
    NmapStatusResponse,
    ScanAuditEntry,
    ScanJobResponse,
    ScanPreviewResponse,
    ScanRequest,
)
from app.services import nmap_runner, scan_service
from app.services.auth_service import AuthContext
from app.services.scan_service import ScanStateError
from app.services.target_validation import InvalidTargetError, TargetNotAuthorizedError

router = APIRouter(prefix="/network", tags=["network"])


def _job_response(db: Session, job: ScanJob) -> dict:
    body = ScanJobResponse.model_validate(job).model_dump()
    audit = db.scalars(
        select(ScanAudit)
        .where(ScanAudit.scan_id == job.id)
        .order_by(ScanAudit.created_at, ScanAudit.id)
    ).all()
    body["audit"] = [ScanAuditEntry.model_validate(entry).model_dump() for entry in audit]
    return body


@router.get("/nmap/status", response_model=NmapStatusResponse, summary="Nmap capability")
def nmap_status(
    auth: AuthContext = Depends(require_permission("READ_ASSETS")),
):
    available = nmap_runner.is_available()
    return {
        "available": available,
        "version": nmap_runner.get_version() if available else None,
        "profiles": sorted(nmap_runner.SCAN_PROFILES),
    }


@router.post(
    "/scans",
    response_model=ScanJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request a controlled Nmap scan of an authorized target",
)
def create_scan(
    request: ScanRequest,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("MANAGE_SCANS")),
    _limit: None = Depends(rate_limit("scan_start", "rate_limit_scan_start")),
):
    """Queue a controlled scan of an authorized target.

    Budgeted by ``RATE_LIMIT_SCAN_START`` (Step 32): starting a scan is
    the most resource-expensive action this router offers. The limit is
    listed last so an unauthorized caller is refused before any budget is
    consumed.
    """
    try:
        job = scan_service.create_scan(
            db, background, request.target, request.scan_profile, request.requested_by
        )
    except InvalidTargetError as exc:
        return error_response("INVALID_TARGET", str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY)
    except TargetNotAuthorizedError as exc:
        return error_response("TARGET_NOT_AUTHORIZED", str(exc), status.HTTP_403_FORBIDDEN)
    except nmap_runner.NmapUnavailableError as exc:
        return error_response("NMAP_UNAVAILABLE", str(exc), status.HTTP_503_SERVICE_UNAVAILABLE)
    return _job_response(db, job)


@router.get("/scans", response_model=list[ScanJobResponse], summary="List recent scan jobs")
def list_scans(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_ASSETS")),
    limit: int = Query(default=20, ge=1, le=100),
):
    jobs = db.scalars(select(ScanJob).order_by(desc(ScanJob.created_at)).limit(limit)).all()
    return [_job_response(db, job) for job in jobs]


@router.get("/scans/{scan_id}", response_model=ScanJobResponse, summary="Scan job status")
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_ASSETS")),
):
    job = db.scalar(select(ScanJob).where(ScanJob.id == scan_id))
    if job is None:
        return error_response(
            "SCAN_NOT_FOUND", f"No scan job with id {scan_id}.", status.HTTP_404_NOT_FOUND
        )
    return _job_response(db, job)


@router.post(
    "/scans/preview",
    response_model=ScanPreviewResponse,
    summary="Preview a discovery without scanning",
)
def preview_scan(
    request: ScanRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("MANAGE_SCANS")),
):
    """Validate a discovery and describe what would happen (Step 21).

    Runs target validation, profile lookup, scope authorization, and
    availability checks, then returns the validated plan. Performs NO
    scan, creates NO assets, starts NO processes. The Nmap argument
    list is never exposed — only the profile behavior the server would
    use. Validation success never claims the target is safe.
    """
    try:
        normalized = scan_service.validate_target(request.target)
    except InvalidTargetError as exc:
        return error_response("INVALID_TARGET", str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY)
    try:
        profile = nmap_runner.SCAN_PROFILES[request.scan_profile]
    except KeyError:
        return error_response(
            "INVALID_TARGET",
            f"Unknown scan profile: {request.scan_profile!r}.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    try:
        scan_service.authorize_target(normalized)
    except TargetNotAuthorizedError as exc:
        return error_response("TARGET_NOT_AUTHORIZED", str(exc), status.HTTP_403_FORBIDDEN)
    return {
        "target": normalized,
        "profile": profile.name,
        "profile_description": profile.description,
        "probes_ports": profile.probes_ports,
        "address_count": scan_service.address_count(normalized),
        "scope_authorized": True,
        "nmap_available": nmap_runner.is_available(),
        "timeout_seconds": profile.timeout_seconds,
    }


@router.post(
    "/scans/{scan_id}/cancel", response_model=ScanJobResponse, summary="Cancel a queued scan"
)
def cancel_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("MANAGE_SCANS")),
):
    """Cancel best-effort: only QUEUED jobs (worker has not picked them up).

    Running scans cannot be stopped; completed/failed/cancelled jobs
    report 409. No schedulers or queues are involved.
    """
    try:
        job = scan_service.cancel_scan(db, scan_id)
    except LookupError:
        return error_response(
            "SCAN_NOT_FOUND", f"No scan job with id {scan_id}.", status.HTTP_404_NOT_FOUND
        )
    except ScanStateError as exc:
        return error_response("SCAN_NOT_CANCELLABLE", str(exc), status.HTTP_409_CONFLICT)
    return _job_response(db, job)
