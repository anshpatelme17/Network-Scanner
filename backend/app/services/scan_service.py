"""Scan-job orchestration (Step 2, hardened in Step 14).

Flow per job::

    POST /network/scans
      -> validate target format + profile + authorization scope
      -> persist ScanJob (queued) + SCAN_REQUESTED audit
      -> schedule background execution -> return 202 (never blocks on Nmap)

    background: re-check state (skip if cancelled) -> running +
      SCAN_STARTED -> Nmap -> parse XML -> upsert inventory
      -> completed (counts + summary) | failed (safe message) + audit

Cancellation is best-effort and honest: only QUEUED jobs (not yet picked
up by the worker) can be cancelled; running scans cannot be stopped and
report 409. No schedulers, no queues, no auto-start — BackgroundTasks
only, same as Step 2.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import BackgroundTasks
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.database import session as session_module
from app.models.scans import SCAN_TYPE_NMAP, ScanAudit, ScanEvent, ScanJob, ScanStatus
from app.services import inventory as inventory_service
from app.services import nmap_runner
from app.services import target_validation as target_validation_module
from app.services.nmap_parser import NmapParseError, parse_nmap_xml
from app.services.target_validation import (
    InvalidTargetError,
    parse_allowed_networks,
)

logger = get_logger(__name__)

DEFAULT_REQUESTED_BY = "operator"
DISCOVERY_SOURCE_NMAP = "nmap"


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _audit(db: Session, job_id: str, event: str, actor: str, detail: str | None = None) -> None:
    db.add(ScanAudit(scan_id=job_id, event=event, actor=actor, detail=detail))


def _allowed_networks() -> list:
    return parse_allowed_networks(get_settings().scan_allowed_networks)


def validate_target(raw: object) -> str:
    """Validate + normalize a target under the configured max scope (Step 21)."""
    return target_validation_module.validate_target(raw)


def authorize_target(normalized_target: str) -> str:
    """Require a validated target inside SCAN_ALLOWED_NETWORKS (Step 21)."""
    return target_validation_module.authorize_target(normalized_target, _allowed_networks())


def address_count(normalized_target: str) -> int:
    """Number of addresses a validated target covers (Step 21, preview only)."""
    import ipaddress as _ipaddress

    try:
        _ipaddress.ip_address(normalized_target)
        return 1
    except ValueError:
        return _ipaddress.ip_network(normalized_target, strict=True).num_addresses


class ScanStateError(ValueError):
    """The job is in a state that forbids the requested operation."""


def create_scan(
    db: Session,
    background: BackgroundTasks,
    target: object,
    profile: str,
    requested_by: object = DEFAULT_REQUESTED_BY,
) -> ScanJob:
    """Validate, authorize, persist (queued) and schedule a scan."""
    normalized_target = validate_target(target)  # InvalidTargetError -> 422
    if profile not in nmap_runner.SCAN_PROFILES:
        raise InvalidTargetError(f"Unknown scan profile: {profile!r}.")  # 422, no flags accepted
    authorize_target(normalized_target)  # TargetNotAuthorizedError -> 403
    if not nmap_runner.is_available():
        raise nmap_runner.NmapUnavailableError("Nmap is not available on this host.")  # -> 503
    actor = (
        requested_by.strip()
        if isinstance(requested_by, str) and requested_by.strip()
        else DEFAULT_REQUESTED_BY
    )
    job = ScanJob(
        target=normalized_target,
        profile=profile,
        scan_type=SCAN_TYPE_NMAP,
        requested_by=actor[:128],
        status=ScanStatus.QUEUED,
    )
    db.add(job)
    db.flush()
    _audit(
        db,
        job.id,
        ScanEvent.REQUESTED,
        job.requested_by,
        f"target={normalized_target} profile={profile}",
    )
    db.commit()
    db.refresh(job)
    background.add_task(execute_scan, job.id, normalized_target, profile)
    return job


def cancel_scan(db: Session, job_id: str, actor: str = DEFAULT_REQUESTED_BY) -> ScanJob:
    """Cancel a QUEUED job. Anything already running/finished reports 409."""
    job = db.scalar(select(ScanJob).where(ScanJob.id == job_id))
    if job is None:
        raise LookupError(f"No scan job with id {job_id}.")
    if job.status != ScanStatus.QUEUED:
        raise ScanStateError(f"Scan job is {job.status}; only queued scans can be cancelled.")
    job.status = ScanStatus.CANCELLED
    job.completed_at = _utcnow()
    _audit(db, job.id, ScanEvent.CANCELLED, actor, None)
    db.commit()
    db.refresh(job)
    return job


def execute_scan(job_id: str, target: str, profile: str) -> None:
    """Background worker: run Nmap, parse, upsert, finalize the job row."""
    db: Session = session_module.get_session_factory()()
    try:
        job = db.scalar(select(ScanJob).where(ScanJob.id == job_id))
        if job is None:  # job deleted mid-flight; nothing to update
            logger.warning("Scan job %s disappeared before execution", job_id)
            return
        if job.status == ScanStatus.CANCELLED:
            # Cancelled while queued: never start Nmap, record the skip.
            _audit(
                db, job.id, ScanEvent.CANCELLED, job.requested_by, "cancelled before worker start"
            )
            db.commit()
            return
        job.status = ScanStatus.RUNNING
        job.started_at = _utcnow()
        job.error = None
        _audit(db, job.id, ScanEvent.STARTED, job.requested_by, f"profile={profile}")
        db.commit()

        try:
            xml_output, nmap_version = nmap_runner.run_scan(profile, target)
            hosts = parse_nmap_xml(xml_output)
            profile_def = nmap_runner.SCAN_PROFILES[profile]
            assets_found, services_found = inventory_service.upsert_scan_results(
                db,
                hosts,
                source=DISCOVERY_SOURCE_NMAP,
                scan_id=job.id,
                replace_services=profile_def.probes_ports,
            )
        except (nmap_runner.NmapScanError, NmapParseError, InvalidTargetError) as exc:
            job.status = ScanStatus.FAILED
            job.error = str(exc)[:500]
            job.completed_at = _utcnow()
            _audit(db, job.id, ScanEvent.FAILED, job.requested_by, job.error)
            db.commit()
            logger.warning("Scan job %s failed: %s", job_id, job.error)
            return

        # Re-fetch: upsert_scan_results committed in the same session.
        job.nmap_version = nmap_version
        job.assets_found = assets_found
        job.services_found = services_found
        job.result_summary = f"{assets_found} hosts, {services_found} ports"
        job.status = ScanStatus.COMPLETED
        job.completed_at = _utcnow()
        _audit(db, job.id, ScanEvent.COMPLETED, job.requested_by, job.result_summary)
        db.commit()
        logger.info(
            "Scan job %s completed: %d assets, %d services",
            job_id,
            assets_found,
            services_found,
        )
    except Exception:  # noqa: BLE001 - job row must never be left stuck in running
        logger.exception("Scan job %s crashed", job_id)
        try:
            job = db.scalar(select(ScanJob).where(ScanJob.id == job_id))
            if job is not None and job.status == ScanStatus.RUNNING:
                job.status = ScanStatus.FAILED
                job.error = "Unexpected internal error during scan."
                job.completed_at = _utcnow()
                _audit(db, job.id, ScanEvent.FAILED, job.requested_by, job.error)
                db.commit()
        except Exception:  # noqa: BLE001
            logger.exception("Could not mark scan job %s as failed", job_id)
    finally:
        db.close()
