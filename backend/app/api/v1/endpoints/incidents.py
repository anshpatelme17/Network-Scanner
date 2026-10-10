"""Incident endpoints (Steps 11 + 17 + 18 + 24 + 29).

Incidents are opened explicitly from existing correlations (plus an
optional existing risk assessment) or via the conservative Step 17
detector over stored data, and move through an explicit status
lifecycle. Evidence, timeline and audit endpoints expose the traceable
record behind each incident. Step 18 adds incident-scoped controlled
response proposals (safe foundation actions only); status changes and
responses record operator workflow — there is no autonomous response,
remediation, or blocking anywhere here.

Step 29 adds investigation intelligence over the same stored records:
``GET /{id}/relationships`` reads deterministic rule-produced links and
``POST /{id}/recalculate`` runs the bounded, parameter-free analysis
that produces them (rules are server-side only; no body parameters are
accepted). Evidence and timeline gains are additive views over the
existing references — no new data, no fabrication.
"""

import json

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from app.api.v1.auth_deps import actor_for, require_permission
from app.api.v1.endpoints.responses import _to_response as _response_to_dict
from app.api.v1.limits import rate_limit
from app.core.config import get_settings
from app.core.errors import error_response
from app.database.session import get_db
from app.models.assets import Asset
from app.models.correlations import Correlation, CorrelationEvidence
from app.models.events import SecurityEvent
from app.models.incidents import Incident, IncidentAudit, IncidentEvidence, IncidentRelationship
from app.models.responses import ResponseAction
from app.models.vulnerabilities import Vulnerability
from app.schemas.incidents import (
    IncidentAuditResponse,
    IncidentCreate,
    IncidentDetailResponse,
    IncidentDetectRequest,
    IncidentDetectResponse,
    IncidentEvidenceResponse,
    IncidentObservationsResponse,
    IncidentPage,
    IncidentRecalculateResponse,
    IncidentRelationshipsPage,
    IncidentResponse,
    IncidentStatusUpdate,
    IncidentTimelineResponse,
    IncidentUpdate,
    IntelligenceResponse,
)
from app.schemas.response_governance import ResponseRecommendationsResponse
from app.schemas.responses import (
    IncidentResponseProposalRequest,
    ResponseActionResponse,
    ResponsePage,
)
from app.services import (
    incident_analysis,
    incident_detection,
    incident_intelligence,
    incident_service,
    response_governance,
    response_service,
)
from app.services.auth_service import AuthContext
from app.services.incident_rules import ANALYSIS_RULES, confidence_label
from app.services.incident_service import (
    AUDIT_UPDATED,
    INCIDENT_TYPES,
    STATUSES,
    IncidentNotFoundError,
    InvalidStatusTransitionError,
)
from app.services.response_service import TARGET_INCIDENT
from app.services.response_service import InvalidResponseError as ResponseInvalidError
from app.services.response_service import is_safe_action as _is_safe_response_action

router = APIRouter(prefix="/incidents", tags=["incidents"])

MAX_LIMIT = 200
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

TIMELINE_KINDS = {
    "OPENED": "opened",
    "STATUS_CHANGED": "status",
    "EVIDENCE_ATTACHED": "evidence",
    "UPDATED": "update",
}


def _to_response(row: Incident) -> dict:
    return {
        "id": row.id,
        "incident_key": row.incident_key,
        "title": row.title,
        "description": row.description,
        "status": row.status,
        "severity": row.severity,
        "confidence": row.confidence,
        "primary_asset_id": row.primary_asset_id,
        "primary_ip": row.primary_ip,
        "hostname": row.hostname,
        "correlation_id": row.correlation_id,
        "risk_assessment_id": row.risk_assessment_id,
        "first_seen": row.first_seen,
        "last_seen": row.last_seen,
        "resolved_at": row.resolved_at,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "version": row.version,
        "incident_type": row.incident_type,
        "risk_score": row.risk_score,
        "detection_reason": row.detection_reason,
    }


def _get_or_404(db: Session, incident_id: str):
    row = db.scalar(select(Incident).where(Incident.id == incident_id))
    if row is None:
        return None
    return row


@router.post(
    "",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Open incident",
)
def open_incident(
    payload: IncidentCreate,
    response: Response,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("CREATE_INCIDENT")),
):
    try:
        row, created = incident_service.create_incident(
            db,
            payload.correlation_id,
            payload.risk_assessment_id,
            actor=actor_for(auth, "system"),
        )
    except IncidentNotFoundError as exc:
        return error_response("REFERENCE_NOT_FOUND", str(exc), status.HTTP_404_NOT_FOUND)
    if not created:
        response.status_code = status.HTTP_200_OK
    return _to_response(row)


@router.get("", response_model=IncidentPage, summary="List incidents")
def list_incidents(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_INCIDENTS")),
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
    incident_type: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
):
    if status_filter is not None and status_filter not in STATUSES:
        return error_response(
            "INVALID_FILTER",
            f"Unknown status filter: {status_filter!r}.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    if severity is not None and severity not in SEVERITIES:
        return error_response(
            "INVALID_FILTER",
            f"Unknown severity filter: {severity!r}.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    if incident_type is not None and incident_type not in INCIDENT_TYPES:
        return error_response(
            "INVALID_FILTER",
            f"Unknown incident type filter: {incident_type!r}.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    query = select(Incident)
    count_query = select(func.count(Incident.id))
    if status_filter is not None:
        query = query.where(Incident.status == status_filter)
        count_query = count_query.where(Incident.status == status_filter)
    if severity is not None:
        query = query.where(Incident.severity == severity)
        count_query = count_query.where(Incident.severity == severity)
    if incident_type is not None:
        query = query.where(Incident.incident_type == incident_type)
        count_query = count_query.where(Incident.incident_type == incident_type)
    total = db.scalar(count_query) or 0
    rows = db.scalars(
        query.order_by(desc(Incident.created_at), Incident.id).limit(limit).offset(offset)
    ).all()
    return {
        "items": [_to_response(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{incident_id}", response_model=IncidentDetailResponse, summary="Incident detail")
def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_INCIDENTS")),
):
    row = _get_or_404(db, incident_id)
    if row is None:
        return error_response(
            "INCIDENT_NOT_FOUND", f"No incident with id {incident_id}.", status.HTTP_404_NOT_FOUND
        )
    detail = _to_response(row)
    detail["evidence_event_ids"] = incident_service.evidence_event_ids(db, row.correlation_id)
    return detail


@router.get(
    "/{incident_id}/intelligence",
    response_model=IntelligenceResponse,
    summary="Deterministic incident intelligence and priority refinement",
)
def get_incident_intelligence(
    incident_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_INCIDENTS")),
):
    """Read-only enrichment of an already-correlated incident (Step 8).

    Server-side and deterministic: context is re-derived from stored rows on
    every call and nothing is written, so a caller cannot steer the result
    and it cannot drift from the evidence. It never modifies the incident's
    risk score, severity or confidence, and never acts on a host.
    """
    row = _get_or_404(db, incident_id)
    if row is None:
        return error_response(
            "INCIDENT_NOT_FOUND", f"No incident with id {incident_id}.", status.HTTP_404_NOT_FOUND
        )
    return incident_intelligence.build_intelligence(db, row.id).as_dict()


@router.post(
    "/{incident_id}/intelligence/refresh",
    response_model=IntelligenceResponse,
    summary="Record an audited incident-intelligence refinement",
)
def refresh_incident_intelligence(
    incident_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("MANAGE_INCIDENT")),
    _limit: None = Depends(rate_limit("incident_intelligence", "rate_limit_recompute")),
):
    """Recompute the refinement and append an audit row.

    The calculation remains read-only with respect to incident state; the
    only durable effect is an ``INTELLIGENCE_REFRESHED`` audit row, so a
    reviewer can see which inputs produced which priority.
    """
    row = _get_or_404(db, incident_id)
    if row is None:
        return error_response(
            "INCIDENT_NOT_FOUND", f"No incident with id {incident_id}.", status.HTTP_404_NOT_FOUND
        )
    return incident_intelligence.refresh_intelligence(db, row.id, actor_for(auth, None))


def _apply_status(db: Session, row: Incident, new_status: str | None, actor: str | None):
    if new_status is None:
        return row
    try:
        return incident_service.set_status(db, row, new_status, actor or "operator")
    except InvalidStatusTransitionError as exc:
        return exc


@router.patch("/{incident_id}", response_model=IncidentResponse, summary="Update incident")
def update_incident(
    payload: IncidentUpdate,
    incident_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("MANAGE_INCIDENT")),
):
    row = _get_or_404(db, incident_id)
    if row is None:
        return error_response(
            "INCIDENT_NOT_FOUND", f"No incident with id {incident_id}.", status.HTTP_404_NOT_FOUND
        )
    if payload.status is not None:
        result = _apply_status(db, row, payload.status, actor_for(auth, payload.actor))
        if isinstance(result, InvalidStatusTransitionError):
            return error_response(
                "INVALID_TRANSITION", str(result), status.HTTP_422_UNPROCESSABLE_ENTITY
            )
        row = result
    if payload.title is not None:
        row.title = payload.title.strip()
    if payload.description is not None:
        row.description = payload.description.strip() or None
    if payload.title is not None or payload.description is not None:
        incident_service.record_audit(
            db, row.id, AUDIT_UPDATED, actor_for(auth, payload.actor), "Title/description edited."
        )
    db.commit()
    db.refresh(row)
    return _to_response(row)


@router.patch(
    "/{incident_id}/status", response_model=IncidentResponse, summary="Change incident status"
)
def change_status(
    payload: IncidentStatusUpdate,
    incident_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("MANAGE_INCIDENT")),
):
    row = _get_or_404(db, incident_id)
    if row is None:
        return error_response(
            "INCIDENT_NOT_FOUND", f"No incident with id {incident_id}.", status.HTTP_404_NOT_FOUND
        )
    result = _apply_status(db, row, payload.status, payload.actor)
    if isinstance(result, InvalidStatusTransitionError):
        return error_response(
            "INVALID_TRANSITION", str(result), status.HTTP_422_UNPROCESSABLE_ENTITY
        )
    return _to_response(result)


@router.post(
    "/{incident_id}/status", response_model=IncidentResponse, summary="Change incident status"
)
def change_status_post(
    payload: IncidentStatusUpdate,
    incident_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("MANAGE_INCIDENT")),
):
    """POST alias of the PATCH status endpoint (controlled transitions only)."""
    return change_status(payload, incident_id, db, auth)


def _evidence_links(db: Session, incident_id: str) -> list[IncidentEvidence]:
    return db.scalars(
        select(IncidentEvidence)
        .where(IncidentEvidence.incident_id == incident_id)
        .order_by(IncidentEvidence.evidence_kind, IncidentEvidence.evidence_id)
    ).all()


@router.get(
    "/{incident_id}/evidence",
    response_model=IncidentEvidenceResponse,
    summary="Incident evidence",
)
def get_evidence(
    incident_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_INCIDENTS")),
):
    """Evidence references for one incident (links only, never copies).

    Step 29 (additive): the same references additionally get a bounded
    overview — counts, primary event, source distribution, distinct
    entity values, existing assets, observed span and contributing
    rules. Lookups are batched (one ``IN`` per kind, never N+1) and the
    event list is capped by ``correlation_evidence_max`` (``truncated``
    reports it); everything derived is computed from the returned rows.
    """
    row = _get_or_404(db, incident_id)
    if row is None:
        return error_response(
            "INCIDENT_NOT_FOUND", f"No incident with id {incident_id}.", status.HTTP_404_NOT_FOUND
        )
    correlation = db.scalar(select(Correlation).where(Correlation.id == row.correlation_id))
    role_by_event = {
        link.event_id: link.role
        for link in db.scalars(
            select(CorrelationEvidence).where(
                CorrelationEvidence.correlation_id == row.correlation_id
            )
        ).all()
    }
    links = _evidence_links(db, row.id)
    event_links = [link for link in links if link.evidence_kind == incident_service.EVIDENCE_EVENT]
    vuln_links = [
        link for link in links if link.evidence_kind == incident_service.EVIDENCE_VULNERABILITY
    ]

    event_rows: dict[str, SecurityEvent] = {}
    if event_links:
        rows = db.scalars(
            select(SecurityEvent)
            .where(SecurityEvent.id.in_([link.evidence_id for link in event_links]))
            .order_by(SecurityEvent.event_time, SecurityEvent.id)
        ).all()
        event_rows = {stored.id: stored for stored in rows}
    vuln_rows: dict[str, Vulnerability] = {}
    if vuln_links:
        rows = db.scalars(
            select(Vulnerability).where(
                Vulnerability.id.in_([link.evidence_id for link in vuln_links])
            )
        ).all()
        vuln_rows = {stored.id: stored for stored in rows}

    events: list[dict] = []
    for link in event_links:  # preserves the (kind, id) link order
        event = event_rows.get(link.evidence_id)
        if event is None:
            continue  # event deleted after linking; cascade cleans the link
        events.append(
            {
                "id": event.id,
                "event_type": event.event_type,
                "severity": event.severity,
                "source_type": event.source_type,
                "title": event.title,
                "event_time": event.event_time,
                "role": role_by_event.get(event.id),
                "reason": link.reason,
            }
        )
    vulnerabilities: list[dict] = []
    for link in vuln_links:
        finding = vuln_rows.get(link.evidence_id)
        if finding is None:
            continue
        vulnerabilities.append(
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "status": finding.status,
                "cve_id": finding.cve_id,
                "reason": link.reason,
            }
        )

    settings = get_settings()
    evidence_count = len(events)
    truncated = evidence_count > settings.correlation_evidence_max
    shown = events[: settings.correlation_evidence_max]
    shown_rows = [event_rows[item["id"]] for item in shown if item["id"] in event_rows]

    primary_event: dict | None = None
    if shown:
        primary_event = min(
            shown,
            key=lambda item: (
                0 if item["role"] == "vulnerability" else 1,
                item["event_time"],
                item["id"],
            ),
        )

    source_distribution: dict[str, int] = {}
    for item in shown:
        source_distribution[item["source_type"]] = (
            source_distribution.get(item["source_type"], 0) + 1
        )

    addresses = sorted(
        {
            value
            for stored in shown_rows
            for value in (stored.source_ip, stored.destination_ip)
            if value
        }
    )
    hosts = sorted({stored.hostname for stored in shown_rows if stored.hostname})
    criteria = []
    if addresses:
        criteria.append(Asset.ip_address.in_(addresses))
    if hosts:
        criteria.append(Asset.hostname.in_(hosts))
    asset_rows = (
        db.scalars(select(Asset).where(or_(*criteria)).order_by(Asset.id)).all() if criteria else []
    )

    # Contributing rules: the incident's Step 24 correlation rule first,
    # then Step 29 rules with stored relationships (catalog order).
    rules: list[dict] = []
    if correlation is not None:
        rules.append(
            {
                "rule_id": correlation.rule_id,
                "rule_name": correlation.rule_name,
                "confidence": correlation.confidence,
                "confidence_label": confidence_label(correlation.confidence),
                "relationship_count": 0,
            }
        )
    seen_rule_ids = {rule["rule_id"] for rule in rules}
    counts = dict(
        db.execute(
            select(IncidentRelationship.rule_id, func.count(IncidentRelationship.id))
            .where(IncidentRelationship.incident_id == row.id)
            .group_by(IncidentRelationship.rule_id)
        ).all()
    )
    for rule_id in ANALYSIS_RULES:
        if rule_id in counts and rule_id not in seen_rule_ids:
            rule = ANALYSIS_RULES[rule_id]
            rules.append(
                {
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "confidence": rule.confidence,
                    "confidence_label": confidence_label(rule.confidence),
                    "relationship_count": int(counts[rule_id]),
                }
            )
            seen_rule_ids.add(rule_id)

    return {
        "incident_id": row.id,
        "incident_type": row.incident_type,
        "detection_reason": row.detection_reason,
        "correlation": (
            {
                "id": correlation.id,
                "rule_id": correlation.rule_id,
                "rule_name": correlation.rule_name,
                "severity": correlation.severity,
                "confidence": correlation.confidence,
                "explanation": correlation.explanation,
            }
            if correlation is not None
            else None
        ),
        "events": shown,
        "vulnerabilities": vulnerabilities,
        "evidence_count": evidence_count,
        "truncated": truncated,
        "primary_event": primary_event,
        "source_distribution": dict(sorted(source_distribution.items())),
        "entities": {
            "source_ips": sorted({stored.source_ip for stored in shown_rows if stored.source_ip}),
            "destination_ips": sorted(
                {stored.destination_ip for stored in shown_rows if stored.destination_ip}
            ),
            "hostnames": sorted({stored.hostname for stored in shown_rows if stored.hostname}),
            "usernames": sorted({stored.username for stored in shown_rows if stored.username}),
        },
        "assets": [
            {"id": asset.id, "ip_address": asset.ip_address, "hostname": asset.hostname}
            for asset in asset_rows
        ],
        "first_observed": min((stored.event_time for stored in shown_rows), default=None),
        "last_observed": max((stored.event_time for stored in shown_rows), default=None),
        "correlation_rules": rules,
    }


@router.get(
    "/{incident_id}/audit", response_model=IncidentAuditResponse, summary="Incident audit trail"
)
def get_audit(
    incident_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("VIEW_AUDIT")),
):
    row = _get_or_404(db, incident_id)
    if row is None:
        return error_response(
            "INCIDENT_NOT_FOUND", f"No incident with id {incident_id}.", status.HTTP_404_NOT_FOUND
        )
    audits = db.scalars(
        select(IncidentAudit)
        .where(IncidentAudit.incident_id == row.id)
        .order_by(IncidentAudit.created_at, IncidentAudit.id)
    ).all()
    return {
        "incident_id": row.id,
        "entries": [
            {
                "action": audit.action,
                "actor": audit.actor,
                "detail": audit.detail,
                "created_at": audit.created_at,
            }
            for audit in audits
        ],
    }


@router.get(
    "/{incident_id}/observations",
    response_model=IncidentObservationsResponse,
    summary="Incident observations",
)
def get_observations(
    incident_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_INCIDENTS")),
):
    """Traceable observation links in Step 24 vocabulary (Step 24).

    Reads the idempotent ``incident_evidence`` links (correlation /
    event / vulnerability references with reasons) without copying
    payloads, plus per-kind counts for the incident header.
    """
    row = _get_or_404(db, incident_id)
    if row is None:
        return error_response(
            "INCIDENT_NOT_FOUND", f"No incident with id {incident_id}.", status.HTTP_404_NOT_FOUND
        )
    links = _evidence_links(db, row.id)
    counts = {"correlation": 0, "event": 0, "vulnerability": 0}
    observations = []
    for link in links:
        if link.evidence_kind in counts:
            counts[link.evidence_kind] += 1
        observations.append(
            {
                "observation_type": link.evidence_kind,
                "observation_id": link.evidence_id,
                "reason": link.reason,
                "created_at": link.created_at,
            }
        )
    return {
        "incident_id": row.id,
        "event_count": counts["event"],
        "vulnerability_count": counts["vulnerability"],
        "correlation_count": counts["correlation"],
        "observations": observations,
    }


@router.get(
    "/{incident_id}/timeline",
    response_model=IncidentTimelineResponse,
    summary="Incident timeline",
)
def get_timeline(
    incident_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_INCIDENTS")),
):
    """Chronological incident record (Step 11/17, extended Step 29).

    Step 29 (additive): the correlation's stored evidence events now
    appear as ``kind == "event"`` entries between the first observation
    marker and the lifecycle audits — real rows only, batched and
    bounded by ``correlation_timeline_max_entries``. When the cap is hit
    the middle of the list keeps its most recent entries while the
    first observation and resolution markers always survive (``truncated``
    reports it). Sort order is unchanged.
    """
    row = _get_or_404(db, incident_id)
    if row is None:
        return error_response(
            "INCIDENT_NOT_FOUND", f"No incident with id {incident_id}.", status.HTTP_404_NOT_FOUND
        )
    entries: list[dict] = [
        {
            "at": row.first_seen,
            "kind": "observation",
            "label": "First observed activity",
            "detail": f"Correlation window opened at {row.first_seen}.",
        }
    ]
    max_entries = get_settings().correlation_timeline_max_entries
    event_ids = incident_service.evidence_event_ids(db, row.correlation_id)
    if event_ids:
        stored_events = db.scalars(
            select(SecurityEvent)
            .where(SecurityEvent.id.in_(event_ids[:max_entries]))
            .order_by(SecurityEvent.event_time, SecurityEvent.id)
        ).all()
        for event in stored_events:
            entries.append(
                {
                    "at": event.event_time,
                    "kind": "event",
                    "label": event.title or event.event_type,
                    "detail": f"{event.source_type}: {event.event_type} ({event.severity})",
                    "event_id": event.id,
                    "event_type": event.event_type,
                    "source": event.source_type,
                    "severity": event.severity,
                    "entity": event.destination_ip
                    or event.source_ip
                    or event.hostname
                    or event.username,
                    "explanation": (event.description or "")[:500] or None,
                }
            )
    audits = db.scalars(
        select(IncidentAudit)
        .where(IncidentAudit.incident_id == row.id)
        .order_by(IncidentAudit.created_at, IncidentAudit.id)
    ).all()
    for audit in audits:
        entries.append(
            {
                "at": audit.created_at,
                "kind": TIMELINE_KINDS.get(audit.action, "audit"),
                "label": audit.action.capitalize().replace("_", " "),
                "detail": f"{audit.actor}: {audit.detail}" if audit.detail else audit.actor,
            }
        )
    if row.last_seen != row.first_seen:
        entries.append(
            {
                "at": row.last_seen,
                "kind": "observation",
                "label": "Latest observed activity",
                "detail": f"Correlation window extends to {row.last_seen}.",
            }
        )
    if row.resolved_at is not None:
        entries.append(
            {
                "at": row.resolved_at,
                "kind": "resolution",
                "label": "Resolved",
                "detail": f"Incident entered {row.status} at {row.resolved_at}.",
            }
        )
    entries.sort(key=lambda entry: (entry["at"] is None, entry["at"]))
    truncated = False
    if len(entries) > max_entries:
        truncated = True
        head = entries[0]
        has_resolution = entries[-1]["kind"] == "resolution"
        tail = entries[-1] if has_resolution else None
        middle = entries[1:-1] if has_resolution else entries[1:]
        room = max_entries - (1 + (1 if has_resolution else 0))
        middle = middle[len(middle) - room :] if room > 0 else []
        entries = [head, *middle]
        if tail is not None:
            entries.append(tail)
    return {"incident_id": row.id, "entries": entries, "truncated": truncated}


@router.post("/detect", response_model=IncidentDetectResponse, summary="Run incident detection")
def run_detection(
    payload: IncidentDetectRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("MANAGE_INCIDENT")),
):
    """Conservative detection over stored data (Step 17, analysis only).

    With ``correlation_id``: evaluate one correlation (optionally with a
    stored risk linkage). Without: evaluate every correlation in stable
    order. Creates nothing for non-qualifying input; reprocessing the
    same evidence returns the same incidents (idempotent).
    """
    actor = actor_for(auth, payload.actor or incident_detection.DETECTOR_ACTOR)
    if payload.correlation_id is not None:
        prior_id = incident_service.incident_id(payload.correlation_id, payload.risk_assessment_id)
        prior = db.scalar(select(Incident).where(Incident.id == prior_id))
        prior_seen = prior.last_seen if prior is not None else None
        prior_evidence = (
            db.scalar(
                select(func.count(IncidentEvidence.id)).where(
                    IncidentEvidence.incident_id == prior_id
                )
            )
            or 0
        )
        try:
            incident, created, reason = incident_detection.detect_for_correlation(
                db, payload.correlation_id, payload.risk_assessment_id, actor
            )
        except IncidentNotFoundError as exc:
            return error_response("REFERENCE_NOT_FOUND", str(exc), status.HTTP_404_NOT_FOUND)
        current_evidence = (
            db.scalar(
                select(func.count(IncidentEvidence.id)).where(
                    IncidentEvidence.incident_id == prior_id
                )
            )
            or 0
        )
        changed = (
            incident is not None
            and not created
            and prior is not None
            and (incident.last_seen != prior_seen or current_evidence != prior_evidence)
        )
        return {
            "evaluated": 1,
            "created": 1 if created else 0,
            "updated": 1 if changed else 0,
            "skipped": 1 if incident is None else 0,
            "detector_version": incident_detection.DETECTION_VERSION,
            "outcomes": [
                {
                    "correlation_id": payload.correlation_id,
                    "incident_id": incident.id if incident is not None else None,
                    "created": created,
                    "reason": reason,
                }
            ],
        }
    if payload.risk_assessment_id is not None:
        return error_response(
            "INVALID_REQUEST",
            "Bulk detection uses the canonical no-risk identity; pass a correlation_id to link a risk assessment.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    return incident_detection.detect_all(db, actor)


@router.post(
    "/{incident_id}/responses",
    response_model=ResponseActionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Propose a safe response for an incident",
)
def propose_incident_response(
    payload: IncidentResponseProposalRequest,
    incident_id: str,
    response: Response,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("PROPOSE_RESPONSE")),
):
    """Propose a Step 18 safe foundation action for an incident.

    The target is always the incident record itself. Only safe action
    types are accepted here (422 otherwise); all other proposals belong
    on POST /api/v1/responses. Approval and execution follow the shared
    controlled lifecycle — nothing executes on proposal.
    """
    if _get_or_404(db, incident_id) is None:
        return error_response(
            "INCIDENT_NOT_FOUND",
            f"No incident with id {incident_id}.",
            status.HTTP_404_NOT_FOUND,
        )
    if not _is_safe_response_action(payload.action_type):
        return error_response(
            "INVALID_PROPOSAL",
            f"Only safe foundation actions may be proposed here: {payload.action_type!r}.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    try:
        row, created = response_service.propose_action(
            db,
            incident_id,
            payload.action_type,
            TARGET_INCIDENT,
            incident_id,
            payload.reason,
            payload.requested_by,
            payload.dry_run,
        )
    except ResponseInvalidError as exc:
        return error_response("INVALID_PROPOSAL", str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY)
    if not created:
        response.status_code = status.HTTP_200_OK
    return _response_to_dict(row)


@router.get(
    "/{incident_id}/responses",
    response_model=ResponsePage,
    summary="List an incident's responses",
)
def list_incident_responses(
    incident_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_RESPONSES")),
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
):
    if _get_or_404(db, incident_id) is None:
        return error_response(
            "INCIDENT_NOT_FOUND",
            f"No incident with id {incident_id}.",
            status.HTTP_404_NOT_FOUND,
        )
    if status_filter is not None and status_filter not in response_service.STATUSES:
        return error_response(
            "INVALID_FILTER",
            f"Unknown status filter: {status_filter!r}.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    query = select(ResponseAction).where(ResponseAction.incident_id == incident_id)
    count_query = select(func.count(ResponseAction.id)).where(
        ResponseAction.incident_id == incident_id
    )
    if status_filter is not None:
        query = query.where(ResponseAction.status == status_filter)
        count_query = count_query.where(ResponseAction.status == status_filter)
    total = db.scalar(count_query) or 0
    rows = db.scalars(
        query.order_by(desc(ResponseAction.created_at), ResponseAction.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return {
        "items": [_response_to_dict(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get(
    "/{incident_id}/response-recommendations",
    response_model=ResponseRecommendationsResponse,
    summary="Deterministic response recommendations for an incident",
)
def list_incident_response_recommendations(
    incident_id: str,
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_RESPONSES")),
):
    """Actions the stored evidence makes available, and why (Step 30).

    Purely deterministic and read-only: the items come from stored event
    fields, the platform inventory, the server-side action allow-list,
    and provider capability. Risk score and priority appear as context
    only — a high-risk incident never causes an action to be created,
    approved, or executed, and nothing here is ever automatic.
    """
    incident = _get_or_404(db, incident_id)
    if incident is None:
        return error_response(
            "INCIDENT_NOT_FOUND", f"No incident with id {incident_id}.", status.HTTP_404_NOT_FOUND
        )
    items = response_governance.recommendations(db, incident)
    window = items[offset : offset + limit]
    score, priority = response_governance._incident_risk(db, incident)
    return {
        "incident_id": incident.id,
        "incident_key": incident.incident_key,
        "severity": incident.severity,
        "risk_score": score,
        "risk_priority": priority,
        "items": window,
        "total": len(items),
        "truncated": len(items) > offset + len(window),
        "policy_version": response_governance.POLICY_VERSION,
        "governance_version": response_governance.GOVERNANCE_VERSION,
    }


@router.get(
    "/{incident_id}/relationships",
    response_model=IncidentRelationshipsPage,
    summary="Incident relationships",
)
def list_incident_relationships(
    incident_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_INCIDENTS")),
    rule_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
):
    """Stored Step 29 relationships for one incident (bounded reads).

    ``rule_id`` filters by one catalog rule; unknown ids are rejected
    with INVALID_FILTER, never silently ignored. Ordering is strongest
    confidence first with the unique relationship identity as tiebreak —
    a total order, so pagination never skips or repeats a row. Only
    stored rows are read; nothing is computed or inferred here.
    """
    row = _get_or_404(db, incident_id)
    if row is None:
        return error_response(
            "INCIDENT_NOT_FOUND", f"No incident with id {incident_id}.", status.HTTP_404_NOT_FOUND
        )
    if rule_id is not None and rule_id not in ANALYSIS_RULES:
        return error_response(
            "INVALID_FILTER",
            f"Unknown relationship rule filter: {rule_id!r}.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    rows, total = incident_analysis.list_relationships(db, row.id, rule_id, limit, offset)
    items: list[dict] = []
    for relationship in rows:
        try:
            decoded = json.loads(relationship.evidence_json)
        except ValueError:
            decoded = []
        evidence_event_ids = decoded if isinstance(decoded, list) else []
        items.append(
            {
                "id": relationship.id,
                "incident_id": relationship.incident_id,
                "rule_id": relationship.rule_id,
                "rule_name": relationship.rule_name,
                "relation": relationship.relation,
                "source_kind": relationship.source_kind,
                "source_id": relationship.source_id,
                "source_label": relationship.source_label,
                "target_kind": relationship.target_kind,
                "target_id": relationship.target_id,
                "target_label": relationship.target_label,
                "confidence": relationship.confidence,
                "confidence_label": relationship.confidence_label,
                "explanation": relationship.explanation,
                "evidence_event_ids": [str(event_id) for event_id in evidence_event_ids],
                "first_seen": relationship.first_seen,
                "last_seen": relationship.last_seen,
            }
        )
    return {
        "incident_id": row.id,
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.post(
    "/{incident_id}/recalculate",
    response_model=IncidentRecalculateResponse,
    summary="Recalculate incident relationships",
)
async def recalculate_incident_relationships(
    request: Request,
    incident_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("MANAGE_INCIDENT")),
    _limit: None = Depends(rate_limit("incident_recalculate", "rate_limit_recalculate")),
):
    """Bounded, parameter-free, deterministic analysis (Step 29).

    Any request body beyond an empty object is rejected: rule selection,
    expressions, thresholds and commands are never accepted from callers.
    The analysis reads only stored rows and reconciles deterministic
    relationship references — it creates no evidence, no entities and no
    actions, and never touches an external system. Incident risk scoring
    stays on the Step 25 ``POST /risk/incidents/{id}/calculate``.
    """
    if _get_or_404(db, incident_id) is None:
        return error_response(
            "INCIDENT_NOT_FOUND", f"No incident with id {incident_id}.", status.HTTP_404_NOT_FOUND
        )
    body = (await request.body()).strip()
    if body not in (b"", b"{}"):
        return error_response(
            "INVALID_REQUEST",
            "Recalculate accepts no body: rules are server-side only.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    try:
        return incident_analysis.analyze_incident(db, incident_id, actor_for(auth, None))
    except IncidentNotFoundError as exc:  # deleted mid-flight
        return error_response("INCIDENT_NOT_FOUND", str(exc), status.HTTP_404_NOT_FOUND)
