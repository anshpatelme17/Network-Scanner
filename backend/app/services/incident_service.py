"""Incident service (Step 11, recording and management only).

Flow::

    POST /incidents {correlation_id, risk_assessment_id?}
      -> validate the referenced rows exist (404 otherwise; nothing is
         manufactured)
      -> deterministic identity -> return existing (200) or create (201)

Severity: the linked risk assessment's severity when a risk reference
is supplied, otherwise the correlation's severity (documented fallback).
Confidence: the correlation's confidence. first_seen/last_seen: the
correlation's window. The linked asset (by correlation primary_ip) is
referenced when it exists.

Status lifecycle (explicit transitions only, no automation)::

    OPEN -> ACKNOWLEDGED, CLOSED
    ACKNOWLEDGED -> INVESTIGATING, CLOSED
    INVESTIGATING -> RESOLVED, CLOSED
    RESOLVED -> CLOSED
    CLOSED -> (terminal)

Identity: ``sha256("incident:v1" | correlation_id |
risk_assessment_id or "")`` — no timestamps, no randomness. Re-creating
the same logical incident returns the existing row unchanged.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.assets import Asset
from app.models.correlations import Correlation, CorrelationEvidence
from app.models.incidents import Incident, IncidentAudit, IncidentEvidence
from app.models.risk import RiskAssessment

logger = get_logger(__name__)


def _utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


INCIDENT_VERSION = "1.0.0"
IDENTITY_NAMESPACE = "incident:v1"

# Controlled incident-type vocabulary (Step 17). Classification only:
# a type never claims a host is compromised. Values with no producing
# rule yet are reserved and documented in incident_detection.
TYPE_VULNERABILITY_ACTIVITY = "VULNERABILITY_ACTIVITY"
TYPE_SUSPICIOUS_NETWORK_ACTIVITY = "SUSPICIOUS_NETWORK_ACTIVITY"
TYPE_AUTHENTICATION_ANOMALY = "AUTHENTICATION_ANOMALY"
TYPE_MALWARE_INDICATOR = "MALWARE_INDICATOR"
TYPE_POLICY_VIOLATION = "POLICY_VIOLATION"
TYPE_CORRELATED_SECURITY_EVENT = "CORRELATED_SECURITY_EVENT"
TYPE_OTHER = "OTHER"
INCIDENT_TYPES = (
    TYPE_VULNERABILITY_ACTIVITY,
    TYPE_SUSPICIOUS_NETWORK_ACTIVITY,
    TYPE_AUTHENTICATION_ANOMALY,
    TYPE_MALWARE_INDICATOR,
    TYPE_POLICY_VIOLATION,
    TYPE_CORRELATED_SECURITY_EVENT,
    TYPE_OTHER,
)

# Controlled audit actions (Step 17, append-only).
AUDIT_OPENED = "OPENED"
AUDIT_EVIDENCE_ATTACHED = "EVIDENCE_ATTACHED"
AUDIT_STATUS_CHANGED = "STATUS_CHANGED"
AUDIT_UPDATED = "UPDATED"

# Evidence kinds (Step 17, reference links only, never payload copies).
EVIDENCE_CORRELATION = "correlation"
EVIDENCE_EVENT = "event"
EVIDENCE_VULNERABILITY = "vulnerability"
EVIDENCE_KINDS = (EVIDENCE_CORRELATION, EVIDENCE_EVENT, EVIDENCE_VULNERABILITY)

STATUS_OPEN = "OPEN"
STATUS_ACKNOWLEDGED = "ACKNOWLEDGED"
STATUS_INVESTIGATING = "INVESTIGATING"
STATUS_RESOLVED = "RESOLVED"
STATUS_CLOSED = "CLOSED"
STATUSES = (STATUS_OPEN, STATUS_ACKNOWLEDGED, STATUS_INVESTIGATING, STATUS_RESOLVED, STATUS_CLOSED)

# Explicit transitions only. CLOSED is terminal.
TRANSITIONS: dict[str, tuple[str, ...]] = {
    STATUS_OPEN: (STATUS_ACKNOWLEDGED, STATUS_CLOSED),
    STATUS_ACKNOWLEDGED: (STATUS_INVESTIGATING, STATUS_CLOSED),
    STATUS_INVESTIGATING: (STATUS_RESOLVED, STATUS_CLOSED),
    STATUS_RESOLVED: (STATUS_CLOSED,),
    STATUS_CLOSED: (),
}


class IncidentNotFoundError(LookupError):
    """A referenced correlation or risk assessment does not exist."""


class InvalidStatusTransitionError(ValueError):
    """The requested status change is not an allowed transition."""


def incident_id(correlation_id: str, risk_assessment_id: str | None) -> str:
    """Deterministic identity. No time, no randomness."""
    canonical = json.dumps(
        [IDENTITY_NAMESPACE, correlation_id, risk_assessment_id or ""], separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def incident_key_for(assessment_id: str) -> str:
    return "INC-" + assessment_id[:12].upper()


def record_audit(
    db: Session, incident_id: str, action: str, actor: str, detail: str | None = None
) -> IncidentAudit:
    """Append one audit row (Step 17). Rows are append-only, never edited.

    Step 31: the originating request's correlation id is recorded so an
    incident lifecycle change can be tied to the HTTP request and its
    server-side log line. The signature is unchanged, so every existing
    caller keeps working.
    """
    from app.core.request_context import current_request_id_or_new

    row = IncidentAudit(
        incident_id=incident_id,
        action=action,
        actor=(actor or "system")[:128],
        detail=detail,
        request_id=current_request_id_or_new() or None,
    )
    db.add(row)
    return row


def attach_evidence(
    db: Session,
    incident_id: str,
    kind: str,
    evidence_id: str,
    reason: str | None = None,
) -> bool:
    """Attach one evidence reference (Step 17). Idempotent: existing links
    are returned unchanged (False); only genuinely new links (True) should
    produce audit rows, so callers can distinguish."""
    if kind not in EVIDENCE_KINDS:
        raise ValueError(f"Unknown evidence kind: {kind!r}.")
    existing = db.scalar(
        select(IncidentEvidence).where(
            IncidentEvidence.incident_id == incident_id,
            IncidentEvidence.evidence_kind == kind,
            IncidentEvidence.evidence_id == evidence_id,
        )
    )
    if existing is not None:
        return False
    db.add(
        IncidentEvidence(
            incident_id=incident_id, evidence_kind=kind, evidence_id=evidence_id, reason=reason
        )
    )
    return True


def create_incident(
    db: Session,
    correlation_id: str,
    risk_assessment_id: str | None = None,
    *,
    incident_type: str = TYPE_OTHER,
    detection_reason: str | None = None,
    actor: str = "system",
) -> tuple[Incident, bool]:
    """Create or return the incident for a correlation (+ optional risk row)."""
    if incident_type not in INCIDENT_TYPES:
        raise ValueError(f"Unknown incident type: {incident_type!r}.")
    correlation = db.scalar(select(Correlation).where(Correlation.id == correlation_id))
    if correlation is None:
        raise IncidentNotFoundError(f"No correlation with id {correlation_id}.")
    risk = None
    if risk_assessment_id is not None:
        risk = db.scalar(select(RiskAssessment).where(RiskAssessment.id == risk_assessment_id))
        if risk is None:
            raise IncidentNotFoundError(f"No risk assessment with id {risk_assessment_id}.")

    row_id = incident_id(correlation_id, risk_assessment_id)
    existing = db.scalar(select(Incident).where(Incident.id == row_id))
    if existing is not None:
        return existing, False

    asset_id: str | None = None
    if correlation.primary_ip:
        asset = db.scalar(select(Asset).where(Asset.ip_address == correlation.primary_ip))
        asset_id = asset.id if asset is not None else None

    severity = risk.severity if risk is not None else correlation.severity
    row = Incident(
        id=row_id,
        incident_key=incident_key_for(row_id),
        title=f"Incident: {correlation.title}",
        description=(
            "Security incident opened for review from correlated activity. "
            "Related records are not proof of compromise. "
            f"Source correlation {correlation.id} ({correlation.rule_name}); "
            + (
                f"risk assessment {risk.id} (score {risk.score})."
                if risk is not None
                else "no risk assessment linked."
            )
        ),
        status=STATUS_OPEN,
        severity=severity,
        confidence=correlation.confidence,
        primary_asset_id=asset_id,
        primary_ip=correlation.primary_ip,
        hostname=correlation.hostname,
        correlation_id=correlation.id,
        risk_assessment_id=risk.id if risk is not None else None,
        first_seen=correlation.window_start,
        last_seen=correlation.window_end,
        version=INCIDENT_VERSION,
        incident_type=incident_type,
        risk_score=risk.score if risk is not None else None,
        detection_reason=detection_reason,
    )
    db.add(row)
    db.flush()
    record_audit(
        db,
        row.id,
        AUDIT_OPENED,
        actor,
        f"Opened from correlation {correlation.id} ({correlation.rule_name}).",
    )
    db.commit()
    db.refresh(row)
    logger.info("Incident %s opened from correlation %s", row.incident_key, correlation.id)
    return row, True


def set_status(db: Session, incident: Incident, new_status: str, actor: str = "system") -> Incident:
    """Apply an explicit status transition (validated, never automated)."""
    if new_status not in STATUSES:
        raise InvalidStatusTransitionError(f"Unknown status: {new_status!r}.")
    allowed = TRANSITIONS.get(incident.status, ())
    if new_status not in allowed:
        raise InvalidStatusTransitionError(
            f"Cannot move incident from {incident.status} to {new_status}."
        )
    old_status = incident.status
    incident.status = new_status
    if new_status in (STATUS_RESOLVED, STATUS_CLOSED) and incident.resolved_at is None:
        incident.resolved_at = _utcnow_naive()
    record_audit(
        db,
        incident.id,
        AUDIT_STATUS_CHANGED,
        actor,
        f"Status changed from {old_status} to {new_status}.",
    )
    db.commit()
    db.refresh(incident)
    return incident


def evidence_event_ids(db: Session, correlation_id: str) -> list[str]:
    """Ordered original event IDs backing an incident's correlation."""
    links = db.scalars(
        select(CorrelationEvidence)
        .where(CorrelationEvidence.correlation_id == correlation_id)
        .order_by(CorrelationEvidence.position)
    ).all()
    return [link.event_id for link in links]


__all__ = [
    "AUDIT_EVIDENCE_ATTACHED",
    "AUDIT_OPENED",
    "AUDIT_STATUS_CHANGED",
    "AUDIT_UPDATED",
    "EVIDENCE_CORRELATION",
    "EVIDENCE_EVENT",
    "EVIDENCE_KINDS",
    "EVIDENCE_VULNERABILITY",
    "INCIDENT_TYPES",
    "INCIDENT_VERSION",
    "STATUSES",
    "TRANSITIONS",
    "TYPE_AUTHENTICATION_ANOMALY",
    "TYPE_CORRELATED_SECURITY_EVENT",
    "TYPE_MALWARE_INDICATOR",
    "TYPE_OTHER",
    "TYPE_POLICY_VIOLATION",
    "TYPE_SUSPICIOUS_NETWORK_ACTIVITY",
    "TYPE_VULNERABILITY_ACTIVITY",
    "IncidentNotFoundError",
    "InvalidStatusTransitionError",
    "attach_evidence",
    "create_incident",
    "evidence_event_ids",
    "incident_id",
    "incident_key_for",
    "record_audit",
    "set_status",
]
