"""SOC overview aggregation (Phase 2, Step 9).

A single **read-only** roll-up of stored security state for a dashboard. It
introduces no detection, scoring or correlation logic: every number is a SQL
``COUNT`` over rows the platform already stores, and every incident priority is
the existing :func:`app.services.risk_service.priority_for` band applied to the
score of the incident's **linked** risk assessment, never to a bare snapshot.

Design constraints honoured here:

* **Server-side only.** Nothing is accepted from the caller except a bounded
  ``limit``. Identity, roles, severity, priority and ordering are never
  client-supplied, and no security decision is taken from request data.
* **Bounded.** Every list is capped (``MAX_ITEMS``) and every count is a
  database aggregate, so no table is ever read in full. There is no N+1
  query: the incident list and the connector states are fetched once each.
* **No secrets.** The payload contains counts, identifiers, enums, scores and
  timestamps. Connector health reuses the Step 27 truth machine, which
  already refuses to expose configuration values.
* **Fail closed.** The route requires ``READ_INCIDENTS``; a caller without
  it receives 401/403 and no data.
* **Status, not action.** Response/workflow information is surfaced as
  recorded status only. Nothing here triggers, approves or executes anything.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.models.assets import Asset, DiscoveredService
from app.models.correlations import Correlation
from app.models.events import EventAudit, SecurityEvent
from app.models.incidents import Incident
from app.models.responses import ResponseAction
from app.models.risk import RiskAssessment
from app.models.vulnerabilities import Vulnerability
from app.services.connectors import describe_all
from app.services.risk_service import priority_for

# Hard ceiling on any list in this payload. The route may request fewer.
MAX_ITEMS = 50
DEFAULT_ITEMS = 10

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
OPEN_INCIDENT_STATUSES = ("OPEN", "IN_PROGRESS", "PENDING_APPROVAL")
OPEN_VULNERABILITY_STATUSES = ("open", "new", "in_progress", "detected", "confirmed")


def _count(db: Session, model, *conditions) -> int:
    """One aggregate query per count — never a full table read."""
    statement = select(func.count()).select_from(model)
    for condition in conditions:
        statement = statement.where(condition)
    return int(db.scalar(statement) or 0)


def _severity_buckets(db: Session) -> dict[str, int]:
    """Per-severity incident counts, in a fixed order, one grouped query."""
    rows = db.execute(
        select(Incident.severity, func.count(Incident.id))
        .where(Incident.severity.in_(SEVERITY_ORDER))
        .group_by(Incident.severity)
    ).all()
    found = {str(severity).upper(): int(count) for severity, count in rows}
    # Report every bucket, including zeros, so the UI never has to guess.
    return {name: found.get(name, 0) for name in SEVERITY_ORDER}


def _priority_buckets(db: Session) -> dict[str, int]:
    """Per-priority incident counts derived from the linked risk assessment.

    Priority is the existing :func:`app.services.risk_service.priority_for`
    band applied to the incident's **authoritative** assessment score (via
    ``Incident.risk_assessment_id``) — never to a bare stored snapshot, so
    a detached or evicted assessment can never masquerade as current risk.
    Incidents with no valid assessment fall into ``UNSCORED`` rather than
    being silently dropped or given an invented priority.
    """
    rows = db.execute(
        select(RiskAssessment.score)
        .select_from(Incident)
        .outerjoin(RiskAssessment, RiskAssessment.id == Incident.risk_assessment_id)
    ).scalars()
    counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0, "UNSCORED": 0}
    for score in rows:
        if score is None:
            counts["UNSCORED"] += 1
        else:
            counts[priority_for(int(score))] += 1
    return counts


def _top_incidents(db: Session, limit: int) -> list[dict[str, object]]:
    """Most recent open incidents, bounded, ordered deterministically.

    Risk columns come from the incident's linked assessment (authoritative),
    not the raw snapshot; an incident without a valid assessment reports
    ``null`` for both score and priority rather than an invented band.
    """
    rows = db.execute(
        select(Incident, RiskAssessment.score, RiskAssessment.priority)
        .outerjoin(RiskAssessment, RiskAssessment.id == Incident.risk_assessment_id)
        .where(Incident.status.in_(OPEN_INCIDENT_STATUSES))
        .order_by(desc(Incident.last_seen), Incident.id)
        .limit(limit)
    ).all()
    return [
        {
            "id": row.id,
            "incident_key": row.incident_key,
            "title": row.title,
            "status": row.status,
            "severity": row.severity,
            "confidence": int(row.confidence or 0),
            "risk_score": int(score) if score is not None else None,
            # Derived from the authoritative score by the existing band function.
            "priority": (
                (stored_priority or priority_for(int(score))) if score is not None else None
            ),
            "primary_asset_id": row.primary_asset_id,
            "primary_ip": row.primary_ip,
            "hostname": row.hostname,
            "correlation_id": row.correlation_id,
            "first_seen": row.first_seen.isoformat(),
            "last_seen": row.last_seen.isoformat(),
        }
        for row, score, stored_priority in rows
    ]


def _recent_audit(db: Session, limit: int) -> list[dict[str, object]]:
    """Most recent ingestion audit rows (append-only), bounded."""
    rows = db.scalars(
        select(EventAudit).order_by(desc(EventAudit.created_at), EventAudit.id).limit(limit)
    ).all()
    # detail is an operator-facing sentence produced by the platform; it is
    # truncated defensively and never contains a payload or credential.
    return [
        {
            "id": row.id,
            "action": row.action,
            "actor": row.actor,
            "event_id": row.event_id,
            "detail": (row.detail or "")[:200],
            "created_at": row.created_at.isoformat(),
        }
        for row in rows
    ]


def build_overview(db: Session, *, limit: int = DEFAULT_ITEMS) -> dict[str, object]:
    """Build the SOC overview payload. Pure read; writes nothing."""
    capped = max(1, min(int(limit), MAX_ITEMS))
    generated_at = datetime.now(UTC).replace(tzinfo=None)

    open_incidents = tuple(
        _count(db, Incident, Incident.status == status) for status in OPEN_INCIDENT_STATUSES
    )
    counts = {
        "assets_total": _count(db, Asset),
        "assets_active": _count(db, Asset, Asset.state == "up"),
        "services_total": _count(db, DiscoveredService),
        "events_total": _count(db, SecurityEvent),
        "correlations_total": _count(db, Correlation),
        "incidents_total": _count(db, Incident),
        "incidents_open": sum(open_incidents),
        "risk_assessments_total": _count(db, RiskAssessment),
        "vulnerabilities_open": _count(
            db,
            Vulnerability,
            func.lower(func.coalesce(Vulnerability.status, "open")).in_(
                OPEN_VULNERABILITY_STATUSES
            ),
        ),
        "response_actions_total": _count(db, ResponseAction),
        "response_actions_pending_approval": _count(
            db, ResponseAction, ResponseAction.status == "PENDING_APPROVAL"
        ),
    }

    return {
        "generated_at": generated_at.isoformat(),
        "version": "soc-overview:1.0.0",
        "counts": counts,
        "incidents_by_severity": _severity_buckets(db),
        "incidents_by_priority": _priority_buckets(db),
        "top_incidents": _top_incidents(db, capped),
        "recent_audit": _recent_audit(db, capped),
        # Reused verbatim from the Step 27 connector truth machine: it reports
        # configured/state only, never a configured value.
        "connectors": [
            {
                "source": item.source,
                "mode": item.mode,
                "state": item.state,
                "connector_state": item.connector_state,
                "last_check_at": item.last_check_at,
                "last_poll_at": item.last_poll_at,
                "last_error_category": item.last_error_category,
                "events_retrieved": item.events_retrieved,
            }
            for item in describe_all()
        ],
        "limits": {"max_items": MAX_ITEMS, "requested_items": capped},
        "disclaimer": (
            "Read-only roll-up of stored state. Related events are not proof of "
            "compromise, and nothing on this screen performs an action."
        ),
    }


__all__ = ["DEFAULT_ITEMS", "MAX_ITEMS", "build_overview"]
