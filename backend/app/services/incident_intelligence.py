"""Deterministic incident intelligence and priority refinement (Phase 2, Step 8).

Reads an **already-correlated** incident and produces a bounded, explainable
intelligence summary over data that is already stored. It is an enrichment
layer, not a second incident model and not a replacement for the Step 10/25
risk score:

* the incident's ``risk_score`` is left exactly as the linked Step 10
  assessment set it — this module never writes to it;
* the incident's ``severity`` and ``confidence`` are read, never invented;
* nothing here writes an incident, a correlation or an event, contacts a
  network, or acts on a host.

What it adds is a *consolidated context* and a *priority refinement* with
explicit factors, computed from:

- the correlation's evidence events (bounded, de-duplicated by event id);
- the affected assets those events resolve to (exact match only, so an
  unresolved asset simply contributes nothing and is reported as such);
- the open vulnerability findings recorded for those assets;
- the incident's own relationships (Step 29), severity, confidence and
  timestamps.

Every input is a stored row. A missing asset, an unresolved event, or an
absent finding produces **no** row and no invented value; the summary states
what was and was not resolved.

Determinism: the factors are a pure function of the stored rows, the input
ordering is total (event id), and nothing reads a clock except the explicit
``recency_days`` computed from the incident's stored ``last_seen`` against
the supplied ``now``. The same evidence always yields the same summary and
the same priority.

Bounds: every query is batched and capped by ``Settings`` limits
(``correlation_max_events_per_operation``, ``correlation_relationship_max``,
``correlation_relationship_evidence_max``). There is no N+1 lookup and no
unbounded history scan.

No AI/ML, no probabilistic or learned scoring, and no autonomous response.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.assets import Asset
from app.models.correlations import CorrelationEvidence
from app.models.events import SecurityEvent
from app.models.incidents import Incident, IncidentRelationship
from app.models.vulnerabilities import Vulnerability
from app.services.risk_service import severity_points

ANALYSIS_VERSION = "1.0.0"
MODULE_VERSION = "incident-intelligence:1.0.0"

# Severities that indicate a still-actionable exposure. A finding in a
# terminal state contributes context but no exposure points.
OPEN_STATUSES = ("open", "new", "in_progress", "detected", "confirmed")
MAX_VULNERABILITY_SEVERITIES = 5

# Priority refinement bands (minimum points, priority). Deliberately distinct
# from ``risk_service.PRIORITY_BANDS``: those map a 0-100 risk score, these
# map enrichment points so the two never get confused.
REFINEMENT_BANDS = ((40, "P1"), (25, "P2"), (12, "P3"), (0, "P4"))


@dataclass(frozen=True)
class Intelligence:
    """Immutable, fully explainable result for one incident."""

    incident_id: str
    correlation_id: str
    status: str
    severity: str
    confidence: int
    priority: str
    points: int
    factors: dict[str, object]
    explanation: str
    evidence: dict[str, object]
    assets: dict[str, object]
    vulnerabilities: dict[str, object]
    relationships: dict[str, object]
    timeline: dict[str, object]

    def as_dict(self) -> dict[str, object]:
        return {
            "analysis_version": ANALYSIS_VERSION,
            "module_version": MODULE_VERSION,
            "incident_id": self.incident_id,
            "correlation_id": self.correlation_id,
            "status": self.status,
            "severity": self.severity,
            "confidence": self.confidence,
            "priority": self.priority,
            "points": self.points,
            "factors": dict(self.factors),
            "explanation": self.explanation,
            "evidence": dict(self.evidence),
            "assets": dict(self.assets),
            "vulnerabilities": dict(self.vulnerabilities),
            "relationships": dict(self.relationships),
            "timeline": dict(self.timeline),
        }


def _naive_utc(moment: datetime) -> datetime:
    if moment.tzinfo is not None:
        return moment.astimezone(UTC).replace(tzinfo=None)
    return moment


def _priority_for_points(points: int) -> str:
    for minimum, priority in REFINEMENT_BANDS:
        if points >= minimum:
            return priority
    return "P4"  # unreachable: bands cover 0+


def _load_evidence_events(
    db: Session, correlation_id: str, limit: int
) -> tuple[list[SecurityEvent], int]:
    """Distinct evidence events for one correlation, ordered by id.

    ``DISTINCT`` plus the unique ``(correlation_id, event_id)`` constraint
    means the same event cannot be counted twice, so duplicate evidence can
    never inflate the refinement.
    """
    rows = db.execute(
        select(SecurityEvent)
        .join(CorrelationEvidence, CorrelationEvidence.event_id == SecurityEvent.id)
        .where(CorrelationEvidence.correlation_id == correlation_id)
        .distinct()
        .order_by(SecurityEvent.id)
        .limit(limit)
    ).scalars()
    events = list(rows)
    total = db.scalar(
        select(func.count(func.distinct(CorrelationEvidence.event_id))).where(
            CorrelationEvidence.correlation_id == correlation_id
        )
    )
    return events, int(total or 0)


def _assets_for_events(db: Session, events: list[SecurityEvent]) -> dict[str, list[str]]:
    """Map inventoried asset id -> the event ids that resolved to it.

    Exact match on the asset's address or host name, the same rule
    ``event_service.correlate_asset`` uses. An event that matches nothing is
    reported as unresolved rather than being attached to a guess.
    """
    addresses = sorted(
        {e.source_ip for e in events if e.source_ip}
        | {e.destination_ip for e in events if e.destination_ip}
    )
    hostnames = sorted({e.hostname for e in events if e.hostname})
    if not addresses and not hostnames:
        return {}
    assets = list(
        db.scalars(
            select(Asset).where((Asset.ip_address.in_(addresses)) | (Asset.hostname.in_(hostnames)))
        )
    )
    by_address = {asset.ip_address: asset for asset in assets if asset.ip_address}
    by_hostname = {asset.hostname: asset for asset in assets if asset.hostname}
    mapping: dict[str, list[str]] = {}
    for event in events:
        for candidate in (event.destination_ip, event.source_ip):
            asset = by_address.get(candidate) if candidate else None
            if asset is not None:
                mapping.setdefault(asset.id, []).append(event.id)
                break
        else:
            asset = by_hostname.get(event.hostname) if event.hostname else None
            if asset is not None:
                mapping.setdefault(asset.id, []).append(event.id)
    return mapping


def _open_findings(db: Session, asset_ids: list[str], limit: int) -> dict[str, list[Vulnerability]]:
    """Open vulnerability findings per asset, capped and deterministic."""
    if not asset_ids:
        return {}
    rows = db.scalars(
        select(Vulnerability)
        .where(
            Vulnerability.asset_id.in_(asset_ids),
            func.lower(func.coalesce(Vulnerability.status, "open")).in_(OPEN_STATUSES),
        )
        .order_by(Vulnerability.severity, Vulnerability.id)
        .limit(limit)
    ).all()
    grouped: dict[str, list[Vulnerability]] = {}
    for row in rows:
        grouped.setdefault(row.asset_id, []).append(row)
    return grouped


def build_intelligence(
    db: Session, incident_id: str, *, now: datetime | None = None
) -> Intelligence:
    """Build the deterministic intelligence summary for one incident.

    Raises ``KeyError`` for an unknown incident (mapped to 404 upstream).
    """
    settings = get_settings()
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if incident is None:
        raise KeyError(f"Unknown incident: {incident_id!r}.")

    events, evidence_total = _load_evidence_events(
        db, incident.correlation_id, int(settings.correlation_max_events_per_operation)
    )

    # ---- evidence (de-duplicated by construction) -------------------------
    severities: dict[str, int] = {}
    sources: dict[str, int] = {}
    for event in events:
        severities[event.severity] = severities.get(event.severity, 0) + 1
        sources[event.source_type] = sources.get(event.source_type, 0) + 1
    max_severity = max(severities, key=lambda name: (severity_points(name), name), default="INFO")
    evidence = {
        "count": len(events),
        "total_available": evidence_total,
        "truncated": evidence_total > len(events),
        "max_severity": max_severity,
        "by_severity": dict(sorted(severities.items())),
        "by_source_type": dict(sorted(sources.items())),
        "distinct_event_ids": len({event.id for event in events}),
    }

    # ---- affected assets (exact match only) -------------------------------
    asset_map = _assets_for_events(db, events)
    asset_ids = sorted(asset_map)
    assets = {
        "count": len(asset_ids),
        "ids": asset_ids,
        "unresolved_event_count": len(events)
        - len({eid for ids in asset_map.values() for eid in ids}),
        "primary_asset_id": incident.primary_asset_id,
        "hostname": incident.hostname,
        "primary_ip": incident.primary_ip,
    }

    # ---- vulnerability context (stored findings only) ---------------------
    finding_cap = int(settings.correlation_relationship_max) * MAX_VULNERABILITY_SEVERITIES
    findings_by_asset = _open_findings(db, asset_ids, finding_cap)
    finding_total = sum(len(items) for items in findings_by_asset.values())
    finding_severities: dict[str, int] = {}
    for items in findings_by_asset.values():
        for finding in items:
            finding_severities[finding.severity] = finding_severities.get(finding.severity, 0) + 1
    top_finding_severity = max(
        finding_severities,
        key=lambda name: (severity_points(name), name),
        default=None,
    )
    vulnerabilities = {
        "open_finding_count": finding_total,
        "by_severity": dict(sorted(finding_severities.items())),
        "max_severity": top_finding_severity,
        "truncated": finding_total > finding_cap,
        "assets_with_findings": sorted(
            asset_id for asset_id, items in findings_by_asset.items() if items
        ),
    }

    # ---- relationships (Step 29) ------------------------------------------
    relationship_limit = int(settings.correlation_relationship_max)
    relationships = db.scalars(
        select(IncidentRelationship)
        .where(IncidentRelationship.incident_id == incident_id)
        .order_by(IncidentRelationship.id)
        .limit(relationship_limit)
    ).all()
    relationship_total = db.scalar(
        select(func.count(IncidentRelationship.id)).where(
            IncidentRelationship.incident_id == incident_id
        )
    )
    relationship_view = {
        "count": len(relationships),
        "total_available": int(relationship_total or 0),
        "truncated": int(relationship_total or 0) > len(relationships),
        "max_confidence": max((row.confidence for row in relationships), default=0),
        "by_label": {
            label: sum(1 for row in relationships if row.confidence_label == label)
            for label in sorted({row.confidence_label for row in relationships})
        },
    }

    # ---- recency ----------------------------------------------------------
    moment = _naive_utc(now) if now is not None else _naive_utc(datetime.now(UTC))
    last_seen = _naive_utc(incident.last_seen)
    recency_days = max((moment - last_seen).days, 0)

    # ---- deterministic refinement ----------------------------------------
    points = 0
    factors: dict[str, object] = {
        "evidence_count": evidence["count"],
        "evidence_points": 0,
        "max_severity": max_severity,
        "severity_points": 0,
        "relationship_count": relationship_view["count"],
        "relationship_points": 0,
        "open_finding_count": vulnerabilities["open_finding_count"],
        "finding_points": 0,
        "recency_days": recency_days,
        "recency_points": 0,
        "asset_count": assets["count"],
    }

    evidence_points = min(2 * evidence["count"], 10)
    factors["evidence_points"] = evidence_points
    points += evidence_points

    severity_pts = severity_points(max_severity)
    factors["severity_points"] = severity_pts
    points += severity_pts

    relationship_points = min(2 * relationship_view["count"], 10)
    factors["relationship_points"] = relationship_points
    points += relationship_points

    # Vulnerability context: presence and worst severity, not a count of rows,
    # so many low findings cannot outrank one critical exposure.
    finding_points = 0
    if vulnerabilities["open_finding_count"] > 0:
        finding_points = min(2 + severity_points(top_finding_severity), 12)
    factors["finding_points"] = finding_points
    points += finding_points

    recency_pts = 5 if recency_days <= 1 else (3 if recency_days <= 7 else 0)
    factors["recency_points"] = recency_pts
    points += recency_pts

    bounded = max(0, min(points, 100))
    priority = _priority_for_points(bounded)
    factors["points_total"] = bounded

    reasons = [
        f"{evidence['count']} distinct evidence event(s) contribute {evidence_points} point(s).",
        f"Highest evidence severity {max_severity} contributes {severity_pts} point(s).",
        f"{relationship_view['count']} stored relationship(s) contribute {relationship_points} point(s).",
    ]
    if vulnerabilities["open_finding_count"]:
        reasons.append(
            f"{vulnerabilities['open_finding_count']} open vulnerability finding(s) on the "
            f"affected asset(s), worst severity {top_finding_severity}, contribute "
            f"{finding_points} point(s)."
        )
    else:
        reasons.append("No open vulnerability finding is recorded for the affected asset(s).")
    if assets["count"] == 0:
        reasons.append("No inventoried asset was resolved; the incident stays asset-unresolved.")
    reasons.append(f"Last seen {recency_days} day(s) ago contributes {recency_pts} point(s).")
    reasons.append(
        f"Refinement total {bounded} point(s) -> priority {priority}. This is a review "
        f"ordering, not a verdict, and not proof of compromise."
    )
    explanation = " ".join(reasons)

    timeline = {
        "first_seen": _naive_utc(incident.first_seen).isoformat(),
        "last_seen": last_seen.isoformat(),
        "recency_days": recency_days,
        "resolved_at": (
            _naive_utc(incident.resolved_at).isoformat() if incident.resolved_at else None
        ),
        "earliest_evidence": (
            _naive_utc(min(event.event_time for event in events)).isoformat() if events else None
        ),
        "latest_evidence": (
            _naive_utc(max(event.event_time for event in events)).isoformat() if events else None
        ),
    }

    return Intelligence(
        incident_id=incident.id,
        correlation_id=incident.correlation_id,
        status=incident.status,
        severity=incident.severity,
        confidence=int(incident.confidence or 0),
        priority=priority,
        points=bounded,
        factors=factors,
        explanation=explanation,
        evidence=evidence,
        assets=assets,
        vulnerabilities=vulnerabilities,
        relationships=relationship_view,
        timeline=timeline,
    )


def refresh_intelligence(
    db: Session, incident_id: str, actor: str, *, now: datetime | None = None
) -> dict[str, object]:
    """Build the summary and append an audit row describing the calculation.

    The calculation is read-only with respect to incident state: it stores no
    score, creates no incident and changes no risk assessment. The audit row
    is the durable record that a refinement ran, with its inputs and result.
    """
    from app.services.incident_service import record_audit

    result = build_intelligence(db, incident_id, now=now)
    record_audit(
        db,
        incident_id,
        "INTELLIGENCE_REFRESHED",
        actor,
        (
            f"Refinement {result.points} point(s) -> {result.priority} from "
            f"{result.evidence['count']} evidence event(s), "
            f"{result.relationships['count']} relationship(s), "
            f"{result.vulnerabilities['open_finding_count']} open finding(s), "
            f"{result.assets['count']} resolved asset(s)."
        ),
    )
    db.commit()
    return result.as_dict()


__all__ = [
    "ANALYSIS_VERSION",
    "REFINEMENT_BANDS",
    "Intelligence",
    "build_intelligence",
    "refresh_intelligence",
]
