"""Incident analysis service (Step 29, deterministic and bounded).

Runs the Step 29 rule catalog over ONE incident's stored evidence
events (the correlation's ``CorrelationEvidence`` rows — the same
records every earlier step already displays) plus existing ``Asset``
rows, then reconciles flat ``IncidentRelationship`` rows.

Guarantees:

- **Stored data only.** Candidates are rows already in the database;
  missing fields produce no match, unknown assets/users produce no
  rows, and no entity, identity or event is ever manufactured. Nothing
  here talks to a network, executes anything, or acts on a host.
- **Deterministic.** Same evidence rows → same relationship set and
  same audit details, always: rules are pure functions, iteration
  order is the catalog order, identities are content hashes (no clock,
  no randomness). Analysis is idempotent: a second run with unchanged
  evidence creates 0 rows.
- **Reconciling.** Rows whose identity no longer matches current
  evidence are pruned, so the stored set is exactly a function of the
  current inputs (evidence changed → relationships replaced).
- **Bounded.** Candidates capped by ``correlation_max_events_per_``
  ``operation``; output capped by ``correlation_relationship_max``
  (deterministic catalog-order truncation, reported via ``truncated``);
  stored evidence ids per row capped by ``correlation_relationship_``
  ``evidence_max``. All lookups are batched (``IN``), never N+1.
- **Audited.** Every run appends ``INCIDENT_RECALCULATED``; runs that
  create rows also append ``INCIDENT_CORRELATED`` (same actor/detail
  conventions as the Step 17 incident audits).

The Step 24 recompute path (``POST /correlations/recompute``) never
calls this module, so the Step 24 contract (``rules_evaluated == 3``)
is untouched. Risk scoring stays the job of ``risk_service`` (Step 25
endpoint); relationship counts are surfaced there only as an
informational factor.
"""

from __future__ import annotations

import hashlib
import json

from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.assets import Asset
from app.models.events import SecurityEvent
from app.models.incidents import Incident, IncidentRelationship
from app.services import incident_service
from app.services.incident_rules import (
    ANALYSIS_RULE_FUNCTIONS,
    ANALYSIS_RULES,
    ANALYSIS_VERSION,
    AnalysisEvent,
    apply_analysis_rules,
    confidence_label,
    effective_window_minutes,
)

logger = get_logger(__name__)

IDENTITY_NAMESPACE = "incident-relationship:v1"

# Step 29 audit actions (append-only, controlled vocabulary; ≤32 chars).
AUDIT_INCIDENT_RECALCULATED = "INCIDENT_RECALCULATED"
AUDIT_INCIDENT_CORRELATED = "INCIDENT_CORRELATED"


def relationship_id(
    incident_id: str,
    rule_id: str,
    source_kind: str,
    source_id: str,
    target_kind: str,
    target_id: str,
) -> str:
    """Deterministic identity. No time, no randomness."""
    canonical = json.dumps(
        [
            IDENTITY_NAMESPACE,
            incident_id,
            rule_id,
            source_kind,
            source_id,
            target_kind,
            target_id,
        ],
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _load_analysis_events(db: Session, event_ids: list[str]) -> list[AnalysisEvent]:
    if not event_ids:
        return []
    rows = db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.id.in_(event_ids))
        .order_by(SecurityEvent.event_time, SecurityEvent.id)
    ).all()
    return [
        AnalysisEvent(
            id=row.id,
            event_time=row.event_time,
            source_type=row.source_type,
            event_type=row.event_type,
            severity=row.severity,
            title=row.title,
            source_ip=row.source_ip,
            destination_ip=row.destination_ip,
            hostname=row.hostname,
            username=row.username,
            action=row.action,
            status=row.status,
        )
        for row in rows
    ]


def _known_assets(db: Session, events: list[AnalysisEvent]) -> dict[str, str]:
    """One batched lookup: address/hostname key -> existing asset id.

    Only stored assets appear here — nothing is created, and the first
    asset id wins for a shared key (deterministic by id order).
    """
    addresses = {
        value for event in events for value in (event.source_ip, event.destination_ip) if value
    }
    hosts = {event.hostname for event in events if event.hostname}
    criteria = []
    if addresses:
        criteria.append(Asset.ip_address.in_(sorted(addresses)))
    if hosts:
        criteria.append(Asset.hostname.in_(sorted(hosts)))
    if not criteria:
        return {}
    rows = db.scalars(select(Asset).where(or_(*criteria)).order_by(Asset.id)).all()
    mapping: dict[str, str] = {}
    for asset in rows:
        for key in (asset.ip_address, asset.hostname):
            if key and key not in mapping:
                mapping[key] = asset.id
    return mapping


def analyze_incident(db: Session, incident_id: str, actor: str = "system") -> dict[str, object]:
    """Bounded, deterministic relationship analysis for one incident.

    Raises ``incident_service.IncidentNotFoundError`` for unknown
    incidents. Commits on success; the caller owns no transaction.
    """
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if incident is None:
        raise incident_service.IncidentNotFoundError(f"No incident with id {incident_id}.")

    settings = get_settings()
    max_events = settings.correlation_max_events_per_operation
    max_relationships = settings.correlation_relationship_max
    evidence_max = settings.correlation_relationship_evidence_max

    candidate_ids = incident_service.evidence_event_ids(db, incident.correlation_id)
    bounded_ids = candidate_ids[:max_events]
    events = _load_analysis_events(db, bounded_ids)
    known_assets = _known_assets(db, events)

    drafts = apply_analysis_rules(events, known_assets)
    truncated = len(drafts) > max_relationships
    drafts = drafts[:max_relationships]

    payloads: list[dict[str, object]] = []
    for draft in drafts:
        rule = ANALYSIS_RULES[draft.rule_id]
        payloads.append(
            {
                "id": relationship_id(
                    incident.id,
                    rule.id,
                    draft.source_kind,
                    draft.source_id,
                    draft.target_kind,
                    draft.target_id,
                ),
                "incident_id": incident.id,
                "rule_id": rule.id,
                "rule_name": rule.name,
                "relation": draft.relation,
                "source_kind": draft.source_kind,
                "source_id": draft.source_id,
                "source_label": (draft.source_label or "")[:255] or None,
                "target_kind": draft.target_kind,
                "target_id": draft.target_id,
                "target_label": (draft.target_label or "")[:255] or None,
                "confidence": rule.confidence,
                "confidence_label": confidence_label(rule.confidence),
                "explanation": draft.explanation,
                "evidence_json": json.dumps(
                    sorted(set(draft.evidence_event_ids))[:evidence_max], separators=(",", ":")
                ),
                "first_seen": draft.first_seen,
                "last_seen": draft.last_seen,
            }
        )

    existing = db.scalars(
        select(IncidentRelationship).where(IncidentRelationship.incident_id == incident.id)
    ).all()
    existing_by_id = {row.id: row for row in existing}
    created = 0
    refreshed = 0
    for payload in payloads:
        row = existing_by_id.get(str(payload["id"]))
        if row is None:
            db.add(IncidentRelationship(**payload))  # type: ignore[arg-type]
            created += 1
            continue
        for key, value in payload.items():
            if key == "id":
                continue
            setattr(row, key, value)
        refreshed += 1
    expected = {str(payload["id"]) for payload in payloads}
    for row in existing:
        if row.id not in expected:
            db.delete(row)

    total = len(payloads)
    truncated_note = " (truncated to the configured relationship cap)" if truncated else ""
    incident_service.record_audit(
        db,
        incident.id,
        AUDIT_INCIDENT_RECALCULATED,
        actor,
        f"Relationship analysis {ANALYSIS_VERSION}: {created} created, {refreshed} refreshed, "
        f"{total} total from {len(events)} of {len(candidate_ids)} evidence event(s)"
        f"{truncated_note}.",
    )
    if created:
        incident_service.record_audit(
            db,
            incident.id,
            AUDIT_INCIDENT_CORRELATED,
            actor,
            f"{created} new relationship(s) derived deterministically from stored evidence "
            "events; no new evidence or entities created.",
        )
    db.commit()

    logger.info(
        "Incident %s analysis v%s: %d events, %d relationships (%d created)",
        incident.incident_key,
        ANALYSIS_VERSION,
        len(events),
        total,
        created,
    )
    return {
        "incident_id": incident.id,
        "analysis_version": ANALYSIS_VERSION,
        "rules_evaluated": len(ANALYSIS_RULE_FUNCTIONS),
        "events_considered": len(events),
        "relationships_created": created,
        "relationships_refreshed": refreshed,
        "relationships_total": total,
        "truncated": truncated,
        "bounds": {
            "max_events": max_events,
            "max_relationships": max_relationships,
            "max_evidence_per_relationship": evidence_max,
            "temporal_window_minutes": effective_window_minutes("temporal-auth-sequence"),
            "cross_source_window_minutes": effective_window_minutes("cross-source-observation"),
            "entity_window_minutes": effective_window_minutes("same-entity-window"),
        },
    }


def list_relationships(
    db: Session,
    incident_id: str,
    rule_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[IncidentRelationship], int]:
    """Stable, paginated relationship rows for one incident.

    Ordered by strongest confidence first, then rule id and the unique
    six-column identity — a total order, so pagination never skips or
    repeats a row.
    """
    criteria = [IncidentRelationship.incident_id == incident_id]
    if rule_id is not None:
        criteria.append(IncidentRelationship.rule_id == rule_id)
    total = db.scalar(select(func.count(IncidentRelationship.id)).where(*criteria)) or 0
    rows = db.scalars(
        select(IncidentRelationship)
        .where(*criteria)
        .order_by(
            IncidentRelationship.confidence.desc(),
            IncidentRelationship.rule_id,
            IncidentRelationship.source_kind,
            IncidentRelationship.source_id,
            IncidentRelationship.target_kind,
            IncidentRelationship.target_id,
        )
        .limit(limit)
        .offset(offset)
    ).all()
    return list(rows), total


def delete_relationships(db: Session, incident_id: str) -> None:
    """Remove every stored relationship for one incident (test/tooling aid)."""
    db.execute(delete(IncidentRelationship).where(IncidentRelationship.incident_id == incident_id))


__all__ = [
    "AUDIT_INCIDENT_CORRELATED",
    "AUDIT_INCIDENT_RECALCULATED",
    "IDENTITY_NAMESPACE",
    "analyze_incident",
    "delete_relationships",
    "list_relationships",
    "relationship_id",
]
