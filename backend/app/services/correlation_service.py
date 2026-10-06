"""Correlation engine service (Step 9, analysis only).

Pipeline::

    SecurityEvent rows (bounded fetch, event_time order)
      -> EventView list (naive-UTC moments, out-of-order safe)
      -> apply_all_rules() -> drafts
      -> upsert by deterministic id (create or refresh, never duplicate)

``recompute_correlations`` scans at most ``MAX_EVENTS_SCANNED`` recent
rows — bounded work, no parameters, no rule selection from callers, so
there is no arbitrary-rule-execution surface. Severity is inherited as
the evidence maximum; confidence is the rule's fixed value; titles name
the rule and pivot without claiming compromise.
"""

from __future__ import annotations

import hashlib
import json

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.correlations import Correlation, CorrelationAudit, CorrelationEvidence
from app.models.events import SecurityEvent
from app.services.correlation_rules import (
    ALL_RULES,
    RULES,
    SEVERITY_RANK,
    CorrelationDraft,
    EventView,
    apply_all_rules,
)

logger = get_logger(__name__)

# Bounded scan: recompute looks at recent history only.
MAX_EVENTS_SCANNED = 500
IDENTITY_NAMESPACE = "correlation:v1"

# Step 24 recompute audit actions (append-only; never contain secrets).
AUDIT_RUN_STARTED = "RUN_STARTED"
AUDIT_MATCHED = "CORRELATION_MATCHED"
AUDIT_RUN_COMPLETED = "RUN_COMPLETED"


def record_correlation_audit(
    db: Session,
    action: str,
    actor: str,
    correlation_id: str | None = None,
    detail: str | None = None,
) -> None:
    """Append one recompute lifecycle row (Step 24)."""
    db.add(
        CorrelationAudit(
            correlation_id=correlation_id, action=action, actor=actor[:128], detail=detail
        )
    )


def deterministic_id(rule_id: str, event_ids: list[str]) -> str:
    """Stable identity for an evidence set. No time, no randomness."""
    canonical = json.dumps([IDENTITY_NAMESPACE, rule_id, sorted(event_ids)], separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def to_view(event: SecurityEvent) -> EventView:
    return EventView(
        id=event.id,
        event_time=event.event_time,
        source_type=event.source_type,
        event_type=event.event_type,
        severity=event.severity,
        title=event.title,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        hostname=event.hostname,
    )


def severity_of(event_ids: list[str], by_id: dict[str, EventView]) -> str:
    best = "INFO"
    best_rank = -1
    for event_id in event_ids:
        rank = SEVERITY_RANK.get(by_id[event_id].severity, 0)
        if rank > best_rank:
            best, best_rank = by_id[event_id].severity, rank
    return best


def upsert_draft(
    db: Session, draft: CorrelationDraft, by_id: dict[str, EventView]
) -> tuple[Correlation, bool]:
    """Create or refresh the correlation for a draft. Returns (row, created)."""
    correlation_id = deterministic_id(draft.rule_id, draft.event_ids)
    rule = RULES[draft.rule_id]
    moments = sorted(by_id[event_id].moment() for event_id in draft.event_ids)
    # Total order: ties on event_time break by event id, otherwise positions
    # could flip between recomputes whenever the database returns tied rows
    # in a different order.
    ordered = sorted(draft.event_ids, key=lambda event_id: (by_id[event_id].moment(), event_id))
    existing = db.scalar(select(Correlation).where(Correlation.id == correlation_id))
    if existing is None:
        row = Correlation(
            id=correlation_id,
            rule_id=rule.id,
            rule_name=rule.name,
            title=f"{rule.name}: {draft.primary_ip or draft.hostname or f'{len(draft.event_ids)} related events'}",
            description=(
                "Correlated activity grouped for review. Related events are "
                "not proof of compromise. " + draft.explanation
            ),
            status="open",
            severity=severity_of(draft.event_ids, by_id),
            confidence=rule.confidence,
            explanation=draft.explanation,
            primary_ip=draft.primary_ip,
            hostname=draft.hostname,
            window_start=moments[0],
            window_end=moments[-1],
            event_count=len(draft.event_ids),
        )
        db.add(row)
        db.flush()
        for position, event_id in enumerate(ordered):
            db.add(
                CorrelationEvidence(
                    correlation_id=row.id,
                    event_id=event_id,
                    role=draft.roles.get(event_id, "related"),
                    position=position,
                )
            )
        db.commit()
        db.refresh(row)
        return row, True
    # Refresh a known correlation: same evidence set by identity, but
    # re-sync links and derived fields so replays converge exactly.
    existing_evidence = {
        link.event_id: link
        for link in db.scalars(
            select(CorrelationEvidence).where(CorrelationEvidence.correlation_id == existing.id)
        ).all()
    }
    for position, event_id in enumerate(ordered):
        link = existing_evidence.get(event_id)
        if link is None:
            db.add(
                CorrelationEvidence(
                    correlation_id=existing.id,
                    event_id=event_id,
                    role=draft.roles.get(event_id, "related"),
                    position=position,
                )
            )
        else:
            link.position = position
            link.role = draft.roles.get(event_id, "related")
    existing.severity = severity_of(draft.event_ids, by_id)
    existing.event_count = len(draft.event_ids)
    existing.window_start = moments[0]
    existing.window_end = moments[-1]
    db.commit()
    db.refresh(existing)
    return existing, False


def recompute_correlations(db: Session, actor: str = "system") -> dict[str, object]:
    """Run all rules over recent events; upsert correlations. Deterministic.

    Audits RUN_STARTED once, CORRELATION_MATCHED per newly created
    correlation, and RUN_COMPLETED with counts. Refreshes are routine
    replays (audited on the correlation detail path), not new matches.
    """
    record_correlation_audit(
        db, AUDIT_RUN_STARTED, actor, None, f"Scanning up to {MAX_EVENTS_SCANNED} recent events."
    )
    db.commit()
    rows = db.scalars(
        select(SecurityEvent).order_by(desc(SecurityEvent.event_time)).limit(MAX_EVENTS_SCANNED)
    ).all()
    views = [to_view(event) for event in rows]
    by_id = {view.id: view for view in views}
    drafts = apply_all_rules(views)
    created = 0
    refreshed = 0
    ids: list[str] = []
    for draft in drafts:
        row, was_created = upsert_draft(db, draft, by_id)
        ids.append(row.id)
        if was_created:
            created += 1
            record_correlation_audit(
                db,
                AUDIT_MATCHED,
                actor,
                row.id,
                f"Rule {row.rule_id} matched {row.event_count} event(s).",
            )
        else:
            refreshed += 1
    record_correlation_audit(
        db,
        AUDIT_RUN_COMPLETED,
        actor,
        None,
        f"{len(views)} scanned, {len(drafts)} drafts, {created} created, {refreshed} refreshed.",
    )
    db.commit()
    logger.info(
        "Correlation recompute: %d events scanned, %d drafts, %d created, %d refreshed",
        len(views),
        len(drafts),
        created,
        refreshed,
    )
    return {
        "events_scanned": len(views),
        "rules_evaluated": len(ALL_RULES),
        "created": created,
        "refreshed": refreshed,
        "correlation_ids": sorted(ids),
    }


__all__ = [
    "AUDIT_MATCHED",
    "AUDIT_RUN_COMPLETED",
    "AUDIT_RUN_STARTED",
    "MAX_EVENTS_SCANNED",
    "deterministic_id",
    "recompute_correlations",
    "record_correlation_audit",
    "severity_of",
    "to_view",
    "upsert_draft",
]
