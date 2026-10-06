"""Finding links (Step 16, derived — never stored, never guessed).

Links connect a Step 15 ``Vulnerability`` row to already-stored platform
records using only compatible identifiers that both sides actually
carry. Every link carries its reason; absence of evidence yields an
empty list plus an explanation — never a fabricated relationship and
never an AI/LLM judgment.

Link rules (deterministic, documented):

- finding ↔ asset: the finding's own ``asset_id`` foreign key.
- finding ↔ service: the finding's own ``service_id`` foreign key.
- finding ↔ related events: ``SecurityEvent`` rows whose source or
  destination IP, or hostname, matches the finding's asset IP/hostname.
  Ordered by event time, oldest first.
- finding ↔ incidents: incidents whose correlation evidence includes at
  least one related event above (resolved through the existing
  correlation → evidence → incident chain).

No timestamps are invented, no thresholds are hidden, and nothing here
executes, contacts, or modifies anything.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.assets import Asset
from app.models.correlations import Correlation, CorrelationEvidence
from app.models.events import SecurityEvent
from app.models.incidents import Incident
from app.models.vulnerabilities import Vulnerability


def asset_keys(db: Session, finding: Vulnerability) -> dict[str, object]:
    """Resolve the finding's asset context (ip/hostname), if the asset exists."""
    asset = db.scalar(select(Asset).where(Asset.id == finding.asset_id))
    if asset is None:
        return {"ip": None, "hostname": None}
    return {"ip": asset.ip_address, "hostname": asset.hostname}


def related_events(db: Session, finding: Vulnerability, limit: int = 100) -> list[SecurityEvent]:
    """Events touching the finding's asset, oldest first."""
    keys = asset_keys(db, finding)
    candidates: list[SecurityEvent] = []
    if keys["ip"] is not None:
        candidates.extend(
            db.scalars(
                select(SecurityEvent)
                .where(
                    (SecurityEvent.source_ip == keys["ip"])
                    | (SecurityEvent.destination_ip == keys["ip"])
                )
                .order_by(SecurityEvent.event_time, SecurityEvent.id)
                .limit(limit)
            ).all()
        )
    if keys["hostname"]:
        candidates.extend(
            db.scalars(
                select(SecurityEvent)
                .where(SecurityEvent.hostname == keys["hostname"])
                .order_by(SecurityEvent.event_time, SecurityEvent.id)
                .limit(limit)
            ).all()
        )
    seen: set[str] = set()
    ordered: list[SecurityEvent] = []
    for event in sorted(candidates, key=lambda item: (item.event_time, item.id)):
        if event.id not in seen:
            seen.add(event.id)
            ordered.append(event)
    return ordered[:limit]


def related_incidents(db: Session, finding: Vulnerability) -> list[Incident]:
    """Incidents whose correlation evidence includes a related event."""
    related_ids = {event.id for event in related_events(db, finding, limit=1000)}
    if not related_ids:
        return []
    evidence = db.scalars(
        select(CorrelationEvidence).where(CorrelationEvidence.event_id.in_(sorted(related_ids)))
    ).all()
    correlation_ids = sorted({link.correlation_id for link in evidence})
    if not correlation_ids:
        return []
    incidents = db.scalars(
        select(Incident)
        .where(Incident.correlation_id.in_(correlation_ids))
        .order_by(Incident.created_at, Incident.id)
    ).all()
    return list(incidents)


def covering_correlations(db: Session, finding: Vulnerability) -> list[Correlation]:
    """Correlations touching the finding's asset (primary IP or evidence).

    Same shared-identifier rule as the links above, restricted to the
    correlation level for risk-signal purposes.
    """
    keys = asset_keys(db, finding)
    matched: dict[str, Correlation] = {}
    if keys["ip"] is not None:
        for correlation in db.scalars(
            select(Correlation).where(Correlation.primary_ip == keys["ip"])
        ).all():
            matched[correlation.id] = correlation
    for event in related_events(db, finding, limit=1000):
        for link in db.scalars(
            select(CorrelationEvidence).where(CorrelationEvidence.event_id == event.id)
        ).all():
            correlation = db.scalar(
                select(Correlation).where(Correlation.id == link.correlation_id)
            )
            if correlation is not None:
                matched[correlation.id] = correlation
    return [matched[key] for key in sorted(matched)]


def describe_links(db: Session, finding: Vulnerability) -> dict[str, object]:
    """Explainable link summary for one finding."""
    keys = asset_keys(db, finding)
    events = related_events(db, finding)
    incidents = related_incidents(db, finding)
    reasons: list[str] = []
    if keys["ip"] is not None:
        reasons.append(f"shares asset IP {keys['ip']}")
    if keys["hostname"]:
        reasons.append(f"shares asset hostname {keys['hostname']}")
    return {
        "asset_id": finding.asset_id,
        "service_id": finding.service_id,
        "related_event_ids": [event.id for event in events],
        "related_incident_ids": [incident.id for incident in incidents],
        "reasons": reasons or ["no compatible asset identifiers shared with stored events"],
    }


__all__ = [
    "asset_keys",
    "covering_correlations",
    "describe_links",
    "related_events",
    "related_incidents",
]
