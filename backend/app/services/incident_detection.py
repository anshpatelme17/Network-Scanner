"""Conservative incident detection (Step 17, analysis only, stored data only).

The detector consumes EXISTING stored correlations (plus optional stored
risk assessments and vulnerability findings). It performs no scanning,
executes nothing, and opens no network connections.

Qualification is deliberately conservative and fully deterministic. A
correlation qualifies for an incident when at least one holds:

- its rule pairs a vulnerability finding with observed activity
  (``vuln-exposure`` — finding plus activity by construction);
- it groups three or more evidence events (repeated/multi-source
  substance, not a lone observation);
- its severity is HIGH or CRITICAL.

Anything else is left alone with an explained skip reason: a lone
LOW/INFO observation is an investigation lead at most, and a
vulnerability finding by itself is never enough — ``ASSESS`` returns
``qualifies=False`` for finding-only input and no incident is created.

Deduplication reuses the Step 11 identity
(``sha256("incident:v1" | correlation_id | risk_assessment_id or "")``):
reprocessing the same evidence returns the same row unchanged
(``created=False``). When new qualifying evidence arrives for an
existing incident (a wider correlation window or genuinely new evidence
links), the incident's ``last_seen`` advances and the additions are
audited — ``first_seen`` is never rewritten.

Type classification is a fixed mapping from the correlation's
``rule_id`` (classifications only; never a compromise claim):

- ``vuln-exposure`` -> VULNERABILITY_ACTIVITY
- ``multi-source-target`` -> SUSPICIOUS_NETWORK_ACTIVITY
- ``repeated-source`` -> CORRELATED_SECURITY_EVENT
- anything else -> OTHER

AUTHENTICATION_ANOMALY, MALWARE_INDICATOR and POLICY_VIOLATION are
reserved vocabulary with no producing rule yet; the detector never
emits them.

Risk/confidence (documented, no second formula): ``risk_score`` is the
linked Step 10 assessment's score verbatim (NULL when no assessment is
linked); ``confidence`` is the correlation's confidence and represents
evidence strength, not probability of compromise.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.assets import Asset
from app.models.correlations import Correlation, CorrelationEvidence
from app.models.incidents import Incident, IncidentEvidence
from app.models.vulnerabilities import Vulnerability
from app.services import incident_service
from app.services.incident_service import (
    AUDIT_EVIDENCE_ATTACHED,
    EVIDENCE_CORRELATION,
    EVIDENCE_EVENT,
    EVIDENCE_VULNERABILITY,
    TYPE_CORRELATED_SECURITY_EVENT,
    TYPE_OTHER,
    TYPE_SUSPICIOUS_NETWORK_ACTIVITY,
    TYPE_VULNERABILITY_ACTIVITY,
)

logger = get_logger(__name__)

DETECTION_VERSION = "1.0.0"
DETECTOR_ACTOR = "detection"

# Fixed rule -> type classification (see module docstring).
RULE_TYPE_MAP: dict[str, str] = {
    "vuln-exposure": TYPE_VULNERABILITY_ACTIVITY,
    "multi-source-target": TYPE_SUSPICIOUS_NETWORK_ACTIVITY,
    "repeated-source": TYPE_CORRELATED_SECURITY_EVENT,
}

# Conservative substance bar for pure event groupings.
MIN_GROUP_EVENTS = 3
STRONG_SEVERITIES = frozenset({"HIGH", "CRITICAL"})


def classify_type(correlation: Correlation) -> str:
    """Controlled type from the correlation rule (deterministic)."""
    return RULE_TYPE_MAP.get(correlation.rule_id, TYPE_OTHER)


def assess(correlation: Correlation) -> tuple[bool, str]:
    """Decide whether a correlation qualifies (deterministic, explained).

    Returns (qualifies, reason). The reason is stored as the incident's
    ``detection_reason`` or as the skip explanation for non-qualifying
    input — never hallucinated, always derived from the row. Reasons name
    the actual pivot identifiers (asset IP/hostname), event counts, and
    the matched rule (Step 24).
    """
    pivot = correlation.primary_ip or correlation.hostname or "unknown host"
    if correlation.rule_id == "vuln-exposure":
        return True, (
            f"Correlation {correlation.id} matches rule 'vuln-exposure': a recorded "
            f"vulnerability finding on host {pivot} "
            f"combined with {correlation.event_count} observed event(s). "
            "The finding alone would not qualify; the observed activity does."
        )
    if correlation.event_count >= MIN_GROUP_EVENTS:
        return True, (
            f"Correlation {correlation.id} groups {correlation.event_count} related events "
            f"against {pivot} under rule '{correlation.rule_id}' (bar: {MIN_GROUP_EVENTS})."
        )
    if correlation.severity in STRONG_SEVERITIES:
        return True, (
            f"Correlation {correlation.id} carries severity {correlation.severity} "
            f"against {pivot} under rule '{correlation.rule_id}'."
        )
    return False, (
        f"Correlation {correlation.id} does not qualify: rule '{correlation.rule_id}' with "
        f"{correlation.event_count} event(s) at severity {correlation.severity} against "
        f"{pivot} is a lone observation, kept as an investigation lead rather than an incident."
    )


def finding_refs_for_correlation(db: Session, correlation: Correlation) -> list[Vulnerability]:
    """Vulnerability rows sharing the correlation's asset identifiers.

    Same shared-identifier logic as the Step 16 finding links: match the
    correlation's primary IP/hostname against finding asset references.
    Returns rows (references only); empty when nothing is stored.
    """
    keys = {key for key in (correlation.primary_ip, correlation.hostname) if key}
    if not keys:
        return []
    rows = db.execute(
        select(Vulnerability, Asset).join(Asset, Vulnerability.asset_id == Asset.id)
    ).all()
    matched: list[Vulnerability] = []
    for finding, asset in rows:
        candidates = {asset.ip_address, asset.hostname}
        if keys & (candidates - {None}):
            matched.append(finding)
    return sorted(matched, key=lambda finding: finding.id)


def _attach_all_evidence(db: Session, incident: Incident, correlation: Correlation) -> int:
    """Attach correlation + event + finding references. Returns new-link count."""
    added = 0
    if incident_service.attach_evidence(
        db,
        incident.id,
        EVIDENCE_CORRELATION,
        correlation.id,
        f"Source correlation {correlation.id} ({correlation.rule_name}).",
    ):
        added += 1
    links = db.scalars(
        select(CorrelationEvidence)
        .where(CorrelationEvidence.correlation_id == correlation.id)
        .order_by(CorrelationEvidence.position)
    ).all()
    for link in links:
        if incident_service.attach_evidence(
            db,
            incident.id,
            EVIDENCE_EVENT,
            link.event_id,
            f"Evidence event in role '{link.role}' (position {link.position}).",
        ):
            added += 1
    for finding in finding_refs_for_correlation(db, correlation):
        if incident_service.attach_evidence(
            db,
            incident.id,
            EVIDENCE_VULNERABILITY,
            finding.id,
            f"Finding {finding.id} shares asset identifiers with the incident host.",
        ):
            added += 1
    return added


def detect_for_correlation(
    db: Session,
    correlation_id: str,
    risk_assessment_id: str | None = None,
    actor: str = DETECTOR_ACTOR,
) -> tuple[Incident | None, bool, str]:
    """Run detection for one correlation. Returns (incident|None, created, reason).

    Non-qualifying input yields (None, False, skip-reason) and creates
    nothing. Qualifying input reuses the Step 11 identity: same evidence
    twice returns the same row with created=False; a wider window or new
    evidence links update last_seen/evidence with an audit row. Note the
    identity includes the risk linkage, so (correlation, None) and
    (correlation, riskX) are distinct logical incidents by Step 11
    design — bulk detection always uses the canonical no-risk identity.
    """
    correlation = db.scalar(select(Correlation).where(Correlation.id == correlation_id))
    if correlation is None:
        raise incident_service.IncidentNotFoundError(f"No correlation with id {correlation_id}.")
    qualifies, reason = assess(correlation)
    if not qualifies:
        return None, False, reason

    incident, created = incident_service.create_incident(
        db,
        correlation.id,
        risk_assessment_id,
        incident_type=classify_type(correlation),
        detection_reason=reason,
        actor=actor,
    )
    if created:
        _attach_all_evidence(db, incident, correlation)
        db.commit()
        db.refresh(incident)
        logger.info("Detection opened incident %s (%s)", incident.incident_key, reason)
        return incident, True, reason

    # Existing incident: advance last_seen only when the correlation
    # window genuinely extends it; attach only genuinely new evidence.
    updated = False
    if correlation.window_end > incident.last_seen:
        incident.last_seen = correlation.window_end
        updated = True
    if correlation.window_start < incident.first_seen:
        incident.first_seen = correlation.window_start
        updated = True
    added = _attach_all_evidence(db, incident, correlation)
    if added:
        incident_service.record_audit(
            db, incident.id, AUDIT_EVIDENCE_ATTACHED, actor, f"{added} new evidence link(s)."
        )
        updated = True
    if updated:
        db.commit()
        db.refresh(incident)
    return incident, False, reason


def detect_all(db: Session, actor: str = DETECTOR_ACTOR) -> dict[str, object]:
    """Evaluate every correlation in stable order (fully deterministic).

    Bulk detection always uses the canonical no-risk identity (one
    incident per correlation): passing a risk assessment here would fork
    Step 11 identities, so the single-correlation endpoint owns the
    optional risk linkage instead. Correlations that already have an
    incident are reprocessed through the same update path (wider window
    or new evidence links update them, counted as updated); all other
    repeat runs are no-ops. Returns a summary dict with
    evaluated/created/updated/skipped counts plus per-item outcomes.
    """
    correlations = db.scalars(
        select(Correlation).order_by(Correlation.window_start, Correlation.id)
    ).all()
    outcomes: list[dict[str, object]] = []
    created = 0
    updated = 0
    skipped = 0
    for correlation in correlations:
        prior = db.scalar(select(Incident).where(Incident.correlation_id == correlation.id))
        prior_seen = prior.last_seen if prior is not None else None
        prior_evidence = (
            db.scalar(
                select(func.count(IncidentEvidence.id)).where(
                    IncidentEvidence.incident_id == prior.id
                )
            )
            if prior is not None
            else 0
        )
        incident, was_created, reason = detect_for_correlation(db, correlation.id, None, actor)
        if incident is None:
            skipped += 1
        elif was_created:
            created += 1
        else:
            current_evidence = (
                db.scalar(
                    select(func.count(IncidentEvidence.id)).where(
                        IncidentEvidence.incident_id == incident.id
                    )
                )
                or 0
            )
            if (
                prior is None
                or incident.last_seen != prior_seen
                or current_evidence != prior_evidence
            ):
                updated += 1
        outcomes.append(
            {
                "correlation_id": correlation.id,
                "incident_id": incident.id if incident is not None else None,
                "created": was_created,
                "reason": reason,
            }
        )
    return {
        "evaluated": len(outcomes),
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "detector_version": DETECTION_VERSION,
        "outcomes": outcomes,
    }


__all__ = [
    "DETECTION_VERSION",
    "MIN_GROUP_EVENTS",
    "RULE_TYPE_MAP",
    "assess",
    "classify_type",
    "detect_all",
    "detect_for_correlation",
    "finding_refs_for_correlation",
]
