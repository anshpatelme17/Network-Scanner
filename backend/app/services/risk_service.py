"""Deterministic risk scoring (Step 10, analysis only).

Scores platform entities — assets, vulnerability findings, correlations —
using ONLY data already stored in the database. The mathematics are pure
functions of their inputs (``compute_*``): no clock, no randomness, no
row ordering, no network calls. ``recompute_risk`` only gathers inputs
and persists results.

Documented formula (v1.0.0), all constants centralized below:

    score = clamp(10 + severity_pts + signal_pts + recency_pts, 0, 100)

- ``severity_pts`` from the strongest directly linked severity signal:
  INFO 0, LOW 10, MEDIUM 25, HIGH 40, CRITICAL 55.
- ``signal_pts`` per entity (each sub-term capped):
  - vulnerability: ``int(cvss / 10 * 15)`` (0 when CVSS absent) +
    5 if the finding's host matches a known asset +
    min(3 × covering correlations, 9)
  - correlation: min(2 × evidence count, 10) + confidence // 10
  - asset: min(2 × open ports, 10) + min(3 × linked findings, 12) +
    min(5 × linked correlations, 10)
- ``recency_pts`` from the newest contributing timestamp measured
  against the newest event_time present anywhere in the dataset
  (a data-derived reference — never wall-clock time):
  ≤7 days 10, ≤30 days 5, older or unknown 0.
- Bands: 80–100 CRITICAL, 60–79 HIGH, 40–59 MEDIUM, 20–39 LOW, 0–19 INFO.

Step 29: incident assessments additionally RECORD the incident's stored
relationship count as an informational ``factors`` field (no points —
no score can change because relationships exist).

A score is a neutral, reproducible number with factors and explanation;
it never claims compromise and drives no action.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.assets import Asset, DiscoveredService
from app.models.correlations import Correlation, CorrelationEvidence
from app.models.events import SecurityEvent
from app.models.incidents import Incident, IncidentEvidence, IncidentRelationship
from app.models.risk import RiskAssessment, RiskAudit
from app.models.vulnerabilities import Vulnerability
from app.services import vuln_correlation

logger = get_logger(__name__)

SCORING_VERSION = "1.0.0"
IDENTITY_NAMESPACE = "risk-assessment:v1"

ENTITY_ASSET = "asset"
ENTITY_VULNERABILITY = "vulnerability"
ENTITY_CORRELATION = "correlation"
# Step 15 finding rows. Kept distinct from "vulnerability" (Step 10
# event findings) so existing assessments never change meaning.
ENTITY_VULN_FINDING = "vuln_finding"
# Step 25 incident rows. Scored from incident severity, confidence, and
# linked-observation counts (see score_incident).
ENTITY_INCIDENT = "incident"
ENTITY_TYPES = (
    ENTITY_ASSET,
    ENTITY_VULNERABILITY,
    ENTITY_CORRELATION,
    ENTITY_VULN_FINDING,
    ENTITY_INCIDENT,
)

SEVERITY_POINTS = {"INFO": 0, "LOW": 10, "MEDIUM": 25, "HIGH": 40, "CRITICAL": 55}

# (minimum score, band), descending. Centralized thresholds.
SCORE_BANDS = ((80, "CRITICAL"), (60, "HIGH"), (40, "MEDIUM"), (20, "LOW"), (0, "INFO"))

# Step 25 priority bands (minimum score, priority), descending.
# Advisory triage order only; derives from the same clamped score.
PRIORITY_BANDS = ((80, "P1"), (60, "P2"), (40, "P3"), (0, "P4"))

RECENCY_FULL_DAYS = 7
RECENCY_FULL_POINTS = 10
RECENCY_PART_DAYS = 30
RECENCY_PART_POINTS = 5

# Bounded recompute: deterministic entity order, capped volume.
MAX_ASSESSMENTS = 1000


def _utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def clamp_score(value: int) -> int:
    """Clamp any integer into the 0–100 score range."""
    return max(0, min(100, value))


def band_for(score: int) -> str:
    """Map a clamped score to its severity band."""
    clamped = clamp_score(score)
    for minimum, band in SCORE_BANDS:
        if clamped >= minimum:
            return band
    return "INFO"  # unreachable: bands cover 0–100


def priority_for(score: int) -> str:
    """Map a clamped score to its priority band (Step 25, advisory only)."""
    clamped = clamp_score(score)
    for minimum, priority in PRIORITY_BANDS:
        if clamped >= minimum:
            return priority
    return "P4"  # unreachable: bands cover 0–100


def severity_points(severity: str | None) -> int:
    return SEVERITY_POINTS.get((severity or "INFO").upper(), 0)


def cvss_points(cvss: object) -> int:
    """0–15 points from a CVSS score; 0 when absent or unparseable."""
    if isinstance(cvss, bool):
        return 0
    score: float | None = None
    if isinstance(cvss, int | float):
        score = float(cvss)
    elif isinstance(cvss, str) and cvss.strip():
        try:
            score = float(cvss.strip())
        except ValueError:
            score = None
    if score is None or score < 0:
        return 0
    return min(15, int(min(score, 10.0) / 10.0 * 15))


def recency_points(days: int | None) -> int:
    """Points from data-relative age; None (unknown) scores 0."""
    if days is None or days < 0:
        return 0 if days is None else RECENCY_FULL_POINTS
    if days <= RECENCY_FULL_DAYS:
        return RECENCY_FULL_POINTS
    if days <= RECENCY_PART_DAYS:
        return RECENCY_PART_POINTS
    return 0


def assessment_id(entity_type: str, entity_id: str, version: str = SCORING_VERSION) -> str:
    """Deterministic identity. No time, no randomness."""
    canonical = json.dumps(
        [IDENTITY_NAMESPACE, version, entity_type, entity_id], separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _finalize(parts: dict[str, object], notes: list[str]) -> dict[str, object]:
    total = (
        10
        + int(parts.get("severity_pts", 0))
        + int(parts.get("signal_pts", 0))
        + int(parts.get("recency_pts", 0))
    )
    score = clamp_score(total)
    return {
        "score": score,
        "severity": band_for(score),
        "priority": priority_for(score),
        "factors": dict(parts),
        "explanation": "Risk score "
        + str(score)
        + " ("
        + band_for(score)
        + ", priority "
        + priority_for(score)
        + "). "
        + " ".join(notes),
    }


def score_vulnerability(
    severity: str | None,
    cvss: object,
    asset_known: bool,
    covering_correlations: int,
    recency_days: int | None,
) -> dict[str, object]:
    """Pure scoring for one vulnerability finding."""
    severity_pts = severity_points(severity)
    cvss_pts = cvss_points(cvss)
    signal_pts = cvss_pts + (5 if asset_known else 0) + min(3 * max(covering_correlations, 0), 9)
    result = _finalize(
        {
            "severity": (severity or "INFO").upper(),
            "severity_pts": severity_pts,
            "cvss": cvss if isinstance(cvss, int | float | str) else None,
            "cvss_pts": cvss_pts,
            "asset_known": asset_known,
            "covering_correlations": max(covering_correlations, 0),
            "signal_pts": signal_pts,
            "recency_days": recency_days,
            "recency_pts": recency_points(recency_days),
        },
        [
            f"Finding severity contributes {severity_pts} points.",
            f"CVSS contributes {cvss_pts} points.",
            "Host matches a known asset (+5)."
            if asset_known
            else "Host is not a known asset (+0).",
            f"Covered by {max(covering_correlations, 0)} correlation(s).",
        ],
    )
    return result


def score_correlation(
    severity: str | None,
    evidence_count: int,
    confidence: int,
    recency_days: int | None,
) -> dict[str, object]:
    """Pure scoring for one correlation."""
    severity_pts = severity_points(severity)
    count = max(evidence_count, 0)
    signal_pts = min(2 * count, 10) + max(min(confidence, 100), 0) // 10
    return _finalize(
        {
            "severity": (severity or "INFO").upper(),
            "severity_pts": severity_pts,
            "evidence_count": count,
            "confidence": confidence,
            "signal_pts": signal_pts,
            "recency_days": recency_days,
            "recency_pts": recency_points(recency_days),
        },
        [
            f"Correlation severity contributes {severity_pts} points.",
            f"{count} supporting evidence item(s), rule confidence {confidence}.",
        ],
    )


def score_asset(
    max_severity: str | None,
    open_ports: int,
    finding_count: int,
    correlation_count: int,
    recency_days: int | None,
) -> dict[str, object]:
    """Pure scoring for one asset."""
    severity_pts = severity_points(max_severity)
    signal_pts = (
        min(2 * max(open_ports, 0), 10)
        + min(3 * max(finding_count, 0), 12)
        + min(5 * max(correlation_count, 0), 10)
    )
    return _finalize(
        {
            "max_severity": (max_severity or "INFO").upper(),
            "severity_pts": severity_pts,
            "open_ports": max(open_ports, 0),
            "finding_count": max(finding_count, 0),
            "correlation_count": max(correlation_count, 0),
            "signal_pts": signal_pts,
            "recency_days": recency_days,
            "recency_pts": recency_points(recency_days),
        },
        [
            f"Strongest linked severity contributes {severity_pts} points.",
            f"{max(open_ports, 0)} open port(s), {max(finding_count, 0)} finding(s), "
            f"{max(correlation_count, 0)} correlation(s) linked.",
        ],
    )


def score_incident(
    severity: str | None,
    confidence: int | None,
    observation_count: int,
    vulnerability_count: int,
    recency_days: int | None,
    relationship_count: int = 0,
) -> dict[str, object]:
    """Pure scoring for one incident (Step 25, advisory classification only).

    Documented factors (unknown inputs score 0, never guessed):

    - incident severity → severity_pts (same table as every entity);
    - observation_count (linked correlation + event observations),
      2 points each, capped at 10;
    - vulnerability_count (linked vulnerability observations),
      3 points each, capped at 9;
    - confidence (correlation strength 0–100, NOT compromise
      probability), integer-divided by 10;
    - recency vs the dataset maximum, same table as every entity.

    Step 29 (informational only): ``relationship_count`` — stored
    Step 29 relationship rows for the incident — is recorded as a
    ``factors`` field and mentioned in the explanation when nonzero, but
    contributes **no points**: the formula and every score are
    byte-for-byte identical to Step 25.

    Maximum 10 + 55 + 10 + 9 + 10 + 10 = 104, clamped to 100;
    minimum 10 (base alone).
    """
    severity_pts = severity_points(severity)
    observations = max(observation_count, 0)
    vulnerabilities = max(vulnerability_count, 0)
    relationships = max(relationship_count, 0)
    confidence_value = max(min(confidence if isinstance(confidence, int) else 0, 100), 0)
    signal_pts = min(2 * observations, 10) + min(3 * vulnerabilities, 9) + confidence_value // 10
    notes = [
        f"Incident severity contributes {severity_pts} points.",
        f"{observations} observation(s) and {vulnerabilities} linked "
        f"vulnerabilit{'y' if vulnerabilities == 1 else 'ies'}, "
        f"correlation confidence {confidence_value}.",
    ]
    if relationships:
        notes.append(
            f"{relationships} stored Step 29 relationship(s) noted as an "
            "informational factor (contributes no points)."
        )
    return _finalize(
        {
            "severity": (severity or "INFO").upper(),
            "severity_pts": severity_pts,
            "observation_count": observations,
            "vulnerability_count": vulnerabilities,
            "confidence": confidence_value,
            "relationship_count": relationships,
            "signal_pts": signal_pts,
            "recency_days": recency_days,
            "recency_pts": recency_points(recency_days),
        },
        notes,
    )


def _naive(moment: datetime) -> datetime:
    if moment.tzinfo is not None:
        return moment.astimezone(UTC).replace(tzinfo=None)
    return moment


def _age_days(newest: datetime | None, reference: datetime | None) -> int | None:
    if newest is None or reference is None:
        return None
    return max((_naive(reference) - _naive(newest)).days, 0)


def _read_cvss(normalized_data: str | None) -> object:
    if not normalized_data:
        return None
    try:
        parsed = json.loads(normalized_data)
    except (ValueError, TypeError):
        return None
    if isinstance(parsed, dict):
        vendor = parsed.get("vendor")
        if isinstance(vendor, dict):
            return vendor.get("cvss")
    return None


def _persist_assessment(
    db: Session,
    entity_type: str,
    entity_id: str,
    result: dict[str, object],
    actor: str,
    reason: str,
) -> tuple[RiskAssessment, bool, bool]:
    """Upsert one assessment row with change audit (Step 25).

    Returns ``(row, created, changed)``. A ``RiskAudit`` row is written
    only when the assessment is new or its score/severity/priority
    differs — repeat calculations with identical outcomes are silent.
    The caller owns the transaction.
    """
    row_id = assessment_id(entity_type, entity_id)
    payload = {
        "score": result["score"],
        "severity": result["severity"],
        "priority": result["priority"],
        "factors": json.dumps(result["factors"], sort_keys=True, default=str),
        "explanation": result["explanation"],
        "calculated_at": _utcnow_naive(),
        "scoring_version": SCORING_VERSION,
    }
    existing = db.scalar(select(RiskAssessment).where(RiskAssessment.id == row_id))
    if existing is None:
        row = RiskAssessment(id=row_id, entity_type=entity_type, entity_id=entity_id, **payload)  # type: ignore[arg-type]
        db.add(row)
        db.flush()
        db.add(
            RiskAudit(
                assessment_id=row_id,
                actor=actor[:128],
                previous_score=None,
                new_score=int(result["score"]),
                classification=str(result["severity"]),
                reason=reason,
            )
        )
        return row, True, True
    changed = (
        existing.score != result["score"]
        or existing.severity != result["severity"]
        or (existing.priority or priority_for(existing.score)) != result["priority"]
    )
    previous_score = existing.score
    for key, value in payload.items():
        setattr(existing, key, value)
    db.flush()
    if changed:
        db.add(
            RiskAudit(
                assessment_id=row_id,
                actor=actor[:128],
                previous_score=previous_score,
                new_score=int(result["score"]),
                classification=str(result["severity"]),
                reason=reason,
            )
        )
    db.refresh(existing)
    return existing, False, changed


def current_incident_assessment(db: Session, incident_id: str) -> RiskAssessment | None:
    """The incident's authoritative assessment for the current scoring version.

    Deterministic identity (``entity_type == "incident"`` plus the current
    :data:`SCORING_VERSION`) means this is a single row: the one the single
    and global calculation paths upsert. ``None`` when the incident has
    never been scored, or when its assessment was evicted by a recompute.
    """
    return db.scalar(
        select(RiskAssessment).where(RiskAssessment.id == assessment_id(ENTITY_INCIDENT, incident_id))
    )


def sync_incident_snapshot(db: Session, incident: Incident) -> RiskAssessment | None:
    """Align the incident's compatibility snapshot with its assessment.

    ``Incident.risk_assessment_id`` and ``Incident.risk_score`` are a
    denormalized mirror of the incident's authoritative assessment (see
    :func:`current_incident_assessment`). When the assessment exists the
    snapshot points at it and copies its score; when it does not, both
    fields are cleared so a score can never outlive its assessment. A
    missing assessment is therefore ``(NULL, NULL)`` — never confused with
    a valid assessment whose score is ``0``.

    The caller owns the transaction; this never commits.
    """
    row = current_incident_assessment(db, incident.id)
    if row is None:
        incident.risk_assessment_id = None
        incident.risk_score = None
        return None
    incident.risk_assessment_id = row.id
    incident.risk_score = row.score
    return row


def _sync_incident_snapshots(
    db: Session,
    scored: list[Incident],
    evicted_incident_ids: set[str],
) -> None:
    """Batched snapshot refresh after a global recompute. Never commits."""
    if scored:
        scores = dict(
            db.execute(
                select(RiskAssessment.entity_id, RiskAssessment.score)
                .where(RiskAssessment.entity_type == ENTITY_INCIDENT)
                .where(RiskAssessment.entity_id.in_([incident.id for incident in scored]))
            ).all()
        )
        for incident in scored:
            own_id = assessment_id(ENTITY_INCIDENT, incident.id)
            if incident.id in scores:
                incident.risk_assessment_id = own_id
                incident.risk_score = scores[incident.id]
            else:
                incident.risk_assessment_id = None
                incident.risk_score = None
    if evicted_incident_ids:
        for incident in db.scalars(
            select(Incident).where(Incident.id.in_(evicted_incident_ids))
        ).all():
            incident.risk_assessment_id = None
            incident.risk_score = None


def recompute_risk(db: Session, actor: str = "system") -> dict[str, object]:
    """Score all assets, findings, correlations, and incidents. Deterministic upserts."""
    reference = db.scalar(select(func.max(SecurityEvent.event_time)))
    if reference is not None:
        reference = _naive(reference)

    assessed: set[tuple[str, str]] = set()
    created = 0
    updated = 0

    def _store(entity_type: str, entity_id: str, result: dict[str, object]) -> None:
        nonlocal created, updated
        assessed.add((entity_type, entity_id))
        _row, was_created, _changed = _persist_assessment(
            db, entity_type, entity_id, result, actor, "Scheduled recompute."
        )
        # Step 10 counting contract preserved: every re-stored row counts
        # as updated (audit rows, by contrast, are written only on change).
        if was_created:
            created += 1
        else:
            updated += 1

    assets = db.scalars(select(Asset).order_by(Asset.id).limit(MAX_ASSESSMENTS)).all()
    for asset in assets:
        open_ports = (
            db.scalar(
                select(func.count(DiscoveredService.id)).where(
                    DiscoveredService.asset_id == asset.id
                )
            )
            or 0
        )
        finding_criteria = [SecurityEvent.destination_ip == asset.ip_address]
        if asset.hostname:
            finding_criteria.append(SecurityEvent.hostname == asset.hostname)
        findings = db.scalars(
            select(SecurityEvent)
            .where(SecurityEvent.event_type == "VULNERABILITY_FINDING")
            .where(*finding_criteria)
            .order_by(SecurityEvent.id)
            .limit(MAX_ASSESSMENTS)
        ).all()
        linked_correlations = db.scalars(
            select(Correlation)
            .where(Correlation.primary_ip == asset.ip_address)
            .order_by(Correlation.id)
        ).all()
        severities = [finding.severity for finding in findings] + [
            correlation.severity for correlation in linked_correlations
        ]
        strongest = max(severities, key=lambda level: SEVERITY_POINTS.get(level, 0), default="INFO")
        candidates = [asset.last_seen]
        candidates.extend(finding.event_time for finding in findings)
        candidates.extend(correlation.window_end for correlation in linked_correlations)
        newest = max((_naive(moment) for moment in candidates if moment is not None), default=None)
        result = score_asset(
            strongest if severities else None,
            open_ports,
            len(findings),
            len(linked_correlations),
            _age_days(newest, reference),
        )
        _store(ENTITY_ASSET, asset.id, result)
        if len(assessed) >= MAX_ASSESSMENTS:
            break

    findings_all = db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.event_type == "VULNERABILITY_FINDING")
        .order_by(SecurityEvent.id)
        .limit(MAX_ASSESSMENTS)
    ).all()
    for finding in findings_all:
        known_criteria = [Asset.ip_address == finding.destination_ip]
        if finding.hostname:
            known_criteria.append(Asset.hostname == finding.hostname)
        asset_known = (db.scalar(select(func.count(Asset.id)).where(*known_criteria)) or 0) > 0
        covering = (
            db.scalar(
                select(func.count(CorrelationEvidence.id)).where(
                    CorrelationEvidence.event_id == finding.id
                )
            )
            or 0
        )
        result = score_vulnerability(
            finding.severity,
            _read_cvss(finding.normalized_data),
            asset_known,
            covering,
            _age_days(finding.event_time, reference),
        )
        _store(ENTITY_VULNERABILITY, finding.id, result)
        if len(assessed) >= MAX_ASSESSMENTS:
            break

    correlations = db.scalars(
        select(Correlation).order_by(Correlation.id).limit(MAX_ASSESSMENTS)
    ).all()
    for correlation in correlations:
        evidence_count = (
            db.scalar(
                select(func.count(CorrelationEvidence.id)).where(
                    CorrelationEvidence.correlation_id == correlation.id
                )
            )
            or 0
        )
        result = score_correlation(
            correlation.severity,
            evidence_count,
            correlation.confidence,
            _age_days(correlation.window_end, reference),
        )
        _store(ENTITY_CORRELATION, correlation.id, result)
        if len(assessed) >= MAX_ASSESSMENTS:
            break

    vuln_findings = db.scalars(
        select(Vulnerability).order_by(Vulnerability.id).limit(MAX_ASSESSMENTS)
    ).all()
    for finding in vuln_findings:
        asset_known = (
            db.scalar(select(func.count(Asset.id)).where(Asset.id == finding.asset_id)) or 0
        ) > 0
        covering = vuln_correlation.covering_correlations(db, finding)
        result = score_vulnerability(
            finding.severity,
            finding.cvss_score,
            asset_known,
            len(covering),
            _age_days(finding.last_seen, reference),
        )
        _store(ENTITY_VULN_FINDING, finding.id, result)
        if len(assessed) >= MAX_ASSESSMENTS:
            break

    incidents = db.scalars(select(Incident).order_by(Incident.id).limit(MAX_ASSESSMENTS)).all()
    relationship_counts: dict[str, int] = {}
    if incidents:  # Step 29: one batched lookup, never per-incident queries
        relationship_counts = dict(
            db.execute(
                select(IncidentRelationship.incident_id, func.count(IncidentRelationship.id))
                .where(IncidentRelationship.incident_id.in_([row.id for row in incidents]))
                .group_by(IncidentRelationship.incident_id)
            ).all()
        )
    scored_incidents: list[Incident] = []
    for incident in incidents:
        links = db.scalars(
            select(IncidentEvidence).where(IncidentEvidence.incident_id == incident.id)
        ).all()
        kinds = [link.evidence_kind for link in links]
        observation_count = sum(1 for kind in kinds if kind in ("event", "correlation"))
        vulnerability_count = sum(1 for kind in kinds if kind == "vulnerability")
        result = score_incident(
            incident.severity,
            incident.confidence,
            observation_count,
            vulnerability_count,
            _age_days(incident.last_seen, reference),
            relationship_count=relationship_counts.get(incident.id, 0),
        )
        _store(ENTITY_INCIDENT, incident.id, result)
        scored_incidents.append(incident)
        if len(assessed) >= MAX_ASSESSMENTS:
            break

    # Drop assessments whose entity no longer exists (deterministic set).
    evicted_incident_ids: set[str] = set()
    for row in db.scalars(select(RiskAssessment)).all():
        if (row.entity_type, row.entity_id) not in assessed:
            if row.entity_type == ENTITY_INCIDENT:
                evicted_incident_ids.add(row.entity_id)
            db.delete(row)
    db.flush()

    # Keep the incident compatibility snapshot aligned with its assessment:
    # refresh every incident scored here and clear any whose assessment was
    # evicted, so a deleted assessment never leaves a stale score behind.
    _sync_incident_snapshots(db, scored_incidents, evicted_incident_ids)
    db.commit()
    logger.info(
        "Risk recompute v%s: %d assessed, %d created, %d updated",
        SCORING_VERSION,
        len(assessed),
        created,
        updated,
    )
    return {
        "assessed": len(assessed),
        "created": created,
        "updated": updated,
        "scoring_version": SCORING_VERSION,
    }


def calculate_incident_risk(
    db: Session, incident_id: str, actor: str, reason: str
) -> RiskAssessment:
    """Calculate (or refresh) one incident's assessment (Step 25).

    Same deterministic inputs as the recompute path; upserts the single
    row, refreshes the incident's compatibility snapshot to match it, and
    commits. Raises ``LookupError`` for unknown incidents. Never touches
    any external system.
    """
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if incident is None:
        raise LookupError(f"No incident with id {incident_id}.")
    links = db.scalars(
        select(IncidentEvidence).where(IncidentEvidence.incident_id == incident.id)
    ).all()
    kinds = [link.evidence_kind for link in links]
    reference = db.scalar(select(func.max(SecurityEvent.event_time)))
    if reference is not None:
        reference = _naive(reference)
    relationship_count = (
        db.scalar(
            select(func.count(IncidentRelationship.id)).where(
                IncidentRelationship.incident_id == incident.id
            )
        )
        or 0
    )
    result = score_incident(
        incident.severity,
        incident.confidence,
        sum(1 for kind in kinds if kind in ("event", "correlation")),
        sum(1 for kind in kinds if kind == "vulnerability"),
        _age_days(incident.last_seen, reference),
        relationship_count=relationship_count,
    )
    row, _created, _changed = _persist_assessment(
        db, ENTITY_INCIDENT, incident.id, result, actor, reason
    )
    sync_incident_snapshot(db, incident)
    db.commit()
    db.refresh(row)
    logger.info("Incident risk calculated for %s: score %s", incident_id[:12], result["score"])
    return row


__all__ = [
    "ENTITY_ASSET",
    "ENTITY_CORRELATION",
    "ENTITY_INCIDENT",
    "ENTITY_TYPES",
    "ENTITY_VULNERABILITY",
    "ENTITY_VULN_FINDING",
    "MAX_ASSESSMENTS",
    "PRIORITY_BANDS",
    "SCORING_VERSION",
    "band_for",
    "calculate_incident_risk",
    "clamp_score",
    "current_incident_assessment",
    "cvss_points",
    "priority_for",
    "recency_points",
    "assessment_id",
    "recompute_risk",
    "score_asset",
    "score_correlation",
    "score_incident",
    "score_vulnerability",
    "severity_points",
    "sync_incident_snapshot",
]
