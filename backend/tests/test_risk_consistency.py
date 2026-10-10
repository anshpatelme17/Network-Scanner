"""Risk consistency: canonical assessment + snapshot sync (Phase 2).

These tests assert the implementation-phase design:
- `RiskAssessment` is canonical; `Incident.risk_score` mirrors the
  assessment (non-authoritative compatibility snapshot).
- `calculate_incident_risk` syncs snapshots before/after the commit scope.
- `recompute_risk` refreshes snapshots for processed incidents and clears
  snapshots for incidents whose assessment was evicted.
- Missing/dangling FK → `(None, None)` for `_incident_risk`; no fallback
  to the raw snapshot.
- Governance and SOC overview read from the FK/assessment, not the raw
  snapshot.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select

from app.database import session as session_module
from app.models.incidents import Incident
from app.models.risk import RiskAssessment
from app.services import incident_service, response_governance, risk_service, soc_overview


def _make_correlation(db, *, correlation_id, severity="MEDIUM", confidence=70):
    from app.models.correlations import Correlation

    moment = datetime(2026, 1, 5, 10, 0)
    corr = Correlation(
        id=correlation_id,
        rule_id="multi-source-target",
        rule_name="Same target, multiple sources",
        title="Correlation for consistency test",
        description="seeded",
        status="open",
        severity=severity,
        confidence=confidence,
        explanation="seeded",
        window_start=moment,
        window_end=moment,
        event_count=2,
    )
    db.add(corr)
    db.flush()
    return corr


def _attach_evidence(db, incident_id, count=2):
    from app.models.incidents import IncidentEvidence
    from app.models.events import SecurityEvent

    moment = datetime(2026, 1, 5, 10, 5)
    for i in range(count):
        ev = SecurityEvent(
            event_type="AUTH_FAILURE",
            severity="MEDIUM",
            title=f"ev-{i}",
            source_ip="192.0.2.10",
            destination_ip="198.51.100.23",
            source_type="WAZUH",
            source_name="sensor",
            event_time=moment,
            external_event_id=f"rc-ev-{incident_id}-{i}",
            fingerprint=f"fp-rc-{incident_id}-{i}",
        )
        db.add(ev)
        db.flush()
        db.add(
            IncidentEvidence(
                incident_id=incident_id,
                evidence_kind="event",
                evidence_id=ev.id,
            )
        )


def test_calculate_incident_risk_syncs_snapshot(client, clean_db):
    db = session_module.get_session_factory()()
    try:
        corr = _make_correlation(db, correlation_id="rc-corr-1", severity="HIGH")
        inc, _ = incident_service.create_incident(db, corr.id, actor="tester")
        _attach_evidence(db, inc.id)
        db.commit()
        inc_id = inc.id
    finally:
        db.close()

    db = session_module.get_session_factory()()
    try:
        risk_service.calculate_incident_risk(db, inc_id, actor="tester", reason="sync")
        db.commit()
        refreshed = db.get(Incident, inc_id)
        assert refreshed is not None
        assert refreshed.risk_assessment_id is not None
        row = db.get(RiskAssessment, refreshed.risk_assessment_id)
        assert row is not None
        assert refreshed.risk_score == row.score
        assert row.entity_type == risk_service.ENTITY_INCIDENT
        assert row.entity_id == inc_id
    finally:
        db.close()


def test_recompute_refreshes_processed_snapshots(client, clean_db):
    db = session_module.get_session_factory()()
    try:
        corr = _make_correlation(db, correlation_id="rc-corr-2", severity="HIGH")
        inc, _ = incident_service.create_incident(db, corr.id, actor="tester")
        _attach_evidence(db, inc.id)
        db.commit()
        inc_id = inc.id
    finally:
        db.close()

    db = session_module.get_session_factory()()
    try:
        # First calculate so both exist and are aligned.
        risk_service.calculate_incident_risk(db, inc_id, actor="tester", reason="init")
        db.commit()
        stale = db.get(Incident, inc_id)
        assert stale.risk_score is not None
        # Introduce a stale snapshot (simulate old code path) by detaching.
        old_score = stale.risk_score
        old_aid = stale.risk_assessment_id
        stale.risk_score = 5
        db.commit()
    finally:
        db.close()

    db = session_module.get_session_factory()()
    try:
        risk_service.recompute_risk(db, actor="system")
        db.commit()
        fixed = db.get(Incident, inc_id)
        assert fixed is not None
        assert fixed.risk_assessment_id == old_aid
        assert fixed.risk_score == old_score
    finally:
        db.close()


def test_missing_assessment_clears_snapshot(client, clean_db):
    db = session_module.get_session_factory()()
    try:
        corr = _make_correlation(db, correlation_id="rc-corr-3", severity="MEDIUM")
        inc, _ = incident_service.create_incident(db, corr.id, actor="tester")
        _attach_evidence(db, inc.id)
        db.commit()
        inc_id = inc.id
    finally:
        db.close()

    db = session_module.get_session_factory()()
    try:
        risk_service.calculate_incident_risk(db, inc_id, actor="tester", reason="init")
        db.commit()
        # Simulate evicted assessment (dangling FK case is similar).
        inc = db.get(Incident, inc_id)
        aid = inc.risk_assessment_id
        inc.risk_assessment_id = None
        inc.risk_score = 99
        # Remove the assessment so that syncing finds nothing.
        if aid:
            ra = db.get(RiskAssessment, aid)
            if ra:
                db.delete(ra)
        db.commit()
        # Clear by syncing against no assessment.
        risk_service.sync_incident_snapshot(db, inc)
        db.commit()
        inc = db.get(Incident, inc_id)
        assert inc.risk_assessment_id is None
        assert inc.risk_score is None
        score, priority = response_governance._incident_risk(db, inc)
        assert score is None and priority is None
    finally:
        db.close()


def test_governance_reads_authoritative_assessment(client, clean_db):
    db = session_module.get_session_factory()()
    try:
        corr = _make_correlation(db, correlation_id="rc-corr-4", severity="HIGH")
        inc, _ = incident_service.create_incident(db, corr.id, actor="tester")
        _attach_evidence(db, inc.id)
        db.commit()
        inc_id = inc.id
    finally:
        db.close()

    db = session_module.get_session_factory()()
    try:
        risk_service.calculate_incident_risk(db, inc_id, actor="tester", reason="init")
        db.commit()
        inc = db.get(Incident, inc_id)
        score, priority = response_governance._incident_risk(db, inc)
        assert score is not None and priority in ("P1", "P2", "P3", "P4")
    finally:
        db.close()


def test_soc_overview_reads_authoritative_assessment(client, clean_db):
    db = session_module.get_session_factory()()
    try:
        corr = _make_correlation(db, correlation_id="rc-corr-5", severity="CRITICAL")
        inc, _ = incident_service.create_incident(db, corr.id, actor="tester")
        _attach_evidence(db, inc.id)
        db.commit()
        inc_id = inc.id
    finally:
        db.close()

    db = session_module.get_session_factory()()
    try:
        risk_service.calculate_incident_risk(db, inc_id, actor="tester", reason="init")
        db.commit()
        overview = soc_overview.build_overview(db, limit=10)
        # The incident should appear in top_incidents with priority from assessment.
        found = any(item["id"] == inc_id for item in overview["top_incidents"])
        assert found
    finally:
        db.close()
