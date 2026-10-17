"""Step 60 - read-only SOC overview integration.

``GET /api/v1/overview`` (the API behind the SOC dashboard, Step 9) is
documented as a read-only roll-up in which every number is a SQL ``COUNT``
over rows the platform already stores. Until now that surface was only
tested in isolation: Step 9 pinned the payload shape and bounds, Step 58
pinned the aggregated priority buckets at their boundaries. Nothing
asserted that the dashboard roll-up and the per-domain read endpoints it
summarizes actually *agree* on one shared dataset, read back through the
real HTTP stack (routing + auth + service + database).

This module seeds one mixed dataset and then reads it back both through
``/api/v1/overview`` and through the operational list endpoints that a
drill-down would use (assets, events, correlations, incidents, risk,
vulnerabilities, responses). It asserts:

* every overview count equals the total the corresponding list surface
  reports over the same rows;
* ``incidents_open`` equals the incident domain's own non-terminal status
  count (and the overview derives that set from the domain, not from a
  drifted copy of it);
* the severity and priority buckets equal the distributions computed from
  the incidents list and the risk list respectively.

It is strictly read-only: every request is a ``GET``, and a before/after
row-count comparison over every table the reads touch proves nothing was
written. Seeding uses the established in-memory test database, not a live
service or persistent data.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select

from app.database import session as session_module
from tests.test_auth import _admin_headers

TS = datetime(2026, 2, 1, 9, 0, 0)


def _get(client, path: str, headers: dict, **params):  # noqa: ANN001, ANN201
    return client.get(path, headers=headers, params=params or None)


def _seed() -> None:
    """One small, fully known dataset: 2 assets, 3 events, 2 correlations,
    4 incidents (3 non-terminal, one per priority band plus one unscored),
    3 findings (2 open), 2 response actions (1 pending) and 3 assessments."""
    from app.models.assets import Asset, DiscoveredService
    from app.models.correlations import Correlation
    from app.models.incidents import Incident
    from app.models.risk import RiskAssessment
    from app.models.vulnerabilities import Vulnerability
    from app.services import risk_service

    db = session_module.get_session_factory()()
    try:
        db.add_all(
            [
                Asset(
                    id="asset-a",
                    ip_address="10.0.0.1",
                    hostname="a",
                    state="up",
                    first_seen=TS,
                    last_seen=TS,
                ),
                Asset(
                    id="asset-b",
                    ip_address="10.0.0.2",
                    hostname="b",
                    state="up",
                    first_seen=TS,
                    last_seen=TS,
                ),
            ]
        )
        db.add_all(
            [
                DiscoveredService(id="svc-1", asset_id="asset-a", port=22, protocol="tcp"),
                DiscoveredService(id="svc-2", asset_id="asset-a", port=443, protocol="tcp"),
            ]
        )
        db.add_all(
            [
                _event("evt-1", "HIGH", "fp-1"),
                _event("evt-2", "LOW", "fp-2"),
                _event("evt-3", "MEDIUM", "fp-3"),
            ]
        )
        db.add_all(
            [
                Correlation(
                    id="corr-1",
                    rule_id="r1",
                    rule_name="R1",
                    title="c1",
                    severity="CRITICAL",
                    window_start=TS,
                    window_end=TS,
                ),
                Correlation(
                    id="corr-2",
                    rule_id="r2",
                    rule_name="R2",
                    title="c2",
                    severity="HIGH",
                    window_start=TS,
                    window_end=TS,
                ),
            ]
        )
        # (id, key, status, severity, correlation, score, assessment id)
        incidents = [
            ("inc-1", "INC-000001", "OPEN", "CRITICAL", "corr-1", 85, "ra-1"),
            ("inc-2", "INC-000002", "ACKNOWLEDGED", "HIGH", "corr-2", 65, "ra-2"),
            ("inc-3", "INC-000003", "INVESTIGATING", "MEDIUM", "corr-1", 45, "ra-3"),
            ("inc-4", "INC-000004", "RESOLVED", "LOW", "corr-2", None, None),
        ]
        for incident_id, key, status, severity, corr, score, assessment_id in incidents:
            if assessment_id is not None:
                db.add(
                    RiskAssessment(
                        id=assessment_id,
                        entity_type=risk_service.ENTITY_INCIDENT,
                        entity_id=incident_id,
                        score=score,
                        severity=risk_service.band_for(score),
                        priority=risk_service.priority_for(score),
                        scoring_version=risk_service.SCORING_VERSION,
                    )
                )
            db.add(
                Incident(
                    id=incident_id,
                    incident_key=key,
                    title=key,
                    status=status,
                    severity=severity,
                    confidence=70,
                    correlation_id=corr,
                    risk_assessment_id=assessment_id,
                    first_seen=TS,
                    last_seen=TS,
                )
            )
        db.add_all(
            [
                Vulnerability(
                    id="vuln-1",
                    asset_id="asset-a",
                    scanner="seed",
                    scanner_finding_id="f-1",
                    title="v1",
                    severity="HIGH",
                    status="OPEN",
                ),
                Vulnerability(
                    id="vuln-2",
                    asset_id="asset-b",
                    scanner="seed",
                    scanner_finding_id="f-2",
                    title="v2",
                    severity="MEDIUM",
                    status="OPEN",
                ),
                Vulnerability(
                    id="vuln-3",
                    asset_id="asset-a",
                    scanner="seed",
                    scanner_finding_id="f-3",
                    title="v3",
                    severity="LOW",
                    status="RESOLVED",
                ),
            ]
        )
        # act-1 is pending but has no deadline, so a read-path expiry sweep is
        # a no-op and the "reads write nothing" assertion stays meaningful.
        db.add_all(
            [
                _action("act-1", "PENDING_APPROVAL", "198.51.100.7", expires_at=None),
                _action("act-2", "REJECTED", "198.51.100.8", expires_at=None),
            ]
        )
        db.commit()
    finally:
        db.close()


def _event(event_id: str, severity: str, fingerprint: str):  # noqa: ANN001, ANN201
    from app.models.events import SecurityEvent

    return SecurityEvent(
        id=event_id,
        event_time=TS,
        source_type="SURICATA",
        source_name="fixture",
        event_type="fixture.record",
        severity=severity,
        title=event_id,
        fingerprint=fingerprint,
        normalized_data="{}",
    )


def _action(action_id: str, status: str, target: str, *, expires_at):  # noqa: ANN001, ANN201
    from app.models.responses import ResponseAction

    return ResponseAction(
        id=action_id,
        incident_id="inc-1",
        action_type="BLOCK_INDICATOR",
        target_type="IP",
        target_reference=target,
        reason="seeded",
        requested_by="analyst-1",
        status=status,
        dry_run=True,
        policy_version="1.0.0",
        provider="MOCK",
        policy_decision="APPROVAL_REQUIRED",
        approval_required=True,
        rollback_supported=False,
        target_evidence="[]",
        expires_at=expires_at,
    )


def test_overview_counts_match_the_domain_read_surfaces(client, clean_db):
    headers = _admin_headers(client)
    _seed()

    counts = _get(client, "/api/v1/overview", headers).json()["counts"]

    assets = _get(client, "/api/v1/assets", headers, limit=50).json()
    summary = _get(client, "/api/v1/assets/summary", headers).json()
    events = _get(client, "/api/v1/events", headers, limit=50).json()
    correlations = _get(client, "/api/v1/correlations", headers, limit=50).json()
    incidents = _get(client, "/api/v1/incidents", headers, limit=50).json()
    risk = _get(client, "/api/v1/risk", headers, limit=50).json()
    open_findings = _get(client, "/api/v1/vulnerabilities", headers, status="OPEN", limit=50).json()
    responses = _get(client, "/api/v1/responses", headers, limit=50).json()
    pending = _get(
        client, "/api/v1/responses", headers, status="PENDING_APPROVAL", limit=50
    ).json()

    # Each overview number is exactly what the drill-down surface reports.
    assert counts["assets_total"] == assets["total"] == 2
    assert counts["services_total"] == summary["total_services"] == 2
    # ... and the per-asset grouped count (Step 58) sums to the same total.
    assert counts["services_total"] == sum(item["service_count"] for item in assets["items"])
    assert counts["events_total"] == events["total"] == 3
    assert counts["correlations_total"] == correlations["total"] == 2
    assert counts["incidents_total"] == incidents["total"] == 4
    assert counts["risk_assessments_total"] == risk["total"] == 3
    assert counts["vulnerabilities_open"] == open_findings["total"] == 2
    assert counts["response_actions_total"] == responses["total"] == 2
    assert counts["response_actions_pending_approval"] == pending["total"] == 1


def test_open_and_bucket_counts_match_the_incident_surfaces(client, clean_db):
    from app.services import risk_service, soc_overview
    from app.services.incident_service import STATUSES

    headers = _admin_headers(client)
    _seed()

    overview = _get(client, "/api/v1/overview", headers).json()
    incidents = _get(client, "/api/v1/incidents", headers, limit=50).json()
    risk = _get(client, "/api/v1/risk", headers, limit=50).json()

    # "Open" is the domain's own non-terminal status set, derived here the
    # same way the domain derives it (only RESOLVED/CLOSED are terminal).
    non_terminal = {value for value in STATUSES if value not in {"RESOLVED", "CLOSED"}}
    assert non_terminal == {"OPEN", "ACKNOWLEDGED", "INVESTIGATING"}
    assert set(soc_overview.OPEN_INCIDENT_STATUSES) == non_terminal
    from_items = sum(1 for item in incidents["items"] if item["status"] in non_terminal)
    assert from_items == 3
    assert overview["counts"]["incidents_open"] == from_items

    # Severity buckets are the incidents list's own severity distribution.
    severity = {name: 0 for name in soc_overview.SEVERITY_ORDER}
    for item in incidents["items"]:
        severity[item["severity"]] += 1
    assert overview["incidents_by_severity"] == severity

    # Priority buckets come from the linked assessments the risk surface lists;
    # an incident with no assessment is UNSCORED, never an invented band.
    priority = {"P1": 0, "P2": 0, "P3": 0, "P4": 0, "UNSCORED": 0}
    scored = 0
    for item in risk["items"]:
        if item["entity_type"] == risk_service.ENTITY_INCIDENT:
            priority[item["priority"]] += 1
            scored += 1
    priority["UNSCORED"] += incidents["total"] - scored
    assert overview["incidents_by_priority"] == priority


def test_the_entire_read_sequence_writes_nothing(client, clean_db):
    from app.models.assets import Asset, DiscoveredService
    from app.models.correlations import Correlation
    from app.models.events import EventAudit, SecurityEvent
    from app.models.incidents import Incident, IncidentAudit
    from app.models.responses import ResponseAction
    from app.models.risk import RiskAssessment
    from app.models.vulnerabilities import Vulnerability

    headers = _admin_headers(client)
    _seed()

    models = (
        Asset,
        DiscoveredService,
        SecurityEvent,
        EventAudit,
        Correlation,
        Incident,
        IncidentAudit,
        RiskAssessment,
        Vulnerability,
        ResponseAction,
    )

    def snapshot() -> dict[str, int]:
        db = session_module.get_session_factory()()
        try:
            return {
                model.__tablename__: int(
                    db.scalar(select(func.count()).select_from(model)) or 0
                )
                for model in models
            }
        finally:
            db.close()

    before = snapshot()

    _get(client, "/api/v1/overview", headers)
    _get(client, "/api/v1/assets", headers, limit=50)
    _get(client, "/api/v1/assets/summary", headers)
    _get(client, "/api/v1/events", headers, limit=50)
    _get(client, "/api/v1/correlations", headers, limit=50)
    _get(client, "/api/v1/incidents", headers, limit=50)
    _get(client, "/api/v1/risk", headers, limit=50)
    _get(client, "/api/v1/vulnerabilities", headers, status="OPEN", limit=50)
    _get(client, "/api/v1/responses", headers, limit=50)

    assert snapshot() == before
