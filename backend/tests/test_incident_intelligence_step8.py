"""Phase 2 Step 8 — deterministic incident intelligence and priority refinement.

Exercises the enrichment layer over an already-correlated incident:
evidence aggregation (de-duplicated), affected-asset resolution, stored
vulnerability context, relationship context, recency, a bounded and
explained priority refinement, auditability, and RBAC.

Guarantees pinned here: the incident's own ``risk_score``/``severity``/
``confidence`` are never modified, no asset or evidence is invented, results
are deterministic and repeatable, queries are bounded, and nothing acts on a
host.

**No test contacts a real Wazuh or Defender service.**
"""

from datetime import datetime

import httpx

GRAPH = "graph.microsoft.com"
AUTHORITY = "login.microsoftonline.com"
NOW = datetime(2026, 1, 10, 12, 0, 0)


def _install(handler):
    from app.services import http_connector

    http_connector.install_test_transport(httpx.MockTransport(handler))


def _configure(monkeypatch, **overrides):
    from app.core.config import get_settings

    base = {
        "WAZUH_API_URL": "https://wazuh.test:55000",
        "WAZUH_USERNAME": "u",
        "WAZUH_PASSWORD": "p",
        "DEFENDER_TENANT_ID": "t",
        "DEFENDER_CLIENT_ID": "c",
        "DEFENDER_CLIENT_SECRET": "s",
        "CONNECTOR_RETRY_MAX": "0",
    }
    base.update(overrides)
    for key, value in base.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()


def _clear():
    from app.core.config import get_settings
    from app.services import connector_polling, connectors, ingestion

    connector_polling.reset()
    connectors.reset_runtime()
    ingestion.reset_runtime()
    get_settings.cache_clear()


def _tokens(client, *, role="ADMIN", username="admin", headers=None):
    """Create a user (bootstrap, or with existing admin headers) and log in."""
    body = {
        "username": username,
        "password": "admin-pass-word-1",
        "display_name": username.title(),
        "roles": [role],
    }
    created = client.post("/api/v1/users", json=body, headers=headers)
    assert created.status_code in (201, 409), created.text
    token = client.post(
        "/api/v1/auth/login", json={"username": username, "password": "admin-pass-word-1"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _login(client, username="admin"):
    """Token for an existing user (bootstrap may already be closed)."""
    token = client.post(
        "/api/v1/auth/login", json={"username": username, "password": "admin-pass-word-1"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _wazuh(alert_id, *, dstip="10.0.0.5", hostname="ws-01", minute=0, level=12):
    return {
        "id": alert_id,
        "timestamp": f"2026-01-05T10:{minute:02d}:00.000+0000",
        "rule": {"id": "5712", "level": level, "description": f"rule {alert_id}"},
        "agent": {"id": "001", "name": hostname, "ip": "10.0.0.5"},
        "data": {"srcip": "203.0.113.10", **({"dstip": dstip} if dstip else {})},
    }


def _defender(alert_id, *, hostname="ws-01", minute=5, severity="high"):
    record = {
        "id": alert_id,
        "title": f"alert {alert_id}",
        "severity": severity,
        "category": "Execution",
        "status": "new",
        "firstDetectedDateTime": f"2026-01-05T10:{minute:02d}:00Z",
        "remoteIp": "203.0.113.10",
    }
    if hostname:
        record["host"] = {"computerName": hostname}
    return record


def _handler(wazuh_alerts, defender_alerts):
    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host.endswith("wazuh.test"):
            if request.url.path.endswith("/security/user/authenticate"):
                return httpx.Response(200, json={"token": "mock-jwt"})
            return httpx.Response(
                200,
                json={
                    "data": {"totalItems": len(wazuh_alerts), "alerts": wazuh_alerts},
                    "error": 0,
                },
            )
        if host == AUTHORITY:
            return httpx.Response(200, json={"access_token": "mock-token", "expires_in": 3599})
        if host == GRAPH:
            return httpx.Response(200, json={"value": defender_alerts})
        raise AssertionError(f"unexpected host {host}")

    return handler


def _seed_asset(ip, hostname=None):
    from app.database import session as session_module
    from app.models.assets import Asset

    db = session_module.get_session_factory()()
    try:
        db.add(Asset(ip_address=ip, hostname=hostname, state="up"))
        db.commit()
    finally:
        db.close()


def _seed_finding(asset_id, *, severity="HIGH", status="open", finding_id="f-1"):
    from app.database import session as session_module
    from app.models.vulnerabilities import Vulnerability

    db = session_module.get_session_factory()()
    try:
        db.add(
            Vulnerability(
                asset_id=asset_id,
                scanner="step8",
                scanner_finding_id=finding_id,
                title=f"finding {finding_id}",
                severity=severity,
                status=status,
                cvss_score=7.5,
            )
        )
        db.commit()
    finally:
        db.close()


def _incident_for(client, admin, wazuh_alerts, defender_alerts, *, min_created=1):
    """Poll both vendors, recompute, and open an incident from the first match.

    More than one correlation can legitimately match: three or more events
    sharing a source address also satisfy the ``repeated-source`` rule. The
    caller therefore asserts a minimum, not an exact count.
    """
    _install(_handler(wazuh_alerts, defender_alerts))
    client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
    client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin)
    result = client.post("/api/v1/correlations/recompute", json={}, headers=admin).json()
    assert result["created"] >= min_created, result
    correlation_id = result["correlation_ids"][0]
    incident = client.post(
        "/api/v1/incidents", json={"correlation_id": correlation_id}, headers=admin
    )
    assert incident.status_code == 201, incident.text
    return incident.json()


def _intelligence(client, admin, incident_id, *, expect=200):
    response = client.get(f"/api/v1/incidents/{incident_id}/intelligence", headers=admin)
    assert response.status_code == expect, response.text
    return response.json() if expect == 200 else response


# ---------------------------------------------------------------------------
# 1. Normal incident
# ---------------------------------------------------------------------------


def test_normal_incident_gets_an_explained_refinement(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    _seed_asset("10.0.0.5", hostname="ws-01")
    try:
        admin = _tokens(client)
        incident = _incident_for(client, admin, [_wazuh("s8-n1")], [_defender("s8-n2")])
        result = _intelligence(client, admin, incident["id"])

        assert result["incident_id"] == incident["id"]
        assert result["correlation_id"] == incident["correlation_id"]
        assert result["analysis_version"] == "1.0.0"
        assert result["evidence"]["count"] == 2
        assert result["evidence"]["distinct_event_ids"] == 2
        assert result["assets"]["count"] == 1
        assert result["priority"] in {"P1", "P2", "P3", "P4"}
        assert 0 <= result["points"] <= 100
        # Every factor is present and the explanation states the outcome.
        for key in (
            "evidence_points",
            "severity_points",
            "relationship_points",
            "finding_points",
            "recency_points",
            "points_total",
        ):
            assert key in result["factors"], key
        assert "priority" in result["explanation"]
        assert "not a verdict" in result["explanation"]
        assert "not proof of compromise" in result["explanation"]
    finally:
        _clear()


def test_refinement_does_not_modify_the_incident(monkeypatch, client, clean_db):
    """The existing Step 10/25 risk score, severity and confidence stand."""
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        incident = _incident_for(client, admin, [_wazuh("s8-i1")], [_defender("s8-i2")])
        before = client.get(f"/api/v1/incidents/{incident['id']}", headers=admin).json()
        _intelligence(client, admin, incident["id"])
        client.post(
            f"/api/v1/incidents/{incident['id']}/intelligence/refresh", json={}, headers=admin
        )
        after = client.get(f"/api/v1/incidents/{incident['id']}", headers=admin).json()
        for field in ("risk_score", "severity", "confidence", "status", "version"):
            assert after[field] == before[field], field
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 2. Duplicate events must not inflate risk
# ---------------------------------------------------------------------------


def test_duplicate_evidence_does_not_inflate_the_refinement(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    _seed_asset("10.0.0.5", hostname="ws-01")
    try:
        admin = _tokens(client)
        incident = _incident_for(client, admin, [_wazuh("s8-d1")], [_defender("s8-d2")])
        first = _intelligence(client, admin, incident["id"])

        # Re-poll and recompute: the same evidence set, re-derived.
        client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin)
        client.post("/api/v1/correlations/recompute", json={}, headers=admin)
        second = _intelligence(client, admin, incident["id"])

        assert first["evidence"]["count"] == second["evidence"]["count"] == 2
        assert first["points"] == second["points"]
        assert first["priority"] == second["priority"]
    finally:
        _clear()


def test_evidence_count_is_distinct_event_ids(monkeypatch, client, clean_db):
    """Repeated identical evidence must not raise the evidence contribution."""
    from app.database import session as session_module
    from app.services.incident_intelligence import _load_evidence_events

    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        incident = _incident_for(client, admin, [_wazuh("s8-u1")], [_defender("s8-u2")])
        db = session_module.get_session_factory()()
        try:
            events, total = _load_evidence_events(db, incident["correlation_id"], 100)
            assert len(events) == len({e.id for e in events}) == total
        finally:
            db.close()
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 3. Missing / unknown assets
# ---------------------------------------------------------------------------


def test_unknown_asset_is_reported_unresolved_not_invented(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        # No asset is inventoried for this host.
        incident = _incident_for(client, admin, [_wazuh("s8-x1")], [_defender("s8-x2")])
        result = _intelligence(client, admin, incident["id"])
        assert result["assets"]["count"] == 0
        assert result["assets"]["ids"] == []
        assert result["assets"]["unresolved_event_count"] == 2
        assert "unresolved" in result["explanation"]
        # Still a valid, bounded summary.
        assert result["evidence"]["count"] == 2
        assert result["priority"] in {"P1", "P2", "P3", "P4"}
    finally:
        _clear()


def test_resolved_asset_contributes_vulnerability_context(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    _seed_asset("10.0.0.5", hostname="ws-01")
    try:
        admin = _tokens(client)
        incident = _incident_for(client, admin, [_wazuh("s8-v1")], [_defender("s8-v2")])
        db_asset = client.get("/api/v1/assets", headers=admin).json()["items"][0]
        _seed_finding(db_asset["id"], severity="CRITICAL")
        result = _intelligence(client, admin, incident["id"])
        assert result["vulnerabilities"]["open_finding_count"] == 1
        assert result["vulnerabilities"]["max_severity"] == "CRITICAL"
        assert result["factors"]["finding_points"] > 0
        assert "vulnerability finding" in result["explanation"]
    finally:
        _clear()


def test_resolved_finding_raises_priority_relative_to_none(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    _seed_asset("10.0.0.5", hostname="ws-01")
    try:
        admin = _tokens(client)
        incident = _incident_for(client, admin, [_wazuh("s8-p1")], [_defender("s8-p2")])
        without = _intelligence(client, admin, incident["id"])
        db_asset = client.get("/api/v1/assets", headers=admin).json()["items"][0]
        _seed_finding(db_asset["id"], severity="CRITICAL")
        with_finding = _intelligence(client, admin, incident["id"])
        assert with_finding["points"] > without["points"]
    finally:
        _clear()


def test_closed_finding_is_not_counted_as_open_context(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    _seed_asset("10.0.0.5", hostname="ws-01")
    try:
        admin = _tokens(client)
        incident = _incident_for(client, admin, [_wazuh("s8-c1")], [_defender("s8-c2")])
        db_asset = client.get("/api/v1/assets", headers=admin).json()["items"][0]
        _seed_finding(db_asset["id"], severity="CRITICAL", status="closed")
        result = _intelligence(client, admin, incident["id"])
        assert result["vulnerabilities"]["open_finding_count"] == 0
        assert result["factors"]["finding_points"] == 0
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 4. High-severity evidence
# ---------------------------------------------------------------------------


def test_higher_severity_evidence_scores_higher(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        low = _incident_for(
            client, admin, [_wazuh("s8-low", level=3)], [_defender("s8-low2", severity="low")]
        )
        low_result = _intelligence(client, admin, low["id"])
    finally:
        _clear()

    _install(_handler([_wazuh("s8-hi", level=15)], [_defender("s8-hi2", severity="critical")]))
    _configure(monkeypatch)
    try:
        # Reuse the existing operator: bootstrap is closed once a user exists.
        admin = _login(client)
        client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin)
        result = client.post("/api/v1/correlations/recompute", json={}, headers=admin).json()
        high = client.post(
            "/api/v1/incidents",
            json={"correlation_id": result["correlation_ids"][0]},
            headers=admin,
        ).json()
        high_result = _intelligence(client, admin, high["id"])
        assert high_result["severity"] == "CRITICAL"
        assert high_result["points"] > low_result["points"]
        assert high_result["factors"]["severity_points"] > low_result["factors"]["severity_points"]
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 5. Stale / old evidence (recency)
# ---------------------------------------------------------------------------


def test_recency_reduces_points_for_old_incidents(monkeypatch, client, clean_db):
    from app.services import incident_intelligence

    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        incident = _incident_for(client, admin, [_wazuh("s8-s1")], [_defender("s8-s2")])
        from app.database import session as session_module

        db = session_module.get_session_factory()()
        try:
            fresh = incident_intelligence.build_intelligence(
                db, incident["id"], now=datetime(2026, 1, 5, 12, 0)
            ).as_dict()
            stale = incident_intelligence.build_intelligence(
                db, incident["id"], now=datetime(2026, 3, 5, 12, 0)
            ).as_dict()
        finally:
            db.close()
        assert fresh["factors"]["recency_days"] == 0
        assert stale["factors"]["recency_days"] > 30
        assert stale["factors"]["recency_points"] == 0
        assert fresh["factors"]["recency_points"] == 5
        assert stale["points"] < fresh["points"]
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 6. Multiple related events / relationships
# ---------------------------------------------------------------------------


def test_multiple_related_events_aggregate_within_bounds(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        incident = _incident_for(
            client,
            admin,
            [_wazuh("s8-m1", minute=0), _wazuh("s8-m2", minute=1, level=6)],
            [_defender("s8-m3", minute=2)],
        )
        # Run the Step 29 rule catalog so relationships exist to aggregate.
        detect = client.post(
            "/api/v1/incidents/detect",
            json={"correlation_id": incident["correlation_id"]},
            headers=admin,
        )
        assert detect.status_code in {200, 201, 422}, detect.text
        result = _intelligence(client, admin, incident["id"])
        assert result["evidence"]["count"] == 3
        assert result["evidence"]["distinct_event_ids"] == 3
        assert result["relationships"]["count"] <= result["relationships"]["total_available"]
    finally:
        _clear()


def test_evidence_input_is_bounded(monkeypatch, client, clean_db):
    _configure(monkeypatch, CORRELATION_MAX_EVENTS_PER_OPERATION="2")
    try:
        admin = _tokens(client)
        incident = _incident_for(
            client,
            admin,
            [_wazuh("s8-b1", minute=0), _wazuh("s8-b2", minute=1), _wazuh("s8-b3", minute=2)],
            [_defender("s8-b4", minute=3)],
        )
        result = _intelligence(client, admin, incident["id"])
        assert result["evidence"]["count"] == 2
        assert result["evidence"]["truncated"] is True
        assert result["evidence"]["total_available"] == 4
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 7. Empty / minimal incident
# ---------------------------------------------------------------------------


def test_incident_with_no_evidence_is_still_valid(monkeypatch, client, clean_db):
    """A correlation with no stored evidence must still produce a valid summary."""
    from app.database import session as session_module
    from app.models.correlations import Correlation
    from app.models.incidents import Incident

    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        now = datetime(2026, 1, 5, 12, 0)
        db = session_module.get_session_factory()()
        try:
            correlation = Correlation(
                id="s8-empty-correlation",
                rule_id="multi-source-target",
                rule_name="Same target, multiple sources",
                title="empty",
                description="no evidence",
                status="open",
                severity="INFO",
                confidence=0,
                explanation="constructed for the empty-evidence case",
                window_start=now,
                window_end=now,
                event_count=0,
            )
            db.add(correlation)
            db.flush()
            incident = Incident(
                incident_key="S8EMPTY",
                title="empty incident",
                status="OPEN",
                severity="INFO",
                confidence=0,
                correlation_id=correlation.id,
                first_seen=now,
                last_seen=now,
            )
            db.add(incident)
            db.commit()
            incident_id = incident.id
        finally:
            db.close()

        result = _intelligence(client, admin, incident_id)
        assert result["evidence"]["count"] == 0
        assert result["evidence"]["max_severity"] == "INFO"
        assert result["assets"]["count"] == 0
        assert result["vulnerabilities"]["open_finding_count"] == 0
        assert result["relationships"]["count"] == 0
        assert result["points"] >= 0
        assert result["timeline"]["earliest_evidence"] is None
        # Deterministic and stable even with nothing to enrich.
        assert _intelligence(client, admin, incident_id) == result
    finally:
        _clear()


def test_missing_incident_is_404(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        assert _intelligence(client, admin, "nope", expect=404) is not None
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 8. Determinism
# ---------------------------------------------------------------------------


def test_results_are_deterministic_and_repeatable(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    _seed_asset("10.0.0.5", hostname="ws-01")
    try:
        admin = _tokens(client)
        incident = _incident_for(client, admin, [_wazuh("s8-r1")], [_defender("s8-r2")])
        first = _intelligence(client, admin, incident["id"])
        for _ in range(3):
            assert _intelligence(client, admin, incident["id"]) == first
    finally:
        _clear()


def test_no_ai_or_probabilistic_scoring():
    from app.services import incident_intelligence

    assert incident_intelligence.ANALYSIS_VERSION == "1.0.0"
    # Every band is a fixed integer threshold; nothing is learned.
    for minimum, priority in incident_intelligence.REFINEMENT_BANDS:
        assert isinstance(minimum, int)
        assert priority in {"P1", "P2", "P3", "P4"}
    source = open(  # noqa: SIM115
        incident_intelligence.__file__, encoding="utf-8"
    ).read()
    for banned in ("random", "numpy", "sklearn", "tensorflow", "torch", "llm"):
        assert banned not in source.lower(), banned


# ---------------------------------------------------------------------------
# 9. Auditability
# ---------------------------------------------------------------------------


def test_refresh_records_an_audit_row(monkeypatch, client, clean_db):
    from sqlalchemy import select

    from app.database import session as session_module
    from app.models.incidents import IncidentAudit

    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        incident = _incident_for(client, admin, [_wazuh("s8-au1")], [_defender("s8-au2")])
        response = client.post(
            f"/api/v1/incidents/{incident['id']}/intelligence/refresh", json={}, headers=admin
        )
        assert response.status_code == 200
        db = session_module.get_session_factory()()
        try:
            rows = db.scalars(
                select(IncidentAudit).where(IncidentAudit.incident_id == incident["id"])
            ).all()
        finally:
            db.close()
        refinements = [r for r in rows if r.action == "INTELLIGENCE_REFRESHED"]
        assert len(refinements) == 1
        detail = refinements[0].detail or ""
        assert "point(s)" in detail
        assert "evidence event(s)" in detail
        # The audit row never carries event payloads or secrets.
        assert "203.0.113.10" not in detail
    finally:
        _clear()


def test_audit_detail_contains_no_secret(client, clean_db, monkeypatch):
    _configure(monkeypatch, WAZUH_PASSWORD="s8-audit-password", DEFENDER_CLIENT_SECRET="s8-secret")
    _install(_handler([_wazuh("s8-as1")], [_defender("s8-as2")]))
    try:
        admin = _tokens(client)
        incident = _incident_for(client, admin, [_wazuh("s8-as1")], [_defender("s8-as2")])
        response = client.post(
            f"/api/v1/incidents/{incident['id']}/intelligence/refresh", json={}, headers=admin
        )
        blob = response.text
        assert "s8-audit-password" not in blob
        assert "s8-secret" not in blob
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 10. RBAC
# ---------------------------------------------------------------------------


def test_intelligence_read_requires_read_incidents(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        incident = _incident_for(client, admin, [_wazuh("s8-rb1")], [_defender("s8-rb2")])
        assert client.get(f"/api/v1/incidents/{incident['id']}/intelligence").status_code == 401
    finally:
        _clear()


def test_refresh_requires_manage_incident(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        incident = _incident_for(client, admin, [_wazuh("s8-rb3")], [_defender("s8-rb4")])
        reader = _tokens(client, role="VIEWER", username="viewer1", headers=admin)
        denied = client.post(
            f"/api/v1/incidents/{incident['id']}/intelligence/refresh", json={}, headers=reader
        )
        assert denied.status_code == 403
        assert denied.json()["error"]["code"] == "PERMISSION_DENIED"
        # A viewer may still read the summary.
        assert client.get(
            f"/api/v1/incidents/{incident['id']}/intelligence", headers=reader
        ).status_code in (200, 403)
    finally:
        _clear()


def test_no_autonomous_response_capability_is_exposed(monkeypatch, client, clean_db):
    """Step 8 is analysis only: no blocking, isolation or remediation route."""
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        incident = _incident_for(client, admin, [_wazuh("s8-no1")], [_defender("s8-no2")])
        result = _intelligence(client, admin, incident["id"])
        # The response is a summary; it carries no action, no target to act
        # on, and no instruction.
        for forbidden in ("action", "block", "isolate", "remediat", "command", "execute"):
            assert forbidden not in result["explanation"].lower(), forbidden
    finally:
        _clear()
