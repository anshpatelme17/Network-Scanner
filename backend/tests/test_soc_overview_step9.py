"""Phase 2 Step 9 — SOC overview endpoint.

Covers the read-only dashboard roll-up: normal data, the empty state,
authorization failure, bounded limits, unknown/malformed input, and
secret-redaction / no-write guarantees.
"""

import httpx
import pytest

OVERVIEW = "/api/v1/overview"
GRAPH = "graph.microsoft.com"
AUTHORITY = "login.microsoftonline.com"


def _install(handler):
    from app.services import http_connector

    http_connector.install_test_transport(httpx.MockTransport(handler))


def _configure(monkeypatch, **overrides):
    from app.core.config import get_settings

    base = {
        "WAZUH_API_URL": "https://wazuh.test:55000",
        "WAZUH_USERNAME": "u",
        "WAZUH_PASSWORD": "s9-wazuh-password",
        "DEFENDER_TENANT_ID": "t",
        "DEFENDER_CLIENT_ID": "c",
        "DEFENDER_CLIENT_SECRET": "s9-defender-secret",
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
    token = client.post(
        "/api/v1/auth/login", json={"username": username, "password": "admin-pass-word-1"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _vendor_handler(wazuh_alerts, defender_alerts):
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


def _wazuh(alert_id, *, minute=0, level=12):
    return {
        "id": alert_id,
        "timestamp": f"2026-01-05T10:{minute:02d}:00.000+0000",
        "rule": {"id": "5712", "level": level, "description": f"rule {alert_id}"},
        "agent": {"id": "001", "name": "ws-01", "ip": "10.0.0.5"},
        "data": {"srcip": "203.0.113.10", "dstip": "10.0.0.5"},
    }


def _defender(alert_id, *, minute=5):
    return {
        "id": alert_id,
        "title": f"alert {alert_id}",
        "severity": "high",
        "category": "Execution",
        "status": "new",
        "firstDetectedDateTime": f"2026-01-05T10:{minute:02d}:00Z",
        "remoteIp": "203.0.113.10",
        "host": {"computerName": "ws-01"},
    }


def _seed_asset(ip, hostname="ws-01"):
    from app.database import session as session_module
    from app.models.assets import Asset

    db = session_module.get_session_factory()()
    try:
        db.add(Asset(ip_address=ip, hostname=hostname, state="up"))
        db.commit()
    finally:
        db.close()


def _seed_incident(*, key, title, severity, risk_score, status="OPEN", last_seen_hour=0):
    from datetime import datetime, timedelta

    from app.database import session as session_module
    from app.models.correlations import Correlation
    from app.models.incidents import Incident
    from app.models.risk import RiskAssessment
    from app.services import risk_service

    db = session_module.get_session_factory()()
    try:
        moment = datetime(2026, 1, 5, 10, 0) + timedelta(hours=last_seen_hour)
        correlation_id = f"s9-corr-{key}"
        db.add(
            Correlation(
                id=correlation_id,
                rule_id="multi-source-target",
                rule_name="Same target, multiple sources",
                title=title,
                description="seeded",
                status="open",
                severity=severity,
                confidence=70,
                explanation="seeded for step 9",
                window_start=moment,
                window_end=moment,
                event_count=2,
            )
        )
        db.flush()
        incident = Incident(
            incident_key=key,
            title=title,
            description="seeded",
            status=status,
            severity=severity,
            confidence=70,
            correlation_id=correlation_id,
            first_seen=moment,
            last_seen=moment,
        )
        db.add(incident)
        db.flush()  # assign the deterministic incident id
        if risk_score is not None:
            # A score is only meaningful with the authoritative assessment
            # it came from; the snapshot mirrors that row (the dashboard
            # reads the assessment, not the bare snapshot).
            assessment_id = risk_service.assessment_id(
                risk_service.ENTITY_INCIDENT, incident.id
            )
            db.add(
                RiskAssessment(
                    id=assessment_id,
                    entity_type=risk_service.ENTITY_INCIDENT,
                    entity_id=incident.id,
                    score=risk_score,
                    severity=risk_service.band_for(risk_score),
                    priority=risk_service.priority_for(risk_score),
                    factors="{}",
                    explanation="seeded for step 9",
                    scoring_version=risk_service.SCORING_VERSION,
                )
            )
            incident.risk_assessment_id = assessment_id
            incident.risk_score = risk_score
        db.commit()
        return incident.id
    finally:
        db.close()


def _overview(client, headers=None, **params):
    return client.get(OVERVIEW, headers=headers, params=params or None)


# ---------------------------------------------------------------------------
# Normal data
# ---------------------------------------------------------------------------


def test_overview_reports_counts_for_a_populated_platform(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    _seed_asset("10.0.0.5")
    try:
        admin = _tokens(client)
        _install(_vendor_handler([_wazuh("s9-w1")], [_defender("s9-d1")]))
        client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin)
        client.post("/api/v1/correlations/recompute", json={}, headers=admin)

        body = _overview(client, admin)
        assert body.status_code == 200, body.text
        data = body.json()

        assert data["version"] == "soc-overview:1.0.0"
        assert data["counts"]["assets_total"] == 1
        assert data["counts"]["assets_active"] == 1
        assert data["counts"]["events_total"] == 2
        assert data["counts"]["correlations_total"] == 1
        # Every documented bucket is present, including zeros.
        assert set(data["incidents_by_severity"]) == {
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
        }
        assert set(data["incidents_by_priority"]) == {"P1", "P2", "P3", "P4", "UNSCORED"}
        assert data["limits"]["max_items"] >= data["limits"]["requested_items"]
        assert "not proof of compromise" in data["disclaimer"]
    finally:
        _clear()


def test_overview_surfaces_incident_severity_and_priority(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        _seed_incident(key="S9A1", title="critical incident", severity="CRITICAL", risk_score=85)
        _seed_incident(
            key="S9A2", title="low incident", severity="LOW", risk_score=10, last_seen_hour=1
        )
        data = _overview(client, admin).json()

        assert data["counts"]["incidents_total"] == 2
        assert data["incidents_by_severity"]["CRITICAL"] == 1
        assert data["incidents_by_priority"]["P1"] == 1
        assert data["incidents_by_priority"]["P4"] == 1

        top = {item["incident_key"]: item for item in data["top_incidents"]}
        assert set(top) == {"S9A1", "S9A2"}
        # Priority is derived from the stored score by the existing band fn.
        assert top["S9A1"]["priority"] == "P1"
        assert top["S9A2"]["priority"] == "P4"
        assert top["S9A1"]["risk_score"] == 85
        assert top["S9A1"]["correlation_id"]
    finally:
        _clear()


def test_unscored_incident_is_reported_not_invented(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        _seed_incident(key="S9B1", title="no score", severity="MEDIUM", risk_score=None)
        data = _overview(client, admin).json()
        item = data["top_incidents"][0]
        assert item["priority"] is None
        assert data["incidents_by_priority"]["UNSCORED"] == 1
        assert data["incidents_by_priority"]["P3"] == 0
    finally:
        _clear()


def test_overview_surfaces_connector_state_without_configuration(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        data = _overview(client, admin).json()
        sources = {item["source"] for item in data["connectors"]}
        assert {"wazuh", "defender"} <= sources
        for item in data["connectors"]:
            # Truth machine output only: state, never a configured value.
            assert set(item) == {
                "source",
                "mode",
                "state",
                "connector_state",
                "last_check_at",
                "last_poll_at",
                "last_error_category",
                "events_retrieved",
            }
    finally:
        _clear()


def test_overview_surfaces_a_bounded_audit_feed(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        _install(_vendor_handler([_wazuh("s9-au1")], [_defender("s9-au2")]))
        client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        data = _overview(client, admin).json()
        assert data["recent_audit"], "ingestion should have produced audit rows"
        actions = {row["action"] for row in data["recent_audit"]}
        assert "EVENT_RECEIVED" in actions
        for row in data["recent_audit"]:
            assert set(row) == {"id", "action", "actor", "event_id", "detail", "created_at"}
            assert len(row["detail"]) <= 200
    finally:
        _clear()


# ---------------------------------------------------------------------------
# Empty state
# ---------------------------------------------------------------------------


def test_overview_on_an_empty_platform_is_valid_not_an_error(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        data = _overview(client, admin).json()
        assert data["counts"]["assets_total"] == 0
        assert data["counts"]["events_total"] == 0
        assert data["counts"]["incidents_total"] == 0
        assert data["top_incidents"] == []
        assert data["recent_audit"] == []
        assert data["incidents_by_severity"]["CRITICAL"] == 0
        assert data["incidents_by_priority"]["UNSCORED"] == 0
    finally:
        _clear()


# ---------------------------------------------------------------------------
# Authorization (fail closed)
# ---------------------------------------------------------------------------


def test_overview_requires_authentication(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    try:
        # Close bootstrap by creating the first user, so enforcement is active.
        _tokens(client)
        assert _overview(client).status_code == 401
    finally:
        _clear()


def test_overview_inherits_bootstrap_only_while_no_user_exists(monkeypatch, client, clean_db):
    """Documented Step 20 behaviour: bootstrap passes reads until a user exists."""
    _configure(monkeypatch)
    try:
        assert _overview(client).status_code == 200
        # Once the first administrator exists, the same request is refused.
        _tokens(client)
        assert _overview(client).status_code == 401
    finally:
        _clear()


def test_overview_refuses_an_invalid_token(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    try:
        _tokens(client)  # close bootstrap
        response = _overview(client, {"Authorization": "Bearer not-a-real-token"})
        assert response.status_code == 401
    finally:
        _clear()


def test_a_viewer_may_read_but_the_payload_is_read_only(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        viewer = _tokens(client, role="VIEWER", username="viewer1", headers=admin)
        assert _overview(client, viewer).status_code == 200
    finally:
        _clear()


# ---------------------------------------------------------------------------
# Bounded input / unknown or malformed input
# ---------------------------------------------------------------------------


def test_limit_is_bounded_server_side(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        for index in range(4):
            _seed_incident(
                key=f"S9C{index}",
                title=f"incident {index}",
                severity="HIGH",
                risk_score=70,
                last_seen_hour=index,
            )
        data = _overview(client, admin, limit=2).json()
        assert len(data["top_incidents"]) == 2
        assert data["limits"]["requested_items"] == 2
        assert data["limits"]["max_items"] >= 2
    finally:
        _clear()


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": -1},
        {"limit": 10_000},
        {"limit": "many"},
        {"limit": 1.5},
    ],
)
def test_out_of_range_or_malformed_limit_is_rejected(monkeypatch, client, clean_db, params):
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        assert _overview(client, admin, **params).status_code == 422
    finally:
        _clear()


def test_unknown_query_parameters_are_ignored_not_obeyed(monkeypatch, client, clean_db):
    """A caller cannot steer severity, priority, ordering or authorization."""
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        _seed_incident(key="S9D1", title="only incident", severity="CRITICAL", risk_score=90)
        data = _overview(
            client,
            admin,
            severity="INFO",
            priority="P4",
            status="RESOLVED",
            order_by="id",
            include_secrets="true",
        ).json()
        assert data["counts"]["incidents_total"] == 1
        assert data["top_incidents"][0]["severity"] == "CRITICAL"
        assert data["top_incidents"][0]["priority"] == "P1"
    finally:
        _clear()


def test_overview_is_deterministic(monkeypatch, client, clean_db):
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        for index in range(5):
            _seed_incident(
                key=f"S9E{index}",
                title=f"incident {index}",
                severity="HIGH",
                risk_score=70,
                last_seen_hour=index,
            )
        first = _overview(client, admin).json()
        first.pop("generated_at")
        for _ in range(3):
            repeat = _overview(client, admin).json()
            repeat.pop("generated_at")
            assert repeat == first
    finally:
        _clear()


# ---------------------------------------------------------------------------
# Security behaviour
# ---------------------------------------------------------------------------


def test_overview_never_returns_credentials_or_tokens(monkeypatch, client, clean_db):
    _configure(monkeypatch, WAZUH_PASSWORD="s9-leak-wazuh-pw", DEFENDER_CLIENT_SECRET="s9-leak-ds")
    try:
        admin = _tokens(client)
        _install(_vendor_handler([_wazuh("s9-s1")], [_defender("s9-s2")]))
        client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin)
        blob = _overview(client, admin).text
        for probe in (
            "s9-leak-wazuh-pw",
            "s9-leak-ds",
            "s9-wazuh-password",
            "s9-defender-secret",
            "mock-jwt",
            "mock-token",
            "Authorization",
            "password",
            "client_secret",
        ):
            assert probe not in blob, probe
    finally:
        _clear()


def test_overview_writes_nothing(monkeypatch, client, clean_db):
    """A dashboard read must not mutate any stored row."""
    from sqlalchemy import func, select

    from app.database import session as session_module
    from app.models.events import EventAudit, SecurityEvent
    from app.models.incidents import Incident, IncidentAudit

    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        _seed_incident(key="S9F1", title="read only", severity="HIGH", risk_score=70)
        before = {}
        db = session_module.get_session_factory()()
        try:
            for model in (Incident, SecurityEvent, EventAudit, IncidentAudit):
                before[model.__tablename__] = db.scalar(select(func.count()).select_from(model))
        finally:
            db.close()

        _overview(client, admin)

        db = session_module.get_session_factory()()
        try:
            for model in (Incident, SecurityEvent, EventAudit, IncidentAudit):
                after = db.scalar(select(func.count()).select_from(model))
                assert after == before[model.__tablename__], model.__tablename__
        finally:
            db.close()
    finally:
        _clear()


def test_overview_exposes_no_action_capability(monkeypatch, client, clean_db):
    """Status only: no instruction, target or verb to act on."""
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        _seed_incident(key="S9G1", title="status only", severity="HIGH", risk_score=70)
        blob = _overview(client, admin).text.lower()
        for forbidden in ("block", "isolate", "remediat", "execute", "command", "kill"):
            assert forbidden not in blob, forbidden
    finally:
        _clear()


def test_overview_reports_response_workflow_as_status_only(monkeypatch, client, clean_db):
    """Pending response actions are counted, never triggered."""
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        data = _overview(client, admin).json()
        assert "response_actions_total" in data["counts"]
        assert "response_actions_pending_approval" in data["counts"]
        assert data["counts"]["response_actions_pending_approval"] == 0
    finally:
        _clear()
