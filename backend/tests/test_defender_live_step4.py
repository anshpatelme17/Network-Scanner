"""Phase 2 Step 4 — Microsoft Defender connector: specification gap coverage.

The Defender client, its OAuth2 token provider, bounded ``@odata.nextLink``
retrieval, connector lifecycle, audit trail and RBAC were built in Step 27
and are covered by ``test_connectors_step27.py`` (token exchange, nextLink
allow-list, allow-listed nextLink following, repeated-cursor termination,
400 rejection) and ``test_defender.py`` (adapter mapping, dedup, ingest).

This module closes the Step 4 cases those modules do not exercise and
re-asserts the read-only guarantee.

**No test in this module contacts a real Microsoft Defender or Microsoft
identity environment, or any other external service.** Every HTTP
interaction goes through ``httpx.MockTransport`` installed by
``app.services.http_connector``.
"""

import json

import httpx
import pytest

GRAPH_ALERT = {
    "id": "da1a2b3c",
    "title": "Suspicious process executed",
    "description": "Mock Defender alert",
    "severity": "high",
    "category": "Execution",
    "status": "new",
    "firstDetectedDateTime": "2026-01-05T10:00:00Z",
    "host": {"computerName": "ws-01"},
}

GRAPH = "graph.microsoft.com"
AUTHORITY = "login.microsoftonline.com"

BASE_ENV = {
    "DEFENDER_TENANT_ID": "tenant-verify",
    "DEFENDER_CLIENT_ID": "client-verify",
    "DEFENDER_CLIENT_SECRET": "client-secret-verify-value",
    "DEFENDER_API_ENDPOINT": f"https://{GRAPH}/v1.0",
    "DEFENDER_AUTHORITY": f"https://{AUTHORITY}",
    "CONNECTOR_RETRY_MAX": "0",
}


def _install(handler):
    from app.services import http_connector

    http_connector.install_test_transport(httpx.MockTransport(handler))


def _configure(monkeypatch, **overrides):
    from app.core.config import get_settings

    for key, value in {**BASE_ENV, **overrides}.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    return get_settings()


def _clear_settings():
    from app.core.config import get_settings

    get_settings.cache_clear()


def _tokens(client):
    client.post(
        "/api/v1/users",
        json={
            "username": "admin",
            "password": "admin-pass-word-1",
            "display_name": "A",
            "roles": ["ADMIN"],
        },
    )
    token = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "admin-pass-word-1"}
    ).json()["access_token"]
    admin = {"Authorization": f"Bearer {token}"}
    client.post(
        "/api/v1/users",
        json={
            "username": "viewer1",
            "password": "viewer-pass-1234",
            "display_name": "V",
            "roles": ["VIEWER"],
        },
        headers=admin,
    )
    viewer_token = client.post(
        "/api/v1/auth/login", json={"username": "viewer1", "password": "viewer-pass-1234"}
    ).json()["access_token"]
    return admin, {"Authorization": f"Bearer {viewer_token}"}


def _audits():
    from sqlalchemy import select

    from app.database import session as session_module
    from app.models.events import EventAudit

    db = session_module.get_session_factory()()
    try:
        return [(row.action, row.detail or "") for row in db.scalars(select(EventAudit)).all()]
    finally:
        db.close()


def _handler(pages=None, token_status=200, token_body=None, token_text=None, state=None):
    """Mock Graph + identity platform. ``pages`` is consumed in order."""

    remaining = list(pages) if pages else []

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if state is not None:
            state.setdefault("calls", []).append(f"{request.method} {host}{request.url.path}")
        if host == AUTHORITY:
            if token_status != 200:
                return httpx.Response(token_status, json={"error": "invalid_client"})
            if token_text is not None:
                return httpx.Response(200, text=token_text)
            body = (
                token_body
                if token_body is not None
                else {"token_type": "Bearer", "expires_in": 3599, "access_token": "mock-token"}
            )
            return httpx.Response(200, json=body)
        if host == GRAPH:
            if not remaining:
                return httpx.Response(200, json={"value": []})
            page = remaining.pop(0) if len(remaining) > 1 else remaining[0]
            return httpx.Response(200, json=page)
        raise AssertionError(f"unexpected host {host}")

    return handler


# ---------------------------------------------------------------------------
# Unconfigured
# ---------------------------------------------------------------------------


def test_unconfigured_defender_stays_not_configured_and_app_is_healthy(
    monkeypatch, client, clean_db
):
    for key in (
        "DEFENDER_TENANT_ID",
        "DEFENDER_CLIENT_ID",
        "DEFENDER_CLIENT_SECRET",
        "WAZUH_API_URL",
        "WAZUH_USERNAME",
        "WAZUH_PASSWORD",
    ):
        monkeypatch.setenv(key, "")
    from app.core.config import get_settings

    get_settings.cache_clear()
    try:
        admin, _ = _tokens(client)
        assert client.get("/api/v1/health").status_code == 200
        assert client.get("/api/v1/ready").status_code == 200
        status = client.get("/api/v1/events/connectors/defender", headers=admin).json()
        assert status["connector_state"] == "NOT_CONFIGURED"
        checked = client.post("/api/v1/events/connectors/defender/check", headers=admin).json()
        assert checked["connector_state"] == "NOT_CONFIGURED"
    finally:
        _clear_settings()


def test_partial_defender_configuration_is_not_claimed_connected(monkeypatch, client, clean_db):
    """A client id without a secret must not report CONNECTED."""
    _configure(monkeypatch, DEFENDER_CLIENT_SECRET="")
    try:
        admin, _ = _tokens(client)
        status = client.get("/api/v1/events/connectors/defender", headers=admin).json()
        assert status["connector_state"] != "CONNECTED"
        assert status["connector_state"] in {"NOT_CONFIGURED", "ERROR"}
    finally:
        _clear_settings()


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [400, 401, 403])
def test_token_endpoint_rejection_is_auth_failed(monkeypatch, client, clean_db, status):
    _install(_handler(token_status=status))
    _configure(monkeypatch)
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/defender/check", headers=admin).json()
        assert body["connector_state"] == "AUTH_FAILED"
        assert body["last_error_category"] == "AUTH_FAILED"
        assert any(action == "CONNECTOR_AUTH_FAILED" for action, _ in _audits())
    finally:
        _clear_settings()


@pytest.mark.parametrize(
    "token_body",
    [
        {"token_type": "Bearer", "expires_in": 3599},  # no access_token
        {"access_token": ""},  # empty token
        {"access_token": "   "},  # whitespace token
        {"access_token": 12345},  # token is not a string
    ],
)
def test_malformed_token_response_is_refused(monkeypatch, client, clean_db, token_body):
    _install(_handler(token_body=token_body))
    settings = _configure(monkeypatch)
    try:
        from app.services.defender_client import DefenderClient, DefenderConfig
        from app.services.http_connector import HttpErrorCategory

        outcome = DefenderClient(DefenderConfig.from_settings(settings)).check()
        assert outcome.ok is False, "a tokenless response must not count as connected"
        assert outcome.category is HttpErrorCategory.MALFORMED_RESPONSE
    finally:
        _clear_settings()


def test_non_json_token_response_is_refused(monkeypatch, client, clean_db):
    """An HTML error page from a proxy must not be read as a token."""
    _install(_handler(token_text="<html>sign-in required</html>"))
    settings = _configure(monkeypatch)
    try:
        from app.services.defender_client import DefenderClient, DefenderConfig
        from app.services.http_connector import HttpErrorCategory

        outcome = DefenderClient(DefenderConfig.from_settings(settings)).check()
        assert outcome.ok is False
        assert outcome.category is HttpErrorCategory.MALFORMED_RESPONSE
    finally:
        _clear_settings()


def test_successful_token_exchange_reports_connected_only_after_a_real_response(
    monkeypatch, client, clean_db
):
    _install(_handler(pages=[{"value": [dict(GRAPH_ALERT)]}]))
    _configure(monkeypatch)
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/defender/check", headers=admin).json()
        assert body["connector_state"] == "CONNECTED"
        assert any(action == "CONNECTOR_CONNECTED" for action, _ in _audits())
        assert any(action == "CONNECTOR_CHECK_STARTED" for action, _ in _audits())
    finally:
        _clear_settings()


# ---------------------------------------------------------------------------
# Transport failures
# ---------------------------------------------------------------------------


def test_timeout_is_reported_as_timeout(monkeypatch, client, clean_db):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("mock timeout", request=request)

    _install(handler)
    _configure(monkeypatch)
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/defender/check", headers=admin).json()
        assert body["connector_state"] != "CONNECTED"
        assert body["last_error_category"] == "TIMEOUT"
    finally:
        _clear_settings()


def test_connection_failure_is_reported_as_unavailable(monkeypatch, client, clean_db):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("mock connection refused", request=request)

    _install(handler)
    _configure(monkeypatch)
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/defender/check", headers=admin).json()
        assert body["connector_state"] == "UNAVAILABLE"
        assert body["last_error_category"] == "CONNECTION_ERROR"
        assert any(action == "CONNECTOR_UNAVAILABLE" for action, _ in _audits())
    finally:
        _clear_settings()


def test_tls_failure_never_claims_connected(monkeypatch, client, clean_db):
    """A TLS-level failure must surface as a connector state, not a traceback."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("mock TLS handshake refused", request=request)

    _install(handler)
    _configure(monkeypatch)
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/defender/check", headers=admin).json()
        assert body["connector_state"] != "CONNECTED"
        assert body["connector_state"] in {"UNAVAILABLE", "ERROR"}
        blob = json.dumps(body)
        assert "Traceback" not in blob
        assert "httpx" not in blob
    finally:
        _clear_settings()


def test_tls_verification_is_on_by_default_and_configurable(monkeypatch, client, clean_db):
    from app.services.defender_client import DefenderClient, DefenderConfig

    settings = _configure(monkeypatch)
    try:
        assert DefenderClient(DefenderConfig.from_settings(settings))._api_http.verify_tls is True
        assert DefenderClient(DefenderConfig.from_settings(settings))._token_http.verify_tls is True
        off = _configure(monkeypatch, CONNECTOR_VERIFY_TLS="false")
        assert DefenderClient(DefenderConfig.from_settings(off))._api_http.verify_tls is False
    finally:
        _clear_settings()


def test_rate_limited_is_reported_with_retry_after(monkeypatch, client, clean_db):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == AUTHORITY:
            return httpx.Response(200, json={"access_token": "mock-token", "expires_in": 3599})
        return httpx.Response(429, headers={"retry-after": "7"}, json={"error": "throttled"})

    _install(handler)
    settings = _configure(monkeypatch)
    try:
        # The client surfaces the server's Retry-After value.
        from app.services.defender_client import DefenderClient, DefenderConfig

        outcome = DefenderClient(DefenderConfig.from_settings(settings)).check()
        assert outcome.ok is False
        assert outcome.category.name == "RATE_LIMITED"
        assert outcome.retry_after == 7

        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/defender/check", headers=admin).json()
        assert body["connector_state"] == "RATE_LIMITED"
        assert body["last_error_category"] == "RATE_LIMITED"
        assert any(action == "CONNECTOR_RATE_LIMITED" for action, _ in _audits())
    finally:
        _clear_settings()


@pytest.mark.parametrize("status", [401, 403, 500, 503])
def test_alerts_endpoint_http_errors_never_claim_connected(monkeypatch, client, clean_db, status):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == AUTHORITY:
            return httpx.Response(200, json={"access_token": "mock-token", "expires_in": 3599})
        return httpx.Response(status, json={"error": "nope"})

    _install(handler)
    _configure(monkeypatch)
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/defender/check", headers=admin).json()
        assert body["connector_state"] != "CONNECTED"
    finally:
        _clear_settings()


# ---------------------------------------------------------------------------
# Bounds and pagination
# ---------------------------------------------------------------------------


def test_max_events_is_enforced(monkeypatch, client, clean_db):
    many = [dict(GRAPH_ALERT, id=f"a{i}") for i in range(10)]
    _install(_handler(pages=[{"value": many}]))
    _configure(monkeypatch, CONNECTOR_MAX_EVENTS="4", CONNECTOR_MAX_PAGES="5")
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin).json()
        assert body["retrieved"] == 4
        assert body["termination"] == "MAX_EVENTS"
        assert body["truncated"] is True
        assert body["accepted"] == 4
    finally:
        _clear_settings()


def test_max_pages_is_enforced(monkeypatch, client, clean_db):
    next_link = f"https://{GRAPH}/v1.0/security/alerts?$skiptoken=page2"
    _install(
        _handler(
            pages=[
                {"value": [dict(GRAPH_ALERT, id="a1")], "@odata.nextLink": next_link},
            ]
        )
    )
    _configure(monkeypatch, CONNECTOR_MAX_PAGES="2", CONNECTOR_MAX_EVENTS="100")
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin).json()
        assert body["pages"] <= 2
        assert body["termination"] in {"MAX_PAGES", "REPEATED_CURSOR", "COMPLETED"}
    finally:
        _clear_settings()


def test_nextlink_to_a_foreign_host_is_refused_and_nothing_is_stored(monkeypatch, client, clean_db):
    """A hostile nextLink must not steer the backend at another host."""
    hostile = "https://attacker.example.com/steal?$skiptoken=x"
    _install(_handler(pages=[{"value": [dict(GRAPH_ALERT)], "@odata.nextLink": hostile}]))
    _configure(monkeypatch, CONNECTOR_MAX_PAGES="3", CONNECTOR_MAX_EVENTS="100")
    try:
        admin, _ = _tokens(client)
        response = client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin)
        assert response.status_code in {200, 422}
        if response.status_code == 422:
            assert response.json()["error"]["code"] in {
                "INGESTION_FAILED",
                "CONNECTOR_UNAVAILABLE",
            }
        # Only the allow-listed Graph host was ever contacted.
        assert client.get("/api/v1/events", headers=admin).json()["total"] <= 1
    finally:
        _clear_settings()


def test_empty_alert_set_is_a_successful_zero_event_poll(monkeypatch, client, clean_db):
    _install(_handler(pages=[{"value": []}]))
    _configure(monkeypatch)
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin).json()
        assert body["retrieved"] == 0
        assert body["accepted"] == 0
        assert body["termination"] == "COMPLETED"
        assert body["truncated"] is False
        assert any(action == "CONNECTOR_POLL_COMPLETED" for action, _ in _audits())
        assert client.get("/api/v1/events", headers=admin).json()["total"] == 0
    finally:
        _clear_settings()


@pytest.mark.parametrize(
    "payload",
    [
        {"error": {"code": "BadRequest"}},  # no value list
        {"value": "not-a-list"},
        {"value": {"nested": "object"}},
        [],  # top level not an object
    ],
)
def test_malformed_alerts_payload_fails_the_poll_without_inserting(
    monkeypatch, client, clean_db, payload
):
    _install(_handler(pages=[payload]))
    _configure(monkeypatch)
    try:
        admin, _ = _tokens(client)
        response = client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin)
        assert response.status_code == 422, response.text
        assert response.json()["error"]["code"] in {
            "INGESTION_FAILED",
            "CONNECTOR_UNAVAILABLE",
        }
        assert client.get("/api/v1/events", headers=admin).json()["total"] == 0
    finally:
        _clear_settings()


# ---------------------------------------------------------------------------
# Normalization, dedup, unresolved assets
# ---------------------------------------------------------------------------


def test_duplicate_alerts_across_polls_are_deduplicated(monkeypatch, client, clean_db):
    """Re-polling the same alerts must not create a second copy."""
    _install(_handler(pages=[{"value": [dict(GRAPH_ALERT)]}]))
    _configure(monkeypatch)
    try:
        admin, _ = _tokens(client)
        first = client.post(
            "/api/v1/events/connectors/defender/poll", json={}, headers=admin
        ).json()
        assert first["accepted"] == 1
        second = client.post(
            "/api/v1/events/connectors/defender/poll",
            json={},
            headers=admin,
            params={"replay": "true"},
        )
        assert second.status_code == 200
        events = client.get(
            "/api/v1/events", params={"source_type": "DEFENDER"}, headers=admin
        ).json()
        assert events["total"] == 1
    finally:
        _clear_settings()


def test_alert_with_no_resolvable_host_stays_unresolved(monkeypatch, client, clean_db):
    """No asset id may be invented for an alert that names no machine."""
    orphan = {
        "id": "orphan-defender-1",
        "title": "Orphan alert",
        "severity": "medium",
        "category": "Network",
        "status": "new",
        "createdDateTime": "2026-01-05T10:00:00Z",
    }
    _install(_handler(pages=[{"value": [orphan]}]))
    _configure(monkeypatch)
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin).json()
        assert body["accepted"] == 1
        events = client.get(
            "/api/v1/events", params={"source_type": "DEFENDER"}, headers=admin
        ).json()
        assert events["total"] == 1
        item = events["items"][0]
        assert not item.get("asset_id")
        assert item["source_type"] == "DEFENDER"
        assert item["event_type"] == "DEFENDER_ALERT"
        assert item["external_event_id"].startswith("defender:")
    finally:
        _clear_settings()


def test_source_metadata_is_preserved(monkeypatch, client, clean_db):
    _install(_handler(pages=[{"value": [dict(GRAPH_ALERT)]}]))
    _configure(monkeypatch)
    try:
        admin, _ = _tokens(client)
        client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin)
        item = client.get(
            "/api/v1/events", params={"source_type": "DEFENDER"}, headers=admin
        ).json()["items"][0]
        assert item["hostname"] == "ws-01"
        assert item["severity"] == "HIGH"
        assert item["event_time"] is not None
        assert item["title"] == "Suspicious process executed"
    finally:
        _clear_settings()


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


def test_a_viewer_cannot_check_or_poll_defender(monkeypatch, client, clean_db):
    _install(_handler(pages=[{"value": []}]))
    _configure(monkeypatch)
    try:
        admin, viewer = _tokens(client)
        assert client.post("/api/v1/events/connectors/defender/check").status_code == 401
        denied = client.post("/api/v1/events/connectors/defender/poll", json={}, headers=viewer)
        assert denied.status_code == 403
        assert denied.json()["error"]["code"] == "PERMISSION_DENIED"
        # Reads stay available to a viewer.
        assert client.get("/api/v1/events/connectors/defender", headers=viewer).status_code == 200
        # And a MANAGE_EVENTS operator may poll.
        assert (
            client.post(
                "/api/v1/events/connectors/defender/poll", json={}, headers=admin
            ).status_code
            == 200
        )
    finally:
        _clear_settings()


# ---------------------------------------------------------------------------
# Read-only guarantee and secret containment
# ---------------------------------------------------------------------------


def test_poll_writes_nothing_to_defender(monkeypatch, client, clean_db):
    """The only non-GET request is the token exchange."""
    state: dict = {}
    _install(_handler(pages=[{"value": []}], state=state))
    _configure(monkeypatch)
    try:
        admin, _ = _tokens(client)
        client.post("/api/v1/events/connectors/defender/check", headers=admin)
        client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin)
        calls = state["calls"]
        non_get = [c for c in calls if not c.startswith("GET")]
        assert non_get, "a token exchange is expected"
        assert all("/oauth2/v2.0/token" in c for c in non_get), non_get
        assert all(c.startswith("GET") or c.startswith("POST") for c in calls)
        for call in calls:
            assert not any(
                verb in call.lower()
                for verb in ("delete", "put", "patch", "beta", "/users/", "machines/")
            ), f"unexpected call {call}"
    finally:
        _clear_settings()


def test_no_secret_appears_in_responses_or_audit(monkeypatch, client, clean_db):
    secret = "defender-client-secret-verify-9f3a"
    token = "defender-minted-token-7c1d"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == AUTHORITY:
            return httpx.Response(200, json={"access_token": token, "expires_in": 3599})
        return httpx.Response(200, json={"value": [dict(GRAPH_ALERT)]})

    _install(handler)
    _configure(monkeypatch, DEFENDER_CLIENT_SECRET=secret)
    try:
        admin, _ = _tokens(client)
        check = client.post("/api/v1/events/connectors/defender/check", headers=admin)
        poll = client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin)
        listing = client.get("/api/v1/events/connectors", headers=admin)
        status = client.get("/api/v1/events/connectors/defender", headers=admin)
        blob = json.dumps(
            [check.json(), poll.json(), listing.json(), status.json(), _audits()],
            default=str,
        )
        assert secret not in blob
        assert token not in blob
        assert "Authorization" not in blob
    finally:
        _clear_settings()
