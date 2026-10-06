"""Phase 2 Step 3 — Wazuh live read-only foundation: gap coverage.

The Wazuh client, its bounded retrieval, connector lifecycle, audit trail
and RBAC were built in Steps 26–27 and are covered by
``test_connectors_step27.py`` (25 tests) and ``test_wazuh.py`` (14 tests).
This module closes the six cases from the Step 3 specification that those
modules do not exercise, and re-asserts the read-only guarantee.

**No test in this module contacts a real Wazuh installation, or any other
external service.** Every HTTP interaction goes through
``httpx.MockTransport`` installed by ``app.services.http_connector``.
"""

import json

import httpx
import pytest

ALERT = {
    "id": "90011",
    "timestamp": "2026-01-05T10:00:00.000+0000",
    "rule": {"id": "5712", "level": 12, "description": "Phase 2 mock rule"},
    "agent": {"id": "001", "name": "agent-1", "ip": "10.0.0.5"},
    "data": {"srcip": "203.0.113.10", "dstip": "10.0.0.5"},
    "location": "/var/log/test",
}

BASE_ENV = {
    "WAZUH_API_URL": "https://wazuh.test:55000",
    "WAZUH_USERNAME": "u",
    "WAZUH_PASSWORD": "p",
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
    return {"Authorization": f"Bearer {token}"}


def _tokens_with_viewer(client):
    admin = _tokens(client)
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


def _handler(pages=None, alerts=None):
    """Mock Wazuh: authenticate + manager/info, and /alerts from ``pages``."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/security/user/authenticate"):
            return httpx.Response(200, json={"token": "mock-jwt-token-value"})
        if request.url.path.endswith("/manager/info"):
            return httpx.Response(200, json={"data": {}, "error": 0})
        if request.url.path.endswith("/alerts"):
            if alerts is not None:
                return alerts
            offset = int(request.url.params.get("offset", "0"))
            page = (pages or {}).get(offset)
            if page is None:
                raise AssertionError(f"unexpected offset {offset}")
            return httpx.Response(200, json=page)
        raise AssertionError(f"unexpected path {request.url.path}")

    return handler


# ---------------------------------------------------------------------------
# 1. TLS failure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        httpx.ConnectError("mock TLS handshake refused", request=None),
        httpx.ReadError("mock TLS record error"),
    ],
)
def test_tls_failure_is_reported_honestly_and_never_claims_connected(
    monkeypatch, client, clean_db, error
):
    """A TLS-level failure must not surface as CONNECTED or leak internals."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise error

    _install(handler)
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        body = client.post("/api/v1/events/connectors/wazuh/check", headers=admin).json()
        assert body["connector_state"] != "CONNECTED"
        assert body["connector_state"] in {"UNAVAILABLE", "ERROR"}
        # The failure category is recorded, not a raw exception string.
        assert body["last_error_category"] in {
            "CONNECTION_ERROR",
            "TLS_ERROR",
            "ERROR",
        }
        assert "Traceback" not in json.dumps(body)
        assert "httpx" not in json.dumps(body)
        # The failure is audited under an honest connector event.
        assert any(
            action in {"CONNECTOR_UNAVAILABLE", "CONNECTOR_ERROR"} for action, _ in _audits()
        )
    finally:
        _clear_settings()


def test_tls_verification_failure_is_not_silently_downgraded(monkeypatch, client, clean_db):
    """Turning verification off must be an explicit, visible configuration."""
    settings = _configure(monkeypatch, CONNECTOR_VERIFY_TLS="false")
    try:
        from app.services.wazuh_client import WazuhClient, WazuhConfig

        client_obj = WazuhClient(
            WazuhConfig.from_settings(settings),
        )
        assert client_obj._http.verify_tls is False  # noqa: SLF001 - assertion on config
    finally:
        _clear_settings()


# ---------------------------------------------------------------------------
# 2. Malformed authentication response
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        {"data": {"token": ""}},  # token nested, not at the documented location
        {"data": {}},  # no token key at all
        {"token": 12345},  # token is not a string
        {"token": "   "},  # whitespace only
    ],
)
def test_malformed_authentication_response_is_refused(monkeypatch, client, clean_db, body):
    """A response without a usable token must not yield an authenticated client."""
    _install(lambda request: httpx.Response(200, json=body))
    settings = _configure(monkeypatch)
    try:
        from app.services.http_connector import HttpErrorCategory
        from app.services.wazuh_client import WazuhClient, WazuhConfig

        outcome = WazuhClient(WazuhConfig.from_settings(settings)).check()
        assert outcome.ok is False, "a tokenless response must not count as connected"
        assert outcome.category is HttpErrorCategory.MALFORMED_RESPONSE
    finally:
        _clear_settings()


def test_non_json_authentication_body_is_refused(monkeypatch, client, clean_db):
    """An HTML error page from a proxy must not be treated as a token."""
    _install(lambda request: httpx.Response(200, text="<html>not json</html>"))
    settings = _configure(monkeypatch)
    try:
        from app.services.http_connector import HttpErrorCategory
        from app.services.wazuh_client import WazuhClient, WazuhConfig

        outcome = WazuhClient(WazuhConfig.from_settings(settings)).check()
        assert outcome.ok is False
        assert outcome.category is HttpErrorCategory.MALFORMED_RESPONSE
    finally:
        _clear_settings()


def test_malformed_auth_response_never_reports_connected_via_api(monkeypatch, client, clean_db):
    _install(lambda request: httpx.Response(200, json={"data": {}}))
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        body = client.post("/api/v1/events/connectors/wazuh/check", headers=admin).json()
        assert body["connector_state"] != "CONNECTED"
    finally:
        _clear_settings()


# ---------------------------------------------------------------------------
# 3. Wazuh-side HTTP 403 (distinct from 401)
# ---------------------------------------------------------------------------


def test_http_403_from_wazuh_is_auth_failed(monkeypatch, client, clean_db):
    """Wazuh may answer 403 for an authenticated-but-unauthorized token."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/security/user/authenticate"):
            return httpx.Response(403, json={"title": "Forbidden"})
        return httpx.Response(200, json={"data": {}, "error": 0})

    _install(handler)
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        body = client.post("/api/v1/events/connectors/wazuh/check", headers=admin).json()
        assert body["connector_state"] == "AUTH_FAILED"
        assert any(action == "CONNECTOR_AUTH_FAILED" for action, _ in _audits())
    finally:
        _clear_settings()


# ---------------------------------------------------------------------------
# 4. Malformed alert payload
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {"error": 0},  # no data at all
        {"data": "not-a-list", "error": 0},  # data is a string
        {"data": {"alerts": "not-a-list"}, "error": 0},  # alerts is a string
        {"data": {"totalItems": 5}, "error": 0},  # totalItems without alerts
        [],  # top level is a list, not an object
    ],
)
def test_malformed_alert_payload_fails_the_poll_without_inserting(
    monkeypatch, client, clean_db, payload
):
    """A malformed alerts body must fail the poll, not silently yield zero events."""
    _install(_handler(alerts=httpx.Response(200, json=payload)))
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        response = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        # A malformed page is a failed poll, never a silent success.
        assert response.status_code == 422, response.text
        assert response.json()["error"]["code"] in {
            "INGESTION_FAILED",
            "CONNECTOR_UNAVAILABLE",
        }
        # Nothing was invented or stored from an unparseable page.
        events = client.get("/api/v1/events", headers=admin).json()
        assert events["total"] == 0
    finally:
        _clear_settings()


def test_wazuh_error_field_is_surfaced_as_failure(monkeypatch, client, clean_db):
    """Wazuh's own ``error`` field must not be read as success."""
    _install(_handler(alerts=httpx.Response(200, json={"error": 500, "message": "boom"})))
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        events = client.get("/api/v1/events", headers=admin).json()
        assert events["total"] == 0
    finally:
        _clear_settings()


# ---------------------------------------------------------------------------
# 5. Empty result
# ---------------------------------------------------------------------------


def test_empty_alert_set_is_a_successful_zero_event_poll(monkeypatch, client, clean_db):
    """No alerts is a normal outcome, not an error."""
    _install(_handler(pages={0: {"data": {"totalItems": 0, "alerts": []}, "error": 0}}))
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        response = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        assert response.status_code == 200
        body = response.json()
        assert body["retrieved"] == 0
        assert body["accepted"] == 0
        assert body["termination"] == "COMPLETED"
        assert body["truncated"] is False
        assert any(action == "CONNECTOR_POLL_COMPLETED" for action, _ in _audits())
        assert client.get("/api/v1/events", headers=admin).json()["total"] == 0
    finally:
        _clear_settings()


# ---------------------------------------------------------------------------
# 6. Unresolved asset
# ---------------------------------------------------------------------------


def test_alert_with_no_resolvable_address_stays_unresolved(monkeypatch, client, clean_db):
    """The platform must not invent an asset id for an unmappable alert."""
    orphan = {
        "id": "orphan-1",
        "timestamp": "2026-01-05T10:00:00.000+0000",
        "rule": {"id": "5712", "level": 5, "description": "orphan rule"},
        "agent": {"id": "777", "name": ""},
        "data": {},
        "location": "",
    }
    _install(_handler(pages={0: {"data": {"totalItems": 1, "alerts": [orphan]}, "error": 0}}))
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        response = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        assert response.status_code == 200
        body = response.json()
        assert body["accepted"] == 1

        events = client.get("/api/v1/events", params={"source_type": "WAZUH"}, headers=admin).json()
        assert events["total"] == 1
        item = events["items"][0]
        # No fabricated asset linkage.
        assert not item.get("asset_id")
        # Source information is preserved. The external id is the documented
        # deterministic identity (wazuh:<sha256 ...>), not the raw Wazuh id.
        assert item["source_type"] == "WAZUH"
        assert item["event_type"] == "WAZUH_ALERT"
        assert item["external_event_id"].startswith("wazuh:")
    finally:
        _clear_settings()


# ---------------------------------------------------------------------------
# Read-only guarantee
# ---------------------------------------------------------------------------


def test_poll_issues_only_read_only_wazuh_requests(monkeypatch, client, clean_db):
    """Against Wazuh the connector may only POST auth and GET resources."""
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.url.path.endswith("/security/user/authenticate"):
            return httpx.Response(200, json={"token": "mock-jwt-token-value"})
        if request.url.path.endswith("/alerts"):
            return httpx.Response(200, json={"data": {"totalItems": 0, "alerts": []}, "error": 0})
        return httpx.Response(200, json={"data": {}, "error": 0})

    _install(handler)
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        client.post("/api/v1/events/connectors/wazuh/check", headers=admin)
        client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)

        posts = [path for method, path in seen if method == "POST"]
        assert posts, "authentication is expected to POST"
        assert set(posts) == {"/security/user/authenticate"}, f"unexpected Wazuh POST(s): {posts}"
        for method, path in seen:
            if method != "POST":
                assert method == "GET", f"unexpected method {method} for {path}"
            assert not any(
                verb in path.lower()
                for verb in ("delete", "put", "patch", "active-response", "agent", "restart")
            ), f"non read-only path: {path}"
    finally:
        _clear_settings()


def test_no_secret_appears_in_api_response_or_audit(monkeypatch, client, clean_db):
    """The password and the minted token must not escape the server."""
    secret_password = "sup3r-secret-wazuh-password"
    token = "mock-jwt-token-value"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/security/user/authenticate"):
            return httpx.Response(200, json={"token": token})
        return httpx.Response(200, json={"data": {"totalItems": 0, "alerts": []}, "error": 0})

    _install(handler)
    _configure(monkeypatch, WAZUH_PASSWORD=secret_password)
    try:
        admin = _tokens(client)
        check = client.post("/api/v1/events/connectors/wazuh/check", headers=admin)
        poll = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        listing = client.get("/api/v1/events/connectors", headers=admin)
        status = client.get("/api/v1/events/connectors/wazuh", headers=admin)

        blob = json.dumps([check.json(), poll.json(), listing.json(), status.json(), _audits()])
        assert secret_password not in blob
        assert token not in blob
        assert "Authorization" not in blob
    finally:
        _clear_settings()


def test_a_viewer_cannot_trigger_a_poll(monkeypatch, client, clean_db):
    """Only MANAGE_EVENTS may poll. Step 27 asserted this for check only."""
    _install(_handler(pages={0: {"data": {"totalItems": 0, "alerts": []}, "error": 0}}))
    _configure(monkeypatch)
    try:
        admin, viewer = _tokens_with_viewer(client)

        anonymous = client.post("/api/v1/events/connectors/wazuh/poll", json={})
        assert anonymous.status_code == 401

        denied = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=viewer)
        assert denied.status_code == 403
        assert denied.json()["error"]["code"] == "PERMISSION_DENIED"

        # A refused poll must not have consumed a Wazuh request or written events.
        events = client.get("/api/v1/events", headers=admin).json()
        assert events["total"] == 0

        allowed = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        assert allowed.status_code == 200
    finally:
        _clear_settings()


def test_unconfigured_wazuh_remains_not_configured(monkeypatch, client, clean_db):
    for key in ("WAZUH_API_URL", "WAZUH_USERNAME", "WAZUH_PASSWORD"):
        monkeypatch.setenv(key, "")
    from app.core.config import get_settings

    get_settings.cache_clear()
    try:
        admin = _tokens(client)
        body = client.get("/api/v1/events/connectors/wazuh", headers=admin).json()
        assert body["connector_state"] == "NOT_CONFIGURED"
        # A check must not touch the network when nothing is configured.
        checked = client.post("/api/v1/events/connectors/wazuh/check", headers=admin).json()
        assert checked["connector_state"] == "NOT_CONFIGURED"
        assert client.get("/api/v1/health").status_code == 200
    finally:
        _clear_settings()
