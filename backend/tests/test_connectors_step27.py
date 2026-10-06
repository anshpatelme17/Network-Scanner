"""Step 27 — controlled live-connector foundation tests.

Covers, with **mocked HTTP only** (``httpx.MockTransport``; no real
Wazuh, Defender, or any other external service is ever contacted):

- the eight-state ``connector_state`` vocabulary and its truthful
  mapping onto the preserved Step 26 ``mode``/``state`` fields,
- no network I/O on GET reads or on unconfigured checks,
- the shared HTTP layer's destination allow-list, timeouts, bounded
  bodies, redirect refusal, safe GET-only retries, and secret
  redaction,
- Wazuh authenticate/manager-info checks and bounded offset
  pagination with explicit termination reasons,
- Defender client-credentials token exchange, bounded ``nextLink``
  pagination (including nextLink allow-list enforcement),
- normalization reuse through the Step 23 adapter registry,
- RBAC (``MANAGE_EVENTS`` for check/poll, ``READ_EVENTS`` for reads),
- audit rows for every material connector operation with no secrets.

Steps 1–26 behaviour is asserted in ``test_connectors.py`` and must
keep passing unchanged.
"""

import json

import httpx
import pytest

FIXTURE_ALERT = {
    "id": "90011",
    "timestamp": "2026-01-05T10:00:00.000+0000",
    "rule": {"id": "5712", "level": 12, "description": "Step27 mock rule"},
    "agent": {"id": "001", "name": "agent-1", "ip": "10.0.0.5"},
    "data": {"srcip": "203.0.113.10", "dstip": "10.0.0.5"},
    "location": "/var/log/test",
}

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


def _read(name, *parts):
    from pathlib import Path

    fixtures = Path(__file__).parent / "fixtures"
    return (fixtures.joinpath(*parts) / name).read_text(encoding="utf-8")


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
    admin = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "admin-pass-word-1"}
    ).json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin}"}
    client.post(
        "/api/v1/users",
        json={
            "username": "viewer1",
            "password": "viewer-pass-1234",
            "display_name": "V",
            "roles": ["VIEWER"],
        },
        headers=admin_headers,
    )
    viewer = client.post(
        "/api/v1/auth/login", json={"username": "viewer1", "password": "viewer-pass-1234"}
    ).json()["access_token"]
    return admin_headers, {"Authorization": f"Bearer {viewer}"}


def _configure(monkeypatch, **overrides):
    from app.core.config import get_settings

    for key, value in overrides.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    return get_settings()


def _clear_settings():
    from app.core.config import get_settings

    get_settings.cache_clear()


def _install(handler):
    from app.services import http_connector

    http_connector.install_test_transport(httpx.MockTransport(handler))
    return handler


def _audits():
    from sqlalchemy import select

    from app.database import session as session_module
    from app.models.events import EventAudit

    db = session_module.get_session_factory()()
    try:
        rows = db.scalars(select(EventAudit)).all()
        return [(row.action, row.detail or "") for row in rows]
    finally:
        db.close()


def _audit_actions():
    return [action for action, _ in _audits()]


def _audit_blob():
    return json.dumps(_audits())


# --- 27A: state vocabulary ----------------------------------------------------


def test_state_vocabulary_is_truthful_and_bounded(monkeypatch, client, clean_db):
    from app.services import connectors

    assert set(connectors.CONNECTOR_STATES) == {
        "NOT_CONFIGURED",
        "CONFIGURED",
        "CONNECTING",
        "CONNECTED",
        "AUTH_FAILED",
        "UNAVAILABLE",
        "RATE_LIMITED",
        "ERROR",
    }

    # 1. nothing configured → NOT_CONFIGURED (Step 26 fields unchanged)
    try:
        _configure(monkeypatch, WAZUH_API_URL="", WAZUH_USERNAME="", WAZUH_PASSWORD="")
        status = connectors.health("wazuh")
        assert (status.mode, status.state) == ("LIVE", "UNAVAILABLE")
        assert status.connector_state == "NOT_CONFIGURED"

        # 2. partial configuration → NOT_CONFIGURED + INVALID_CONFIGURATION
        _configure(monkeypatch, WAZUH_API_URL="https://wazuh.test:55000", WAZUH_USERNAME="u")
        status = connectors.health("wazuh")
        assert status.state == "INVALID_CONFIGURATION"
        assert status.connector_state == "NOT_CONFIGURED"
        assert "missing: password" in status.detail

        # 3. complete but malformed → ERROR + INVALID_CONFIGURATION
        _configure(
            monkeypatch,
            WAZUH_API_URL="not-a-url",
            WAZUH_USERNAME="u",
            WAZUH_PASSWORD="p",
        )
        status = connectors.health("wazuh")
        assert status.state == "INVALID_CONFIGURATION"
        assert status.connector_state == "ERROR"

        # 4. complete, never checked → CONFIGURED (never CONNECTED by claim)
        _configure(
            monkeypatch,
            WAZUH_API_URL="https://wazuh.test:55000",
            WAZUH_USERNAME="u",
            WAZUH_PASSWORD="p",
        )
        status = connectors.health("wazuh")
        assert status.connector_state == "CONFIGURED"
        assert status.state == "UNAVAILABLE"
        assert "not attempted" in status.detail
        assert status.last_check_at is None
    finally:
        _clear_settings()

    # 5. file source: unconfigured → NOT_CONFIGURED, readable → CONNECTED
    _configure(monkeypatch, SURICATA_EVE_PATH="")
    assert connectors.health("suricata").connector_state == "NOT_CONFIGURED"
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        eve = Path(tmp) / "eve.json"
        eve.write_text(_read("alert.json", "suricata"), encoding="utf-8")
        _configure(monkeypatch, SURICATA_EVE_PATH=str(eve))
        try:
            assert connectors.health("suricata").connector_state == "CONNECTED"
        finally:
            _clear_settings()


def test_api_sources_start_not_configured_in_list(client, clean_db):
    body = client.get("/api/v1/events/connectors").json()
    by_source = {item["source"]: item for item in body["items"]}
    assert by_source["wazuh"]["connector_state"] == "NOT_CONFIGURED"
    assert by_source["defender"]["connector_state"] == "NOT_CONFIGURED"
    assert by_source["suricata"]["connector_state"] == "NOT_CONFIGURED"
    # Step 26 fields still present and unchanged in meaning.
    assert by_source["defender"]["state"] == "UNAVAILABLE"
    assert "last_check_at" in by_source["wazuh"]
    assert by_source["wazuh"]["last_check_at"] is None
    blob = json.dumps(body)
    assert "SECRET" not in blob and "secret" not in blob.replace("client_secret", "")


# --- 27D: shared HTTP layer ---------------------------------------------------


def test_get_status_performs_no_network(client, clean_db):
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json={})

    _install(handler)
    assert client.get("/api/v1/events/connectors").status_code == 200
    assert client.get("/api/v1/events/connectors/wazuh").status_code == 200
    assert calls == []


def test_unconfigured_check_never_touches_the_network(monkeypatch, client, clean_db):
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(500)

    _install(handler)
    _configure(monkeypatch, WAZUH_API_URL="", WAZUH_USERNAME="", WAZUH_PASSWORD="")
    try:
        admin, _ = _tokens(client)
        response = client.post("/api/v1/events/connectors/wazuh/check", headers=admin)
        assert response.status_code == 200
        assert response.json()["connector_state"] == "NOT_CONFIGURED"
        assert calls == []
        actions = _audit_actions()
        assert "CONNECTOR_CHECK_STARTED" in actions
        assert "CONNECTOR_UNAVAILABLE" in actions
    finally:
        _clear_settings()


def test_destination_allowlist_rejects_other_hosts():
    from app.services.http_connector import (
        ConnectorHttpError,
        HttpErrorCategory,
        validate_destination,
    )

    allowed = frozenset({"wazuh.test", "graph.microsoft.com"})
    validate_destination("https://wazuh.test:55000/manager/info", allowed)
    for bad in (
        "https://evil.test/steal",
        "ftp://wazuh.test/x",
        "file:///etc/passwd",
        "https://wazuh.test.evil.test/x",
    ):
        with pytest.raises(ConnectorHttpError) as excinfo:
            validate_destination(bad, allowed)
        assert excinfo.value.category is HttpErrorCategory.DESTINATION_NOT_ALLOWED


def test_bounded_response_body_is_refused(monkeypatch, client, clean_db):
    _configure(
        monkeypatch,
        WAZUH_API_URL="https://wazuh.test:55000",
        WAZUH_USERNAME="u",
        WAZUH_PASSWORD="p",
        CONNECTOR_MAX_RESPONSE_BYTES="1024",
        CONNECTOR_RETRY_MAX="0",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/security/user/authenticate"):
            return httpx.Response(200, json={"token": "t"})
        return httpx.Response(
            200, content=b"x" * 4096, headers={"content-type": "application/json"}
        )

    _install(handler)
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/wazuh/check", headers=admin).json()
        assert body["connector_state"] == "ERROR"
        assert body["last_error_category"] == "RESPONSE_TOO_LARGE"
        assert "CONNECTOR_ERROR" in _audit_actions()
    finally:
        _clear_settings()


def test_redirects_are_not_followed(monkeypatch, client, clean_db):
    _configure(
        monkeypatch,
        WAZUH_API_URL="https://wazuh.test:55000",
        WAZUH_USERNAME="u",
        WAZUH_PASSWORD="p",
        CONNECTOR_RETRY_MAX="0",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.test/steal"})

    _install(handler)
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/wazuh/check", headers=admin).json()
        assert body["connector_state"] == "UNAVAILABLE"
        assert body["last_error_category"] == "HTTP_ERROR"
        # The redirect target was never requested.
        assert all("evil.test" not in line for line in _audit_blob().split())
    finally:
        _clear_settings()


# --- 27G/27H: checks ---------------------------------------------------------


def _wazuh_health_handler(
    *,
    auth_status: int = 200,
    info_status: int = 200,
    record_calls: list[str] | None = None,
    on_request=None,
):
    def handler(request: httpx.Request) -> httpx.Response:
        if record_calls is not None:
            record_calls.append(f"{request.method} {request.url.path}")
        if on_request is not None:
            on_request(request)
        if request.url.path.endswith("/security/user/authenticate"):
            if auth_status == 200:
                return httpx.Response(200, json={"token": "mock-jwt-token-value"})
            return httpx.Response(auth_status, json={"error": 4001})
        if request.url.path.endswith("/manager/info"):
            if info_status == 200:
                return httpx.Response(200, json={"data": {"WAZUH_MANAGER": "mock"}, "error": 0})
            return httpx.Response(info_status, json={"error": 1})
        raise AssertionError(f"unexpected path {request.url.path}")

    return handler


def test_check_marks_connecting_then_connected(monkeypatch, client, clean_db):
    from app.services import connectors

    observed: list[str] = []

    def on_request(request: httpx.Request):
        observed.append(connectors.health("wazuh").connector_state)

    _install(_wazuh_health_handler(on_request=on_request))
    _configure(
        monkeypatch,
        WAZUH_API_URL="https://wazuh.test:55000",
        WAZUH_USERNAME="operator",
        WAZUH_PASSWORD="super-secret-value",
    )
    try:
        admin, _ = _tokens(client)
        response = client.post("/api/v1/events/connectors/wazuh/check", headers=admin)
        assert response.status_code == 200
        body = response.json()
        assert observed and set(observed) == {"CONNECTING"}
        assert body["connector_state"] == "CONNECTED"
        assert body["state"] == "CONNECTED"
        assert body["last_check_at"] is not None
        assert isinstance(body["latency_ms"], int) and body["latency_ms"] >= 0
        assert body["last_error_category"] is None
        assert "super-secret-value" not in json.dumps(body)
        assert "CONNECTOR_CONNECTED" in _audit_actions()
        assert "mock-jwt-token-value" not in _audit_blob()
        # Subsequent read reflects the verified state without any HTTP.
        assert (
            client.get("/api/v1/events/connectors/wazuh", headers=admin).json()["connector_state"]
            == "CONNECTED"
        )
    finally:
        _clear_settings()


def test_check_auth_failure_state(monkeypatch, client, clean_db):
    _install(_wazuh_health_handler(auth_status=401))
    _configure(
        monkeypatch,
        WAZUH_API_URL="https://wazuh.test:55000",
        WAZUH_USERNAME="operator",
        WAZUH_PASSWORD="wrong-password-value",
        CONNECTOR_RETRY_MAX="0",
    )
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/wazuh/check", headers=admin).json()
        assert body["connector_state"] == "AUTH_FAILED"
        assert body["state"] == "UNAVAILABLE"
        assert body["last_error_category"] == "AUTH_FAILED"
        assert "credentials" in body["detail"].lower() or "rejected" in body["detail"].lower()
        actions = _audit_actions()
        assert "CONNECTOR_AUTH_FAILED" in actions
        assert "wrong-password-value" not in _audit_blob()
    finally:
        _clear_settings()


def test_check_rate_limited_reports_retry_after(monkeypatch, client, clean_db):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/security/user/authenticate"):
            return httpx.Response(429, headers={"retry-after": "5"})
        raise AssertionError("no further calls expected")

    _install(handler)
    _configure(
        monkeypatch,
        WAZUH_API_URL="https://wazuh.test:55000",
        WAZUH_USERNAME="u",
        WAZUH_PASSWORD="p",
        CONNECTOR_RETRY_MAX="0",
    )
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/wazuh/check", headers=admin).json()
        assert body["connector_state"] == "RATE_LIMITED"
        assert body["last_error_category"] == "RATE_LIMITED"
        assert body["detail"]
        assert any(
            "Retry after 5" in detail
            for action, detail in _audits()
            if action == "CONNECTOR_RATE_LIMITED"
        )
        assert "CONNECTOR_RATE_LIMITED" in _audit_actions()
    finally:
        _clear_settings()


def test_check_unreachable_endpoint_is_unavailable(monkeypatch, client, clean_db):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("mock connection refused", request=request)

    _install(handler)
    _configure(
        monkeypatch,
        WAZUH_API_URL="https://wazuh.test:55000",
        WAZUH_USERNAME="u",
        WAZUH_PASSWORD="p",
        CONNECTOR_RETRY_MAX="0",
    )
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/wazuh/check", headers=admin).json()
        assert body["connector_state"] == "UNAVAILABLE"
        assert body["last_error_category"] == "CONNECTION_ERROR"
        assert "CONNECTOR_UNAVAILABLE" in _audit_actions()
    finally:
        _clear_settings()


def test_safe_retries_only_for_get(monkeypatch, client, clean_db):
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        if request.method == "POST":
            return httpx.Response(429, headers={"retry-after": "0"})
        return httpx.Response(503)

    _install(handler)
    _configure(
        monkeypatch,
        WAZUH_API_URL="https://wazuh.test:55000",
        WAZUH_USERNAME="u",
        WAZUH_PASSWORD="p",
        CONNECTOR_RETRY_MAX="1",
    )
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/wazuh/check", headers=admin).json()
        assert body["connector_state"] == "RATE_LIMITED"
        # The authentication POST is not idempotent: exactly one attempt.
        assert calls.count("POST /security/user/authenticate") == 1
    finally:
        _clear_settings()


def test_get_is_retried_on_5xx(monkeypatch, client, clean_db):
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        if request.url.path.endswith("/security/user/authenticate"):
            return httpx.Response(200, json={"token": "t"})
        if calls.count("GET /manager/info") == 1:
            return httpx.Response(503)
        return httpx.Response(200, json={"data": {}, "error": 0})

    _install(handler)
    _configure(
        monkeypatch,
        WAZUH_API_URL="https://wazuh.test:55000",
        WAZUH_USERNAME="u",
        WAZUH_PASSWORD="p",
        CONNECTOR_RETRY_MAX="1",
    )
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/wazuh/check", headers=admin).json()
        assert body["connector_state"] == "CONNECTED"
        assert calls.count("GET /manager/info") == 2
    finally:
        _clear_settings()


def test_check_rbac_and_unknown_source(client, clean_db):
    admin, viewer = _tokens(client)
    assert client.post("/api/v1/events/connectors/wazuh/check").status_code == 401
    denied = client.post("/api/v1/events/connectors/wazuh/check", headers=viewer)
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "PERMISSION_DENIED"
    unknown = client.post("/api/v1/events/connectors/nope/check", headers=admin)
    assert unknown.status_code == 422
    assert unknown.json()["error"]["code"] == "UNKNOWN_CONNECTOR"


# --- 27B: Wazuh pagination ----------------------------------------------------


def _wazuh_poll_handler(pages: dict[int, dict], state: dict):
    def handler(request: httpx.Request) -> httpx.Response:
        state.setdefault("calls", []).append(str(request.url))
        if request.url.path.endswith("/security/user/authenticate"):
            return httpx.Response(200, json={"token": "mock-jwt-token-value"})
        if request.url.path.endswith("/alerts"):
            offset = int(request.url.params.get("offset", "0"))
            page = pages.get(offset)
            if page is None:
                raise AssertionError(f"unexpected offset {offset}")
            return httpx.Response(200, json=page)
        if request.url.path.endswith("/manager/info"):
            return httpx.Response(200, json={"data": {}, "error": 0})
        raise AssertionError(f"unexpected path {request.url.path}")

    return handler


def test_wazuh_poll_is_bounded_and_audited(monkeypatch, client, clean_db):
    state: dict = {}
    pages = {
        0: {
            "data": {
                "totalItems": 40,
                "alerts": [dict(FIXTURE_ALERT, id=str(i)) for i in range(10)],
            },
            "error": 0,
        },
        10: {
            "data": {
                "totalItems": 40,
                "alerts": [dict(FIXTURE_ALERT, id=str(i)) for i in range(10, 20)],
            },
            "error": 0,
        },
    }
    _install(_wazuh_poll_handler(pages, state))
    _configure(
        monkeypatch,
        WAZUH_API_URL="https://wazuh.test:55000",
        WAZUH_USERNAME="u",
        WAZUH_PASSWORD="p",
        CONNECTOR_MAX_PAGES="2",
        CONNECTOR_MAX_EVENTS="100",
    )
    try:
        admin, _ = _tokens(client)
        response = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        assert response.status_code == 200
        body = response.json()
        assert body["pages"] == 2
        assert body["retrieved"] == 20
        assert body["termination"] == "MAX_PAGES"
        assert body["truncated"] is True
        assert body["accepted"] == 20
        assert body["rejected"] == 0
        # Ingest reused the Step 23 adapter registry (WAZUH_ALERT).
        events = client.get("/api/v1/events", params={"source_type": "WAZUH"}, headers=admin).json()
        assert events["total"] == 20
        assert events["items"][0]["event_type"] == "WAZUH_ALERT"
        actions = _audit_actions()
        assert "CONNECTOR_POLL_STARTED" in actions
        assert any(
            "termination=MAX_PAGES" in detail
            for action, detail in _audits()
            if action == "CONNECTOR_POLL_COMPLETED"
        )
        # Health now reports the verified poll.
        status = client.get("/api/v1/events/connectors/wazuh", headers=admin).json()
        assert status["connector_state"] == "CONNECTED"
        assert status["last_poll_at"] is not None
        assert status["events_retrieved"] == 20
        assert status["last_success_at"] is not None
        # Bounds: only two pages were ever requested.
        assert len(state["calls"]) == 3  # auth + 2 pages
    finally:
        _clear_settings()


def test_wazuh_poll_completes_when_total_reached(monkeypatch, client, clean_db):
    state: dict = {}
    alert = dict(FIXTURE_ALERT, id="1")
    pages = {0: {"data": {"totalItems": 1, "alerts": [alert]}, "error": 0}}
    _install(_wazuh_poll_handler(pages, state))
    _configure(
        monkeypatch,
        WAZUH_API_URL="https://wazuh.test:55000",
        WAZUH_USERNAME="u",
        WAZUH_PASSWORD="p",
    )
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin).json()
        assert body["termination"] == "COMPLETED"
        assert body["truncated"] is False
        # Replay is idempotent through the Step 3 dedup triple.
        repeat = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin).json()
        assert (repeat["accepted"], repeat["duplicates"]) == (0, 1)
        assert (
            client.get("/api/v1/events", params={"source_type": "WAZUH"}, headers=admin).json()[
                "total"
            ]
            == 1
        )
    finally:
        _clear_settings()


def test_wazuh_poll_stops_on_malformed_pagination(monkeypatch, client, clean_db):
    state: dict = {}
    pages = {0: {"data": {"totalItems": 99, "alerts": []}, "error": 0}}
    _install(_wazuh_poll_handler(pages, state))
    _configure(
        monkeypatch,
        WAZUH_API_URL="https://wazuh.test:55000",
        WAZUH_USERNAME="u",
        WAZUH_PASSWORD="p",
    )
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin).json()
        assert body["termination"] == "MALFORMED_PAGINATION"
        assert len(state["calls"]) == 2  # auth + single page, no loop
    finally:
        _clear_settings()


def test_wazuh_poll_failure_is_structured(monkeypatch, client, clean_db):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/security/user/authenticate"):
            return httpx.Response(200, json={"token": "t"})
        return httpx.Response(500, json={"error": 1, "message": "boom"})

    _install(handler)
    _configure(
        monkeypatch,
        WAZUH_API_URL="https://wazuh.test:55000",
        WAZUH_USERNAME="u",
        WAZUH_PASSWORD="p",
        CONNECTOR_RETRY_MAX="0",
    )
    try:
        admin, _ = _tokens(client)
        response = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "CONNECTOR_UNAVAILABLE"
        actions = _audit_actions()
        assert "CONNECTOR_POLL_STARTED" in actions
        assert "CONNECTOR_POLL_FAILED" in actions
        assert (
            client.get("/api/v1/events/connectors/wazuh", headers=admin).json()[
                "last_error_category"
            ]
            == "HTTP_ERROR"
        )
    finally:
        _clear_settings()


# --- 27C: Defender ------------------------------------------------------------


def _defender_handler(
    *, token_status: int = 200, pages: list[dict] | None = None, state: dict | None = None
):
    pages = pages if pages is not None else []

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if state is not None:
            state.setdefault("hosts", []).append(host)
            state.setdefault("calls", []).append(f"{request.method} {request.url.path}")
        if host.endswith("login.microsoftonline.com"):
            if token_status != 200:
                return httpx.Response(token_status, json={"error": "invalid_client"})
            return httpx.Response(
                200,
                json={
                    "token_type": "Bearer",
                    "expires_in": 3599,
                    "access_token": "mock-graph-token-value",
                },
            )
        if request.url.path.endswith("/security/alerts"):
            if not pages:
                raise AssertionError("unexpected alerts request")
            page = pages.pop(0) if len(pages) > 1 else pages[0]
            return httpx.Response(200, json=page)
        raise AssertionError(f"unexpected host/path {host}{request.url.path}")

    return handler


def test_defender_token_exchange_and_poll(monkeypatch, client, clean_db):
    state: dict = {}
    _install(_defender_handler(pages=[{"value": [dict(GRAPH_ALERT)]}], state=state))
    _configure(
        monkeypatch,
        DEFENDER_TENANT_ID="tenant-1",
        DEFENDER_CLIENT_ID="client-1",
        DEFENDER_CLIENT_SECRET="client-secret-value-1",
    )
    try:
        admin, _ = _tokens(client)
        check = client.post("/api/v1/events/connectors/defender/check", headers=admin).json()
        assert check["connector_state"] == "CONNECTED"
        assert check["last_check_at"] is not None

        body = client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin).json()
        assert body["accepted"] == 1
        assert body["termination"] == "COMPLETED"
        assert body["retrieved"] == 1

        events = client.get(
            "/api/v1/events", params={"source_type": "DEFENDER"}, headers=admin
        ).json()
        assert events["total"] == 1
        item = events["items"][0]
        assert item["event_type"] == "DEFENDER_ALERT"
        assert item["severity"] == "HIGH"
        assert item["hostname"] == "ws-01"
        # Only allow-listed hosts were contacted.
        assert set(state["hosts"]) <= {
            "login.microsoftonline.com",
            "graph.microsoft.com",
        }
        assert "client-secret-value-1" not in _audit_blob()
        assert "mock-graph-token-value" not in _audit_blob()
    finally:
        _clear_settings()


def test_defender_nextlink_pagination_is_allowlisted(monkeypatch, client, clean_db):
    state: dict = {}
    pages = [
        {
            "value": [dict(GRAPH_ALERT, id="a1")],
            "@odata.nextLink": "https://evil.test/v1.0/security/alerts?$skiptoken=1",
        }
    ]
    _install(_defender_handler(pages=pages, state=state))
    _configure(
        monkeypatch,
        DEFENDER_TENANT_ID="tenant-1",
        DEFENDER_CLIENT_ID="client-1",
        DEFENDER_CLIENT_SECRET="client-secret-value-1",
    )
    try:
        admin, _ = _tokens(client)
        response = client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "CONNECTOR_UNAVAILABLE"
        assert "evil.test" not in state["hosts"]
        actions = _audit_actions()
        assert "CONNECTOR_POLL_FAILED" in actions
        assert "DESTINATION_NOT_ALLOWED" in _audit_blob()
        # The first page's record was not ingested: retrieval failed as one unit.
        assert (
            client.get("/api/v1/events", params={"source_type": "DEFENDER"}, headers=admin).json()[
                "total"
            ]
            == 0
        )
    finally:
        _clear_settings()


def test_defender_follows_allowlisted_nextlink(monkeypatch, client, clean_db):
    state: dict = {}
    pages = [
        {
            "value": [dict(GRAPH_ALERT, id="a1")],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/security/alerts?$skiptoken=next",
        },
        {"value": [dict(GRAPH_ALERT, id="a2")]},
    ]
    _install(_defender_handler(pages=pages, state=state))
    _configure(
        monkeypatch,
        DEFENDER_TENANT_ID="tenant-1",
        DEFENDER_CLIENT_ID="client-1",
        DEFENDER_CLIENT_SECRET="client-secret-value-1",
        CONNECTOR_MAX_PAGES="2",
    )
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin).json()
        assert body["accepted"] == 2
        assert body["pages"] == 2
        assert body["termination"] == "COMPLETED"
        assert set(state["hosts"]) == {"login.microsoftonline.com", "graph.microsoft.com"}
        assert (
            client.get("/api/v1/events", params={"source_type": "DEFENDER"}, headers=admin).json()[
                "total"
            ]
            == 2
        )
    finally:
        _clear_settings()


def test_defender_repeated_nextlink_terminates(monkeypatch, client, clean_db):
    state: dict = {}
    pages = [
        {
            "value": [dict(GRAPH_ALERT, id="a1")],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/security/alerts?$skiptoken=same",
        }
    ]
    _install(_defender_handler(pages=pages, state=state))
    _configure(
        monkeypatch,
        DEFENDER_TENANT_ID="tenant-1",
        DEFENDER_CLIENT_ID="client-1",
        DEFENDER_CLIENT_SECRET="client-secret-value-1",
        CONNECTOR_MAX_PAGES="5",
    )
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin).json()
        assert body["termination"] == "REPEATED_CURSOR"
        assert body["accepted"] == 1
        assert sum(1 for call in state["calls"] if call.endswith("/security/alerts")) == 2
    finally:
        _clear_settings()


def test_defender_token_rejection_is_auth_failed(monkeypatch, client, clean_db):
    _install(_defender_handler(token_status=400))
    _configure(
        monkeypatch,
        DEFENDER_TENANT_ID="tenant-1",
        DEFENDER_CLIENT_ID="client-1",
        DEFENDER_CLIENT_SECRET="client-secret-value-1",
        CONNECTOR_RETRY_MAX="0",
    )
    try:
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/defender/check", headers=admin).json()
        assert body["connector_state"] == "AUTH_FAILED"
        assert body["last_error_category"] == "AUTH_FAILED"
        assert "CONNECTOR_AUTH_FAILED" in _audit_actions()
        assert "client-secret-value-1" not in _audit_blob()
        # Poll with rejected credentials fails as a structured 422 too.
        response = client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "CONNECTOR_UNAVAILABLE"
    finally:
        _clear_settings()


# --- audit hygiene + security regression --------------------------------------


def test_audit_rows_carry_no_secrets(monkeypatch, client, clean_db):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/security/user/authenticate"):
            # A hostile/leaky response body must never reach an audit row.
            return httpx.Response(
                500, json={"message": "bad password super-secret-value for operator"}
            )
        raise AssertionError("unexpected path")

    _install(handler)
    _configure(
        monkeypatch,
        WAZUH_API_URL="https://wazuh.test:55000",
        WAZUH_USERNAME="operator",
        WAZUH_PASSWORD="super-secret-value",
        CONNECTOR_RETRY_MAX="0",
    )
    try:
        admin, _ = _tokens(client)
        response = client.post("/api/v1/events/connectors/wazuh/check", headers=admin)
        assert response.status_code == 200
        blob = _audit_blob()
        assert "super-secret-value" not in blob
        assert "super-secret-value" not in response.text
        assert response.json()["connector_state"] == "UNAVAILABLE"
    finally:
        _clear_settings()


def test_security_regression_step27_modules():
    """AST-level proof for the Step 27 connector modules."""
    import ast as _ast
    import inspect as _inspect

    import app.api.v1.endpoints.connectors as endpoints
    import app.schemas.connectors as schemas
    import app.services.connectors as connector_service
    import app.services.defender_client as defender
    import app.services.http_connector as http_layer
    import app.services.wazuh_client as wazuh

    modules = (
        http_layer,
        wazuh,
        defender,
        connector_service,
        endpoints,
        schemas,
    )
    for module in modules:
        tree = _ast.parse(_inspect.getsource(module))
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
                assert not (
                    set(names)
                    & {
                        "subprocess",
                        "os",
                        "pty",
                        "shutil",
                        "importlib",
                        "socket",
                        "requests",
                    }
                ), (module.__name__, names)
            elif isinstance(node, _ast.ImportFrom):
                mod = (node.module or "").split(".")[0]
                assert mod not in {
                    "subprocess",
                    "os",
                    "pty",
                    "shutil",
                    "importlib",
                    "socket",
                    "requests",
                }, (
                    module.__name__,
                    mod,
                )
            if isinstance(node, _ast.Call):
                func = node.func
                if isinstance(func, _ast.Name):
                    assert func.id not in {"eval", "exec", "compile", "__import__"}, func.id
                elif isinstance(func, _ast.Attribute):
                    assert func.attr not in {"system", "popen"}, func.attr

    http_source = _inspect.getsource(http_layer)
    # Redirects are refused, and only this module builds an HTTP client.
    assert "follow_redirects=False" in http_source
    assert http_source.count("httpx.Client(") == 1
    for module in (wazuh, defender, connector_service):
        assert "httpx.Client(" not in _inspect.getsource(module)
    # Wazuh/Defender clients go through the shared layer only.
    assert "ConnectorHttpClient" in _inspect.getsource(wazuh)
    assert "ConnectorHttpClient" in _inspect.getsource(defender)
    assert "validate_destination" in _inspect.getsource(defender)
    # The Step 26 file-poll constraint still holds: one read site.
    service_source = _inspect.getsource(connector_service)
    assert service_source.count("open(") == 1
    assert "socket" not in service_source and "urllib" not in service_source
