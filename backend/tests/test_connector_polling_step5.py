"""Phase 2 Step 5 — controlled polling policy.

Covers the layer added around the existing Step 26–28 pipeline: overlap
prevention, interval and failure cool-down, the opt-in due-poll pass
(disabled by default), and the safe health metadata that reports it.

**No test contacts a real Wazuh or Defender service.** Every HTTP
interaction goes through ``httpx.MockTransport``; file-mode sources use a
temporary file. Fixture mode is exercised unchanged.
"""

import json
import threading
import time
from pathlib import Path

import httpx
import pytest

WAZUH_ALERT = {
    "id": "step5-1",
    "timestamp": "2026-01-05T10:00:00.000+0000",
    "rule": {"id": "5712", "level": 12, "description": "Step 5 mock rule"},
    "agent": {"id": "001", "name": "agent-1", "ip": "10.0.0.5"},
    "data": {"srcip": "203.0.113.10", "dstip": "10.0.0.5"},
    "location": "/var/log/test",
}

GRAPH = "graph.microsoft.com"
AUTHORITY = "login.microsoftonline.com"


def _install(handler):
    from app.services import http_connector

    http_connector.install_test_transport(httpx.MockTransport(handler))


def _configure(monkeypatch, **overrides):
    from app.core.config import get_settings

    for key, value in overrides.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    return get_settings()


def _clear():
    from app.core.config import get_settings
    from app.services import connector_polling

    connector_polling.reset()
    get_settings.cache_clear()


def _wazuh(pages=None, state=None, fail=None):
    remaining = list(pages) if pages else []

    def handler(request: httpx.Request) -> httpx.Response:
        if state is not None:
            state.setdefault("calls", []).append(f"{request.method} {request.url.path}")
        if fail is not None and request.url.path.endswith("/security/user/authenticate"):
            return fail
        if request.url.path.endswith("/security/user/authenticate"):
            return httpx.Response(200, json={"token": "mock-jwt-token-value"})
        if request.url.path.endswith("/manager/info"):
            return httpx.Response(200, json={"data": {}, "error": 0})
        if request.url.path.endswith("/alerts"):
            page = (
                remaining.pop(0)
                if len(remaining) > 1
                else (
                    remaining[0]
                    if remaining
                    else {"data": {"totalItems": 0, "alerts": []}, "error": 0}
                )
            )
            return httpx.Response(200, json=page)
        raise AssertionError(f"unexpected path {request.url.path}")

    return handler


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


def _configure_wazuh(monkeypatch, **overrides):
    base = {
        "WAZUH_API_URL": "https://wazuh.test:55000",
        "WAZUH_USERNAME": "u",
        "WAZUH_PASSWORD": "p",
        "CONNECTOR_RETRY_MAX": "0",
    }
    base.update(overrides)
    return _configure(monkeypatch, **base)


def _audits():
    from sqlalchemy import select

    from app.database import session as session_module
    from app.models.events import EventAudit

    db = session_module.get_session_factory()()
    try:
        return [(row.action, row.detail or "") for row in db.scalars(select(EventAudit)).all()]
    finally:
        db.close()


def _poll_health(client, source, headers):
    return client.get(f"/api/v1/events/connectors/{source}", headers=headers).json()["polling"]


# ---------------------------------------------------------------------------
# 1. Manual Poll Now keeps working
# ---------------------------------------------------------------------------


def test_manual_poll_now_still_works(monkeypatch, client, clean_db):
    _install(_wazuh(pages=[{"data": {"totalItems": 1, "alerts": [WAZUH_ALERT]}, "error": 0}]))
    _configure_wazuh(monkeypatch)
    try:
        admin = _tokens(client)
        response = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        assert response.status_code == 200
        body = response.json()
        assert body["accepted"] == 1
        assert body["termination"] == "COMPLETED"
    finally:
        _clear()


def test_manual_repeat_poll_is_idempotent(monkeypatch, client, clean_db):
    """A second manual poll re-reads and is absorbed by dedup, not refused."""
    _install(_wazuh(pages=[{"data": {"totalItems": 1, "alerts": [WAZUH_ALERT]}, "error": 0}]))
    _configure_wazuh(monkeypatch)
    try:
        admin = _tokens(client)
        first = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin).json()
        assert first["accepted"] == 1
        repeat = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin).json()
        assert repeat["accepted"] == 0
        assert repeat["duplicates"] == 1
        events = client.get("/api/v1/events", params={"source_type": "WAZUH"}, headers=admin).json()
        assert events["total"] == 1
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 2. Never poll a NOT_CONFIGURED connector
# ---------------------------------------------------------------------------


def test_not_configured_connector_is_never_polled(monkeypatch, client, clean_db):
    state: dict = {}
    _install(_wazuh(state=state))
    _configure(monkeypatch, WAZUH_API_URL="", WAZUH_USERNAME="", WAZUH_PASSWORD="")
    try:
        admin = _tokens(client)
        response = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "CONNECTOR_UNAVAILABLE"
        assert state.get("calls") in (None, [])
    finally:
        _clear()


def test_due_pass_skips_not_configured_connectors(monkeypatch, client, clean_db):
    from app.services import connector_polling

    _install(_wazuh())
    _configure_wazuh(monkeypatch, CONNECTOR_AUTO_POLL_ENABLED="true")
    _configure(monkeypatch, WAZUH_API_URL="", WAZUH_USERNAME="", WAZUH_PASSWORD="")
    try:
        db = next(iter([None]), None)
        _ = db
        from app.database import session as session_module

        session = session_module.get_session_factory()()
        try:
            summary = connector_polling.run_due_polls(session, "step5")
        finally:
            session.close()
        assert "wazuh" in summary["skipped_not_configured"]
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 3. Automatic polling is disabled by default
# ---------------------------------------------------------------------------


def test_auto_poll_is_disabled_by_default(monkeypatch, client, clean_db):
    from app.core.config import Settings
    from app.services import connector_polling

    assert Settings.model_fields["connector_auto_poll_enabled"].default is False
    _install(_wazuh())
    _configure_wazuh(monkeypatch)
    try:
        from app.database import session as session_module

        session = session_module.get_session_factory()()
        try:
            summary = connector_polling.run_due_polls(session, "step5")
        finally:
            session.close()
        assert summary["enabled"] is False
        assert summary["polled"] == []
        assert "disabled" in summary["detail"].lower()
    finally:
        _clear()


def test_due_pass_polls_only_when_explicitly_enabled(monkeypatch, client, clean_db):
    from app.services import connector_polling

    _install(_wazuh(pages=[{"data": {"totalItems": 1, "alerts": [WAZUH_ALERT]}, "error": 0}]))
    _configure_wazuh(monkeypatch, CONNECTOR_AUTO_POLL_ENABLED="true")
    try:
        from app.database import session as session_module

        session = session_module.get_session_factory()()
        try:
            summary = connector_polling.run_due_polls(session, "step5")
        finally:
            session.close()
        assert summary["enabled"] is True
        assert any(item["source"] == "wazuh" for item in summary["polled"])
    finally:
        _clear()


def test_no_background_thread_or_timer_is_started():
    """The mechanism must stay scheduler-free."""
    before = {t.name for t in threading.enumerate()}
    from app.services import connector_polling

    connector_polling.reset()
    after = {t.name for t in threading.enumerate()}
    assert before == after


# ---------------------------------------------------------------------------
# 4. Overlap prevention
# ---------------------------------------------------------------------------


def test_overlapping_poll_is_refused(monkeypatch, client, clean_db):
    """A second concurrent poll of the same connector is refused, not run."""
    from app.services import connector_polling

    started = threading.Event()
    release = threading.Event()

    def slow(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/alerts"):
            started.set()
            release.wait(timeout=5)
            return httpx.Response(200, json={"data": {"totalItems": 0, "alerts": []}, "error": 0})
        return _wazuh()(request)

    _install(slow)
    _configure_wazuh(monkeypatch)
    try:
        from app.database import session as session_module

        outcome: dict = {}

        def worker() -> None:
            session = session_module.get_session_factory()()
            try:
                connector_polling.poll_connector(session, "wazuh", "step5")
                outcome["result"] = "completed"
            except BaseException as exc:  # noqa: BLE001
                outcome["result"] = type(exc).__name__
            finally:
                session.close()

        thread = threading.Thread(target=worker)
        thread.start()
        assert started.wait(timeout=5), "first poll never reached the network"

        # The second attempt, while the first holds the lock.
        session = session_module.get_session_factory()()
        try:
            with pytest.raises(connector_polling.PollInProgress):
                connector_polling.poll_connector(session, "wazuh", "step5")
            outcome["refused"] = True
        finally:
            session.close()

        release.set()
        thread.join(timeout=5)
        assert outcome.get("result") == "completed"
        assert outcome.get("refused") is True
    finally:
        _clear()


def test_overlap_is_reported_as_409_over_http(monkeypatch, client, clean_db):
    """The endpoint maps an in-flight poll to a conflict, not a 500."""
    from app.services import connector_polling

    _install(_wazuh(pages=[{"data": {"totalItems": 0, "alerts": []}, "error": 0}]))
    _configure_wazuh(monkeypatch)
    try:
        admin = _tokens(client)
        assert (
            client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin).status_code
            == 200
        )

        # Simulate a stuck poll by holding the per-source lock directly.
        lock = connector_polling._lock_for("wazuh")  # noqa: SLF001
        assert lock.acquire(blocking=False)
        try:
            response = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
            assert response.status_code == 409
            assert response.json()["error"]["code"] == "POLL_IN_PROGRESS"
        finally:
            lock.release()
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 5. Interval and failure cool-down (anti-hammering)
# ---------------------------------------------------------------------------


def test_interval_defers_the_next_automatic_poll(monkeypatch, client, clean_db):
    from app.services import connector_polling

    _install(_wazuh(pages=[{"data": {"totalItems": 0, "alerts": []}, "error": 0}]))
    _configure_wazuh(
        monkeypatch, CONNECTOR_AUTO_POLL_ENABLED="true", CONNECTOR_POLL_INTERVAL_SECONDS="3600"
    )
    try:
        from app.database import session as session_module

        session = session_module.get_session_factory()()
        try:
            first = connector_polling.run_due_polls(session, "step5")
            assert any(i["source"] == "wazuh" for i in first["polled"])
            # Immediately after a successful poll it is no longer due.
            assert connector_polling.is_due("wazuh") is False
            second = connector_polling.run_due_polls(session, "step5")
            assert not any("wazuh" in str(i) for i in second["polled"])
            assert any("wazuh" in str(i) for i in second["skipped_not_due"])
        finally:
            session.close()
    finally:
        _clear()


def test_failure_sets_a_cool_down_and_records_the_category(monkeypatch, client, clean_db):
    from app.services import connector_polling, connectors

    _install(_wazuh(fail=httpx.Response(401, json={"message": "unauthorized"})))
    _configure_wazuh(monkeypatch, CONNECTOR_FAILURE_COOLDOWN_SECONDS="300")
    try:
        from app.database import session as session_module

        session = session_module.get_session_factory()()
        try:
            with pytest.raises(connectors.ConnectorUnavailableError):
                connector_polling.poll_connector(session, "wazuh", "step5")
        finally:
            session.close()

        health = connector_polling.health_for("wazuh")
        assert health.failures == 1
        assert health.last_error_category
        assert health.next_permitted_poll_at is not None
        assert connector_polling.is_due("wazuh") is False
    finally:
        _clear()


def test_unavailable_connector_is_not_hammered_automatically(monkeypatch, client, clean_db):
    from app.services import connector_polling

    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        raise httpx.ConnectError("mock refused", request=request)

    _install(handler)
    _configure_wazuh(
        monkeypatch, CONNECTOR_AUTO_POLL_ENABLED="true", CONNECTOR_FAILURE_COOLDOWN_SECONDS="600"
    )
    try:
        from app.database import session as session_module

        session = session_module.get_session_factory()()
        try:
            first = connector_polling.run_due_polls(session, "step5")
            attempted = len(calls)
            assert attempted > 0
            assert any(f["source"] == "wazuh" for f in first["failed"])
            # A second pass immediately after must not touch the network.
            second = connector_polling.run_due_polls(session, "step5")
            assert len(calls) == attempted
            assert any("wazuh" in str(i) for i in second["skipped_not_due"])
        finally:
            session.close()
    finally:
        _clear()


def test_manual_poll_respects_cooldown_when_asked(monkeypatch, client, clean_db):
    from app.services import connector_polling, connectors

    _install(_wazuh(fail=httpx.Response(401, json={"message": "unauthorized"})))
    _configure_wazuh(monkeypatch, CONNECTOR_FAILURE_COOLDOWN_SECONDS="300")
    try:
        from app.database import session as session_module

        session = session_module.get_session_factory()()
        try:
            with pytest.raises(connectors.ConnectorUnavailableError):
                connector_polling.poll_connector(session, "wazuh", "step5")
            with pytest.raises(connector_polling.PollCooldown) as info:
                connector_polling.poll_connector(session, "wazuh", "step5", respect_cooldown=True)
            assert info.value.retry_after_seconds > 0
        finally:
            session.close()
    finally:
        _clear()


def test_rate_limited_poll_waits_longer(monkeypatch, client, clean_db):
    from app.services import connector_polling, connectors

    _install(_wazuh(fail=httpx.Response(429, headers={"retry-after": "30"}, json={})))
    _configure_wazuh(monkeypatch, CONNECTOR_FAILURE_COOLDOWN_SECONDS="1")
    try:
        from app.database import session as session_module

        session = session_module.get_session_factory()()
        try:
            with pytest.raises(connectors.ConnectorUnavailableError):
                connector_polling.poll_connector(session, "wazuh", "step5")
        finally:
            session.close()
        health = connector_polling.health_for("wazuh")
        assert health.last_error_category == "RATE_LIMITED"
        assert health.next_permitted_poll_at is not None
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 6. Health metadata (safe)
# ---------------------------------------------------------------------------


def test_health_metadata_reports_the_poll_outcome(monkeypatch, client, clean_db):
    _install(_wazuh(pages=[{"data": {"totalItems": 2, "alerts": [WAZUH_ALERT]}, "error": 0}]))
    _configure_wazuh(monkeypatch)
    try:
        admin = _tokens(client)
        client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        health = _poll_health(client, "wazuh", admin)
        assert health["last_poll_started_at"]
        assert health["last_poll_completed_at"]
        assert health["last_successful_poll_at"]
        # The mock replays one page against totalItems=2, so the poll
        # legitimately retrieves 2, stores 1, and dedups 1 - the counting
        # path the metadata reports.
        assert health["events_received"] == 2
        assert health["events_accepted"] == 1
        assert health["events_deduplicated"] == 1
        assert health["last_error_category"] is None
        assert health["in_flight"] is False
        assert health["polls"] == 1
        assert health["next_permitted_poll_at"]
    finally:
        _clear()


def test_health_metadata_reports_failures(monkeypatch, client, clean_db):
    _install(_wazuh(fail=httpx.Response(401, json={"message": "unauthorized"})))
    _configure_wazuh(monkeypatch)
    try:
        admin = _tokens(client)
        client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        health = _poll_health(client, "wazuh", admin)
        assert health["last_error_category"]
        assert health["last_successful_poll_at"] is None
        assert health["failures"] == 1
        assert health["in_flight"] is False
    finally:
        _clear()


def test_health_metadata_never_contains_secrets(monkeypatch, client, clean_db):
    secret = "step5-wazuh-password-secret"
    token = "step5-wazuh-token-secret"
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.path.endswith("/security/user/authenticate"):
            return httpx.Response(200, json={"token": token})
        return httpx.Response(
            200, json={"data": {"totalItems": 1, "alerts": [WAZUH_ALERT]}, "error": 0}
        )

    _install(handler)
    _configure_wazuh(monkeypatch, WAZUH_PASSWORD=secret)
    try:
        admin = _tokens(client)
        poll = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        status = client.get("/api/v1/events/connectors/wazuh", headers=admin)
        listing = client.get("/api/v1/events/connectors", headers=admin)
        blob = json.dumps(
            [poll.json(), status.json(), listing.json(), _audits(), calls], default=str
        )
        assert secret not in blob
        assert token not in blob
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 7. Bounds, dedup, audit, fixture mode preserved
# ---------------------------------------------------------------------------


def test_pagination_and_event_bounds_still_apply(monkeypatch, client, clean_db):
    many = [dict(WAZUH_ALERT, id=f"b{i}") for i in range(10)]
    _install(_wazuh(pages=[{"data": {"totalItems": 99, "alerts": many}, "error": 0}]))
    _configure_wazuh(monkeypatch, CONNECTOR_MAX_EVENTS="3", CONNECTOR_MAX_PAGES="2")
    try:
        admin = _tokens(client)
        body = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin).json()
        assert body["retrieved"] == 3
        assert body["termination"] == "MAX_EVENTS"
        assert body["truncated"] is True
    finally:
        _clear()


def test_repeated_cursor_protection_still_applies(monkeypatch, client, clean_db):
    """A replayed page must not loop forever."""
    page = {
        "data": {"totalItems": 500, "alerts": [dict(WAZUH_ALERT, id="same")]},
        "error": 0,
    }
    _install(_wazuh(pages=[page]))
    _configure_wazuh(monkeypatch, CONNECTOR_MAX_PAGES="5", CONNECTOR_MAX_EVENTS="500")
    try:
        admin = _tokens(client)
        body = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin).json()
        assert body["pages"] <= 5
        assert body["termination"] in {
            "MAX_PAGES",
            "MAX_EVENTS",
            "REPEATED_CURSOR",
            "COMPLETED",
        }
    finally:
        _clear()


def test_audit_events_are_preserved(monkeypatch, client, clean_db):
    _install(_wazuh(pages=[{"data": {"totalItems": 1, "alerts": [WAZUH_ALERT]}, "error": 0}]))
    _configure_wazuh(monkeypatch)
    try:
        admin = _tokens(client)
        client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        actions = [action for action, _ in _audits()]
        assert "CONNECTOR_POLL_STARTED" in actions
        assert "CONNECTOR_POLL_COMPLETED" in actions
    finally:
        _clear()


def test_fixture_mode_file_source_still_polls(monkeypatch, client, clean_db, tmp_path):
    """File/fixture sources are unaffected by the polling policy."""
    from tests.test_connectors import _read

    eve = tmp_path / "eve.json"
    eve.write_text(_read("alert.json", "suricata") + "\n", encoding="utf-8")
    _configure(monkeypatch, SURICATA_EVE_PATH=str(eve))
    try:
        from app.core.config import get_settings

        get_settings.cache_clear()
        admin = _tokens(client)
        response = client.post("/api/v1/events/connectors/suricata/poll", json={}, headers=admin)
        assert response.status_code == 200
        assert response.json()["accepted"] == 1
    finally:
        _clear()


def test_unknown_source_is_still_422(monkeypatch, client, clean_db):
    _configure_wazuh(monkeypatch)
    try:
        admin = _tokens(client)
        response = client.post("/api/v1/events/connectors/nope/poll", json={}, headers=admin)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "UNKNOWN_CONNECTOR"
    finally:
        _clear()


def test_rbac_is_preserved_for_polling(monkeypatch, client, clean_db):
    _install(_wazuh())
    _configure_wazuh(monkeypatch)
    try:
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
            "/api/v1/auth/login",
            json={"username": "viewer1", "password": "viewer-pass-1234"},
        ).json()["access_token"]
        viewer = {"Authorization": f"Bearer {viewer_token}"}
        denied = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=viewer)
        assert denied.status_code == 403
        assert denied.json()["error"]["code"] == "PERMISSION_DENIED"
    finally:
        _clear()


def test_poll_rate_limit_is_preserved(monkeypatch, client, clean_db):
    """The existing per-caller poll budget still bounds manual polling."""
    _install(_wazuh(pages=[{"data": {"totalItems": 0, "alerts": []}, "error": 0}]))
    _configure_wazuh(monkeypatch, RATE_LIMIT_CONNECTOR_POLL="2")
    try:
        admin = _tokens(client)
        codes = [
            client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin).status_code
            for _ in range(4)
        ]
        assert 429 in codes
    finally:
        _clear()


def test_new_settings_are_documented_and_bounded():
    from app.core.config import Settings

    for name in (
        "connector_auto_poll_enabled",
        "connector_poll_interval_seconds",
        "connector_failure_cooldown_seconds",
    ):
        assert name in Settings.model_fields
    assert Settings.model_fields["connector_poll_interval_seconds"].default == 300.0
    assert Settings.model_fields["connector_failure_cooldown_seconds"].default == 60.0
    _ = time  # imported for the threading test above


def test_env_example_ships_auto_poll_disabled():
    root = Path(__file__).resolve().parents[2]
    text = (root / ".env.example").read_text(encoding="utf-8")
    assert "CONNECTOR_AUTO_POLL_ENABLED=false" in text
