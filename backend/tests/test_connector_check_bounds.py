"""Focused protection tests for the connector-check endpoint.

The check endpoint performs audited outbound work, so it must have a
per-caller budget and must not run two checks for one connector at once.
These tests use the existing fixed-window limiter and the same structured
error conventions as the polling endpoint.
"""

from types import SimpleNamespace

from tests.test_auth import _admin_headers, _auth_header

CHECK = "/api/v1/events/connectors/{source}/check"


def _configure(client, monkeypatch, *, limit=60, window=3600):
    from app.core.config import get_settings
    from app.services import connector_polling

    for name in (
        "WAZUH_API_URL",
        "WAZUH_USERNAME",
        "WAZUH_PASSWORD",
        "DEFENDER_TENANT_ID",
        "DEFENDER_CLIENT_ID",
        "DEFENDER_CLIENT_SECRET",
    ):
        monkeypatch.setenv(name, "")
    get_settings.cache_clear()
    settings = get_settings()
    monkeypatch.setattr(settings, "rate_limit_connector_poll", limit)
    monkeypatch.setattr(settings, "rate_limit_window_seconds", window)
    client.app.state.settings = settings
    client.app.state.limiter.reset()
    connector_polling.reset()
    return settings


def _check(client, source, headers):
    return client.post(CHECK.format(source=source), headers=headers)


def _audit_actions():
    from sqlalchemy import select

    from app.database import session as session_module
    from app.models.events import EventAudit

    db = session_module.get_session_factory()()
    try:
        return [row.action for row in db.scalars(select(EventAudit)).all()]
    finally:
        db.close()


def test_normal_check_still_succeeds(client, clean_db, monkeypatch):
    _configure(client, monkeypatch)
    admin = _admin_headers(client)

    response = _check(client, "wazuh", admin)

    assert response.status_code == 200
    assert response.json()["connector_state"] == "NOT_CONFIGURED"
    assert _audit_actions().count("CONNECTOR_CHECK_STARTED") == 1


def test_repeated_checks_follow_the_budget_and_throttle_has_no_side_effects(
    client, clean_db, monkeypatch
):
    _configure(client, monkeypatch, limit=2)
    admin = _admin_headers(client)

    responses = [_check(client, "wazuh", admin) for _ in range(3)]

    assert [response.status_code for response in responses] == [200, 200, 429]
    limited = responses[-1]
    assert limited.json()["error"]["code"] == "RATE_LIMITED"
    assert limited.headers["Retry-After"].isdigit()
    assert "wazuh" not in limited.json()["error"]["message"].lower()
    actions = _audit_actions()
    assert actions.count("CONNECTOR_CHECK_STARTED") == 2
    assert actions.count("CONNECTOR_UNAVAILABLE") == 2


def test_budget_expires_at_the_next_fixed_window(client, clean_db, monkeypatch):
    from app.core import ratelimit

    _configure(client, monkeypatch, limit=1, window=10)
    admin = _admin_headers(client)
    clock = iter([100.0, 101.0, 111.0])
    monkeypatch.setattr(ratelimit, "time", SimpleNamespace(monotonic=lambda: next(clock)))

    first = _check(client, "wazuh", admin)
    limited = _check(client, "wazuh", admin)
    after_window = _check(client, "wazuh", admin)

    assert first.status_code == 200
    assert limited.status_code == 429
    assert limited.headers["Retry-After"] == "9"
    assert after_window.status_code == 200


def test_budget_is_isolated_per_caller(client, clean_db, monkeypatch):
    _configure(client, monkeypatch, limit=1)
    admin = _admin_headers(client)
    other_admin = _auth_header(
        client, "admin2", "second-admin-pass-1", roles=("ADMIN",)
    )

    assert _check(client, "wazuh", admin).status_code == 200
    assert _check(client, "wazuh", admin).status_code == 429
    assert _check(client, "wazuh", other_admin).status_code == 200


def test_overlapping_check_is_rejected_and_other_connectors_are_isolated(
    client, clean_db, monkeypatch
):
    from app.services import connector_polling

    _configure(client, monkeypatch)
    admin = _admin_headers(client)
    lock = connector_polling.check_lock_for("wazuh")
    assert lock.acquire(blocking=False)
    try:
        blocked = _check(client, "wazuh", admin)
        other = _check(client, "defender", admin)
    finally:
        lock.release()

    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "CHECK_IN_PROGRESS"
    assert other.status_code == 200
    assert _check(client, "wazuh", admin).status_code == 200
    assert _audit_actions().count("CONNECTOR_CHECK_STARTED") == 2


def test_auth_and_authorization_are_preserved(client, clean_db, monkeypatch):
    _configure(client, monkeypatch, limit=1)
    admin = _admin_headers(client)
    assert client.post(CHECK.format(source="wazuh")).status_code == 401
    viewer = _auth_header(
        client, "viewer1", "viewer-pass-word-1", roles=("VIEWER",)
    )
    denied = _check(client, "wazuh", viewer)
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "PERMISSION_DENIED"
    assert _audit_actions() == []

    assert _check(client, "wazuh", admin).status_code == 200


def test_check_budget_does_not_consume_the_poll_budget(client, clean_db, monkeypatch):
    _configure(client, monkeypatch, limit=1)
    admin = _admin_headers(client)

    assert _check(client, "wazuh", admin).status_code == 200
    assert _check(client, "wazuh", admin).status_code == 429

    poll = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
    assert poll.status_code == 422
    assert poll.json()["error"]["code"] == "CONNECTOR_UNAVAILABLE"
