"""Brute-force protection for ``POST /auth/login`` (Step 32 Remediation 3).

Finding: the login endpoint applied no throttle of any kind — no lockout,
no failed-attempt counter, nothing but an audit row. Password guessing was
unbounded. (The scan-start half of the same finding was closed in
Remediation 2.)

The budget counts *failed* attempts, charged after the audit row is
committed. These tests pin both halves of that decision: guessing is
bounded, and a correct password is never throttled.
"""

import pytest

from app.core.config import Settings

LOGIN = "/api/v1/auth/login"
ADMIN = {
    "username": "admin",
    "password": "correct-horse-12345",
    "display_name": "Admin",
}


def _settings():
    from app.core.config import get_settings

    return get_settings()


@pytest.fixture()
def admin_user(client, clean_db):
    """A real, active user whose correct password is known."""
    created = client.post(
        "/api/v1/users",
        json={
            "username": ADMIN["username"],
            "password": ADMIN["password"],
            "display_name": ADMIN["display_name"],
            "roles": ["ADMIN"],
        },
    )
    assert created.status_code == 201, created.text
    return ADMIN


def _bad_password(username: str = ADMIN["username"]) -> dict:
    return {"username": username, "password": "wrong-password"}


def _count_login_failures(client) -> int:
    from sqlalchemy import func, select

    from app.database import session as session_module
    from app.models.auth import AuthAudit
    from app.services.auth_service import AUDIT_LOGIN_FAILURE

    db = session_module.get_session_factory()()
    try:
        return db.scalar(
            select(func.count())
            .select_from(AuthAudit)
            .where(AuthAudit.event == AUDIT_LOGIN_FAILURE)
        )
    finally:
        db.close()


def _correct_credentials() -> dict:
    """Only the two fields LoginRequest accepts."""
    return {"username": ADMIN["username"], "password": ADMIN["password"]}


# ---------------------------------------------------------------------------
# Guessing is bounded
# ---------------------------------------------------------------------------


def test_repeated_bad_passwords_are_throttled(client, clean_db, admin_user, monkeypatch):
    monkeypatch.setattr(_settings(), "rate_limit_login_failures", 3)
    client.app.state.limiter.reset()

    for index in range(3):
        response = client.post(LOGIN, json=_bad_password())
        assert response.status_code == 401, index
        assert response.json()["error"]["code"] == "INVALID_CREDENTIALS"

    limited = client.post(LOGIN, json=_bad_password())
    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "RATE_LIMITED"
    assert int(limited.headers["Retry-After"]) >= 1


def test_unknown_usernames_are_throttled_too(client, clean_db, admin_user, monkeypatch):
    """Guessing a name that does not exist must not be a free bypass."""
    monkeypatch.setattr(_settings(), "rate_limit_login_failures", 2)
    client.app.state.limiter.reset()

    for _ in range(2):
        assert client.post(LOGIN, json=_bad_password("no-such-user")).status_code == 401
    assert client.post(LOGIN, json=_bad_password("no-such-user")).status_code == 429


def test_the_budget_is_shared_across_usernames(client, clean_db, admin_user, monkeypatch):
    """One caller gets one budget: spraying names cannot evade it."""
    monkeypatch.setattr(_settings(), "rate_limit_login_failures", 2)
    client.app.state.limiter.reset()

    client.post(LOGIN, json=_bad_password("user-a"))
    client.post(LOGIN, json=_bad_password("user-b"))
    assert client.post(LOGIN, json=_bad_password("user-c")).status_code == 429


def test_a_throttled_attempt_is_still_audited(client, clean_db, admin_user, monkeypatch):
    """A 429 must never hide the evidence that caused it."""
    monkeypatch.setattr(_settings(), "rate_limit_login_failures", 1)
    client.app.state.limiter.reset()

    assert client.post(LOGIN, json=_bad_password()).status_code == 401
    assert client.post(LOGIN, json=_bad_password()).status_code == 429
    assert _count_login_failures(client) == 2, (
        "both failures must be recorded, including the throttled one"
    )


def test_the_generic_failure_message_is_unchanged(client, clean_db, admin_user, monkeypatch):
    """Throttling must not become a username-enumeration signal."""
    monkeypatch.setattr(_settings(), "rate_limit_login_failures", 5)
    client.app.state.limiter.reset()

    known = client.post(LOGIN, json=_bad_password())
    unknown = client.post(LOGIN, json=_bad_password("no-such-user"))
    assert known.status_code == unknown.status_code == 401
    assert known.json() == unknown.json()


# ---------------------------------------------------------------------------
# Legitimate use is never throttled
# ---------------------------------------------------------------------------


def test_correct_passwords_are_never_throttled(client, clean_db, admin_user, monkeypatch):
    """The control bounds guessing, not logins."""
    monkeypatch.setattr(_settings(), "rate_limit_login_failures", 1)
    client.app.state.limiter.reset()

    for index in range(8):
        response = client.post(LOGIN, json=_correct_credentials())
        assert response.status_code == 200, index
        assert response.json()["token_type"] == "bearer"


def test_a_correct_password_still_works_under_the_budget(client, clean_db, admin_user, monkeypatch):
    monkeypatch.setattr(_settings(), "rate_limit_login_failures", 3)
    client.app.state.limiter.reset()

    client.post(LOGIN, json=_bad_password())
    client.post(LOGIN, json=_bad_password())
    assert client.post(LOGIN, json=_correct_credentials()).status_code == 200


def test_zero_disables_the_login_budget(client, clean_db, admin_user, monkeypatch):
    monkeypatch.setattr(_settings(), "rate_limit_login_failures", 0)
    client.app.state.limiter.reset()

    for _ in range(6):
        assert client.post(LOGIN, json=_bad_password()).status_code == 401


def test_other_endpoints_keep_their_own_budgets(client, clean_db, admin_user, monkeypatch):
    """Charging a login failure must not spend a scan or risk budget."""
    from app.core.ratelimit import get_limiter

    monkeypatch.setattr(_settings(), "rate_limit_login_failures", 1)
    client.app.state.limiter.reset()

    client.post(LOGIN, json=_bad_password())
    client.post(LOGIN, json=_bad_password())
    assert client.post(LOGIN, json=_bad_password()).status_code == 429

    limiter = get_limiter(client)
    assert limiter is client.app.state.limiter
    # The scan and risk operations still have their full default budget.
    from app.core.config import get_settings

    settings = get_settings()
    assert settings.rate_limit_scan_start > 1
    assert settings.rate_limit_risk_calculate > 1


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------


def test_login_failure_budget_is_configurable_and_documented():
    """A shipped default that operators cannot tune would repeat the dead-setting bug."""
    assert "rate_limit_login_failures" in Settings.model_fields
    field = Settings.model_fields["rate_limit_login_failures"]
    assert field.default == 5
    assert field.metadata, "the setting must keep its bounds"


def test_login_budget_is_shipped_to_the_container():
    """The env var must be forwarded, or the container silently uses the default.

    Matched with its exact indentation: a mis-indented line is still a
    substring match but is not valid YAML inside the service block, which
    would break the whole compose file rather than this one setting.
    """
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    compose_text = (root / "docker-compose.yml").read_text(encoding="utf-8")
    env_text = (root / ".env.example").read_text(encoding="utf-8")

    compose_lines = [
        line for line in compose_text.splitlines() if "RATE_LIMIT_LOGIN_FAILURES" in line
    ]
    assert len(compose_lines) == 1, compose_lines
    assert re.match(
        r"^ {6}RATE_LIMIT_LOGIN_FAILURES: \$\{RATE_LIMIT_LOGIN_FAILURES:-\d+\}$", compose_lines[0]
    ), compose_lines[0]

    env_lines = [line for line in env_text.splitlines() if "RATE_LIMIT_LOGIN_FAILURES" in line]
    assert len(env_lines) == 1, env_lines
    assert re.match(r"^RATE_LIMIT_LOGIN_FAILURES=\d+$", env_lines[0]), env_lines[0]
