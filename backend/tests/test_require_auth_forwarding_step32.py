"""REQUIRE_AUTH propagation to the container (Step 32 Remediation 4).

Finding: ``REQUIRE_AUTH`` was documented in ``.env.example`` and read by
``Settings``, but it was absent from the backend service's ``environment:``
block. The backend image copies only ``app``/``alembic``/``alembic.ini``, so
the ``env_file=".env"`` source resolves to nothing inside the container and an
unlisted variable is never delivered. Setting ``REQUIRE_AUTH=true`` in the
project ``.env`` therefore did nothing: the deployed service stayed in
auth bootstrap mode, where the first caller can create an administrator
without credentials.

These tests cover both directions -- enforced *and* disabled -- plus the
delivery path itself, since the bug lived in configuration and no amount of
application-level testing would have caught it.
"""

import os
import re
from pathlib import Path

import pytest
import yaml

LOGIN = "/api/v1/auth/login"
ADMIN = {
    "username": "admin",
    "password": "correct-horse-12345",
    "display_name": "Admin",
    "roles": ["ADMIN"],
}
ROOT = Path(__file__).resolve().parents[2]


def _backend_environment() -> dict:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    return compose["services"]["backend"]["environment"]


# ---------------------------------------------------------------------------
# Delivery: the value can actually reach the service
# ---------------------------------------------------------------------------


def test_require_auth_is_forwarded_to_the_backend_service():
    """The regression itself: the variable must be listed, not just documented."""
    environment = _backend_environment()
    assert "REQUIRE_AUTH" in environment, (
        "REQUIRE_AUTH is not in the backend environment block, so the container "
        "never receives it and auth bootstrap mode stays enabled"
    )


def test_forwarding_uses_project_env_interpolation_with_a_safe_default():
    """`${VAR:-default}` is how the operator's .env value reaches the container.

    A hardcoded literal would ignore the project .env; a missing default
    would make `docker compose up` fail for anyone without the variable set.
    """
    value = _backend_environment()["REQUIRE_AUTH"]
    match = re.fullmatch(r"\$\{REQUIRE_AUTH:-(\w+)\}", value)
    assert match, f"expected ${{REQUIRE_AUTH:-<default>}}, got {value!r}"
    assert match.group(1) == "false", "unset must keep the documented bootstrap default"


def test_backend_service_does_not_relie_on_env_file():
    """`env_file` would deliver everything; its absence is why listing matters."""
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    assert "env_file" not in compose["services"]["backend"]


def test_the_image_ships_no_env_file_to_read():
    """Documents *why* forwarding is required: there is no fallback source."""
    dockerfile = (ROOT / "backend" / "Dockerfile").read_text(encoding="utf-8")
    assert not re.search(r"^COPY\s+.*\.env", dockerfile, re.MULTILINE)


def test_setting_is_documented_for_operators():
    assert "REQUIRE_AUTH" in (ROOT / ".env.example").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("true", True), ("false", False), ("1", True), ("0", False)],
)
def test_value_reaching_the_environment_drives_the_setting(raw, expected):
    """End of the chain: environment value -> Settings.require_auth."""
    from app.core.config import Settings

    previous = os.environ.get("REQUIRE_AUTH")
    os.environ["REQUIRE_AUTH"] = raw
    try:
        assert Settings().require_auth is expected
    finally:
        if previous is None:
            os.environ.pop("REQUIRE_AUTH", None)
        else:
            os.environ["REQUIRE_AUTH"] = previous


# ---------------------------------------------------------------------------
# Behaviour: enforced
# ---------------------------------------------------------------------------


@pytest.fixture()
def require_auth(monkeypatch):
    """Set REQUIRE_AUTH the way the container would, then drop the cache.

    ``get_settings`` is an LRU cache, so a value set after ``create_app()``
    is invisible until it is cleared. This mirrors the existing
    ``test_require_auth_mode_disables_bootstrap`` convention.
    """
    from app.core.config import get_settings

    def _set(raw: str) -> None:
        monkeypatch.setenv("REQUIRE_AUTH", raw)
        get_settings.cache_clear()

    yield _set
    get_settings.cache_clear()


def test_enabled_requires_authentication_everywhere(client, clean_db, require_auth):
    """With REQUIRE_AUTH=true there is no unauthenticated escape hatch."""
    require_auth("true")

    # No user exists, yet creation is refused: bootstrap cannot even begin.
    assert client.post("/api/v1/users", json=ADMIN).status_code == 401
    assert client.get("/api/v1/network/scans").status_code == 401
    assert client.get("/api/v1/auth/me").status_code == 401
    # Login stays reachable -- it is how a token is obtained.
    assert client.post(LOGIN, json={"username": "admin", "password": "x"}).status_code == 401


def test_enabled_on_an_empty_database_admits_nobody(client, clean_db, require_auth):
    """Pins the operational consequence of forwarding the setting.

    There is no CLI to create the first administrator, so enabling this on
    an empty database is irreversible through the API. That is the correct
    trade (better than an open first-caller-wins deployment) but it must be
    a deliberate, documented choice by the operator.
    """
    require_auth("true")

    assert client.post("/api/v1/users", json=ADMIN).status_code == 401
    assert client.post(LOGIN, json={"username": "admin", "password": "whatever"}).status_code == 401


def test_enabled_still_allows_a_valid_login(client, clean_db, require_auth):
    """Enforcement must not break the login path for an existing user."""
    from tests.test_auth import _admin_headers

    # Create the administrator while bootstrap is still available...
    created = client.post("/api/v1/users", json=ADMIN)
    assert created.status_code in (201, 409), created.text
    # ...then enforce.
    require_auth("true")

    headers = _admin_headers(client)
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200


# ---------------------------------------------------------------------------
# Behaviour: disabled (unchanged)
# ---------------------------------------------------------------------------


def test_disabled_keeps_bootstrap_mode(client, clean_db, require_auth):
    """The documented local workflow must be untouched by this fix."""
    require_auth("false")

    # No user yet and enforcement off: bootstrap passes reads through.
    assert client.get("/api/v1/network/scans").status_code == 200
    # The first user may still be created without a token.
    assert client.post("/api/v1/users", json=ADMIN).status_code == 201


def test_unset_keeps_bootstrap_mode(client, clean_db, monkeypatch):
    """An absent variable must behave exactly like an explicit false."""
    from app.core.config import get_settings

    monkeypatch.delenv("REQUIRE_AUTH", raising=False)
    get_settings.cache_clear()
    try:
        assert client.get("/api/v1/network/scans").status_code == 200
        assert client.post("/api/v1/users", json=ADMIN).status_code == 201
    finally:
        get_settings.cache_clear()


def test_disabled_does_not_weaken_rbac_once_a_user_exists(client, clean_db, require_auth):
    """Bootstrap is an empty-database convenience, not a permanent bypass."""
    from tests.test_auth import _admin_headers

    require_auth("false")
    assert client.post("/api/v1/users", json=ADMIN).status_code == 201

    # A user now exists, so every request must present a token again.
    assert client.get("/api/v1/network/scans").status_code == 401
    headers = _admin_headers(client)
    me = client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["username"] == ADMIN["username"]
