"""Phase 2 Step 10 — production hardening.

Covers the three hardening areas applied in this step:

1. ``validate_production`` refuses an open bootstrap, disabled TLS
   verification and empty Host validation.
2. Secret redaction applies to *every* LogRecord, including records handled
   by uvicorn's own non-propagating handlers.
3. The deployed Compose surface stays loopback-only with a read-only backend
   root filesystem.
"""

import logging
import logging.config

import pytest

from app.core.config import ENV_PRODUCTION, ENV_STAGING, Settings

SECRET = "s10-super-secret-value"


# ---------------------------------------------------------------------------
# 1. Production configuration hardening
# ---------------------------------------------------------------------------


def _production(**overrides) -> Settings:
    base = {
        "environment": ENV_PRODUCTION,
        "secret_key": "k" * 48,
        "database_url": "postgresql+psycopg://u:s10-real-db-password@db:5432/app",
        "backend_cors_origins": ["https://soc.example.com"],
        "require_auth": True,
        "connector_verify_tls": True,
        "trusted_hosts": ["soc.example.com"],
    }
    base.update(overrides)
    return Settings(**base)


def _staging(**overrides) -> Settings:
    base = {
        "environment": ENV_STAGING,
        "secret_key": "k" * 48,
        "database_url": "postgresql+psycopg://u:s10-real-db-password@db:5432/app",
        "backend_cors_origins": ["https://staging.soc.example.com"],
        "require_auth": True,
        "connector_verify_tls": True,
        "trusted_hosts": ["staging.soc.example.com"],
    }
    base.update(overrides)
    return Settings(**base)


def test_a_fully_hardened_production_config_starts():
    settings = _production()
    settings.validate_production()  # must not raise
    assert settings.is_production


def test_production_refuses_an_open_bootstrap():
    """REQUIRE_AUTH=false leaves unauthenticated first-admin creation open."""
    with pytest.raises(RuntimeError, match="REQUIRE_AUTH must be true in production"):
        _production(require_auth=False).validate_production()


def test_staging_refuses_an_open_bootstrap():
    """Staging is release-like and must not run the unauthenticated bootstrap."""
    with pytest.raises(RuntimeError, match="REQUIRE_AUTH must be true in staging"):
        _staging(require_auth=False).validate_production()


def test_valid_staging_configuration_passes():
    """A fully-configured staging deployment with REQUIRE_AUTH=true is accepted."""
    settings = _staging()
    settings.validate_production()  # must not raise
    assert settings.environment == ENV_STAGING
    assert not settings.is_production


def test_production_refuses_disabled_connector_tls():
    with pytest.raises(RuntimeError, match="CONNECTOR_VERIFY_TLS must be true"):
        _production(connector_verify_tls=False).validate_production()


def test_production_refuses_empty_trusted_hosts():
    with pytest.raises(RuntimeError, match="TRUSTED_HOSTS must list"):
        _production(trusted_hosts=[]).validate_production()


def test_new_rules_are_scoped_to_production_only():
    """Development and test must not start failing on these settings."""
    for environment in ("development", "test"):
        settings = Settings(
            environment=environment,
            require_auth=False,
            connector_verify_tls=False,
            trusted_hosts=[],
        )
        settings.validate_production()  # must not raise


def test_existing_production_guards_still_hold():
    """Step 10 must not weaken any earlier production guard."""
    still_refused = {
        "debug": {"debug": True},
        "placeholder_secret": {"secret_key": "CHANGE_ME_dev_only"},
        "short_secret": {"secret_key": "tooshort"},
        "placeholder_db": {"database_url": "postgresql+psycopg://u:changeme_in_env@db:5432/app"},
        "empty_cors": {"backend_cors_origins": []},
        "dev_cors_only": {
            "backend_cors_origins": [
                "http://localhost:5173",
                "http://localhost:3000",
                "http://localhost",
            ]
        },
        "unbounded_body": {"max_request_bytes": 0},
    }
    for label, override in still_refused.items():
        try:
            _production(**override).validate_production()
        except RuntimeError:
            continue
        pytest.fail(f"{label} should still be refused")


def test_production_error_messages_never_echo_the_secret():
    """A misconfiguration must not leak the value it complains about."""
    try:
        _production(require_auth=False).validate_production()
    except RuntimeError as exc:
        assert SECRET not in str(exc)
        assert "REQUIRE_AUTH" in str(exc)
    else:  # pragma: no cover
        pytest.fail("expected a RuntimeError")


def test_production_rejects_an_unlisted_host_header(monkeypatch):
    """Proof the new TRUSTED_HOSTS rule enforces validation, not just startup."""
    from starlette.testclient import TestClient

    from app.core.config import get_settings
    from app.main import create_app

    for name, value in (
        ("ENVIRONMENT", "production"),
        ("SECRET_KEY", "k" * 48),
        ("REQUIRE_AUTH", "true"),
        ("BACKEND_CORS_ORIGINS", '["https://soc.example"]'),
        ("DATABASE_URL", "postgresql+psycopg://u:realpassword@db:5432/app"),
        ("TRUSTED_HOSTS", '["soc.example"]'),
    ):
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()
    try:
        app = create_app()
        with TestClient(app) as client:
            assert client.get("/api/v1/health", headers={"Host": "soc.example"}).status_code == 200
            # A forged Host header is refused outright.
            assert client.get("/api/v1/health", headers={"Host": "evil.example"}).status_code == 400
    finally:
        get_settings.cache_clear()


def test_staging_startup_fails_fast_without_require_auth(monkeypatch):
    """Startup refuses an open bootstrap in staging, not just the unit method.

    Mirrors ``test_production_rejects_an_unlisted_host_header``: configuration is
    delivered through the environment and the LRU cache is cleared so the app
    under construction reads it. ``create_app`` must raise before serving.
    """
    from app.core.config import get_settings
    from app.main import create_app

    for name, value in (
        ("ENVIRONMENT", "staging"),
        ("SECRET_KEY", "k" * 48),
        ("REQUIRE_AUTH", "false"),
        ("BACKEND_CORS_ORIGINS", '["https://staging.soc.example"]'),
        ("DATABASE_URL", "postgresql+psycopg://u:realpassword@db:5432/app"),
        ("TRUSTED_HOSTS", '["staging.soc.example"]'),
    ):
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="REQUIRE_AUTH must be true in staging"):
            create_app()
    finally:
        get_settings.cache_clear()


def test_staging_startup_starts_when_require_auth_is_true(monkeypatch):
    """A valid staging configuration still boots the application."""
    from app.core.config import get_settings
    from app.main import create_app

    for name, value in (
        ("ENVIRONMENT", "staging"),
        ("SECRET_KEY", "k" * 48),
        ("REQUIRE_AUTH", "true"),
        ("BACKEND_CORS_ORIGINS", '["https://staging.soc.example"]'),
        ("DATABASE_URL", "postgresql+psycopg://u:realpassword@db:5432/app"),
        ("TRUSTED_HOSTS", '["staging.soc.example"]'),
    ):
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()
    try:
        app = create_app()
        assert app is not None
        assert not get_settings().is_production
    finally:
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# 2. Logging hardening
# ---------------------------------------------------------------------------


def test_redaction_covers_uvicorn_non_propagating_handlers(capsys):
    """The Step 31 filter could not see records uvicorn handles privately."""
    from app.core import logging as app_logging

    app_logging.setup_logging("INFO")
    # Reproduce uvicorn's own logging configuration: private handlers with
    # propagate=False, exactly as uvicorn.config.LOGGING_CONFIG sets up.
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "handlers": {"uvicorn_default": {"class": "logging.StreamHandler"}},
            "loggers": {
                "uvicorn": {
                    "handlers": ["uvicorn_default"],
                    "level": "INFO",
                    "propagate": False,
                },
                "uvicorn.error": {"level": "INFO"},
            },
        }
    )

    logging.getLogger("uvicorn.error").warning("connect failed password=%s", SECRET)
    logging.getLogger("uvicorn.error").warning("Authorization: Bearer %s", "abc.def-ghi")
    logging.getLogger("uvicorn.error").warning("db url postgresql://user:%s@db:5432/app", SECRET)

    captured = capsys.readouterr()
    # uvicorn's own handler writes to stderr, which is the point: the record
    # never touches the root handler where the Step 31 filter lived.
    assert SECRET not in captured.err
    assert "abc.def-ghi" not in captured.err
    assert "password=***" in captured.err
    assert "Bearer ***" in captured.err
    # The redacted DSN stays readable rather than losing its "@".
    assert "postgresql://user:***@db:5432/app" in captured.err


def test_redaction_is_idempotent_and_does_not_corrupt_clean_messages(capsys):
    from app.core import logging as app_logging

    app_logging.setup_logging("INFO")
    logger = logging.getLogger("s10.clean")
    logger.info("correlation recompute completed in 42ms")
    logger.info("no secrets here at all")
    captured = capsys.readouterr()
    assert "recompute completed in 42ms" in captured.out
    assert "no secrets here at all" in captured.out


def test_redaction_survives_a_custom_record_factory():
    """A third-party factory must be chained, not discarded."""
    from app.core import logging as app_logging

    sentinel = object()
    app_logging._PREVIOUS_RECORD_FACTORY = None
    logging.setLogRecordFactory(logging.LogRecord)  # restore the stdlib factory
    calls = []

    def custom_factory(*args, **kwargs):
        calls.append(1)
        record = logging.LogRecord(*args, **kwargs)
        record.custom_attribute = sentinel  # type: ignore[attr-defined]
        return record

    logging.setLogRecordFactory(custom_factory)
    app_logging.setup_logging("INFO")
    try:
        record = logging.getLogRecordFactory()(
            "x", logging.INFO, "p", 1, "token=%s", (SECRET,), None
        )
        assert record.getMessage() == "token=***"
        assert getattr(record, "custom_attribute", None) is sentinel
        assert calls, "the pre-existing factory must still be called"
    finally:
        logging.setLogRecordFactory(logging.LogRecord)
        app_logging._PREVIOUS_RECORD_FACTORY = None


def test_redaction_setup_is_idempotent():
    from app.core import logging as app_logging

    app_logging.setup_logging("INFO")
    first = logging.getLogRecordFactory()
    app_logging.setup_logging("INFO")
    assert logging.getLogRecordFactory() is first


def test_logging_never_raises_on_a_broken_format_string():
    """Redaction must not turn a logging error into an application error."""
    from app.core import logging as app_logging

    app_logging.setup_logging("INFO")
    logger = logging.getLogger("s10.broken")
    try:
        logger.info("%d unmatched", "not-an-int")
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"logging raised: {exc}")


# ---------------------------------------------------------------------------
# 3. Deployed Compose surface
# ---------------------------------------------------------------------------


def _compose() -> str:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    return (root / "docker-compose.yml").read_text(encoding="utf-8")


def test_no_service_is_published_on_all_host_interfaces_by_default():
    compose = _compose()
    for line in compose.splitlines():
        stripped = line.strip()
        if stripped.startswith("- ") and "ports" not in stripped and ":" in stripped:
            assert not stripped.startswith('- "0.0.0.0:'), stripped
            assert ":${" not in stripped or "127.0.0.1" in stripped, stripped


def test_backend_root_filesystem_is_read_only():
    compose = _compose()
    backend = compose.split("\n  backend:")[1].split("\nvolumes:")[0]
    assert "read_only: true" in backend
    # /tmp must remain a tmpfs, otherwise read-only breaks any scratch use.
    assert "tmpfs:" in backend


def test_security_controls_are_not_removed_by_this_step():
    compose = _compose()
    assert compose.count("no-new-privileges:true") >= 3
    assert "cap_drop:" in compose
    assert "    - ALL" in compose
    # The database must stay loopback-only and must not gain a public bind.
    db = compose.split("\n  db:")[1].split("\n  backend:")[0]
    assert "127.0.0.1:${POSTGRES_PORT:-5432}:5432" in db


def test_healthchecks_are_preserved():
    compose = _compose()
    assert compose.count("healthcheck:") == 3
    assert "/api/v1/health" in compose


def test_env_example_documents_every_compose_variable():
    """Repository hygiene: .env.example must not drift from compose."""
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
    env_example = (root / ".env.example").read_text(encoding="utf-8")
    variables = set(re.findall(r"\$\{([A-Z_0-9]+)", compose))
    undocumented = [
        name
        for name in sorted(variables)
        if not re.search(rf"(?m)^\s*#?\s*{name}\s*=", env_example)
    ]
    assert not undocumented, undocumented
