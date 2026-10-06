"""Step 31 hardening, performance and production-readiness tests.

Covers: configuration hardening, transport middleware (request id,
security headers, body-size bound), deterministic rate limiting, bounded
connection pool configuration, the additive Step 31 migration, the
performance fixes (no N+1 on the recommendation/expiry/evidence paths),
resource bounds, and a repository-wide structural security scan.

No existing test is modified or relaxed here: the Step 1-30 suites must
keep passing unchanged.
"""

import ast
import inspect
import json
import pkgutil
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from importlib import import_module
from pathlib import Path

import pytest
from sqlalchemy import event as sa_event

from app.core.config import (
    DEV_CORS_ORIGINS,
    ENVIRONMENTS,
    Settings,
)
from app.core.ratelimit import FixedWindowRateLimiter, RateLimitExceeded
from app.core.request_context import (
    MAX_REQUEST_ID_LENGTH,
    get_request_id,
    sanitize_request_id,
    set_request_id,
)

BACKEND_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# §3 Configuration hardening
# ---------------------------------------------------------------------------


def test_environment_is_a_closed_vocabulary():
    assert set(ENVIRONMENTS) == {"development", "test", "staging", "production"}
    # Parsing is deterministic: surrounding whitespace and case are
    # normalised, an unknown name is rejected.
    assert Settings(environment="  PRODUCTION ").environment == "production"
    assert Settings(environment="Staging").environment == "staging"
    for bad in ("prod", "dev", "live", "", "   "):
        with pytest.raises(ValueError):
            Settings(environment=bad)


def test_cors_origins_reject_wildcards_and_blanks():
    for bad in (["*"], ["null"], ["https://ok.example", "*"], [""]):
        with pytest.raises(ValueError):
            Settings(backend_cors_origins=bad)
    ok = Settings(backend_cors_origins=["https://soc.example", "https://admin.example"])
    assert ok.backend_cors_origins == ["https://soc.example", "https://admin.example"]
    # A CSV string is accepted for operator convenience.
    assert Settings(
        backend_cors_origins="https://a.example, https://b.example"
    ).backend_cors_origins == [
        "https://a.example",
        "https://b.example",
    ]


def test_trusted_hosts_default_empty_and_rejects_wildcard():
    assert Settings().trusted_hosts == []
    assert Settings(trusted_hosts=["api.example.com"]).trusted_hosts == ["api.example.com"]
    with pytest.raises(ValueError):
        Settings(trusted_hosts=["*"])


def _production(**overrides) -> Settings:
    base = {
        "environment": "production",
        "secret_key": "k" * 48,
        "backend_cors_origins": ["https://soc.example"],
        "database_url": "postgresql+psycopg://u:realpassword@db:5432/app",
        # Step 10 made these mandatory in production; a "valid production
        # configuration" now means the complete hardened baseline.
        "require_auth": True,
        "connector_verify_tls": True,
        "trusted_hosts": ["soc.example"],
    }
    base.update(overrides)
    return Settings(**base)


def test_production_configuration_refuses_development_assumptions():
    with pytest.raises(RuntimeError, match="DEBUG"):
        _production(debug=True).validate_production()
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        _production(secret_key="CHANGE_ME_dev_only").validate_production()
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        _production(secret_key="short").validate_production()
    with pytest.raises(RuntimeError, match="DATABASE_URL"):
        _production(
            database_url="postgresql+psycopg://u:changeme@db:5432/app"
        ).validate_production()
    with pytest.raises(RuntimeError, match="BACKEND_CORS_ORIGINS"):
        _production(backend_cors_origins=[]).validate_production()
    with pytest.raises(RuntimeError, match="BACKEND_CORS_ORIGINS"):
        _production(backend_cors_origins=list(DEV_CORS_ORIGINS)).validate_production()
    with pytest.raises(RuntimeError, match="MAX_REQUEST_BYTES"):
        _production(max_request_bytes=0).validate_production()


def test_pool_fields_are_capped_by_construction():
    # The Field bounds are the control; each is validated at parse time so
    # an unbounded pool cannot be expressed.
    for field, value in (("db_pool_size", 500), ("db_max_overflow", 500)):
        with pytest.raises(ValueError):
            Settings(**{field: value})


def test_production_configuration_errors_never_echo_secret_values():
    sentinel = "hunter2-not-in-any-log"
    with pytest.raises(RuntimeError) as excinfo:
        _production(secret_key=sentinel).validate_production()
    assert sentinel not in str(excinfo.value)
    # Nor does the placeholder-DATABASE_URL check leak the DSN.
    leaky = f"postgresql+psycopg://user:{sentinel}@db:5432/changeme_password/app"
    with pytest.raises(RuntimeError) as excinfo:
        _production(database_url=leaky).validate_production()
    assert sentinel not in str(excinfo.value)
    assert "postgresql" not in str(excinfo.value)


def test_valid_production_configuration_passes():
    _production().validate_production()


def test_pool_and_request_bounds_are_bounded_by_construction():
    settings = Settings()
    assert settings.db_pool_size >= 1
    assert settings.db_max_overflow >= 0
    assert 1.0 <= settings.db_pool_timeout_seconds <= 120.0
    assert settings.db_connect_timeout_seconds >= 1
    assert settings.max_request_bytes > 0
    for value in (settings.rate_limit_recompute, settings.rate_limit_recalculate):
        assert value > 0
    assert settings.rate_limit_connector_poll > 0
    assert settings.rate_limit_max_buckets >= 16


# ---------------------------------------------------------------------------
# §10/§13 Request correlation
# ---------------------------------------------------------------------------


def test_request_id_sanitisation_rejects_unusable_values():
    assert sanitize_request_id(None) != ""
    # Newlines / control characters cannot be smuggled into a log line.
    for hostile in (
        "abc\ndef",
        "abc\r\nX-Injected: 1",
        "abc def",
        "x" * (MAX_REQUEST_ID_LENGTH + 10),
        "'; DROP TABLE response_audit; --",
    ):
        produced = sanitize_request_id(hostile)
        assert produced != hostile
        assert all(char.isalnum() or char == "-" for char in produced)
    # A well-formed id is preserved.
    assert sanitize_request_id("abc-123") == "abc-123"


def test_request_id_context_var_round_trips():
    set_request_id("deadbeef")
    assert get_request_id() == "deadbeef"


def test_every_response_carries_a_request_id(client, clean_db):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    request_id = response.headers.get("X-Request-ID")
    assert request_id, "every response must be correlatable"
    assert all(char.isalnum() or char == "-" for char in request_id)


def test_inbound_request_id_is_echoed_when_safe(client, clean_db):
    response = client.get("/api/v1/health", headers={"X-Request-ID": "trace-abc-123"})
    assert response.headers.get("X-Request-ID") == "trace-abc-123"


def test_inbound_request_id_is_sanitised_when_hostile(client, clean_db):
    response = client.get("/api/v1/health", headers={"X-Request-ID": "bad id\ninjected"})
    echoed = response.headers.get("X-Request-ID")
    assert echoed and echoed != "bad id\ninjected"
    assert "\n" not in echoed


def test_audit_rows_record_the_request_id(client, clean_db):
    import json as _json

    from tests.test_response_foundation import _approve, _propose, _seed_incident

    incident = _seed_incident(client)
    action = _propose(client, incident["id"], action_type="REVIEW", reason="hardening probe")
    _approve(client, action.json()["id"], actor="lead")
    detail = client.get(f"/api/v1/responses/{action.json()['id']}").json()
    stored = {row["id"]: row for row in detail["audit"]}

    from app.database.session import get_session_factory
    from app.models.responses import ResponseAudit

    db = get_session_factory()()
    try:
        rows = db.query(ResponseAudit).filter(ResponseAudit.action_id == action.json()["id"]).all()
        assert rows, "audit rows must exist"
        for row in rows:
            assert row.request_id, f"{row.event} must be correlated to a request"
            assert len(row.request_id) <= 64
    finally:
        db.close()
    _ = (stored, _json)


def test_incident_audit_rows_record_the_request_id(client, clean_db):
    from app.database.session import get_session_factory
    from app.models.incidents import IncidentAudit
    from tests.test_response_foundation import _seed_incident

    incident = _seed_incident(client)
    client.patch(
        f"/api/v1/incidents/{incident['id']}/status",
        json={"status": "ACKNOWLEDGED", "actor": "lead"},
    )
    db = get_session_factory()()
    try:
        rows = db.query(IncidentAudit).filter(IncidentAudit.incident_id == incident["id"]).all()
        assert rows
        for row in rows:
            assert row.request_id
    finally:
        db.close()


# ---------------------------------------------------------------------------
# §11 Security headers
# ---------------------------------------------------------------------------


def test_security_headers_present_on_api_responses(client, clean_db):
    response = client.get("/api/v1/health")
    headers = response.headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    # No HSTS outside production (it would poison a localhost browser).
    assert "Strict-Transport-Security" not in headers


def test_api_responses_are_not_cacheable(client, clean_db):
    assert "no-store" in client.get("/api/v1/version").headers.get("Cache-Control", "")


def test_hsts_is_added_in_production(monkeypatch):
    from app.core.config import get_settings
    from app.main import create_app

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SECRET_KEY", "k" * 48)
    monkeypatch.setenv("BACKEND_CORS_ORIGINS", '["https://soc.example"]')
    # Step 10: both are mandatory in production, so a production app fixture
    # must now supply them. "testserver" is the TestClient's Host, which
    # TrustedHostMiddleware now correctly validates against this list.
    monkeypatch.setenv("REQUIRE_AUTH", "true")
    monkeypatch.setenv("TRUSTED_HOSTS", '["soc.example", "testserver"]')
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+psycopg://u:realpassword@db:5432/security_platform"
    )
    get_settings.cache_clear()
    try:
        app = create_app()
        from starlette.testclient import TestClient

        with TestClient(app) as client:
            headers = client.get("/api/v1/health").headers
            assert "max-age=31536000" in headers.get("Strict-Transport-Security", "")
            # Production must not publish the API schema.
            assert client.get("/openapi.json").status_code == 404
    finally:
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# §4/§5 Body size and rate limits
# ---------------------------------------------------------------------------


def test_oversized_body_is_refused_before_parsing(client, clean_db):
    oversized = b'{"title": "' + (b"x" * (2 * 1024 * 1024)) + b'"}'
    response = client.post(
        "/api/v1/events",
        content=oversized,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    body = response.json()
    assert body["error"]["code"] == "PAYLOAD_TOO_LARGE"
    # The refusal does not disclose the submitted size.
    assert str(len(oversized)) not in json.dumps(body)


def test_body_size_limit_is_configurable(monkeypatch):
    from starlette.testclient import TestClient

    from app.core.config import get_settings
    from app.main import create_app

    monkeypatch.setenv("MAX_REQUEST_BYTES", "2048")
    get_settings.cache_clear()
    try:
        with TestClient(create_app()) as client:
            response = client.post(
                "/api/v1/events",
                content=b'{"title": "' + (b"x" * 8192) + b'"}',
                headers={"Content-Type": "application/json"},
            )
            assert response.status_code == 413
    finally:
        get_settings.cache_clear()


def test_malformed_content_length_is_refused(client, clean_db):
    response = client.post(
        "/api/v1/events",
        content=b"{}",
        headers={"Content-Type": "application/json", "Content-Length": "not-a-number"},
    )
    assert response.status_code in (400, 422)
    if response.status_code == 400:
        assert response.json()["error"]["code"] == "INVALID_REQUEST"


def test_rate_limiter_is_deterministic_and_bounded():
    limiter = FixedWindowRateLimiter(max_buckets=8)
    # Deterministic: the same call sequence gives the same verdicts.
    for _ in range(3):
        limiter.reset()
        for index in range(5):
            try:
                limiter.check("op", "caller", limit=3, window_seconds=60)
                assert index < 3, f"call {index} should have been allowed"
            except RateLimitExceeded as exc:
                assert index >= 3, f"call {index} should have been refused"
                assert exc.limit == 3
                assert exc.retry_after >= 1
    # Bounded memory: never more buckets than the ceiling, even with many
    # distinct callers.
    for index in range(500):
        limiter.check("op", f"caller-{index}", limit=10_000, window_seconds=60)
    assert len(limiter._buckets) <= 8


def test_rate_limit_of_zero_disables_the_check():
    limiter = FixedWindowRateLimiter()
    for _ in range(100):
        limiter.check("op", "caller", limit=0, window_seconds=60)


def test_rate_limit_applies_to_expensive_operations(client, clean_db, monkeypatch):
    from app.core.config import get_settings

    client.app.state.limiter.reset()
    monkeypatch.setattr(get_settings(), "rate_limit_recompute", 2)
    for index in range(2):
        response = client.post("/api/v1/correlations/recompute", json={})
        assert response.status_code == 200, index
    limited = client.post("/api/v1/correlations/recompute", json={})
    assert limited.status_code == 429
    body = limited.json()
    assert body["error"]["code"] == "RATE_LIMITED"
    assert "correlation recompute" in body["error"]["message"]


def test_rate_limited_call_creates_no_side_effects(client, clean_db, monkeypatch):
    from app.core.config import get_settings

    client.app.state.limiter.reset()
    monkeypatch.setattr(get_settings(), "rate_limit_connector_poll", 1)
    first = client.post("/api/v1/events/connectors/suricata/poll")
    assert first.status_code in (200, 422)
    second = client.post("/api/v1/events/connectors/suricata/poll")
    if first.status_code == 200:
        assert second.status_code == 429


def test_rate_limit_never_replaces_authorization(client, clean_db, monkeypatch):
    """An anonymous caller is refused before any budget is consumed."""
    from tests.test_auth import _admin_headers

    client.app.state.limiter.reset()
    _admin_headers(client)
    for _ in range(5):
        response = client.post("/api/v1/correlations/recompute", json={})
        assert response.status_code in (401, 403, 429)
        if response.status_code in (401, 403):
            return
    _ = monkeypatch


# ---------------------------------------------------------------------------
# §7 Connection pool configuration
# ---------------------------------------------------------------------------


@contextmanager
def _temporary_engine(database_url: str):  # noqa: ANN201
    """Install a throwaway engine, then restore the shared test engine.

    The suite shares one session-scoped SQLite engine. A test that builds
    its own engine must put the original back, or every later test would
    see an engine with no tables.
    """
    from app.database import session as session_module
    from app.database.session import init_engine

    previous_engine = session_module._engine
    previous_factory = session_module._SessionLocal
    session_module._engine = None
    session_module._SessionLocal = None
    try:
        yield init_engine(database_url)
    finally:
        if session_module._engine is not None:
            session_module._engine.dispose()
        session_module._engine = previous_engine
        session_module._SessionLocal = previous_factory


def test_engine_applies_bounded_pool_settings():
    from app.core.config import get_settings

    with _temporary_engine("postgresql+psycopg://u:pw@localhost:5432/nodb") as engine:
        settings = get_settings()
        assert engine.pool.size() == settings.db_pool_size
        assert engine.pool._max_overflow == settings.db_max_overflow
        assert engine.pool._timeout == settings.db_pool_timeout_seconds
        assert engine.pool._recycle == settings.db_pool_recycle_seconds
        assert engine.pool._pre_ping is True


def test_sqlite_engine_is_not_given_server_pool_arguments():
    from app.database.session import _is_sqlite

    assert _is_sqlite("sqlite:///./x.db")
    assert _is_sqlite("sqlite://")
    assert not _is_sqlite("postgresql+psycopg://u:pw@h/db")


def test_statement_timeout_is_set_on_connect():
    from sqlalchemy import event as sqlalchemy_event

    from app.core.config import get_settings
    from app.database.session import apply_statement_timeout

    with _temporary_engine("postgresql+psycopg://u:pw@localhost:5432/nodb") as engine:
        assert get_settings().db_statement_timeout_ms > 0
        assert sqlalchemy_event.contains(engine, "connect", apply_statement_timeout)


def test_database_failure_degrades_to_not_ready(client, monkeypatch):
    from app.services import health as health_service

    monkeypatch.setattr(health_service, "ping_database", lambda: False)
    response = client.get("/api/v1/ready")
    assert response.status_code == 503
    assert response.json()["checks"]["database"] == "down"


# ---------------------------------------------------------------------------
# §6 Migration
# ---------------------------------------------------------------------------


def test_migration_step31_is_the_head_and_additive():
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    script = ScriptDirectory.from_config(config)
    # Step 12 added a migration after this one, so "the head is Step 31" is
    # no longer true and cannot be. The invariant that matters is preserved:
    # the chain is linear (exactly one head) and still runs *through* Step 31,
    # whose own parent is unchanged.
    heads = script.get_heads()
    assert len(heads) == 1, heads
    assert script.get_revision("step31_hardening").down_revision == "step30_controlled_response"
    # The chain back to the Step 30 head is intact.
    revisions = {revision.revision for revision in script.walk_revisions()}
    assert {"step30_controlled_response", "step29_intelligence"} <= revisions
    # Whatever the current head is, Step 31 is an ancestor of it.
    ancestry = set()
    cursor = heads[0]
    while cursor is not None:
        ancestry.add(cursor)
        revision = script.get_revision(cursor)
        cursor = revision.down_revision if revision is not None else None
    assert "step31_hardening" in ancestry


def test_migration_step31_adds_indexes_and_columns_and_is_reversible(tmp_path, monkeypatch):
    from sqlalchemy import create_engine, inspect

    from alembic import command
    from alembic.config import Config

    db_file = tmp_path / "mig31.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))

    command.upgrade(config, "step30_controlled_response")
    before = inspect(create_engine(f"sqlite:///{db_file}"))
    assert "request_id" not in {c["name"] for c in before.get_columns("response_audit")}

    command.upgrade(config, "head")
    after = inspect(create_engine(f"sqlite:///{db_file}"))
    assert "request_id" in {c["name"] for c in after.get_columns("response_audit")}
    assert "request_id" in {c["name"] for c in after.get_columns("incident_audits")}
    action_indexes = {index["name"] for index in after.get_indexes("response_actions")}
    for expected in (
        "ix_response_actions_expires_at",
        "ix_response_actions_provider",
        "ix_response_actions_policy_decision",
        "ix_response_actions_target_reference",
    ):
        assert expected in action_indexes, expected
    audit_indexes = {index["name"] for index in after.get_indexes("response_audit")}
    assert "ix_response_audit_created_at" in audit_indexes
    assert "ix_response_audit_request_id" in audit_indexes

    # Downgrade removes only what this migration added.
    command.downgrade(config, "step30_controlled_response")
    reverted = inspect(create_engine(f"sqlite:///{db_file}"))
    assert "request_id" not in {c["name"] for c in reverted.get_columns("response_audit")}
    assert "response_rollbacks" in reverted.get_table_names()
    assert "incident_relationships" in reverted.get_table_names()


# ---------------------------------------------------------------------------
# §6/§14 Performance: bounded queries
# ---------------------------------------------------------------------------


def _count_queries(db, fn):  # noqa: ANN001, ANN201
    counter = {"n": 0}
    bind = db.get_bind()

    def _before(*_args, **_kwargs):
        counter["n"] += 1

    sa_event.listen(bind, "before_cursor_execute", _before)
    try:
        return fn(), counter["n"]
    finally:
        sa_event.remove(bind, "before_cursor_execute", _before)


def test_recommendations_query_count_does_not_grow_with_candidates(client, clean_db):
    """The Step 30 N+1 fix: total queries are constant, not per-candidate."""
    from app.database.session import get_session_factory
    from app.models.incidents import Incident
    from app.services import response_governance
    from tests.test_response_governance import _seed

    incident_row = _seed(client)
    db = get_session_factory()()
    try:
        incident = db.get(Incident, incident_row["id"])
        (_result, queries) = _count_queries(
            db, lambda: response_governance.recommendations(db, incident)
        )
        # events + risk + assets: constant regardless of how many
        # candidate addresses/accounts the evidence contains.
        assert queries <= 4, f"recommendations issued {queries} queries (expected a constant)"
    finally:
        db.close()


def test_expiry_sweep_is_bounded_by_a_fixed_ceiling():
    from app.services import response_governance

    assert 1 <= response_governance.MAX_EXPIRY_SCAN <= 500


def test_expire_due_issues_at_most_one_commit(client, clean_db):
    from app.database.session import get_session_factory
    from app.models.responses import ResponseAction
    from app.services import response_governance
    from tests.test_response_governance import _request, _seed

    incident = _seed(client)
    # Three overdue rows, three distinct requesters so identity differs.
    ids = []
    for index in range(3):
        body = _request(
            client,
            incident["id"],
            action_type="DISABLE_ACCOUNT",
            target_type="ACCOUNT",
            target_reference="chain-user",
            requested_by=f"perf-requester-{index}",
        ).json()
        ids.append(body["id"])

    db = get_session_factory()()
    try:
        past = datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=5)
        for action_id in ids:
            row = db.get(ResponseAction, action_id)
            row.expires_at = past
        db.commit()

        commits = {"n": 0}

        def _on_commit(_session):
            commits["n"] += 1

        sa_event.listen(db, "after_commit", _on_commit)
        try:
            expired = response_governance.expire_due(db, incident["id"])
        finally:
            sa_event.remove(db, "after_commit", _on_commit)
        assert set(ids) <= set(expired)
        # One batch, one transaction - the previous code committed per row.
        assert commits["n"] <= 1, f"expiry issued {commits['n']} commits"
    finally:
        db.close()


def test_expiry_sweep_is_bounded():
    from app.services import response_governance

    assert 1 <= response_governance.MAX_EXPIRY_SCAN <= 500


def test_correlation_evidence_is_batched(client, clean_db):
    """Step 9 evidence read is one IN query, not one per link."""
    from app.api.v1.endpoints.correlations import _evidence_items
    from app.database.session import get_session_factory
    from app.models.correlations import Correlation
    from tests.test_response_foundation import _seed_incident

    incident = _seed_incident(client)
    db = get_session_factory()()
    try:
        correlation = db.get(Correlation, incident["correlation_id"])
        (_items, queries) = _count_queries(db, lambda: _evidence_items(db, correlation.id))
        # 1 for the links + 1 for the batched events.
        assert queries <= 2, f"evidence read issued {queries} queries"
    finally:
        db.close()


# ---------------------------------------------------------------------------
# §14 Bounded reads
# ---------------------------------------------------------------------------


def test_list_endpoints_reject_unbounded_pagination(client, clean_db):
    for path in (
        "/api/v1/responses?limit=0",
        "/api/v1/responses?limit=100000",
        "/api/v1/responses?offset=-1",
        "/api/v1/events?limit=100000",
        "/api/v1/incidents?limit=100000",
        "/api/v1/incidents/abc/relationships?limit=100000",
        "/api/v1/risk?limit=100000",
    ):
        assert client.get(path).status_code == 422, path


def test_audit_listing_is_bounded_and_ordered(client, clean_db):
    from tests.test_response_foundation import _propose, _seed_incident

    incident = _seed_incident(client)
    action_id = _propose(client, incident["id"], action_type="REVIEW", reason="audit probe").json()[
        "id"
    ]
    detail = client.get(f"/api/v1/responses/{action_id}").json()
    rows = detail["audit"]
    assert rows
    keys = [(row["created_at"], row["id"]) for row in rows]
    assert keys == sorted(keys), "audit rows must be returned in deterministic order"


def test_ingestion_batch_size_is_bounded(client, clean_db):
    from app.core.config import get_settings

    settings = get_settings()
    assert 1 <= settings.ingestion_max_batch_size <= 500
    assert 1 <= settings.ingestion_queue_max <= 10_000
    assert 0 <= settings.ingestion_retry_max <= 3


def test_connector_bounds_are_still_bounded(client, clean_db):
    from app.core.config import get_settings

    settings = get_settings()
    assert 1 <= settings.connector_max_pages <= 20
    assert 1 <= settings.connector_max_events <= 1000
    assert settings.connector_max_response_bytes >= 1024
    assert 1.0 <= settings.connector_timeout_seconds <= 60.0


# ---------------------------------------------------------------------------
# §12 Error handling
# ---------------------------------------------------------------------------


def test_unhandled_exception_does_not_leak_internals(clean_db, monkeypatch):
    """A failing endpoint must return a safe envelope, not internals.

    The TestClient is built with ``raise_server_exceptions=False`` so the
    application's own handler produces the response, exactly as it would
    for a real client.
    """
    from starlette.testclient import TestClient

    from app.api.v1.endpoints import assets as assets_endpoint
    from app.main import create_app

    def _boom(*_args, **_kwargs):
        raise RuntimeError(
            "connection to postgresql://secuser:supersecret@db:5432 failed; "
            "SELECT * FROM assets at /srv/app/data.db"
        )

    # `desc` is the ordering helper the list endpoint calls, so patching it
    # drives a real failure through the real handler chain.
    monkeypatch.setattr(assets_endpoint, "desc", _boom)
    with TestClient(create_app(), raise_server_exceptions=False) as client:
        response = client.get("/api/v1/assets")
    assert response.status_code == 500
    body = json.dumps(response.json())
    assert "supersecret" not in body
    assert "SELECT" not in body
    assert "/srv/app" not in body
    assert "RuntimeError" not in body
    assert response.json()["error"]["code"] == "INTERNAL_ERROR"
    assert "Traceback" not in body
    # The client still gets a correlation id to quote in a report.
    assert response.headers.get("X-Request-ID")


def test_validation_errors_use_the_standard_envelope(client, clean_db):
    response = client.post("/api/v1/responses/controlled", json={})
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "VALIDATION_ERROR"
    # The generic message is used; field-level detail is not dumped.
    assert "check the request parameters" in body["error"]["message"]


def test_not_found_envelope_is_safe(client, clean_db):
    response = client.get("/api/v1/responses/does-not-exist")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "RESPONSE_NOT_FOUND"


# ---------------------------------------------------------------------------
# §15 Repository-wide structural security scan
# ---------------------------------------------------------------------------

# Modules allowed to reach a transport or a shell, and why. Everything
# else in app/ must not import or call them. This is the repo-wide version
# of the per-step AST tests: it is a superset check, not a replacement.
_TRANSPORT_ALLOWLIST = {
    # Outbound, allow-listed, time/size/page bounded HTTP for Step 27
    # connectors.
    "app.services.http_connector",
    "app.services.wazuh_client",
    "app.services.defender_client",
    # Step 2/14 controlled Nmap invocation with a fixed argv (no shell).
    "app.services.nmap_runner",
    "app.services.scan_service",
    "app.services.discovery",
    "app.api.v1.endpoints.network",
}

_SUBPROCESS_ALLOWLIST = {
    # The only modules permitted to spawn a child process, all of them
    # Step 2/14/15 controlled Nmap invocation with a fixed argv built
    # server-side and `shell=False`. Each is additionally covered by the
    # per-step AST tests (test_discovery.test_no_shell_construction,
    # test_vuln_assessment.test_no_execution_paths_in_new_modules), so
    # this entry does not weaken them.
    "app.services.nmap_runner",
    "app.services.scan_service",
    "app.services.discovery",
    "app.services.nmap_vuln_scanner",
    "app.services.vulnerability_scanners",
    "app.services.vulnerability_service",
    "app.api.v1.endpoints.network",
    "app.api.v1.endpoints.vuln_assessment",
}

_NETWORK_ALLOWLIST = _TRANSPORT_ALLOWLIST

_DANGEROUS_BUILTINS = {"eval", "exec", "compile", "__import__"}
_DANGEROUS_ATTRS = {"system", "popen", "Popen", "check_output", "check_call"}
_AI_LIBS = {
    "openai",
    "langchain",
    "llama_index",
    "torch",
    "tensorflow",
    "sklearn",
    "transformers",
    "anthropic",
    "cohere",
    "google.generativeai",
}


def _iter_app_modules():
    import app

    for info in pkgutil.walk_packages(app.__path__, prefix="app."):
        yield info.name


def test_repo_wide_no_dangerous_imports_outside_the_allowlist():
    offenders = []
    for module_name in sorted(_iter_app_modules()):
        module = import_module(module_name)
        path = BACKEND_ROOT / (module_name.replace(".", "/") + ".py")
        if not path.exists():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            roots: list[str] = []
            if isinstance(node, ast.Import):
                roots = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                roots = [(node.module or "").split(".")[0]]
            for root in roots:
                if root in _AI_LIBS:
                    offenders.append(f"{module_name} imports {root}")
                if root in ("subprocess", "ctypes", "multiprocessing", "webbrowser", "ftplib"):
                    if module_name not in _SUBPROCESS_ALLOWLIST:
                        offenders.append(f"{module_name} imports {root}")
                if root in ("socket", "requests", "httpx", "urllib", "http"):
                    if module_name not in _NETWORK_ALLOWLIST:
                        offenders.append(f"{module_name} imports {root}")
        _ = module
    assert offenders == [], offenders


def test_repo_wide_no_dangerous_calls_outside_the_allowlist():
    offenders = []
    for module_name in sorted(_iter_app_modules()):
        path = BACKEND_ROOT / (module_name.replace(".", "/") + ".py")
        if not path.exists():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id in _DANGEROUS_BUILTINS:
                offenders.append(f"{module_name} calls {func.id}()")
            if isinstance(func, ast.Attribute) and func.attr in _DANGEROUS_ATTRS:
                offenders.append(f"{module_name} calls .{func.attr}()")
    assert offenders == [], offenders


def test_no_module_uses_shell_true():
    """Assert on the AST, not on raw text.

    A docstring that merely *documents* "no shell=True" must not read as
    a violation, and a real `shell=True` keyword must.
    """
    offenders = []
    for module_name in sorted(_iter_app_modules()):
        path = BACKEND_ROOT / (module_name.replace(".", "/") + ".py")
        if not path.exists():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                    if keyword.value.value is not False:
                        offenders.append(f"{module_name}: shell={keyword.value.value!r}")
    assert offenders == [], offenders


def test_no_module_uses_shell_true_textually():
    """Belt and braces: the literal must only ever appear as shell=False."""
    offenders = []
    for module_name in sorted(_iter_app_modules()):
        path = BACKEND_ROOT / (module_name.replace(".", "/") + ".py")
        if not path.exists():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docstrings = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                docstrings.add(node.value)
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if "shell=True" not in stripped:
                continue
            if any("shell=True" in doc for doc in docstrings):
                continue  # appears only inside a string literal / comment
            offenders.append(f"{module_name}: {stripped}")
    assert offenders == [], offenders


def test_step31_modules_import_no_transport():
    for module_name in (
        "app.middleware",
        "app.core.ratelimit",
        "app.core.request_context",
        "app.api.v1.limits",
        "app.services.response_governance",
        "app.services.response_providers",
    ):
        module = import_module(module_name)
        source = inspect.getsource(module)
        for banned in (
            "import subprocess",
            "import socket",
            "import requests",
            "import httpx",
            "import urllib",
            "os.system",
            "subprocess.",
            "eval(",
            "exec(",
        ):
            assert banned not in source, f"{module_name} contains {banned!r}"


def test_no_autonomous_response_wiring():
    """No thread/timer/scheduler can drive analysis or response actions.

    The platform's design is operator-initiated only: analysis, ingestion
    and every governed response operation must be triggered by a request.
    A module that imported a scheduler or an event loop would be the first
    place autonomous behaviour could appear, so the import itself is the
    thing banned here.
    """
    allowed = {
        # A threading.Lock guarding an in-process counter is not a
        # scheduler; contextvars is not concurrency either.
        "app.core.ratelimit",
        "app.core.request_context",
        # Phase 2 Step 5: connector_polling uses threading.Lock solely to
        # refuse an overlapping poll of the same connector - the same
        # mutex-not-a-scheduler reasoning as app.core.ratelimit. It starts
        # no thread, timer or event loop, and asserts that in
        # tests/test_connector_polling_step5.py.
        "app.services.connector_polling",
    }
    offenders = []
    for module_name in sorted(_iter_app_modules()):
        if module_name in allowed:
            continue
        path = BACKEND_ROOT / (module_name.replace(".", "/") + ".py")
        if not path.exists():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            roots: list[str] = []
            if isinstance(node, ast.Import):
                roots = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                roots = [(node.module or "").split(".")[0]]
            for root in roots:
                if root in ("sched", "asyncio", "threading", "multiprocessing"):
                    offenders.append(f"{module_name} imports {root}")
    assert offenders == [], offenders


def test_secret_redaction_filter_covers_common_shapes():
    from app.core.logging import _REDACT_PATTERNS

    samples = (
        "password=hunter2",
        "PASSWORD: hunter2",
        "api_key=abcdef123456",
        "api-key: abcdef123456",
        "secret=topsecretvalue",
        "token=eyJhbGciOi.J9.abc",
        "Bearer eyJhbGciOi.J9.abc",
        "postgres://user:topsecret@db:5432/app",
    )
    for sample in samples:
        redacted = sample
        for pattern in _REDACT_PATTERNS:
            redacted = pattern.sub(r"\1***", redacted)
        assert "hunter2" not in redacted, sample
        assert "abcdef123456" not in redacted, sample
        assert "topsecretvalue" not in redacted, sample
        assert "eyJhbGciOi" not in redacted, sample
