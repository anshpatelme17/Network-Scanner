"""Runtime database identity checks using controlled test doubles only."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from sqlalchemy.exc import OperationalError, ProgrammingError

from app.database.session import (
    DatabaseConnectivityError,
    RuntimeIdentityMismatch,
    RuntimeIdentityVerificationError,
    is_connectivity_failure,
    verify_runtime_identity,
)


def _raise(error):
    raise error


class _DriverError(Exception):
    def __init__(self, message: str, sqlstate: str | None = None):
        super().__init__(message)
        self.sqlstate = sqlstate


class _Result:
    def __init__(self, row):
        self.row = row

    def one(self):
        return self.row


class _Connection:
    def __init__(self, row=None, error=None):
        self.row = row
        self.error = error
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True

    def execute(self, statement):
        assert str(statement) == (
            "SELECT session_user, current_user, current_database()"
        )
        if self.error is not None:
            raise self.error
        return _Result(self.row)


class _Engine:
    def __init__(
        self, row=None, connect_error=None, query_error=None, dialect="postgresql"
    ):
        self.dialect = SimpleNamespace(name=dialect)
        self.row = row
        self.connect_error = connect_error
        self.query_error = query_error
        self.disposed = False

    def connect(self):
        if self.connect_error is not None:
            raise self.connect_error
        return _Connection(self.row, self.query_error)

    def dispose(self):
        self.disposed = True


def _run_lifespan(main_module):
    async def run():
        async with main_module.lifespan(None):
            return "yielded"

    return asyncio.run(run())


def _install_startup_fakes(monkeypatch, engine, init_engine=None):
    from app import main
    from app.database import session

    settings = SimpleNamespace(
        app_name="test-app",
        environment="test",
        database_url="synthetic-test-url",
    )
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr(main, "init_engine", init_engine or (lambda _url: engine))
    monkeypatch.setattr(session, "_engine", engine)
    monkeypatch.setattr(session, "_SessionLocal", object())
    return main, session, settings


def test_correct_runtime_identity_is_accepted():
    engine = _Engine(
        row=("sec_runtime", "sec_runtime", "security_platform")
    )

    verify_runtime_identity(engine)


@pytest.mark.parametrize(
    "identity",
    [
        ("secuser", "sec_runtime", "security_platform"),
        ("sec_runtime", "sec_owner", "security_platform"),
        ("sec_runtime", "sec_runtime", "other_database"),
    ],
)
def test_incorrect_runtime_identity_is_rejected(identity):
    with pytest.raises(RuntimeIdentityMismatch):
        verify_runtime_identity(_Engine(row=identity))


def test_connectivity_failure_during_initialization_preserves_degraded_startup(
    monkeypatch,
):
    from app.services import health as health_service

    main, _session, settings = _install_startup_fakes(monkeypatch, _Engine())
    original = _DriverError("synthetic connection failure", "08001")
    error = OperationalError("connect", {}, original)
    monkeypatch.setattr(main, "init_engine", lambda _url: _raise(error))
    monkeypatch.setattr(health_service, "ping_database", lambda: False)

    assert _run_lifespan(main) == "yielded"
    payload, ready = health_service.readiness(settings)
    assert ready is False
    assert payload["checks"]["database"] == "down"


def test_unexpected_initialization_failure_aborts_and_cleans_partial_engine(
    monkeypatch,
):
    main, session, _settings = _install_startup_fakes(monkeypatch, _Engine())
    engine = session._engine
    monkeypatch.setattr(
        main,
        "init_engine",
        lambda _url: _raise(ValueError("synthetic invalid configuration")),
    )

    with pytest.raises(RuntimeError, match="Database engine initialization failed"):
        _run_lifespan(main)

    assert engine.disposed
    assert session._engine is None
    assert session._SessionLocal is None


def test_raw_os_error_during_initialization_is_not_automatically_degraded():
    assert not is_connectivity_failure(
        OSError("synthetic unexpected OS failure"), connection_acquisition=False
    )


def test_raw_os_error_during_connection_acquisition_is_not_connectivity():
    assert not is_connectivity_failure(
        OSError("synthetic OS failure"), connection_acquisition=True
    )


def test_invalidated_dbapi_connection_precedes_non_connectivity_sqlstate():
    error = OperationalError(
        "query",
        {},
        _DriverError("synthetic failure", "28P01"),
        connection_invalidated=True,
    )

    assert is_connectivity_failure(error, connection_acquisition=False)


def test_connection_failure_during_identity_acquisition_is_connectivity_error():
    error = OperationalError("connect", {}, _DriverError("synthetic refusal"))

    with pytest.raises(DatabaseConnectivityError):
        verify_runtime_identity(_Engine(connect_error=error))


def test_unexpected_identity_query_failure_fails_closed():
    error = ProgrammingError(
        "identity query",
        {},
        _DriverError("synthetic query failure", "42501"),
    )

    with pytest.raises(RuntimeIdentityVerificationError):
        verify_runtime_identity(_Engine(query_error=error))


@pytest.mark.parametrize(
    "verification_error",
    [
        RuntimeIdentityMismatch("synthetic mismatch"),
        RuntimeIdentityVerificationError("synthetic verification failure"),
    ],
)
def test_fatal_identity_verification_disposes_and_clears_engine(
    monkeypatch, verification_error
):
    main, session, _settings = _install_startup_fakes(
        monkeypatch,
        _Engine(row=("secuser", "secuser", "security_platform")),
    )
    engine = session._engine
    monkeypatch.setattr(
        main,
        "verify_runtime_identity",
        lambda _engine: _raise(verification_error),
    )

    with pytest.raises(
        RuntimeError, match="Runtime database identity verification failed"
    ):
        _run_lifespan(main)

    assert engine.disposed
    assert session._engine is None
    assert session._SessionLocal is None


def test_identity_connectivity_failure_preserves_degraded_startup(monkeypatch):
    from app.services import health as health_service

    main, _session, settings = _install_startup_fakes(
        monkeypatch,
        _Engine(
            connect_error=OperationalError(
                "connect", {}, _DriverError("synthetic refusal")
            )
        ),
    )
    monkeypatch.setattr(health_service, "ping_database", lambda: False)

    assert _run_lifespan(main) == "yielded"
    payload, ready = health_service.readiness(settings)
    assert ready is False
    assert payload["checks"]["database"] == "down"


def test_sqlite_bypasses_runtime_identity_query():
    class SQLiteEngine(_Engine):
        def connect(self):
            raise AssertionError("SQLite identity verification must not connect")

    verify_runtime_identity(SQLiteEngine(dialect="sqlite"))
