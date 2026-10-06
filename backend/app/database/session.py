"""Database engine / session management.

Step 31: the pool is bounded and every wait has a timeout, so a stalled
database or a connection leak surfaces as a controlled error instead of a
request that hangs forever. Sizing comes from configuration
(``DB_POOL_SIZE``, ``DB_MAX_OVERFLOW``, ``DB_POOL_TIMEOUT_SECONDS``,
``DB_POOL_RECYCLE_SECONDS``, ``DB_CONNECT_TIMEOUT_SECONDS``,
``DB_STATEMENT_TIMEOUT_MS``) — never from a hard-coded assumption about
production. SQLite (used by the test suite) has no server-side pool to
size, so those arguments are only applied to server dialects.
"""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.logging import get_logger
from app.models.audit_guard import install_audit_append_only_guard

logger = get_logger(__name__)

_engine = None
_SessionLocal: sessionmaker | None = None


def _is_sqlite(database_url: str) -> bool:
    return database_url.startswith("sqlite")


def apply_statement_timeout(dbapi_connection, _record) -> None:  # noqa: ANN001
    """Bound a single statement server-side (Step 31).

    A runaway query is stopped by PostgreSQL rather than holding a
    pooled connection indefinitely. Module level so the registration is
    introspectable (and testable) without reaching into a closure.
    """
    from app.core.config import get_settings

    cursor = dbapi_connection.cursor()
    try:
        cursor.execute(f"SET statement_timeout = {int(get_settings().db_statement_timeout_ms)}")
    finally:
        cursor.close()


def init_engine(database_url: str, *, echo: bool = False):
    """Create (once) the global engine and session factory."""
    global _engine, _SessionLocal
    if _engine is not None:
        return _engine

    from app.core.config import get_settings

    settings = get_settings()
    options: dict[str, object] = {
        # ``pool_pre_ping`` makes stale pooled connections fail fast so
        # the readiness probe reports accurately instead of hanging.
        "pool_pre_ping": True,
        "echo": echo,
    }
    if not _is_sqlite(database_url):
        # Bounded pool. Total connections can never exceed
        # pool_size + max_overflow, and a caller waits at most
        # pool_timeout for one before receiving a controlled error.
        options.update(
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_timeout=settings.db_pool_timeout_seconds,
            pool_recycle=settings.db_pool_recycle_seconds,
            connect_args={
                "connect_timeout": settings.db_connect_timeout_seconds,
                "application_name": "security-platform",
            },
        )

    _engine = create_engine(database_url, **options)

    if not _is_sqlite(database_url) and settings.db_statement_timeout_ms > 0:
        event.listen(_engine, "connect", apply_statement_timeout)

    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)
    logger.info("Database engine initialized (pooled=%s)", not _is_sqlite(database_url))
    return _engine


def get_engine():
    if _engine is None:
        raise RuntimeError("Database engine not initialized. Call init_engine() first.")
    return _engine


def get_session_factory() -> sessionmaker:
    if _SessionLocal is None:
        raise RuntimeError("Database engine not initialized. Call init_engine() first.")
    return _SessionLocal


def get_db() -> Generator[Session]:
    """FastAPI dependency yielding a request-scoped session."""
    factory = get_session_factory()
    db = factory()
    try:
        yield db
    finally:
        db.close()


def ping_database() -> bool:
    """Return True when a trivial ``SELECT 1`` succeeds.

    Never raises: readiness endpoints must degrade to 503, not 500.
    """
    try:
        engine = get_engine()
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001 - any failure means "not ready"
        logger.warning("Database ping failed", exc_info=False)
        return False


def reset_engine_for_tests() -> None:
    """Test-only helper to drop the global engine between test sessions."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None


# Step 11: enforce append-only audit history at the ORM unit of work. Installed
# at import time so it applies to every session in the process - the
# application's, the test suite's, and any future entry point - rather than
# relying on each call site to remember it.
install_audit_append_only_guard()
