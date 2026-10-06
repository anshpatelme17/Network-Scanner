"""Shared pytest fixtures.

Uses an isolated in-memory SQLite database so the suite runs without
PostgreSQL. Live-Postgres verification happens via the Docker Compose
readiness probe and ``scripts/smoke_check.py``, not in unit tests.
"""

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, delete
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test_only_secret")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_tmp.db")

import app.models  # noqa: E402,F401 -- register tables on Base.metadata
from app.core.config import get_settings  # noqa: E402
from app.database import session as session_module  # noqa: E402
from app.database.base import Base  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture(scope="session")
def _sqlite_engine():
    # StaticPool: one shared in-memory connection, so background scan tasks
    # running on other threads see the same tables and rows.
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    session_module._engine = engine
    session_module._SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()
    session_module.reset_engine_for_tests()
    get_settings.cache_clear()


@pytest.fixture()
def clean_db(_sqlite_engine):
    """Empty tables before each DB test (schema stays).

    Explicit child-before-parent order: SQLAlchemy cannot topologically
    sort the assets <-> scan_jobs reference cycle, and PostgreSQL (unlike
    SQLite) enforces foreign keys — so deletion order is stated, not inferred.
    """
    from app.models.assets import Asset, DiscoveredService
    from app.models.auth import AuthAudit, RevokedToken, User
    from app.models.correlations import Correlation, CorrelationAudit, CorrelationEvidence
    from app.models.events import EventAudit, SecurityEvent
    from app.models.incidents import (
        Incident,
        IncidentAudit,
        IncidentEvidence,
        IncidentRelationship,
    )
    from app.models.ingestion import IngestionCheckpoint
    from app.models.responses import (
        ResponseAction,
        ResponseAudit,
        ResponseExecution,
        ResponseRollback,
    )
    from app.models.risk import RiskAssessment, RiskAudit
    from app.models.scans import ScanAudit, ScanJob
    from app.models.vulnerabilities import Vulnerability, VulnerabilityAudit
    from app.services import connectors, http_connector, ingestion

    # Step 27: connector runtime health and any injected test transport
    # are per-test state, not schema - reset both with the tables so no
    # check/poll outcome leaks between tests. Step 28: the ingestion
    # metrics/queue counters are per-process too, and stored checkpoints
    # are per-source rows that must not leak between tests.
    connectors.reset_runtime()
    http_connector.clear_test_transport()
    ingestion.reset_runtime()

    ordered = [
        IngestionCheckpoint,
        ResponseExecution,
        # Step 30: rollbacks reference response_actions, so they must be
        # deleted before it (explicit child-before-parent order).
        ResponseRollback,
        ResponseAudit,
        ResponseAction,
        VulnerabilityAudit,
        Vulnerability,
        CorrelationEvidence,
        CorrelationAudit,
        IncidentRelationship,
        IncidentEvidence,
        IncidentAudit,
        Incident,
        Correlation,
        RiskAudit,
        RiskAssessment,
        DiscoveredService,
        ScanAudit,
        ScanJob,
        Asset,
        EventAudit,
        SecurityEvent,
        RevokedToken,
        AuthAudit,
        User,
    ]
    factory = session_module.get_session_factory()
    db = factory()
    try:
        # Step 11: audit history is append-only for the application, so the
        # per-test truncation below needs the explicitly test-only purge
        # scope. It refuses to arm unless ENVIRONMENT=test and is thread-local,
        # so this fixture cannot weaken the guard anywhere else.
        from app.models.audit_guard import allow_audit_purge_for_tests

        with allow_audit_purge_for_tests():
            for model in ordered:
                db.execute(delete(model.__table__))
            db.commit()
    finally:
        db.close()


@pytest.fixture()
def client(_sqlite_engine):
    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client
    get_settings.cache_clear()
