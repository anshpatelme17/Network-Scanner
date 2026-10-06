"""Phase 2 Step 11 — append-only audit enforcement at the ORM layer.

Covers the guard's two layers, its boundaries, and the explicit statement of
what it does *not* cover. Also proves the guard does not restrict reads or
inserts, and that every audit table in the schema is protected.
"""

from datetime import datetime

import pytest
from sqlalchemy import delete as core_delete
from sqlalchemy import select, text

from app.models import audit_guard as guard
from app.models.incidents import IncidentAudit

_MOMENT = datetime(2026, 1, 5, 10, 0)


@pytest.fixture
def db(clean_db):  # noqa: ARG001
    """A session on the isolated test database, rolled back after the test."""
    from app.database import session as session_module

    session = session_module.get_session_factory()()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def _add_audit(db, **overrides):
    fields = {
        "id": "s11-audit-1",
        "incident_id": "s11-incident-1",
        "action": "CREATED",
        "actor": "analyst",
        "detail": "step 11 fixture",
    }
    fields.update(overrides)
    audit = IncidentAudit(**fields)
    db.add(audit)
    db.commit()
    return audit


# ---------------------------------------------------------------------------
# Discovery / coverage
# ---------------------------------------------------------------------------


def test_every_audit_table_in_the_schema_is_protected():
    """A new audit model must be discovered automatically, not by hand."""
    from app.database.base import Base

    expected = {
        "AuthAudit",
        "EventAudit",
        "IncidentAudit",
        "CorrelationAudit",
        "RiskAudit",
        "ResponseAudit",
        "ScanAudit",
        "VulnerabilityAudit",
    }
    discovered = {cls.__name__ for cls in guard.audit_model_classes()}
    assert discovered == expected

    # No mapped class whose name ends in "Audit" may lack a table.
    mapped = {m.class_.__name__ for m in Base.registry.mappers}
    assert {name for name in mapped if name.endswith("Audit")} == expected


def test_detection_is_by_class_name_not_table_suffix():
    """Two audit tables are singular and a '_audits' check would miss them."""
    tables = guard.audit_table_names()
    assert "response_audit" in tables
    assert "scan_audit" in tables
    assert len(tables) == 8


def test_guard_is_installed_once_and_is_idempotent():
    assert guard.install_audit_append_only_guard() is False  # already installed
    assert guard.install_audit_append_only_guard() is False


# ---------------------------------------------------------------------------
# Layer 1: object-level UPDATE / DELETE
# ---------------------------------------------------------------------------


def test_updating_an_audit_record_is_refused(db):
    audit = _add_audit(db)
    audit.detail = "rewritten history"
    with pytest.raises(guard.AuditRecordMutationBlocked, match="append-only"):
        db.commit()
    db.rollback()


def test_deleting_an_audit_record_is_refused(db):
    audit = _add_audit(db)
    db.delete(audit)
    with pytest.raises(guard.AuditRecordMutationBlocked, match="cannot be removed"):
        db.commit()
    db.rollback()


def test_a_refused_mutation_leaves_the_stored_row_unchanged(db):
    """Fail-closed: the original row must survive the refused flush."""
    _add_audit(db)
    audit = db.scalars(select(IncidentAudit)).one()
    original = audit.detail

    audit.detail = "tampered"
    with pytest.raises(guard.AuditRecordMutationBlocked):
        db.commit()
    db.rollback()

    db.expire_all()
    assert db.scalars(select(IncidentAudit)).one().detail == original


def test_the_refusal_message_names_the_record_but_no_secret(db):
    audit = _add_audit(db)
    audit.detail = "x"
    with pytest.raises(guard.AuditRecordMutationBlocked) as excinfo:
        db.commit()
    message = str(excinfo.value)
    assert audit.id in message
    assert "password" not in message.lower()
    db.rollback()


# ---------------------------------------------------------------------------
# Layer 2: ORM bulk UPDATE / DELETE
# ---------------------------------------------------------------------------


def test_bulk_orm_delete_of_audits_is_refused(db):
    _add_audit(db)
    with pytest.raises(guard.AuditRecordMutationBlocked, match="bulk DELETE"):
        db.query(IncidentAudit).delete()
    db.rollback()


def test_bulk_orm_update_of_audits_is_refused(db):
    _add_audit(db)
    with pytest.raises(guard.AuditRecordMutationBlocked, match="bulk UPDATE"):
        db.query(IncidentAudit).update({"detail": "rewritten"})
    db.rollback()


def test_bulk_delete_of_a_non_audit_table_is_still_allowed(db):
    """The guard must not block ordinary deletes elsewhere."""
    from app.models.correlations import Correlation

    db.add(
        Correlation(
            id="s11-corr-1",
            rule_id="multi-source-target",
            rule_name="rule",
            title="t",
            description="d",
            status="open",
            severity="HIGH",
            confidence=50,
            explanation="e",
            window_start=_MOMENT,
            window_end=_MOMENT,
        )
    )
    db.commit()
    assert db.query(Correlation).delete() == 1
    db.commit()


# ---------------------------------------------------------------------------
# The guard must not restrict legitimate behaviour
# ---------------------------------------------------------------------------


def test_inserting_audit_records_still_works(db):
    _add_audit(db, id="s11-audit-a")
    _add_audit(db, id="s11-audit-b", action="UPDATED")
    assert db.scalar(select(IncidentAudit).where(IncidentAudit.id == "s11-audit-a")) is not None
    assert db.scalar(select(IncidentAudit).where(IncidentAudit.id == "s11-audit-b")) is not None


def test_reading_audits_still_works(db):
    _add_audit(db)
    audit = db.scalars(select(IncidentAudit)).one()
    assert audit.action == "CREATED"
    # Repeated reads of the same instance must not make it "dirty".
    db.expire_all()
    assert db.scalars(select(IncidentAudit)).one().actor == "analyst"
    db.commit()  # would raise if reads marked the row dirty


def test_updating_a_non_audit_table_is_still_allowed(db):
    from app.models.incidents import Incident

    _add_audit(db)
    incident = Incident(
        incident_key="S11A",
        title="mutable",
        status="OPEN",
        severity="HIGH",
        confidence=50,
        correlation_id="s11-corr-x",
        first_seen=_MOMENT,
        last_seen=_MOMENT,
    )
    db.add(incident)
    db.commit()

    incident.status = "IN_PROGRESS"
    db.commit()
    db.expire_all()
    assert (
        db.scalar(select(Incident.status).where(Incident.incident_key == "S11A")) == "IN_PROGRESS"
    )


def test_mixed_flush_with_one_audit_mutation_refuses_the_whole_flush(db):
    """The invariant is atomic: a legal change must not sneak through with it."""
    from app.models.incidents import Incident

    _add_audit(db)
    incident = Incident(
        incident_key="S11B",
        title="mixed",
        status="OPEN",
        severity="LOW",
        confidence=10,
        correlation_id="s11-corr-y",
        first_seen=_MOMENT,
        last_seen=_MOMENT,
    )
    db.add(incident)
    db.commit()

    incident.status = "RESOLVED"
    audit = db.scalars(select(IncidentAudit)).one()
    audit.action = "RESOLVED"
    with pytest.raises(guard.AuditRecordMutationBlocked):
        db.commit()
    db.rollback()

    db.expire_all()
    # Neither the audit edit nor the legitimate change was written.
    assert db.scalars(select(IncidentAudit)).one().action == "CREATED"
    assert db.scalar(select(Incident.status).where(Incident.incident_key == "S11B")) == "OPEN"


# ---------------------------------------------------------------------------
# Documented boundary: Core-level statements bypass the ORM unit of work
# ---------------------------------------------------------------------------


def test_raw_text_sql_bypasses_the_guard_by_design(db):
    """Documents the boundary honestly: raw SQL outside the ORM is not guarded.

    Verified empirically: object-level UPDATE/DELETE, ``Query.delete()`` /
    ``Query.update()`` and ``session.execute(delete(Table))`` are all refused,
    but a ``text()`` statement and a raw connection are not, because they do
    not pass through the ORM unit of work. That is exactly why the durable
    answer for tamper-evident audit is database-level enforcement plus a
    restricted database role (Step 10, README 21.6), not this module.
    """
    _add_audit(db)
    db.execute(text("DELETE FROM incident_audits"))
    db.commit()
    assert db.scalars(select(IncidentAudit)).all() == []


def test_core_delete_through_the_session_is_refused(db):
    """``session.execute(delete(Table))`` is ORM-routed and therefore blocked."""
    _add_audit(db)
    with pytest.raises(guard.AuditRecordMutationBlocked, match="append-only"):
        db.execute(core_delete(IncidentAudit.__table__))
    db.rollback()


def test_the_boundary_is_documented_in_the_module():
    """The limitation must be stated in code, not only in the report."""
    from pathlib import Path

    source = Path(guard.__file__).read_text(encoding="utf-8")
    assert "bypass" in source
    assert "database-level" in source


# ---------------------------------------------------------------------------
# The test-only purge escape hatch
# ---------------------------------------------------------------------------


def test_purge_scope_permits_the_truncation_the_fixtures_need(db):
    _add_audit(db)
    with guard.allow_audit_purge_for_tests():
        db.execute(core_delete(IncidentAudit.__table__))
        db.commit()
    assert db.scalars(select(IncidentAudit)).all() == []


def test_purge_scope_refuses_to_arm_outside_the_test_environment(monkeypatch):
    """A production process must have no working escape hatch at all."""
    import types

    from app.core import config as config_module

    monkeypatch.setattr(
        config_module,
        "get_settings",
        lambda: types.SimpleNamespace(environment=config_module.ENV_PRODUCTION),
    )
    with pytest.raises(RuntimeError, match="only available when ENVIRONMENT=test"):
        with guard.allow_audit_purge_for_tests():
            pass


def test_purge_scope_is_released_on_exit(db):
    _add_audit(db)
    with guard.allow_audit_purge_for_tests():
        pass
    # Guard active again immediately after the scope closes.
    with pytest.raises(guard.AuditRecordMutationBlocked):
        db.execute(core_delete(IncidentAudit.__table__))
    db.rollback()


def test_purge_scope_nests_and_unwinds_correctly(db):
    _add_audit(db)
    with guard.allow_audit_purge_for_tests():
        with guard.allow_audit_purge_for_tests():
            db.execute(core_delete(IncidentAudit.__table__))
            db.commit()
        # Inner scope exited; outer scope still grants.
        _add_audit(db, id="s11-audit-2")
        db.execute(core_delete(IncidentAudit.__table__))
        db.commit()
    with pytest.raises(guard.AuditRecordMutationBlocked):
        db.execute(core_delete(IncidentAudit.__table__))
    db.rollback()


# ---------------------------------------------------------------------------
# End-to-end through the API
# ---------------------------------------------------------------------------


def test_audit_trail_is_written_and_readable_through_the_api(monkeypatch, client, clean_db):
    """The guard must not disturb the normal audited request path."""
    from sqlalchemy import select as sql_select

    from app.database import session as session_module
    from app.models.auth import AuthAudit

    body = {
        "username": "s11admin",
        "password": "s11-admin-password",
        "display_name": "S11 Admin",
        "roles": ["ADMIN"],
    }
    assert client.post("/api/v1/users", json=body).status_code == 201
    token = client.post(
        "/api/v1/auth/login",
        json={"username": "s11admin", "password": "s11-admin-password"},
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.post("/api/v1/auth/logout", headers=headers).status_code in (200, 204)

    db = session_module.get_session_factory()()
    try:
        events = set(db.scalars(sql_select(AuthAudit.event)).all())
        # Audited request path still records history while the guard is active.
        assert {"USER_CREATED", "LOGIN_SUCCESS", "LOGOUT"} <= events
        # And the rows remain readable.
        assert len(db.scalars(sql_select(AuthAudit)).all()) >= 2
    finally:
        db.close()
