"""Response approval hardening (Step 41).

Covers the additive rejection-reason audit path and the guarantees around
it, without weakening Steps 1-40:

* an optional, bounded rejection reason is recorded on the
  ``RESPONSE_REJECTED`` audit row and nowhere else;
* whitespace-only and absent reasons produce no rationale;
* an over-long reason is refused by the request contract;
* the requester's own ``reason`` is never overwritten by a decision;
* the decision and its audit row stay atomic — an audit-write failure
  leaves no rejected state and no orphaned transition;
* concurrent approvals produce exactly one decision and exactly one
  approval audit row;
* existing authorization, self-approval, duplicate-decision and
  invalid-transition behaviour is unchanged;
* the Step 41 migration adds the nullable column additively and
  preserves rows written before it.
"""

from __future__ import annotations

import importlib.util
import threading
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, select
from sqlalchemy import event as sa_event
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session as SessionClass

from alembic import command
from alembic.config import Config
from app.database import session as session_module
from app.models.responses import ResponseAction, ResponseAudit
from app.services import response_governance, response_service

from .test_response_governance import OBSERVED_SOURCE_IP, _approve, _request, _seed

REASON = "Confirmed benign after review with the asset owner."

BACKEND_ROOT = Path(__file__).resolve().parent.parent
MIGRATION_PATH = BACKEND_ROOT / "alembic" / "versions" / "step41_response_rejection_reason.py"


def _reject(client, action_id, actor="operator-1", body=None, headers=None):
    payload = {"actor": actor}
    if body is not None:
        payload.update(body)
    return client.post(f"/api/v1/responses/{action_id}/reject", json=payload, headers=headers)


def _audit_events(action_id):
    db = session_module.get_session_factory()()
    try:
        return (
            db.query(ResponseAudit)
            .filter(ResponseAudit.action_id == action_id)
            .order_by(ResponseAudit.created_at, ResponseAudit.id)
            .all()
        )
    finally:
        db.close()


def _rejection_row(action_id):
    rows = _audit_events(action_id)
    rejected = [row for row in rows if row.event == response_service.EVENT_RESPONSE_REJECTED]
    assert len(rejected) == 1, [row.event for row in rows]
    return rejected[0]


def _event_names(action_id):
    return [row.event for row in _audit_events(action_id)]


def _status_of(action_id):
    db = session_module.get_session_factory()()
    try:
        action = db.get(ResponseAction, action_id)
        assert action is not None
        return action
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Optional, bounded rejection reason
# ---------------------------------------------------------------------------


def test_rejection_records_the_reason_on_the_audit_event(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]

    rejected = _reject(client, action_id, body={"reason": REASON})
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["status"] == "REJECTED"

    row = _rejection_row(action_id)
    assert row.detail == REASON
    assert row.actor == "operator-1"
    assert row.action_id == action_id
    assert row.incident_id == incident["id"]
    assert row.previous_status == "PENDING_APPROVAL"
    assert row.new_status == "REJECTED"


def test_rejection_without_a_reason_stays_backward_compatible(client, clean_db):
    """A client that submits no reason at all must keep working."""
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]

    rejected = _reject(client, action_id)
    assert rejected.status_code == 200, rejected.text
    assert _rejection_row(action_id).detail is None


def test_whitespace_only_reason_is_treated_as_absent(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]

    rejected = _reject(client, action_id, body={"reason": "   \n\t  "})
    assert rejected.status_code == 200, rejected.text
    assert _rejection_row(action_id).detail is None


def test_rejection_reason_is_trimmed_of_surrounding_whitespace(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]

    rejected = _reject(client, action_id, body={"reason": f"  {REASON}  \n"})
    assert rejected.status_code == 200, rejected.text
    assert _rejection_row(action_id).detail == REASON


def test_reason_is_refused_when_it_exceeds_the_bound(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]

    refused = _reject(client, action_id, body={"reason": "x" * 2001})
    assert refused.status_code == 422
    # Refused before any state change: nothing was decided or audited.
    status = _status_of(action_id).status
    assert status == "PENDING_APPROVAL"


def test_reason_at_the_bound_is_accepted(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]

    rejected = _reject(client, action_id, body={"reason": "y" * 2000})
    assert rejected.status_code == 200, rejected.text
    assert _rejection_row(action_id).detail == "y" * 2000


def test_reason_never_overwrites_the_requesters_reason(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]

    _reject(client, action_id, body={"reason": REASON})

    action = _status_of(action_id)
    assert action.reason == "Confirmed malicious destination in incident evidence."
    assert action.requested_by == "analyst-1"


def test_approval_and_cancellation_never_record_a_reason(client, clean_db):
    incident = _seed(client)
    approved_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, approved_id).status_code == 200

    cancelled_id = _request(
        client, incident["id"], target_reference=OBSERVED_SOURCE_IP
    ).json()["id"]
    assert (
        client.post(f"/api/v1/responses/{cancelled_id}/cancel", json={"actor": "analyst-1"}).status_code
        == 200
    )

    for action_id, event in (
        (approved_id, response_service.EVENT_RESPONSE_APPROVED),
        (cancelled_id, response_service.EVENT_RESPONSE_CANCELLED),
    ):
        rows = [row for row in _audit_events(action_id) if row.event == event]
        assert len(rows) == 1, event
        assert rows[0].detail is None, f"{event} must never carry a rejection reason"


def test_direct_service_call_clamps_an_over_long_reason(client, clean_db):
    """The schema refuses it; the service clamp is the backstop beneath it."""
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]

    db = session_module.get_session_factory()()
    try:
        response_governance.reject(db, action_id, "operator-1", "z" * 5000)
    finally:
        db.close()

    assert _rejection_row(action_id).detail == "z" * response_governance.MAX_REJECTION_REASON


# ---------------------------------------------------------------------------
# Atomicity: a failed audit write must not leave a rejected state
# ---------------------------------------------------------------------------


def test_audit_write_failure_leaves_no_rejected_state(client, clean_db):
    """A real ORM-level failure, not a mocked service.

    The ``before_flush`` hook raises on the audit INSERT, so the whole
    transaction — status change included — is rolled back. The action
    must still be PENDING_APPROVAL with no rejection audit row.
    """
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]

    db = session_module.get_session_factory()()

    def _reject_audit_inserts(session, _flush_context, _instances):
        # ``session.new`` is the set of pending INSERTs, and is never None
        # for this hook; the third positional argument can be, so the
        # pending set is used instead.
        if any(isinstance(obj, ResponseAudit) for obj in session.new):
            raise SQLAlchemyError("simulated audit-table write failure")

    # ``before_flush`` is a Session event, so it is registered on the
    # Session class rather than the engine.
    sa_event.listen(SessionClass, "before_flush", _reject_audit_inserts)
    try:
        with pytest.raises(SQLAlchemyError):
            response_governance.reject(db, action_id, "operator-1", REASON)
    finally:
        sa_event.remove(SessionClass, "before_flush", _reject_audit_inserts)
        db.rollback()
        db.close()

    action = _status_of(action_id)
    assert action.status == "PENDING_APPROVAL"
    assert _event_names(action_id) == [
        response_service.EVENT_RESPONSE_REQUESTED,
        response_service.EVENT_RESPONSE_APPROVAL_REQUIRED,
    ]


def test_successful_rejection_commits_status_and_audit_together(client, clean_db):
    """The positive control for the atomicity test above."""
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]

    assert _reject(client, action_id, body={"reason": REASON}).status_code == 200
    assert _status_of(action_id).status == "REJECTED"
    assert _rejection_row(action_id).detail == REASON


# ---------------------------------------------------------------------------
# Concurrency
#
# Two distinct properties live here and they must not be conflated:
#
#  1. The state-machine guard — a second decision made *after* the first has
#     committed is refused by the stored-status check. This is what the
#     sequential tests below assert, and it holds on any database.
#  2. The row-lock guard — two decisions that genuinely overlap cannot both
#     be accepted. That is what ``_locked_action``'s ``SELECT ... FOR UPDATE``
#     provides, and it only exists on databases that support it. SQLite
#     silently drops the clause, so it is verified here by
#     ``test_fixture_cannot_exercise_row_locking`` and exercised for real by
#     the ``_overlapping`` tests, which skip (rather than pretend) when the
#     fixture cannot lock.
# ---------------------------------------------------------------------------


def _row_locking_available() -> bool:
    """True when the active test database actually emits ``FOR UPDATE``.

    Determined from the compiled SQL rather than from a dialect name, so
    the check stays honest if the fixture ever changes.
    """
    from app.database.session import get_engine
    from app.models.responses import ResponseAction

    engine = get_engine()
    statement = str(
        select(ResponseAction)
        .where(ResponseAction.id == "probe")
        .with_for_update()
        .compile(dialect=engine.dialect)
    ).upper()
    return "FOR UPDATE" in statement


def test_fixture_cannot_exercise_row_locking(client, clean_db):
    """The limitation is measured here, not assumed.

    SQLite is the unit-test database, and it silently drops
    ``SELECT ... FOR UPDATE``. Without this proof the concurrency tests
    below would be claiming a guarantee they never evaluated.
    """
    from app.database.session import get_engine

    engine = get_engine()
    assert engine.dialect.name == "sqlite"
    assert _row_locking_available() is False, (
        "the fixture now supports row locking, so the interleaved race "
        "tests below no longer need to skip"
    )


def _overlapping_decisions(
    first,
    second,
    action_id: str,
) -> dict[str, str]:
    """Run two decisions that genuinely overlap, deterministically.

    The first decision is suspended after it has read the stored row —
    inside its audit write, so the transition is already decided — and is
    released only once the second decision has run to completion and
    committed. That is exactly the interleaving a row lock exists to
    prevent, and it is forced with events rather than sleeps, so the result
    never depends on scheduling.

    Returns ``{"first": "ok"|"refused", "second": ...}``.
    """
    released = threading.Event()
    reached = threading.Event()
    taken = {"done": False}
    original_audit = response_governance._audit

    def _suspending_audit(db, action, event, actor, previous_status, new_status, detail=None):
        # The first decision only: hold it inside the window it opened.
        if not taken["done"] and not released.is_set():
            taken["done"] = True
            reached.set()
            if not released.wait(timeout=5):
                raise AssertionError("the competing decision never completed")
        original_audit(db, action, event, actor, previous_status, new_status, detail)

    results: dict[str, str] = {}
    # Module-level rebind, so the worker thread sees the wrapper too. It is
    # restored before returning, so no state survives this helper.
    response_governance._audit = _suspending_audit
    try:

        def _run_first() -> None:
            session = session_module.get_session_factory()()
            try:
                first(session, action_id)
                results["first"] = "ok"
            except Exception:  # noqa: BLE001 - the loser must fail closed
                results["first"] = "refused"
            finally:
                session.rollback()
                session.close()

        worker = threading.Thread(target=_run_first, name="first-decision")
        worker.start()
        assert reached.wait(timeout=5), "the first decision never reached its write"

        second_session = session_module.get_session_factory()()
        try:
            second(second_session, action_id)
            results["second"] = "ok"
        except Exception:  # noqa: BLE001
            results["second"] = "refused"
        finally:
            second_session.rollback()
            second_session.close()
        released.set()

        worker.join(timeout=5)
        assert not worker.is_alive(), "the first decision never completed"
    finally:
        response_governance._audit = original_audit

    return results


def test_concurrent_approvals_produce_exactly_one_decision(client, clean_db):
    """Two sessions approving one request: one wins, one is refused.

    This asserts the **state-machine** guard, not the row lock: the second
    decision is made after the first has already committed, so it is
    refused by the stored-status check. It would pass on any database.
    Genuinely overlapping approvals are covered by
    ``test_overlapping_approvals_are_serialized_by_row_locking``.
    """
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]

    results = []
    for _ in range(2):
        other = session_module.get_session_factory()()
        try:
            response_governance.approve(other, action_id, "operator-2")
            results.append("ok")
        except Exception:  # noqa: BLE001 - the loser must fail closed
            results.append("refused")
        finally:
            other.rollback()
            other.close()

    assert results.count("ok") == 1, results
    assert results.count("refused") == 1, results

    approvals = [row for row in _audit_events(action_id) if row.event == "RESPONSE_APPROVED"]
    assert len(approvals) == 1, "exactly one approval audit row"
    assert approvals[0].actor == "operator-2"

    action = _status_of(action_id)
    assert action.status == "APPROVED"
    assert action.approved_by == "operator-2"
    assert action.approved_at is not None


def test_approval_and_rejection_race_produce_one_decision(client, clean_db):
    """An approval and a rejection racing on one request.

    The state-machine counterpart of
    ``test_overlapping_approval_and_rejection_are_serialized``: the two
    decisions are made in turn, and the second is refused.
    """
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]

    outcomes = []
    for operation in (response_governance.approve, lambda db, aid, actor: response_governance.reject(db, aid, actor, REASON)):
        other = session_module.get_session_factory()()
        try:
            operation(other, action_id, "operator-2")
            outcomes.append("decided")
        except Exception:  # noqa: BLE001
            outcomes.append("refused")
        finally:
            other.rollback()
            other.close()

    assert outcomes.count("decided") == 1, outcomes
    assert outcomes.count("refused") == 1, outcomes

    decisions = [
        row
        for row in _audit_events(action_id)
        if row.event in ("RESPONSE_APPROVED", "RESPONSE_REJECTED")
    ]
    assert len(decisions) == 1, [row.event for row in decisions]
    assert _status_of(action_id).status in ("APPROVED", "REJECTED")


def test_overlapping_approvals_are_serialized_by_row_locking(client, clean_db):
    """Genuinely overlapping approvals: the row lock picks exactly one.

    Both decisions are in flight at the same instant — the first is held
    after it has read the stored row, the second commits in that window —
    so this is the case ``SELECT ... FOR UPDATE`` exists to prevent. On a
    database that honours the clause the first decision blocks, re-reads
    the committed state, and is refused.
    """
    if not _row_locking_available():
        pytest.skip(
            "SQLite drops SELECT ... FOR UPDATE, so this fixture cannot "
            "exercise the row lock; run this test against PostgreSQL."
        )

    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]

    results = _overlapping_decisions(
        lambda session, aid: response_governance.approve(session, aid, "operator-2"),
        lambda session, aid: response_governance.approve(session, aid, "operator-3"),
        action_id,
    )

    # Exactly one decision was accepted and the other failed closed.
    assert sorted(results.values()) == ["ok", "refused"], results
    # Whichever one won, its identity is the one the audit trail records.
    winner = "operator-2" if results["first"] == "ok" else "operator-3"
    approvals = [row for row in _audit_events(action_id) if row.event == "RESPONSE_APPROVED"]
    assert len(approvals) == 1, "exactly one approval audit row"
    assert approvals[0].actor == winner

    action = _status_of(action_id)
    assert action.status == "APPROVED"
    assert action.approved_by == winner
    assert action.approved_at is not None


def test_overlapping_approval_and_rejection_are_serialized(client, clean_db):
    """An approval and a rejection truly in flight together: one outcome."""
    if not _row_locking_available():
        pytest.skip(
            "SQLite drops SELECT ... FOR UPDATE, so this fixture cannot "
            "exercise the row lock; run this test against PostgreSQL."
        )

    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]

    results = _overlapping_decisions(
        lambda session, aid: response_governance.approve(session, aid, "operator-2"),
        lambda session, aid: response_governance.reject(session, aid, "operator-3", REASON),
        action_id,
    )

    assert sorted(results.values()) == ["ok", "refused"], results

    decisions = [
        row
        for row in _audit_events(action_id)
        if row.event in ("RESPONSE_APPROVED", "RESPONSE_REJECTED")
    ]
    assert len(decisions) == 1, [row.event for row in decisions]
    decided = decisions[0].event
    assert _status_of(action_id).status == (
        "APPROVED" if decided == "RESPONSE_APPROVED" else "REJECTED"
    )
    if decided == "RESPONSE_REJECTED":
        assert decisions[0].detail == REASON


# ---------------------------------------------------------------------------
# Preserved invariants
# ---------------------------------------------------------------------------


def test_rejection_requires_the_same_permission_as_approval(client, clean_db):
    from tests.test_auth import _admin_headers, _auth_header, _seed_incident_auth

    incident = _seed_incident_auth(client, _admin_headers(client))
    analyst = _auth_header(client, "s41-analyst", "analyst-pass-5678", roles=("SECURITY_ANALYST",))
    # An analyst may request, but holds neither APPROVE_RESPONSE nor the
    # ability to reject their own request.
    action_id = client.post(
        "/api/v1/responses/controlled",
        json={
            "incident_id": incident["id"],
            "action_type": "BLOCK_INDICATOR",
            "target_type": "IP",
            "target_reference": "198.51.100.23",
            "reason": "evidence-backed block",
            "requested_by": "s41-analyst",
        },
        headers=analyst,
    ).json()["id"]

    denied = _reject(
        client, action_id, actor="s41-analyst", body={"reason": REASON}, headers=analyst
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "PERMISSION_DENIED"
    assert "APPROVE_RESPONSE" in denied.json()["error"]["message"]
    assert _event_names(action_id) == [
        response_service.EVENT_RESPONSE_REQUESTED,
        response_service.EVENT_RESPONSE_APPROVAL_REQUIRED,
    ]


def test_self_approval_is_still_refused_under_the_default_configuration(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"], requested_by="operator-1").json()["id"]

    attempted = _approve(client, action_id, actor="operator-1")
    assert attempted.status_code == 409
    assert "different user" in attempted.json()["error"]["message"]
    assert _status_of(action_id).approved_by is None


def test_duplicate_rejection_still_fails_closed(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]

    assert _reject(client, action_id, body={"reason": REASON}).status_code == 200
    again = _reject(client, action_id, body={"reason": "second attempt"})
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "INVALID_TRANSITION"
    # The first rationale is the one on record; a duplicate cannot rewrite it.
    assert _rejection_row(action_id).detail == REASON


def test_decision_after_rejection_is_refused(client, clean_db):
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _reject(client, action_id, body={"reason": REASON}).status_code == 200

    assert _approve(client, action_id).status_code == 409
    assert client.post(f"/api/v1/responses/{action_id}/execute", json={}).status_code == 409


def test_approval_does_not_execute(client, clean_db):
    """Approval writes status and identity only; nothing is performed."""
    incident = _seed(client)
    action_id = _request(client, incident["id"]).json()["id"]
    assert _approve(client, action_id).status_code == 200

    action = _status_of(action_id)
    assert action.status == "APPROVED"
    assert action.execution_status is None
    assert action.completed_at is None
    assert action.result_summary is None

    detail = client.get(f"/api/v1/responses/{action_id}").json()
    assert detail["execution"] is None


# ---------------------------------------------------------------------------
# Migration
# ---------------------------------------------------------------------------


def test_migration_adds_the_column_without_losing_existing_rows(tmp_path, monkeypatch):
    db_file = tmp_path / "s41.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))

    command.upgrade(config, "phase2_risk_consistency")
    before = inspect(create_engine(f"sqlite:///{db_file}"))
    assert "detail" not in {c["name"] for c in before.get_columns("response_audit")}

    # A row written before the column existed.
    engine = create_engine(f"sqlite:///{db_file}")
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "INSERT INTO response_actions "
            "(id, incident_id, action_type, target_type, target_reference, reason, "
            " requested_by, status, dry_run, policy_version, created_at, extra_metadata, "
            " provider, policy_decision, approval_required, rollback_supported, target_evidence) "
            "VALUES ('act-1', 'inc-1', 'BLOCK_INDICATOR', 'IP', '198.51.100.23', "
            " 'seeded', 'analyst-1', 'PENDING_APPROVAL', 1, '1.0.0', "
            " '2026-01-01 00:00:00', '{}', 'MOCK', 'APPROVAL_REQUIRED', 1, 0, '[]')"
        )
        connection.exec_driver_sql(
            "INSERT INTO response_audit (id, action_id, incident_id, event, actor, "
            "policy_version, created_at) VALUES "
            "('aud-1', 'act-1', 'inc-1', 'RESPONSE_REQUESTED', 'analyst-1', '1.0.0', "
            " '2026-01-01 00:00:00')"
        )

    command.upgrade(config, "head")
    after = inspect(create_engine(f"sqlite:///{db_file}"))
    columns = {c["name"]: c for c in after.get_columns("response_audit")}
    assert "detail" in columns
    assert columns["detail"]["nullable"] is True

    with engine.begin() as connection:
        kept = connection.exec_driver_sql(
            "SELECT event, actor, detail FROM response_audit WHERE id = 'aud-1'"
        ).fetchall()
        assert kept == [("RESPONSE_REQUESTED", "analyst-1", None)], kept

    # Reversible, and the reversal removes exactly what the upgrade added.
    command.downgrade(config, "phase2_risk_consistency")
    reverted = inspect(create_engine(f"sqlite:///{db_file}"))
    assert "detail" not in {c["name"] for c in reverted.get_columns("response_audit")}


def test_migration_declares_the_expected_revision_chain():
    spec = importlib.util.spec_from_file_location("s41_migration", MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    assert module.revision == "step41_response_rejection_reason"
    assert module.down_revision == "phase2_risk_consistency"
    assert module.branch_labels is None
    assert module.depends_on is None
    assert callable(module.upgrade)
    assert callable(module.downgrade)
