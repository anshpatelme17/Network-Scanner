"""Append-only enforcement for audit records (Phase 2, Step 11).

Every audit table in this platform is *append-only by convention*: no
endpoint updates or deletes an audit row, and each audit write happens in the
same transaction as the fact it records. That convention is good but it is
not an invariant — a future bug, a careless ``db.query(...).delete()``, or a
bulk statement could rewrite security history without anything objecting.

Step 10 recorded this precisely as a limitation: *"Audit tables are
append-only by convention and by code path... There is no database-level
enforcement."* Database-level enforcement (triggers, ``REVOKE``) is a
migration and belongs to a deployment's DBA; this module closes the gap that
*is* in reach, at the ORM unit-of-work boundary, so that an accidental
mutation fails loudly in development, in tests, and in production.

Two layers, because SQLAlchemy offers two ways to mutate a row:

1. ``before_flush`` refuses an ``UPDATE`` or ``DELETE`` of a loaded audit
   instance (``session.dirty`` / ``session.deleted``).
2. ``do_orm_execute`` refuses an ORM bulk ``UPDATE``/``DELETE`` whose target
   table is an audit table (``db.query(Audit).delete()``).

**Scope and limits, stated plainly:**

* Refusal is fail-closed and immediate: the flush never reaches the database
  and the caller gets :class:`AuditRecordMutationBlocked`.
* Core-level statements (``db.execute(delete(Audit.__table__))``,
  ``text("DELETE FROM ...")``, a migration, ``Session.execute`` of a Core
  construct) bypass the ORM unit of work and therefore bypass this guard.
  That is not an oversight to be fixed later in this module — it is the
  boundary. The durable answer for tamper-evident audit is database-level
  enforcement plus a restricted database role, as documented in Step 10.
* The guard never changes read behaviour, never blocks ``INSERT``, and adds
  no capability of any kind: it can only refuse to destroy history.

Detection is by **class name** (``*Audit``) rather than table-name suffix,
because two audit tables are singular (``response_audit``, ``scan_audit``)
and would have been missed by a ``_audits`` check.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import event
from sqlalchemy.orm import Session

from app.core.logging import get_logger

logger = get_logger(__name__)

AUDIT_CLASS_SUFFIX = "Audit"

_INSTALLED = False
_AUDIT_TYPES: tuple[type, ...] | None = None
# Depth counter for the test-only escape hatch below.
#
# Deliberately a plain module-level integer rather than a ``threading.local``:
# Step 31 forbids application modules from importing ``threading``,
# ``asyncio``, ``sched`` or ``multiprocessing``, so that no background or
# autonomous machinery can be introduced by accident. That control is worth
# more than per-thread isolation here, because the hatch cannot be armed at
# all outside ``ENVIRONMENT=test`` (see below) and its only caller is a
# synchronous test fixture.
_audit_purge_depth = 0


class AuditRecordMutationBlocked(RuntimeError):
    """An attempt was made to update or delete an append-only audit record.

    Deliberately a ``RuntimeError`` and not an ``HTTPException``: this is a
    programming/consistency error that must surface as a failure, never as a
    silent partial write and never as a value a caller could interpret as a
    successful outcome.
    """


def audit_model_classes() -> tuple[type, ...]:
    """Every mapped audit model, discovered from the ORM registry.

    Discovered rather than hand-listed so a newly added audit model cannot be
    forgotten here. A test asserts the discovery matches the eight expected
    tables, so an accidental rename or a missing import fails loudly.
    """
    global _AUDIT_TYPES
    from app.database.base import Base

    # Recompute while the registry is still empty (models not yet imported);
    # cache only once the mapping registry is populated.
    if not Base.registry.mappers:
        _AUDIT_TYPES = None
        return ()
    found = tuple(
        sorted(
            {
                mapper.class_
                for mapper in Base.registry.mappers
                if mapper.class_.__name__.endswith(AUDIT_CLASS_SUFFIX)
            },
            key=lambda cls: cls.__name__,
        )
    )
    if found != _AUDIT_TYPES:
        _AUDIT_TYPES = found
    return found


def audit_table_names() -> frozenset[str]:
    """Table names of every audit model, for bulk-statement inspection."""
    return frozenset(cls.__tablename__ for cls in audit_model_classes())


def is_audit_record(obj: Any) -> bool:
    """True when ``obj`` is a mapped audit instance."""
    audit_types = audit_model_classes()
    return bool(audit_types) and isinstance(obj, audit_types)


def _audit_label(obj: Any) -> str:
    identifier = getattr(obj, "id", None)
    return (
        f"{type(obj).__name__}(id={identifier!r})" if identifier is not None else type(obj).__name__
    )


def _purge_active() -> bool:
    """True only inside an explicitly granted, test-only purge scope."""
    return _audit_purge_depth > 0


@contextmanager
def allow_audit_purge_for_tests() -> Iterator[None]:
    """Temporarily permit audit-table purges. **Test-only; inert in production.**

    The test suite truncates every table between tests so cases stay
    isolated, and that genuinely requires deleting audit rows. Rather than
    weakening the guard for everyone, this is an explicit, narrow, scoped
    capability with two properties that make it safe to ship in the same
    module as the guard:

    * It **refuses to arm unless ``ENVIRONMENT=test``**, so a production or
      staging process has no working escape hatch at all — calling it there
      raises instead of granting. There is therefore no concurrency question
      to answer in a deployed process.
    * It is a depth counter released on exit, so nested use unwinds
      correctly and the guard re-arms the moment the scope closes.

    Application code must never use this; it exists so the isolation the
    pre-existing fixtures already depend on keeps working.
    """
    global _audit_purge_depth
    from app.core.config import ENV_TEST, get_settings

    if get_settings().environment != ENV_TEST:
        raise RuntimeError(
            "allow_audit_purge_for_tests() is only available when ENVIRONMENT=test; "
            "audit history is append-only in every other environment."
        )
    _audit_purge_depth += 1
    try:
        yield
    finally:
        _audit_purge_depth -= 1


def forbid_audit_object_mutation(session, flush_context, instances) -> None:  # noqa: ANN001, ARG001
    """``before_flush``: refuse an UPDATE or DELETE of an audit instance."""
    if _purge_active():
        return
    if session.dirty:
        for obj in session.dirty:
            if is_audit_record(obj):
                raise AuditRecordMutationBlocked(
                    f"{_audit_label(obj)} is append-only: an UPDATE was attempted. "
                    "Append a new audit row instead of modifying an existing one."
                )
    if session.deleted:
        for obj in session.deleted:
            if is_audit_record(obj):
                raise AuditRecordMutationBlocked(
                    f"{_audit_label(obj)} is append-only: a DELETE was attempted. "
                    "Audit history cannot be removed."
                )


def forbid_audit_bulk_mutation(execute_state) -> None:  # noqa: ANN001
    """``do_orm_execute``: refuse an ORM bulk UPDATE/DELETE of an audit table."""
    if not (execute_state.is_update or execute_state.is_delete):
        return
    statement = getattr(execute_state, "statement", None)
    table = getattr(statement, "table", None)
    table_name = getattr(table, "name", None)
    if table_name is None or table_name not in audit_table_names():
        return
    if _purge_active():
        return
    verb = "UPDATE" if execute_state.is_update else "DELETE"
    raise AuditRecordMutationBlocked(
        f"table {table_name!r} is append-only: a bulk {verb} was attempted. "
        "Audit history cannot be modified or removed."
    )


def install_audit_append_only_guard() -> bool:
    """Register both guards on the ORM ``Session``. Idempotent.

    Returns True when the listeners were registered by this call and False
    when they were already present, so installation can be asserted in a test
    without counting duplicate registrations.
    """
    global _INSTALLED
    if _INSTALLED:
        return False
    if not event.contains(Session, "before_flush", forbid_audit_object_mutation):
        event.listen(Session, "before_flush", forbid_audit_object_mutation)
    if not event.contains(Session, "do_orm_execute", forbid_audit_bulk_mutation):
        event.listen(Session, "do_orm_execute", forbid_audit_bulk_mutation)
    _INSTALLED = True
    logger.info("Append-only audit guard installed for %d audit tables", len(audit_table_names()))
    return True


__all__ = [
    "AUDIT_CLASS_SUFFIX",
    "AuditRecordMutationBlocked",
    "allow_audit_purge_for_tests",
    "audit_model_classes",
    "audit_table_names",
    "forbid_audit_bulk_mutation",
    "forbid_audit_object_mutation",
    "install_audit_append_only_guard",
    "is_audit_record",
]
