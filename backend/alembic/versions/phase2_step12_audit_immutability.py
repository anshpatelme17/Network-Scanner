"""Phase 2 Step 12: database-level append-only enforcement for audit tables.

Revision ID: phase2_step12_audit_immutability
Revises: step31_hardening
Create Date: 2026-10-01

Step 11 enforced append-only audit history at the ORM unit of work, and
documented the boundary honestly: raw ``text()`` SQL, a raw connection, a
migration, or any external client bypasses the ORM entirely. This migration
closes that boundary at the database, so audit history is protected no matter
how the statement arrives.

For each audit table a ``BEFORE UPDATE OR DELETE ... FOR EACH ROW`` trigger
raises ``restrict_violation``. ``INSERT`` is untouched, so audit recording is
completely unaffected.

Design notes:

* **Frozen table list.** The eight table names are hard-coded rather than
  imported from the models. A migration must be an immutable snapshot; if it
  derived its table list from live model code, renaming a model would
  silently rewrite the meaning of an already-applied migration. A test asserts
  this list still matches ``audit_guard.audit_table_names()`` so the two
  cannot drift apart unnoticed.
* **PostgreSQL only, and a no-op elsewhere.** The suite runs on SQLite, where
  PL/pgSQL does not exist. The dialect is checked before any DDL is issued, so
  ``upgrade()`` on SQLite succeeds and changes nothing.
* **Idempotent.** Each trigger is dropped before it is created, so re-running
  ``upgrade()`` cannot fail on "trigger already exists".
* **Reversible.** ``downgrade()`` removes only the triggers and the function
  this migration created. It rewrites no rows, so a rollback cannot lose audit
  history.

Deliberate boundary: this covers DML (``UPDATE``/``DELETE``). ``TRUNCATE``,
``DROP TABLE`` and a superuser are *not* blocked. Blocking ``TRUNCATE`` was
considered and rejected as out of scope: it changes operational behaviour for
deliberate data-purge procedures, and "append-only" is about rows not being
modified or removed by normal DML. Superusers can always disable triggers,
which is why the deployment guidance is a restricted database role (README
21.7) rather than this trigger alone.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "phase2_step12_audit_immutability"
down_revision: str | None = "step31_hardening"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Frozen snapshot of every audit table (see module docstring).
AUDIT_TABLES: tuple[str, ...] = (
    "auth_audits",
    "correlation_audits",
    "event_audits",
    "incident_audits",
    "response_audit",
    "risk_audits",
    "scan_audit",
    "vulnerability_audits",
)

GUARD_FUNCTION = "audit_append_only_guard"

#: Dialect this migration applies to. Anything else is a silent no-op.
SUPPORTED_DIALECT = "postgresql"


def trigger_name(table: str) -> str:
    """Deterministic trigger name for one audit table."""
    return f"trg_{table}_append_only"


def _function_ddl() -> str:
    """The single PL/pgSQL guard function shared by every trigger."""
    return f"""
CREATE OR REPLACE FUNCTION {GUARD_FUNCTION}() RETURNS trigger
LANGUAGE plpgsql
AS $audit_append_only$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = 'restrict_violation',
        MESSAGE = format(
            'audit_append_only: % is append-only; % is not permitted on audit history',
            TG_TABLE_NAME,
            TG_OP
        );
END;
$audit_append_only$
""".strip()


def build_upgrade_statements(
    dialect_name: str, tables: Sequence[str] = AUDIT_TABLES
) -> tuple[str, ...]:
    """DDL that installs append-only enforcement, or nothing on other dialects.

    Pure function: no connection, no Alembic context. Keeping it pure is what
    makes the migration's logic testable on SQLite, where the DDL itself could
    never be executed.
    """
    if dialect_name != SUPPORTED_DIALECT:
        return ()
    statements = [_function_ddl()]
    for table in tables:
        name = trigger_name(table)
        statements.append(f"DROP TRIGGER IF EXISTS {name} ON {table};")
        statements.append(
            f"CREATE TRIGGER {name} BEFORE UPDATE OR DELETE ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION {GUARD_FUNCTION}();"
        )
    return tuple(statements)


def build_downgrade_statements(
    dialect_name: str, tables: Sequence[str] = AUDIT_TABLES
) -> tuple[str, ...]:
    """DDL that removes exactly what :func:`build_upgrade_statements` added."""
    if dialect_name != SUPPORTED_DIALECT:
        return ()
    statements = [f"DROP TRIGGER IF EXISTS {trigger_name(table)} ON {table};" for table in tables]
    statements.append(f"DROP FUNCTION IF EXISTS {GUARD_FUNCTION}();")
    return tuple(statements)


def _dialect_name() -> str:
    return op.get_bind().dialect.name


def upgrade() -> None:
    for statement in build_upgrade_statements(_dialect_name()):
        op.execute(statement)


def downgrade() -> None:
    for statement in build_downgrade_statements(_dialect_name()):
        op.execute(statement)
