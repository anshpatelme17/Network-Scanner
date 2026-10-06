"""Phase 2 Step 12 (fix): the guard raises 23001 instead of failing on format().

Revision ID: phase2_step12_guard_sqlstate_fix
Revises: phase2_step12_audit_immutability
Create Date: 2026-10-06

``phase2_step12_audit_immutability`` installed the append-only guard with a
malformed ``format()`` template::

    MESSAGE = format(
        'audit_append_only: % is append-only; % is not permitted on audit history',
        TG_TABLE_NAME,
        TG_OP
    )

``%`` followed by a space is not a conversion specification, so PostgreSQL
raises ``unrecognized format() type specifier " "`` with SQLSTATE ``22023``
*before* the guard's own ``RAISE EXCEPTION`` runs. The write was still refused,
so the protection never silently failed - but the refusal arrived as an
unclassified internal error instead of the intended ``restrict_violation``,
which is what callers are documented to catch. Step 13's runtime verification
found this on a real server.

This revision replaces the function body in place. Nothing else changes:

* The eight ``BEFORE UPDATE OR DELETE`` triggers are untouched and keep
  pointing at the same function name.
* ``INSERT`` remains untouched, so audit recording is unaffected.
* The protection is not weakened. ``ERRCODE`` remains ``restrict_violation``,
  which is condition name 23001; only the message template is corrected, from
  ``%`` to ``%s``.

Two lessons are encoded in the shape of this migration rather than only in its
docstring. A bare ``%`` in a ``format()`` template is not inert - it is a
runtime error waiting for the first write attempt, and a migration is exactly
the place where such a mistake is invisible to review because the SQL is a
string nobody executes until it is installed. And ``CREATE OR REPLACE
FUNCTION`` makes the repair possible without touching the trigger set, which is
why a body fix needs no table DDL at all.

Step 12's own migration is deliberately left exactly as it was applied. Editing
an already-applied migration would make the recorded history disagree with the
database it claims to describe; the repair belongs forward, in this revision.

Design notes:

* **PostgreSQL only, and a no-op elsewhere.** The suite runs on SQLite, where
  PL/pgSQL does not exist, so the dialect is checked before any DDL is issued.
* **Reversible.** ``downgrade()`` reinstates the previous function body, which
  is what the prior revision installed, so a rollback returns the database to
  the state that revision describes. The restored body is the defective one;
  that is inherent to reversing to it, and re-upgrading repairs it again.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "phase2_step12_guard_sqlstate_fix"
down_revision: str | None = "phase2_step12_audit_immutability"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Same function the triggers already call; only its body is replaced.
GUARD_FUNCTION = "audit_append_only_guard"

#: Dialect this migration applies to. Anything else is a silent no-op.
SUPPORTED_DIALECT = "postgresql"

#: The condition name PostgreSQL maps to SQLSTATE 23001.
RESTRICT_VIOLATION = "restrict_violation"

#: The corrected template. `%s` is a conversion specification; a bare `%` is not.
MESSAGE_TEMPLATE = (
    "audit_append_only: %s is append-only; %s is not permitted on audit history"
)

#: The body installed by phase2_step12_audit_immutability, kept verbatim so
#: `downgrade()` can restore it exactly. Do not "fix" it here.
PREVIOUS_MESSAGE_TEMPLATE = (
    "audit_append_only: % is append-only; % is not permitted on audit history"
)


def _function_ddl(message_template: str) -> str:
    """The PL/pgSQL guard function with the given message template."""
    return f"""
CREATE OR REPLACE FUNCTION {GUARD_FUNCTION}() RETURNS trigger
LANGUAGE plpgsql
AS $audit_append_only$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '{RESTRICT_VIOLATION}',
        MESSAGE = format(
            '{message_template}',
            TG_TABLE_NAME,
            TG_OP
        );
END;
$audit_append_only$
""".strip()


def build_upgrade_statements(dialect_name: str) -> tuple[str, ...]:
    """DDL that repairs the guard, or nothing on other dialects.

    Pure function: no connection, no Alembic context.
    """
    if dialect_name != SUPPORTED_DIALECT:
        return ()
    return (_function_ddl(MESSAGE_TEMPLATE),)


def build_downgrade_statements(dialect_name: str) -> tuple[str, ...]:
    """DDL that reinstates the body the previous revision installed."""
    if dialect_name != SUPPORTED_DIALECT:
        return ()
    return (_function_ddl(PREVIOUS_MESSAGE_TEMPLATE),)


def _dialect_name() -> str:
    return op.get_bind().dialect.name


def upgrade() -> None:
    for statement in build_upgrade_statements(_dialect_name()):
        op.execute(statement)


def downgrade() -> None:
    for statement in build_downgrade_statements(_dialect_name()):
        op.execute(statement)
