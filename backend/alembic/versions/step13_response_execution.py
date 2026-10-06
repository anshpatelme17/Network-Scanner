"""Step 13: simulation execution records.

Revision ID: step13_response_execution
Revises: step12b_response_status_length
Create Date: 2026-09-28

Creates ``response_executions`` (one persisted simulation result per
response action) and adds the ``execution_status`` column to
``response_actions``. No executors, no side effects — storage only.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step13_response_execution"
down_revision: str | None = "step12b_response_status_length"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "response_executions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "action_id",
            sa.String(64),
            sa.ForeignKey("response_actions.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("incident_id", sa.String(64), nullable=False),
        sa.Column("adapter", sa.String(32), nullable=False, server_default="simulation"),
        sa.Column("dry_run", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("would_execute", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("result", sa.String(16), nullable=False, server_default="SIMULATED"),
        sa.Column("explanation", sa.Text(), nullable=False, server_default=""),
        sa.Column("policy_version", sa.String(16), nullable=False, server_default="1.0.0"),
        sa.Column("simulated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    for name, columns in [
        ("ix_response_executions_action_id", ["action_id"]),
        ("ix_response_executions_incident_id", ["incident_id"]),
    ]:
        op.create_index(name, "response_executions", columns)

    with op.batch_alter_table("response_actions") as batch_op:
        batch_op.add_column(sa.Column("execution_status", sa.String(16), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("response_actions") as batch_op:
        batch_op.drop_column("execution_status")
    op.drop_table("response_executions")
