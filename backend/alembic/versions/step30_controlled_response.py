"""Step 30: controlled defensive-response governance columns.

Revision ID: step30_controlled_response
Revises: step29_intelligence
Create Date: 2026-09-30

Additive only: seven columns on the existing ``response_actions`` table
(server-selected provider, policy decision, approval requirement,
rollback capability/state/prior-state reference, and the server-derived
target evidence) plus one new ``response_rollbacks`` table recording
explicit, authorized rollback attempts. No existing table is dropped, no
existing column is narrowed or renamed, and no row is rewritten: every
Step 12/13/18/19 response row keeps the documented dry-run-only
posture through the column defaults, so previously stored proposals
remain exactly as truthful as they were before this step.

The rollback table's UNIQUE constraint on ``action_id`` is the
structural guarantee that one action can be rolled back at most once,
and the existing UNIQUE on ``response_executions.action_id`` continues
to guarantee at most one execution per action.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step30_controlled_response"
down_revision: str | None = "step29_intelligence"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "response_actions",
        sa.Column("provider", sa.String(32), nullable=False, server_default="MOCK"),
    )
    op.add_column(
        "response_actions",
        sa.Column("policy_decision", sa.String(32), nullable=False, server_default="DRY_RUN_ONLY"),
    )
    op.add_column(
        "response_actions",
        sa.Column("approval_required", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.add_column(
        "response_actions",
        sa.Column("rollback_supported", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("response_actions", sa.Column("rollback_state", sa.String(16), nullable=True))
    op.add_column(
        "response_actions", sa.Column("rollback_reference", sa.String(128), nullable=True)
    )
    op.add_column(
        "response_actions",
        sa.Column("target_evidence", sa.Text(), nullable=False, server_default="[]"),
    )

    op.create_table(
        "response_rollbacks",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "action_id",
            sa.String(64),
            sa.ForeignKey("response_actions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("incident_id", sa.String(64), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False, server_default="MOCK"),
        sa.Column("result", sa.String(16), nullable=False, server_default="UNSUPPORTED"),
        sa.Column("explanation", sa.Text(), nullable=False, server_default=""),
        sa.Column("policy_version", sa.String(16), nullable=False, server_default="1.0.0"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("action_id", name="uq_response_rollback_action"),
    )
    op.create_index("ix_response_rollbacks_action_id", "response_rollbacks", ["action_id"])
    op.create_index("ix_response_rollbacks_incident_id", "response_rollbacks", ["incident_id"])


def downgrade() -> None:
    op.drop_index("ix_response_rollbacks_incident_id", table_name="response_rollbacks")
    op.drop_index("ix_response_rollbacks_action_id", table_name="response_rollbacks")
    op.drop_table("response_rollbacks")
    op.drop_column("response_actions", "target_evidence")
    op.drop_column("response_actions", "rollback_reference")
    op.drop_column("response_actions", "rollback_state")
    op.drop_column("response_actions", "rollback_supported")
    op.drop_column("response_actions", "approval_required")
    op.drop_column("response_actions", "policy_decision")
    op.drop_column("response_actions", "provider")
