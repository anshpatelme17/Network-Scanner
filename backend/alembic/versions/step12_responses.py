"""Step 12: dry-run response proposals and audit trail.

Revision ID: step12_responses
Revises: step11_incidents
Create Date: 2026-09-27

Creates ``response_actions`` and ``response_audit``. Action rows carry
deterministic application-assigned IDs; audit rows are append-only
workflow records. No executors, no side effects.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step12_responses"
down_revision: str | None = "step11_incidents"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "response_actions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "incident_id",
            sa.String(64),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("action_type", sa.String(32), nullable=False),
        sa.Column("target_type", sa.String(16), nullable=False),
        sa.Column("target_reference", sa.String(256), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("requested_by", sa.String(128), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="PROPOSED"),
        sa.Column("dry_run", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("policy_version", sa.String(16), nullable=False, server_default="1.0.0"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("extra_metadata", sa.Text(), nullable=False, server_default="{}"),
    )
    for name, columns in [
        ("ix_response_actions_incident_id", ["incident_id"]),
        ("ix_response_actions_action_type", ["action_type"]),
        ("ix_response_actions_status", ["status"]),
        ("ix_response_actions_created_at", ["created_at"]),
    ]:
        op.create_index(name, "response_actions", columns)

    op.create_table(
        "response_audit",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "action_id",
            sa.String(64),
            sa.ForeignKey("response_actions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("incident_id", sa.String(64), nullable=False),
        sa.Column("event", sa.String(32), nullable=False),
        sa.Column("previous_status", sa.String(16), nullable=True),
        sa.Column("new_status", sa.String(16), nullable=True),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("policy_version", sa.String(16), nullable=False, server_default="1.0.0"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    for name, columns in [
        ("ix_response_audit_action_id", ["action_id"]),
        ("ix_response_audit_incident_id", ["incident_id"]),
        ("ix_response_audit_event", ["event"]),
    ]:
        op.create_index(name, "response_audit", columns)


def downgrade() -> None:
    op.drop_table("response_audit")
    op.drop_table("response_actions")
