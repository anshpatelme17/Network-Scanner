"""Step 24: correlation-run audit trail.

Revision ID: step24_correlation
Revises: step23_events
Create Date: 2026-09-28

Additive only: new append-only ``correlation_audits`` table for
recompute lifecycle facts (RUN_STARTED / CORRELATION_MATCHED /
RUN_COMPLETED). No existing table is touched; no data rewritten.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step24_correlation"
down_revision: str | None = "step23_events"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "correlation_audits",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "correlation_id",
            sa.String(64),
            sa.ForeignKey("correlations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_correlation_audits_correlation_id", "correlation_audits", ["correlation_id"]
    )
    op.create_index("ix_correlation_audits_action", "correlation_audits", ["action"])


def downgrade() -> None:
    op.drop_table("correlation_audits")
