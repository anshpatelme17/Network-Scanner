"""Step 25: incident risk scoring, priority bands, calculation audit.

Revision ID: step25_risk
Revises: step24_correlation
Create Date: 2026-09-28

Additive only: ``risk_assessments`` gains nullable ``priority`` (readers
fall back to deriving it from the stored score, so pre-existing rows
stay correct); new append-only ``risk_audits`` table. No data rewritten.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step25_risk"
down_revision: str | None = "step24_correlation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("risk_assessments", sa.Column("priority", sa.String(8), nullable=True))
    op.create_index("ix_risk_assessments_priority", "risk_assessments", ["priority"])
    op.create_table(
        "risk_audits",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "assessment_id",
            sa.String(64),
            sa.ForeignKey("risk_assessments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("previous_score", sa.Integer(), nullable=True),
        sa.Column("new_score", sa.Integer(), nullable=False),
        sa.Column("classification", sa.String(16), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_risk_audits_assessment_id", "risk_audits", ["assessment_id"])


def downgrade() -> None:
    op.drop_table("risk_audits")
    op.drop_index("ix_risk_assessments_priority", table_name="risk_assessments")
    op.drop_column("risk_assessments", "priority")
