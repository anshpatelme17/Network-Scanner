"""Step 10: deterministic risk assessments.

Revision ID: step10_risk_assessments
Revises: step9_correlations
Create Date: 2026-09-27

Creates ``risk_assessments`` with indexes for the list/detail query
patterns. Assessment rows carry deterministic application-assigned IDs.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step10_risk_assessments"
down_revision: str | None = "step9_correlations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "risk_assessments",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("entity_type", sa.String(16), nullable=False),
        sa.Column("entity_id", sa.String(64), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("factors", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("explanation", sa.Text(), nullable=False, server_default=""),
        sa.Column("calculated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("scoring_version", sa.String(16), nullable=False),
    )
    for name, columns in [
        ("ix_risk_assessments_entity_type", ["entity_type"]),
        ("ix_risk_assessments_entity_id", ["entity_id"]),
        ("ix_risk_assessments_score", ["score"]),
        ("ix_risk_assessments_severity", ["severity"]),
        ("ix_risk_assessments_scoring_version", ["scoring_version"]),
        ("ix_risk_entity", ["entity_type", "entity_id"]),
    ]:
        op.create_index(name, "risk_assessments", columns)


def downgrade() -> None:
    op.drop_table("risk_assessments")
