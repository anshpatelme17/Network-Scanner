"""Step 11: incident records.

Revision ID: step11_incidents
Revises: step10_risk_assessments
Create Date: 2026-09-27

Creates ``incidents`` with a unique human-readable key and indexes for
the list/detail query patterns. Incident rows carry deterministic
application-assigned IDs.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step11_incidents"
down_revision: str | None = "step10_risk_assessments"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("incident_key", sa.String(16), nullable=False, unique=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="OPEN"),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "primary_asset_id",
            sa.String(36),
            sa.ForeignKey("assets.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("primary_ip", sa.String(45), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column(
            "correlation_id",
            sa.String(64),
            sa.ForeignKey("correlations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "risk_assessment_id",
            sa.String(64),
            sa.ForeignKey("risk_assessments.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("version", sa.String(16), nullable=False, server_default="1.0.0"),
    )
    for name, columns in [
        ("ix_incidents_incident_key", ["incident_key"]),
        ("ix_incidents_status", ["status"]),
        ("ix_incidents_severity", ["severity"]),
        ("ix_incidents_correlation_id", ["correlation_id"]),
        ("ix_incidents_risk_assessment_id", ["risk_assessment_id"]),
        ("ix_incidents_created_at", ["created_at"]),
    ]:
        op.create_index(name, "incidents", columns)


def downgrade() -> None:
    op.drop_table("incidents")
