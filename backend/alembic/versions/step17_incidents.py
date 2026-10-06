"""Step 17: incident foundation columns and evidence/audit tables.

Revision ID: step17_incidents
Revises: step15_vulnerabilities
Create Date: 2026-09-28

Additive only: new nullable/defaulted columns on ``incidents``
(``incident_type``, ``risk_score``, ``resolved_at``,
``detection_reason``) plus ``incident_audits`` and
``incident_evidence`` tables. Existing rows default to type OTHER with
NULL score/reason timestamps; no existing data is rewritten.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step17_incidents"
down_revision: str | None = "step15_vulnerabilities"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "incidents",
        sa.Column("incident_type", sa.String(32), nullable=False, server_default="OTHER"),
    )
    op.add_column("incidents", sa.Column("risk_score", sa.Integer(), nullable=True))
    op.add_column("incidents", sa.Column("resolved_at", sa.DateTime(), nullable=True))
    op.add_column("incidents", sa.Column("detection_reason", sa.Text(), nullable=True))
    op.create_index("ix_incidents_incident_type", "incidents", ["incident_type"])

    op.create_table(
        "incident_audits",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "incident_id",
            sa.String(64),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False, server_default="system"),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_incident_audits_incident_id", "incident_audits", ["incident_id"])

    op.create_table(
        "incident_evidence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "incident_id",
            sa.String(64),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("evidence_kind", sa.String(16), nullable=False),
        sa.Column("evidence_id", sa.String(64), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint(
            "incident_id", "evidence_kind", "evidence_id", name="uq_incident_evidence"
        ),
    )
    op.create_index("ix_incident_evidence_incident_id", "incident_evidence", ["incident_id"])


def downgrade() -> None:
    op.drop_table("incident_evidence")
    op.drop_table("incident_audits")
    op.drop_index("ix_incidents_incident_type", table_name="incidents")
    op.drop_column("incidents", "detection_reason")
    op.drop_column("incidents", "resolved_at")
    op.drop_column("incidents", "risk_score")
    op.drop_column("incidents", "incident_type")
