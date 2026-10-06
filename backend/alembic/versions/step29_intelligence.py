"""Step 29: incident-intelligence relationships table.

Revision ID: step29_intelligence
Revises: step28_ingestion
Create Date: 2026-09-30

Additive only: new ``incident_relationships`` table (one row per
deterministic rule-produced link between an incident's stored evidence
events and existing assets/users/indicators). No existing table is
modified and no row is rewritten; incidents without analysis simply
have no rows here. Identity and the six-column uniqueness constraint
come from the model (see ``app.models.incidents.IncidentRelationship``),
so repeated analysis upserts instead of duplicating.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step29_intelligence"
down_revision: str | None = "step28_ingestion"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "incident_relationships",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "incident_id",
            sa.String(64),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("rule_name", sa.String(128), nullable=False),
        sa.Column("relation", sa.String(64), nullable=False),
        sa.Column("source_kind", sa.String(16), nullable=False),
        sa.Column("source_id", sa.String(255), nullable=False),
        sa.Column("source_label", sa.String(255), nullable=True),
        sa.Column("target_kind", sa.String(16), nullable=False),
        sa.Column("target_id", sa.String(255), nullable=False),
        sa.Column("target_label", sa.String(255), nullable=True),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("confidence_label", sa.String(16), nullable=False, server_default="WEAK"),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("evidence_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint(
            "incident_id",
            "rule_id",
            "source_kind",
            "source_id",
            "target_kind",
            "target_id",
            name="uq_incident_relationship",
        ),
    )
    op.create_index(
        "ix_incident_relationships_incident_id", "incident_relationships", ["incident_id"]
    )
    op.create_index("ix_incident_relationships_rule_id", "incident_relationships", ["rule_id"])


def downgrade() -> None:
    op.drop_index("ix_incident_relationships_rule_id", table_name="incident_relationships")
    op.drop_index("ix_incident_relationships_incident_id", table_name="incident_relationships")
    op.drop_table("incident_relationships")
