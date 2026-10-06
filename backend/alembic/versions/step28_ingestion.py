"""Step 28: ingestion checkpoints (cursor/checkpoint foundation).

Revision ID: step28_ingestion
Revises: step25_risk
Create Date: 2026-09-30

Additive only: new ``ingestion_checkpoints`` table (one row per connector
source) holding the server-built, sanitized cursor of the last
*successfully processed* bounded poll. No existing table is modified and
no row is rewritten; a missing row simply means "no checkpoint yet".
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step28_ingestion"
down_revision: str | None = "step25_risk"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ingestion_checkpoints",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("cursor", sa.Text(), nullable=True),
        sa.Column("last_event_time", sa.DateTime(), nullable=True),
        sa.Column("last_external_event_id", sa.String(255), nullable=True),
        sa.Column("advance_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_rejected_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_ingestion_checkpoints_source", "ingestion_checkpoints", ["source"], unique=True
    )


def downgrade() -> None:
    op.drop_index("ix_ingestion_checkpoints_source", table_name="ingestion_checkpoints")
    op.drop_table("ingestion_checkpoints")
