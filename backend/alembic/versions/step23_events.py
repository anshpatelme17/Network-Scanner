"""Step 23: event confidence/occurrence tracking + ingest audit.

Revision ID: step23_events
Revises: step22_vuln_foundation
Create Date: 2026-09-28

Additive only: ``security_events`` gains nullable ``confidence``,
``occurrence_count`` (default 1) and ``last_seen_at``; new
``event_audits`` table for the ingestion lifecycle. Existing rows get
NULL confidence/last_seen_at and count 1; no data rewritten.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step23_events"
down_revision: str | None = "step22_vuln_foundation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("security_events", sa.Column("confidence", sa.Integer(), nullable=True))
    op.add_column(
        "security_events",
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
    )
    op.add_column("security_events", sa.Column("last_seen_at", sa.DateTime(), nullable=True))
    op.create_table(
        "event_audits",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "event_id",
            sa.String(36),
            sa.ForeignKey("security_events.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_event_audits_event_id", "event_audits", ["event_id"])
    op.create_index("ix_event_audits_action", "event_audits", ["action"])


def downgrade() -> None:
    op.drop_table("event_audits")
    op.drop_column("security_events", "last_seen_at")
    op.drop_column("security_events", "occurrence_count")
    op.drop_column("security_events", "confidence")
