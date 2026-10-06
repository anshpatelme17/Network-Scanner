"""Step 3: canonical security events table.

Revision ID: step3_security_events
Revises: step2_asset_inventory
Create Date: 2026-09-27

Creates ``security_events`` with the idempotency unique constraint
(source_type, source_name, external_event_id) and indexes for the
common query patterns (time, severity, source, type, asset).
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step3_security_events"
down_revision: str | None = "step2_asset_inventory"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "security_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("event_time", sa.DateTime(), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("source_type", sa.String(32), nullable=False),
        sa.Column("source_name", sa.String(128), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("destination_ip", sa.String(45), nullable=True),
        sa.Column("source_port", sa.Integer(), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(8), nullable=True),
        sa.Column(
            "asset_id",
            sa.String(36),
            sa.ForeignKey("assets.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("username", sa.String(128), nullable=True),
        sa.Column("process_name", sa.String(255), nullable=True),
        sa.Column("action", sa.String(64), nullable=True),
        sa.Column("status", sa.String(32), nullable=True),
        sa.Column("raw_event", sa.Text(), nullable=True),
        sa.Column("normalized_data", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("correlation_key", sa.String(64), nullable=True),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("external_event_id", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint(
            "source_type", "source_name", "external_event_id", name="uq_event_source_external_id"
        ),
    )
    for name, columns in [
        ("ix_security_events_event_time", ["event_time"]),
        ("ix_security_events_severity", ["severity"]),
        ("ix_security_events_source_type", ["source_type"]),
        ("ix_security_events_event_type", ["event_type"]),
        ("ix_security_events_asset_id", ["asset_id"]),
        ("ix_security_events_external_event_id", ["external_event_id"]),
        ("ix_security_events_source_ip", ["source_ip"]),
        ("ix_security_events_destination_ip", ["destination_ip"]),
        ("ix_security_events_fingerprint", ["fingerprint"]),
        ("ix_security_events_correlation_key", ["correlation_key"]),
        ("ix_event_time_severity", ["event_time", "severity"]),
    ]:
        op.create_index(name, "security_events", columns)


def downgrade() -> None:
    op.drop_table("security_events")
