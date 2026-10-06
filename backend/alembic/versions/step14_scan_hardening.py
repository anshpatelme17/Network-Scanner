"""Step 14: authorized-discovery hardening (additive only).

Revision ID: step14_scan_hardening
Revises: step13_response_execution
Create Date: 2026-09-28

- assets: asset_type / discovery_source / discovery_scan_id
- discovered_services: discovery_scan_id
- scan_jobs: scan_type / requested_by / result_summary
- new scan_audit table (append-only lifecycle events)

No existing column is altered or dropped; all additions are nullable
or carry defaults, so existing rows are unaffected.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step14_scan_hardening"
down_revision: str | None = "step13_response_execution"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("assets") as batch_op:
        batch_op.add_column(
            sa.Column("asset_type", sa.String(32), nullable=False, server_default="UNKNOWN")
        )
        batch_op.add_column(sa.Column("discovery_source", sa.String(32), nullable=True))
        batch_op.add_column(sa.Column("discovery_scan_id", sa.String(36), nullable=True))
        batch_op.create_foreign_key(
            "fk_assets_discovery_scan",
            "scan_jobs",
            ["discovery_scan_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index("ix_assets_asset_type", ["asset_type"])

    with op.batch_alter_table("discovered_services") as batch_op:
        batch_op.add_column(sa.Column("discovery_scan_id", sa.String(36), nullable=True))
        batch_op.create_foreign_key(
            "fk_services_discovery_scan",
            "scan_jobs",
            ["discovery_scan_id"],
            ["id"],
            ondelete="SET NULL",
        )

    with op.batch_alter_table("scan_jobs") as batch_op:
        batch_op.add_column(
            sa.Column("scan_type", sa.String(16), nullable=False, server_default="nmap")
        )
        batch_op.add_column(
            sa.Column("requested_by", sa.String(128), nullable=False, server_default="operator")
        )
        batch_op.add_column(sa.Column("result_summary", sa.String(256), nullable=True))

    op.create_table(
        "scan_audit",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "scan_id",
            sa.String(36),
            sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event", sa.String(32), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("detail", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    for name, columns in [
        ("ix_scan_audit_scan_id", ["scan_id"]),
        ("ix_scan_audit_event", ["event"]),
    ]:
        op.create_index(name, "scan_audit", columns)


def downgrade() -> None:
    op.drop_table("scan_audit")
    with op.batch_alter_table("scan_jobs") as batch_op:
        batch_op.drop_column("result_summary")
        batch_op.drop_column("requested_by")
        batch_op.drop_column("scan_type")
    with op.batch_alter_table("discovered_services") as batch_op:
        batch_op.drop_constraint("fk_services_discovery_scan", type_="foreignkey")
        batch_op.drop_column("discovery_scan_id")
    with op.batch_alter_table("assets") as batch_op:
        batch_op.drop_index("ix_assets_asset_type")
        batch_op.drop_constraint("fk_assets_discovery_scan", type_="foreignkey")
        batch_op.drop_column("discovery_scan_id")
        batch_op.drop_column("discovery_source")
        batch_op.drop_column("asset_type")
