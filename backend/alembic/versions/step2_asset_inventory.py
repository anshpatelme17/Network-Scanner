"""Step 2: asset inventory + controlled scan jobs.

Revision ID: step2_asset_inventory
Revises: None (first domain migration; versions/ was empty in Step 1)
Create Date: 2026-09-27

Creates ``assets``, ``discovered_services`` and ``scan_jobs`` with the
uniqueness constraints and indexes the inventory depends on.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step2_asset_inventory"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("ip_address", sa.String(45), nullable=False, unique=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("mac_address", sa.String(17), nullable=True),
        sa.Column("operating_system", sa.String(255), nullable=True),
        sa.Column("state", sa.String(16), nullable=False, server_default="up"),
        sa.Column("first_seen", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_assets_ip_address", "assets", ["ip_address"])
    op.create_index("ix_assets_hostname", "assets", ["hostname"])
    op.create_index("ix_assets_state", "assets", ["state"])

    op.create_table(
        "discovered_services",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "asset_id",
            sa.String(36),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(8), nullable=False, server_default="tcp"),
        sa.Column("state", sa.String(16), nullable=False, server_default="open"),
        sa.Column("service_name", sa.String(64), nullable=True),
        sa.Column("product", sa.String(128), nullable=True),
        sa.Column("version", sa.String(64), nullable=True),
        sa.Column("extra_info", sa.Text(), nullable=True),
        sa.Column("discovered_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("asset_id", "port", "protocol", name="uq_service_asset_port_proto"),
    )
    op.create_index("ix_discovered_services_asset_id", "discovered_services", ["asset_id"])
    op.create_index("ix_service_asset_port", "discovered_services", ["asset_id", "port"])

    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("target", sa.String(64), nullable=False),
        sa.Column("profile", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("error", sa.String(512), nullable=True),
        sa.Column("assets_found", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("services_found", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("nmap_version", sa.String(32), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
    )
    op.create_index("ix_scan_jobs_target", "scan_jobs", ["target"])
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])


def downgrade() -> None:
    op.drop_table("scan_jobs")
    op.drop_table("discovered_services")
    op.drop_table("assets")
