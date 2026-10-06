"""Step 15: normalized vulnerability findings.

Revision ID: step15_vulnerabilities
Revises: step14_scan_hardening
Create Date: 2026-09-28

Creates ``vulnerabilities`` and ``vulnerability_audits``; extends
``scan_jobs`` with an asset reference and a wider profile column for
vulnerability-assessment profiles. Additive only; existing rows and
Step 14 behavior are unaffected.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step15_vulnerabilities"
down_revision: str | None = "step14_scan_hardening"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "asset_id",
            sa.String(36),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "service_id",
            sa.String(36),
            sa.ForeignKey("discovered_services.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("scanner", sa.String(64), nullable=False),
        sa.Column("scanner_finding_id", sa.String(128), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cve_id", sa.String(32), nullable=True),
        sa.Column("cwe_id", sa.String(32), nullable=True),
        sa.Column("affected_component", sa.String(256), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("remediation_reference", sa.Text(), nullable=True),
        sa.Column("extra_data", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("status", sa.String(16), nullable=False, server_default="OPEN"),
        sa.Column("first_seen", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint(
            "scanner", "scanner_finding_id", "asset_id", "service_id", name="uq_vuln_identity"
        ),
    )
    for name, columns in [
        ("ix_vulnerabilities_asset_id", ["asset_id"]),
        ("ix_vulnerabilities_service_id", ["service_id"]),
        ("ix_vulnerabilities_severity", ["severity"]),
        ("ix_vulnerabilities_status", ["status"]),
        ("ix_vulnerabilities_cve_id", ["cve_id"]),
        ("ix_vulnerabilities_scanner", ["scanner"]),
    ]:
        op.create_index(name, "vulnerabilities", columns)

    op.create_table(
        "vulnerability_audits",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "vulnerability_id",
            sa.String(64),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event", sa.String(32), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("previous_status", sa.String(16), nullable=True),
        sa.Column("new_status", sa.String(16), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("detail", sa.String(512), nullable=True),
    )
    for name, columns in [
        ("ix_vulnerability_audits_vulnerability_id", ["vulnerability_id"]),
        ("ix_vulnerability_audits_event", ["event"]),
    ]:
        op.create_index(name, "vulnerability_audits", columns)

    with op.batch_alter_table("scan_jobs") as batch_op:
        batch_op.add_column(sa.Column("asset_id", sa.String(36), nullable=True))
        batch_op.create_foreign_key(
            "fk_scan_jobs_asset", "assets", ["asset_id"], ["id"], ondelete="SET NULL"
        )
        batch_op.alter_column(
            "profile", existing_type=sa.String(16), type_=sa.String(64), existing_nullable=False
        )


def downgrade() -> None:
    with op.batch_alter_table("scan_jobs") as batch_op:
        batch_op.alter_column(
            "profile", existing_type=sa.String(64), type_=sa.String(16), existing_nullable=False
        )
        batch_op.drop_constraint("fk_scan_jobs_asset", type_="foreignkey")
        batch_op.drop_column("asset_id")
    op.drop_table("vulnerability_audits")
    op.drop_table("vulnerabilities")
