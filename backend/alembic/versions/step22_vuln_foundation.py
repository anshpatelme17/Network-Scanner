"""Step 22: vulnerability finding versions, job scanner, NOT_SEEN support.

Revision ID: step22_vuln_foundation
Revises: step20_auth
Create Date: 2026-09-28

Additive only: ``vulnerabilities`` gains nullable ``scanner_version``,
``detected_version`` and ``fixed_version``; ``scan_jobs`` gains nullable
``scanner`` (which adapter ran the job). No status column change is
needed (NOT_SEEN fits VARCHAR(16)). Existing rows keep NULLs; no data
is rewritten.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step22_vuln_foundation"
down_revision: str | None = "step20_auth"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("vulnerabilities", sa.Column("scanner_version", sa.String(64), nullable=True))
    op.add_column("vulnerabilities", sa.Column("detected_version", sa.String(128), nullable=True))
    op.add_column("vulnerabilities", sa.Column("fixed_version", sa.String(128), nullable=True))
    op.add_column("scan_jobs", sa.Column("scanner", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_jobs", "scanner")
    op.drop_column("vulnerabilities", "fixed_version")
    op.drop_column("vulnerabilities", "detected_version")
    op.drop_column("vulnerabilities", "scanner_version")
