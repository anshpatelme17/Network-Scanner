"""Step 18: controlled response foundation columns.

Revision ID: step18_response_foundation
Revises: step17_incidents
Create Date: 2026-09-28

Additive only: ``response_actions`` gains ``approved_by``,
``started_at``, ``completed_at``, ``failure_reason`` and
``result_summary`` for the Step 18 safe-action execution path.
Existing rows keep NULLs; no existing data is rewritten and no
Step 12/13 semantics change.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step18_response_foundation"
down_revision: str | None = "step17_incidents"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("response_actions", sa.Column("approved_by", sa.String(128), nullable=True))
    op.add_column("response_actions", sa.Column("started_at", sa.DateTime(), nullable=True))
    op.add_column("response_actions", sa.Column("completed_at", sa.DateTime(), nullable=True))
    op.add_column("response_actions", sa.Column("failure_reason", sa.Text(), nullable=True))
    op.add_column("response_actions", sa.Column("result_summary", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("response_actions", "result_summary")
    op.drop_column("response_actions", "failure_reason")
    op.drop_column("response_actions", "completed_at")
    op.drop_column("response_actions", "started_at")
    op.drop_column("response_actions", "approved_by")
