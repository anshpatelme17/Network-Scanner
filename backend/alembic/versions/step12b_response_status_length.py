"""Step 12 fix: widen response status columns.

Revision ID: step12b_response_status_length
Revises: step12_responses
Create Date: 2026-09-28

``response_actions.status`` was VARCHAR(16) but the documented lifecycle
value ``DRY_RUN_COMPLETED`` is 17 characters — SQLite ignores the limit
so tests passed, while PostgreSQL rejected the write at runtime. This
migration widens the action status and audit status-transition columns
to VARCHAR(32). Uses batch mode so it applies on SQLite and PostgreSQL.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step12b_response_status_length"
down_revision: str | None = "step12_responses"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("response_actions") as batch_op:
        batch_op.alter_column(
            "status",
            existing_type=sa.String(16),
            type_=sa.String(32),
            existing_nullable=False,
        )
    with op.batch_alter_table("response_audit") as batch_op:
        for column in ("previous_status", "new_status"):
            batch_op.alter_column(
                column,
                existing_type=sa.String(16),
                type_=sa.String(32),
                existing_nullable=True,
            )


def downgrade() -> None:
    with op.batch_alter_table("response_audit") as batch_op:
        for column in ("previous_status", "new_status"):
            batch_op.alter_column(
                column,
                existing_type=sa.String(32),
                type_=sa.String(16),
                existing_nullable=True,
            )
    with op.batch_alter_table("response_actions") as batch_op:
        batch_op.alter_column(
            "status",
            existing_type=sa.String(32),
            type_=sa.String(16),
            existing_nullable=False,
        )
