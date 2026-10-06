"""Step 20: authentication/RBAC foundation tables.

Revision ID: step20_auth
Revises: step18_response_foundation
Create Date: 2026-09-28

Additive only: ``users``, ``revoked_tokens`` and ``auth_audits``.
No existing table is touched; existing data keeps working.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step20_auth"
down_revision: str | None = "step18_response_foundation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("username", sa.String(128), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(256), nullable=False),
        sa.Column("display_name", sa.String(256), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("roles", sa.Text(), nullable=False, server_default='["VIEWER"]'),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("last_login_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_users_username", "users", ["username"])
    op.create_index("ix_users_is_active", "users", ["is_active"])

    op.create_table(
        "revoked_tokens",
        sa.Column("jti", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_revoked_tokens_user_id", "revoked_tokens", ["user_id"])

    op.create_table(
        "auth_audits",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), nullable=True),
        sa.Column("username", sa.String(128), nullable=True),
        sa.Column("event", sa.String(32), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_auth_audits_user_id", "auth_audits", ["user_id"])
    op.create_index("ix_auth_audits_username", "auth_audits", ["username"])
    op.create_index("ix_auth_audits_event", "auth_audits", ["event"])


def downgrade() -> None:
    op.drop_table("auth_audits")
    op.drop_table("revoked_tokens")
    op.drop_table("users")
