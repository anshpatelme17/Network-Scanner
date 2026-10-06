"""User identity, token revocation, and auth audit (Step 20).

``User`` is the single application identity: username (unique,
case-insensitive by convention — stored lowercased), Argon2id
``password_hash`` (never a raw password), display name, active flag,
and a JSON list of role names validated against the Step 20 role
vocabulary. Permissions are NOT stored; they derive deterministically
from roles via ``auth_service.ROLE_PERMISSIONS``, so role meaning
cannot drift per row.

``RevokedToken`` is the logout denylist for otherwise-stateless JWTs
(jti primary key). ``AuthAudit`` records authentication and
authorization lifecycle events using the same actor/event/detail
conventions as the other audit tables. Audit rows never contain
passwords, hashes, or tokens.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


def _utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    display_name: Mapped[str] = mapped_column(String(256), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    # JSON array of role names, e.g. '["SECURITY_ANALYST"]'.
    roles: Mapped[str] = mapped_column(Text, nullable=False, default='["VIEWER"]')
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)


class RevokedToken(Base):
    """Logout denylist (Step 20). One row per revoked JWT id."""

    __tablename__ = "revoked_tokens"

    jti: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now()
    )


class AuthAudit(Base):
    """Authentication/authorization lifecycle facts (Step 20, append-only)."""

    __tablename__ = "auth_audits"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    event: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, default=_utcnow_naive
    )
