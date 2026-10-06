"""FastAPI authorization dependencies (Step 20).

``require_permission(PERM)`` is a dependency factory: it resolves the
caller server-side (never from client claims) and enforces one
permission, raising into the project error envelope (401
missing/invalid auth, 403 insufficient permission) with audit rows. In
bootstrap mode (no users yet, ``REQUIRE_AUTH`` unset) every check
passes through as the legacy context, preserving Steps 1–19 behavior
exactly.

``actor_for(context, fallback)`` selects the audit identity: the
authenticated username when enforced, otherwise the legacy operator
label supplied by the caller.
"""

from __future__ import annotations

from fastapi import Depends, Header, Request, status
from sqlalchemy.orm import Session

from app.core.errors import AuthHTTPException
from app.database.session import get_db
from app.services import auth_service
from app.services.auth_service import (
    AUDIT_AUTHORIZATION_DENIED,
    AUDIT_PERMISSION_DENIED,
    AuthContext,
    AuthError,
)


def actor_for(context: AuthContext, fallback: str | None = None) -> str:
    """Audit/approval identity: token user when enforced, else caller label."""
    if context.enforcement and context.authenticated:
        return context.username
    return (fallback or "operator")[:128]


def _resolve(
    db: Session,
    permission: str | None,
    authorization: str | None,
    request: Request | None = None,
) -> AuthContext:
    try:
        context = auth_service.resolve_context(db, authorization)
    except AuthError as exc:
        auth_service.record_auth_audit(db, AUDIT_AUTHORIZATION_DENIED, None, None, str(exc))
        db.commit()
        raise AuthHTTPException(
            "AUTH_REQUIRED", "Authentication is required.", status.HTTP_401_UNAUTHORIZED
        ) from exc
    if context.enforcement and permission is not None and permission not in context.permissions:
        auth_service.record_auth_audit(
            db,
            AUDIT_PERMISSION_DENIED,
            context.user_id,
            context.username,
            f"Missing permission: {permission}.",
        )
        db.commit()
        raise AuthHTTPException(
            "PERMISSION_DENIED",
            f"Permission is required: {permission}.",
            status.HTTP_403_FORBIDDEN,
        )
    if request is not None:
        # Step 31: publish the resolved identity on the request so
        # cross-cutting concerns (rate-limit budgeting) can attribute a
        # call without re-parsing the token. The server still makes every
        # authorization decision from this object, not from the request.
        request.state.auth = context
    return context


def require_permission(permission: str):
    """Dependency factory enforcing one permission (server-side)."""

    def _dependency(
        request: Request,
        db: Session = Depends(get_db),
        authorization: str | None = Header(default=None),
    ) -> AuthContext:
        return _resolve(db, permission, authorization, request)

    return _dependency


def require_authenticated(
    request: Request,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
) -> AuthContext:
    """Any valid authenticated user (bootstrap mode passes through)."""
    return _resolve(db, None, authorization, request)


__all__ = ["actor_for", "require_authenticated", "require_permission"]
