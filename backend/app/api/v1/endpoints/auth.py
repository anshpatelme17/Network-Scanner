"""Authentication endpoints (Step 20).

Login validates credentials against Argon2id hashes, rejects inactive
users with the same generic message as bad credentials (no username
enumeration), updates ``last_login_at`` only on success, and returns a
short-lived JWT. ``/me`` returns the token's safe identity (never
hashes or tokens). ``/logout`` revokes the presenting token via the
server-side denylist and audits the event. No username-only auth, no
client-provided roles/ids, no user selection via query params.
"""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Header, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.v1.auth_deps import actor_for, require_authenticated, require_permission
from app.core.config import get_settings
from app.core.errors import error_response
from app.core.ratelimit import enforce_rate_limit
from app.database.session import get_db
from app.models.auth import AuthAudit, RevokedToken
from app.schemas.auth import LoginRequest, TokenResponse, UserResponse
from app.services import auth_service
from app.services.auth_service import (
    AUDIT_LOGIN_FAILURE,
    AUDIT_LOGIN_SUCCESS,
    AUDIT_LOGOUT,
    AuthContext,
)

router = APIRouter(prefix="/auth", tags=["auth"])

_GENERIC_FAILURE = "Invalid username or password."


def _to_user_response(user, permissions) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "is_active": user.is_active,
        "roles": auth_service.parse_roles(user.roles),
        "permissions": sorted(permissions),
        "created_at": user.created_at,
        "updated_at": user.updated_at,
        "last_login_at": user.last_login_at,
    }


@router.post("/login", response_model=TokenResponse, summary="Log in")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Exchange credentials for a token.

    Failed attempts are budgeted by ``RATE_LIMIT_LOGIN_FAILURES`` (Step
    32). The check sits in the failure branch rather than in a dependency
    list because only the handler knows the attempt failed: counting
    *attempts* would throttle a correct password and lock out legitimate
    operators and services, which is an availability risk rather than a
    security gain. The budget is keyed by caller, and since there is no
    token yet it is the client host — see ``app/core/ratelimit.py``.

    Ordering is deliberate: the failure is audited and committed *before*
    the budget is charged, so a throttled attempt is still recorded and a
    later 429 never hides the evidence of the guessing that caused it.
    """
    user = auth_service.authenticate(db, payload.username, payload.password)
    if user is None:
        # Generic message: no signal for username vs password vs inactive.
        auth_service.record_auth_audit(
            db,
            AUDIT_LOGIN_FAILURE,
            None,
            auth_service.normalize_username(payload.username),
            "Credential validation failed.",
        )
        db.commit()
        enforce_rate_limit(
            request,
            "auth_login_failure",
            request.app.state.settings.rate_limit_login_failures,
        )
        return error_response("INVALID_CREDENTIALS", _GENERIC_FAILURE, status.HTTP_401_UNAUTHORIZED)
    roles = auth_service.parse_roles(user.roles)
    token, _jti = auth_service.create_token(user, roles)
    user.last_login_at = datetime.now(UTC).replace(tzinfo=None)
    auth_service.record_auth_audit(
        db, AUDIT_LOGIN_SUCCESS, user.id, user.username, "Login succeeded."
    )
    db.commit()
    db.refresh(user)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in_minutes": get_settings().access_token_minutes,
    }


@router.get("/me", response_model=UserResponse, summary="Current identity")
def me(auth: AuthContext = Depends(require_authenticated), db: Session = Depends(get_db)):
    if not auth.enforcement:
        return error_response(
            "NO_IDENTITY",
            "No users exist yet; create the first ADMIN user first.",
            status.HTTP_404_NOT_FOUND,
        )
    from app.models.auth import User

    user = db.scalar(select(User).where(User.id == auth.user_id))
    if user is None:
        return error_response("NOT_FOUND", "User no longer exists.", status.HTTP_404_NOT_FOUND)
    return _to_user_response(user, auth.permissions)


@router.post("/logout", summary="Log out")
def logout(
    auth: AuthContext = Depends(require_authenticated),
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
):
    if auth.enforcement and authorization:
        try:
            claims = auth_service.decode_token(authorization[7:].strip())
        except auth_service.AuthError:
            claims = {}
        jti = (claims or {}).get("jti", "")
        if jti and db.scalar(select(RevokedToken).where(RevokedToken.jti == jti)) is None:
            db.add(RevokedToken(jti=jti, user_id=auth.user_id or ""))
        auth_service.record_auth_audit(db, AUDIT_LOGOUT, auth.user_id, auth.username, "Logout.")
        db.commit()
    return {"logged_out": True, "actor": actor_for(auth, None)}


@router.get("/audit", summary="Authentication audit trail")
def auth_audit(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("VIEW_AUDIT")),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    """Read authentication/authorization audit events (Step 20).

    Rows never contain passwords, hashes, or tokens by construction.
    """
    rows = db.scalars(
        select(AuthAudit)
        .order_by(AuthAudit.created_at.desc(), AuthAudit.id)
        .limit(limit)
        .offset(offset)
    ).all()
    total = db.scalar(select(func.count(AuthAudit.id))) or 0
    return {
        "items": [
            {
                "id": row.id,
                "user_id": row.user_id,
                "username": row.username,
                "event": row.event,
                "detail": row.detail,
                "created_at": row.created_at,
            }
            for row in rows
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }
