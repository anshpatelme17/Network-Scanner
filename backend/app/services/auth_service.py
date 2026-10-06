"""Authentication, RBAC, and authorization service (Step 20).

Identity: ``User`` rows with Argon2id password hashes (never raw
passwords, never logged). Sessions are short-lived JWTs (HS256, signed
with the deployment ``secret_key``) carrying sub/username/roles/jti/
iat/exp; validation checks signature, expiry, user existence +
activeness, and the logout denylist. No plaintext secrets anywhere;
configuration comes from the environment.

Permissions derive deterministically from roles via
``ROLE_PERMISSIONS`` — they are never stored per row, so role meaning
cannot drift. There is deliberately NO ``EXECUTE_ARBITRARY_COMMAND``
permission and no path from any permission to command execution,
external control changes, or autonomous behavior; the Step 18/19
safe/simulation workflow is the only execution capability and keeps
its own policy gates.

Enforcement activates once at least one user exists. With an empty
user table the API runs in documented bootstrap mode (legacy open
access, ``enforcement=False``) so the first ADMIN can be created;
``REQUIRE_AUTH=true`` disables bootstrap entirely. Bootstrap mode
preserves every Step 1–19 behavior and test unchanged.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.auth import AuthAudit, RevokedToken, User

logger = get_logger(__name__)

# Roles (closed vocabulary; stored on User.roles as a JSON list).
ROLE_ADMIN = "ADMIN"
ROLE_SECURITY_ANALYST = "SECURITY_ANALYST"
ROLE_OPERATOR = "OPERATOR"
ROLE_VIEWER = "VIEWER"
ROLES = (ROLE_ADMIN, ROLE_SECURITY_ANALYST, ROLE_OPERATOR, ROLE_VIEWER)

# Permissions (closed vocabulary; derived, never stored).
PERM_READ_ASSETS = "READ_ASSETS"
PERM_READ_EVENTS = "READ_EVENTS"
PERM_READ_VULNERABILITIES = "READ_VULNERABILITIES"
PERM_READ_INCIDENTS = "READ_INCIDENTS"
PERM_READ_RESPONSES = "READ_RESPONSES"
PERM_RUN_ANALYSIS = "RUN_ANALYSIS"
PERM_CREATE_INCIDENT = "CREATE_INCIDENT"
PERM_MANAGE_INCIDENT = "MANAGE_INCIDENT"
PERM_PROPOSE_RESPONSE = "PROPOSE_RESPONSE"
PERM_APPROVE_RESPONSE = "APPROVE_RESPONSE"
PERM_EXECUTE_SAFE_RESPONSE = "EXECUTE_SAFE_RESPONSE"
# Step 30: the controlled defensive-response ladder. Separation of duties
# is enforced by the ROLE_PERMISSIONS mapping below, not by a setting:
# REQUEST/CANCEL are analyst-level, while APPROVE/EXECUTE/ROLLBACK are
# operator-level so a requester cannot approve their own consequential
# request through roles alone. There is deliberately still NO permission
# that grants command execution, arbitrary provider selection, or an
# unrestricted firewall/account/endpoint action.
PERM_REQUEST_RESPONSE = "REQUEST_RESPONSE"
PERM_CANCEL_RESPONSE = "CANCEL_RESPONSE"
PERM_EXECUTE_RESPONSE = "EXECUTE_RESPONSE"
PERM_ROLLBACK_RESPONSE = "ROLLBACK_RESPONSE"
PERM_VIEW_AUDIT = "VIEW_AUDIT"
PERM_MANAGE_ASSETS = "MANAGE_ASSETS"
PERM_MANAGE_EVENTS = "MANAGE_EVENTS"
PERM_MANAGE_SCANS = "MANAGE_SCANS"
PERM_MANAGE_VULNERABILITIES = "MANAGE_VULNERABILITIES"
PERM_MANAGE_USERS = "MANAGE_USERS"
PERM_MANAGE_ROLES = "MANAGE_ROLES"
PERM_MANAGE_SETTINGS = "MANAGE_SETTINGS"
PERMISSIONS = (
    PERM_READ_ASSETS,
    PERM_READ_EVENTS,
    PERM_READ_VULNERABILITIES,
    PERM_READ_INCIDENTS,
    PERM_READ_RESPONSES,
    PERM_RUN_ANALYSIS,
    PERM_CREATE_INCIDENT,
    PERM_MANAGE_INCIDENT,
    PERM_PROPOSE_RESPONSE,
    PERM_APPROVE_RESPONSE,
    PERM_EXECUTE_SAFE_RESPONSE,
    PERM_REQUEST_RESPONSE,
    PERM_CANCEL_RESPONSE,
    PERM_EXECUTE_RESPONSE,
    PERM_ROLLBACK_RESPONSE,
    PERM_VIEW_AUDIT,
    PERM_MANAGE_ASSETS,
    PERM_MANAGE_EVENTS,
    PERM_MANAGE_SCANS,
    PERM_MANAGE_VULNERABILITIES,
    PERM_MANAGE_USERS,
    PERM_MANAGE_ROLES,
    PERM_MANAGE_SETTINGS,
)

_READ_ALL = (
    PERM_READ_ASSETS,
    PERM_READ_EVENTS,
    PERM_READ_VULNERABILITIES,
    PERM_READ_INCIDENTS,
    PERM_READ_RESPONSES,
)
_MANAGE_CONTENT = (
    PERM_RUN_ANALYSIS,
    PERM_CREATE_INCIDENT,
    PERM_MANAGE_INCIDENT,
    PERM_PROPOSE_RESPONSE,
    # Step 30: an analyst may raise a controlled response and withdraw
    # it, but may not approve, execute, or roll it back.
    PERM_REQUEST_RESPONSE,
    PERM_CANCEL_RESPONSE,
    PERM_VIEW_AUDIT,
    PERM_MANAGE_ASSETS,
    PERM_MANAGE_EVENTS,
    PERM_MANAGE_SCANS,
    PERM_MANAGE_VULNERABILITIES,
)
# Step 30: operator-only capabilities. Kept out of _MANAGE_CONTENT so the
# request/approve separation of duties is a property of the role map.
_RESPONSE_EXECUTION = (
    PERM_APPROVE_RESPONSE,
    PERM_EXECUTE_SAFE_RESPONSE,
    PERM_EXECUTE_RESPONSE,
    PERM_ROLLBACK_RESPONSE,
)

# Centralized, deterministic role -> permission mapping.
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    ROLE_VIEWER: frozenset(_READ_ALL),
    ROLE_SECURITY_ANALYST: frozenset(_READ_ALL + _MANAGE_CONTENT),
    ROLE_OPERATOR: frozenset(_READ_ALL + _MANAGE_CONTENT + _RESPONSE_EXECUTION),
    ROLE_ADMIN: frozenset(PERMISSIONS),
}

JWT_ALGORITHM = "HS256"

# Auth audit events (Step 20, append-only, never contain secrets).
AUDIT_LOGIN_SUCCESS = "LOGIN_SUCCESS"
AUDIT_LOGIN_FAILURE = "LOGIN_FAILURE"
AUDIT_LOGOUT = "LOGOUT"
AUDIT_AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
AUDIT_PERMISSION_DENIED = "PERMISSION_DENIED"
AUDIT_USER_CREATED = "USER_CREATED"
AUDIT_USER_DISABLED = "USER_DISABLED"
AUDIT_ROLE_CHANGED = "ROLE_CHANGED"

MIN_PASSWORD_LENGTH = 12


class AuthError(Exception):
    """Invalid/missing credentials or token (maps to 401)."""


class ForbiddenError(Exception):
    """Authenticated but not permitted (maps to 403)."""


_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Argon2id hash. Raises AuthError on policy violation (never logs input)."""
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise AuthError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Constant-shape boolean check (no timing oracle beyond argon2 itself)."""
    try:
        return _hasher.verify(password_hash, password or "")
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def normalize_username(username: str) -> str:
    return (username or "").strip().lower()


def parse_roles(raw: str | list[str]) -> list[str]:
    """Validate a role list; raises AuthError on unknown roles."""
    roles = json.loads(raw) if isinstance(raw, str) else list(raw)
    if not isinstance(roles, list) or not roles:
        raise AuthError("At least one role is required.")
    cleaned = []
    for role in roles:
        if role not in ROLES:
            raise AuthError(f"Unknown role: {role!r}.")
        if role not in cleaned:
            cleaned.append(role)
    return cleaned


def permissions_for_roles(roles: list[str]) -> frozenset[str]:
    """Deterministic union of role permissions."""
    granted: set[str] = set()
    for role in roles:
        granted |= set(ROLE_PERMISSIONS.get(role, frozenset()))
    return frozenset(granted)


def _utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def record_auth_audit(
    db: Session,
    event: str,
    user_id: str | None,
    username: str | None,
    detail: str | None = None,
) -> None:
    """Append one auth audit row. Never called with secrets."""
    db.add(AuthAudit(user_id=user_id, username=username, event=event, detail=detail))


def user_count(db: Session) -> int:
    return db.scalar(select(func.count(User.id))) or 0


def enforcement_active(db: Session) -> bool:
    """True once any user exists, or when bootstrap mode is disabled."""
    if get_settings().require_auth:
        return True
    return user_count(db) > 0


def create_token(user: User, roles: list[str]) -> tuple[str, str]:
    """Mint a short-lived access JWT. Returns (token, jti)."""
    settings = get_settings()
    now = datetime.now(UTC)
    jti = str(uuid.uuid4())
    payload = {
        "sub": user.id,
        "username": user.username,
        "roles": roles,
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.access_token_minutes)).timestamp()),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=JWT_ALGORITHM), jti


def decode_token(token: str) -> dict:
    """Verify signature + expiry. Raises AuthError (never leaks why beyond invalid)."""
    try:
        return jwt.decode(token, get_settings().secret_key, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise AuthError("Access token has expired.") from None
    except jwt.InvalidTokenError:
        raise AuthError("Access token is invalid.") from None


def authenticate(db: Session, username: str, password: str) -> User | None:
    """Validate credentials. Returns the user or None (no reason given out)."""
    row = db.scalar(select(User).where(User.username == normalize_username(username)))
    if row is None or not row.is_active:
        return None
    if not verify_password(row.password_hash, password):
        return None
    return row


@dataclass(frozen=True)
class AuthContext:
    """Who is calling, resolved server-side (Step 20)."""

    authenticated: bool
    enforcement: bool
    username: str
    user_id: str | None
    roles: tuple[str, ...]
    permissions: frozenset[str]


def legacy_context() -> AuthContext:
    """Bootstrap-mode identity: legacy open access, no permissions asserted."""
    return AuthContext(
        authenticated=False,
        enforcement=False,
        username="operator",
        user_id=None,
        roles=(),
        permissions=frozenset(),
    )


def resolve_context(db: Session, authorization: str | None) -> AuthContext:
    """Resolve the caller from the Authorization header (server-side only).

    Raises AuthError (401) for missing/invalid tokens when enforcement
    is active. Never trusts client-provided roles, ids, or headers.
    """
    if not enforcement_active(db):
        return legacy_context()
    if not authorization or not authorization.lower().startswith("bearer "):
        raise AuthError("Authentication is required.")
    claims = decode_token(authorization[7:].strip())
    jti = claims.get("jti", "")
    if jti and db.scalar(select(RevokedToken).where(RevokedToken.jti == jti)) is not None:
        raise AuthError("Access token has been revoked.")
    user = db.scalar(select(User).where(User.id == claims.get("sub", "")))
    if user is None or not user.is_active:
        raise AuthError("Access token is invalid.")
    roles = parse_roles(user.roles)
    return AuthContext(
        authenticated=True,
        enforcement=True,
        username=user.username,
        user_id=user.id,
        roles=tuple(roles),
        permissions=permissions_for_roles(roles),
    )


__all__ = [
    "AUDIT_AUTHORIZATION_DENIED",
    "AUDIT_LOGIN_FAILURE",
    "AUDIT_LOGIN_SUCCESS",
    "AUDIT_LOGOUT",
    "AUDIT_PERMISSION_DENIED",
    "AUDIT_ROLE_CHANGED",
    "AUDIT_USER_CREATED",
    "AUDIT_USER_DISABLED",
    "JWT_ALGORITHM",
    "MIN_PASSWORD_LENGTH",
    "PERMISSIONS",
    "ROLES",
    "ROLE_PERMISSIONS",
    "AuthContext",
    "AuthError",
    "ForbiddenError",
    "authenticate",
    "create_token",
    "decode_token",
    "enforcement_active",
    "hash_password",
    "legacy_context",
    "normalize_username",
    "parse_roles",
    "permissions_for_roles",
    "record_auth_audit",
    "resolve_context",
    "user_count",
    "verify_password",
]
