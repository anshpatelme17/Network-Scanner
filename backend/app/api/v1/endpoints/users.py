"""User management endpoints (Step 20, ADMIN only after bootstrap).

With an empty user table a single ADMIN may be created without a token
(documented bootstrap); afterwards every operation requires
``MANAGE_USERS``, and changing roles additionally requires
``MANAGE_ROLES``. Disabling or downgrading the last active ADMIN is
refused. All changes are audited (USER_CREATED/USER_DISABLED/
ROLE_CHANGED/USER_UPDATED); audits never contain passwords or tokens.
"""

import json

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.api.v1.auth_deps import actor_for, require_permission
from app.core.errors import error_response
from app.database.session import get_db
from app.models.auth import User
from app.schemas.auth import UserCreate, UserPage, UserResponse, UserUpdate
from app.services import auth_service
from app.services.auth_service import (
    AUDIT_ROLE_CHANGED,
    AUDIT_USER_CREATED,
    AUDIT_USER_DISABLED,
    PERM_MANAGE_ROLES,
    PERM_MANAGE_USERS,
    AuthContext,
    AuthError,
)

router = APIRouter(prefix="/users", tags=["users"])

MAX_LIMIT = 200
AUDIT_USER_UPDATED = "USER_UPDATED"


def _to_response(user: User) -> dict:
    roles = auth_service.parse_roles(user.roles)
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "is_active": user.is_active,
        "roles": roles,
        "permissions": sorted(auth_service.permissions_for_roles(roles)),
        "created_at": user.created_at,
        "updated_at": user.updated_at,
        "last_login_at": user.last_login_at,
    }


def _active_admin_count(db: Session, exclude_id: str | None = None) -> int:
    count = 0
    for row in db.scalars(select(User).where(User.is_active.is_(True))).all():
        try:
            roles = auth_service.parse_roles(row.roles)
        except AuthError:
            continue
        if auth_service.ROLE_ADMIN in roles and row.id != exclude_id:
            count += 1
    return count


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission(PERM_MANAGE_USERS)),
):
    username = auth_service.normalize_username(payload.username)
    if not username or len(username) > 128:
        return error_response(
            "INVALID_USER", "Username is invalid.", status.HTTP_422_UNPROCESSABLE_ENTITY
        )
    if db.scalar(select(User).where(User.username == username)) is not None:
        return error_response("INVALID_USER", "Username is taken.", status.HTTP_409_CONFLICT)
    try:
        roles = auth_service.parse_roles(payload.roles)
        password_hash = auth_service.hash_password(payload.password)
    except AuthError as exc:
        return error_response("INVALID_USER", str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY)
    if not auth.enforcement:
        # Bootstrap: the very first user must be a lone ADMIN.
        if roles != [auth_service.ROLE_ADMIN]:
            return error_response(
                "INVALID_USER",
                "The first user must be created with roles [ADMIN].",
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        actor = "bootstrap"
    else:
        actor = actor_for(auth, None)
    user = User(
        username=username,
        password_hash=password_hash,
        display_name=payload.display_name.strip(),
        is_active=True,
        roles=json.dumps(roles),
    )
    db.add(user)
    db.flush()
    auth_service.record_auth_audit(
        db, AUDIT_USER_CREATED, user.id, username, f"Created by {actor} with roles {roles}."
    )
    db.commit()
    db.refresh(user)
    return _to_response(user)


@router.get("", response_model=UserPage)
def list_users(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission(PERM_MANAGE_USERS)),
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
):
    total = db.scalar(select(func.count(User.id))) or 0
    rows = db.scalars(
        select(User).order_by(desc(User.created_at), User.id).limit(limit).offset(offset)
    ).all()
    return {
        "items": [_to_response(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{user_id}", response_model=UserResponse)
def get_user(
    user_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission(PERM_MANAGE_USERS)),
):
    row = db.scalar(select(User).where(User.id == user_id))
    if row is None:
        return error_response(
            "USER_NOT_FOUND", f"No user with id {user_id}.", status.HTTP_404_NOT_FOUND
        )
    return _to_response(row)


@router.patch("/{user_id}", response_model=UserResponse)
def update_user(
    payload: UserUpdate,
    user_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission(PERM_MANAGE_USERS)),
):
    row = db.scalar(select(User).where(User.id == user_id))
    if row is None:
        return error_response(
            "USER_NOT_FOUND", f"No user with id {user_id}.", status.HTTP_404_NOT_FOUND
        )
    actor = actor_for(auth, None)
    if payload.roles is not None:
        if PERM_MANAGE_ROLES not in auth.permissions:
            auth_service.record_auth_audit(
                db,
                auth_service.AUDIT_PERMISSION_DENIED,
                auth.user_id,
                auth.username,
                "Missing permission: MANAGE_ROLES.",
            )
            db.commit()
            return error_response(
                "PERMISSION_DENIED",
                "Permission is required: MANAGE_ROLES.",
                status.HTTP_403_FORBIDDEN,
            )
        try:
            roles = auth_service.parse_roles(payload.roles)
        except AuthError as exc:
            return error_response("INVALID_USER", str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY)
        if auth_service.ROLE_ADMIN not in roles and _active_admin_count(db, exclude_id=row.id) == 0:
            try:
                current = auth_service.parse_roles(row.roles)
            except AuthError:
                current = []
            if auth_service.ROLE_ADMIN in current:
                return error_response(
                    "INVALID_USER",
                    "Refusing to remove the last active ADMIN role.",
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                )
        row.roles = json.dumps(roles)
        auth_service.record_auth_audit(
            db, AUDIT_ROLE_CHANGED, row.id, row.username, f"Roles set to {roles} by {actor}."
        )
    if payload.display_name is not None:
        row.display_name = payload.display_name.strip()
    if payload.password is not None:
        try:
            row.password_hash = auth_service.hash_password(payload.password)
        except AuthError as exc:
            return error_response("INVALID_USER", str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY)
        auth_service.record_auth_audit(
            db, AUDIT_USER_UPDATED, row.id, row.username, f"Password rotated by {actor}."
        )
    if payload.is_active is not None and payload.is_active != row.is_active:
        if payload.is_active is False and _active_admin_count(db, exclude_id=row.id) == 0:
            try:
                current = auth_service.parse_roles(row.roles)
            except AuthError:
                current = []
            if auth_service.ROLE_ADMIN in current:
                return error_response(
                    "INVALID_USER",
                    "Refusing to disable the last active ADMIN.",
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                )
        row.is_active = payload.is_active
        auth_service.record_auth_audit(
            db,
            AUDIT_USER_DISABLED if payload.is_active is False else AUDIT_USER_UPDATED,
            row.id,
            row.username,
            f"Active set to {payload.is_active} by {actor}.",
        )
    db.commit()
    db.refresh(row)
    return _to_response(row)
