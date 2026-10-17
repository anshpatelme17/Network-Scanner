"""Read-only response audit history (Step 42A, v2).

A single per-action audit feed. It exposes the stored lifecycle audit
rows for one controlled ``ResponseAction`` — nothing more. The endpoint
is deliberately read-only: it performs no state transition, never calls
``response_governance.expire_due()``, and writes no audit row of its
own. There is no global or cross-action feed here, and no mutation
surface of any kind.
"""

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.v1.auth_deps import require_permission
from app.core.errors import error_response
from app.database.session import get_db
from app.models.responses import ResponseAction, ResponseAudit
from app.schemas.responses import AuditEntry, ResponseAuditPage
from app.services.auth_service import AuthContext

router = APIRouter(prefix="/responses", tags=["responses"])

MAX_LIMIT = 200


@router.get(
    "/{action_id}/audit",
    response_model=ResponseAuditPage,
    summary="Read-only audit history for a response action (v2)",
)
def get_response_audit(
    action_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_RESPONSES")),
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
):
    """Chronological audit rows for one action, bounded by pagination.

    Only rows whose ``action_id`` equals the requested id are returned,
    so one action's history can never include another's. The stored
    not-found convention (``RESPONSE_NOT_FOUND``) is reused unchanged.
    ``detail`` is the stored optional rationale and is non-null only for
    a rejection; execute, approval and cancellation entries carry none.
    Reading executes no INSERT/UPDATE/DELETE and no governance
    transition.
    """
    row = db.scalar(select(ResponseAction).where(ResponseAction.id == action_id))
    if row is None:
        return error_response(
            "RESPONSE_NOT_FOUND",
            f"No response proposal with id {action_id}.",
            status.HTTP_404_NOT_FOUND,
        )
    total = (
        db.scalar(
            select(func.count(ResponseAudit.id)).where(ResponseAudit.action_id == action_id)
        )
        or 0
    )
    rows = db.scalars(
        select(ResponseAudit)
        .where(ResponseAudit.action_id == action_id)
        .order_by(ResponseAudit.created_at, ResponseAudit.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return {
        "action_id": row.id,
        "incident_id": row.incident_id,
        "entries": [AuditEntry.model_validate(entry) for entry in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
        "truncated": offset + len(rows) < total,
    }
