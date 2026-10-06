"""Risk query endpoints (Step 10, analysis only).

Read-only views over deterministically computed risk assessments, plus
one bounded, parameter-free recompute trigger. Scores describe stored
evidence; nothing here acts on any host.
"""

import json

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.api.v1.auth_deps import actor_for, require_permission
from app.api.v1.limits import rate_limit
from app.core.errors import error_response
from app.database.session import get_db
from app.models.risk import RiskAssessment
from app.schemas.risk import RiskAssessmentResponse, RiskPage, RiskRecomputeResult
from app.services import risk_service
from app.services.auth_service import AuthContext
from app.services.risk_service import ENTITY_TYPES

router = APIRouter(prefix="/risk", tags=["risk"])

MAX_LIMIT = 200


def _to_response(row: RiskAssessment) -> dict:
    factors: dict = {}
    if row.factors:
        try:
            parsed = json.loads(row.factors)
            if isinstance(parsed, dict):
                factors = parsed
        except (ValueError, TypeError):
            factors = {}
    return {
        "id": row.id,
        "entity_type": row.entity_type,
        "entity_id": row.entity_id,
        "score": row.score,
        "severity": row.severity,
        "priority": row.priority or risk_service.priority_for(row.score),
        "factors": factors,
        "explanation": row.explanation,
        "calculated_at": row.calculated_at,
        "scoring_version": row.scoring_version,
    }


@router.get("", response_model=RiskPage, summary="List risk assessments")
def list_risk(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_INCIDENTS")),
    entity_type: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
):
    if entity_type is not None and entity_type not in ENTITY_TYPES:
        return error_response(
            "INVALID_ENTITY_TYPE",
            f"Unknown entity type: {entity_type!r}. Expected one of {list(ENTITY_TYPES)}.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    if severity is not None and severity not in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        return error_response(
            "INVALID_FILTER",
            f"Unknown severity filter: {severity!r}.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    query = select(RiskAssessment)
    count_query = select(func.count(RiskAssessment.id))
    if entity_type is not None:
        query = query.where(RiskAssessment.entity_type == entity_type)
        count_query = count_query.where(RiskAssessment.entity_type == entity_type)
    if severity is not None:
        query = query.where(RiskAssessment.severity == severity)
        count_query = count_query.where(RiskAssessment.severity == severity)
    total = db.scalar(count_query) or 0
    rows = db.scalars(
        query.order_by(desc(RiskAssessment.score), RiskAssessment.id).limit(limit).offset(offset)
    ).all()
    return {
        "items": [_to_response(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get(
    "/{entity_type}/{entity_id}", response_model=RiskAssessmentResponse, summary="Risk detail"
)
def get_risk(
    entity_type: str,
    entity_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_INCIDENTS")),
):
    if entity_type not in ENTITY_TYPES:
        return error_response(
            "INVALID_ENTITY_TYPE",
            f"Unknown entity type: {entity_type!r}. Expected one of {list(ENTITY_TYPES)}.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    row = db.scalar(
        select(RiskAssessment).where(
            RiskAssessment.entity_type == entity_type, RiskAssessment.entity_id == entity_id
        )
    )
    if row is None:
        return error_response(
            "RISK_NOT_FOUND",
            f"No risk assessment for {entity_type} {entity_id}.",
            status.HTTP_404_NOT_FOUND,
        )
    return _to_response(row)


@router.post("/recompute", response_model=RiskRecomputeResult, summary="Recompute risk scores")
def recompute(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("RUN_ANALYSIS")),
    _limit: None = Depends(rate_limit("risk_recompute", "rate_limit_risk_calculate")),
):
    """Bounded, parameter-free, deterministic recompute over stored entities."""
    return risk_service.recompute_risk(db, actor_for(auth, None))


@router.post(
    "/incidents/{incident_id}/calculate",
    response_model=RiskAssessmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Calculate incident risk",
)
async def calculate_incident(
    incident_id: str,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("MANAGE_INCIDENT")),
    _limit: None = Depends(rate_limit("risk_calculate", "rate_limit_risk_calculate")),
):
    """Calculate (or refresh) one incident's advisory risk assessment (Step 25).

    Analysis only: scores stored evidence, upserts the single snapshot
    row idempotently, and audits creations/changes. Accepts no formulas,
    code, or commands — the scoring policy is fixed server-side.
    """
    body = (await request.body()).strip()
    if body not in (b"", b"{}"):
        return error_response(
            "INVALID_REQUEST",
            "Calculate accepts no body: scoring policy is server-side only.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    actor = actor_for(auth, None)
    try:
        row = risk_service.calculate_incident_risk(
            db, incident_id, actor, "Operator-requested incident risk calculation."
        )
    except LookupError:
        return error_response(
            "INCIDENT_NOT_FOUND",
            f"No incident with id {incident_id}.",
            status.HTTP_404_NOT_FOUND,
        )
    return _to_response(row)
