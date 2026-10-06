"""Ingestion observability endpoints (Step 28).

Two read-only, RBAC-gated endpoints that report the bounded pipeline:
overall ingestion status (pipeline stages, configured bounds, queue /
backpressure counters, streaming activation state, per-source counters
with connector truth and checkpoint state) and the stored checkpoints
themselves.

Both endpoints are pure reads: no network call, no filesystem read, no
poll trigger, no client-supplied cursor or path. Configuration is never
presented as connectivity — connector states come from the Step 27 truth
machine (a source is CONNECTED only after a check/poll verified it).
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.v1.auth_deps import require_permission
from app.database.session import get_db
from app.schemas.ingestion import CheckpointPage, IngestionStatusResponse
from app.services import ingestion
from app.services.auth_service import AuthContext

router = APIRouter(prefix="/events/ingestion", tags=["ingestion"])


@router.get(
    "/status",
    response_model=IngestionStatusResponse,
    summary="Bounded ingestion pipeline status (read-only)",
)
def ingestion_status(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_EVENTS")),
):
    return ingestion.status(db)


@router.get(
    "/checkpoints",
    response_model=CheckpointPage,
    summary="Stored ingestion checkpoints (read-only)",
)
def ingestion_checkpoints(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_EVENTS")),
):
    return {"items": ingestion.list_checkpoints(db)}
