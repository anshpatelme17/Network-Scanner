"""Live event-connector endpoints (Steps 26–28).

Read endpoints report server-evaluated connector truth (mode/state,
Step 27 connector_state + runtime health, presence-only configuration,
ephemeral last-success stamp) and never perform network I/O. The check
endpoint runs one audited connectivity check through the shared client
layer (RBAC ``MANAGE_EVENTS``). The poll endpoint runs the Step 28
bounded ingestion pipeline — operator-configured local file for file
sources, allow-listed paginated API retrieval for Wazuh/Defender — with
bounded queue, bounded batches, transient retry, and checkpoint
advancement (Step 28). No endpoint accepts commands, paths, URLs,
credentials, or adapter selections; unknown sources are rejected, and a
failed poll returns a structured 422 without ever advancing a
checkpoint.
"""

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.v1.auth_deps import actor_for, require_permission
from app.api.v1.limits import rate_limit
from app.core.errors import error_response
from app.database.session import get_db
from app.schemas.connectors import ConnectorsPage, ConnectorStatusResponse, PollResult
from app.services import connector_polling, connectors, ingestion
from app.services.auth_service import AuthContext

router = APIRouter(prefix="/events/connectors", tags=["connectors"])


def _to_status(status_obj: connectors.ConnectorStatus) -> dict:
    return {
        "source": status_obj.source,
        "mode": status_obj.mode,
        "state": status_obj.state,
        "detail": status_obj.detail,
        "configured": dict(status_obj.configured),
        "last_success_at": status_obj.last_success_at,
        "connector_state": status_obj.connector_state,
        "last_check_at": status_obj.last_check_at,
        "last_poll_at": status_obj.last_poll_at,
        "last_error_category": status_obj.last_error_category,
        "events_retrieved": status_obj.events_retrieved,
        "latency_ms": status_obj.latency_ms,
        # Phase 2 Step 5: safe polling metadata (no secrets by construction).
        "polling": connector_polling.health_for(status_obj.source).as_dict(),
    }


def _unknown_source(source: str):
    return error_response(
        "UNKNOWN_CONNECTOR",
        f"Unknown connector source: {source!r}.",
        status.HTTP_422_UNPROCESSABLE_ENTITY,
    )


@router.get("", response_model=ConnectorsPage, summary="List event connectors")
def list_connectors(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_EVENTS")),
):
    return {"items": [_to_status(item) for item in connectors.describe_all()]}


@router.get(
    "/{source}", response_model=ConnectorStatusResponse, summary="Connector status and health"
)
def connector_status(
    source: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_EVENTS")),
):
    try:
        return _to_status(connectors.health(source))
    except KeyError:
        return _unknown_source(source)


@router.post(
    "/{source}/check",
    response_model=ConnectorStatusResponse,
    summary="Run one audited connector connectivity check",
)
def check_connector(
    source: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("MANAGE_EVENTS")),
):
    try:
        return _to_status(connectors.check_connector(db, source, actor_for(auth, None)))
    except KeyError:
        return _unknown_source(source)


@router.post(
    "/{source}/poll",
    response_model=PollResult,
    summary="Poll a configured connector through the bounded ingestion pipeline",
)
def poll_connector(
    source: str,
    replay: bool = Query(
        default=False,
        description="Re-run the same bounded, audited pipeline for this source.",
    ),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("MANAGE_EVENTS")),
    _limit: None = Depends(rate_limit("connector_poll", "rate_limit_connector_poll")),
):
    if source not in connectors.SOURCES:
        return _unknown_source(source)
    try:
        # Phase 2 Step 5: the same bounded pipeline, now with overlap
        # prevention and a failure cool-down. Manual "Poll Now" is unchanged
        # for the operator - it just cannot overlap or hammer a source.
        return connector_polling.poll_connector(db, source, actor_for(auth, None), replay=replay)
    except connector_polling.PollInProgress as exc:
        return error_response("POLL_IN_PROGRESS", str(exc), status.HTTP_409_CONFLICT)
    except connector_polling.PollCooldown as exc:
        return error_response(
            "POLL_COOLDOWN",
            str(exc),
            status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(max(1, int(exc.retry_after_seconds)))},
        )
    except ingestion.IngestionFailedError as exc:
        return error_response("INGESTION_FAILED", str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY)
    except connectors.ConnectorUnavailableError as exc:
        return error_response(
            "CONNECTOR_UNAVAILABLE", str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY
        )
