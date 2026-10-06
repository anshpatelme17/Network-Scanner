"""Zeek ingestion endpoints (Steps 5 + 23).

Same shape as the Suricata endpoints: resolve the FIXTURE adapter from
the static server-side registry and feed the shared ``event_service``
pipeline — the same validation, normalization, asset correlation,
idempotency, audit, and storage. No vendor logic lives here beyond the
registry key, and no live sensor is ever contacted.
"""

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session

from app.api.v1.auth_deps import actor_for, require_permission
from app.api.v1.endpoints.events import _to_response
from app.core.errors import error_response
from app.database.session import get_db
from app.schemas.events import EventResponse
from app.schemas.suricata import BatchItemError
from app.schemas.zeek import ZeekBatchRequest, ZeekBatchResponse, ZeekIngestRequest
from app.services import event_service
from app.services.auth_service import AuthContext
from app.services.event_adapters import resolve_adapter

router = APIRouter(prefix="/events/ingest/zeek", tags=["ingest"])

_REGISTRATION = resolve_adapter("zeek")


def _ingest_one(db: Session, record: object, source_name: str, actor: str):
    """Adapt + store one Zeek record. Returns (response_dict, created)."""
    event, created = event_service.ingest_via_adapter(db, _REGISTRATION, record, source_name, actor)
    return _to_response(event), created


@router.post(
    "",
    response_model=EventResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest Zeek event",
)
def ingest_zeek(
    payload: ZeekIngestRequest,
    response: Response,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("MANAGE_EVENTS")),
):
    try:
        body, created = _ingest_one(db, payload.event, payload.source_name, actor_for(auth, None))
    except _REGISTRATION.error as exc:
        return error_response("INVALID_ZEEK", str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY)
    except event_service.PayloadTooLargeError as exc:
        return error_response(
            "PAYLOAD_TOO_LARGE", str(exc), status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
        )
    if not created:
        response.status_code = status.HTTP_200_OK
    return body


@router.post(
    "/batch",
    response_model=ZeekBatchResponse,
    summary="Ingest up to 100 Zeek events (partial failures tolerated)",
)
def ingest_zeek_batch(
    payload: ZeekBatchRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("MANAGE_EVENTS")),
):
    accepted = 0
    duplicates = 0
    errors: list[BatchItemError] = []
    bodies: list[dict] = []
    actor = actor_for(auth, None)
    for index, record in enumerate(payload.events):
        try:
            body, created = _ingest_one(db, record, payload.source_name, actor)
        except _REGISTRATION.error as exc:
            errors.append(BatchItemError(index=index, code="INVALID_ZEEK", message=str(exc)))
            continue
        except event_service.PayloadTooLargeError as exc:
            errors.append(BatchItemError(index=index, code="PAYLOAD_TOO_LARGE", message=str(exc)))
            continue
        except Exception:  # noqa: BLE001 - one bad event must not crash the batch
            errors.append(
                BatchItemError(
                    index=index, code="INGEST_FAILED", message="Event could not be stored."
                )
            )
            continue
        if created:
            accepted += 1
        else:
            duplicates += 1
        bodies.append(body)
    return ZeekBatchResponse(
        accepted=accepted,
        duplicates=duplicates,
        rejected=len(errors),
        errors=errors,
        items=[EventResponse(**body) for body in bodies],
    )
