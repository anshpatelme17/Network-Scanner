"""Vulnerability finding ingestion endpoints (Step 8).

Same shape as the other ingest endpoints: adapt each record via
``vulnerability_adapter`` and feed the existing ``event_service``
pipeline — the same validation, normalization, idempotency, and
storage. No scanners are executed here; records are data only.
"""

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session

from app.api.v1.auth_deps import require_permission
from app.api.v1.endpoints.events import _to_response
from app.core.errors import error_response
from app.database.session import get_db
from app.schemas.events import EventResponse
from app.schemas.suricata import BatchItemError
from app.schemas.vulnerability import (
    VulnerabilityBatchRequest,
    VulnerabilityBatchResponse,
    VulnerabilityIngestRequest,
)
from app.services import event_service
from app.services.auth_service import AuthContext
from app.services.vulnerability_adapter import (
    VulnerabilityAdapterError,
    adapt_vulnerability_finding,
)

router = APIRouter(prefix="/events/ingest/vulnerabilities", tags=["ingest"])


def _ingest_one(db: Session, record: object, source_name: str):
    """Adapt + store one finding. Returns (response_dict, created)."""
    envelope = adapt_vulnerability_finding(record, source_name)
    attributes = event_service.normalize_event(envelope)
    event, created = event_service.store_event(db, attributes)
    return _to_response(event), created


@router.post(
    "", response_model=EventResponse, status_code=status.HTTP_201_CREATED, summary="Ingest finding"
)
def ingest_vulnerability(
    payload: VulnerabilityIngestRequest,
    response: Response,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("MANAGE_VULNERABILITIES")),
):
    try:
        body, created = _ingest_one(db, payload.event, payload.source_name)
    except VulnerabilityAdapterError as exc:
        return error_response(
            "INVALID_VULNERABILITY", str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY
        )
    except event_service.PayloadTooLargeError as exc:
        return error_response(
            "PAYLOAD_TOO_LARGE", str(exc), status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
        )
    if not created:
        response.status_code = status.HTTP_200_OK
    return body


@router.post(
    "/batch",
    response_model=VulnerabilityBatchResponse,
    summary="Ingest up to 100 findings (partial failures tolerated)",
)
def ingest_vulnerability_batch(
    payload: VulnerabilityBatchRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("MANAGE_VULNERABILITIES")),
):
    accepted = 0
    duplicates = 0
    errors: list[BatchItemError] = []
    bodies: list[dict] = []
    for index, record in enumerate(payload.events):
        try:
            body, created = _ingest_one(db, record, payload.source_name)
        except VulnerabilityAdapterError as exc:
            errors.append(
                BatchItemError(index=index, code="INVALID_VULNERABILITY", message=str(exc))
            )
            continue
        except event_service.PayloadTooLargeError as exc:
            errors.append(BatchItemError(index=index, code="PAYLOAD_TOO_LARGE", message=str(exc)))
            continue
        except Exception:  # noqa: BLE001 - one bad finding must not crash the batch
            errors.append(
                BatchItemError(
                    index=index, code="INGEST_FAILED", message="Finding could not be stored."
                )
            )
            continue
        if created:
            accepted += 1
        else:
            duplicates += 1
        bodies.append(body)
    return VulnerabilityBatchResponse(
        accepted=accepted,
        duplicates=duplicates,
        rejected=len(errors),
        errors=errors,
        items=[EventResponse(**body) for body in bodies],
    )
