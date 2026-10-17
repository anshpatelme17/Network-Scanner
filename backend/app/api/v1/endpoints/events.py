"""Security event ingestion endpoints (Steps 3 + 23, generic only).

No vendor adapters live here — this API accepts the vendor-neutral
envelope, normalizes it, correlates inventory, and stores it. All
ingestion is operator-submitted data (FIXTURE grade: no live sensor
connections exist); source-specific adapters submit through this same
pipeline via the static ``event_adapters`` registry.
"""

import json
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.api.v1.auth_deps import actor_for, require_permission
from app.core.errors import error_response
from app.database.session import get_db
from app.models.event_enums import Severity
from app.models.events import SecurityEvent
from app.schemas.events import EventIngest, EventPage, EventResponse, EventSummary
from app.services import event_service
from app.services.auth_service import AuthContext

router = APIRouter(prefix="/events", tags=["events"])

MAX_LIMIT = 200


def _to_response(event: SecurityEvent) -> dict:
    raw = None
    if event.raw_event:
        try:
            raw = json.loads(event.raw_event)
        except (ValueError, TypeError):
            raw = None
    normalized: dict = {}
    if event.normalized_data:
        try:
            parsed = json.loads(event.normalized_data)
            if isinstance(parsed, dict):
                normalized = parsed
        except (ValueError, TypeError):
            normalized = {}
    return {
        "id": event.id,
        "event_time": event.event_time,
        "received_at": event.received_at,
        "source_type": event.source_type,
        "source_name": event.source_name,
        "event_type": event.event_type,
        "severity": event.severity,
        "title": event.title,
        "description": event.description,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "source_port": event.source_port,
        "destination_port": event.destination_port,
        "protocol": event.protocol,
        "asset_id": event.asset_id,
        "hostname": event.hostname,
        "username": event.username,
        "process_name": event.process_name,
        "action": event.action,
        "status": event.status,
        "confidence": event.confidence,
        "occurrence_count": event.occurrence_count,
        "last_seen_at": event.last_seen_at,
        "ingest_mode": event_service.ingest_mode(),
        "raw_event": raw,
        "normalized_data": normalized,
        "correlation_key": event.correlation_key,
        "fingerprint": event.fingerprint,
        "external_event_id": event.external_event_id,
        "created_at": event.created_at,
    }


@router.post(
    "", response_model=EventResponse, status_code=status.HTTP_201_CREATED, summary="Ingest event"
)
def ingest_event(
    payload: EventIngest,
    response: Response,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("MANAGE_EVENTS")),
):
    actor = actor_for(auth, None)
    try:
        attributes = event_service.normalize_event(payload.model_dump())
    except event_service.PayloadTooLargeError as exc:
        event_service.record_event_audit(db, event_service.AUDIT_REJECTED, None, actor, str(exc))
        db.commit()
        return error_response(
            "PAYLOAD_TOO_LARGE", str(exc), status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
        )
    event_service.correlate_asset(db, attributes)
    event, created = event_service.store_event(db, attributes)
    event_service.record_event_audit(
        db, event_service.AUDIT_NORMALIZED, event.id, actor, "Generic envelope normalized."
    )
    event_service.record_event_audit(
        db,
        event_service.AUDIT_RECEIVED if created else event_service.AUDIT_DEDUPLICATED,
        event.id,
        actor,
        f"Generic ingest {'stored' if created else 'replay'} (occurrence {event.occurrence_count}).",
    )
    db.commit()
    if not created:
        response.status_code = status.HTTP_200_OK  # idempotent replay: same event back
    return _to_response(event)


@router.get("", response_model=EventPage, summary="List events")
def list_events(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_EVENTS")),
    severity: str | None = Query(default=None),
    source_type: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    asset_id: str | None = Query(default=None),
    since: datetime | None = Query(default=None, description="event_time >= (ISO 8601)"),
    until: datetime | None = Query(default=None, description="event_time <= (ISO 8601)"),
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
):
    if severity is not None and severity not in {level.value for level in Severity}:
        return error_response(
            "INVALID_FILTER",
            f"Unknown severity filter: {severity!r}.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    query = select(SecurityEvent)
    count_query = select(func.count(SecurityEvent.id))
    criteria = []
    if severity is not None:
        criteria.append(SecurityEvent.severity == severity)
    if source_type is not None:
        criteria.append(SecurityEvent.source_type == source_type)
    if event_type is not None:
        criteria.append(SecurityEvent.event_type == event_type)
    if asset_id is not None:
        criteria.append(SecurityEvent.asset_id == asset_id)
    if since is not None:
        criteria.append(SecurityEvent.event_time >= since)
    if until is not None:
        criteria.append(SecurityEvent.event_time <= until)
    if criteria:
        query = query.where(*criteria)
        count_query = count_query.where(*criteria)
    total = db.scalar(count_query) or 0
    events = db.scalars(
        query.order_by(desc(SecurityEvent.event_time), SecurityEvent.id).limit(limit).offset(offset)
    ).all()
    return {
        "items": [_to_response(event) for event in events],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/summary", response_model=EventSummary, summary="Event totals")
def event_summary(
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("READ_EVENTS"))
):
    day_ago = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=24)
    total = db.scalar(select(func.count(SecurityEvent.id))) or 0
    critical = (
        db.scalar(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.severity == Severity.CRITICAL.value
            )
        )
        or 0
    )
    high = (
        db.scalar(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.severity == Severity.HIGH.value
            )
        )
        or 0
    )
    last_24h = (
        db.scalar(select(func.count(SecurityEvent.id)).where(SecurityEvent.event_time >= day_ago))
        or 0
    )
    return {
        "total_events": total,
        "critical_events": critical,
        "high_events": high,
        "last_24h_events": last_24h,
    }


@router.get("/{event_id}", response_model=EventResponse, summary="Event detail")
def get_event(
    event_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_EVENTS")),
):
    event = db.scalar(select(SecurityEvent).where(SecurityEvent.id == event_id))
    if event is None:
        return error_response(
            "EVENT_NOT_FOUND", f"No event with id {event_id}.", status.HTTP_404_NOT_FOUND
        )
    return _to_response(event)


@router.get("/{event_id}/audit", summary="Event ingest audit trail")
def get_event_audit(
    event_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_EVENTS")),
):
    """Chronological ingest lifecycle facts for one event (Step 23)."""
    from app.models.events import EventAudit

    event = db.scalar(select(SecurityEvent).where(SecurityEvent.id == event_id))
    if event is None:
        return error_response(
            "EVENT_NOT_FOUND", f"No event with id {event_id}.", status.HTTP_404_NOT_FOUND
        )
    rows = db.scalars(
        select(EventAudit)
        .where(EventAudit.event_id == event_id)
        .order_by(EventAudit.created_at, EventAudit.id)
    ).all()
    return {
        "event_id": event_id,
        "entries": [
            {
                "action": row.action,
                "actor": row.actor,
                "detail": row.detail,
                "created_at": row.created_at,
            }
            for row in rows
        ],
    }
