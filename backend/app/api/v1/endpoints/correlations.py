"""Correlation query endpoints (Step 9, analysis only).

Read-only views over deterministically computed correlations, plus one
bounded, parameter-free recompute trigger. No rule management, no rule
execution parameters, no response actions — there is nothing here that
could act on a host.
"""

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.api.v1.auth_deps import actor_for, require_permission
from app.api.v1.limits import rate_limit
from app.core.errors import error_response
from app.database.session import get_db
from app.models.correlations import Correlation, CorrelationEvidence
from app.models.events import SecurityEvent
from app.schemas.correlations import (
    AttackChain,
    ChainEdge,
    ChainNode,
    CorrelationDetail,
    CorrelationPage,
    CorrelationSummary,
    EvidenceItem,
    RecomputeResult,
)
from app.services import correlation_service
from app.services.auth_service import AuthContext
from app.services.incident_rules import confidence_label

router = APIRouter(prefix="/correlations", tags=["correlations"])

MAX_LIMIT = 200


def _summary(row: Correlation) -> CorrelationSummary:
    summary = CorrelationSummary.model_validate(row)
    # Step 29: deterministic label of the stored confidence (server-side
    # derivation only; the confidence value itself is unchanged).
    summary.confidence_label = confidence_label(row.confidence)
    return summary


def _evidence_items(db: Session, correlation_id: str) -> list[EvidenceItem]:
    """Stored evidence for one correlation, in deterministic order.

    Step 31: batched. The previous version ran one SELECT per evidence
    link (an N+1 that grew with cluster size). Now the events are fetched
    in a single IN query and indexed in memory, so the cost is two queries
    regardless of how many events a correlation holds.
    """
    links = db.scalars(
        select(CorrelationEvidence)
        .where(CorrelationEvidence.correlation_id == correlation_id)
        .order_by(CorrelationEvidence.position)
    ).all()
    if not links:
        return []
    event_ids = {link.event_id for link in links}
    events = {
        event.id: event
        for event in db.scalars(select(SecurityEvent).where(SecurityEvent.id.in_(event_ids))).all()
    }
    items: list[EvidenceItem] = []
    for link in links:
        event = events.get(link.event_id)
        if event is None:
            continue  # event deleted after linking; cascade cleans the link
        items.append(
            EvidenceItem(
                event_id=event.id,
                role=link.role,
                position=link.position,
                event_type=event.event_type,
                source_type=event.source_type,
                severity=event.severity,
                title=event.title,
                event_time=event.event_time,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
            )
        )
    return items


@router.get("", response_model=CorrelationPage, summary="List correlations")
def list_correlations(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_EVENTS")),
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
    rule_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
):
    if status_filter is not None and status_filter not in ("open", "acknowledged", "resolved"):
        return error_response(
            "INVALID_FILTER",
            f"Unknown status filter: {status_filter!r}.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    if severity is not None and severity not in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        return error_response(
            "INVALID_FILTER",
            f"Unknown severity filter: {severity!r}.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    query = select(Correlation)
    count_query = select(func.count(Correlation.id))
    if status_filter is not None:
        query = query.where(Correlation.status == status_filter)
        count_query = count_query.where(Correlation.status == status_filter)
    if severity is not None:
        query = query.where(Correlation.severity == severity)
        count_query = count_query.where(Correlation.severity == severity)
    if rule_id is not None:
        query = query.where(Correlation.rule_id == rule_id)
        count_query = count_query.where(Correlation.rule_id == rule_id)
    total = db.scalar(count_query) or 0
    rows = db.scalars(
        query.order_by(desc(Correlation.updated_at), Correlation.id).limit(limit).offset(offset)
    ).all()
    return {
        "items": [_summary(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{correlation_id}", response_model=CorrelationDetail, summary="Correlation detail")
def get_correlation(
    correlation_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_EVENTS")),
):
    row = db.scalar(select(Correlation).where(Correlation.id == correlation_id))
    if row is None:
        return error_response(
            "CORRELATION_NOT_FOUND",
            f"No correlation with id {correlation_id}.",
            status.HTTP_404_NOT_FOUND,
        )
    detail = _summary(row).model_dump()
    detail["description"] = row.description
    detail["explanation"] = row.explanation
    detail["evidence"] = _evidence_items(db, row.id)
    return detail


@router.get(
    "/{correlation_id}/attack-chain", response_model=AttackChain, summary="Ordered evidence chain"
)
def get_attack_chain(
    correlation_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_EVENTS")),
):
    row = db.scalar(select(Correlation).where(Correlation.id == correlation_id))
    if row is None:
        return error_response(
            "CORRELATION_NOT_FOUND",
            f"No correlation with id {correlation_id}.",
            status.HTTP_404_NOT_FOUND,
        )
    evidence = _evidence_items(db, row.id)
    nodes: list[ChainNode] = [
        ChainNode(
            id=f"correlation:{row.id}",
            kind="correlation",
            label=row.title,
            detail={"rule": row.rule_name, "severity": row.severity},
        )
    ]
    edges: list[ChainEdge] = []
    pivot_id: str | None = None
    if row.primary_ip:
        pivot_id = f"asset:{row.primary_ip}"
        nodes.append(ChainNode(id=pivot_id, kind="asset", label=row.primary_ip, detail={}))
        edges.append(ChainEdge(source=f"correlation:{row.id}", target=pivot_id, relation="pivot"))
    for item in evidence:
        node_id = f"event:{item.event_id}"
        kind = "vulnerability" if item.event_type == "VULNERABILITY_FINDING" else "event"
        nodes.append(
            ChainNode(
                id=node_id,
                kind=kind,
                label=f"{item.event_time.isoformat()} — {item.title}",
                detail={
                    "source": item.source_type,
                    "type": item.event_type,
                    "severity": item.severity,
                    "role": item.role,
                },
            )
        )
        edges.append(
            ChainEdge(source=f"correlation:{row.id}", target=node_id, relation="supported by")
        )
        if pivot_id is not None:
            edges.append(ChainEdge(source=pivot_id, target=node_id, relation="observed in"))
    return AttackChain(correlation_id=row.id, nodes=nodes, edges=edges)


@router.post("/recompute", response_model=RecomputeResult, summary="Recompute correlations")
async def recompute(
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("RUN_ANALYSIS")),
    _limit: None = Depends(rate_limit("correlation_recompute", "rate_limit_recompute")),
):
    """Bounded, parameter-free, deterministic recompute over recent events.

    Any request body beyond an empty object is rejected: rule selection,
    expressions, and commands are never accepted from callers (Step 24).
    """
    body = (await request.body()).strip()
    if body not in (b"", b"{}"):
        return error_response(
            "INVALID_REQUEST",
            "Recompute accepts no body: rules are server-side only.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    return correlation_service.recompute_correlations(db, actor_for(auth, None))
