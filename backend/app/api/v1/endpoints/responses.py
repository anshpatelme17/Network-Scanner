"""Response proposal endpoints (Steps 12, 18, 19 and Step 30 governance).

Proposals describe actions, move through explicit approval states, and
can be previewed via a pure dry-run function. Step 18 adds a
synchronous execution path for SAFE foundation actions only
(REVIEW, COLLECT_EVIDENCE, MARK_FOR_INVESTIGATION, ACKNOWLEDGE,
CLOSE), which operate exclusively on platform workflow records. The
seven Step 12 action types remain simulation-only. Notably absent by
design: /block, /isolate, /quarantine, /remediate, /firewall,
/disable-account, and any generic command-execution interface.

Step 30 adds a controlled defensive-response flow for six explicitly
allow-listed action types (BLOCK_INDICATOR,
DISABLE_INDICATOR_BLOCK, ISOLATE_ENDPOINT, RELEASE_ENDPOINT,
DISABLE_ACCOUNT, ENABLE_ACCOUNT). Those types are recognised by the
governance layer and routed to it; every other action type continues
down the unchanged Step 12/13/18/19 path. A Step 30 request must name a
target that stored incident evidence supports, waits in PENDING_APPROVAL
for a second human, expires on a server-bounded TTL, and is executed
only through a registry provider - never a command, socket, or URL.
"""

import json

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.api.v1.auth_deps import actor_for, require_permission
from app.api.v1.limits import rate_limit
from app.core.errors import error_response
from app.database.session import get_db
from app.models.incidents import IncidentEvidence
from app.models.responses import ResponseAction, ResponseAudit, ResponseRollback
from app.schemas.response_governance import (
    ControlledActionResponse,
    ControlledDryRunResponse,
    ControlledResponseRequest,
    GovernanceActorRequest,
    ResponsePolicyResponse,
    RollbackResponse,
)
from app.schemas.responses import (
    AdapterEvidence,
    AuditEntry,
    DryRunResult,
    ExecutionRequest,
    ExecutionResult,
    PreviewResponse,
    ResponseActionResponse,
    ResponseDecisionRequest,
    ResponseDetailResponse,
    ResponsePage,
    ResponseProposalRequest,
)
from app.services import response_governance, response_policy, response_service
from app.services.auth_service import (
    PERM_CANCEL_RESPONSE,
    PERM_EXECUTE_RESPONSE,
    PERM_ROLLBACK_RESPONSE,
    AuthContext,
)
from app.services.response_executors import SIMULATION_ADAPTER, get_executor, select_adapter_name
from app.services.response_policy import (
    DECISION_ALLOW,
    DECISION_ALLOW_SAFE,
    DECISION_DENY,
)
from app.services.response_providers import is_controlled_action
from app.services.response_service import (
    STATUSES,
    InvalidResponseError,
    InvalidResponseTransitionError,
    ResponseNotFoundError,
)

router = APIRouter(prefix="/responses", tags=["responses"])

MAX_LIMIT = 200


def _stored_evidence(raw: str | None) -> list[str]:
    """Server-derived target proof, rendered as a list. Never client input."""
    try:
        parsed = json.loads(raw or "[]")
    except ValueError:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed][: response_governance.MAX_EVIDENCE_REFERENCES_STORED]


def _to_response(row: ResponseAction) -> dict:
    return {
        "id": row.id,
        "incident_id": row.incident_id,
        "action_type": row.action_type,
        "target_type": row.target_type,
        "target_reference": row.target_reference,
        "reason": row.reason,
        "requested_by": row.requested_by,
        "status": row.status,
        "dry_run": row.dry_run,
        "policy_version": row.policy_version,
        "execution_status": row.execution_status,
        "created_at": row.created_at,
        "approved_at": row.approved_at,
        "expires_at": row.expires_at,
        "approved_by": row.approved_by,
        "started_at": row.started_at,
        "completed_at": row.completed_at,
        "failure_reason": row.failure_reason,
        "result_summary": row.result_summary,
        # Step 30 governance fields. Every pre-Step-30 row reports the
        # dry-run-only defaults, so nothing here can claim a controlled
        # capability that row never had.
        "provider": row.provider,
        "policy_decision": row.policy_decision,
        "approval_required": row.approval_required,
        "rollback_supported": row.rollback_supported,
        "rollback_state": row.rollback_state,
        "rollback_reference": row.rollback_reference,
        "target_evidence": _stored_evidence(row.target_evidence),
    }


def _audit_entries(db: Session, action_id: str) -> list[AuditEntry]:
    # Chronological with an id tiebreak so rapid successive events order deterministically.
    rows = db.scalars(
        select(ResponseAudit)
        .where(ResponseAudit.action_id == action_id)
        .order_by(ResponseAudit.created_at, ResponseAudit.id)
    ).all()
    return [AuditEntry.model_validate(row) for row in rows]


def _get_or_404(db: Session, action_id: str):
    row = db.scalar(select(ResponseAction).where(ResponseAction.id == action_id))
    if row is None:
        return None
    return row


# Every refusal the governance layer can raise, as one union. Each maps
# to a specific, safe error envelope in _governance_error below; an
# exception outside this set is a real bug and is re-raised rather than
# being flattened into a 422.
_GOVERNANCE_EXCEPTIONS = (
    response_governance.TargetRejectedError
    | response_governance.PolicyDeniedError
    | response_service.InvalidResponseError
    | response_service.InvalidResponseTransitionError
    | response_service.ResponseNotFoundError
)


def _governance_error(exc: Exception) -> Response:
    """Map a governance refusal onto the standard error envelope."""
    if isinstance(exc, response_governance.TargetRejectedError):
        return error_response(
            "TARGET_NOT_SUPPORTED", str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY
        )
    if isinstance(exc, response_governance.PolicyDeniedError):
        return error_response(
            "ACTION_NOT_PERMITTED", str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY
        )
    if isinstance(exc, response_service.InvalidResponseTransitionError):
        return error_response("INVALID_TRANSITION", str(exc), status.HTTP_409_CONFLICT)
    if isinstance(exc, response_service.InvalidResponseError):
        return error_response("INVALID_PROPOSAL", str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY)
    if isinstance(exc, response_service.ResponseNotFoundError):
        return error_response("RESPONSE_NOT_FOUND", str(exc), status.HTTP_404_NOT_FOUND)
    raise exc


# ---------------------------------------------------------------------------
# Step 30: controlled defensive responses
# ---------------------------------------------------------------------------


@router.post(
    "/controlled",
    response_model=ControlledActionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Request a controlled defensive response",
)
def request_controlled_response(
    payload: ControlledResponseRequest,
    response: Response,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("REQUEST_RESPONSE")),
    _limit: None = Depends(rate_limit("response_request", "rate_limit_response_governance")),
):
    """Open a controlled response request for an allow-listed action.

    The action type, target type, provider, policy decision, approval
    requirement, and expiry are all decided server-side. A request is
    created in PENDING_APPROVAL and is never executable from here; a
    target with no supporting stored evidence is rejected and audited
    rather than accepted on the caller's word.
    """
    actor = actor_for(auth, payload.requested_by)
    try:
        row, created, _verdict = response_governance.request_action(
            db,
            payload.incident_id,
            payload.action_type,
            payload.target_type,
            payload.target_reference,
            payload.reason,
            actor,
            payload.ttl_minutes,
        )
    except Exception as exc:  # noqa: BLE001 - mapped to the safe envelope below
        if isinstance(exc, _GOVERNANCE_EXCEPTIONS):
            return _governance_error(exc)
        raise
    if not created:
        response.status_code = status.HTTP_200_OK  # deterministic replay
    return _to_response(row)


@router.get(
    "/{action_id}/policy",
    response_model=ResponsePolicyResponse,
    summary="Deterministic policy verdict for a response",
)
def get_response_policy(
    action_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_RESPONSES")),
):
    """Report the policy verdict for a stored action. Performs nothing."""
    row = _get_or_404(db, action_id)
    if row is None:
        return error_response(
            "RESPONSE_NOT_FOUND",
            f"No response proposal with id {action_id}.",
            status.HTTP_404_NOT_FOUND,
        )
    verdict = response_governance.evaluate_policy(db, row)
    return {"action_id": row.id, **verdict}


@router.post(
    "/{action_id}/rollback",
    response_model=RollbackResponse,
    summary="Roll back an executed controlled response",
)
def rollback_response(
    action_id: str,
    payload: GovernanceActorRequest | None = None,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission(PERM_ROLLBACK_RESPONSE)),
    _limit: None = Depends(rate_limit("response_rollback", "rate_limit_response_governance")),
):
    """Explicitly roll back a completed controlled response.

    Requires its own permission and its own audit trail, and never
    guesses a previous state: a provider that recorded no prior state
    produces an UNSUPPORTED record rather than a fabricated
    compensating action. A repeat call replays the stored record.
    """
    actor = actor_for(auth, payload.actor if payload is not None else "operator")
    try:
        return response_governance.rollback(db, action_id, actor)
    except Exception as exc:  # noqa: BLE001 - mapped to the safe envelope below
        if isinstance(exc, _GOVERNANCE_EXCEPTIONS):
            return _governance_error(exc)
        raise


@router.post(
    "",
    response_model=ResponseActionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Propose response",
)
def propose_response(
    payload: ResponseProposalRequest,
    response: Response,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("PROPOSE_RESPONSE")),
):
    try:
        row, created = response_service.propose_action(
            db,
            payload.incident_id,
            payload.action_type,
            payload.target_type,
            payload.target_reference,
            payload.reason,
            payload.requested_by,
            payload.dry_run,
        )
    except ResponseNotFoundError as exc:
        return error_response("INCIDENT_NOT_FOUND", str(exc), status.HTTP_404_NOT_FOUND)
    except InvalidResponseError as exc:
        return error_response("INVALID_PROPOSAL", str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY)
    if not created:
        response.status_code = status.HTTP_200_OK
    return _to_response(row)


@router.get("", response_model=ResponsePage, summary="List response proposals")
def list_responses(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_RESPONSES")),
    status_filter: str | None = Query(default=None, alias="status"),
    action_type: str | None = Query(default=None),
    incident_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
):
    if status_filter is not None and status_filter not in STATUSES:
        return error_response(
            "INVALID_FILTER",
            f"Unknown status filter: {status_filter!r}.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    # Step 30: enforce bounded expiry on the read path. There is no
    # scheduler in this platform, so an overdue approval is retired here
    # (audited) rather than sitting executable until someone notices.
    if incident_id is not None:
        response_governance.expire_due(db, incident_id)
    else:
        response_governance.expire_due(db)
    query = select(ResponseAction)
    count_query = select(func.count(ResponseAction.id))
    if status_filter is not None:
        query = query.where(ResponseAction.status == status_filter)
        count_query = count_query.where(ResponseAction.status == status_filter)
    if action_type is not None:
        query = query.where(ResponseAction.action_type == action_type)
        count_query = count_query.where(ResponseAction.action_type == action_type)
    if incident_id is not None:
        query = query.where(ResponseAction.incident_id == incident_id)
        count_query = count_query.where(ResponseAction.incident_id == incident_id)
    total = db.scalar(count_query) or 0
    rows = db.scalars(
        query.order_by(desc(ResponseAction.created_at), ResponseAction.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return {
        "items": [_to_response(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{action_id}", response_model=ResponseDetailResponse, summary="Response detail")
def get_response(
    action_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_RESPONSES")),
):
    row = _get_or_404(db, action_id)
    if row is None:
        return error_response(
            "RESPONSE_NOT_FOUND",
            f"No response proposal with id {action_id}.",
            status.HTTP_404_NOT_FOUND,
        )
    response_governance.expire_due(db, row.incident_id)
    db.refresh(row)
    detail = _to_response(row)
    detail["audit"] = _audit_entries(db, row.id)
    stored = response_service.get_execution(db, row.id)
    detail["execution"] = ExecutionResult.model_validate(stored) if stored is not None else None
    rollback_row = db.scalar(select(ResponseRollback).where(ResponseRollback.action_id == row.id))
    detail["rollback"] = RollbackResponse.model_validate(rollback_row) if rollback_row else None
    return detail


def _decide(db: Session, action_id: str, actor: str, operation: str):
    row = _get_or_404(db, action_id)
    if row is None:
        return error_response(
            "RESPONSE_NOT_FOUND",
            f"No response proposal with id {action_id}.",
            status.HTTP_404_NOT_FOUND,
        )
    if is_controlled_action(row.action_type):
        # Step 30 governance path: separation of duties, expiry guard,
        # and the controlled transition map all live in the service.
        try:
            if operation == "approve":
                updated = response_governance.approve(db, row.id, actor)
            elif operation == "reject":
                updated = response_governance.reject(db, row.id, actor)
            else:
                updated = response_governance.cancel(db, row.id, actor)
        except Exception as exc:  # noqa: BLE001 - mapped to the safe envelope below
            return _governance_error(exc)
        return _to_response(updated)
    try:
        if operation == "approve":
            updated = response_service.approve_action(db, row, actor)
        elif operation == "reject":
            updated = response_service.reject_action(db, row, actor)
        else:
            updated = response_service.cancel_action(db, row, actor)
    except InvalidResponseTransitionError as exc:
        return error_response("INVALID_TRANSITION", str(exc), status.HTTP_409_CONFLICT)
    return _to_response(updated)


@router.post(
    "/{action_id}/approve", response_model=ResponseActionResponse, summary="Approve proposal"
)
def approve_response(
    payload: ResponseDecisionRequest,
    action_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("APPROVE_RESPONSE")),
    _limit: None = Depends(rate_limit("response_approve", "rate_limit_response_governance")),
):
    return _decide(db, action_id, actor_for(auth, payload.actor), "approve")


@router.post(
    "/{action_id}/reject", response_model=ResponseActionResponse, summary="Reject proposal"
)
def reject_response(
    payload: ResponseDecisionRequest,
    action_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("APPROVE_RESPONSE")),
):
    return _decide(db, action_id, actor_for(auth, payload.actor), "reject")


@router.post(
    "/{action_id}/cancel", response_model=ResponseActionResponse, summary="Cancel proposal"
)
def cancel_response(
    payload: ResponseDecisionRequest,
    action_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission(PERM_CANCEL_RESPONSE)),
):
    return _decide(db, action_id, actor_for(auth, payload.actor), "cancel")


@router.post("/{action_id}/dry-run", response_model=DryRunResult, summary="Dry-run preview")
def dry_run_response(
    action_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("RUN_ANALYSIS")),
):
    row = _get_or_404(db, action_id)
    if row is None:
        return error_response(
            "RESPONSE_NOT_FOUND",
            f"No response proposal with id {action_id}.",
            status.HTTP_404_NOT_FOUND,
        )
    return response_service.record_dry_run(db, row)


@router.post(
    "/{action_id}/provider-preview",
    response_model=ControlledDryRunResponse,
    summary="Provider-aware dry run (Step 30)",
)
def provider_preview_response(
    action_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("RUN_ANALYSIS")),
):
    """Validate the target and preview the provider's action (Step 30).

    Read-only apart from audit rows. The provider validates the target,
    states the policy verdict, and describes what it would do - it
    cannot perform it, because no provider in the registry holds a
    transport. ``executed`` is always false and the explanation always
    states that nothing external was performed.
    """
    row = _get_or_404(db, action_id)
    if row is None:
        return error_response(
            "RESPONSE_NOT_FOUND",
            f"No response proposal with id {action_id}.",
            status.HTTP_404_NOT_FOUND,
        )
    try:
        return response_governance.dry_run(db, row.id, actor_for(auth))
    except Exception as exc:  # noqa: BLE001 - mapped to the safe envelope below
        if isinstance(exc, _GOVERNANCE_EXCEPTIONS):
            return _governance_error(exc)
        raise


@router.post(
    "/{action_id}/preview",
    response_model=PreviewResponse,
    summary="Preview adapter handling",
)
def preview_response(
    action_id: str,
    payload: ExecutionRequest | None = None,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("RUN_ANALYSIS")),
):
    """Validate a proposal and report what its adapter would do (Step 19).

    Read-only apart from one audit row: validates the stored proposal,
    enforces the Step 18 approval policy (unapproved work is rejected,
    never previewed as executable), selects the adapter from the static
    server-side registry, validates the target, and returns the typed
    simulation result with stored-reference evidence. Nothing executes;
    no external system is contacted or modified.
    """
    actor = actor_for(auth, payload.actor if payload is not None else "operator")
    row = _get_or_404(db, action_id)
    if row is None:
        return error_response(
            "RESPONSE_NOT_FOUND",
            f"No response proposal with id {action_id}.",
            status.HTTP_404_NOT_FOUND,
        )
    decision = response_policy.evaluate_for_execution(row)
    if decision["decision"] not in (DECISION_ALLOW, DECISION_ALLOW_SAFE):
        response_service.record_execution_denied(db, row, actor, str(decision["decision"]))
        code = "EXECUTION_DENIED" if decision["decision"] == DECISION_DENY else "REQUIRE_APPROVAL"
        return error_response(code, str(decision["reason"]), status.HTTP_403_FORBIDDEN)
    adapter_name = select_adapter_name(row.action_type)
    try:
        executor = get_executor(adapter_name)
    except KeyError:
        return error_response(
            "INVALID_ADAPTER",
            f"Action type is not served by a registered adapter: {row.action_type}.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    try:
        executor.validate_target(row.target_type, row.target_reference)
    except response_service.InvalidResponseError as exc:
        return error_response("INVALID_TARGET", str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY)
    request = executor.build_request(row, adapter_name)
    result = executor.preview(request, would_execute=True)
    evidence = []
    if row.action_type == response_service.ACTION_COLLECT_EVIDENCE:
        links = db.scalars(
            select(IncidentEvidence)
            .where(IncidentEvidence.incident_id == row.incident_id)
            .order_by(IncidentEvidence.evidence_kind, IncidentEvidence.evidence_id)
        ).all()
        evidence = [
            AdapterEvidence(kind=link.evidence_kind, reference=link.evidence_id, detail=link.reason)
            for link in links
        ]
    response_service.record_preview(db, row, actor, adapter_name, True)
    return {
        "action_id": row.id,
        "incident_id": row.incident_id,
        "adapter_type": adapter_name,
        "accepted": result.accepted,
        "executed": result.executed,
        "simulated": result.simulated,
        "would_execute": result.would_execute,
        "status": result.status,
        "result_summary": result.result_summary,
        "evidence": evidence,
        "policy_decision": decision["decision"],
        "policy_version": response_service.POLICY_VERSION,
    }


@router.post(
    "/{action_id}/execute",
    response_model=ExecutionResult,
    status_code=status.HTTP_201_CREATED,
    summary="Execute an approved proposal",
)
def execute_response(
    action_id: str,
    request: Request,
    response: Response,
    payload: ExecutionRequest | None = None,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("EXECUTE_SAFE_RESPONSE")),
    _limit: None = Depends(rate_limit("response_execute", "rate_limit_response_governance")),
):
    """Run an approved proposal through its allowlisted executor.

    The server selects the executor by action type; clients cannot
    choose one. Simulation types run the deterministic simulation
    adapter (SIMULATED, nothing performed). Safe foundation types run
    the platform-record-only executor (COMPLETED/FAILED on incident
    workflow records; no external change ever occurs). Completed work
    replays the stored row instead of executing twice.
    """
    actor = actor_for(auth, payload.actor if payload is not None else "operator")
    row = _get_or_404(db, action_id)
    if row is None:
        return error_response(
            "RESPONSE_NOT_FOUND",
            f"No response proposal with id {action_id}.",
            status.HTTP_404_NOT_FOUND,
        )
    if is_controlled_action(row.action_type):
        # Step 30: a controlled action needs its own execution permission
        # on top of the safe-response one, plus a recorded approver, a
        # live TTL, and a registry provider. Repeat calls replay the
        # stored execution row instead of acting twice.
        if (
            auth.enforcement
            and auth.authenticated
            and PERM_EXECUTE_RESPONSE not in auth.permissions
        ):
            return error_response(
                "PERMISSION_DENIED",
                f"Permission is required: {PERM_EXECUTE_RESPONSE}.",
                status.HTTP_403_FORBIDDEN,
            )
        idempotency_key = request.headers.get("Idempotency-Key")
        try:
            stored, created = response_governance.execute(db, row.id, actor, idempotency_key)
        except Exception as exc:  # noqa: BLE001 - mapped to the safe envelope below
            if isinstance(exc, _GOVERNANCE_EXCEPTIONS):
                return _governance_error(exc)
            raise
        if not created:
            response.status_code = status.HTTP_200_OK  # idempotent replay
        return ExecutionResult.model_validate(stored)
    existing = response_service.get_execution(db, row.id)
    if existing is not None:
        response.status_code = status.HTTP_200_OK  # idempotent replay
        return ExecutionResult.model_validate(existing)
    decision = response_policy.evaluate_for_execution(row)
    if decision["decision"] == DECISION_ALLOW_SAFE:
        try:
            stored = response_service.execute_safe_action(db, row, actor)
        except InvalidResponseTransitionError as exc:
            return error_response("INVALID_TRANSITION", str(exc), status.HTTP_409_CONFLICT)
        except InvalidResponseError as exc:
            return error_response(
                "INVALID_PROPOSAL", str(exc), status.HTTP_422_UNPROCESSABLE_ENTITY
            )
        return ExecutionResult.model_validate(stored)
    if decision["decision"] != DECISION_ALLOW:
        response_service.record_execution_denied(db, row, actor, str(decision["decision"]))
        code = "EXECUTION_DENIED" if decision["decision"] == DECISION_DENY else "REQUIRE_APPROVAL"
        return error_response(code, str(decision["reason"]), status.HTTP_403_FORBIDDEN)
    executor = get_executor(SIMULATION_ADAPTER)
    result = executor.execute(row)
    stored = response_service.persist_execution(db, row, result, actor)
    return ExecutionResult.model_validate(stored)
