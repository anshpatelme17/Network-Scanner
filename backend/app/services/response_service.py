"""Response proposal service (Step 12, dry-run / approval only).

Everything here describes, approves, or records workflow around a
*represented* action. There is deliberately no executor: no function in
this module — or anywhere in the codebase — performs, dispatches, or
schedules a real security action. ``dry_run_result`` is a pure function
of the stored proposal that always reports ``would_execute: False``.

Lifecycle (explicit operator operations only; invalid moves rejected)::

    PROPOSED -> APPROVED | REJECTED | CANCELLED | DRY_RUN_COMPLETED
    DRY_RUN_COMPLETED -> APPROVED | REJECTED | CANCELLED
    APPROVED -> CANCELLED
    REJECTED, CANCELLED, EXPIRED -> (terminal)

Identity is deterministic: ``sha256("response-action:v1" |
incident_id | action_type | target_type | target_reference |
requested_by)``. Replays return the existing row unchanged — never
resurrected, never duplicated.

Step 18 adds a controlled execution path for SAFE foundation actions
only (REVIEW, COLLECT_EVIDENCE, MARK_FOR_INVESTIGATION, ACKNOWLEDGE,
CLOSE). Safe actions operate exclusively on platform workflow records
(incident status, evidence references, review notes) through the
existing incident services — they never touch external systems, run
processes, open sockets, or modify hosts/networks/accounts. Execution
still requires PROPOSED → APPROVED, records approval identity once,
runs synchronously through RUNNING into COMPLETED or FAILED with an
honest result summary or failure reason, and replays the stored result
instead of executing twice. The seven Step 12 action types remain
simulation-only; nothing about their path changes.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.incidents import Incident
from app.models.responses import ResponseAction, ResponseAudit
from app.services import incident_service
from app.services.response_providers import (
    ACTION_BLOCK_INDICATOR,
    ACTION_DISABLE_INDICATOR_BLOCK,
    ACTION_ENABLE_ACCOUNT,
    ACTION_ISOLATE_ENDPOINT,
    ACTION_RELEASE_ENDPOINT,
    CONTROLLED_ACTION_TYPES,
    TARGET_ENDPOINT,
    TARGET_HASH,
    TARGET_INDICATOR,
)

logger = get_logger(__name__)

POLICY_VERSION = "1.0.0"
IDENTITY_NAMESPACE = "response-action:v1"
# Adapter name recorded on safe-execution rows. Only the execute
# endpoint selects it, and only for allowlisted safe action types.
SAFE_ADAPTER = "safe-record"
# Approval time-to-live: derived from the stored approval timestamp only.
APPROVAL_TTL_DAYS = 7

ACTION_ISOLATE_ASSET = "ISOLATE_ASSET"
ACTION_BLOCK_IP = "BLOCK_IP"
ACTION_BLOCK_DOMAIN = "BLOCK_DOMAIN"
ACTION_DISABLE_ACCOUNT = "DISABLE_ACCOUNT"
ACTION_QUARANTINE_ASSET = "QUARANTINE_ASSET"
ACTION_FIREWALL_RULE = "FIREWALL_RULE"
ACTION_REMEDIATION = "REMEDIATION"
ACTION_TYPES = (
    ACTION_ISOLATE_ASSET,
    ACTION_BLOCK_IP,
    ACTION_BLOCK_DOMAIN,
    ACTION_DISABLE_ACCOUNT,
    ACTION_QUARANTINE_ASSET,
    ACTION_FIREWALL_RULE,
    ACTION_REMEDIATION,
)

# Step 18 safe foundation actions (additive allow-list extension).
# These operate ONLY on platform workflow records via the existing
# incident services. They cannot address hosts, networks, accounts, or
# any external system; the target is always the incident itself.
ACTION_REVIEW = "REVIEW"
ACTION_COLLECT_EVIDENCE = "COLLECT_EVIDENCE"
ACTION_MARK_FOR_INVESTIGATION = "MARK_FOR_INVESTIGATION"
ACTION_ACKNOWLEDGE = "ACKNOWLEDGE"
ACTION_CLOSE = "CLOSE"
SAFE_ACTION_TYPES = (
    ACTION_REVIEW,
    ACTION_COLLECT_EVIDENCE,
    ACTION_MARK_FOR_INVESTIGATION,
    ACTION_ACKNOWLEDGE,
    ACTION_CLOSE,
)
ACTION_TYPES = ACTION_TYPES + SAFE_ACTION_TYPES

# Step 30 controlled defensive action types (additive allow-list
# extension). These are the only types the Step 30 governance flow will
# request, approve, execute, or roll back, and the only ones that may
# name an indicator / endpoint / account target. They are reachable from
# the proposal allow-list but CANNOT be executed by the Step 13
# simulation path or the Step 18 safe-execution path: both check
# is_safe_action() / their own allow-lists and neither knows these
# types. Execution goes exclusively through response_governance, which
# requires a stored-evidence target, a second approver, and a TTL.
ACTION_TYPES = ACTION_TYPES + CONTROLLED_ACTION_TYPES

TARGET_ASSET = "ASSET"
TARGET_IP = "IP"
TARGET_DOMAIN = "DOMAIN"
TARGET_ACCOUNT = "ACCOUNT"
# Step 18: safe actions address the incident record itself; the target
# reference must equal the proposal's incident_id (enforced below).
TARGET_INCIDENT = "INCIDENT"
# Step 19: simulated hostname targets. Validated syntactically only —
# never resolved, never contacted (see validate_target).
TARGET_HOSTNAME = "HOSTNAME"
TARGET_TYPES = (
    TARGET_ASSET,
    TARGET_IP,
    TARGET_DOMAIN,
    TARGET_ACCOUNT,
    TARGET_INCIDENT,
    TARGET_HOSTNAME,
    # Step 30 controlled-response targets. "INDICATOR" is a validated IP
    # or hash observed in incident evidence; "ENDPOINT" is an identifier
    # for a host already known to the platform; "HASH" is a 32/40/64 hex
    # indicator hash. None is ever invented — response_governance proves
    # each one against stored incident evidence before it is accepted.
    TARGET_INDICATOR,
    TARGET_ENDPOINT,
    TARGET_HASH,
)

STATUS_PROPOSED = "PROPOSED"
STATUS_APPROVED = "APPROVED"
STATUS_REJECTED = "REJECTED"
STATUS_CANCELLED = "CANCELLED"
STATUS_EXPIRED = "EXPIRED"
STATUS_DRY_RUN_COMPLETED = "DRY_RUN_COMPLETED"
STATUS_READY_FOR_EXECUTION = "READY_FOR_EXECUTION"
# Step 18: synchronous safe-execution outcomes (platform records only).
STATUS_RUNNING = "RUNNING"
STATUS_COMPLETED = "COMPLETED"
STATUS_FAILED = "FAILED"
# Step 30 governance states. PENDING_APPROVAL is where a consequential
# request waits for a second human; ROLLED_BACK is the only state a
# COMPLETED action can leave for. Both fit String(32).
STATUS_PENDING_APPROVAL = "PENDING_APPROVAL"
STATUS_ROLLED_BACK = "ROLLED_BACK"
STATUSES = (
    STATUS_PROPOSED,
    STATUS_PENDING_APPROVAL,
    STATUS_APPROVED,
    STATUS_REJECTED,
    STATUS_CANCELLED,
    STATUS_EXPIRED,
    STATUS_DRY_RUN_COMPLETED,
    STATUS_READY_FOR_EXECUTION,
    STATUS_RUNNING,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_ROLLED_BACK,
)

TRANSITIONS: dict[str, tuple[str, ...]] = {
    STATUS_PROPOSED: (STATUS_APPROVED, STATUS_REJECTED, STATUS_CANCELLED, STATUS_DRY_RUN_COMPLETED),
    # Step 30: a controlled request is created directly in
    # PENDING_APPROVAL and waits for a distinct approver. It may be
    # approved, rejected, cancelled, or expire — never executed directly.
    STATUS_PENDING_APPROVAL: (
        STATUS_APPROVED,
        STATUS_REJECTED,
        STATUS_CANCELLED,
        STATUS_EXPIRED,
        STATUS_DRY_RUN_COMPLETED,
    ),
    STATUS_DRY_RUN_COMPLETED: (
        STATUS_APPROVED,
        STATUS_REJECTED,
        STATUS_CANCELLED,
        STATUS_READY_FOR_EXECUTION,
        STATUS_RUNNING,
    ),
    # EXPIRED is reachable only from a pending/approved Step 30 request
    # and only ever written by the expiry check, never by a client.
    STATUS_APPROVED: (
        STATUS_CANCELLED,
        STATUS_DRY_RUN_COMPLETED,
        STATUS_RUNNING,
        STATUS_EXPIRED,
    ),
    STATUS_REJECTED: (),
    STATUS_CANCELLED: (),
    STATUS_EXPIRED: (),
    # READY_FOR_EXECUTION is reached only through the execute endpoint
    # (policy check + simulation), never through generic transitions.
    STATUS_READY_FOR_EXECUTION: (),
    # RUNNING is entered only by the execute endpoint for approved safe
    # actions and resolves synchronously; there are no background
    # workers, so cancellation mid-run cannot occur.
    STATUS_RUNNING: (STATUS_COMPLETED, STATUS_FAILED),
    # Step 30: a completed controlled action may only leave this state
    # through an explicit, separately authorized rollback.
    STATUS_COMPLETED: (STATUS_ROLLED_BACK,),
    STATUS_FAILED: (),
    STATUS_ROLLED_BACK: (),
}

EVENT_PROPOSED = "ACTION_PROPOSED"
EVENT_APPROVED = "ACTION_APPROVED"
EVENT_REJECTED = "ACTION_REJECTED"
EVENT_CANCELLED = "ACTION_CANCELLED"
EVENT_DRY_RUN_COMPLETED = "DRY_RUN_COMPLETED"
EVENT_EXECUTION_REQUESTED = "EXECUTION_REQUESTED"
EVENT_EXECUTION_STARTED = "EXECUTION_STARTED"
EVENT_EXECUTION_COMPLETED = "EXECUTION_COMPLETED"
EVENT_EXECUTION_FAILED = "EXECUTION_FAILED"
EVENT_EXECUTION_DENIED = "EXECUTION_DENIED"
# Step 19: a preview validation was performed (no state change, no
# external effect). Repeated previews each record their own row —
# they are distinct operator reads, unlike executions which replay.
EVENT_PREVIEWED = "RESPONSE_PREVIEWED"

# Step 30 governance audit vocabulary. Every value fits the
# ``response_audit.event`` String(32) column. The RESPONSE_ prefix marks
# the controlled defensive-response flow so it is distinguishable from
# the Step 12/13/18/19 proposal, simulation, and safe-execution events
# above, none of whose meaning or wording changes.
EVENT_RESPONSE_REQUESTED = "RESPONSE_REQUESTED"  # 17
EVENT_RESPONSE_APPROVAL_REQUIRED = "RESPONSE_APPROVAL_REQUIRED"  # 26
EVENT_RESPONSE_APPROVED = "RESPONSE_APPROVED"  # 17
EVENT_RESPONSE_REJECTED = "RESPONSE_REJECTED"  # 17
EVENT_RESPONSE_CANCELLED = "RESPONSE_CANCELLED"  # 18
EVENT_RESPONSE_EXPIRED = "RESPONSE_EXPIRED"  # 16
EVENT_RESPONSE_EXECUTION_STARTED = "RESPONSE_EXECUTION_STARTED"  # 26
EVENT_RESPONSE_EXECUTION_COMPLETED = "RESPONSE_EXECUTION_COMPLETED"  # 28
EVENT_RESPONSE_EXECUTION_FAILED = "RESPONSE_EXECUTION_FAILED"  # 26
EVENT_RESPONSE_ROLLBACK_STARTED = "RESPONSE_ROLLBACK_STARTED"  # 25
EVENT_RESPONSE_ROLLBACK_COMPLETED = "RESPONSE_ROLLBACK_COMPLETED"  # 27
EVENT_RESPONSE_DRY_RUN = "RESPONSE_DRY_RUN"  # 17
EVENT_RESPONSE_TARGET_REJECTED = "RESPONSE_TARGET_REJECTED"  # 24
RESPONSE_AUDIT_EVENTS = (
    EVENT_RESPONSE_REQUESTED,
    EVENT_RESPONSE_APPROVAL_REQUIRED,
    EVENT_RESPONSE_APPROVED,
    EVENT_RESPONSE_REJECTED,
    EVENT_RESPONSE_CANCELLED,
    EVENT_RESPONSE_EXPIRED,
    EVENT_RESPONSE_EXECUTION_STARTED,
    EVENT_RESPONSE_EXECUTION_COMPLETED,
    EVENT_RESPONSE_EXECUTION_FAILED,
    EVENT_RESPONSE_ROLLBACK_STARTED,
    EVENT_RESPONSE_ROLLBACK_COMPLETED,
    EVENT_RESPONSE_DRY_RUN,
    EVENT_RESPONSE_TARGET_REJECTED,
)

_DRY_RUN_EXPLANATIONS = {
    ACTION_ISOLATE_ASSET: "Action would request isolating the asset from the network.",
    ACTION_BLOCK_IP: "Action would request blocking the specified IP.",
    ACTION_BLOCK_DOMAIN: "Action would request blocking the specified domain.",
    ACTION_DISABLE_ACCOUNT: "Action would request disabling the specified account.",
    ACTION_QUARANTINE_ASSET: "Action would request quarantining the specified asset.",
    ACTION_FIREWALL_RULE: "Action would request creating the described firewall rule.",
    ACTION_REMEDIATION: "Action would request the described remediation steps.",
    ACTION_REVIEW: "Action would record a review of the incident. No external change.",
    ACTION_COLLECT_EVIDENCE: "Action would collect the incident's evidence references. No external change.",
    ACTION_MARK_FOR_INVESTIGATION: "Action would mark the incident for investigation. No external change.",
    ACTION_ACKNOWLEDGE: "Action would acknowledge the incident. No external change.",
    ACTION_CLOSE: "Action would close the incident record. No external change.",
    # Step 30 controlled actions. Every sentence states plainly that the
    # action is not performed, so a dry run can never be misread as a
    # successful block, isolation, or account change.
    ACTION_BLOCK_INDICATOR: (
        "Action would request blocking an observed indicator for the configured TTL. "
        "No external change."
    ),
    ACTION_DISABLE_INDICATOR_BLOCK: (
        "Action would request lifting an indicator block recorded by the platform. "
        "No external change."
    ),
    ACTION_ISOLATE_ENDPOINT: (
        "Action would request isolating an endpoint known to the platform for the "
        "configured TTL. No external change."
    ),
    ACTION_RELEASE_ENDPOINT: (
        "Action would request releasing an endpoint isolation recorded by the platform. "
        "No external change."
    ),
    ACTION_ENABLE_ACCOUNT: (
        "Action would request re-enabling an account observed in incident evidence. "
        "No external change."
    ),
}


def is_safe_action(action_type: str) -> bool:
    """True only for the Step 18 platform-record-only action types."""
    return action_type in SAFE_ACTION_TYPES


class ResponseNotFoundError(LookupError):
    """Referenced incident or response action does not exist."""


class InvalidResponseError(ValueError):
    """Proposal fields are invalid (type, target, reason, dry_run)."""


class InvalidResponseTransitionError(ValueError):
    """The requested status change is not an allowed transition."""


def _utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


_HOSTNAME_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def _validate_hostname(reference: str) -> None:
    """Syntactic hostname check only. Never resolves, never contacts.

    Rejects URL schemes, ports, spaces, and over-long names so a
    hostname target cannot smuggle a URL, command, or path. Raises
    InvalidResponseError.
    """
    if "://" in reference or "@" in reference or " " in reference:
        raise InvalidResponseError(f"Target is not a plain hostname: {reference!r}.")
    candidate = reference[:-1] if reference.endswith(".") else reference
    if not candidate or len(candidate) > 253:
        raise InvalidResponseError(f"Target is not a valid hostname: {reference!r}.")
    if not all(_HOSTNAME_LABEL.match(label) for label in candidate.split(".")):
        raise InvalidResponseError(f"Target is not a valid hostname: {reference!r}.")


def action_id(
    incident_id: str, action_type: str, target_type: str, target_reference: str, requested_by: str
) -> str:
    """Deterministic identity. No time, no randomness."""
    canonical = json.dumps(
        [IDENTITY_NAMESPACE, incident_id, action_type, target_type, target_reference, requested_by],
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def validate_target(target_type: str, target_reference: str) -> None:
    """Presence + shape validation. Raises InvalidResponseError."""
    reference = (target_reference or "").strip()
    if not reference:
        raise InvalidResponseError("Target reference must not be empty.")
    if len(reference) > 256:
        raise InvalidResponseError("Target reference is too long.")
    if target_type not in TARGET_TYPES:
        raise InvalidResponseError(f"Unsupported target type: {target_type!r}.")
    if target_type == TARGET_IP:
        try:
            ipaddress.ip_address(reference)
        except ValueError:
            raise InvalidResponseError(
                f"Target is not a valid IP address: {reference!r}."
            ) from None
    if target_type == TARGET_HOSTNAME:
        _validate_hostname(reference)


def _audit(
    db: Session,
    action: ResponseAction,
    event: str,
    actor: str,
    previous_status: str | None,
    new_status: str | None,
) -> None:
    from app.core.request_context import current_request_id_or_new

    db.add(
        ResponseAudit(
            action_id=action.id,
            incident_id=action.incident_id,
            event=event,
            previous_status=previous_status,
            new_status=new_status,
            actor=actor,
            policy_version=POLICY_VERSION,
            # Step 31: correlation id of the originating request. Nullable
            # because rows written outside a request have none; sanitised
            # by app.core.request_context, never caller text.
            request_id=current_request_id_or_new() or None,
        )
    )


def propose_action(
    db: Session,
    incident_id: str,
    action_type: str,
    target_type: str,
    target_reference: str,
    reason: str,
    requested_by: str,
    dry_run: bool = True,
) -> tuple[ResponseAction, bool]:
    """Validate, then create or return the proposal. dry_run must stay true."""
    if action_type not in ACTION_TYPES:
        raise InvalidResponseError(f"Unsupported action type: {action_type!r}.")
    validate_target(target_type, target_reference)
    if is_safe_action(action_type):
        # Safe actions address the incident record itself: the target
        # must name this proposal's incident, keeping identity and
        # validation uniform with every other proposal.
        if target_type != TARGET_INCIDENT or target_reference.strip() != incident_id:
            raise InvalidResponseError(
                "Safe actions must target the incident itself "
                "(target_type INCIDENT with the incident id)."
            )
    elif target_type == TARGET_INCIDENT:
        raise InvalidResponseError("Only safe foundation actions may target an incident record.")
    if not (reason or "").strip():
        raise InvalidResponseError("Reason must not be empty.")
    if not (requested_by or "").strip():
        raise InvalidResponseError("Requested-by must not be empty.")
    if dry_run is not True:
        raise InvalidResponseError("Only dry-run proposals are supported; dry_run must be true.")
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if incident is None:
        raise ResponseNotFoundError(f"No incident with id {incident_id}.")

    row_id = action_id(
        incident_id, action_type, target_type, target_reference.strip(), requested_by.strip()
    )
    existing = db.scalar(select(ResponseAction).where(ResponseAction.id == row_id))
    if existing is not None:
        return existing, False

    row = ResponseAction(
        id=row_id,
        incident_id=incident.id,
        action_type=action_type,
        target_type=target_type,
        target_reference=target_reference.strip(),
        reason=reason.strip(),
        requested_by=requested_by.strip(),
        status=STATUS_PROPOSED,
        dry_run=True,
        policy_version=POLICY_VERSION,
    )
    db.add(row)
    db.flush()
    _audit(db, row, EVENT_PROPOSED, row.requested_by, None, STATUS_PROPOSED)
    db.commit()
    db.refresh(row)
    logger.info("Response proposal %s opened for incident %s", row.id[:12], incident_id[:12])
    return row, True


def _transition(
    db: Session, action: ResponseAction, new_status: str, actor: str, event: str
) -> ResponseAction:
    allowed = TRANSITIONS.get(action.status, ())
    if new_status not in allowed:
        raise InvalidResponseTransitionError(
            f"Cannot move response from {action.status} to {new_status}."
        )
    previous = action.status
    action.status = new_status
    if new_status == STATUS_APPROVED:
        action.approved_at = _utcnow_naive()
        action.expires_at = action.approved_at + timedelta(days=APPROVAL_TTL_DAYS)
        # Approval identity is stamped once here; no transition ever
        # re-enters APPROVED, so it can never be silently rewritten.
        action.approved_by = actor
    _audit(db, action, event, actor, previous, new_status)
    db.commit()
    db.refresh(action)
    return action


def approve_action(db: Session, action: ResponseAction, actor: str) -> ResponseAction:
    return _transition(db, action, STATUS_APPROVED, actor, EVENT_APPROVED)


def reject_action(db: Session, action: ResponseAction, actor: str) -> ResponseAction:
    return _transition(db, action, STATUS_REJECTED, actor, EVENT_REJECTED)


def cancel_action(db: Session, action: ResponseAction, actor: str) -> ResponseAction:
    return _transition(db, action, STATUS_CANCELLED, actor, EVENT_CANCELLED)


def dry_run_result(action: ResponseAction) -> dict[str, object]:
    """Pure preview of a proposal. Always reports that nothing executed."""
    return {
        "action_id": action.id,
        "action_type": action.action_type,
        "target": f"{action.target_type}:{action.target_reference}",
        "dry_run": True,
        "would_execute": False,
        "result": "SIMULATED",
        "explanation": _DRY_RUN_EXPLANATIONS.get(
            action.action_type, "Action would be simulated only."
        )
        + " No action was executed.",
        "policy_version": POLICY_VERSION,
    }


def record_dry_run(db: Session, action: ResponseAction) -> dict[str, object]:
    """Preview a proposal: audit the dry run and advance the lifecycle.

    PROPOSED and APPROVED both move to DRY_RUN_COMPLETED (the specified
    APPROVED → DRY_RUN_COMPLETED edge); any other status only records
    the preview audit. The dry-run result itself is pure.
    """
    result = dry_run_result(action)
    if action.status in (STATUS_PROPOSED, STATUS_APPROVED):
        _transition(
            db, action, STATUS_DRY_RUN_COMPLETED, action.requested_by, EVENT_DRY_RUN_COMPLETED
        )
    else:
        _audit(
            db, action, EVENT_DRY_RUN_COMPLETED, action.requested_by, action.status, action.status
        )
        db.commit()
        db.refresh(action)
    return result


def execution_id(action_id: str) -> str:
    """Deterministic identity for an execution record. No time, no randomness."""
    canonical = json.dumps(["response-execution:v1", action_id], separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def get_execution(db: Session, action_id: str):
    """Return the stored execution row for an action, if any."""
    from app.models.responses import ResponseExecution

    return db.scalar(select(ResponseExecution).where(ResponseExecution.action_id == action_id))


def persist_execution(db: Session, action: ResponseAction, result: dict[str, object], actor: str):
    """Store a simulation result and advance the action. Simulation only."""
    from app.models.responses import ResponseExecution

    _audit(db, action, EVENT_EXECUTION_REQUESTED, actor, action.status, action.status)
    row = ResponseExecution(
        id=execution_id(action.id),
        action_id=action.id,
        incident_id=action.incident_id,
        adapter="simulation",
        dry_run=True,
        would_execute=False,
        result="SIMULATED",
        explanation=str(result.get("explanation", "")),
        policy_version=POLICY_VERSION,
    )
    db.add(row)
    action.status = STATUS_READY_FOR_EXECUTION
    action.execution_status = "SIMULATED"
    _audit(
        db,
        action,
        EVENT_EXECUTION_COMPLETED,
        actor,
        STATUS_DRY_RUN_COMPLETED,
        STATUS_READY_FOR_EXECUTION,
    )
    db.commit()
    db.refresh(row)
    db.refresh(action)
    return row


def record_execution_denied(db: Session, action: ResponseAction, actor: str, decision: str) -> None:
    """Audit a refused execution without changing action state."""
    _audit(db, action, EVENT_EXECUTION_DENIED, actor, action.status, action.status)
    db.commit()
    logger.info("Execution denied for %s: %s", action.id[:12], decision)


def record_preview(
    db: Session, action: ResponseAction, actor: str, adapter_name: str, would_execute: bool
) -> None:
    """Audit a Step 19 adapter preview (Step 19, read-only).

    Records that validation + adapter selection + target validation ran
    and what they concluded. Changes no workflow state and performs no
    execution of any kind.
    """
    _audit(
        db,
        action,
        EVENT_PREVIEWED,
        actor,
        action.status,
        action.status,
    )
    db.commit()
    logger.info(
        "Preview for %s via %s (would_execute=%s)",
        action.id[:12],
        adapter_name,
        would_execute,
    )


def _apply_safe_effect(db: Session, action: ResponseAction, actor: str) -> str:
    """Perform a safe action's platform-record effect. Returns a summary.

    Only incident workflow records are touched, through the existing
    incident services with their own validation. Anything the incident
    lifecycle rejects (or any unexpected failure) propagates to the
    caller, which records FAILED instead of leaking.
    """
    from app.models.incidents import IncidentEvidence

    incident = db.scalar(select(Incident).where(Incident.id == action.incident_id))
    if incident is None:
        raise ResponseNotFoundError(f"No incident with id {action.incident_id}.")
    key = incident.incident_key
    if action.action_type == ACTION_REVIEW:
        return f"Incident {key} reviewed by {actor}. No external system change was performed."
    if action.action_type == ACTION_COLLECT_EVIDENCE:
        count = (
            db.scalar(
                select(func.count(IncidentEvidence.id)).where(
                    IncidentEvidence.incident_id == incident.id
                )
            )
            or 0
        )
        return (
            f"Collected {count} evidence reference(s) for incident {key}. "
            "No external system change was performed."
        )
    if action.action_type == ACTION_ACKNOWLEDGE:
        incident_service.set_status(db, incident, incident_service.STATUS_ACKNOWLEDGED, actor)
        return f"Incident {key} acknowledged."
    if action.action_type == ACTION_MARK_FOR_INVESTIGATION:
        incident_service.set_status(db, incident, incident_service.STATUS_INVESTIGATING, actor)
        return f"Incident {key} marked for investigation."
    if action.action_type == ACTION_CLOSE:
        incident_service.set_status(db, incident, incident_service.STATUS_CLOSED, actor)
        return f"Incident {key} closed. No external system change was performed."
    raise InvalidResponseError(f"Not a safe action: {action.action_type!r}.")


def execute_safe_action(db: Session, action: ResponseAction, actor: str):
    """Execute an approved safe action synchronously (Step 18).

    APPROVED (or previewed DRY_RUN_COMPLETED) → RUNNING → COMPLETED or
    FAILED. Both outcomes persist a ``ResponseExecution`` row (adapter
    ``safe-record``), so replays return the stored row instead of
    executing twice. Failures are recorded with an honest reason;
    nothing leaks.
    """
    from app.models.responses import ResponseExecution

    if not is_safe_action(action.action_type):
        raise InvalidResponseError(f"Not a safe action: {action.action_type!r}.")
    if action.status not in (STATUS_APPROVED, STATUS_DRY_RUN_COMPLETED):
        raise InvalidResponseTransitionError(f"Cannot execute response from {action.status}.")
    previous = action.status
    action.status = STATUS_RUNNING
    action.started_at = _utcnow_naive()
    _audit(db, action, EVENT_EXECUTION_STARTED, actor, previous, STATUS_RUNNING)
    db.commit()
    db.refresh(action)
    try:
        summary = _apply_safe_effect(db, action, actor)
    except Exception as exc:
        action.status = STATUS_FAILED
        action.completed_at = _utcnow_naive()
        action.failure_reason = str(exc)
        row = ResponseExecution(
            id=execution_id(action.id),
            action_id=action.id,
            incident_id=action.incident_id,
            adapter=SAFE_ADAPTER,
            dry_run=True,
            would_execute=True,
            result=STATUS_FAILED,
            explanation=f"Safe action failed: {exc} No external system change was performed.",
            policy_version=POLICY_VERSION,
        )
        db.add(row)
        _audit(db, action, EVENT_EXECUTION_FAILED, actor, STATUS_RUNNING, STATUS_FAILED)
        db.commit()
        db.refresh(row)
        db.refresh(action)
        logger.info("Safe execution failed for %s: %s", action.id[:12], exc)
        return row
    action.status = STATUS_COMPLETED
    action.completed_at = _utcnow_naive()
    action.result_summary = summary
    action.execution_status = STATUS_COMPLETED
    row = ResponseExecution(
        id=execution_id(action.id),
        action_id=action.id,
        incident_id=action.incident_id,
        adapter=SAFE_ADAPTER,
        dry_run=True,
        would_execute=True,
        result=STATUS_COMPLETED,
        explanation=summary,
        policy_version=POLICY_VERSION,
    )
    db.add(row)
    _audit(db, action, EVENT_EXECUTION_COMPLETED, actor, STATUS_RUNNING, STATUS_COMPLETED)
    db.commit()
    db.refresh(row)
    db.refresh(action)
    logger.info("Safe execution completed for %s", action.id[:12])
    return row


__all__ = [
    "ACTION_TYPES",
    "APPROVAL_TTL_DAYS",
    "EVENT_APPROVED",
    "EVENT_CANCELLED",
    "EVENT_DRY_RUN_COMPLETED",
    "EVENT_EXECUTION_COMPLETED",
    "EVENT_EXECUTION_DENIED",
    "EVENT_EXECUTION_FAILED",
    "EVENT_EXECUTION_REQUESTED",
    "EVENT_EXECUTION_STARTED",
    "EVENT_PREVIEWED",
    "EVENT_PROPOSED",
    "EVENT_REJECTED",
    "EVENT_RESPONSE_APPROVAL_REQUIRED",
    "EVENT_RESPONSE_APPROVED",
    "EVENT_RESPONSE_CANCELLED",
    "EVENT_RESPONSE_DRY_RUN",
    "EVENT_RESPONSE_EXECUTION_COMPLETED",
    "EVENT_RESPONSE_EXECUTION_FAILED",
    "EVENT_RESPONSE_EXECUTION_STARTED",
    "EVENT_RESPONSE_EXPIRED",
    "EVENT_RESPONSE_REJECTED",
    "EVENT_RESPONSE_REQUESTED",
    "EVENT_RESPONSE_ROLLBACK_COMPLETED",
    "EVENT_RESPONSE_ROLLBACK_STARTED",
    "EVENT_RESPONSE_TARGET_REJECTED",
    "POLICY_VERSION",
    "RESPONSE_AUDIT_EVENTS",
    "SAFE_ACTION_TYPES",
    "SAFE_ADAPTER",
    "STATUSES",
    "STATUS_COMPLETED",
    "STATUS_FAILED",
    "STATUS_PENDING_APPROVAL",
    "STATUS_READY_FOR_EXECUTION",
    "STATUS_ROLLED_BACK",
    "STATUS_RUNNING",
    "TARGET_ENDPOINT",
    "TARGET_HASH",
    "TARGET_HOSTNAME",
    "TARGET_INCIDENT",
    "TARGET_INDICATOR",
    "TARGET_TYPES",
    "TRANSITIONS",
    "InvalidResponseError",
    "InvalidResponseTransitionError",
    "ResponseNotFoundError",
    "action_id",
    "approve_action",
    "cancel_action",
    "dry_run_result",
    "execute_safe_action",
    "execution_id",
    "get_execution",
    "get_execution",
    "is_safe_action",
    "persist_execution",
    "propose_action",
    "record_dry_run",
    "record_execution_denied",
    "record_preview",
    "reject_action",
    "validate_target",
]
