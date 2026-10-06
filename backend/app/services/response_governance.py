"""Controlled defensive-response governance (Step 30).

This is the decision layer between *detect / correlate / risk* and
*authorized action*. It exists so that the platform can never move
silently from detection to response:

    DETECTION -> CORRELATION -> RISK -> RECOMMENDED RESPONSE
              -> HUMAN APPROVAL -> AUTHORIZED ACTION
              -> VERIFICATION -> AUDIT

Rules that hold for every function in this module:

* The server is authoritative for action type, target, policy,
  authorization, state, provider, and expiry. No function accepts a
  policy decision, a provider name, a risk score, or an approval from a
  caller.
* A target is never accepted because a caller named it. It must be
  justified by *stored* incident evidence (the incident's correlation
  evidence events, the Step 17 evidence links, and the platform asset
  inventory). An unjustified target is rejected and audited, never
  "assumed".
* Risk score and priority are read for *reporting* and recommendation
  wording only. A high risk never causes an action to be created,
  approved, or executed.
* Nothing here executes an operating-system command, contacts a
  firewall, endpoint agent, identity provider, or cloud API. Execution
  is delegated to a registry provider (see ``response_providers``), whose
  only functioning member records a platform-side row.
* Expiry is enforced on read: an expired request or approval can never
  be executed, and approving does not extend the original window.
* Every state change appends to the existing ``response_audit`` table.
  There is no second audit system.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.assets import Asset
from app.models.events import SecurityEvent
from app.models.incidents import Incident, IncidentEvidence
from app.models.responses import ResponseAction, ResponseAudit, ResponseExecution, ResponseRollback
from app.models.risk import RiskAssessment
from app.services import incident_service, response_service, risk_service
from app.services.response_providers import (
    MOCK_PROVIDER,
    ROLLBACK_PAIRS,
    ProviderOutcome,
    ProviderTargetRejected,
    ResponseProvider,
    allowed_target_types,
    get_provider,
    is_controlled_action,
    select_provider_name,
)

logger = get_logger(__name__)

POLICY_VERSION = "1.0.0"
GOVERNANCE_VERSION = "1.0.0"
ROLLBACK_IDENTITY_NAMESPACE = "response-rollback:v1"

# Policy decisions (spec vocabulary). Stored on
# ``response_actions.policy_decision`` (String(32) - all four fit).
DECISION_NOT_ALLOWED = "NOT_ALLOWED"  # 11
DECISION_DRY_RUN_ONLY = "DRY_RUN_ONLY"  # 13
DECISION_APPROVAL_REQUIRED = "APPROVAL_REQUIRED"  # 17
DECISION_ALLOWED_WITH_APPROVAL = "ALLOWED_WITH_APPROVAL"  # 21
POLICY_DECISIONS = (
    DECISION_NOT_ALLOWED,
    DECISION_DRY_RUN_ONLY,
    DECISION_APPROVAL_REQUIRED,
    DECISION_ALLOWED_WITH_APPROVAL,
)

# Provider outcome statuses mirrored into response state / execution rows.
PROVIDER_SIMULATED = "SIMULATED"
PROVIDER_COMPLETED = "COMPLETED"
PROVIDER_FAILED = "FAILED"
PROVIDER_UNSUPPORTED = "UNSUPPORTED"

# Bounded reads. Every proof query is capped so target validation can
# never turn into an unbounded scan.
MAX_EVIDENCE_EVENTS_SCANNED = 500
MAX_EVIDENCE_REFERENCES_STORED = 20
MAX_RECOMMENDATIONS = 20
# Step 31: hard ceiling on rows retired by a single expiry sweep, so the
# read-path call that triggers it stays bounded even if a deployment has
# accumulated a large backlog of overdue requests.
MAX_EXPIRY_SCAN = 200


class TargetRejectedError(ValueError):
    """The target is not supported by stored incident evidence."""


class PolicyDeniedError(ValueError):
    """Policy refuses this action (unknown type, no provider, bad TTL)."""


def _utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


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
            actor=(actor or "operator")[:128],
            policy_version=POLICY_VERSION,
            request_id=current_request_id_or_new() or None,
        )
    )


def rollback_id(action_id: str) -> str:
    """Deterministic rollback identity. No time, no randomness."""
    canonical = json.dumps([ROLLBACK_IDENTITY_NAMESPACE, action_id], separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def resolve_ttl_minutes(requested_minutes: int | None) -> int:
    """Clamp a requested TTL into the server-controlled window.

    There is no unlimited TTL and no "permanent block" option: a request
    without a TTL gets the configured default, and a request above the
    ceiling is clamped down to it rather than rejected outright (the
    clamp is always reported).
    """
    settings = get_settings()
    ceiling = settings.response_max_ttl_minutes
    if requested_minutes is None:
        return min(settings.response_default_ttl_minutes, ceiling)
    if requested_minutes < 1:
        raise PolicyDeniedError("TTL must be at least one minute.")
    return min(int(requested_minutes), ceiling)


# ---------------------------------------------------------------------------
# Target validation against stored evidence
# ---------------------------------------------------------------------------


def _evidence_event_ids(db: Session, incident: Incident) -> list[str]:
    """Stored event ids backing this incident, newest chain first.

    Two stored chains are unioned because they are populated
    independently: the Step 24 correlation evidence (what the incident
    was actually opened from) and the Step 17 incident evidence links.
    An incident opened manually can have the first and not the second,
    so relying on only one would reject legitimately evidenced targets.
    """
    ids: list[str] = []
    if incident.correlation_id:
        ids.extend(incident_service.evidence_event_ids(db, incident.correlation_id))
    if not ids:
        links = db.scalars(
            select(IncidentEvidence.evidence_id).where(
                IncidentEvidence.incident_id == incident.id,
                IncidentEvidence.evidence_kind == incident_service.EVIDENCE_EVENT,
            )
        ).all()
        ids.extend(links)
    seen: set[str] = set()
    ordered: list[str] = []
    for value in ids:
        if value and value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def target_evidence(
    db: Session,
    incident: Incident,
    target_type: str,
    target_reference: str,
) -> list[str]:
    """Event ids that prove this target was observed in this incident.

    Returns a bounded, deterministically ordered list. An empty list
    means the platform holds no evidence for the target; the caller must
    reject it. Nothing is inferred from fields that were not stored.
    """
    reference = (target_reference or "").strip()
    if not reference:
        return []
    event_ids = _evidence_event_ids(db, incident)[:MAX_EVIDENCE_EVENTS_SCANNED]
    if not event_ids:
        return []

    rows = db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.id.in_(event_ids))
        .order_by(SecurityEvent.event_time, SecurityEvent.id)
    ).all()
    if not rows:
        return []

    from app.services.response_providers import TARGET_HASH, TARGET_INDICATOR

    if target_type in ("IP", TARGET_INDICATOR):
        matched = [
            row.id for row in rows if reference in (row.source_ip, row.destination_ip, row.hostname)
        ]
    elif target_type == "ACCOUNT":
        matched = [row.id for row in rows if reference == row.username]
    elif target_type in ("HOSTNAME", "ENDPOINT", "ASSET"):
        # A host target must be BOTH known to the platform inventory and
        # actually referenced by this incident's evidence. Knowing a host
        # exists is not evidence that this incident involves it.
        asset = db.scalar(
            select(Asset).where(or_(Asset.ip_address == reference, Asset.hostname == reference))
        )
        if asset is None:
            return []
        matched = [
            row.id
            for row in rows
            if reference in (row.source_ip, row.destination_ip, row.hostname, row.asset_id)
            or row.asset_id == asset.id
        ]
    elif target_type == TARGET_HASH:
        # Steps 1-29 store no indicator-hash field on any model, and the
        # raw/normalized JSON blobs are never interpreted. There is
        # therefore no honest way to evidence a hash target, so it is
        # reported as unsupported instead of being matched loosely.
        return []
    else:
        return []
    return sorted(matched)[:MAX_EVIDENCE_REFERENCES_STORED]


def validate_target_against_evidence(
    db: Session,
    incident: Incident,
    action_type: str,
    target_type: str,
    target_reference: str,
    provider: ResponseProvider,
) -> list[str]:
    """Provider capability check + stored-evidence proof. Raises on refusal."""
    permitted = allowed_target_types(action_type)
    if target_type not in permitted:
        raise TargetRejectedError(
            f"{action_type} cannot target {target_type}. "
            f"Permitted target types: {', '.join(permitted) if permitted else 'none'}."
        )
    try:
        provider.validate_target(target_type, target_reference)
    except ProviderTargetRejected as exc:
        raise TargetRejectedError(str(exc)) from None
    reference = (target_reference or "").strip()
    if not get_settings().response_target_evidence_required:
        return []
    evidence = target_evidence(db, incident, target_type, reference)
    if not evidence:
        raise TargetRejectedError(
            f"No stored evidence in incident {incident.incident_key} supports target "
            f"{target_type}:{reference}. Targets must be justified by observed evidence."
        )
    return evidence


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


def _incident_risk(db: Session, incident: Incident) -> tuple[int | None, str]:
    """Read-only (score, priority) for reporting. Never recalculates."""
    row = db.scalar(
        select(RiskAssessment).where(
            RiskAssessment.entity_type == risk_service.ENTITY_INCIDENT,
            RiskAssessment.entity_id == incident.id,
        )
    )
    score = row.score if row is not None else incident.risk_score
    if score is None:
        return None, risk_service.priority_for(0)
    priority = (
        row.priority if row is not None and row.priority else risk_service.priority_for(score)
    )
    return score, priority


def evaluate_policy(
    db: Session,
    action: ResponseAction,
    incident: Incident | None = None,
) -> dict[str, object]:
    """Deterministic policy verdict for a stored action. Never executes.

    The verdict is a pure function of the stored action, the stored
    evidence, the registry, the settings, and the clock. It never
    depends on who is asking.
    """
    settings = get_settings()
    if incident is None:
        incident = db.scalar(select(Incident).where(Incident.id == action.incident_id))
    provider_name = action.provider or select_provider_name(action.action_type)
    try:
        provider = get_provider(provider_name)
    except KeyError:
        return {
            "decision": DECISION_NOT_ALLOWED,
            "approval_required": True,
            "provider": provider_name,
            "provider_capable": False,
            "target_proven": False,
            "evidence_event_ids": [],
            "expires_at": action.expires_at,
            "reason": f"No registered provider: {provider_name!r}.",
            "policy_version": POLICY_VERSION,
        }

    if not is_controlled_action(action.action_type):
        return {
            "decision": DECISION_NOT_ALLOWED,
            "approval_required": True,
            "provider": provider_name,
            "provider_capable": False,
            "target_proven": False,
            "evidence_event_ids": [],
            "expires_at": action.expires_at,
            "reason": (
                f"{action.action_type} is not a controlled defensive action type. "
                "This endpoint governs Step 30 action types only."
            ),
            "policy_version": POLICY_VERSION,
        }

    allowed = allowed_target_types(action.action_type)
    evidence_ids = list(_stored_evidence(action))
    target_proven = action.target_type in allowed and bool(evidence_ids)
    if not target_proven:
        reason = (
            f"{action.action_type} cannot target {action.target_type}."
            if action.target_type not in allowed
            else (
                "No stored incident evidence supports this target. "
                "Requesting a response for an unobserved target is not permitted."
            )
        )
        return {
            "decision": DECISION_NOT_ALLOWED,
            "approval_required": True,
            "provider": provider_name,
            "provider_capable": provider.supports_execution,
            "target_proven": False,
            "evidence_event_ids": [],
            "expires_at": action.expires_at,
            "reason": reason,
            "policy_version": POLICY_VERSION,
        }

    if not provider.supports_execution:
        return {
            "decision": DECISION_DRY_RUN_ONLY,
            "approval_required": True,
            "provider": provider_name,
            "provider_capable": False,
            "target_proven": True,
            "evidence_event_ids": evidence_ids,
            "expires_at": action.expires_at,
            "reason": (
                f"Provider {provider_name} cannot perform this action in this deployment. "
                "Preview and audit remain available; execution is not."
            ),
            "policy_version": POLICY_VERSION,
        }

    approval_required = action.approval_required and not settings.response_allow_self_approval
    if action.status == response_service.STATUS_APPROVED:
        decision = DECISION_ALLOWED_WITH_APPROVAL
        reason = (
            f"{action.action_type} against {action.target_type}:{action.target_reference} is "
            f"approved and evidenced by {len(evidence_ids)} stored event(s); the provider is "
            f"{provider_name}."
        )
    else:
        decision = DECISION_APPROVAL_REQUIRED
        reason = (
            f"{action.action_type} is available because the incident contains a stored "
            f"{action.target_type} indicator supported by {len(evidence_ids)} event(s) and "
            f"policy requires human approval before the provider {provider_name} may act."
        )
    return {
        "decision": decision,
        "approval_required": approval_required,
        "provider": provider_name,
        "provider_capable": True,
        "target_proven": True,
        "evidence_event_ids": evidence_ids,
        "expires_at": action.expires_at,
        "reason": reason,
        "policy_version": POLICY_VERSION,
    }


def _stored_evidence(action: ResponseAction) -> list[str]:
    try:
        parsed = json.loads(action.target_evidence or "[]")
    except ValueError:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed][:MAX_EVIDENCE_REFERENCES_STORED]


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def get_action(db: Session, action_id: str) -> ResponseAction | None:
    return db.scalar(select(ResponseAction).where(ResponseAction.id == action_id))


def _locked_action(db: Session, action_id: str) -> ResponseAction:
    """Fetch for update so two operators cannot run one action twice.

    PostgreSQL honours SELECT ... FOR UPDATE. SQLite (used by the test
    suite) ignores it, which is safe here because every guarded
    operation re-checks the stored state inside the same transaction.
    """
    row = db.scalar(select(ResponseAction).where(ResponseAction.id == action_id).with_for_update())
    if row is None:
        raise response_service.ResponseNotFoundError(f"No response proposal with id {action_id}.")
    return row


def is_expired(action: ResponseAction, now: datetime | None = None) -> bool:
    """True when the action's bounded window has closed."""
    if action.expires_at is None:
        return False
    return (now or _utcnow_naive()) >= action.expires_at


def request_action(
    db: Session,
    incident_id: str,
    action_type: str,
    target_type: str,
    target_reference: str,
    reason: str,
    requested_by: str,
    ttl_minutes: int | None = None,
) -> tuple[ResponseAction, bool, dict[str, object]]:
    """Validate, prove the target, evaluate policy, and open a request.

    A controlled request is created in PENDING_APPROVAL - never in a
    state that could be executed. Replays return the existing row
    unchanged (deterministic identity, no duplicate action).
    """
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if incident is None:
        raise response_service.ResponseNotFoundError(f"No incident with id {incident_id}.")
    if not is_controlled_action(action_type):
        raise PolicyDeniedError(f"Not a controlled defensive action type: {action_type!r}.")
    if not (reason or "").strip():
        raise response_service.InvalidResponseError("Reason must not be empty.")
    if not (requested_by or "").strip():
        raise response_service.InvalidResponseError("Requested-by must not be empty.")

    provider_name = select_provider_name(action_type)
    try:
        provider = get_provider(provider_name)
    except KeyError:
        raise PolicyDeniedError(f"No registered provider: {provider_name!r}.") from None

    # A provider that cannot execute is still allowed to hold a request
    # (the operator can preview and audit it), so the target is validated
    # for shape and evidence regardless of provider capability.
    evidence_ids = validate_target_against_evidence(
        db, incident, action_type, target_type, target_reference, provider
    )
    ttl = resolve_ttl_minutes(ttl_minutes)
    now = _utcnow_naive()

    row_id = response_service.action_id(
        incident_id, action_type, target_type, target_reference.strip(), requested_by.strip()
    )
    existing = db.scalar(select(ResponseAction).where(ResponseAction.id == row_id))
    if existing is not None:
        return existing, False, evaluate_policy(db, existing, incident)

    row = ResponseAction(
        id=row_id,
        incident_id=incident.id,
        action_type=action_type,
        target_type=target_type,
        target_reference=target_reference.strip(),
        reason=reason.strip(),
        requested_by=requested_by.strip(),
        status=response_service.STATUS_PENDING_APPROVAL,
        dry_run=True,
        policy_version=POLICY_VERSION,
        provider=provider_name,
        approval_required=not get_settings().response_allow_self_approval,
        rollback_supported=False,
        target_evidence=json.dumps(evidence_ids, separators=(",", ":")),
        expires_at=now + timedelta(minutes=ttl),
    )
    db.add(row)
    db.flush()
    _audit(db, row, response_service.EVENT_RESPONSE_REQUESTED, row.requested_by, None, row.status)
    _audit(
        db,
        row,
        response_service.EVENT_RESPONSE_APPROVAL_REQUIRED,
        row.requested_by,
        row.status,
        row.status,
    )
    db.commit()
    db.refresh(row)
    verdict = evaluate_policy(db, row, incident)
    row.policy_decision = str(verdict["decision"])
    db.commit()
    db.refresh(row)
    logger.info(
        "Controlled response %s requested for incident %s (%s, provider %s)",
        row.id[:12],
        incident_id[:12],
        row.action_type,
        provider_name,
    )
    return row, True, verdict


def _record_target_rejection(db: Session, incident: Incident, actor: str, message: str) -> None:
    """Audit a refused target without creating an action row.

    A rejected target produces no ResponseAction (nothing was requested
    successfully), so the attempt is recorded on the incident audit trail
    where it is still attributable and append-only.
    """
    incident_service.record_audit(
        db,
        incident.id,
        response_service.EVENT_RESPONSE_TARGET_REJECTED,
        (actor or "operator")[:128],
        message[:2000],
    )
    db.commit()


def dry_run(db: Session, action_id: str, actor: str) -> dict[str, object]:
    """Validate, preview, and audit. Performs nothing, ever."""
    action = _locked_action(db, action_id)
    incident = db.scalar(select(Incident).where(Incident.id == action.incident_id))
    if incident is None:
        raise response_service.ResponseNotFoundError(f"No incident with id {action.incident_id}.")
    provider = get_provider(action.provider or select_provider_name(action.action_type))
    try:
        provider.validate_target(action.target_type, action.target_reference)
    except ProviderTargetRejected as exc:
        _audit(
            db,
            action,
            response_service.EVENT_RESPONSE_TARGET_REJECTED,
            actor,
            action.status,
            action.status,
        )
        db.commit()
        raise TargetRejectedError(str(exc)) from None
    outcome = provider.preview_action(_provider_request(action))
    _audit(db, action, response_service.EVENT_RESPONSE_DRY_RUN, actor, action.status, action.status)
    db.commit()
    verdict = evaluate_policy(db, action, incident)
    return {
        "action_id": action.id,
        "incident_id": action.incident_id,
        "action_type": action.action_type,
        "target": f"{action.target_type}:{action.target_reference}",
        "provider": outcome.provider,
        "dry_run": True,
        "would_execute": True,
        "executed": False,
        "result": outcome.status,
        "explanation": outcome.result_summary,
        "changes": list(outcome.changes),
        "evidence_event_ids": _stored_evidence(action),
        "policy_decision": verdict["decision"],
        "policy_reason": verdict["reason"],
        "expires_at": action.expires_at,
        "policy_version": POLICY_VERSION,
        "governance_version": GOVERNANCE_VERSION,
    }


def _provider_request(action: ResponseAction) -> dict[str, object]:
    return {
        "action_id": action.id,
        "incident_id": action.incident_id,
        "action_type": action.action_type,
        "target_type": action.target_type,
        "target_reference": action.target_reference,
        "approved_by": action.approved_by,
        "requested_by": action.requested_by,
        "rollback_reference": action.rollback_reference,
        "policy_version": POLICY_VERSION,
    }


def approve(db: Session, action_id: str, actor: str) -> ResponseAction:
    """Second-human approval with separation of duties and an expiry guard.

    Only a request still in PENDING_APPROVAL may be approved. A rejected,
    cancelled, expired, completed, or already-approved action is refused
    with a transition error rather than being revived.
    """
    settings = get_settings()
    action = _locked_action(db, action_id)
    if action.status != response_service.STATUS_PENDING_APPROVAL:
        raise response_service.InvalidResponseTransitionError(
            f"Cannot approve a response in status {action.status}."
        )
    if is_expired(action):
        _expire(db, action, actor)
        raise response_service.InvalidResponseTransitionError(
            "This request expired before it was approved; it can no longer be approved."
        )
    if (
        action.approval_required
        and not settings.response_allow_self_approval
        and action.requested_by == actor
    ):
        _audit(
            db,
            action,
            response_service.EVENT_RESPONSE_APPROVAL_REQUIRED,
            actor,
            action.status,
            action.status,
        )
        db.commit()
        raise response_service.InvalidResponseTransitionError(
            "A consequential response must be approved by a different user than requested it."
        )
    previous = action.status
    if response_service.STATUS_APPROVED not in response_service.TRANSITIONS[previous]:
        raise response_service.InvalidResponseTransitionError(
            f"Cannot move response from {previous} to APPROVED."
        )
    action.status = response_service.STATUS_APPROVED
    action.approved_at = _utcnow_naive()
    action.approved_by = actor
    # The approval window is the ORIGINAL requested window. Approving
    # never extends it, so a stale request cannot be revived by a late
    # approval.
    if action.expires_at is None:
        action.expires_at = action.approved_at + timedelta(
            minutes=settings.response_default_ttl_minutes
        )
    _audit(db, action, response_service.EVENT_RESPONSE_APPROVED, actor, previous, action.status)
    db.commit()
    db.refresh(action)
    return action


def reject(db: Session, action_id: str, actor: str) -> ResponseAction:
    action = _locked_action(db, action_id)
    if action.status != response_service.STATUS_PENDING_APPROVAL:
        raise response_service.InvalidResponseTransitionError(
            f"Cannot reject a response in status {action.status}."
        )
    previous = action.status
    action.status = response_service.STATUS_REJECTED
    _audit(db, action, response_service.EVENT_RESPONSE_REJECTED, actor, previous, action.status)
    db.commit()
    db.refresh(action)
    return action


def cancel(db: Session, action_id: str, actor: str) -> ResponseAction:
    action = _locked_action(db, action_id)
    if action.status not in (
        response_service.STATUS_PENDING_APPROVAL,
        response_service.STATUS_APPROVED,
    ):
        raise response_service.InvalidResponseTransitionError(
            f"Cannot cancel a response in status {action.status}."
        )
    previous = action.status
    action.status = response_service.STATUS_CANCELLED
    _audit(db, action, response_service.EVENT_RESPONSE_CANCELLED, actor, previous, action.status)
    db.commit()
    db.refresh(action)
    return action


def _expire(db: Session, action: ResponseAction, actor: str) -> None:
    """Mark one action EXPIRED and audit it, without committing.

    Step 31: the caller owns the transaction. Previously this committed
    per row, which meant a single read-path call could open hundreds of
    transactions; ``expire_due`` now commits once for the whole batch.
    """
    previous = action.status
    action.status = response_service.STATUS_EXPIRED
    _audit(db, action, response_service.EVENT_RESPONSE_EXPIRED, actor, previous, action.status)


def expire_due(db: Session, incident_id: str | None = None) -> list[str]:
    """Expire every overdue pending/approved request. Audited, bounded.

    Called on read paths (list/detail/execute) rather than by a
    background worker, because this platform has no scheduler. The
    whole batch is one SELECT and at most one COMMIT, and the filter is
    ordered by the (now indexed) ``expires_at`` column so the hot path
    touches only genuinely overdue rows.
    """
    query = (
        select(ResponseAction)
        .where(
            ResponseAction.status.in_(
                (
                    response_service.STATUS_PENDING_APPROVAL,
                    response_service.STATUS_APPROVED,
                )
            ),
            ResponseAction.expires_at.is_not(None),
            ResponseAction.expires_at <= _utcnow_naive(),
        )
        .order_by(ResponseAction.expires_at)
    )
    if incident_id is not None:
        query = query.where(ResponseAction.incident_id == incident_id)
    rows = db.scalars(query.limit(MAX_EXPIRY_SCAN)).all()
    if not rows:
        return []
    expired: list[str] = []
    for row in rows:
        _expire(db, row, "system")
        expired.append(row.id)
    db.commit()
    return expired


def execute(
    db: Session,
    action_id: str,
    actor: str,
    idempotency_key: str | None = None,
) -> tuple[ResponseExecution, bool]:
    """Execute an approved action through its registry provider.

    Returns ``(execution_row, created)``. A repeat call replays the
    stored row and performs nothing: the deterministic execution id and
    the UNIQUE constraint on ``response_executions.action_id`` make
    double execution impossible even under a race.
    """
    action = _locked_action(db, action_id)
    if action.status == response_service.STATUS_ROLLED_BACK:
        # A rolled-back action must never be re-performed, and must not be
        # reported as still standing: refuse even though the original
        # execution row exists.
        raise response_service.InvalidResponseTransitionError(
            "This response was rolled back and cannot be executed again."
        )
    # Idempotency: a repeat execute of a still-standing action (including
    # an already-completed one) replays the stored row instead of acting
    # twice, so a retried request is always safe.
    existing = db.scalar(select(ResponseExecution).where(ResponseExecution.action_id == action_id))
    if existing is not None:
        return existing, False
    if is_expired(action):
        _expire(db, action, actor)
        raise response_service.InvalidResponseTransitionError(
            "This response expired and can no longer be executed."
        )
    if action.status != response_service.STATUS_APPROVED:
        raise response_service.InvalidResponseTransitionError(
            f"Cannot execute a response in status {action.status}."
        )
    if not action.approved_by:
        raise response_service.InvalidResponseTransitionError(
            "This response has no recorded approver and cannot be executed."
        )
    provider = get_provider(action.provider or select_provider_name(action.action_type))
    if not provider.supports_execution:
        raise PolicyDeniedError(
            f"Provider {provider.name} cannot execute this action in this deployment."
        )

    previous = action.status
    action.status = response_service.STATUS_RUNNING
    action.started_at = _utcnow_naive()
    _audit(
        db,
        action,
        response_service.EVENT_RESPONSE_EXECUTION_STARTED,
        actor,
        previous,
        action.status,
    )
    db.commit()
    db.refresh(action)

    outcome: ProviderOutcome = provider.execute_action(_provider_request(action))
    completed_at = _utcnow_naive()
    if outcome.status == PROVIDER_COMPLETED:
        action.status = response_service.STATUS_COMPLETED
        action.completed_at = completed_at
        action.result_summary = outcome.result_summary
        action.execution_status = PROVIDER_COMPLETED
        action.rollback_supported = outcome.rollback_supported
        action.rollback_reference = outcome.rollback_reference
        event = response_service.EVENT_RESPONSE_EXECUTION_COMPLETED
    else:
        action.status = response_service.STATUS_FAILED
        action.completed_at = completed_at
        action.failure_reason = outcome.failure_reason or outcome.result_summary
        action.result_summary = outcome.result_summary
        action.execution_status = PROVIDER_FAILED
        action.rollback_supported = False
        action.rollback_reference = None
        event = response_service.EVENT_RESPONSE_EXECUTION_FAILED
    row = ResponseExecution(
        id=response_service.execution_id(action.id),
        action_id=action.id,
        incident_id=action.incident_id,
        adapter=outcome.provider,
        dry_run=False,
        would_execute=True,
        result=PROVIDER_COMPLETED if outcome.executed else PROVIDER_FAILED,
        explanation=outcome.result_summary,
        policy_version=POLICY_VERSION,
    )
    db.add(row)
    _audit(db, action, event, actor, response_service.STATUS_RUNNING, action.status)
    db.commit()
    db.refresh(row)
    db.refresh(action)
    logger.info(
        "Controlled response %s execution finished as %s (provider %s)",
        action.id[:12],
        action.status,
        outcome.provider,
    )
    return row, True


def rollback(db: Session, action_id: str, actor: str) -> ResponseRollback:
    """Explicit, separately authorized rollback of a completed action.

    Never guesses the previous state: if the provider recorded no
    prior-state reference, the rollback is recorded as UNSUPPORTED with
    an honest explanation instead of a fabricated compensating action.
    """
    existing = db.scalar(select(ResponseRollback).where(ResponseRollback.action_id == action_id))
    if existing is not None:
        return existing

    action = _locked_action(db, action_id)
    if action.status != response_service.STATUS_COMPLETED:
        raise response_service.InvalidResponseTransitionError(
            f"Cannot roll back a response in status {action.status}."
        )
    expected = ROLLBACK_PAIRS.get(action.action_type)
    if expected is None:
        raise PolicyDeniedError(f"{action.action_type} has no defined rollback action.")
    if not action.rollback_reference:
        row = ResponseRollback(
            id=rollback_id(action.id),
            action_id=action.id,
            incident_id=action.incident_id,
            provider=action.provider,
            result=PROVIDER_UNSUPPORTED,
            explanation=(
                f"Rollback is unsupported: the provider {action.provider} recorded no prior "
                f"state for {action.action_type}, and the platform will not guess one. The "
                f"expected inverse action is {expected}."
            ),
            policy_version=POLICY_VERSION,
        )
        db.add(row)
        action.rollback_state = PROVIDER_UNSUPPORTED
        _audit(
            db,
            action,
            response_service.EVENT_RESPONSE_ROLLBACK_STARTED,
            actor,
            action.status,
            action.status,
        )
        _audit(
            db,
            action,
            response_service.EVENT_RESPONSE_ROLLBACK_COMPLETED,
            actor,
            action.status,
            action.status,
        )
        db.commit()
        db.refresh(row)
        return row

    provider = get_provider(action.provider)
    _audit(
        db,
        action,
        response_service.EVENT_RESPONSE_ROLLBACK_STARTED,
        actor,
        action.status,
        action.status,
    )
    db.commit()
    outcome = provider.rollback_action(_provider_request(action))
    if outcome.status == PROVIDER_COMPLETED:
        result = PROVIDER_COMPLETED
        action.status = response_service.STATUS_ROLLED_BACK
        action.rollback_state = PROVIDER_COMPLETED
    else:
        result = PROVIDER_FAILED
        action.rollback_state = PROVIDER_FAILED
    row = ResponseRollback(
        id=rollback_id(action.id),
        action_id=action.id,
        incident_id=action.incident_id,
        provider=outcome.provider,
        result=result,
        explanation=outcome.result_summary,
        policy_version=POLICY_VERSION,
    )
    db.add(row)
    _audit(
        db,
        action,
        response_service.EVENT_RESPONSE_ROLLBACK_COMPLETED,
        actor,
        action.status,
        action.status,
    )
    db.commit()
    db.refresh(row)
    db.refresh(action)
    return row


# ---------------------------------------------------------------------------
# Deterministic recommendations (spec 18)
# ---------------------------------------------------------------------------


def recommendations(db: Session, incident: Incident) -> list[dict[str, object]]:
    """Actions the stored evidence makes available, with the reason.

    Deterministic: derived only from stored event fields, the platform
    inventory, the action allow-list, and provider capability. No
    scoring, no learning, no ranking preference - and nothing here is
    ever executed. Availability never implies permission.
    """
    rows = db.scalars(
        select(SecurityEvent)
        .where(
            SecurityEvent.id.in_(_evidence_event_ids(db, incident)[:MAX_EVIDENCE_EVENTS_SCANNED])
        )
        .order_by(SecurityEvent.event_time, SecurityEvent.id)
    ).all()
    if not rows:
        return []
    _, priority = _incident_risk(db, incident)
    provider = get_provider(MOCK_PROVIDER)

    observed_ips = sorted(
        {value for row in rows for value in (row.source_ip, row.destination_ip) if value}
    )
    observed_accounts = sorted({row.username for row in rows if row.username})
    known_assets = db.scalars(
        select(Asset)
        .where(
            or_(
                Asset.ip_address.in_(observed_ips or [""]),
                Asset.hostname.in_([r.hostname for r in rows if r.hostname] or [""]),
            )
        )
        .order_by(Asset.id)
    ).all()

    out: list[dict[str, object]] = []

    def add(
        action_type: str,
        target_type: str,
        target_reference: str,
        evidence_ids: list[str],
        available: bool,
        blocked: str | None,
    ) -> None:
        if len(out) >= MAX_RECOMMENDATIONS:
            return
        if target_type not in allowed_target_types(action_type):
            return
        out.append(
            {
                "action_type": action_type,
                "target_type": target_type,
                "target_reference": target_reference,
                "incident_id": incident.id,
                "incident_key": incident.incident_key,
                "severity": incident.severity,
                "risk_priority": priority,
                "available": available,
                "provider": select_provider_name(action_type),
                "evidence_event_ids": evidence_ids,
                "reason": (
                    f"Indicator blocking is available because the incident contains a stored "
                    f"{target_type} indicator supported by {len(evidence_ids)} event(s) and the "
                    f"configured policy permits this action after human approval."
                    if available
                    else blocked
                ),
                "requires_approval": True,
                "automatic": False,
            }
        )

    # Step 31: build the evidence index ONCE from the event set already
    # loaded above. The previous implementation called target_evidence()
    # inside these three loops, which re-ran the evidence-event query and
    # the event fetch once per candidate address/account/asset (an N+1
    # with an unbounded loop). Total queries here are now fixed: events,
    # risk, assets.
    evidence_by_ip: dict[str, list[str]] = {}
    evidence_by_account: dict[str, list[str]] = {}
    evidence_by_host: dict[str, list[str]] = {}
    for row in rows:
        for address in (row.source_ip, row.destination_ip, row.hostname):
            if address:
                bucket = evidence_by_ip.setdefault(address, [])
                if row.id not in bucket:
                    bucket.append(row.id)
        if row.username:
            bucket = evidence_by_account.setdefault(row.username, [])
            if row.id not in bucket:
                bucket.append(row.id)
        if row.asset_id:
            bucket = evidence_by_host.setdefault(row.asset_id, [])
            if row.id not in bucket:
                bucket.append(row.id)

    def _bounded(values: list[str]) -> list[str]:
        return sorted(values)[:MAX_EVIDENCE_REFERENCES_STORED]

    for address in observed_ips:
        # An IP/hostname target is evidenced by the events that carried it;
        # a host that is ALSO in the inventory is the ASSET case below.
        evidence = _bounded(evidence_by_ip.get(address, []))
        add(
            "BLOCK_INDICATOR",
            "IP",
            address,
            evidence,
            bool(evidence) and provider.supports_execution,
            None if evidence else "No stored evidence supports this indicator.",
        )
    for account in observed_accounts:
        evidence = _bounded(evidence_by_account.get(account, []))
        add(
            "DISABLE_ACCOUNT",
            "ACCOUNT",
            account,
            evidence,
            bool(evidence) and provider.supports_execution,
            None if evidence else "No stored evidence supports this identity.",
        )
    for asset in known_assets:
        evidence = _bounded(
            evidence_by_host.get(asset.id, []) + evidence_by_ip.get(asset.ip_address, [])
        )
        add(
            "ISOLATE_ENDPOINT",
            "ASSET",
            asset.id,
            evidence,
            bool(evidence) and provider.supports_execution,
            None if evidence else "The asset is known but no incident evidence references it.",
        )
    return out


__all__ = [
    "DECISION_ALLOWED_WITH_APPROVAL",
    "DECISION_APPROVAL_REQUIRED",
    "DECISION_DRY_RUN_ONLY",
    "DECISION_NOT_ALLOWED",
    "GOVERNANCE_VERSION",
    "MAX_EVIDENCE_EVENTS_SCANNED",
    "MAX_EVIDENCE_REFERENCES_STORED",
    "MAX_RECOMMENDATIONS",
    "POLICY_DECISIONS",
    "POLICY_VERSION",
    "PolicyDeniedError",
    "TargetRejectedError",
    "approve",
    "cancel",
    "evaluate_policy",
    "execute",
    "expire_due",
    "get_action",
    "is_expired",
    "recommendations",
    "reject",
    "request_action",
    "resolve_ttl_minutes",
    "rollback",
    "rollback_id",
    "target_evidence",
    "validate_target_against_evidence",
]
