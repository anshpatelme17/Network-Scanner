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

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.assets import Asset
from app.models.events import SecurityEvent
from app.models.incidents import Incident, IncidentEvidence
from app.models.responses import ResponseAction, ResponseAudit, ResponseExecution, ResponseRollback
from app.models.risk import RiskAssessment
from app.services import incident_service, response_service, risk_service
from app.services.response_providers import (
    CONTROLLED_ACTION_TYPES,
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

# Step 40: the "expiring soon" warning window. A WARNING threshold only:
# it never extends, shortens, or otherwise alters an action's actual TTL
# or expiry enforcement, both of which remain governed by
# ``is_expired``/``expire_due`` and the configured TTL ceiling.
EXPIRY_WARNING_HOURS = 72

# Step 40: payload version for the read-only Response Center summary.
RESPONSE_CENTER_VERSION = "1"

# Step 40: the lifecycle states a controlled-response row can occupy.
# ``PROPOSED`` and ``READY_FOR_EXECUTION`` are deliberately absent: they
# belong to the Step 12-19 proposal flow, which a controlled request
# never enters (one is created in PENDING_APPROVAL and leaves it only
# through approve / reject / cancel / expire / dry-run). Every key is
# always reported, including zeros, so a client never has to guess
# whether a missing key means "none" or "not reported".
RESPONSE_CENTER_STATUSES = (
    response_service.STATUS_PENDING_APPROVAL,
    response_service.STATUS_APPROVED,
    response_service.STATUS_REJECTED,
    response_service.STATUS_CANCELLED,
    response_service.STATUS_EXPIRED,
    response_service.STATUS_DRY_RUN_COMPLETED,
    response_service.STATUS_RUNNING,
    response_service.STATUS_COMPLETED,
    response_service.STATUS_FAILED,
    response_service.STATUS_ROLLED_BACK,
)

# Step 40: server-side cap on each returned list. Mirrors the module's
# existing MAX_LIMIT conventions, so a caller can widen the window but
# never remove the bound.
RESPONSE_CENTER_MAX_LIMIT = 200
RESPONSE_CENTER_DEFAULT_LIMIT = 100


class TargetRejectedError(ValueError):
    """The target is not supported by stored incident evidence."""


class PolicyDeniedError(ValueError):
    """Policy refuses this action (unknown type, no provider, bad TTL)."""


def _utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


# Step 41: hard ceiling on an operator-supplied rejection reason. The
# request schema enforces the same bound so an over-long reason is
# refused with a 422 rather than silently truncated; the service clamp
# below is the backstop for a direct service caller.
MAX_REJECTION_REASON = 2000


def _sanitize_rejection_reason(reason: str | None) -> str | None:
    """Trim and bound an optional operator-supplied rejection reason.

    A whitespace-only or absent reason becomes ``None`` so the audit row
    records no rationale rather than an empty-looking one. The value is
    only ever operator text: no exception detail, server message, or
    caller-controlled server state is interpolated here.
    """
    cleaned = (reason or "").strip()
    if not cleaned:
        return None
    return cleaned[:MAX_REJECTION_REASON]


def _audit(
    db: Session,
    action: ResponseAction,
    event: str,
    actor: str,
    previous_status: str | None,
    new_status: str | None,
    detail: str | None = None,
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
            # Optional, already-sanitised operator rationale. Only the
            # rejection path supplies one; every other lifecycle event
            # and every legacy row keeps NULL.
            detail=detail,
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


def _incident_risk(db: Session, incident: Incident) -> tuple[int | None, str | None]:
    """Read-only (score, priority) from the incident's linked assessment.

    The assessment is authoritative. When the incident has no valid linked
    assessment the result is ``(None, None)``: the raw ``risk_score``
    snapshot is never trusted on its own, so a detached or evicted
    assessment can never be reported as current risk, and no band is
    invented for a missing score. Never recalculates.
    """
    if incident.risk_assessment_id is None:
        return None, None
    row = db.get(RiskAssessment, incident.risk_assessment_id)
    if row is None:
        return None, None
    score = int(row.score)
    priority = row.priority or risk_service.priority_for(score)
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


def reject(
    db: Session, action_id: str, actor: str, reason: str | None = None
) -> ResponseAction:
    """Refuse a pending request, recording why if the approver said.

    Only a request still in PENDING_APPROVAL may be rejected. The status
    change and the audit row are appended to the same transaction and
    committed together, so a request can never be REJECTED without its
    audit trail — if the audit write fails, the decision fails closed and
    no state is left behind.

    ``reason`` is optional operator text. It is sanitised before storage
    and is never sourced from a server exception or internal message.
    """
    action = _locked_action(db, action_id)
    if action.status != response_service.STATUS_PENDING_APPROVAL:
        raise response_service.InvalidResponseTransitionError(
            f"Cannot reject a response in status {action.status}."
        )
    previous = action.status
    action.status = response_service.STATUS_REJECTED
    _audit(
        db,
        action,
        response_service.EVENT_RESPONSE_REJECTED,
        actor,
        previous,
        action.status,
        _sanitize_rejection_reason(reason),
    )
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


def expire_due(db: Session, incident_id: str | None = None, now: datetime | None = None) -> list[str]:
    """Expire every overdue pending/approved request. Audited, bounded.

    Called on read paths (list/detail/summary) rather than by a
    background worker, because this platform has no scheduler. The
    whole batch is one SELECT and at most one COMMIT, and the filter is
    ordered by the (now indexed) ``expires_at`` column so the hot path
    touches only genuinely overdue rows.

    ``now`` lets a caller that already captured one timestamp for a
    request retire overdue rows against that same instant, so a single
    read cannot make two subtly different decisions about the same
    deadline. It defaults to the current time, which is what every
    existing call site already relied on.
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
            ResponseAction.expires_at <= (now or _utcnow_naive()),
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


# ---------------------------------------------------------------------------
# Step 40: read-only Response Center summary
# ---------------------------------------------------------------------------


def _controlled_only() -> ColumnElement[bool]:
    """SQL predicate for "this row is a Step 30 controlled response".

    ``response_providers.is_controlled_action`` is the authoritative
    predicate and is membership in ``CONTROLLED_ACTION_TYPES``; this is the
    same test expressed for SQL so the summary and the policy layer can
    never disagree about which rows are governed.
    """
    return ResponseAction.action_type.in_(CONTROLLED_ACTION_TYPES)


def _summary_row(row: ResponseAction) -> dict[str, object]:
    """One action as plain data. Mirrors the Step 30 wire shape exactly."""
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
        "provider": row.provider,
        "policy_decision": row.policy_decision,
        "approval_required": row.approval_required,
        "rollback_supported": row.rollback_supported,
        "rollback_state": row.rollback_state,
        "rollback_reference": row.rollback_reference,
        "target_evidence": _stored_evidence(row),
        "execution_status": row.execution_status,
        "created_at": row.created_at,
        "approved_at": row.approved_at,
        "expires_at": row.expires_at,
        "approved_by": row.approved_by,
        "started_at": row.started_at,
        "completed_at": row.completed_at,
        "failure_reason": row.failure_reason,
        "result_summary": row.result_summary,
    }


def build_response_center_summary(
    db: Session,
    *,
    limit: int = RESPONSE_CENTER_DEFAULT_LIMIT,
    offset: int = 0,
) -> dict[str, object]:
    """Aggregate stored controlled-response state for the Response Center.

    Read-only apart from the shared, already-established read-path expiry
    sweep, and deterministic for a given stored state:

    * Only Step 30 controlled actions are included. Legacy Step 12/13/18/19
      proposal rows are excluded by ``_controlled_only()`` so a dry-run
      proposal can never appear next to a governed request.
    * ``counts`` and ``total`` are complete aggregates - never bounded -
      so they are safe to render as exact numbers.
    * The two lists are bounded by ``limit``/``offset`` over a
      deterministic ``(expires_at, id)`` ordering, and ``truncated`` says
      so honestly when either list was cut short.
    * ``expiring_soon`` is a pure function of ``expires_at``: strictly in
      the future and within ``EXPIRY_WARNING_HOURS``. It is a warning
      only, never an enforcement decision, and it excludes rows that have
      already expired and rows with no expiry at all.
    * Query count is fixed (expiry sweep, one grouped count, one pending
      list, one expiry count, one expiry list) regardless of table size;
      there is no per-row query.

    ``expire_due`` is called once, exactly as the existing list and detail
    endpoints already do, so overdue requests are retired and audited by
    the same code path rather than a second, divergent one.
    """
    capped_limit = max(1, min(int(limit), RESPONSE_CENTER_MAX_LIMIT))
    capped_offset = max(0, int(offset))

    # One timestamp captured for the whole request, so every comparison
    # below is against the same instant rather than a drifting clock.
    now = _utcnow_naive()
    expire_due(db, now=now)

    controlled = _controlled_only()
    observed = dict(
        db.execute(
            select(ResponseAction.status, func.count(ResponseAction.id)).where(controlled)
            .group_by(ResponseAction.status)
        ).all()
    )
    counts: dict[str, int] = {status: 0 for status in RESPONSE_CENTER_STATUSES}
    for status, count in observed.items():
        # A status outside the canonical vocabulary is reported rather
        # than silently dropped: hiding a row would be the dishonest
        # outcome, and none is expected because the set is closed.
        counts[str(status)] = counts.get(str(status), 0) + int(count)
    total = sum(counts.values())

    pending_where = (controlled, ResponseAction.status == response_service.STATUS_PENDING_APPROVAL)
    pending_total = counts.get(response_service.STATUS_PENDING_APPROVAL, 0)
    pending_rows = db.scalars(
        select(ResponseAction)
        .where(*pending_where)
        .order_by(ResponseAction.expires_at, ResponseAction.id)
        .limit(capped_limit)
        .offset(capped_offset)
    ).all()

    horizon = now + timedelta(hours=EXPIRY_WARNING_HOURS)
    expiring_where = (
        controlled,
        ResponseAction.expires_at.is_not(None),
        ResponseAction.expires_at > now,
        ResponseAction.expires_at <= horizon,
    )
    expiring_total = int(
        db.scalar(select(func.count()).select_from(ResponseAction).where(*expiring_where)) or 0
    )
    expiring_rows = db.scalars(
        select(ResponseAction)
        .where(*expiring_where)
        .order_by(ResponseAction.expires_at, ResponseAction.id)
        .limit(capped_limit)
        .offset(capped_offset)
    ).all()

    # truncation is reported per list against that list's own exact total,
    # so "incomplete" always means "this list omitted rows" - never the
    # aggregate counts, which are complete by construction.
    truncated = (capped_offset + len(pending_rows)) < pending_total or (
        capped_offset + len(expiring_rows)
    ) < expiring_total

    return {
        "version": RESPONSE_CENTER_VERSION,
        "generated_at": now.isoformat(),
        "counts": counts,
        "pending_approval": [_summary_row(row) for row in pending_rows],
        "expiring_soon": [_summary_row(row) for row in expiring_rows],
        "total": total,
        "limit": capped_limit,
        "offset": capped_offset,
        "truncated": truncated,
        "expiry_warning_hours": EXPIRY_WARNING_HOURS,
    }


__all__ = [
    "DECISION_ALLOWED_WITH_APPROVAL",
    "DECISION_APPROVAL_REQUIRED",
    "DECISION_DRY_RUN_ONLY",
    "DECISION_NOT_ALLOWED",
    "EXPIRY_WARNING_HOURS",
    "GOVERNANCE_VERSION",
    "MAX_EVIDENCE_EVENTS_SCANNED",
    "MAX_EVIDENCE_REFERENCES_STORED",
    "MAX_RECOMMENDATIONS",
    "MAX_REJECTION_REASON",
    "POLICY_DECISIONS",
    "POLICY_VERSION",
    "RESPONSE_CENTER_DEFAULT_LIMIT",
    "RESPONSE_CENTER_MAX_LIMIT",
    "RESPONSE_CENTER_STATUSES",
    "RESPONSE_CENTER_VERSION",
    "PolicyDeniedError",
    "TargetRejectedError",
    "approve",
    "build_response_center_summary",
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
