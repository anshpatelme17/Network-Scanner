"""Request/response contracts for controlled defensive responses (Step 30).

Every request model sets ``extra="forbid"``. That is load-bearing here:
it is what makes ``{"command": "..."}``, ``{"provider": "..."}``,
``{"policy": "..."}``, ``{"risk_score": 99}`` and ``{"approved": true}``
rejected with a 422 instead of being silently ignored on a route that can
reach a defensive action. The server decides the action type, provider,
policy, approval, and expiry; a client may only *ask* for an allow-listed
action against an allow-listed target shape.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.services.response_governance import GOVERNANCE_VERSION, POLICY_VERSION
from app.services.response_providers import (
    ACTION_TARGET_TYPES,
    CONTROLLED_ACTION_TYPES,
    CONTROLLED_TARGET_TYPES,
)

_ACTION_HELP = "Allow-listed controlled action: " + ", ".join(CONTROLLED_ACTION_TYPES)
_TARGET_HELP = "Allow-listed target type: " + ", ".join(CONTROLLED_TARGET_TYPES)


class ControlledResponseRequest(BaseModel):
    """Ask for a controlled defensive action against an incident."""

    model_config = {"extra": "forbid"}

    incident_id: str = Field(min_length=1, max_length=64)
    action_type: str = Field(description=_ACTION_HELP)
    target_type: str = Field(description=_TARGET_HELP)
    target_reference: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=2000)
    requested_by: str = Field(min_length=1, max_length=128)
    ttl_minutes: int | None = Field(
        default=None,
        ge=1,
        description=(
            "Requested lifetime. Deliberately has no upper bound here: the "
            "server clamps it to RESPONSE_MAX_TTL_MINUTES and reports the "
            "effective value, so an over-long request is bounded rather than "
            "rejected. There is no unlimited option."
        ),
    )


class GovernanceActorRequest(BaseModel):
    """Actor label. Only used as a bootstrap-mode fallback; the token wins."""

    model_config = {"extra": "forbid"}

    actor: str = Field(default="operator", min_length=1, max_length=128)


class ControlledActionResponse(BaseModel):
    """A stored response action including Step 30 governance fields.

    Used by the Step 30 routes. The seven governance fields are also
    surfaced on the shared Step 12/18/19 routes (as optional fields) so
    one incident view never has two shapes.
    """

    model_config = {"from_attributes": True}

    id: str
    incident_id: str
    action_type: str
    target_type: str
    target_reference: str
    reason: str
    requested_by: str
    status: str
    dry_run: bool
    policy_version: str
    provider: str
    policy_decision: str
    approval_required: bool
    rollback_supported: bool
    rollback_state: str | None = None
    rollback_reference: str | None = None
    target_evidence: list[str] = Field(default_factory=list)
    execution_status: str | None = None
    created_at: datetime
    approved_at: datetime | None = None
    expires_at: datetime | None = None
    approved_by: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    failure_reason: str | None = None
    result_summary: str | None = None


class ResponsePolicyResponse(BaseModel):
    """Deterministic policy verdict for one stored action."""

    model_config = {"from_attributes": True}

    action_id: str
    decision: str
    approval_required: bool
    provider: str
    provider_capable: bool
    target_proven: bool
    evidence_event_ids: list[str] = Field(default_factory=list)
    expires_at: datetime | None = None
    reason: str
    policy_version: str = POLICY_VERSION


class ControlledDryRunResponse(BaseModel):
    """Result of a provider dry run. ``executed`` is always false."""

    model_config = {"from_attributes": True}

    action_id: str
    incident_id: str
    action_type: str
    target: str
    provider: str
    dry_run: bool = True
    would_execute: bool
    executed: bool = False
    result: str
    explanation: str
    changes: list[str] = Field(default_factory=list)
    evidence_event_ids: list[str] = Field(default_factory=list)
    policy_decision: str
    policy_reason: str
    expires_at: datetime | None = None
    policy_version: str = POLICY_VERSION
    governance_version: str = GOVERNANCE_VERSION


class RollbackResponse(BaseModel):
    """Recorded rollback attempt for an executed action."""

    model_config = {"from_attributes": True}

    id: str
    action_id: str
    incident_id: str
    provider: str
    result: str
    explanation: str
    policy_version: str = POLICY_VERSION
    created_at: datetime


class ResponseRecommendation(BaseModel):
    """One deterministic, evidence-backed action suggestion.

    ``automatic`` is always false and ``requires_approval`` is always
    true: availability never implies permission, and nothing here is ever
    executed on the basis of a risk score.
    """

    model_config = {"extra": "forbid"}

    action_type: str
    target_type: str
    target_reference: str
    incident_id: str
    incident_key: str
    severity: str
    risk_priority: str | None = None
    available: bool
    provider: str
    evidence_event_ids: list[str] = Field(default_factory=list)
    reason: str
    requires_approval: bool = True
    automatic: bool = False


class ResponseRecommendationsResponse(BaseModel):
    """Bounded recommendation list for one incident."""

    model_config = {"from_attributes": True}

    incident_id: str
    incident_key: str
    severity: str
    risk_score: int | None = None
    risk_priority: str | None = None
    items: list[ResponseRecommendation] = Field(default_factory=list)
    total: int = 0
    truncated: bool = False
    action_target_types: dict[str, list[str]] = Field(
        default_factory=lambda: {k: list(v) for k, v in ACTION_TARGET_TYPES.items()}
    )
    policy_version: str = POLICY_VERSION
    governance_version: str = GOVERNANCE_VERSION


__all__ = [
    "ControlledActionResponse",
    "ControlledDryRunResponse",
    "ControlledResponseRequest",
    "GovernanceActorRequest",
    "ResponsePolicyResponse",
    "ResponseRecommendation",
    "ResponseRecommendationsResponse",
    "RollbackResponse",
]
