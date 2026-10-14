"""Pydantic schemas for response proposals (Steps 12 + 18)."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.response_governance import RollbackResponse
from app.services.response_service import ACTION_TYPES, TARGET_TYPES


class ResponseProposalRequest(BaseModel):
    incident_id: str = Field(min_length=1, max_length=64)
    action_type: str = Field(description=f"One of: {', '.join(ACTION_TYPES)}")
    target_type: str = Field(description=f"One of: {', '.join(TARGET_TYPES)}")
    target_reference: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=2000)
    requested_by: str = Field(min_length=1, max_length=128)
    dry_run: bool = Field(default=True, description="Must stay true; no live execution exists.")

    model_config = {"extra": "forbid"}


class IncidentResponseProposalRequest(BaseModel):
    """Propose a safe foundation action for an incident (Step 18).

    The incident comes from the path; the target is always the incident
    record itself. Only safe action types are accepted here — other
    proposals belong on POST /api/v1/responses.
    """

    action_type: str = Field(description="A safe foundation action type.")
    reason: str = Field(min_length=1, max_length=2000)
    requested_by: str = Field(min_length=1, max_length=128)
    dry_run: bool = Field(default=True)

    model_config = {"extra": "forbid"}


class ResponseDecisionRequest(BaseModel):
    actor: str = Field(default="operator", min_length=1, max_length=128)
    # Step 41: optional operator rationale for the decision. Bounded so an
    # over-long reason is refused rather than silently truncated, and
    # absent by default so every existing client keeps working. The
    # governance layer records it only on the rejection audit event and
    # never lets it overwrite the requester's own reason.
    reason: str | None = Field(
        default=None, max_length=2000, description="Optional rationale for this decision."
    )

    model_config = {"extra": "forbid"}


class ExecutionRequest(BaseModel):
    actor: str = Field(default="operator", min_length=1, max_length=128)

    model_config = {"extra": "forbid"}


class ResponseActionResponse(BaseModel):
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
    execution_status: str | None = Field(
        default=None, description="SIMULATED after simulation; COMPLETED after safe execution."
    )
    created_at: datetime
    approved_at: datetime | None = None
    expires_at: datetime | None = None
    # Step 18 (additive): approval identity + safe-execution outcome.
    approved_by: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    failure_reason: str | None = None
    result_summary: str | None = None
    # Step 30 (additive): controlled-response governance state. Present
    # on every row so the incident view has one shape; a Step 12-19
    # proposal reports the dry-run-only defaults and therefore can never
    # imply a controlled capability it does not have.
    provider: str = "MOCK"
    policy_decision: str = "DRY_RUN_ONLY"
    approval_required: bool = True
    rollback_supported: bool = False
    rollback_state: str | None = None
    rollback_reference: str | None = None
    target_evidence: list[str] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class AuditEntry(BaseModel):
    id: str
    event: str
    previous_status: str | None = None
    new_status: str | None = None
    actor: str
    policy_version: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ExecutionResult(BaseModel):
    id: str
    action_id: str
    incident_id: str
    adapter: str
    dry_run: bool
    would_execute: bool
    result: str
    explanation: str
    policy_version: str
    simulated_at: datetime

    model_config = {"from_attributes": True}


class ResponseDetailResponse(ResponseActionResponse):
    audit: list[AuditEntry] = Field(default_factory=list)
    execution: ExecutionResult | None = Field(default=None)
    # Step 30: the recorded rollback attempt, or null when none was made.
    rollback: RollbackResponse | None = Field(default=None)


class ResponsePage(BaseModel):
    items: list[ResponseActionResponse]
    total: int
    limit: int
    offset: int


class DryRunResult(BaseModel):
    action_id: str
    action_type: str
    target: str
    dry_run: bool
    would_execute: bool
    result: str
    explanation: str
    policy_version: str


class AdapterRequest(BaseModel):
    """Strongly typed adapter input (Step 19).

    Built server-side from the stored proposal only. There is no API
    surface that accepts adapter commands, executable paths, or shell
    strings — unknown fields are rejected by ``extra=forbid`` everywhere.
    """

    adapter_type: str
    action_type: str
    target_type: str
    target_reference: str
    incident_id: str
    response_id: str
    dry_run: bool
    requested_by: str
    approved_by: str | None = None
    policy_version: str

    model_config = {"extra": "forbid"}


class AdapterEvidence(BaseModel):
    """One evidence reference inside an adapter result (Step 19).

    References to stored records only — never fabricated findings, never
    claims about external systems.
    """

    kind: str
    reference: str
    detail: str | None = None

    model_config = {"extra": "forbid"}


class AdapterResult(BaseModel):
    """Strongly typed adapter output (Step 19).

    For every Step 19 adapter: ``executed`` is always False and
    ``simulated`` always True. ``would_execute`` answers whether the
    execute endpoint would run the stored proposal now (policy view of
    current state), without running anything.
    """

    accepted: bool
    executed: bool
    simulated: bool
    status: str
    adapter_type: str
    action_type: str
    target: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    result_summary: str
    failure_reason: str | None = None
    evidence: list[AdapterEvidence] = Field(default_factory=list)
    would_execute: bool

    model_config = {"extra": "forbid"}


class PreviewResponse(BaseModel):
    """Response-adapter preview (Step 19, read-only).

    Validation + adapter selection + target validation + what would
    happen. No workflow state changes; no external effect.
    """

    action_id: str
    incident_id: str
    adapter_type: str
    accepted: bool
    executed: bool
    simulated: bool
    would_execute: bool
    status: str
    result_summary: str
    evidence: list[AdapterEvidence] = Field(default_factory=list)
    policy_decision: str
    policy_version: str

    model_config = {"extra": "forbid"}
