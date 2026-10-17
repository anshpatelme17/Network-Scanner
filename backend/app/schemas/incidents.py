"""Pydantic schemas for incidents (Steps 11 + 17)."""

from datetime import datetime

from pydantic import BaseModel, Field


class IncidentCreate(BaseModel):
    correlation_id: str = Field(min_length=1, max_length=64)
    risk_assessment_id: str | None = Field(default=None, min_length=1, max_length=64)

    model_config = {"extra": "forbid"}


class IncidentUpdate(BaseModel):
    status: str | None = Field(default=None)
    title: str | None = Field(default=None, min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=4000)
    actor: str | None = Field(default=None, min_length=1, max_length=128)

    model_config = {"extra": "forbid"}


class IncidentStatusUpdate(BaseModel):
    status: str = Field(min_length=1, max_length=16)
    actor: str | None = Field(default=None, min_length=1, max_length=128)

    model_config = {"extra": "forbid"}


class IncidentResponse(BaseModel):
    id: str
    incident_key: str
    title: str
    description: str | None = None
    status: str
    severity: str
    confidence: int
    primary_asset_id: str | None = None
    primary_ip: str | None = None
    hostname: str | None = None
    correlation_id: str
    risk_assessment_id: str | None = None
    first_seen: datetime
    last_seen: datetime
    resolved_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    version: str
    # Step 17 (additive): classification, verbatim linked-assessment
    # score, and the deterministic detection explanation.
    incident_type: str = "OTHER"
    risk_score: int | None = None
    detection_reason: str | None = None

    model_config = {"from_attributes": True}


class IntelligenceResponse(BaseModel):
    """Deterministic incident-intelligence summary (Phase 2, Step 8).

    Every field is a count, a bounded integer, a stored identifier, an ISO
    timestamp or a fixed label. Derived entirely from stored rows on the
    server; nothing here is client-supplied and no credential can appear.
    """

    analysis_version: str
    module_version: str
    incident_id: str
    correlation_id: str
    status: str
    severity: str
    confidence: int
    priority: str
    points: int
    factors: dict[str, object] = Field(default_factory=dict)
    explanation: str
    evidence: dict[str, object] = Field(default_factory=dict)
    assets: dict[str, object] = Field(default_factory=dict)
    vulnerabilities: dict[str, object] = Field(default_factory=dict)
    relationships: dict[str, object] = Field(default_factory=dict)
    timeline: dict[str, object] = Field(default_factory=dict)


class IncidentDetailResponse(IncidentResponse):
    evidence_event_ids: list[str] = Field(default_factory=list)


class IncidentPage(BaseModel):
    items: list[IncidentResponse]
    total: int
    limit: int
    offset: int


class EvidenceEvent(BaseModel):
    id: str
    event_type: str
    severity: str
    source_type: str
    title: str
    event_time: datetime
    role: str | None = None
    reason: str | None = None


class EvidenceVulnerability(BaseModel):
    id: str
    title: str
    severity: str
    status: str
    cve_id: str | None = None
    reason: str | None = None


class EvidenceCorrelation(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    severity: str
    confidence: int
    explanation: str


class EvidenceEntities(BaseModel):
    """Distinct identity-ish values observed on the evidence events.

    Real field values only — absent fields stay absent; nothing is
    inferred, joined or manufactured (Step 29).
    """

    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    usernames: list[str] = Field(default_factory=list)


class EvidenceAsset(BaseModel):
    """One existing asset row referenced by the evidence fields (batched
    lookup; unknown hosts simply produce no entry)."""

    id: str
    ip_address: str
    hostname: str | None = None


class EvidenceRule(BaseModel):
    """One rule that contributed to this incident's evidence view.

    ``relationship_count`` is the number of stored Step 29 relationships
    the rule produced for this incident (0 for the incident's Step 24
    correlation rule, which produces correlations instead).
    """

    rule_id: str
    rule_name: str
    confidence: int
    confidence_label: str
    relationship_count: int = 0


class IncidentEvidenceResponse(BaseModel):
    incident_id: str
    incident_type: str
    detection_reason: str | None = None
    correlation: EvidenceCorrelation | None = None
    events: list[EvidenceEvent] = Field(default_factory=list)
    vulnerabilities: list[EvidenceVulnerability] = Field(default_factory=list)
    # Step 29 (additive): bounded overview of the same references —
    # never a payload copy and never new data.
    evidence_count: int = 0
    truncated: bool = False
    primary_event: EvidenceEvent | None = None
    source_distribution: dict[str, int] = Field(default_factory=dict)
    entities: EvidenceEntities = Field(default_factory=EvidenceEntities)
    assets: list[EvidenceAsset] = Field(default_factory=list)
    first_observed: datetime | None = None
    last_observed: datetime | None = None
    correlation_rules: list[EvidenceRule] = Field(default_factory=list)


class TimelineEntry(BaseModel):
    at: datetime | None = None
    kind: str
    label: str
    detail: str | None = None
    # Step 29 (additive): populated for kind == "event" entries only.
    event_id: str | None = None
    event_type: str | None = None
    source: str | None = None
    severity: str | None = None
    entity: str | None = None
    explanation: str | None = None
    # Step 44 (additive): populated for kind == "response" entries only —
    # the controlled-response lifecycle rows for this incident, projected
    # onto the same chronological record. The optional per-action rationale
    # is deliberately not duplicated here; it stays on the per-action audit
    # endpoint where it belongs.
    action_id: str | None = None
    action_type: str | None = None
    event: str | None = None
    actor: str | None = None
    previous_status: str | None = None
    new_status: str | None = None


class IncidentTimelineResponse(BaseModel):
    incident_id: str
    entries: list[TimelineEntry] = Field(default_factory=list)
    truncated: bool = False


class AuditEntry(BaseModel):
    action: str
    actor: str
    detail: str | None = None
    created_at: datetime


class IncidentAuditResponse(BaseModel):
    incident_id: str
    entries: list[AuditEntry] = Field(default_factory=list)


class IncidentObservation(BaseModel):
    """One traceable observation link (Step 24 observation vocabulary)."""

    observation_type: str
    observation_id: str
    reason: str | None = None
    created_at: datetime


class IncidentObservationsResponse(BaseModel):
    incident_id: str
    event_count: int
    vulnerability_count: int
    correlation_count: int
    observations: list[IncidentObservation] = Field(default_factory=list)


class IncidentDetectRequest(BaseModel):
    correlation_id: str | None = Field(default=None, min_length=1, max_length=64)
    risk_assessment_id: str | None = Field(default=None, min_length=1, max_length=64)
    actor: str | None = Field(default=None, min_length=1, max_length=128)

    model_config = {"extra": "forbid"}


class DetectOutcome(BaseModel):
    correlation_id: str
    incident_id: str | None = None
    created: bool
    reason: str


class IncidentDetectResponse(BaseModel):
    evaluated: int
    created: int
    updated: int
    skipped: int
    detector_version: str
    outcomes: list[DetectOutcome] = Field(default_factory=list)


class IncidentRelationshipItem(BaseModel):
    """One stored Step 29 relationship (deterministic rule output).

    ``confidence_label`` is the deterministic DIRECT/STRONG/MODERATE/
    WEAK description of the rule's fixed confidence — a relationship
    description, not a machine-learning prediction. Every row names the
    stored records it links; unknown entities produce no row at all.
    """

    id: str
    incident_id: str
    rule_id: str
    rule_name: str
    relation: str
    source_kind: str
    source_id: str
    source_label: str | None = None
    target_kind: str
    target_id: str
    target_label: str | None = None
    confidence: int
    confidence_label: str
    explanation: str
    evidence_event_ids: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime


class IncidentRelationshipsPage(BaseModel):
    incident_id: str
    items: list[IncidentRelationshipItem]
    total: int
    limit: int
    offset: int


class IncidentRelationshipBounds(BaseModel):
    """The effective server-side bounds this analysis ran under."""

    max_events: int
    max_relationships: int
    max_evidence_per_relationship: int
    temporal_window_minutes: int
    cross_source_window_minutes: int
    entity_window_minutes: int


class IncidentRecalculateResponse(BaseModel):
    """Result of a bounded, parameter-free relationship recalculation."""

    incident_id: str
    analysis_version: str
    rules_evaluated: int
    events_considered: int
    relationships_created: int
    relationships_refreshed: int
    relationships_total: int
    truncated: bool
    bounds: IncidentRelationshipBounds
