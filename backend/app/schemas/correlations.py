"""Pydantic schemas for correlations and attack chains (Step 9)."""

from datetime import datetime

from pydantic import BaseModel, Field


class CorrelationSummary(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    title: str
    status: str
    severity: str
    confidence: int
    # Step 29 (additive): deterministic DIRECT/STRONG/MODERATE/WEAK
    # description of ``confidence`` (evidence strength, not probability).
    # Set by the endpoint from the stored confidence — never client input.
    confidence_label: str = "MODERATE"
    primary_ip: str | None = None
    hostname: str | None = None
    event_count: int
    window_start: datetime
    window_end: datetime
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class EvidenceItem(BaseModel):
    event_id: str
    role: str
    position: int
    event_type: str
    source_type: str
    severity: str
    title: str
    event_time: datetime
    source_ip: str | None = None
    destination_ip: str | None = None

    model_config = {"from_attributes": True}


class CorrelationDetail(CorrelationSummary):
    description: str | None = None
    explanation: str
    evidence: list[EvidenceItem] = Field(default_factory=list)


class CorrelationPage(BaseModel):
    items: list[CorrelationSummary]
    total: int
    limit: int
    offset: int


class ChainNode(BaseModel):
    id: str
    kind: str = Field(description="'correlation' | 'asset' | 'event' | 'vulnerability'")
    label: str
    detail: dict[str, str] = Field(default_factory=dict)


class ChainEdge(BaseModel):
    source: str
    target: str
    relation: str


class AttackChain(BaseModel):
    correlation_id: str
    nodes: list[ChainNode]
    edges: list[ChainEdge]


class RecomputeResult(BaseModel):
    events_scanned: int
    rules_evaluated: int
    created: int
    refreshed: int
    correlation_ids: list[str]
