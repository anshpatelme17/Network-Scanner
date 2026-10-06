"""SOC overview response schema (Phase 2, Step 9).

Every field is a count, a bounded integer, a stored identifier, an ISO
timestamp, a score, or a fixed enum label. No event payloads, no
configuration values and no credential is representable here.
"""

from pydantic import BaseModel, Field


class OverviewCount(BaseModel):
    assets_total: int = 0
    assets_active: int = 0
    services_total: int = 0
    events_total: int = 0
    correlations_total: int = 0
    incidents_total: int = 0
    incidents_open: int = 0
    risk_assessments_total: int = 0
    vulnerabilities_open: int = 0
    response_actions_total: int = 0
    response_actions_pending_approval: int = 0


class OverviewIncident(BaseModel):
    id: str
    incident_key: str
    title: str
    status: str
    severity: str
    confidence: int
    risk_score: int | None = None
    priority: str | None = None
    primary_asset_id: str | None = None
    primary_ip: str | None = None
    hostname: str | None = None
    correlation_id: str
    first_seen: str
    last_seen: str


class OverviewAudit(BaseModel):
    id: str
    action: str
    actor: str
    event_id: str | None = None
    detail: str = ""
    created_at: str


class OverviewConnector(BaseModel):
    source: str
    mode: str
    state: str
    connector_state: str
    last_check_at: str | None = None
    last_poll_at: str | None = None
    last_error_category: str | None = None
    events_retrieved: int = 0


class OverviewLimits(BaseModel):
    max_items: int
    requested_items: int


class SocOverviewResponse(BaseModel):
    generated_at: str
    version: str
    counts: OverviewCount = Field(default_factory=OverviewCount)
    incidents_by_severity: dict[str, int] = Field(default_factory=dict)
    incidents_by_priority: dict[str, int] = Field(default_factory=dict)
    top_incidents: list[OverviewIncident] = Field(default_factory=list)
    recent_audit: list[OverviewAudit] = Field(default_factory=list)
    connectors: list[OverviewConnector] = Field(default_factory=list)
    limits: OverviewLimits
    disclaimer: str
