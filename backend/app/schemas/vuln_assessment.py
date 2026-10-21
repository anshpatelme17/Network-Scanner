"""Pydantic schemas for vulnerability assessments and findings (Steps 15 + 22)."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

VulnScanProfileName = Literal[
    "BASELINE_VULNERABILITY_ASSESSMENT", "SERVICE_VULNERABILITY_ASSESSMENT", "BASIC", "STANDARD"
]


class VulnScanRequest(BaseModel):
    asset_id: str | None = Field(
        default=None, description="Inventoried asset to assess (exactly one of asset_id/target)."
    )
    target: str | None = Field(
        default=None,
        description="IP/CIDR target; must resolve to an inventoried asset inside the scan scope.",
    )
    profile: VulnScanProfileName = Field(
        default="BASELINE_VULNERABILITY_ASSESSMENT",
        description="Allow-listed assessment profile. No scanner flags accepted.",
    )
    requested_by: str = Field(default="operator", min_length=1, max_length=128)

    model_config = {"extra": "forbid"}


class VulnScanAuditEntry(BaseModel):
    event: str
    actor: str
    detail: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class VulnScanResponse(BaseModel):
    id: str
    target: str
    profile: str
    scan_type: str
    asset_id: str | None = None
    scanner: str | None = Field(
        default=None,
        description="Adapter that ran the job (LIVE nmap-vuln vs MOCK fixture-scanner).",
    )
    requested_by: str
    status: str
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    assets_found: int
    services_found: int
    result_summary: str | None = None
    nmap_version: str | None = None
    audit: list[VulnScanAuditEntry] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class VulnerabilityResponse(BaseModel):
    id: str
    asset_id: str
    service_id: str | None = None
    scanner: str
    scanner_version: str | None = None
    scanner_finding_id: str
    title: str
    description: str | None = None
    severity: str
    cvss_score: float | None = None
    cve_id: str | None = None
    cwe_id: str | None = None
    affected_component: str | None = None
    detected_version: str | None = None
    fixed_version: str | None = None
    evidence: str | None = None
    remediation_reference: str | None = None
    extra_data: dict = Field(default_factory=dict)
    status: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class VulnFindingAuditEntry(BaseModel):
    event: str
    actor: str
    previous_status: str | None = None
    new_status: str | None = None
    created_at: datetime
    detail: str | None = None

    model_config = {"from_attributes": True}


class VulnerabilityDetailResponse(VulnerabilityResponse):
    audit: list[VulnFindingAuditEntry] = Field(default_factory=list)
    audit_total: int = 0
    audit_limit: int | None = None
    audit_offset: int | None = None
    audit_truncated: bool = False


class VulnerabilityPage(BaseModel):
    items: list[VulnerabilityResponse]
    total: int
    limit: int
    offset: int


class VulnStatusUpdate(BaseModel):
    status: str = Field(min_length=1, max_length=16)
    actor: str = Field(default="operator", min_length=1, max_length=128)

    model_config = {"extra": "forbid"}


class LinkedEvent(BaseModel):
    id: str
    event_type: str
    source_type: str
    severity: str
    title: str
    event_time: datetime

    model_config = {"from_attributes": True}


class LinkedIncident(BaseModel):
    id: str
    incident_key: str
    title: str
    status: str

    model_config = {"from_attributes": True}


class FindingCorrelations(BaseModel):
    vulnerability_id: str
    asset_id: str
    service_id: str | None = None
    related_events: list[LinkedEvent] = Field(default_factory=list)
    related_incidents: list[LinkedIncident] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)


class AssetVulnRisk(BaseModel):
    asset_id: str
    finding_count: int
    highest_severity: str
    highest_cvss: float | None = None
    critical_count: int
    high_count: int
    aggregate_risk: int = Field(
        ge=0, le=100, description="Maximum finding score; never a compromise claim."
    )
    risk_level: str
    calculated_at: datetime | None = None
