"""Pydantic schemas for controlled Nmap scans (Steps 2 + 21).

The request carries ONLY a target and an allow-listed profile name.
There is deliberately no field for flags, options, or commands.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

ScanProfileName = Literal["quick", "standard", "DISCOVERY_PING", "DISCOVERY_TCP_COMMON"]


class ScanRequest(BaseModel):
    target: str = Field(
        description="Authorized scan target: single IPv4/IPv6 address or CIDR network "
        "inside the configured SCAN_ALLOWED_NETWORKS scope.",
        examples=["127.0.0.1"],
    )
    scan_profile: ScanProfileName = Field(
        default="quick",
        description="Allow-listed scan profile. Exact Nmap arguments are fixed server-side.",
    )
    requested_by: str = Field(
        default="operator",
        min_length=1,
        max_length=128,
        description="Operator label recorded on the job and its audit trail.",
    )

    model_config = {"extra": "forbid"}


class ScanAuditEntry(BaseModel):
    event: str
    actor: str
    detail: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanJobResponse(BaseModel):
    id: str
    target: str
    profile: str
    scan_type: str = "nmap"
    requested_by: str = "operator"
    status: str
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    assets_found: int
    services_found: int
    result_summary: str | None = None
    nmap_version: str | None = None
    audit: list[ScanAuditEntry] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class NmapStatusResponse(BaseModel):
    available: bool
    version: str | None = None
    profiles: list[str] = Field(description="Allow-listed scan profile names")


class ScanPreviewResponse(BaseModel):
    """Discovery preview (Step 21, validation only).

    Describes what a discovery WOULD do without doing it: no scan is
    started, no assets are created. The constructed Nmap argument list
    is deliberately NOT exposed — only the profile description, probe
    behavior, and scope accounting the server validated.
    """

    target: str
    profile: str
    profile_description: str
    probes_ports: bool
    address_count: int
    scope_authorized: bool
    nmap_available: bool
    timeout_seconds: int

    model_config = {"extra": "forbid"}
