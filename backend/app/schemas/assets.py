"""Pydantic schemas for assets and discovered services (Step 2)."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class ServiceResponse(BaseModel):
    id: str
    port: int
    protocol: str
    state: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    discovered_at: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}


class AssetResponse(BaseModel):
    id: str
    ip_address: str
    hostname: str | None = None
    mac_address: str | None = None
    operating_system: str | None = None
    state: str
    asset_type: str = Field(
        default="UNKNOWN", description="Classification; UNKNOWN unless determined"
    )
    discovery_source: str | None = Field(
        default=None, description="Where the asset was learned from"
    )
    service_count: int = Field(default=0, description="Open services currently known")
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}


class AssetDetailResponse(AssetResponse):
    services: list[ServiceResponse] = Field(default_factory=list)


class AssetPage(BaseModel):
    items: list[AssetResponse]
    total: int
    limit: int
    offset: int


class InventorySummary(BaseModel):
    total_assets: int
    active_assets: int
    total_services: int
    last_scan_at: datetime | None = None
    last_scan_status: str | None = None


AssetStateFilter = Literal["up", "down"]
