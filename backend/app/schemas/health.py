"""Pydantic response schemas for system endpoints."""

from typing import Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    app: str = Field(description="Application name")
    version: str = Field(description="Application version")
    environment: str = Field(description="Deployment environment")


class ReadinessResponse(BaseModel):
    status: Literal["ready", "not_ready"]
    app: str
    version: str
    environment: str
    checks: dict[str, str] = Field(description="Subsystem checks, e.g. {'database': 'up'}")


class VersionResponse(BaseModel):
    app: str
    version: str
    environment: str
    api_prefix: str


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail
