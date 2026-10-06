"""Pydantic schemas for risk assessments (Steps 10 + 25)."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class RiskAssessmentResponse(BaseModel):
    id: str
    entity_type: str
    entity_id: str
    score: int = Field(ge=0, le=100)
    severity: str
    priority: str = Field(default="P4", description="Advisory triage band P1-P4.")
    factors: dict[str, Any] = Field(default_factory=dict)
    explanation: str
    calculated_at: datetime
    scoring_version: str

    model_config = {"from_attributes": True}


class RiskPage(BaseModel):
    items: list[RiskAssessmentResponse]
    total: int
    limit: int
    offset: int


class RiskRecomputeResult(BaseModel):
    assessed: int
    created: int
    updated: int
    scoring_version: str
