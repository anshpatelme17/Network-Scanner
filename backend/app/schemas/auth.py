"""Pydantic schemas for authentication and user management (Step 20)."""

from datetime import datetime

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)

    model_config = {"extra": "forbid"}


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int


class UserResponse(BaseModel):
    id: str
    username: str
    display_name: str
    is_active: bool
    roles: list[str]
    permissions: list[str]
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None = None

    model_config = {"from_attributes": False}


class UserPage(BaseModel):
    items: list[UserResponse]
    total: int
    limit: int
    offset: int


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=128)
    password: str = Field(min_length=1, max_length=256)
    display_name: str = Field(min_length=1, max_length=256)
    roles: list[str] = Field(default_factory=lambda: ["VIEWER"])

    model_config = {"extra": "forbid"}


class UserUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=256)
    password: str | None = Field(default=None, min_length=1, max_length=256)
    roles: list[str] | None = None
    is_active: bool | None = None

    model_config = {"extra": "forbid"}
