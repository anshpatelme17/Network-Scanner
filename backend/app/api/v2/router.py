"""Versioned (v2) router aggregation.

v2 exists only for endpoints that cannot be added to v1 without changing
existing behaviour. Today that is the read-only response audit history.
Nothing here duplicates, replaces, or alters a v1 route.
"""

from fastapi import APIRouter

from app.api.v2.endpoints import response_audit

v2_router = APIRouter()
v2_router.include_router(response_audit.router)
