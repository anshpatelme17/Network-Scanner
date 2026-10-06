"""System endpoints: liveness, readiness, version.

No sensitive configuration is ever returned. Database credentials, secret
keys and connection strings are deliberately excluded from all responses.
"""

import json

from fastapi import APIRouter, Depends, Response, status

from app import __version__
from app.core.config import Settings, get_settings
from app.database.session import ping_database
from app.schemas.health import HealthResponse, ReadinessResponse, VersionResponse
from app.services import health as health_service

router = APIRouter(tags=["system"])


def _settings() -> Settings:
    return get_settings()


@router.get("/health", response_model=HealthResponse, summary="Liveness probe")
def liveness(settings: Settings = Depends(_settings)) -> dict[str, str]:
    """Cheap liveness check: process is running. No DB access."""
    return health_service.liveness(settings)


@router.get(
    "/ready",
    summary="Readiness probe (includes database check)",
    response_model=ReadinessResponse,
    responses={
        200: {"description": "Ready to serve traffic"},
        503: {"description": "Not ready (e.g. database unreachable)"},
    },
)
def readiness(response: Response, settings: Settings = Depends(_settings)):
    payload, ready = health_service.readiness(settings)
    response.status_code = status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE
    return payload


@router.get("/version", response_model=VersionResponse, summary="Application version")
def version(settings: Settings = Depends(_settings)) -> dict[str, str]:
    return health_service.version_info(settings)


@router.get("/health/db", summary="Database connectivity check")
def database_health(settings: Settings = Depends(_settings)):  # noqa: ARG001
    """Explicit DB check used by the dashboard's database-status card."""
    up = ping_database()
    body = {
        "status": "ok" if up else "unavailable",
        "app": settings.app_name,
        "version": __version__,
        "environment": settings.environment,
        "checks": {"database": "up" if up else "down"},
    }
    return Response(
        content=json.dumps(body),
        media_type="application/json",
        status_code=200 if up else 503,
    )
