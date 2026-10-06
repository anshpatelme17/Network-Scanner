"""System health service: liveness vs readiness.

Liveness (``/health``) never touches the database. Readiness (``/ready``)
performs a cheap ``SELECT 1`` so orchestrators only route traffic when the
app can actually serve requests.
"""

from __future__ import annotations

from app import __version__
from app.core.config import Settings
from app.database.session import ping_database


def liveness(settings: Settings) -> dict[str, str]:
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": __version__,
        "environment": settings.environment,
    }


def readiness(settings: Settings) -> tuple[dict[str, object], bool]:
    database_up = ping_database()
    ready = bool(database_up)
    payload: dict[str, object] = {
        "status": "ready" if ready else "not_ready",
        "app": settings.app_name,
        "version": __version__,
        "environment": settings.environment,
        "checks": {"database": "up" if database_up else "down"},
    }
    return payload, ready


def version_info(settings: Settings) -> dict[str, str]:
    return {
        "app": settings.app_name,
        "version": __version__,
        "environment": settings.environment,
        "api_prefix": settings.api_v1_prefix,
    }
