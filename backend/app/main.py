"""Application entry point.

Layering (Step 1)::

    Frontend -> API (/api/v1) -> Services -> Database

Later stages insert, behind service interfaces::

    Collectors -> Normalization -> Event Bus -> Correlation
      -> Risk -> Response -> Dashboard / Audit
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import __version__
from app.api.v1.router import v1_router
from app.core.config import get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import get_logger, setup_logging
from app.core.ratelimit import FixedWindowRateLimiter
from app.database.session import init_engine
from app.middleware import (
    BodySizeLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    settings = get_settings()
    logger.info(
        "Starting %s v%s in '%s' environment",
        settings.app_name,
        __version__,
        settings.environment,
    )
    try:
        init_engine(settings.database_url)
        logger.info("Database engine initialized")
    except Exception:  # noqa: BLE001
        # Never crash liveness because the DB is down; readiness reports it.
        logger.exception("Database engine initialization failed; readiness will be down")
    yield
    logger.info("Shutting down application")


def create_app() -> FastAPI:
    settings = get_settings()
    setup_logging(settings.log_level)

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        debug=settings.debug and not settings.is_production,
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
    )
    # Handlers read the live settings for rate-limit budgets.
    app.state.settings = settings
    # One limiter per application instance. A real deployment has exactly
    # one app, so budgets are per-process there; keeping it on app.state
    # (rather than a module global) means a second app in the same process
    # cannot inherit another's counters.
    app.state.limiter = FixedWindowRateLimiter(max_buckets=settings.rate_limit_max_buckets)

    # CORS: explicit allow-list only, never "*" (rejected at parse time by
    # the settings validator as well).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.backend_cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Accept", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
    )

    # Step 31 transport hardening. Middleware is added outermost-first, so
    # the request context runs before anything else can log or reject, and
    # the body cap is applied before routing. These bound and label
    # traffic only: they never authenticate or authorize.
    app.add_middleware(SecurityHeadersMiddleware, settings=settings)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    app.add_middleware(RequestContextMiddleware)
    if settings.trusted_hosts:
        # Optional (empty by default) so the development workflow and the
        # TestClient keep working; a deployment behind a known hostname
        # should set TRUSTED_HOSTS.
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)

    register_exception_handlers(app, settings)

    @app.get("/", tags=["system"], summary="Service root")
    def root():
        return {
            "app": settings.app_name,
            "version": __version__,
            "environment": settings.environment,
            "api_prefix": settings.api_v1_prefix,
            "status": "running",
        }

    app.include_router(v1_router, prefix=settings.api_v1_prefix)
    return app


app = create_app()
