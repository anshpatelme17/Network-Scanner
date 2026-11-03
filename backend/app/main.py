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
from app.api.v2.router import v2_router
from app.core.config import get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import get_logger, setup_logging
from app.core.ratelimit import FixedWindowRateLimiter
from app.database.session import (
    DatabaseConnectivityError,
    RuntimeIdentityMismatch,
    RuntimeIdentityVerificationError,
    dispose_engine,
    init_engine,
    is_connectivity_failure,
    verify_runtime_identity,
)
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
        engine = init_engine(settings.database_url)
    except Exception as exc:  # noqa: BLE001 - classify without exposing details
        if is_connectivity_failure(exc, connection_acquisition=False):
            logger.warning(
                "Database connection unavailable; readiness will be down"
            )
        else:
            dispose_engine()
            logger.error("Database engine initialization failed; startup aborted")
            raise RuntimeError(
                "Database engine initialization failed."
            ) from None
    else:
        try:
            verify_runtime_identity(engine)
        except DatabaseConnectivityError:
            logger.warning("Database connection unavailable; readiness will be down")
        except RuntimeIdentityMismatch:
            dispose_engine()
            logger.error("Runtime database identity mismatch; startup aborted")
            raise RuntimeError(
                "Runtime database identity verification failed."
            ) from None
        except RuntimeIdentityVerificationError:
            dispose_engine()
            logger.error(
                "Runtime database identity verification failed; startup aborted"
            )
            raise RuntimeError(
                "Runtime database identity verification failed."
            ) from None
        except Exception:  # noqa: BLE001 - an unclassified check fails closed
            dispose_engine()
            logger.error(
                "Runtime database identity verification failed; startup aborted"
            )
            raise RuntimeError(
                "Runtime database identity verification failed."
            ) from None
        else:
            logger.info("Database engine initialized")
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

    # Step 31 transport hardening. Starlette wraps middleware in reverse
    # registration order: request context runs first, security headers wrap
    # body-limit rejections, and the body cap runs before routing. These
    # bound and label traffic only: they never authenticate or authorize.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    app.add_middleware(SecurityHeadersMiddleware, settings=settings)
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
    # Step 42A: the optional v2 surface. It carries only the read-only
    # response audit history today; mounting it changes no v1 route.
    app.include_router(v2_router, prefix=settings.api_v2_prefix)
    return app


app = create_app()
