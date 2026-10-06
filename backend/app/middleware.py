"""HTTP middleware: correlation ids, security headers, body-size bounds
(Step 31).

Three concerns, one module, all pure transport-level hardening:

* ``RequestContextMiddleware`` mints a sanitised correlation id per
  request, publishes it to :mod:`app.core.request_context` (so audit rows
  and log lines can reference it) and echoes it back on the response.
  It also emits one access log record per request with method, path,
  status and duration — the record goes through the existing redacting
  filter, so a query string containing a token is scrubbed.
* ``SecurityHeadersMiddleware`` sets conservative response headers. The
  policy is a fixed default; it can be tightened by configuration but
  never silently disabled per-route.
* ``BodySizeLimitMiddleware`` refuses an over-sized declared body with
  413 *before* it is buffered, so a large payload cannot exhaust memory.
  It is a defence in depth step: the per-field caps in the ingest
  services remain the authoritative content limits.

None of these authenticate, authorize, or make decisions. They only
bound and label traffic; the server-side RBAC checks in Step 20/30 remain
the security boundary.
"""

from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.config import Settings
from app.core.logging import get_logger
from app.core.request_context import (
    REQUEST_ID_HEADER,
    sanitize_request_id,
    set_request_id,
)

logger = get_logger(__name__)

# Paths that carry no sensitive payload and should never be cached by a
# browser or an intermediary. Applied to every API response.
NO_STORE_PATHS = ("/api/",)

# Conservative default policy. `connect-src 'self'` keeps the API from
# being used as a script/websocket source; the SPA is served by nginx, not
# here, so a strict policy on the API cannot break the UI.
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Correlation id + one access log line per request."""

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001, ANN201
        request_id = set_request_id(sanitize_request_id(request.headers.get(REQUEST_ID_HEADER)))
        request.state.request_id = request_id
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            # Let the application's exception handler produce the safe
            # envelope; only the observability line is added here.
            elapsed_ms = (time.perf_counter() - started) * 1000
            logger.exception(
                "unhandled request error id=%s %s %s in %.1fms",
                request_id,
                request.method,
                request.url.path,
                elapsed_ms,
            )
            raise
        elapsed_ms = (time.perf_counter() - started) * 1000
        response.headers[REQUEST_ID_HEADER] = request_id
        # Health and readiness are polled by orchestrators on a timer and
        # are pure liveness signals; logging them every few seconds would
        # bury real traffic, so they are logged at DEBUG only.
        if request.url.path.endswith(("/health", "/ready", "/health/db")):
            logger.debug(
                "access id=%s %s %s %s in %.1fms",
                request_id,
                request.method,
                request.url.path,
                response.status_code,
                elapsed_ms,
            )
        else:
            logger.info(
                "access id=%s %s %s %s in %.1fms",
                request_id,
                request.method,
                request.url.path,
                response.status_code,
                elapsed_ms,
            )
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Conservative security headers on every response."""

    def __init__(self, app, settings: Settings) -> None:  # noqa: ANN001
        super().__init__(app)
        self._settings = settings
        # A deployment may add origins to the frame policy, but it may not
        # remove the baseline protections.
        self._csp = CONTENT_SECURITY_POLICY
        if settings.is_production:
            # HSTS only makes sense where TLS terminates; enabling it in
            # development would poison the browser's localhost HSTS cache.
            self._hsts = "max-age=31536000; includeSubDomains"
        else:
            self._hsts = None

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001, ANN201
        response: Response = await call_next(request)
        headers = response.headers
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("X-Frame-Options", "DENY")
        headers.setdefault("Referrer-Policy", "no-referrer")
        headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
        headers.setdefault("Content-Security-Policy", self._csp)
        if self._hsts:
            headers.setdefault("Strict-Transport-Security", self._hsts)
        if any(request.url.path.startswith(prefix) for prefix in NO_STORE_PATHS):
            # API responses carry incident detail; they must not be kept
            # in a shared cache after logout.
            headers.setdefault("Cache-Control", "no-store")
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject an over-sized declared request body with 413 before parsing."""

    def __init__(self, app, max_bytes: int) -> None:  # noqa: ANN001
        super().__init__(app)
        self._max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001, ANN201
        if self._max_bytes > 0:
            declared = request.headers.get("content-length")
            if declared is not None:
                try:
                    length = int(declared)
                except ValueError:
                    return JSONResponse(
                        status_code=400,
                        content={
                            "error": {
                                "code": "INVALID_REQUEST",
                                "message": "Content-Length is not a valid integer.",
                            }
                        },
                    )
                if length < 0:
                    return JSONResponse(
                        status_code=400,
                        content={
                            "error": {
                                "code": "INVALID_REQUEST",
                                "message": "Content-Length must not be negative.",
                            }
                        },
                    )
                if length > self._max_bytes:
                    # Deliberately does not echo the requested size back.
                    logger.warning(
                        "rejected over-sized request body id=%s limit=%d",
                        getattr(request.state, "request_id", ""),
                        self._max_bytes,
                    )
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error": {
                                "code": "PAYLOAD_TOO_LARGE",
                                "message": ("Request body exceeds the configured maximum size."),
                            }
                        },
                    )
        return await call_next(request)


__all__ = [
    "CONTENT_SECURITY_POLICY",
    "NO_STORE_PATHS",
    "BodySizeLimitMiddleware",
    "RequestContextMiddleware",
    "SecurityHeadersMiddleware",
]
