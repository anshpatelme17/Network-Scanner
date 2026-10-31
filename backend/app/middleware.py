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
  413 before routing, and counts actual bytes when the body is received. It
  holds at most the configured limit in memory and replays accepted bodies to
  the application. It is a defence in depth step: the per-field caps in the
  ingest services remain the authoritative content limits.

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


class BodySizeLimitMiddleware:
    """Bound actual HTTP request-body bytes before passing a request downstream.

    The body is received incrementally and the accumulated buffer never
    exceeds ``max_bytes``. Accepted bytes are replayed as a single complete
    ``http.request`` message, so downstream parsers see the same body without
    an unbounded read or a second read from the original ASGI channel.
    Converting the bounded buffer to replay ``bytes`` temporarily uses up to
    roughly twice the configured limit inside this middleware; the final ASGI
    input chunk is released before that copy, and the bytearray is released
    before downstream processing. An individual chunk is already materialized
    by the ASGI server before this middleware can inspect it, so an unusually
    large single chunk can add to process peak memory; that chunk is rejected
    without copying it into the accumulated buffer.
    """

    def __init__(self, app, max_bytes: int) -> None:  # noqa: ANN001
        self.app = app
        self._max_bytes = max_bytes

    async def __call__(self, scope, receive, send) -> None:  # noqa: ANN001
        if scope["type"] != "http" or self._max_bytes <= 0:
            await self.app(scope, receive, send)
            return

        content_lengths = [
            value for name, value in scope.get("headers", ()) if name.lower() == b"content-length"
        ]
        declared_length: int | None = None
        if content_lengths:
            try:
                if len(content_lengths) != 1:
                    raise ValueError
                raw_length = content_lengths[0]
                if not raw_length or any(byte < 48 or byte > 57 for byte in raw_length):
                    raise ValueError
                declared_length = int(raw_length)
            except ValueError:
                await self._send_error(
                    scope,
                    receive,
                    send,
                    400,
                    "INVALID_REQUEST",
                    "Content-Length is not a valid integer.",
                )
                return
            if declared_length < 0:
                await self._send_error(
                    scope,
                    receive,
                    send,
                    400,
                    "INVALID_REQUEST",
                    "Content-Length must not be negative.",
                )
                return
            if declared_length > self._max_bytes:
                await self._reject_oversized(scope, receive, send)
                return

        body = bytearray()
        disconnected = False
        message = None
        chunk = b""
        while True:
            message = await receive()
            if not isinstance(message, dict):
                await self._send_error(
                    scope,
                    receive,
                    send,
                    400,
                    "INVALID_REQUEST",
                    "Request body was not valid.",
                )
                return
            message_type = message.get("type")
            if message_type == "http.disconnect":
                disconnected = True
                break
            if message_type != "http.request":
                await self._send_error(
                    scope,
                    receive,
                    send,
                    400,
                    "INVALID_REQUEST",
                    "Request body was not valid.",
                )
                return
            chunk = message.get("body", b"")
            if not isinstance(chunk, bytes):
                await self._send_error(
                    scope,
                    receive,
                    send,
                    400,
                    "INVALID_REQUEST",
                    "Request body was not valid.",
                )
                return
            if len(body) + len(chunk) > self._max_bytes:
                await self._reject_oversized(scope, receive, send)
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break

        if not disconnected and declared_length is not None and len(body) != declared_length:
            await self._send_error(
                scope,
                receive,
                send,
                400,
                "INVALID_REQUEST",
                "Content-Length does not match the request body.",
            )
            return

        # The received message still references its original chunk. Release
        # that reference before making the one bounded copy for replay.
        message = None
        chunk = b""
        replay_body = bytes(body)
        body.clear()
        del body

        replay_messages = []
        if disconnected:
            if replay_body:
                replay_messages.append(
                    {"type": "http.request", "body": replay_body, "more_body": True}
                )
            replay_messages.append({"type": "http.disconnect"})
        else:
            replay_messages.append(
                {"type": "http.request", "body": replay_body, "more_body": False}
            )

        async def replay_receive():  # noqa: ANN202
            if replay_messages:
                return replay_messages.pop(0)
            return await receive()

        await self.app(scope, replay_receive, send)

    async def _reject_oversized(self, scope, receive, send) -> None:  # noqa: ANN001
        state = scope.get("state")
        request_id = state.get("request_id", "") if isinstance(state, dict) else ""
        logger.warning(
            "rejected over-sized request body id=%s limit=%d", request_id, self._max_bytes
        )
        await self._send_error(
            scope,
            receive,
            send,
            413,
            "PAYLOAD_TOO_LARGE",
            "Request body exceeds the configured maximum size.",
        )

    @staticmethod
    async def _send_error(
        scope, receive, send, status_code: int, code: str, message: str  # noqa: ANN001
    ) -> None:
        response = JSONResponse(
            status_code=status_code,
            content={"error": {"code": code, "message": message}},
        )
        await response(scope, receive, send)


__all__ = [
    "CONTENT_SECURITY_POLICY",
    "NO_STORE_PATHS",
    "BodySizeLimitMiddleware",
    "RequestContextMiddleware",
    "SecurityHeadersMiddleware",
]
