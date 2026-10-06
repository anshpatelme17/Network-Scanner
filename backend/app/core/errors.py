"""Consistent API error format and exception handlers.

All errors returned to clients look like::

    {"error": {"code": "SOME_ERROR_CODE", "message": "Human-readable message"}}

Stack traces and internal details are never exposed in production.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import Settings
from app.core.ratelimit import RateLimitExceeded

logger = logging.getLogger(__name__)


def error_response(
    code: str, message: str, status_code: int, headers: dict[str, str] | None = None
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
        headers=headers or None,
    )


class AuthHTTPException(StarletteHTTPException):
    """Authorization failure carrying a project error code (Step 20).

    Raised by authorization dependencies (which cannot return endpoint
    responses) and rendered into the standard envelope by the handler
    below. Carries no secrets — code and message only.
    """

    def __init__(self, code: str, message: str, status_code: int) -> None:
        super().__init__(status_code=status_code, detail=message)
        self.code = code


def safe_validation_summary(exc: RequestValidationError) -> list[dict[str, object]]:
    """A log-safe summary of a validation failure: type and location only.

    ``RequestValidationError.errors()`` includes an ``input`` key holding the
    submitted value — and, for a ``missing`` field, the *entire request
    body*. A password, token or API key therefore reaches the log verbatim.
    The redaction filter cannot compensate: its pattern requires the field
    name to be immediately followed by ``:``/``=``, whereas Pydantic renders
    ``'password': '…'``, so the substitution never matches.

    Keeping only ``type`` and ``loc`` preserves the diagnostic value an
    operator actually needs — which field failed, and in what way — while
    making a value leak structurally impossible rather than dependent on
    a pattern staying in sync. ``msg`` is omitted deliberately: it is
    derivable from ``type`` for every built-in Pydantic error, and a
    custom validator is free to interpolate the offending value into it.
    """
    return [{"type": error.get("type"), "loc": error.get("loc")} for error in exc.errors()]


def register_exception_handlers(app: FastAPI, settings: Settings) -> None:
    @app.exception_handler(RateLimitExceeded)
    async def _rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
        # Step 31: a resource budget, not an authorization decision. The
        # message names the operation and the wait, never the caller's
        # identity or current budget state.
        return error_response(
            "RATE_LIMITED",
            (
                f"Too many {exc.operation.replace('_', ' ')} requests. "
                f"Retry after {exc.retry_after} second(s)."
            ),
            status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(exc.retry_after)},
        )

    @app.exception_handler(AuthHTTPException)
    async def _auth_exception_handler(request: Request, exc: AuthHTTPException) -> JSONResponse:
        return error_response(exc.code, str(exc.detail), exc.status_code)

    @app.exception_handler(StarletteHTTPException)
    async def _http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        code = "NOT_FOUND" if exc.status_code == 404 else "HTTP_ERROR"
        if exc.status_code == 404:
            message = f"Resource not found: {request.url.path}"
        elif isinstance(exc.detail, str) and exc.detail:
            message = exc.detail
        else:
            message = "Request failed."
        return error_response(code, message, exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def _validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Log the failure shape only. `exc.errors()` would put submitted
        # values (and, for a missing field, the whole body) into the log.
        logger.warning(
            "Validation error on %s: %s",
            request.url.path,
            safe_validation_summary(exc),
        )
        return error_response(
            "VALIDATION_ERROR",
            "Invalid request. Please check the request parameters and body.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    @app.exception_handler(Exception)
    async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:  # noqa: BLE001
        # Never log secrets; exc messages could contain user input only. The
        # correlation id is the client's handle for this record: it is safe
        # to return because it is generated/sanitised, not caller text.
        from app.core.request_context import get_request_id

        logger.exception(
            "Unhandled error id=%s on %s %s",
            get_request_id() or "-",
            request.method,
            request.url.path,
        )
        # Step 31: even outside production the client gets the exception
        # TYPE only. The message of a SQLAlchemy/OSError exception can
        # contain SQL text, bound parameters, filesystem paths, or DSN
        # fragments, and a development client does not need it. The full
        # detail stays in the server log, reachable via the request id.
        if settings.debug and not settings.is_production:
            message = f"Internal server error ({type(exc).__name__})."
        else:
            message = "Internal server error."
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": {"code": "INTERNAL_ERROR", "message": message}},
            headers={"X-Request-ID": get_request_id()} if get_request_id() else None,
        )
