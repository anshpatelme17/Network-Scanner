"""Rate-limit dependencies for resource-heavy operations (Step 31).

A thin FastAPI adapter over :mod:`app.core.ratelimit`. Limits come from
``Settings`` only — never from a request body, query parameter, or
header — and a limit of ``0`` disables the check for that operation.

On exceeding a budget the dependency raises
:class:`~app.core.ratelimit.RateLimitExceeded`, which
``register_exception_handlers`` renders as a 429 envelope with a
``Retry-After`` header. Raising (rather than returning a response) is
deliberate: a value returned from a dependency is not reliably treated as
the final response, whereas an exception always reaches the handler.

This is resource protection, not a security control. It sits *after*
authentication and authorization in the endpoint's dependency list, so an
unauthorized caller still receives 401/403 and never consumes a budget,
and it never widens what an authorized caller may do.
"""

from __future__ import annotations

from fastapi import Request

from app.core.config import get_settings
from app.core.ratelimit import enforce_rate_limit


def rate_limit(operation: str, setting: str):
    """Build a dependency enforcing one configured budget.

    ``setting`` is the name of the ``Settings`` field holding the limit
    (named explicitly so a typo fails loudly at import time rather than
    silently disabling a limit).
    """

    async def _dependency(request: Request) -> None:
        limit = getattr(get_settings(), setting)
        enforce_rate_limit(request, operation, limit)

    return _dependency


__all__ = ["rate_limit"]
