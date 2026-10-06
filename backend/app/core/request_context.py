"""Request-scoped correlation context (Step 31).

A request id is minted once per request (or taken from an inbound
``X-Request-ID`` header, sanitised) and published through a
:class:`contextvars.ContextVar` so that any layer can attach it to a log
line or an audit row without threading it through every signature.

Deliberately absent: the inbound value is never trusted as-is. It is
stripped to a conservative character set and length so a caller cannot
inject newlines or control characters into log records, and it is only
ever echoed back, never interpreted.
"""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar

REQUEST_ID_HEADER = "X-Request-ID"
MAX_REQUEST_ID_LENGTH = 64

# Conservative allow-list: hex digits and dashes only. Anything else is
# discarded in favour of a freshly generated id, which removes the
# log-injection vector that echoing a caller-supplied id would otherwise
# create.
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")

_current_request_id: ContextVar[str] = ContextVar("request_id", default="")


def new_request_id() -> str:
    """Generate a fresh correlation id."""
    return uuid.uuid4().hex


def sanitize_request_id(value: str | None) -> str:
    """Return a safe correlation id for an inbound header value.

    An unusable or over-long value is replaced rather than truncated, so
    two different requests can never share a correlation id.
    """
    if value and _SAFE_REQUEST_ID.match(value.strip()):
        return value.strip()[:MAX_REQUEST_ID_LENGTH]
    return new_request_id()


def set_request_id(value: str) -> str:
    """Bind the correlation id for the current request and return it."""
    _current_request_id.set(value)
    return value


def get_request_id() -> str:
    """Correlation id for the current request, or "" outside a request."""
    return _current_request_id.get()


def current_request_id_or_new() -> str:
    """Correlation id, generating one when called outside a request."""
    value = get_request_id()
    return value or set_request_id(new_request_id())


__all__ = [
    "MAX_REQUEST_ID_LENGTH",
    "REQUEST_ID_HEADER",
    "current_request_id_or_new",
    "get_request_id",
    "new_request_id",
    "sanitize_request_id",
    "set_request_id",
]
