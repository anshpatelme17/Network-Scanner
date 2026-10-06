"""Shared outbound HTTP foundation for live connectors (Step 27D).

One controlled path for every connector HTTP call: Wazuh and Microsoft
Defender clients are built on top of :class:`ConnectorHttpClient`, and
no other module performs outbound requests.

Safety properties (server-side only, never client-influenced):

- **Destination allow-list.** Every request URL's scheme must be
  ``http``/``https`` and its hostname must be one of the *configured*
  connector destinations (derived from settings). Client input never
  reaches this layer; callers pass a fixed path or a server-returned
  pagination URL that is re-validated against the same allow-list.
- **No redirects.** ``follow_redirects`` is disabled, so a 3xx is an
  explicit structured error instead of an open redirector.
- **Timeouts.** Every request carries a bounded timeout from settings.
- **Bounded bodies.** Responses are streamed and hard-capped at
  ``connector_max_response_bytes``; exceeding it raises
  ``RESPONSE_TOO_LARGE`` before the body is materialized.
- **Safe status handling.** 401/403 → ``AUTH_FAILED``; 429 →
  ``RATE_LIMITED`` (with ``Retry-After`` seconds when numeric); other
  non-2xx → ``HTTP_ERROR``; transport failures → ``TIMEOUT`` /
  ``CONNECTION_ERROR``.
- **Safe retries only.** At most ``connector_retry_max`` extra attempts
  and only for idempotent GETs on 429/503/timeout/connection errors.
- **Secret redaction.** Configured secret values (passwords, client
  secrets, minted tokens) are stripped from every message this layer
  produces; Authorization headers are never echoed.
- **Correlation.** Each attempt is tagged with a correlation id that is
  safe to audit.

This is *not* a generic HTTP proxy: there is no client-selectable URL,
method, header, or body anywhere in the connector path.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse

import httpx

from app.core.config import get_settings

# Response headers that may be surfaced to callers/audits. Everything
# else (notably ``Authorization``) is dropped at the boundary.
SAFE_HEADERS = frozenset(
    {
        "content-type",
        "retry-after",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "www-authenticate",
    }
)

RETRYABLE_STATUSES = frozenset({429, 503})
DEFAULT_MAX_RETRY_SLEEP_SECONDS = 2.0


class HttpErrorCategory(str, Enum):
    """Structured, secret-free failure categories for connector HTTP."""

    NOT_CONFIGURED = "NOT_CONFIGURED"
    DESTINATION_NOT_ALLOWED = "DESTINATION_NOT_ALLOWED"
    TIMEOUT = "TIMEOUT"
    CONNECTION_ERROR = "CONNECTION_ERROR"
    AUTH_FAILED = "AUTH_FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    HTTP_ERROR = "HTTP_ERROR"
    RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"


class ConnectorHttpError(Exception):
    """A connector HTTP failure with a safe category and message."""

    def __init__(
        self,
        category: HttpErrorCategory,
        message: str,
        *,
        status_code: int | None = None,
        retry_after: int | None = None,
        correlation_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.message = message
        self.status_code = status_code
        self.retry_after = retry_after
        self.correlation_id = correlation_id

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message


@dataclass(frozen=True)
class HttpResult:
    """One successful (2xx) connector HTTP response, already bounded."""

    status_code: int
    body_text: str
    json: Any | None
    headers: dict[str, str] = field(default_factory=dict)
    elapsed_ms: int = 0
    attempts: int = 1
    correlation_id: str = ""


def redact(text: str, secrets: tuple[str, ...]) -> str:
    """Remove configured secret values from a message (best effort)."""
    result = text
    for secret in secrets:
        if secret and len(secret) >= 4 and secret in result:
            result = result.replace(secret, "***")
    return result


def allowed_hosts_for(settings: Any) -> frozenset[str]:
    """Hostnames this deployment may contact, derived from settings only."""
    hosts: set[str] = set()
    for url in (
        getattr(settings, "wazuh_api_url", ""),
        getattr(settings, "defender_api_endpoint", ""),
        getattr(settings, "defender_authority", ""),
    ):
        if not url or not str(url).strip():
            continue
        parsed = urlparse(str(url).strip())
        if parsed.hostname:
            hosts.add(parsed.hostname.lower())
    return frozenset(hosts)


def validate_destination(url: str, allowed_hosts: frozenset[str]) -> None:
    """Reject anything that is not an allow-listed http(s) destination."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ConnectorHttpError(
            HttpErrorCategory.DESTINATION_NOT_ALLOWED,
            f"Destination scheme {parsed.scheme or '(none)'!r} is not permitted.",
        )
    hostname = (parsed.hostname or "").lower()
    if not hostname or hostname not in allowed_hosts:
        raise ConnectorHttpError(
            HttpErrorCategory.DESTINATION_NOT_ALLOWED,
            "Destination host is not an allow-listed connector endpoint.",
        )


def join_url(base_url: str, path: str) -> str:
    """Compose a fixed path onto the configured base URL."""
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return base_url.rstrip("/") + "/" + path.lstrip("/")


# --- test-only transport hook -------------------------------------------------
# Tests install an httpx.MockTransport here so the whole suite runs without
# any real network. Production never sets it (None = real transport).
_test_transport: httpx.BaseTransport | None = None


def install_test_transport(transport: httpx.BaseTransport | None) -> None:
    """TEST-ONLY: inject a mocked transport for connector HTTP."""
    global _test_transport
    _test_transport = transport


def clear_test_transport() -> None:
    """TEST-ONLY: remove the injected transport."""
    global _test_transport
    _test_transport = None


def _parse_retry_after(value: str | None) -> int | None:
    if not value:
        return None
    try:
        seconds = int(value.strip())
    except ValueError:
        return None  # HTTP-date form is deliberately not supported
    return max(0, seconds)


class ConnectorHttpClient:
    """Bounded, allow-listed HTTP client for one connector destination."""

    def __init__(
        self,
        *,
        base_url: str,
        allowed_hosts: frozenset[str],
        secrets: tuple[str, ...] = (),
        timeout_seconds: float | None = None,
        max_response_bytes: int | None = None,
        verify_tls: bool | None = None,
        retry_max: int | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        settings = get_settings()
        self.base_url = (base_url or "").strip().rstrip("/")
        self.allowed_hosts = allowed_hosts
        self.secrets = tuple(secrets)
        self.timeout = (
            timeout_seconds if timeout_seconds is not None else settings.connector_timeout_seconds
        )
        self.max_bytes = (
            max_response_bytes
            if max_response_bytes is not None
            else settings.connector_max_response_bytes
        )
        self.verify_tls = settings.connector_verify_tls if verify_tls is None else verify_tls
        self.retry_max = settings.connector_retry_max if retry_max is None else retry_max
        self._sleep = sleep_fn

    # -- helpers ---------------------------------------------------------
    def _redact(self, message: str) -> str:
        return redact(message, self.secrets)

    def _new_client(self) -> httpx.Client:
        return httpx.Client(
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=False,
            verify=self.verify_tls,
            transport=_test_transport,
        )

    def _read_bounded(self, response: httpx.Response) -> bytes:
        chunks: list[bytes] = []
        size = 0
        for chunk in response.iter_bytes():
            size += len(chunk)
            if size > self.max_bytes:
                raise ConnectorHttpError(
                    HttpErrorCategory.RESPONSE_TOO_LARGE,
                    f"Response exceeded the {self.max_bytes}-byte connector limit.",
                    status_code=response.status_code,
                )
            chunks.append(chunk)
        return b"".join(chunks)

    @staticmethod
    def _safe_headers(response: httpx.Response) -> dict[str, str]:
        return {
            name: value for name, value in response.headers.items() if name.lower() in SAFE_HEADERS
        }

    # -- core request ----------------------------------------------------
    def request(
        self,
        method: str,
        path_or_url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_body: Any | None = None,
        timeout_override: float | None = None,
    ) -> HttpResult:
        """Perform one bounded request and return a 2xx result.

        Raises :class:`ConnectorHttpError` with a structured category for
        every failure mode. Never includes credentials or response
        bodies in error messages.
        """
        method = method.upper()
        if not self.base_url:
            raise ConnectorHttpError(
                HttpErrorCategory.NOT_CONFIGURED, "Connector base URL is not configured."
            )
        url = join_url(self.base_url, path_or_url)
        validate_destination(url, self.allowed_hosts)

        max_attempts = 1 + (self.retry_max if method == "GET" else 0)
        correlation_id = uuid.uuid4().hex[:16]
        last_error: ConnectorHttpError | None = None
        started = time.perf_counter()

        for attempt in range(1, max_attempts + 1):
            request_headers = dict(headers or {})
            try:
                with self._new_client() as client:
                    with client.stream(
                        method,
                        url,
                        headers=request_headers,
                        params=params,
                        data=data,
                        json=json_body,
                        timeout=httpx.Timeout(timeout_override or self.timeout),
                    ) as response:
                        body = self._read_bounded(response)
                        status = response.status_code
                        safe_headers = self._safe_headers(response)

                        if 200 <= status < 300:
                            parsed: Any | None
                            text = body.decode("utf-8", errors="replace")
                            try:
                                parsed = json.loads(text) if text.strip() else None
                            except ValueError:
                                parsed = None
                            return HttpResult(
                                status_code=status,
                                body_text=text,
                                json=parsed,
                                headers=safe_headers,
                                elapsed_ms=int((time.perf_counter() - started) * 1000),
                                attempts=attempt,
                                correlation_id=correlation_id,
                            )

                        if status in {401, 403}:
                            raise ConnectorHttpError(
                                HttpErrorCategory.AUTH_FAILED,
                                f"Connector endpoint rejected the request (HTTP {status}).",
                                status_code=status,
                                correlation_id=correlation_id,
                            )
                        if status == 429:
                            retry_after = _parse_retry_after(response.headers.get("retry-after"))
                            raise ConnectorHttpError(
                                HttpErrorCategory.RATE_LIMITED,
                                "Connector endpoint rate-limited the request.",
                                status_code=status,
                                retry_after=retry_after,
                                correlation_id=correlation_id,
                            )
                        if status in {301, 302, 303, 307, 308}:
                            raise ConnectorHttpError(
                                HttpErrorCategory.HTTP_ERROR,
                                f"Unexpected redirect (HTTP {status}); redirects are not followed.",
                                status_code=status,
                                correlation_id=correlation_id,
                            )
                        raise ConnectorHttpError(
                            HttpErrorCategory.HTTP_ERROR,
                            f"Connector endpoint returned HTTP {status}.",
                            status_code=status,
                            correlation_id=correlation_id,
                        )
            except ConnectorHttpError as exc:
                last_error = exc
                retryable = (
                    method == "GET"
                    and attempt < max_attempts
                    and (
                        exc.category is HttpErrorCategory.RATE_LIMITED
                        and exc.status_code in RETRYABLE_STATUSES
                        or exc.category is HttpErrorCategory.HTTP_ERROR
                        and exc.status_code in RETRYABLE_STATUSES
                        or exc.category
                        in {HttpErrorCategory.TIMEOUT, HttpErrorCategory.CONNECTION_ERROR}
                    )
                )
                if not retryable:
                    raise
                wait = float(exc.retry_after or 0.25)
                self._sleep(min(wait, DEFAULT_MAX_RETRY_SLEEP_SECONDS))
            except httpx.TimeoutException:
                last_error = ConnectorHttpError(
                    HttpErrorCategory.TIMEOUT,
                    f"Connector request timed out after {self.timeout:g}s.",
                    correlation_id=correlation_id,
                )
                if method == "GET" and attempt < max_attempts:
                    self._sleep(min(0.25, DEFAULT_MAX_RETRY_SLEEP_SECONDS))
                    continue
                raise last_error from None
            except httpx.TransportError:
                last_error = ConnectorHttpError(
                    HttpErrorCategory.CONNECTION_ERROR,
                    "Could not reach the configured connector endpoint.",
                    correlation_id=correlation_id,
                )
                if method == "GET" and attempt < max_attempts:
                    self._sleep(min(0.25, DEFAULT_MAX_RETRY_SLEEP_SECONDS))
                    continue
                raise last_error from None

        raise last_error or ConnectorHttpError(
            HttpErrorCategory.HTTP_ERROR, "Connector request failed.", correlation_id=correlation_id
        )

    def request_json(
        self,
        method: str,
        path_or_url: str,
        *,
        expect_json: bool = True,
        **kwargs: Any,
    ) -> HttpResult:
        """Perform a request and require a JSON body when one is expected."""
        result = self.request(method, path_or_url, **kwargs)
        if expect_json and result.json is None:
            raise ConnectorHttpError(
                HttpErrorCategory.MALFORMED_RESPONSE,
                "Connector endpoint returned a body that is not valid JSON.",
                status_code=result.status_code,
                correlation_id=result.correlation_id,
            )
        return result


__all__ = [
    "ConnectorHttpClient",
    "ConnectorHttpError",
    "HttpErrorCategory",
    "HttpResult",
    "SAFE_HEADERS",
    "allowed_hosts_for",
    "clear_test_transport",
    "install_test_transport",
    "join_url",
    "redact",
    "validate_destination",
]
