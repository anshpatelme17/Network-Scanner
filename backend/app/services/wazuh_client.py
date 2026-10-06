"""Wazuh REST API client (Step 27B).

Authenticated health check and bounded alert retrieval for one
operator-configured Wazuh manager. Every network call goes through the
shared :class:`~app.services.http_connector.ConnectorHttpClient`
(destination allow-list, timeout, bounded body, no redirects, safe
retries, secret redaction) — this module never touches a socket,
process, or generic HTTP helper directly.

Authentication abstraction: :class:`WazuhAuthenticator` is the only
place that mints a bearer token (``POST /security/user/authenticate``
with HTTP Basic over the configured base URL). The token lives in
memory on the client instance only: it is never returned to a caller,
never written to an audit row, never logged, and is registered as a
redaction secret so it cannot appear in any error message.

Documented API shapes (Wazuh 4.x; responses are parsed defensively):

- ``POST /security/user/authenticate`` → ``{"token": "<jwt>"}``
  (401 → ``AUTH_FAILED``).
- ``GET /manager/info`` → ``{"data": {...}, "error": 0}``.
- ``GET /alerts?limit=&offset=`` →
  ``{"data": {"totalItems": N, "alerts": [...]}, "error": 0}``
  (3.x-style ``{"data": [...], "totalItems": N}`` is also accepted).

Pagination is bounded by ``connector_max_pages`` and
``connector_max_events`` and terminates with an explicit reason
(``COMPLETED`` / ``MAX_PAGES`` / ``MAX_EVENTS`` /
``REPEATED_CURSOR`` / ``MALFORMED_PAGINATION``) so a poll can never
loop forever on a cursor the server keeps replaying.

Retrieved items come from the Wazuh ``/alerts`` *resource*, so each one
is stamped with the documented ``event_type`` ``"alert"`` (the resource
type) when the payload does not carry one. The platform never guesses a
category from message text; adapters still validate every record, and
records the adapter rejects are counted as rejected, not dropped.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from app.core.config import get_settings
from app.services.http_connector import (
    ConnectorHttpClient,
    ConnectorHttpError,
    HttpErrorCategory,
    allowed_hosts_for,
)

# The Wazuh resource this client reads is /alerts, i.e. rule alerts.
RESOURCE_EVENT_TYPE = "alert"

AUTH_PATH = "/security/user/authenticate"
INFO_PATH = "/manager/info"
ALERTS_PATH = "/alerts"
MAX_PAGE_SIZE = 100

TERMINATION_COMPLETED = "COMPLETED"
TERMINATION_MAX_PAGES = "MAX_PAGES"
TERMINATION_MAX_EVENTS = "MAX_EVENTS"
TERMINATION_REPEATED_CURSOR = "REPEATED_CURSOR"
TERMINATION_MALFORMED = "MALFORMED_PAGINATION"


@dataclass(frozen=True)
class WazuhConfig:
    """Validated Wazuh connection settings (no secret values exposed)."""

    base_url: str
    username: str
    password: str
    max_pages: int
    max_events: int

    @classmethod
    def from_settings(cls, settings: object) -> WazuhConfig:
        return cls(
            base_url=str(getattr(settings, "wazuh_api_url", "")).strip(),
            username=str(getattr(settings, "wazuh_username", "")).strip(),
            password=str(getattr(settings, "wazuh_password", "")),
            max_pages=int(getattr(settings, "connector_max_pages", 3)),
            max_events=int(getattr(settings, "connector_max_events", 100)),
        )

    @property
    def is_complete(self) -> bool:
        return bool(self.base_url and self.username and self.password)


@dataclass(frozen=True)
class CheckOutcome:
    """Result of one health check (safe to audit)."""

    ok: bool
    latency_ms: int
    detail: str
    category: HttpErrorCategory | None = None
    status_code: int | None = None
    retry_after: int | None = None


@dataclass
class FetchOutcome:
    """Bounded retrieval result with an explicit termination reason."""

    records: list[object] = field(default_factory=list)
    pages: int = 0
    termination: str = TERMINATION_COMPLETED


class WazuhAuthenticator:
    """Mints and holds a Wazuh API bearer token (memory only)."""

    def __init__(self, http: ConnectorHttpClient, username: str, password: str) -> None:
        self._http = http
        self._username = username
        self._password = password
        self._token: str | None = None

    @property
    def token(self) -> str | None:
        return self._token

    def invalidate(self) -> None:
        self._token = None

    def authenticate(self) -> str:
        """Exchange Basic credentials for a bearer token, or raise."""
        if self._token:
            return self._token
        credentials = base64.b64encode(f"{self._username}:{self._password}".encode()).decode(
            "ascii"
        )
        result = self._http.request_json(
            "POST",
            AUTH_PATH,
            headers={"Authorization": f"Basic {credentials}", "accept": "application/json"},
        )
        payload = result.json if isinstance(result.json, dict) else {}
        token = payload.get("token")
        if not isinstance(token, str) or not token.strip():
            raise ConnectorHttpError(
                HttpErrorCategory.MALFORMED_RESPONSE,
                "Wazuh authentication response did not include a token.",
                status_code=result.status_code,
                correlation_id=result.correlation_id,
            )
        self._token = token.strip()
        # The minted token becomes a redaction secret immediately.
        self._http.secrets = tuple(self._http.secrets) + (self._token,)
        return self._token


class WazuhClient:
    """Health checks and bounded alert retrieval for one Wazuh manager."""

    def __init__(self, config: WazuhConfig) -> None:
        if not config.base_url:
            raise ConnectorHttpError(
                HttpErrorCategory.NOT_CONFIGURED, "Wazuh API base URL is not configured."
            )
        settings = get_settings()
        self.config = config
        self._http = ConnectorHttpClient(
            base_url=config.base_url,
            allowed_hosts=allowed_hosts_for(settings),
            secrets=(config.password,),
        )
        self._auth = WazuhAuthenticator(self._http, config.username, config.password)

    def check(self) -> CheckOutcome:
        """Authenticate and read manager info; never raises for HTTP."""
        try:
            self._auth.authenticate()
            result = self._http.request_json(
                "GET", INFO_PATH, headers={"Authorization": f"Bearer {self._auth.token}"}
            )
        except ConnectorHttpError as exc:
            return CheckOutcome(
                ok=False,
                latency_ms=0,
                detail=self._describe_failure(exc),
                category=exc.category,
                status_code=exc.status_code,
                retry_after=exc.retry_after,
            )
        return CheckOutcome(
            ok=True,
            latency_ms=result.elapsed_ms,
            detail=(
                f"Authenticated and read manager info (HTTP {result.status_code}) "
                f"in {result.elapsed_ms} ms."
            ),
            status_code=result.status_code,
        )

    def fetch_alerts(self) -> FetchOutcome:
        """Retrieve a bounded set of alerts with explicit termination.

        Raises :class:`ConnectorHttpError` for any transport, auth, or
        payload failure — callers map the category to audit rows.
        """
        token = self._auth.authenticate()
        headers = {"Authorization": f"Bearer {token}", "accept": "application/json"}
        outcome = FetchOutcome()
        seen_offsets: set[int] = set()
        offset = 0
        page_size = min(self.config.max_events, MAX_PAGE_SIZE)
        termination = TERMINATION_MAX_PAGES

        for _page in range(self.config.max_pages):
            if offset in seen_offsets:
                termination = TERMINATION_REPEATED_CURSOR
                break
            seen_offsets.add(offset)
            result = self._http.request_json(
                "GET", ALERTS_PATH, headers=headers, params={"limit": page_size, "offset": offset}
            )
            outcome.pages += 1
            page_items, total = self._parse_alerts_page(result.json, result.correlation_id)
            if not page_items:
                termination = (
                    TERMINATION_COMPLETED
                    if total is not None and offset >= total
                    else TERMINATION_MALFORMED
                )
                break
            outcome.records.extend(
                self._stamp(item)
                for item in page_items[: max(0, self.config.max_events - len(outcome.records))]
            )
            if len(outcome.records) >= self.config.max_events:
                termination = TERMINATION_MAX_EVENTS
                break
            if total is None:
                termination = TERMINATION_MALFORMED
                break
            if offset + len(page_items) >= total:
                termination = TERMINATION_COMPLETED
                break
            offset += len(page_items)
        else:
            termination = TERMINATION_MAX_PAGES

        outcome.termination = termination
        return outcome

    # -- internals -------------------------------------------------------
    @staticmethod
    def _stamp(item: object) -> object:
        """Attach the resource-derived event_type when absent."""
        if isinstance(item, dict) and "event_type" not in item:
            stamped = dict(item)
            stamped["event_type"] = RESOURCE_EVENT_TYPE
            return stamped
        return item

    @staticmethod
    def _parse_alerts_page(payload: object, correlation_id: str) -> tuple[list[object], int | None]:
        if not isinstance(payload, dict):
            raise ConnectorHttpError(
                HttpErrorCategory.MALFORMED_RESPONSE,
                "Wazuh alerts response was not a JSON object.",
                correlation_id=correlation_id,
            )
        error = payload.get("error", 0)
        if isinstance(error, int) and not isinstance(error, bool) and error != 0:
            message = payload.get("message")
            detail = message if isinstance(message, str) and message.strip() else "unknown error"
            raise ConnectorHttpError(
                HttpErrorCategory.HTTP_ERROR,
                f"Wazuh API reported error {error}: {detail[:200]}",
                correlation_id=correlation_id,
            )
        data = payload.get("data")
        raw_items: object
        raw_total: object
        if isinstance(data, dict) and isinstance(data.get("alerts"), list):
            raw_items = data["alerts"]
            raw_total = data.get("totalItems")
        elif isinstance(data, list):
            raw_items = data
            raw_total = payload.get("totalItems")
        else:
            raise ConnectorHttpError(
                HttpErrorCategory.MALFORMED_RESPONSE,
                "Wazuh alerts response did not include a data.alerts list.",
                correlation_id=correlation_id,
            )
        items = list(raw_items) if isinstance(raw_items, list) else []
        total: int | None
        if isinstance(raw_total, int) and not isinstance(raw_total, bool) and raw_total >= 0:
            total = raw_total
        else:
            total = None
        return items, total

    @staticmethod
    def _describe_failure(exc: ConnectorHttpError) -> str:
        base = {
            HttpErrorCategory.AUTH_FAILED: "Wazuh rejected the credentials (HTTP 401/403).",
            HttpErrorCategory.RATE_LIMITED: "Wazuh rate-limited the request.",
            HttpErrorCategory.TIMEOUT: "Wazuh did not respond within the configured timeout.",
            HttpErrorCategory.CONNECTION_ERROR: "Could not reach the configured Wazuh endpoint.",
            HttpErrorCategory.HTTP_ERROR: "Wazuh returned an unexpected HTTP status.",
            HttpErrorCategory.RESPONSE_TOO_LARGE: "Wazuh response exceeded the size limit.",
            HttpErrorCategory.MALFORMED_RESPONSE: "Wazuh returned an unexpected payload.",
            HttpErrorCategory.DESTINATION_NOT_ALLOWED: "Destination is not allow-listed.",
            HttpErrorCategory.NOT_CONFIGURED: "Wazuh connector is not configured.",
        }.get(exc.category, "Wazuh check failed.")
        if exc.category is HttpErrorCategory.RATE_LIMITED and exc.retry_after is not None:
            return f"{base} Retry after {exc.retry_after} s."
        return base


__all__ = [
    "ALERTS_PATH",
    "AUTH_PATH",
    "CheckOutcome",
    "FetchOutcome",
    "INFO_PATH",
    "RESOURCE_EVENT_TYPE",
    "TERMINATION_COMPLETED",
    "TERMINATION_MALFORMED",
    "TERMINATION_MAX_EVENTS",
    "TERMINATION_MAX_PAGES",
    "TERMINATION_REPEATED_CURSOR",
    "WazuhAuthenticator",
    "WazuhClient",
    "WazuhConfig",
]
