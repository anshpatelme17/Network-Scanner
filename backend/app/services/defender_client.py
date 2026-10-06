"""Microsoft Defender for Endpoint / Graph client (Step 27C).

OAuth2 client-credentials authentication and bounded alert retrieval
from Microsoft Graph for one operator-configured tenant. Every network
call goes through the shared
:class:`~app.services.http_connector.ConnectorHttpClient` (destination
allow-list, timeout, bounded body, no redirects, safe retries, secret
redaction); this module never touches a socket, process, or generic
HTTP helper directly.

Authentication abstraction: :class:`DefenderTokenProvider` is the only
place that requests an access token
(``POST {authority}/{tenant}/oauth2/v2.0/token``). The provider is
injected into :class:`DefenderClient`, so a future MSAL-backed
implementation can replace it without touching retrieval code. Tokens
live in memory on the provider only — never returned, never audited,
never logged — and are registered as redaction secrets. The client
secret itself is a redaction secret from construction onward.

Documented API shapes:

- Token: ``{"access_token": "...", "expires_in": 3599}``; invalid
  credentials surface as HTTP 400/401/403 and are mapped to
  ``AUTH_FAILED`` (the token endpoint has no "connected" state we can
  claim without holding valid credentials).
- Alerts: ``GET {endpoint}/security/alerts?$top=N`` →
  ``{"value": [...], "@odata.nextLink": "https://..."}``.

Pagination follows ``@odata.nextLink`` up to ``connector_max_pages``
pages and ``connector_max_events`` records. Each nextLink is
re-validated against the destination allow-list before it is used, so a
hostile or misconfigured server cannot steer the backend at another
host; a repeated nextLink terminates with ``REPEATED_CURSOR``.

Retrieved items come from the Graph ``security/alerts`` *resource*, so
each one is stamped with the documented ``event_type`` ``"alert"`` when
absent, and real detection timestamps (``firstDetectedDateTime`` /
``createdDateTime`` / ``lastUpdatedDateTime``) plus the host computer
name are mapped onto the adapter's documented field names. Nothing is
invented: absent fields stay absent, and the adapter still validates
every record (rejects are counted, never dropped).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.config import get_settings
from app.services.http_connector import (
    ConnectorHttpClient,
    ConnectorHttpError,
    HttpErrorCategory,
    allowed_hosts_for,
    validate_destination,
)

RESOURCE_EVENT_TYPE = "alert"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
ALERTS_PATH = "/security/alerts"
TOKEN_PATH_TEMPLATE = "/{tenant}/oauth2/v2.0/token"

TERMINATION_COMPLETED = "COMPLETED"
TERMINATION_MAX_PAGES = "MAX_PAGES"
TERMINATION_MAX_EVENTS = "MAX_EVENTS"
TERMINATION_REPEATED_CURSOR = "REPEATED_CURSOR"
TERMINATION_MALFORMED = "MALFORMED_PAGINATION"

TIMESTAMP_FIELDS = ("firstDetectedDateTime", "createdDateTime", "lastUpdatedDateTime")


@dataclass(frozen=True)
class DefenderConfig:
    """Validated Defender connection settings (no secret values exposed)."""

    tenant_id: str
    client_id: str
    client_secret: str
    api_endpoint: str
    authority: str
    max_pages: int
    max_events: int

    @classmethod
    def from_settings(cls, settings: object) -> DefenderConfig:
        return cls(
            tenant_id=str(getattr(settings, "defender_tenant_id", "")).strip(),
            client_id=str(getattr(settings, "defender_client_id", "")).strip(),
            client_secret=str(getattr(settings, "defender_client_secret", "")),
            api_endpoint=str(getattr(settings, "defender_api_endpoint", "")).strip(),
            authority=str(getattr(settings, "defender_authority", "")).strip(),
            max_pages=int(getattr(settings, "connector_max_pages", 3)),
            max_events=int(getattr(settings, "connector_max_events", 100)),
        )

    @property
    def is_complete(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)


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


class DefenderTokenProvider:
    """Client-credentials token provider (memory-only token)."""

    def __init__(self, http: ConnectorHttpClient, config: DefenderConfig) -> None:
        self._http = http
        self._config = config
        self._token: str | None = None

    @property
    def token(self) -> str | None:
        return self._token

    def invalidate(self) -> None:
        self._token = None

    def get_token(self) -> str:
        """Return a bearer token, exchanging credentials when needed."""
        if self._token:
            return self._token
        try:
            result = self._http.request(
                "POST",
                TOKEN_PATH_TEMPLATE.format(tenant=self._config.tenant_id),
                data={
                    "client_id": self._config.client_id,
                    "client_secret": self._config.client_secret,
                    "scope": GRAPH_SCOPE,
                    "grant_type": "client_credentials",
                },
                headers={"accept": "application/json"},
            )
        except ConnectorHttpError as exc:
            rejected = exc.category is HttpErrorCategory.AUTH_FAILED or (
                exc.category is HttpErrorCategory.HTTP_ERROR and exc.status_code == 400
            )
            if rejected:
                raise ConnectorHttpError(
                    HttpErrorCategory.AUTH_FAILED,
                    "Defender token endpoint rejected the client credentials.",
                    status_code=exc.status_code,
                    correlation_id=exc.correlation_id,
                ) from None
            raise
        payload = result.json if isinstance(result.json, dict) else {}
        token = payload.get("access_token")
        if not isinstance(token, str) or not token.strip():
            raise ConnectorHttpError(
                HttpErrorCategory.MALFORMED_RESPONSE,
                "Defender token response did not include an access token.",
                status_code=result.status_code,
                correlation_id=result.correlation_id,
            )
        self._token = token.strip()
        # The minted token becomes a redaction secret immediately.
        self._http.secrets = tuple(self._http.secrets) + (self._token,)
        return self._token


class DefenderClient:
    """Health checks and bounded alert retrieval for one Defender tenant."""

    def __init__(self, config: DefenderConfig) -> None:
        if not (config.api_endpoint and config.authority):
            raise ConnectorHttpError(
                HttpErrorCategory.NOT_CONFIGURED, "Defender API endpoint is not configured."
            )
        settings = get_settings()
        self.config = config
        allowed = allowed_hosts_for(settings)
        self._api_http = ConnectorHttpClient(
            base_url=config.api_endpoint,
            allowed_hosts=allowed,
            secrets=(config.client_secret,),
        )
        self._token_http = ConnectorHttpClient(
            base_url=config.authority,
            allowed_hosts=allowed,
            secrets=(config.client_secret,),
        )
        self._provider = DefenderTokenProvider(self._token_http, config)

    def check(self) -> CheckOutcome:
        """Request a token and read one alert page; never raises for HTTP."""
        try:
            token = self._provider.get_token()
            result = self._api_http.request_json(
                "GET",
                ALERTS_PATH,
                headers={"Authorization": f"Bearer {token}"},
                params={"$top": 1},
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
                f"Exchanged credentials and read security alerts (HTTP {result.status_code}) "
                f"in {result.elapsed_ms} ms."
            ),
            status_code=result.status_code,
        )

    def fetch_alerts(self) -> FetchOutcome:
        """Retrieve a bounded set of alerts with explicit termination.

        Raises :class:`ConnectorHttpError` for any transport, auth, or
        payload failure — callers map the category to audit rows.
        """
        token = self._provider.get_token()
        headers = {"Authorization": f"Bearer {token}", "accept": "application/json"}
        outcome = FetchOutcome()
        url: str | None = ALERTS_PATH
        params: dict[str, object] | None = {"$top": min(self.config.max_events, 50)}
        seen_urls: set[str] = set()
        termination = TERMINATION_MAX_PAGES

        for _page in range(self.config.max_pages):
            if url is None:
                termination = TERMINATION_COMPLETED
                break
            if url in seen_urls:
                termination = TERMINATION_REPEATED_CURSOR
                break
            seen_urls.add(url)
            result = self._api_http.request_json("GET", url, headers=headers, params=params)
            outcome.pages += 1
            page_items, next_link = self._parse_alerts_page(result.json, result.correlation_id)
            if not page_items:
                termination = TERMINATION_MALFORMED if next_link else TERMINATION_COMPLETED
                break
            outcome.records.extend(
                self._stamp(item)
                for item in page_items[: max(0, self.config.max_events - len(outcome.records))]
            )
            if len(outcome.records) >= self.config.max_events:
                termination = TERMINATION_MAX_EVENTS
                break
            if not next_link:
                termination = TERMINATION_COMPLETED
                break
            # Server-provided URL is re-validated against our allow-list.
            validate_destination(next_link, self._api_http.allowed_hosts)
            url = next_link
            params = None  # nextLink carries its own query string
        else:
            termination = TERMINATION_MAX_PAGES

        outcome.termination = termination
        return outcome

    # -- internals -------------------------------------------------------
    @staticmethod
    def _stamp(item: object) -> object:
        """Attach resource-derived and documented field mappings."""
        if not isinstance(item, dict):
            return item
        record = dict(item)
        if "event_type" not in record:
            record["event_type"] = RESOURCE_EVENT_TYPE
        if not record.get("timestamp"):
            for name in TIMESTAMP_FIELDS:
                value = record.get(name)
                if isinstance(value, str) and value.strip():
                    record["timestamp"] = value
                    break
        host = record.get("host")
        if isinstance(host, dict) and isinstance(host.get("computerName"), str):
            record.setdefault("deviceName", host["computerName"])
        return record

    @staticmethod
    def _parse_alerts_page(payload: object, correlation_id: str) -> tuple[list[object], str | None]:
        if not isinstance(payload, dict) or not isinstance(payload.get("value"), list):
            raise ConnectorHttpError(
                HttpErrorCategory.MALFORMED_RESPONSE,
                "Defender alerts response did not include a value list.",
                correlation_id=correlation_id,
            )
        items = list(payload["value"])
        next_link = payload.get("@odata.nextLink")
        if isinstance(next_link, str) and next_link.strip():
            return items, next_link.strip()
        return items, None

    @staticmethod
    def _describe_failure(exc: ConnectorHttpError) -> str:
        base = {
            HttpErrorCategory.AUTH_FAILED: "Defender rejected the client credentials.",
            HttpErrorCategory.RATE_LIMITED: "Defender rate-limited the request.",
            HttpErrorCategory.TIMEOUT: "Defender did not respond within the configured timeout.",
            HttpErrorCategory.CONNECTION_ERROR: "Could not reach the configured Defender endpoint.",
            HttpErrorCategory.HTTP_ERROR: "Defender returned an unexpected HTTP status.",
            HttpErrorCategory.RESPONSE_TOO_LARGE: "Defender response exceeded the size limit.",
            HttpErrorCategory.MALFORMED_RESPONSE: "Defender returned an unexpected payload.",
            HttpErrorCategory.DESTINATION_NOT_ALLOWED: "Destination is not allow-listed.",
            HttpErrorCategory.NOT_CONFIGURED: "Defender connector is not configured.",
        }.get(exc.category, "Defender check failed.")
        if exc.category is HttpErrorCategory.RATE_LIMITED and exc.retry_after is not None:
            return f"{base} Retry after {exc.retry_after} s."
        return base


__all__ = [
    "ALERTS_PATH",
    "CheckOutcome",
    "DefenderClient",
    "DefenderConfig",
    "DefenderTokenProvider",
    "FetchOutcome",
    "GRAPH_SCOPE",
    "RESOURCE_EVENT_TYPE",
    "TERMINATION_COMPLETED",
    "TERMINATION_MALFORMED",
    "TERMINATION_MAX_EVENTS",
    "TERMINATION_MAX_PAGES",
    "TERMINATION_REPEATED_CURSOR",
]
