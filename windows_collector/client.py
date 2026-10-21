"""Authenticated backend client for collector event ingestion."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from .config import CollectorConfig
from .errors import AuthenticationError, BackendError
from .transport import HttpResponse, HttpTransport, UrllibTransport

TOKEN_EXPIRY_SKEW = timedelta(seconds=30)


@dataclass(frozen=True)
class IngestResult:
    status_code: int
    created: bool


class _TokenRejected(AuthenticationError):
    pass


def _decode_json(response: HttpResponse) -> dict:
    try:
        payload = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackendError("Backend returned an invalid JSON response.") from exc
    if not isinstance(payload, dict):
        raise BackendError("Backend returned an invalid JSON response.")
    return payload


@dataclass
class BackendClient:
    config: CollectorConfig
    transport: HttpTransport = field(default_factory=UrllibTransport)
    _access_token: str | None = field(default=None, init=False, repr=False)
    _token_expires_at: datetime | None = field(default=None, init=False, repr=False)

    @property
    def authenticated(self) -> bool:
        return self._token_is_fresh()

    def _token_is_fresh(self) -> bool:
        if self._access_token is None or self._token_expires_at is None:
            return False
        return datetime.now(UTC) + TOKEN_EXPIRY_SKEW < self._token_expires_at

    def _clear_token(self) -> None:
        self._access_token = None
        self._token_expires_at = None

    def login(self) -> None:
        response = self.transport.post_json(
            self.config.login_url,
            {"username": self.config.username, "password": self.config.password},
            timeout=self.config.request_timeout_seconds,
        )
        if response.status_code in {401, 403}:
            raise AuthenticationError("Backend rejected collector credentials.")
        if response.status_code != 200:
            raise BackendError(f"Backend login failed (HTTP {response.status_code}).")
        payload = _decode_json(response)
        token = payload.get("access_token")
        token_type = payload.get("token_type", "bearer")
        expires = payload.get("expires_in_minutes")
        if not isinstance(token, str) or not token.strip():
            raise BackendError("Backend login response did not contain a token.")
        if not isinstance(token_type, str) or token_type.lower() != "bearer":
            raise BackendError("Backend login response had an unsupported token type.")
        if isinstance(expires, bool) or not isinstance(expires, int | float) or expires <= 0:
            raise BackendError("Backend login response had an invalid expiry.")
        self._access_token = token
        self._token_expires_at = datetime.now(UTC) + timedelta(minutes=float(expires))

    def _ensure_authenticated(self) -> None:
        if not self._token_is_fresh():
            self.login()

    def _auth_headers(self) -> dict[str, str]:
        if self._access_token is None:
            raise AuthenticationError("Collector is not authenticated.")
        return {"Authorization": f"Bearer {self._access_token}"}

    def _post_event(self, event: dict) -> IngestResult:
        response = self.transport.post_json(
            self.config.events_url,
            event,
            headers=self._auth_headers(),
            timeout=self.config.request_timeout_seconds,
        )
        if response.status_code == 201:
            return IngestResult(status_code=201, created=True)
        if response.status_code == 200:
            return IngestResult(status_code=200, created=False)
        return self._raise_for_event_status(response.status_code)

    def _raise_for_event_status(self, status_code: int) -> IngestResult:
        if status_code == 401:
            raise _TokenRejected("Backend rejected the collector token.")
        if status_code == 403:
            raise AuthenticationError("Collector lacks permission to ingest events.")
        if status_code == 413:
            raise BackendError("Backend rejected the event as too large.")
        if status_code == 422:
            raise BackendError("Backend rejected the event as invalid.")
        if status_code == 429:
            raise BackendError("Backend rate-limited the collector.")
        raise BackendError(f"Backend returned HTTP {status_code}.")

    def ingest_event(self, event: dict) -> IngestResult:
        self._ensure_authenticated()
        try:
            return self._post_event(event)
        except _TokenRejected:
            self._clear_token()
            self._ensure_authenticated()
            try:
                return self._post_event(event)
            except _TokenRejected as exc:
                self._clear_token()
                raise AuthenticationError("Backend rejected the collector token.") from exc

    def close(self) -> None:
        self._clear_token()


__all__ = ["BackendClient", "IngestResult", "TOKEN_EXPIRY_SKEW"]
