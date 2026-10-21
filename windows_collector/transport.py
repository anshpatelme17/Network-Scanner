"""Minimal JSON-over-HTTP transport with strict redirect handling."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol

from .errors import TransportError
from .models import COLLECTOR_NAME, COLLECTOR_VERSION

MAX_RESPONSE_BYTES = 1_048_576


@dataclass(frozen=True)
class HttpResponse:
    status_code: int
    body: bytes
    headers: dict[str, str]


class HttpTransport(Protocol):
    def post_json(
        self,
        url: str,
        payload: dict,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> HttpResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class UrllibTransport:
    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoRedirect())

    def post_json(
        self,
        url: str,
        payload: dict,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> HttpResponse:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        request_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": f"{COLLECTOR_NAME}/{COLLECTOR_VERSION}",
        }
        if headers:
            request_headers.update(headers)
        request = urllib.request.Request(url, data=body, headers=request_headers, method="POST")
        try:
            with self._opener.open(request, timeout=timeout) as response:
                return HttpResponse(
                    status_code=response.status,
                    body=response.read(MAX_RESPONSE_BYTES),
                    headers=dict(response.headers.items()),
                )
        except urllib.error.HTTPError as exc:
            with exc:
                return HttpResponse(
                    status_code=exc.code,
                    body=exc.read(MAX_RESPONSE_BYTES),
                    headers=dict(exc.headers.items()) if exc.headers else {},
                )
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransportError("Backend request failed.") from exc


__all__ = ["HttpResponse", "HttpTransport", "MAX_RESPONSE_BYTES", "UrllibTransport"]
