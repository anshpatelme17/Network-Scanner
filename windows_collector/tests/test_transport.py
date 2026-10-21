from __future__ import annotations

import io
import json
import urllib.error
from email.message import Message

import pytest

from windows_collector.errors import TransportError
from windows_collector.transport import UrllibTransport, _NoRedirect


class FakeResponse:
    status = 201
    headers = {"Content-Type": "application/json"}

    def __init__(self, body: bytes) -> None:
        self.body = body

    def read(self, limit: int = -1) -> bytes:
        return self.body

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


class FakeOpener:
    def __init__(self, result: object) -> None:
        self.result = result
        self.requests: list[tuple[object, float]] = []

    def open(self, request: object, timeout: float) -> FakeResponse:
        self.requests.append((request, timeout))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result  # type: ignore[return-value]


def test_posts_json_with_headers_and_timeout() -> None:
    transport = UrllibTransport()
    opener = FakeOpener(FakeResponse(b'{"ok":true}'))
    transport._opener = opener  # type: ignore[assignment]
    response = transport.post_json(
        "https://soc.example.test/api/v1/events",
        {"event": "value"},
        headers={"Authorization": "Bearer token"},
        timeout=7.5,
    )
    assert response.status_code == 201
    assert response.body == b'{"ok":true}'
    request, timeout = opener.requests[0]
    assert timeout == 7.5
    assert request.get_header("Content-type") == "application/json"
    assert request.get_header("Authorization") == "Bearer token"
    assert json.loads(request.data) == {"event": "value"}  # type: ignore[attr-defined]


def test_http_error_response_is_returned_not_raised() -> None:
    transport = UrllibTransport()
    headers = Message()
    error = urllib.error.HTTPError(
        "https://soc.example.test",
        401,
        "Unauthorized",
        headers,
        io.BytesIO(b'{"error":{"code":"AUTH"}}'),
    )
    transport._opener = FakeOpener(error)  # type: ignore[assignment]
    response = transport.post_json("https://soc.example.test", {})
    assert response.status_code == 401
    assert response.body == b'{"error":{"code":"AUTH"}}'


@pytest.mark.parametrize(
    "error",
    [
        urllib.error.URLError("offline"),
        TimeoutError("timed out"),
        OSError("socket failed"),
    ],
)
def test_connection_failures_are_typed(error: Exception) -> None:
    transport = UrllibTransport()
    transport._opener = FakeOpener(error)  # type: ignore[assignment]
    with pytest.raises(TransportError):
        transport.post_json("https://soc.example.test", {})


def test_redirects_are_disabled() -> None:
    handler = _NoRedirect()
    assert handler.redirect_request(None, None, 302, "Found", {}, "https://elsewhere.test") is None
