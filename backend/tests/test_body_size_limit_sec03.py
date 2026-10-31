"""SEC-03 tests for the configured ASGI request-body limit."""

import asyncio
import json
from collections.abc import Iterable
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.middleware import (
    BodySizeLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)

BODY_LIMIT = 7


def _app_and_calls():
    app = FastAPI()
    calls: list[bytes] = []

    @app.post("/api/v1/events")
    async def accept(request: Request) -> JSONResponse:
        body = await request.body()
        calls.append(body)
        try:
            payload = json.loads(body) if body else None
        except json.JSONDecodeError:
            payload = None
        return JSONResponse({"body": body.decode("utf-8"), "payload": payload})

    # Match create_app() ordering: request context wraps security headers,
    # which wrap the body limiter before the route.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=BODY_LIMIT)
    app.add_middleware(
        SecurityHeadersMiddleware,
        settings=SimpleNamespace(is_production=False),
    )
    app.add_middleware(RequestContextMiddleware)
    return app, calls


def _request(
    app,
    chunks: Iterable[bytes],
    headers: list[tuple[bytes, bytes]] | None = None,
    receive_count: list[int] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    chunks = list(chunks)
    messages = [
        {
            "type": "http.request",
            "body": chunk,
            "more_body": index < len(chunks) - 1,
        }
        for index, chunk in enumerate(chunks)
    ]
    if not messages:
        messages = [{"type": "http.request", "body": b"", "more_body": False}]
    return _request_messages(app, messages, headers, receive_count)


def _request_messages(
    app,
    messages: list[dict],
    headers: list[tuple[bytes, bytes]] | None = None,
    receive_count: list[int] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    message_index = 0
    sent: list[dict] = []
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/v1/events",
        "raw_path": b"/api/v1/events",
        "query_string": b"",
        "root_path": "",
        "headers": headers or [],
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
        "state": {},
    }

    async def receive() -> dict:
        nonlocal message_index
        if receive_count is not None:
            receive_count[0] += 1
        if message_index < len(messages):
            message = messages[message_index]
            message_index += 1
            return message
        return {"type": "http.disconnect"}

    async def send(message: dict) -> None:
        sent.append(message)

    asyncio.run(asyncio.wait_for(app(scope, receive, send), timeout=1))
    start = next(message for message in sent if message["type"] == "http.response.start")
    response_body = b"".join(
        message.get("body", b"")
        for message in sent
        if message["type"] == "http.response.body"
    )
    response_headers = {
        key.decode("latin-1").lower(): value.decode("latin-1")
        for key, value in start.get("headers", [])
    }
    return start["status"], response_headers, response_body


def test_body_below_limit_reaches_route_without_corruption() -> None:
    app, calls = _app_and_calls()
    status, _headers, body = _request(app, [b"{}"])

    assert status == 200
    assert calls == [b"{}"]
    assert json.loads(body) == {"body": "{}", "payload": {}}


def test_body_exactly_at_limit_is_accepted() -> None:
    app, calls = _app_and_calls()
    content = b'{"a":1}'
    status, _headers, body = _request(
        app,
        [content],
        headers=[(b"content-length", str(len(content)).encode("ascii"))],
    )

    assert len(content) == BODY_LIMIT
    assert status == 200
    assert calls == [content]
    assert json.loads(body)["payload"] == {"a": 1}


def test_declared_oversized_body_is_rejected_before_route() -> None:
    app, calls = _app_and_calls()
    receive_count = [0]
    status, _headers, body = _request(
        app,
        [b"ignored"],
        headers=[(b"content-length", b"8")],
        receive_count=receive_count,
    )

    assert status == 413
    assert calls == []
    assert receive_count == [0]
    assert "x-request-id" in _headers
    assert _headers["x-content-type-options"] == "nosniff"
    assert json.loads(body) == {
        "error": {
            "code": "PAYLOAD_TOO_LARGE",
            "message": "Request body exceeds the configured maximum size.",
        }
    }


def test_undeclared_oversized_body_is_rejected_before_route() -> None:
    app, calls = _app_and_calls()
    status, headers, body = _request(app, [b"12345678"])

    assert status == 413
    assert calls == []
    assert "x-request-id" in headers
    assert headers["x-content-type-options"] == "nosniff"
    assert json.loads(body)["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_multiple_chunks_are_counted_by_combined_size() -> None:
    app, calls = _app_and_calls()
    status, _headers, body = _request(app, [b"123", b"45", b"678"])

    assert status == 413
    assert calls == []
    assert json.loads(body)["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_empty_body_is_accepted_and_replayed() -> None:
    app, calls = _app_and_calls()
    status, _headers, body = _request(app, [])

    assert status == 200
    assert calls == [b""]
    assert json.loads(body) == {"body": "", "payload": None}


def test_valid_json_is_preserved_for_the_route() -> None:
    app, calls = _app_and_calls()
    content = b'{"a":1}'
    status, _headers, body = _request(
        app,
        [b'{"a":', b"1}"],
        headers=[(b"content-type", b"application/json")],
    )

    assert status == 200
    assert calls == [content]
    assert json.loads(body)["payload"] == {"a": 1}


@pytest.mark.parametrize("content_length", [b"not-a-number", b"", b"+2", b" 2"])
def test_invalid_content_length_is_rejected_before_route(content_length: bytes) -> None:
    app, calls = _app_and_calls()
    status, _headers, body = _request(
        app,
        [b"{}"],
        headers=[(b"content-length", content_length)],
    )

    assert status == 400
    assert calls == []
    assert json.loads(body)["error"]["code"] == "INVALID_REQUEST"


def test_negative_content_length_is_rejected_before_route() -> None:
    app, calls = _app_and_calls()
    status, _headers, body = _request(
        app,
        [b""],
        headers=[(b"content-length", b"-1")],
    )

    assert status == 400
    assert calls == []
    assert json.loads(body)["error"]["code"] == "INVALID_REQUEST"


def test_duplicate_content_length_is_rejected_before_route() -> None:
    app, calls = _app_and_calls()
    status, _headers, body = _request(
        app,
        [b"{}"],
        headers=[(b"content-length", b"2"), (b"content-length", b"2")],
    )

    assert status == 400
    assert calls == []
    assert json.loads(body)["error"]["code"] == "INVALID_REQUEST"


def test_oversized_actual_body_is_rejected_when_declared_length_is_smaller() -> None:
    app, calls = _app_and_calls()
    status, _headers, body = _request(
        app,
        [b"12345678"],
        headers=[(b"content-length", b"1")],
    )

    assert status == 413
    assert calls == []
    assert json.loads(body)["error"]["code"] == "PAYLOAD_TOO_LARGE"


@pytest.mark.parametrize("declared_length", [1, 3])
def test_completed_body_must_match_declared_content_length(
    declared_length: int,
) -> None:
    app, calls = _app_and_calls()
    status, _headers, body = _request(
        app,
        [b"{}"],
        headers=[(b"content-length", str(declared_length).encode("ascii"))],
    )

    assert status == 400
    assert calls == []
    assert json.loads(body)["error"]["code"] == "INVALID_REQUEST"


def _disconnect_observer(observed: list[dict]):
    async def app(scope, receive, send) -> None:  # noqa: ANN001
        while True:
            message = await receive()
            observed.append(message)
            if message["type"] == "http.disconnect":
                break
            if message["type"] == "http.request" and not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    return app


def test_disconnect_before_any_body_chunk_is_replayed() -> None:
    observed: list[dict] = []
    app = BodySizeLimitMiddleware(_disconnect_observer(observed), max_bytes=BODY_LIMIT)
    status, _headers, _body = _request_messages(
        app,
        [{"type": "http.disconnect"}],
    )

    assert status == 204
    assert observed == [{"type": "http.disconnect"}]


@pytest.mark.parametrize("chunks", [[b"abc"], [b"ab", b"cd"]])
def test_disconnect_after_body_chunks_replays_partial_body_then_disconnect(
    chunks: list[bytes],
) -> None:
    observed: list[dict] = []
    app = BodySizeLimitMiddleware(_disconnect_observer(observed), max_bytes=BODY_LIMIT)
    incoming = [
        {"type": "http.request", "body": chunk, "more_body": True} for chunk in chunks
    ]
    incoming.append({"type": "http.disconnect"})

    status, _headers, _body = _request_messages(app, incoming)

    assert status == 204
    assert observed == [
        {"type": "http.request", "body": b"".join(chunks), "more_body": True},
        {"type": "http.disconnect"},
    ]


def test_unexpected_receive_message_is_rejected_without_route_call() -> None:
    calls: list[bool] = []

    async def route(scope, receive, send) -> None:  # noqa: ANN001
        calls.append(True)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    app = BodySizeLimitMiddleware(route, max_bytes=BODY_LIMIT)
    status, _headers, body = _request_messages(
        app,
        [{"type": "websocket.receive", "text": "invalid for HTTP"}],
    )

    assert status == 400
    assert calls == []
    assert json.loads(body)["error"]["code"] == "INVALID_REQUEST"
