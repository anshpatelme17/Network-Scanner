from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from windows_collector.client import BackendClient
from windows_collector.config import CollectorConfig
from windows_collector.errors import AuthenticationError, BackendError, TransportError
from windows_collector.transport import HttpResponse, HttpTransport

LOGIN_PAYLOAD = {
    "access_token": "access-token-123",
    "token_type": "bearer",
    "expires_in_minutes": 60,
}
EVENT = {"source_type": "WINDOWS", "source_name": "soc-windows", "event_type": "WINDOWS_EVENT_1"}


def json_response(status_code: int, payload: dict[str, Any]) -> HttpResponse:
    return HttpResponse(
        status_code=status_code,
        body=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )


class FakeTransport(HttpTransport):
    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, dict, dict[str, str] | None, float]] = []

    def post_json(
        self,
        url: str,
        payload: dict,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> HttpResponse:
        self.calls.append((url, payload, headers, timeout))
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def make_client(
    config: CollectorConfig, responses: list[Any]
) -> tuple[BackendClient, FakeTransport]:
    transport = FakeTransport(responses)
    return BackendClient(config=config, transport=transport), transport


def test_login_and_ingest_uses_bearer_token(config: CollectorConfig) -> None:
    client, transport = make_client(
        config, [json_response(200, LOGIN_PAYLOAD), json_response(201, {"id": "event-1"})]
    )
    result = client.ingest_event(EVENT)
    assert result.created is True
    assert result.status_code == 201
    assert client.authenticated is True
    assert transport.calls[0][0] == "https://soc.example.test/api/v1/auth/login"
    assert transport.calls[0][1] == {
        "username": "collector",
        "password": "Secret-Password-123",
    }
    assert transport.calls[0][2] is None
    assert transport.calls[1][0] == "https://soc.example.test/api/v1/events"
    assert transport.calls[1][1] == EVENT
    assert transport.calls[1][2] == {"Authorization": "Bearer access-token-123"}
    assert transport.calls[1][3] == 10.0


def test_replay_is_reported_as_duplicate(config: CollectorConfig) -> None:
    client, _ = make_client(
        config, [json_response(200, LOGIN_PAYLOAD), json_response(200, {"id": "event-1"})]
    )
    result = client.ingest_event(EVENT)
    assert result.created is False
    assert result.status_code == 200


@pytest.mark.parametrize("status_code", [401, 403])
def test_login_credential_failures_are_typed(config: CollectorConfig, status_code: int) -> None:
    client, _ = make_client(config, [json_response(status_code, {"error": {"code": "AUTH"}})])
    with pytest.raises(AuthenticationError) as error:
        client.login()
    assert "Secret-Password-123" not in str(error.value)


def test_login_server_failure_is_typed(config: CollectorConfig) -> None:
    client, _ = make_client(config, [json_response(500, {"error": {"code": "SERVER"}})])
    with pytest.raises(BackendError):
        client.login()


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"access_token": "", "expires_in_minutes": 60},
        {"access_token": 123, "expires_in_minutes": 60},
        {"access_token": "token"},
        {"access_token": "token", "expires_in_minutes": 0},
        {"access_token": "token", "expires_in_minutes": -1},
        {"access_token": "token", "expires_in_minutes": True},
        {"access_token": "token", "expires_in_minutes": "60"},
        {"access_token": "token", "expires_in_minutes": 60, "token_type": "mac"},
        {"access_token": "token", "expires_in_minutes": 60, "token_type": 5},
    ],
)
def test_invalid_login_payloads_are_rejected(
    config: CollectorConfig, payload: dict[str, Any]
) -> None:
    client, _ = make_client(config, [json_response(200, payload)])
    with pytest.raises(BackendError):
        client.login()


def test_invalid_login_json_is_rejected(config: CollectorConfig) -> None:
    client, _ = make_client(config, [HttpResponse(status_code=200, body=b"not-json", headers={})])
    with pytest.raises(BackendError):
        client.login()


def test_event_401_relogs_in_once_and_retries(config: CollectorConfig) -> None:
    client, transport = make_client(
        config,
        [
            json_response(200, LOGIN_PAYLOAD),
            json_response(401, {"error": {"code": "EXPIRED"}}),
            json_response(200, LOGIN_PAYLOAD),
            json_response(201, {"id": "event-1"}),
        ],
    )
    result = client.ingest_event(EVENT)
    assert result.created is True
    assert len(transport.calls) == 4
    assert transport.calls[2][0].endswith("/api/v1/auth/login")
    assert transport.calls[3][2] == {"Authorization": "Bearer access-token-123"}


def test_second_event_401_is_rejected(config: CollectorConfig) -> None:
    client, transport = make_client(
        config,
        [
            json_response(200, LOGIN_PAYLOAD),
            json_response(401, {"error": {"code": "EXPIRED"}}),
            json_response(200, LOGIN_PAYLOAD),
            json_response(401, {"error": {"code": "EXPIRED"}}),
        ],
    )
    with pytest.raises(AuthenticationError):
        client.ingest_event(EVENT)
    assert len(transport.calls) == 4
    assert client.authenticated is False


def test_event_403_does_not_retry(config: CollectorConfig) -> None:
    client, transport = make_client(
        config,
        [
            json_response(200, LOGIN_PAYLOAD),
            json_response(403, {"error": {"code": "FORBIDDEN"}}),
        ],
    )
    with pytest.raises(AuthenticationError):
        client.ingest_event(EVENT)
    assert len(transport.calls) == 2


@pytest.mark.parametrize(
    ("status_code", "message"),
    [
        (413, "too large"),
        (422, "invalid"),
        (429, "rate-limited"),
        (500, "HTTP 500"),
    ],
)
def test_event_failures_are_reported_safely(
    config: CollectorConfig, status_code: int, message: str
) -> None:
    client, _ = make_client(
        config,
        [
            json_response(200, LOGIN_PAYLOAD),
            json_response(status_code, {"error": {"code": "FAILED", "message": "detail"}}),
        ],
    )
    with pytest.raises(BackendError) as error:
        client.ingest_event(EVENT)
    assert message in str(error.value)
    assert "Secret-Password-123" not in str(error.value)


def test_expired_token_triggers_login(config: CollectorConfig) -> None:
    client, transport = make_client(
        config,
        [
            json_response(200, LOGIN_PAYLOAD),
            json_response(200, LOGIN_PAYLOAD),
            json_response(201, {"id": "event-1"}),
        ],
    )
    client.login()
    client._token_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    client.ingest_event(EVENT)
    assert len(transport.calls) == 3
    assert transport.calls[1][0].endswith("/api/v1/auth/login")
    assert transport.calls[2][2] == {"Authorization": "Bearer access-token-123"}


def test_transport_error_propagates(config: CollectorConfig) -> None:
    client, _ = make_client(config, [TransportError("offline")])
    with pytest.raises(TransportError):
        client.login()


def test_secrets_are_not_in_repr(config: CollectorConfig) -> None:
    client, _ = make_client(config, [json_response(200, LOGIN_PAYLOAD)])
    client.login()
    rendered = repr(client)
    assert "Secret-Password-123" not in rendered
    assert "access-token-123" not in rendered


def test_close_clears_authentication(config: CollectorConfig) -> None:
    client, _ = make_client(config, [json_response(200, LOGIN_PAYLOAD)])
    client.login()
    client.close()
    assert client.authenticated is False
