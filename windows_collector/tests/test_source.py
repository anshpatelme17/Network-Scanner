from __future__ import annotations

import base64
import json
import subprocess
from typing import Any

import pytest

from windows_collector.errors import SourceDataError, SourceError, SourceUnavailableError
from windows_collector.source import (
    ALLOWED_EVENT_DATA,
    POWERSHELL_SCRIPT,
    PowerShellEventSource,
)


def event_payload(
    record_id: int,
    event_id: int = 4688,
    **overrides: Any,
) -> dict[str, Any]:
    payload = {
        "record_id": record_id,
        "event_id": event_id,
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "level": 4,
        "task": 13312,
        "opcode": 0,
        "keywords": "Audit Success",
        "time_created": "2026-10-19T12:34:56.1234567Z",
        "computer": "WORKSTATION-01",
        "user_id": "S-1-5-21-1000",
        "event_data": {"TargetUserName": "alice"},
    }
    payload.update(overrides)
    return payload


def completed(payload: dict[str, Any] | str, returncode: int = 0) -> subprocess.CompletedProcess:
    raw = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
    output = base64.b64encode(raw.encode("utf-8")).decode("ascii")
    return subprocess.CompletedProcess(
        args=["powershell.exe"], returncode=returncode, stdout=output, stderr=""
    )


class FakeRunner:
    def __init__(self, results: list[Any]) -> None:
        self.results = list(results)
        self.calls: list[tuple[list[str], dict[str, str], float]] = []

    def __call__(
        self, args: list[str], environment: dict[str, str], timeout: float
    ) -> subprocess.CompletedProcess:
        self.calls.append((args, environment, timeout))
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def make_source(runner: FakeRunner, **overrides: Any) -> PowerShellEventSource:
    values = {
        "channel": "Security",
        "powershell_path": "powershell.exe",
        "timeout_seconds": 30.0,
        "runner": runner,
    }
    values.update(overrides)
    return PowerShellEventSource(**values)


def test_events_are_parsed_sorted_and_deduplicated() -> None:
    runner = FakeRunner(
        [
            completed(
                {
                    "newest_record_id": "3",
                    "events": [
                        event_payload(3),
                        event_payload(1),
                        event_payload(2),
                        event_payload(2, event_id=9999),
                    ],
                }
            )
        ]
    )
    batch = make_source(runner).read_batch(0, 50)
    assert [event.record_id for event in batch.events] == [1, 2, 3]
    assert batch.events[1].event_id == 9999
    assert batch.newest_record_id == 3
    assert batch.reset_detected is False
    args, environment, timeout = runner.calls[0]
    assert args[0] == "powershell.exe"
    assert "-NoProfile" in args
    assert environment["SOC_WINDOWS_AFTER_RECORD_ID"] == "0"
    assert environment["SOC_WINDOWS_MAX_EVENTS"] == "50"
    assert environment["SOC_WINDOWS_EVENT_CHANNEL"] == "Security"
    assert timeout == 30.0


def test_environment_is_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOC_BACKEND_PASSWORD", "must-not-leak")
    monkeypatch.setenv("SOC_BACKEND_USERNAME", "must-not-leak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-leak")
    monkeypatch.setenv("SOC_WINDOWS_EVENT_CHANNEL", "must-not-be-used")
    runner = FakeRunner([completed({"newest_record_id": 0, "events": []})])
    make_source(runner).read_batch(0, 10)
    _, environment, _ = runner.calls[0]
    assert "SOC_BACKEND_PASSWORD" not in environment
    assert "SOC_BACKEND_USERNAME" not in environment
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert environment["SOC_WINDOWS_EVENT_CHANNEL"] == "Security"
    assert "must-not-leak" not in repr(environment)


def test_event_data_is_allowlisted_and_clipped() -> None:
    runner = FakeRunner(
        [
            completed(
                {
                    "newest_record_id": 1,
                    "events": [
                        event_payload(
                            1,
                            event_data={
                                "Image": "I" * 600,
                                "NotAllowed": "secret",
                                "IpAddress": "10.0.0.5",
                            },
                        )
                    ],
                }
            )
        ]
    )
    batch = make_source(runner).read_batch(0, 10)
    assert batch.events[0].event_data == {"Image": "I" * 512, "IpAddress": "10.0.0.5"}


def test_non_ascii_event_data_round_trips() -> None:
    runner = FakeRunner(
        [
            completed(
                {
                    "newest_record_id": 1,
                    "events": [event_payload(1, event_data={"TargetUserName": "José"})],
                }
            )
        ]
    )
    event = make_source(runner).read_batch(0, 10).events[0]
    assert event.event_data["TargetUserName"] == "José"


def test_script_matches_parser_allowlist_and_uses_env_inputs() -> None:
    for name in ALLOWED_EVENT_DATA:
        assert name in POWERSHELL_SCRIPT
    assert "$env:SOC_WINDOWS_EVENT_CHANNEL" in POWERSHELL_SCRIPT
    assert "$env:SOC_WINDOWS_AFTER_RECORD_ID" in POWERSHELL_SCRIPT
    assert "$env:SOC_WINDOWS_MAX_EVENTS" in POWERSHELL_SCRIPT
    assert "[Convert]::ToBase64String" in POWERSHELL_SCRIPT
    assert "-FilterXPath" in POWERSHELL_SCRIPT


def test_optional_fields_are_allowed_to_be_missing() -> None:
    runner = FakeRunner(
        [
            completed(
                {
                    "newest_record_id": 1,
                    "events": [
                        {
                            "record_id": 1,
                            "event_id": 1,
                            "time_created": "2026-10-19T00:00:00Z",
                            "event_data": {},
                        }
                    ],
                }
            )
        ]
    )
    event = make_source(runner).read_batch(0, 10).events[0]
    assert event.channel == "Security"
    assert event.provider is None
    assert event.level is None
    assert event.task is None
    assert event.opcode is None
    assert event.keywords is None
    assert event.computer is None
    assert event.user_id is None


def test_log_clear_is_detected_and_reread_from_zero() -> None:
    runner = FakeRunner(
        [
            completed({"newest_record_id": 50, "events": []}),
            completed({"newest_record_id": 51, "events": [event_payload(51)]}),
        ]
    )
    batch = make_source(runner).read_batch(100, 10)
    assert batch.reset_detected is True
    assert [event.record_id for event in batch.events] == [51]
    assert runner.calls[0][1]["SOC_WINDOWS_AFTER_RECORD_ID"] == "100"
    assert runner.calls[1][1]["SOC_WINDOWS_AFTER_RECORD_ID"] == "0"


def test_empty_log_after_checkpoint_is_treated_as_a_reset() -> None:
    runner = FakeRunner(
        [
            completed({"newest_record_id": None, "events": []}),
            completed({"newest_record_id": 2, "events": [event_payload(2)]}),
        ]
    )
    batch = make_source(runner).read_batch(100, 10)
    assert batch.reset_detected is True
    assert [event.record_id for event in batch.events] == [2]


def test_empty_batch_without_reset_does_not_reread() -> None:
    runner = FakeRunner([completed({"newest_record_id": 100, "events": []})])
    batch = make_source(runner).read_batch(100, 10)
    assert batch.reset_detected is False
    assert batch.events == ()
    assert len(runner.calls) == 1


def test_events_older_than_checkpoint_are_filtered() -> None:
    runner = FakeRunner(
        [
            completed(
                {
                    "newest_record_id": 5,
                    "events": [event_payload(4), event_payload(5)],
                }
            )
        ]
    )
    batch = make_source(runner).read_batch(4, 10)
    assert [event.record_id for event in batch.events] == [5]


@pytest.mark.parametrize(
    "result",
    [
        subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="Access denied"),
        FileNotFoundError("powershell.exe"),
        OSError("failed to start"),
    ],
)
def test_source_unavailable_errors_are_typed(result: Any) -> None:
    with pytest.raises(SourceUnavailableError):
        make_source(FakeRunner([result])).read_batch(0, 10)


def test_timeout_is_typed() -> None:
    with pytest.raises(SourceError):
        make_source(FakeRunner([subprocess.TimeoutExpired(["powershell.exe"], 30)])).read_batch(
            0, 10
        )


@pytest.mark.parametrize("stdout", ["", "not-json", "[]", '{"events":"bad"}'])
def test_invalid_source_payloads_are_rejected(stdout: str) -> None:
    with pytest.raises(SourceDataError):
        make_source(FakeRunner([completed(stdout)])).read_batch(0, 10)


def test_invalid_base64_is_rejected() -> None:
    result = subprocess.CompletedProcess(
        args=["powershell.exe"], returncode=0, stdout="not-base64!", stderr=""
    )
    with pytest.raises(SourceDataError):
        make_source(FakeRunner([result])).read_batch(0, 10)


@pytest.mark.parametrize(
    "payload",
    [
        {"newest_record_id": 1, "events": ["bad"]},
        {"newest_record_id": 1, "events": [event_payload(-1)]},
        {"newest_record_id": -1, "events": []},
        {"newest_record_id": None, "events": [event_payload(1)]},
        {"newest_record_id": 1, "events": [event_payload(2)]},
        {"newest_record_id": 1, "events": [event_payload(1, time_created=None)]},
        {"newest_record_id": 1, "events": [{**event_payload(1), "record_id": "bad"}]},
    ],
)
def test_malformed_events_are_rejected(payload: dict[str, Any]) -> None:
    with pytest.raises(SourceDataError):
        make_source(FakeRunner([completed(payload)])).read_batch(0, 10)


@pytest.mark.parametrize(("after", "limit"), [(-1, 10), (0, 0), (0, 501)])
def test_batch_arguments_are_bounded(after: int, limit: int) -> None:
    with pytest.raises(SourceError):
        make_source(FakeRunner([])).read_batch(after, limit)
