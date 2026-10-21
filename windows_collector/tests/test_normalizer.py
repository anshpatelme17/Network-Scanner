from __future__ import annotations

import pytest

from windows_collector.errors import NormalizationError
from windows_collector.models import RawWindowsEvent
from windows_collector.normalizer import normalize_event


def make_event(**overrides) -> RawWindowsEvent:
    values = {
        "record_id": 42,
        "event_id": 4688,
        "channel": "Security",
        "event_time": "2026-10-19T12:34:56.1234567Z",
        "provider": "Microsoft-Windows-Security-Auditing",
        "level": 2,
        "task": 13312,
        "opcode": 0,
        "keywords": "Audit Success",
        "computer": "WORKSTATION-01",
        "user_id": "S-1-5-21-1000",
        "event_data": {
            "TargetUserName": "alice",
            "Image": r"C:\Windows\System32\cmd.exe",
            "IpAddress": "10.0.0.5",
            "IpPort": "4444",
        },
    }
    values.update(overrides)
    return RawWindowsEvent(**values)


def test_full_event_is_normalized() -> None:
    payload = normalize_event(make_event(), "soc-windows")
    assert payload["source_type"] == "WINDOWS"
    assert payload["source_name"] == "soc-windows"
    assert payload["event_type"] == "WINDOWS_EVENT_4688"
    assert payload["severity"] == "HIGH"
    assert payload["hostname"] == "WORKSTATION-01"
    assert payload["username"] == "alice"
    assert payload["process_name"] == r"C:\Windows\System32\cmd.exe"
    assert payload["source_ip"] == "10.0.0.5"
    assert payload["source_port"] == 4444
    assert payload["event_time"] == "2026-10-19T12:34:56.123456Z"
    assert payload["external_event_id"].startswith("windows:Security:42:")
    assert len(payload["external_event_id"]) <= 255
    assert "Microsoft-Windows-Security-Auditing event 4688 on WORKSTATION-01" in payload["title"]
    assert "Record ID: 42" in payload["description"]
    assert payload["raw_event"]["provenance"] == "windows_event_log"
    assert payload["raw_event"]["record_id"] == 42


def test_raw_event_does_not_include_full_xml_or_message() -> None:
    payload = normalize_event(make_event(), "soc-windows")
    raw = payload["raw_event"]
    assert "xml" not in raw
    assert "message" not in raw
    assert "EventData" not in raw
    assert raw["event_data"]["Image"] == r"C:\Windows\System32\cmd.exe"


def test_missing_optional_fields_are_omitted() -> None:
    event = RawWindowsEvent(
        record_id=1,
        event_id=1,
        channel="System",
        event_time="2026-10-19T00:00:00Z",
    )
    payload = normalize_event(event, "soc-windows")
    for key in ("hostname", "username", "process_name", "source_ip", "source_port"):
        assert key not in payload
    assert payload["raw_event"]["provider"] is None
    assert payload["raw_event"]["event_data"] == {}


def test_subject_username_and_process_aliases_are_used() -> None:
    event = make_event(
        event_data={
            "SubjectUserName": "bob",
            "NewProcessName": r"C:\Windows\explorer.exe",
            "SourceIp": "2001:db8::1",
        }
    )
    payload = normalize_event(event, "soc-windows")
    assert payload["username"] == "bob"
    assert payload["process_name"] == r"C:\Windows\explorer.exe"
    assert payload["source_ip"] == "2001:db8::1"


def test_invalid_ip_and_port_are_omitted() -> None:
    event = make_event(event_data={"IpAddress": "not-an-ip", "IpPort": "99999"})
    payload = normalize_event(event, "soc-windows")
    assert "source_ip" not in payload
    assert "source_port" not in payload


@pytest.mark.parametrize(
    ("level", "severity"),
    [
        (1, "CRITICAL"),
        (2, "HIGH"),
        (3, "MEDIUM"),
        (4, "LOW"),
        (5, "INFO"),
        (None, "INFO"),
        (99, "INFO"),
    ],
)
def test_levels_map_to_closed_severity_values(level: int | None, severity: str) -> None:
    payload = normalize_event(make_event(level=level), "soc-windows")
    assert payload["severity"] == severity


def test_invalid_timestamp_is_rejected() -> None:
    with pytest.raises(NormalizationError):
        normalize_event(make_event(event_time="yesterday"), "soc-windows")


def test_naive_timestamp_is_treated_as_utc() -> None:
    payload = normalize_event(make_event(event_time="2026-10-19T12:34:56"), "soc-windows")
    assert payload["event_time"] == "2026-10-19T12:34:56Z"


def test_long_external_id_is_hashed_to_the_schema_limit() -> None:
    payload = normalize_event(make_event(channel="C" * 255), "soc-windows")
    external = payload["external_event_id"]
    assert external.startswith("windows:sha256:")
    assert len(external) <= 255


def test_external_id_changes_when_record_ids_are_reused_after_log_clear() -> None:
    first = normalize_event(make_event(event_time="2026-10-19T00:00:00Z"), "soc-windows")
    second = normalize_event(make_event(event_time="2026-10-20T00:00:00Z"), "soc-windows")
    assert first["external_event_id"] != second["external_event_id"]


@pytest.mark.parametrize("source_name", ["", "   ", "x" * 129])
def test_invalid_source_names_are_rejected(source_name: str) -> None:
    with pytest.raises(NormalizationError):
        normalize_event(make_event(), source_name)


def test_invalid_event_type_is_rejected() -> None:
    with pytest.raises(NormalizationError):
        normalize_event("not-an-event", "soc-windows")  # type: ignore[arg-type]


def test_negative_identifiers_are_rejected() -> None:
    with pytest.raises(NormalizationError):
        normalize_event(make_event(record_id=-1), "soc-windows")
    with pytest.raises(NormalizationError):
        normalize_event(make_event(event_id=-1), "soc-windows")


def test_title_and_values_are_bounded() -> None:
    payload = normalize_event(
        make_event(
            provider="P" * 600,
            computer="H" * 400,
            event_data={"TargetUserName": "U" * 300, "Image": "I" * 400},
        ),
        "soc-windows",
    )
    assert len(payload["title"]) <= 512
    assert len(payload["hostname"]) <= 255
    assert len(payload["username"]) <= 128
    assert len(payload["process_name"]) <= 255
