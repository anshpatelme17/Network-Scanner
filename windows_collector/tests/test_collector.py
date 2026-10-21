from __future__ import annotations

from typing import Any

import pytest

from windows_collector.checkpoint import CheckpointStore
from windows_collector.client import IngestResult
from windows_collector.collector import WindowsEventCollector
from windows_collector.config import CollectorConfig
from windows_collector.errors import (
    AuthenticationError,
    CheckpointError,
    NormalizationError,
    SourceUnavailableError,
    TransportError,
)
from windows_collector.models import RawWindowsEvent, SourceBatch


def make_event(record_id: int, event_time: str = "2026-10-19T12:00:00Z") -> RawWindowsEvent:
    return RawWindowsEvent(
        record_id=record_id,
        event_id=4688,
        channel="Security",
        event_time=event_time,
        provider="Microsoft-Windows-Security-Auditing",
        level=4,
        computer="WORKSTATION-01",
        event_data={"TargetUserName": "alice"},
    )


class FakeSource:
    def __init__(self, batches: list[Any]) -> None:
        self.batches = list(batches)
        self.calls: list[tuple[int, int]] = []

    def read_batch(self, after_record_id: int, limit: int) -> SourceBatch:
        self.calls.append((after_record_id, limit))
        result = self.batches.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class FakeClient:
    def __init__(self, results: list[Any]) -> None:
        self.results = list(results)
        self.calls: list[dict] = []
        self.authenticated = True

    def ingest_event(self, payload: dict) -> IngestResult:
        self.calls.append(payload)
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def make_collector(
    config: CollectorConfig, source: FakeSource, client: FakeClient
) -> WindowsEventCollector:
    return WindowsEventCollector(
        config=config,
        source=source,  # type: ignore[arg-type]
        client=client,  # type: ignore[arg-type]
        checkpoint=CheckpointStore(config.checkpoint_path, config.channel),
    )


def test_successful_batch_advances_checkpoint_after_uploads(config: CollectorConfig) -> None:
    source = FakeSource(
        [
            SourceBatch(
                events=(make_event(1), make_event(2)),
                newest_record_id=2,
            )
        ]
    )
    client = FakeClient([IngestResult(201, True), IngestResult(201, True)])
    collector = make_collector(config, source, client)
    status = collector.collect_once()
    assert source.calls == [(0, 50)]
    assert len(client.calls) == 2
    assert client.calls[0]["external_event_id"].startswith("windows:Security:1:")
    assert status.events_read == 2
    assert status.events_uploaded == 2
    assert status.checkpoint == 2
    assert status.last_upload_success_at is not None
    assert status.last_error is None
    assert CheckpointStore(config.checkpoint_path, "Security").load().record_id == 2


def test_duplicate_uploads_are_counted_and_checkpointed(config: CollectorConfig) -> None:
    source = FakeSource([SourceBatch(events=(make_event(7),), newest_record_id=7)])
    client = FakeClient([IngestResult(200, False)])
    collector = make_collector(config, source, client)
    status = collector.collect_once()
    assert status.events_duplicate == 1
    assert status.events_uploaded == 0
    assert status.checkpoint == 7


def test_upload_failure_does_not_advance_checkpoint(config: CollectorConfig) -> None:
    source = FakeSource([SourceBatch(events=(make_event(1), make_event(2)), newest_record_id=2)])
    client = FakeClient([IngestResult(201, True), TransportError("offline")])
    collector = make_collector(config, source, client)
    with pytest.raises(TransportError):
        collector.collect_once()
    assert len(client.calls) == 2
    assert not config.checkpoint_path.exists()
    assert collector.status.events_uploaded == 1
    assert collector.status.last_upload_success_at is None


def test_malformed_batch_fails_closed_before_upload(config: CollectorConfig) -> None:
    source = FakeSource(
        [
            SourceBatch(
                events=(make_event(1), make_event(2, event_time="not-a-time")),
                newest_record_id=2,
            )
        ]
    )
    client = FakeClient([])
    collector = make_collector(config, source, client)
    with pytest.raises(NormalizationError):
        collector.collect_once()
    assert client.calls == []
    assert not config.checkpoint_path.exists()


def test_log_clear_resets_checkpoint_to_new_event(config: CollectorConfig) -> None:
    store = CheckpointStore(config.checkpoint_path, "Security")
    store.save(100)
    source = FakeSource(
        [SourceBatch(events=(make_event(51),), newest_record_id=51, reset_detected=True)]
    )
    client = FakeClient([IngestResult(201, True)])
    collector = make_collector(config, source, client)
    status = collector.collect_once()
    assert status.checkpoint_reset is True
    assert status.checkpoint == 51
    assert store.load().record_id == 51


def test_cleared_log_with_no_events_resets_checkpoint_to_zero(config: CollectorConfig) -> None:
    store = CheckpointStore(config.checkpoint_path, "Security")
    store.save(100)
    source = FakeSource([SourceBatch(events=(), newest_record_id=None, reset_detected=True)])
    client = FakeClient([])
    collector = make_collector(config, source, client)
    status = collector.collect_once()
    assert status.checkpoint_reset is True
    assert status.checkpoint == 0
    assert store.load().record_id == 0


def test_empty_batch_leaves_checkpoint_untouched(config: CollectorConfig) -> None:
    store = CheckpointStore(config.checkpoint_path, "Security")
    store.save(10)
    source = FakeSource([SourceBatch(events=(), newest_record_id=10)])
    client = FakeClient([])
    collector = make_collector(config, source, client)
    status = collector.collect_once()
    assert status.checkpoint == 10
    assert store.load().record_id == 10
    assert client.calls == []


def test_authentication_failure_marks_status_and_preserves_checkpoint(
    config: CollectorConfig,
) -> None:
    store = CheckpointStore(config.checkpoint_path, "Security")
    store.save(10)
    source = FakeSource([SourceBatch(events=(make_event(11),), newest_record_id=11)])
    client = FakeClient([AuthenticationError("rejected")])
    collector = make_collector(config, source, client)
    with pytest.raises(AuthenticationError):
        collector.collect_once()
    assert collector.status.authenticated is False
    assert store.load().record_id == 10


def test_checkpoint_load_failure_is_reported(config: CollectorConfig) -> None:
    config.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    config.checkpoint_path.write_text("invalid", encoding="utf-8")
    source = FakeSource([])
    client = FakeClient([])
    collector = make_collector(config, source, client)
    with pytest.raises(CheckpointError):
        collector.collect_once()
    assert client.calls == []


def test_run_forever_records_source_failures_and_sleeps(config: CollectorConfig) -> None:
    source = FakeSource(
        [
            SourceUnavailableError("PowerShell is not available."),
            SourceUnavailableError("PowerShell is not available."),
        ]
    )
    client = FakeClient([])
    collector = make_collector(config, source, client)
    sleeps: list[float] = []
    status = collector.run_forever(sleep_fn=sleeps.append, max_iterations=2)
    assert status.last_error == "PowerShell is not available."
    assert status.source_available is False
    assert len(source.calls) == 2
    assert sleeps == [30.0]


def test_run_forever_handles_unexpected_failures(config: CollectorConfig) -> None:
    source = FakeSource([ValueError("unexpected")])
    client = FakeClient([])
    collector = make_collector(config, source, client)
    status = collector.run_forever(sleep_fn=lambda _: None, max_iterations=1)
    assert status.last_error == "Unexpected collector failure."


def test_run_forever_stop_callback(config: CollectorConfig) -> None:
    source = FakeSource([SourceBatch(events=(), newest_record_id=0)])
    client = FakeClient([])
    collector = make_collector(config, source, client)
    status = collector.run_forever(stop_fn=lambda: True, sleep_fn=lambda _: None)
    assert status.events_read == 0
    assert source.calls == []
