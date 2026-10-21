from __future__ import annotations

import json
from pathlib import Path

import pytest

from windows_collector.checkpoint import CheckpointStore
from windows_collector.errors import CheckpointError


def test_missing_checkpoint_starts_at_zero(tmp_path: Path) -> None:
    store = CheckpointStore(tmp_path / "checkpoint.json", "Security")
    state = store.load()
    assert state.record_id == 0
    assert state.channel == "Security"
    assert state.updated_at is None


def test_checkpoint_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "checkpoint.json"
    store = CheckpointStore(path, "Security")
    saved = store.save(42)
    assert saved.record_id == 42
    assert saved.updated_at is not None
    loaded = store.load()
    assert loaded.record_id == 42
    assert loaded.channel == "Security"
    assert loaded.updated_at == saved.updated_at
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == 1


def test_checkpoint_is_channel_scoped(tmp_path: Path) -> None:
    path = tmp_path / "checkpoint.json"
    CheckpointStore(path, "Security").save(10)
    with pytest.raises(CheckpointError):
        CheckpointStore(path, "System").load()


@pytest.mark.parametrize(
    "content",
    [
        "not-json",
        "[]",
        "{}",
        '{"version": 2, "channel": "Security", "record_id": 1}',
        '{"version": 1, "channel": "Security", "record_id": -1}',
        '{"version": 1, "channel": "Security", "record_id": true}',
        '{"version": 1, "channel": "Security", "record_id": "1"}',
        '{"version": 1, "channel": "Security", "record_id": 1, "updated_at": 5}',
    ],
)
def test_invalid_checkpoint_files_are_rejected(tmp_path: Path, content: str) -> None:
    path = tmp_path / "checkpoint.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(CheckpointError):
        CheckpointStore(path, "Security").load()


def test_checkpoint_path_must_be_a_file(tmp_path: Path) -> None:
    with pytest.raises(CheckpointError):
        CheckpointStore(tmp_path, "Security").load()


def test_atomic_write_failure_preserves_previous_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "checkpoint.json"
    store = CheckpointStore(path, "Security")
    store.save(10)
    original = path.read_bytes()

    def failing_replace(source: str, destination: Path) -> None:
        raise OSError("simulated failure")

    monkeypatch.setattr("windows_collector.checkpoint.os.replace", failing_replace)
    with pytest.raises(CheckpointError):
        store.save(11)
    assert path.read_bytes() == original
    assert store.load().record_id == 10
    assert [item.name for item in tmp_path.iterdir()] == ["checkpoint.json"]


def test_negative_checkpoint_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(CheckpointError):
        CheckpointStore(tmp_path / "checkpoint.json", "Security").save(-1)
