from __future__ import annotations

import json
from pathlib import Path

import pytest

from windows_collector.cli import main


def test_status_works_without_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SOC_BACKEND_URL", "https://soc.example.test")
    monkeypatch.setenv("SOC_WINDOWS_EVENT_CHANNEL", "Security")
    monkeypatch.setenv("SOC_WINDOWS_CHECKPOINT_PATH", str(tmp_path / "checkpoint.json"))
    monkeypatch.delenv("SOC_BACKEND_USERNAME", raising=False)
    monkeypatch.delenv("SOC_BACKEND_PASSWORD", raising=False)
    assert main(["--status"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["checkpoint"] == 0
    assert payload["channel"] == "Security"
    assert payload["checkpoint_path"] == str(tmp_path / "checkpoint.json")
    assert payload["collector_version"] == "0.1.0"


def test_status_reports_invalid_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_text("invalid", encoding="utf-8")
    monkeypatch.setenv("SOC_BACKEND_URL", "https://soc.example.test")
    monkeypatch.setenv("SOC_WINDOWS_EVENT_CHANNEL", "Security")
    monkeypatch.setenv("SOC_WINDOWS_CHECKPOINT_PATH", str(checkpoint))
    assert main(["--status"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["last_error"] == "Checkpoint file could not be read."


def test_config_error_returns_two(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("SOC_BACKEND_URL", "https://soc.example.test")
    monkeypatch.delenv("SOC_WINDOWS_EVENT_CHANNEL", raising=False)
    assert main(["--status"]) == 2
    assert any("SOC_WINDOWS_EVENT_CHANNEL" in message for message in caplog.messages)


def test_version_exits_zero() -> None:
    with pytest.raises(SystemExit) as error:
        main(["--version"])
    assert error.value.code == 0
