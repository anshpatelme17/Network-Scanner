from __future__ import annotations

from pathlib import Path

import pytest

from windows_collector.config import CollectorConfig


@pytest.fixture
def config(tmp_path: Path) -> CollectorConfig:
    return CollectorConfig(
        backend_url="https://soc.example.test",
        username="collector",
        password="Secret-Password-123",
        channel="Security",
        checkpoint_path=tmp_path / "checkpoint.json",
    )
