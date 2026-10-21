from __future__ import annotations

from pathlib import Path

import pytest

from windows_collector.config import CollectorConfig
from windows_collector.errors import ConfigError

BASE_ENV = {
    "SOC_BACKEND_URL": "https://soc.example.test/",
    "SOC_BACKEND_USERNAME": "collector",
    "SOC_BACKEND_PASSWORD": "Secret-Password-123",
    "SOC_WINDOWS_EVENT_CHANNEL": "Security",
    "LOCALAPPDATA": r"C:\Users\collector\AppData\Local",
}


def test_valid_config_and_defaults() -> None:
    config = CollectorConfig.from_env(BASE_ENV)
    assert config.backend_url == "https://soc.example.test"
    assert config.login_url == "https://soc.example.test/api/v1/auth/login"
    assert config.events_url == "https://soc.example.test/api/v1/events"
    assert config.username == "collector"
    assert config.channel == "Security"
    assert config.batch_size == 50
    assert config.poll_interval_seconds == 30.0
    assert config.request_timeout_seconds == 10.0
    assert config.source_timeout_seconds == 30.0
    assert config.source_name == "windows-event-collector"
    assert config.checkpoint_path == Path(
        r"C:\Users\collector\AppData\Local\SOCWindowsCollector\checkpoint.json"
    )


def test_password_is_not_in_repr() -> None:
    config = CollectorConfig.from_env(BASE_ENV)
    assert "Secret-Password-123" not in repr(config)


@pytest.mark.parametrize(
    "missing",
    [
        "SOC_BACKEND_URL",
        "SOC_BACKEND_USERNAME",
        "SOC_BACKEND_PASSWORD",
        "SOC_WINDOWS_EVENT_CHANNEL",
    ],
)
def test_missing_required_values_are_rejected(missing: str) -> None:
    environment = dict(BASE_ENV)
    environment.pop(missing)
    with pytest.raises(ConfigError):
        CollectorConfig.from_env(environment)


def test_status_config_does_not_require_credentials() -> None:
    environment = dict(BASE_ENV)
    environment.pop("SOC_BACKEND_USERNAME")
    environment.pop("SOC_BACKEND_PASSWORD")
    config = CollectorConfig.from_env(environment, require_credentials=False)
    assert config.username == ""
    assert config.password == ""


@pytest.mark.parametrize(
    "url",
    [
        "http://soc.example.test",
        "https://user:password@soc.example.test",
        "https://soc.example.test/api",
        "https://soc.example.test?token=value",
        "https://soc.example.test#fragment",
        "ftp://soc.example.test",
        "https://soc.example.test:99999",
        "not-a-url",
    ],
)
def test_invalid_backend_urls_are_rejected(url: str) -> None:
    environment = dict(BASE_ENV)
    environment["SOC_BACKEND_URL"] = url
    with pytest.raises(ConfigError):
        CollectorConfig.from_env(environment)


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://[::1]:8000",
        "https://soc.example.test:8443",
    ],
)
def test_safe_backend_urls_are_accepted(url: str) -> None:
    environment = dict(BASE_ENV)
    environment["SOC_BACKEND_URL"] = url
    assert CollectorConfig.from_env(environment).backend_url == url.rstrip("/")


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("SOC_WINDOWS_BATCH_SIZE", "0"),
        ("SOC_WINDOWS_BATCH_SIZE", "501"),
        ("SOC_WINDOWS_BATCH_SIZE", "abc"),
        ("SOC_WINDOWS_POLL_INTERVAL_SECONDS", "4"),
        ("SOC_WINDOWS_POLL_INTERVAL_SECONDS", "3601"),
        ("SOC_WINDOWS_REQUEST_TIMEOUT_SECONDS", "0"),
        ("SOC_WINDOWS_REQUEST_TIMEOUT_SECONDS", "121"),
        ("SOC_WINDOWS_SOURCE_TIMEOUT_SECONDS", "4"),
        ("SOC_WINDOWS_SOURCE_TIMEOUT_SECONDS", "301"),
    ],
)
def test_out_of_range_values_are_rejected(name: str, value: str) -> None:
    environment = dict(BASE_ENV)
    environment[name] = value
    with pytest.raises(ConfigError):
        CollectorConfig.from_env(environment)


def test_optional_values_can_be_overridden(tmp_path: Path) -> None:
    environment = dict(BASE_ENV)
    environment.update(
        {
            "SOC_WINDOWS_BATCH_SIZE": "25",
            "SOC_WINDOWS_POLL_INTERVAL_SECONDS": "15",
            "SOC_WINDOWS_REQUEST_TIMEOUT_SECONDS": "20",
            "SOC_WINDOWS_SOURCE_TIMEOUT_SECONDS": "40",
            "SOC_WINDOWS_CHECKPOINT_PATH": str(tmp_path / "state.json"),
            "SOC_WINDOWS_SOURCE_NAME": "windows-security-live",
        }
    )
    config = CollectorConfig.from_env(environment)
    assert config.batch_size == 25
    assert config.poll_interval_seconds == 15.0
    assert config.request_timeout_seconds == 20.0
    assert config.source_timeout_seconds == 40.0
    assert config.checkpoint_path == tmp_path / "state.json"
    assert config.source_name == "windows-security-live"


def test_invalid_channel_and_source_name_are_rejected() -> None:
    environment = dict(BASE_ENV)
    environment["SOC_WINDOWS_EVENT_CHANNEL"] = "Security\nOther"
    with pytest.raises(ConfigError):
        CollectorConfig.from_env(environment)
    environment["SOC_WINDOWS_EVENT_CHANNEL"] = "x" * 256
    with pytest.raises(ConfigError):
        CollectorConfig.from_env(environment)
    environment["SOC_WINDOWS_EVENT_CHANNEL"] = "Security"
    environment["SOC_WINDOWS_SOURCE_NAME"] = "x" * 129
    with pytest.raises(ConfigError):
        CollectorConfig.from_env(environment)
