"""Environment-driven collector configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .errors import ConfigError
from .models import COLLECTOR_NAME


def _text(value: str | None, name: str) -> str:
    if value is None or not value.strip():
        raise ConfigError(f"Missing required configuration: {name}.")
    return value.strip()


def _secret(value: str | None, name: str) -> str:
    if value is None or not value:
        raise ConfigError(f"Missing required configuration: {name}.")
    return value


def _parse_int(value: str | None, name: str, default: int, minimum: int, maximum: int) -> int:
    if value is None or not value.strip():
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer.") from exc
    if not minimum <= parsed <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}.")
    return parsed


def _parse_float(
    value: str | None, name: str, default: float, minimum: float, maximum: float
) -> float:
    if value is None or not value.strip():
        return default
    try:
        parsed = float(value)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number.") from exc
    if not minimum <= parsed <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}.")
    return parsed


def _validate_backend_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ConfigError("SOC_BACKEND_URL is not a valid URL.") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigError("SOC_BACKEND_URL must be an http or https URL.")
    if parsed.username or parsed.password:
        raise ConfigError("SOC_BACKEND_URL must not contain credentials.")
    if parsed.query or parsed.fragment:
        raise ConfigError("SOC_BACKEND_URL must not contain a query or fragment.")
    if parsed.path not in {"", "/"}:
        raise ConfigError("SOC_BACKEND_URL must be an origin without an API path.")
    if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ConfigError("SOC_BACKEND_URL must use HTTPS unless it targets localhost.")
    if port is not None and not 1 <= port <= 65535:
        raise ConfigError("SOC_BACKEND_URL has an invalid port.")
    return f"{parsed.scheme}://{parsed.netloc}"


def _default_checkpoint_path(environment: dict[str, str]) -> Path:
    local_app_data = environment.get("LOCALAPPDATA")
    if local_app_data:
        root = Path(local_app_data)
    else:
        root = Path.home() / "AppData" / "Local"
    return root / "SOCWindowsCollector" / "checkpoint.json"


@dataclass(frozen=True)
class CollectorConfig:
    backend_url: str
    username: str
    password: str = field(repr=False)
    channel: str
    checkpoint_path: Path
    batch_size: int = 50
    poll_interval_seconds: float = 30.0
    request_timeout_seconds: float = 10.0
    source_timeout_seconds: float = 30.0
    powershell_path: str = "powershell.exe"
    source_name: str = COLLECTOR_NAME

    @property
    def login_url(self) -> str:
        return f"{self.backend_url}/api/v1/auth/login"

    @property
    def events_url(self) -> str:
        return f"{self.backend_url}/api/v1/events"

    @classmethod
    def from_env(
        cls,
        environment: dict[str, str] | None = None,
        require_credentials: bool = True,
    ) -> CollectorConfig:
        source = dict(os.environ) if environment is None else dict(environment)
        backend_url = _validate_backend_url(_text(source.get("SOC_BACKEND_URL"), "SOC_BACKEND_URL"))
        if require_credentials:
            username = _text(source.get("SOC_BACKEND_USERNAME"), "SOC_BACKEND_USERNAME")
            password = _secret(source.get("SOC_BACKEND_PASSWORD"), "SOC_BACKEND_PASSWORD")
        else:
            username = source.get("SOC_BACKEND_USERNAME", "").strip()
            password = source.get("SOC_BACKEND_PASSWORD", "")
        channel = _text(source.get("SOC_WINDOWS_EVENT_CHANNEL"), "SOC_WINDOWS_EVENT_CHANNEL")
        if len(channel) > 255 or any(ord(character) < 32 for character in channel):
            raise ConfigError("SOC_WINDOWS_EVENT_CHANNEL is invalid.")
        source_name = (
            source.get("SOC_WINDOWS_SOURCE_NAME", COLLECTOR_NAME).strip() or COLLECTOR_NAME
        )
        if len(source_name) > 128:
            raise ConfigError("SOC_WINDOWS_SOURCE_NAME must be 128 characters or fewer.")
        powershell_path = source.get("SOC_WINDOWS_POWERSHELL", "powershell.exe").strip()
        if not powershell_path:
            raise ConfigError("SOC_WINDOWS_POWERSHELL must not be empty.")
        checkpoint_value = source.get("SOC_WINDOWS_CHECKPOINT_PATH")
        checkpoint_path = (
            Path(checkpoint_value).expanduser()
            if checkpoint_value and checkpoint_value.strip()
            else _default_checkpoint_path(source)
        )
        return cls(
            backend_url=backend_url,
            username=username,
            password=password,
            channel=channel,
            checkpoint_path=checkpoint_path,
            batch_size=_parse_int(
                source.get("SOC_WINDOWS_BATCH_SIZE"), "SOC_WINDOWS_BATCH_SIZE", 50, 1, 500
            ),
            poll_interval_seconds=_parse_float(
                source.get("SOC_WINDOWS_POLL_INTERVAL_SECONDS"),
                "SOC_WINDOWS_POLL_INTERVAL_SECONDS",
                30.0,
                5.0,
                3600.0,
            ),
            request_timeout_seconds=_parse_float(
                source.get("SOC_WINDOWS_REQUEST_TIMEOUT_SECONDS"),
                "SOC_WINDOWS_REQUEST_TIMEOUT_SECONDS",
                10.0,
                1.0,
                120.0,
            ),
            source_timeout_seconds=_parse_float(
                source.get("SOC_WINDOWS_SOURCE_TIMEOUT_SECONDS"),
                "SOC_WINDOWS_SOURCE_TIMEOUT_SECONDS",
                30.0,
                5.0,
                300.0,
            ),
            powershell_path=powershell_path,
            source_name=source_name,
        )


__all__ = ["CollectorConfig"]
