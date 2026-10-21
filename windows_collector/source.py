"""Windows Event Log source backed by PowerShell ``Get-WinEvent``."""

from __future__ import annotations

import base64
import binascii
import json
import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .errors import SourceDataError, SourceError, SourceUnavailableError
from .models import RawWindowsEvent, SourceBatch

ALLOWED_EVENT_DATA = frozenset(
    {
        "Application",
        "AuthenticationPackageName",
        "Image",
        "IpAddress",
        "IpPort",
        "LogonType",
        "NewProcessName",
        "ProcessName",
        "SourceIp",
        "SubjectDomainName",
        "SubjectUserName",
        "TargetDomainName",
        "TargetUserName",
        "WorkstationName",
    }
)

SAFE_ENV_KEYS = frozenset(
    {
        "ALLUSERSPROFILE",
        "APPDATA",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PSMODULEPATH",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    }
)

POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$channel = $env:SOC_WINDOWS_EVENT_CHANNEL
$after = [long]$env:SOC_WINDOWS_AFTER_RECORD_ID
$maxEvents = [int]$env:SOC_WINDOWS_MAX_EVENTS
$allowed = @(
  'Application', 'AuthenticationPackageName', 'Image', 'IpAddress', 'IpPort',
  'LogonType', 'NewProcessName', 'ProcessName', 'SourceIp', 'SubjectDomainName',
  'SubjectUserName', 'TargetDomainName', 'TargetUserName', 'WorkstationName'
)
$newest = $null
try {
  $latest = Get-WinEvent -LogName $channel -MaxEvents 1 -ErrorAction Stop
  $newest = [long]$latest.RecordId
} catch {
  if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') { throw }
}
$filter = "*[System[EventRecordID > $after]]"
$events = @()
try {
  $events = @(Get-WinEvent -LogName $channel -FilterXPath $filter -Oldest -MaxEvents $maxEvents -ErrorAction Stop)
} catch {
  if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') { throw }
}
$result = @()
foreach ($event in $events) {
  $xml = [xml]$event.ToXml()
  $data = @{}
  foreach ($node in @($xml.Event.EventData.Data)) {
    if ($null -ne $node.Name) {
      $name = [string]$node.Name
      if ($allowed -contains $name) {
        $value = [string]$node.'#text'
        if ($value.Length -gt 512) { $value = $value.Substring(0, 512) }
        $data[$name] = $value
      }
    }
  }
  $level = $null
  if ($null -ne $event.Level) { $level = [int]$event.Level }
  $task = $null
  if ($null -ne $event.Task) { $task = [int]$event.Task }
  $opcode = $null
  if ($null -ne $event.Opcode) { $opcode = [int]$event.Opcode }
  $keywords = $null
  if ($null -ne $event.Keywords) { $keywords = [string]$event.Keywords }
  $result += [pscustomobject]@{
    record_id = [long]$event.RecordId
    event_id = [int]$event.Id
    channel = [string]$event.LogName
    provider = [string]$event.ProviderName
    level = $level
    task = $task
    opcode = $opcode
    keywords = $keywords
    time_created = $event.TimeCreated.ToUniversalTime().ToString('o')
    computer = [string]$event.MachineName
    user_id = [string]$event.UserId
    event_data = $data
  }
}
$json = ConvertTo-Json -InputObject @{ newest_record_id = $newest; events = @($result) } -Compress -Depth 6
[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
"""


def _default_runner(
    args: list[str], environment: dict[str, str], timeout: float
) -> subprocess.CompletedProcess[str]:
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        env=environment,
        creationflags=creationflags,
    )


def _safe_environment(after_record_id: int, limit: int, channel: str) -> dict[str, str]:
    environment: dict[str, str] = {}
    for key, value in os.environ.items():
        if key.upper() in SAFE_ENV_KEYS:
            environment[key] = value
    environment["SOC_WINDOWS_EVENT_CHANNEL"] = channel
    environment["SOC_WINDOWS_AFTER_RECORD_ID"] = str(after_record_id)
    environment["SOC_WINDOWS_MAX_EVENTS"] = str(limit)
    return environment


def _as_int(value: object, name: str) -> int:
    if isinstance(value, bool):
        raise SourceDataError(f"Windows event has an invalid {name}.")
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise SourceDataError(f"Windows event has an invalid {name}.") from exc
    if parsed < 0:
        raise SourceDataError(f"Windows event has an invalid {name}.")
    return parsed


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _optional_text(value: object, limit: int = 512) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:limit]


def _parse_event(payload: object, requested_channel: str) -> RawWindowsEvent:
    if not isinstance(payload, dict):
        raise SourceDataError("Windows event payload is not an object.")
    record_id = _as_int(payload.get("record_id"), "record_id")
    event_id = _as_int(payload.get("event_id"), "event_id")
    event_time = _optional_text(payload.get("time_created"), 64)
    if event_time is None:
        raise SourceDataError("Windows event has no timestamp.")
    channel = _optional_text(payload.get("channel"), 255) or requested_channel
    raw_data = payload.get("event_data")
    event_data: dict[str, str] = {}
    if isinstance(raw_data, dict):
        for key, value in list(raw_data.items())[:32]:
            name = str(key)
            if name in ALLOWED_EVENT_DATA and value is not None:
                text = str(value)
                event_data[name] = text[:512]
    return RawWindowsEvent(
        record_id=record_id,
        event_id=event_id,
        channel=channel,
        event_time=event_time,
        provider=_optional_text(payload.get("provider"), 255),
        level=_optional_int(payload.get("level")),
        task=_optional_int(payload.get("task")),
        opcode=_optional_int(payload.get("opcode")),
        keywords=_optional_text(payload.get("keywords"), 256),
        computer=_optional_text(payload.get("computer"), 255),
        user_id=_optional_text(payload.get("user_id"), 255),
        event_data=event_data,
    )


@dataclass
class PowerShellEventSource:
    channel: str
    powershell_path: str = "powershell.exe"
    timeout_seconds: float = 30.0
    runner: Callable[[list[str], dict[str, str], float], subprocess.CompletedProcess[str]] = (
        _default_runner
    )

    def _invoke(self, after_record_id: int, limit: int) -> tuple[list[RawWindowsEvent], int | None]:
        args = [
            self.powershell_path,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            POWERSHELL_SCRIPT,
        ]
        environment = _safe_environment(after_record_id, limit, self.channel)
        try:
            completed = self.runner(args, environment, self.timeout_seconds)
        except FileNotFoundError as exc:
            raise SourceUnavailableError("PowerShell is not available.") from exc
        except subprocess.TimeoutExpired as exc:
            raise SourceError("Windows event source timed out.") from exc
        except OSError as exc:
            raise SourceUnavailableError("Windows event source could not be started.") from exc
        if completed.returncode != 0:
            raise SourceUnavailableError(
                f"Windows event source is unavailable (exit {completed.returncode})."
            )
        output = (completed.stdout or "").strip().lstrip("\ufeff")
        if not output:
            raise SourceDataError("Windows event source returned no data.")
        try:
            raw_payload = base64.b64decode(output, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise SourceDataError("Windows event source returned invalid encoding.") from exc
        try:
            payload: Any = json.loads(raw_payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SourceDataError("Windows event source returned invalid JSON.") from exc
        if not isinstance(payload, dict):
            raise SourceDataError("Windows event source returned an invalid payload.")
        raw_events = payload.get("events")
        if not isinstance(raw_events, list):
            raise SourceDataError("Windows event source returned no event list.")
        newest_value = payload.get("newest_record_id")
        newest = None if newest_value is None else _as_int(newest_value, "newest_record_id")
        events = [_parse_event(item, self.channel) for item in raw_events if isinstance(item, dict)]
        if len(events) != len(raw_events):
            raise SourceDataError("Windows event source returned a malformed event.")
        if events and newest is None:
            raise SourceDataError("Windows event source omitted the newest record ID.")
        if events and newest is not None and newest < max(event.record_id for event in events):
            raise SourceDataError("Windows event source returned an inconsistent newest record ID.")
        unique = {event.record_id: event for event in events if event.record_id > after_record_id}
        ordered = tuple(sorted(unique.values(), key=lambda event: event.record_id))
        return list(ordered), newest

    def read_batch(self, after_record_id: int, limit: int) -> SourceBatch:
        if after_record_id < 0:
            raise SourceError("Checkpoint record ID is invalid.")
        if not 1 <= limit <= 500:
            raise SourceError("Batch size must be between 1 and 500.")
        events, newest = self._invoke(after_record_id, limit)
        reset = bool(after_record_id > 0 and (newest is None or newest < after_record_id))
        if reset:
            events, newest = self._invoke(0, limit)
        return SourceBatch(
            events=tuple(events),
            newest_record_id=newest,
            reset_detected=reset,
        )


__all__ = ["ALLOWED_EVENT_DATA", "PowerShellEventSource", "POWERSHELL_SCRIPT", "SAFE_ENV_KEYS"]
