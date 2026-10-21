"""Durable, channel-scoped checkpoint storage."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .errors import CheckpointError
from .models import utc_now_iso

CHECKPOINT_VERSION = 1


@dataclass(frozen=True)
class CheckpointState:
    record_id: int
    channel: str
    updated_at: str | None


class CheckpointStore:
    def __init__(self, path: Path, channel: str) -> None:
        self.path = Path(path)
        self.channel = channel

    def load(self) -> CheckpointState:
        if not self.path.exists():
            return CheckpointState(record_id=0, channel=self.channel, updated_at=None)
        if not self.path.is_file():
            raise CheckpointError("Checkpoint path is not a regular file.")
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CheckpointError("Checkpoint file could not be read.") from exc
        if not isinstance(payload, dict):
            raise CheckpointError("Checkpoint file has an invalid format.")
        if payload.get("version") != CHECKPOINT_VERSION:
            raise CheckpointError("Checkpoint file has an unsupported version.")
        stored_channel = payload.get("channel")
        if stored_channel != self.channel:
            raise CheckpointError("Checkpoint belongs to a different event channel.")
        record_id = payload.get("record_id")
        if isinstance(record_id, bool) or not isinstance(record_id, int) or record_id < 0:
            raise CheckpointError("Checkpoint record ID is invalid.")
        updated_at = payload.get("updated_at")
        if updated_at is not None and not isinstance(updated_at, str):
            raise CheckpointError("Checkpoint timestamp is invalid.")
        return CheckpointState(record_id=record_id, channel=self.channel, updated_at=updated_at)

    def save(self, record_id: int) -> CheckpointState:
        if record_id < 0:
            raise CheckpointError("Checkpoint record ID is invalid.")
        state = CheckpointState(
            record_id=record_id,
            channel=self.channel,
            updated_at=utc_now_iso(),
        )
        payload = {
            "version": CHECKPOINT_VERSION,
            "channel": state.channel,
            "record_id": state.record_id,
            "updated_at": state.updated_at,
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise CheckpointError("Checkpoint directory could not be created.") from exc
        handle = None
        temporary_path: str | None = None
        try:
            handle, temporary_path = tempfile.mkstemp(
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                dir=self.path.parent,
                text=True,
            )
            with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
                handle = None
                json.dump(payload, stream, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, self.path)
            temporary_path = None
        except OSError as exc:
            raise CheckpointError("Checkpoint file could not be written.") from exc
        finally:
            if handle is not None:
                os.close(handle)
            if temporary_path is not None:
                try:
                    os.unlink(temporary_path)
                except OSError:
                    pass
        return state


__all__ = ["CHECKPOINT_VERSION", "CheckpointState", "CheckpointStore"]
