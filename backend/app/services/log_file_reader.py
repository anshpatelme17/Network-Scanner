"""Safe file-source inspection for bounded log ingestion (Step 28).

Detects, from metadata only, that a configured log file changed
underneath a bounded poll:

- ``ROTATED`` — the file identity (device + inode where the platform
  reports one) differs from the identity recorded with the checkpoint;
- ``OFFSET_INVALID`` — the stored byte offset is now beyond the end of
  the file, so resuming there is impossible;
- ``TRUNCATED`` — the file shrank (rewrite/rotation in place);
- ``MISSING`` — the configured path is gone.

The module never opens, reads, watches, or tails anything: it only
``stat()``s the operator-configured path and compares it with the stored
cursor. File access stays strictly inside the configured path — no
client-supplied path, no directory traversal, no filesystem monitoring.

Platform note: inode identity is not reported everywhere (e.g. some
Windows/``st_ino == 0`` cases). When identity is unavailable the
rotation check is skipped truthfully and only size/offset checks run.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DETECTION_ROTATED = "ROTATED"
DETECTION_TRUNCATED = "TRUNCATED"
DETECTION_OFFSET_INVALID = "OFFSET_INVALID"
DETECTION_MISSING = "MISSING"


@dataclass(frozen=True)
class FileState:
    """Metadata snapshot of one configured file (no content)."""

    exists: bool
    identity: str | None = None
    size: int | None = None


def stat_file(path_value: str) -> FileState:
    """Stat the configured path; missing/unreadable paths report absent."""
    try:
        info = Path(path_value).stat()
    except OSError:
        return FileState(exists=False)
    inode = getattr(info, "st_ino", 0) or 0
    identity = f"{info.st_dev}:{inode}" if inode else None
    return FileState(exists=True, identity=identity, size=int(info.st_size))


def evaluate(prior: Mapping[str, Any] | None, state: FileState) -> str | None:
    """Compare the stored cursor with the current file state.

    Returns the most specific detection, or ``None`` when the stored
    position is still valid. Ordering: identity change (rotation) beats
    an invalid offset, which beats a plain truncation.
    """
    if not state.exists:
        return DETECTION_MISSING
    if not prior:
        return None
    prior_identity = prior.get("file_identity")
    if isinstance(prior_identity, str) and prior_identity and state.identity:
        if prior_identity != state.identity:
            return DETECTION_ROTATED
    size = state.size if state.size is not None else 0
    offset = prior.get("offset")
    if isinstance(offset, int) and not isinstance(offset, bool) and offset > 0 and offset > size:
        return DETECTION_OFFSET_INVALID
    prior_size = prior.get("file_size")
    if isinstance(prior_size, int) and not isinstance(prior_size, bool) and prior_size > size:
        return DETECTION_TRUNCATED
    return None


__all__ = [
    "DETECTION_MISSING",
    "DETECTION_OFFSET_INVALID",
    "DETECTION_ROTATED",
    "DETECTION_TRUNCATED",
    "FileState",
    "evaluate",
    "stat_file",
]
