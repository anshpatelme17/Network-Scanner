"""Controlled Nmap execution (Step 2, defensive).

Security contract (enforced here, not by callers):

- No ``shell=True``, no ``os.system``, no ``eval``/``exec`` — ever.
- The executable is the literal ``"nmap"`` resolved from ``PATH``; the
  command is an explicit ``list[str]``; user input (the *validated* target)
  is exactly one argv element, never concatenated into a command line.
- Nmap flags come ONLY from the allow-listed ``SCAN_PROFILES`` below.
  The API accepts a profile *name*; unknown names are rejected before any
  process is spawned.
- Every run has a per-profile timeout and a hard cap on captured output,
  bounding scan duration and memory use.
- The child gets a minimal, fixed environment — nothing from the request.

If Nmap is not installed, nothing else breaks: availability is reported
as ``False`` and scan creation returns a controlled 503.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

NMAP_EXECUTABLE = "nmap"

# Captured stdout/stderr beyond this is truncated (still parsed if valid).
MAX_OUTPUT_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class ScanProfile:
    name: str
    description: str
    args: tuple[str, ...]
    timeout_seconds: int
    # False when the profile never probes ports (host discovery only):
    # normalization must then keep previously observed services instead
    # of replacing them with an empty observation.
    probes_ports: bool = True


# Fixed approved TCP port set for DISCOVERY_TCP_COMMON. Explicit and
# finite — never derived from client input, never the full range.
DISCOVERY_TCP_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"

SCAN_PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        description="Fast service/version inventory of the most common ports.",
        args=("-sV", "-T4", "--top-ports", "100"),
        timeout_seconds=180,
    ),
    "standard": ScanProfile(
        name="standard",
        description="Deeper service discovery with OS fingerprinting attempt.",
        args=("-sV", "-O", "-T4", "--top-ports", "1000"),
        timeout_seconds=900,
    ),
    # Step 21 discovery profiles (additive; existing profiles untouched).
    "DISCOVERY_PING": ScanProfile(
        name="DISCOVERY_PING",
        description="Host discovery only: ping sweep, no port probing.",
        args=("-sn", "-T4"),
        timeout_seconds=120,
        probes_ports=False,
    ),
    "DISCOVERY_TCP_COMMON": ScanProfile(
        name="DISCOVERY_TCP_COMMON",
        description="Controlled TCP discovery over a fixed approved port set.",
        args=("-sT", "-T4", "-p", DISCOVERY_TCP_PORTS),
        timeout_seconds=300,
    ),
}

# Fixed minimal environment for the child process.
_CHILD_ENV = {"PATH": os.defpath, "LC_ALL": "C", "LANG": "C"}


class NmapUnavailableError(RuntimeError):
    """Nmap is not installed or not executable."""


class NmapScanError(RuntimeError):
    """Nmap ran but the scan failed (timeout, crash, unusable output)."""


def is_available() -> bool:
    """True when an ``nmap`` executable is on ``PATH``."""
    return shutil.which(NMAP_EXECUTABLE) is not None


def get_version() -> str | None:
    """Return e.g. ``"7.94"`` or None when Nmap is missing/broken.

    Only the version number is exposed — never raw paths or full banners.
    """
    if not is_available():
        return None
    try:
        completed = subprocess.run(
            [NMAP_EXECUTABLE, "--version"],
            shell=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=_CHILD_ENV,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    first_line = (completed.stdout or "").splitlines()
    if not first_line or not first_line[0].startswith("Nmap version "):
        return None
    # First line looks like "Nmap version 7.95 ( https://nmap.org )";
    # expose only the version number, never paths or banners.
    token = first_line[0].removeprefix("Nmap version ").strip().split()
    return token[0] if token else None


def build_argv(profile_name: str, validated_target: str) -> list[str]:
    """Build the exact argv for a profile. No user input beyond the target.

    Raises ``KeyError`` for unknown profiles (mapped to 422 by the API).
    """
    profile = SCAN_PROFILES[profile_name]
    return [NMAP_EXECUTABLE, "-oX", "-", *profile.args, validated_target]


def run_scan(profile_name: str, validated_target: str) -> tuple[str, str | None]:
    """Run Nmap and return ``(xml_stdout, nmap_version)``.

    Raises :class:`NmapUnavailableError` / :class:`NmapScanError` with
    short, operator-safe messages (no tracebacks, no full command lines
    containing target details beyond what the operator supplied).
    """
    try:
        profile = SCAN_PROFILES[profile_name]
    except KeyError:
        raise NmapScanError(f"Unknown scan profile: {profile_name!r}.") from None
    if not is_available():
        raise NmapUnavailableError("Nmap executable is not available on this host.")
    argv = build_argv(profile_name, validated_target)
    try:
        completed = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            timeout=profile.timeout_seconds,
            env=_CHILD_ENV,
        )
    except subprocess.TimeoutExpired:
        raise NmapScanError(
            f"Scan timed out after {profile.timeout_seconds} seconds (profile {profile_name!r})."
        ) from None
    except OSError as exc:
        raise NmapScanError(f"Could not start Nmap: {exc.strerror or 'OS error'}.") from None
    xml_output = (completed.stdout or "")[:MAX_OUTPUT_BYTES]
    if completed.returncode != 0 or "<nmaprun" not in xml_output:
        stderr_tail = (completed.stderr or "").strip()[-300:]
        raise NmapScanError(
            "Nmap did not produce usable XML output."
            + (f" Scanner reported: {stderr_tail}" if stderr_tail else "")
        )
    return xml_output, get_version()
