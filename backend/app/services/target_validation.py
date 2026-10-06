"""Strict scan-target validation (Step 2, hardened in Step 14).

Two layers, checked in order:

1. Format validation (``validate_target``): only single IPv4/IPv6
   addresses or bounded CIDR networks (≤256 addresses). Anything else —
   hostnames, URLs, shell metacharacters, flag-looking strings — is
   rejected. Purely syntactic (``ipaddress`` module); never executes.
2. Authorization scope (``authorize_target``): the normalized target
   must fall inside the configured ``SCAN_ALLOWED_NETWORKS`` CIDR
   allow-list (loopback-only by default). Well-formed but out-of-scope
   targets are refused with ``TargetNotAuthorizedError``. Fail-closed:
   an empty or unparseable allow-list denies everything.

Scans must only ever target systems/networks the operator is authorized
to assess; the API and UI state this explicitly.
"""

from __future__ import annotations

import ipaddress

from app.core.logging import get_logger

logger = get_logger(__name__)

# Networks larger than this are refused by default: an inventory scan
# must stay small, fast and attributable. /24 (256 addresses) is the
# largest allowed unless discovery_max_addresses says otherwise.
DEFAULT_MAX_NETWORK_ADDRESSES = 256
MAX_TARGET_LENGTH = 64

_SHELL_METACHARACTERS = frozenset(";&|$`()<>\\'\"*?!~#%=\n\r\t ")


class InvalidTargetError(ValueError):
    """Raised when a scan target is not an authorized format."""


class TargetNotAuthorizedError(ValueError):
    """Raised when a well-formed target falls outside the allowed scope."""


def parse_allowed_networks(raw: str) -> list[ipaddress._BaseNetwork]:
    """Parse the CIDR allow-list. Invalid entries are skipped with a warning.

    Returns an empty list when nothing parses — callers treat that as
    deny-all (fail-closed).
    """
    networks: list[ipaddress._BaseNetwork] = []
    for entry in (raw or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid SCAN_ALLOWED_NETWORKS entry: %r", entry)
    return networks


def validate_target(raw: object, max_addresses: int | None = None) -> str:
    """Validate and normalize a scan target.

    Returns the canonical ``ipaddress`` string (e.g. ``"127.0.0.1"`` or
    ``"192.168.1.0/24"``). CIDR networks larger than ``max_addresses``
    (default ``discovery_max_addresses``, 256) are refused. Raises
    :class:`InvalidTargetError` otherwise.
    """
    from app.core.config import get_settings

    limit = max_addresses if max_addresses is not None else get_settings().discovery_max_addresses
    if not isinstance(raw, str):
        raise InvalidTargetError("Target must be a string.")
    target = raw.strip()
    if not target:
        raise InvalidTargetError("Target must not be empty.")
    if len(target) > MAX_TARGET_LENGTH:
        raise InvalidTargetError("Target is too long.")
    if any(char in _SHELL_METACHARACTERS for char in target):
        raise InvalidTargetError("Target contains characters that are never valid in an IP/CIDR.")
    if target.startswith("-"):
        raise InvalidTargetError("Target must not look like a command-line flag.")

    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        address = None
    if address is not None:
        return str(address)

    try:
        network = ipaddress.ip_network(target, strict=True)
    except ValueError:
        raise InvalidTargetError(
            "Target must be a single IPv4/IPv6 address or a CIDR network (e.g. 192.168.1.0/24)."
        ) from None
    if network.num_addresses > limit:
        raise InvalidTargetError(f"Network too large for a discovery scan (max {limit} addresses).")
    return str(network)


def authorize_target(normalized_target: str, allowed_networks: list[ipaddress._BaseNetwork]) -> str:
    """Require a validated target to sit inside the authorization scope.

    Single IPs must be contained in an allowed network; CIDR targets
    must be fully contained (``subnet_of``) — the scope is never
    silently expanded. Raises :class:`TargetNotAuthorizedError`.
    """
    try:
        address = ipaddress.ip_address(normalized_target)
    except ValueError:
        address = None
    if address is not None:
        if any(
            address in network for network in allowed_networks if address.version == network.version
        ):
            return normalized_target
        raise TargetNotAuthorizedError(
            "Target is outside the authorized scan scope. "
            "Only explicitly approved networks may be scanned."
        )
    try:
        network = ipaddress.ip_network(normalized_target, strict=True)
    except ValueError:
        raise TargetNotAuthorizedError("Target is outside the authorized scan scope.") from None
    same_version = [allowed for allowed in allowed_networks if allowed.version == network.version]
    if any(network.subnet_of(allowed) for allowed in same_version):
        return normalized_target
    raise TargetNotAuthorizedError(
        "Target network is outside the authorized scan scope. "
        "Only explicitly approved networks may be scanned."
    )
