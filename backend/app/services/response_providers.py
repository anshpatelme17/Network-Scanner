"""Response provider interface and server-side registry (Step 30).

This module is the *controlled* provider layer for defensive responses.
It is intentionally a separate registry from ``response_executors``
(Steps 13/19), whose five simulation adapters and their exact wire shapes
are frozen by regression tests. Nothing here is registered into that
registry and nothing there is modified.

Safety properties, all structural rather than conventional:

* No imports of ``subprocess``, ``os``, ``socket``, ``shutil``,
  ``importlib``, ``requests``, ``httpx``, or ``urllib``. A provider
  therefore *cannot* run a command, open a socket, or make an HTTP call,
  even by accident — there is no transport in scope to do it with.
* No provider is selected from client input. ``get_provider`` takes a
  name that only ever comes from ``PROVIDER_SELECTION`` or the
  ``RESPONSE_PROVIDER`` setting, and raises ``KeyError`` otherwise.
* Every provider validates and previews without performing anything.
  ``preview_action`` is pure.
* The only registered provider that can report an execution is ``MOCK``,
  and what it "executes" is a platform-side record. It never contacts,
  configures, or modifies Microsoft Defender, a firewall, Wazuh, an
  endpoint agent, a cloud security API, or any operating system.

Real integrations (Defender / Wazuh / firewall / endpoint management /
cloud) are represented by the ``NOT_CONFIGURED`` provider, which refuses
every consequential action with an explicit reason. That is the default
posture: this platform does not claim a defensive capability it cannot
actually perform and test.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

# Step 30 registry names.
MOCK_PROVIDER = "MOCK"
NOT_CONFIGURED_PROVIDER = "NOT_CONFIGURED"

# Step 30 controlled action types. These are the only actions the
# governance flow will request, approve, execute, or roll back, and the
# only ones that may ever name an indicator/endpoint target. Lengths all
# fit the ``response_actions.action_type`` String(32) column.
ACTION_BLOCK_INDICATOR = "BLOCK_INDICATOR"
ACTION_DISABLE_INDICATOR_BLOCK = "DISABLE_INDICATOR_BLOCK"
ACTION_ISOLATE_ENDPOINT = "ISOLATE_ENDPOINT"
ACTION_RELEASE_ENDPOINT = "RELEASE_ENDPOINT"
ACTION_DISABLE_ACCOUNT = "DISABLE_ACCOUNT"
ACTION_ENABLE_ACCOUNT = "ENABLE_ACCOUNT"
CONTROLLED_ACTION_TYPES = (
    ACTION_BLOCK_INDICATOR,
    ACTION_DISABLE_INDICATOR_BLOCK,
    ACTION_ISOLATE_ENDPOINT,
    ACTION_RELEASE_ENDPOINT,
    ACTION_DISABLE_ACCOUNT,
    ACTION_ENABLE_ACCOUNT,
)

# Step 30 target types. "INDICATOR" (9), "ENDPOINT" (8) and "HASH" (4)
# all fit the ``response_actions.target_type`` String(16) column.
TARGET_INDICATOR = "INDICATOR"
TARGET_ENDPOINT = "ENDPOINT"
TARGET_HASH = "HASH"
CONTROLLED_TARGET_TYPES = (
    "IP",
    TARGET_INDICATOR,
    TARGET_ENDPOINT,
    "ACCOUNT",
    "ASSET",
    TARGET_HASH,
)

# Which target types each action type is allowed to address. A
# combination outside this table is rejected by the policy layer before
# anything is proposed, so an action can never be pointed at a target
# shape it has no meaning for (e.g. BLOCK_INDICATOR at an ACCOUNT).
ACTION_TARGET_TYPES: dict[str, tuple[str, ...]] = {
    ACTION_BLOCK_INDICATOR: ("IP", TARGET_INDICATOR, TARGET_HASH),
    ACTION_DISABLE_INDICATOR_BLOCK: ("IP", TARGET_INDICATOR, TARGET_HASH),
    ACTION_ISOLATE_ENDPOINT: ("IP", "ASSET", TARGET_ENDPOINT, "HOSTNAME"),
    ACTION_RELEASE_ENDPOINT: ("IP", "ASSET", TARGET_ENDPOINT, "HOSTNAME"),
    ACTION_DISABLE_ACCOUNT: ("ACCOUNT",),
    ACTION_ENABLE_ACCOUNT: ("ACCOUNT",),
}

# Provider names for the *future* real integrations named in the Step 30
# brief. They are registered as NOT_CONFIGURED on purpose: the interface
# exists, the capability does not, and the platform says so.
PROVIDER_DEFENDER = "DEFENDER"
PROVIDER_WAZUH = "WAZUH"
PROVIDER_FIREWALL = "FIREWALL"
PROVIDER_ENDPOINT_MANAGER = "ENDPOINT_MANAGER"
PROVIDER_CLOUD = "CLOUD"

# Documented test sentinel. The mock provider must be able to exercise
# its failure path (so FAILED handling, rollback-unsupported honesty, and
# audit wording are all testable) without a real provider. When an
# otherwise valid, evidenced target is exactly this reference, MOCK
# returns a controlled failure. It is a syntactically valid account label
# so it still passes target validation and evidence checking first - the
# failure comes from the provider, not from a rejected request. It cannot
# do harm: MOCK never performs anything regardless of this value.
FAILURE_SENTINEL = "sim-failure-user"

_HASH_LABEL = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
_ACCOUNT_LABEL = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

NOT_CONFIGURED_NOTE = (
    "No real defensive provider is configured for this action type. "
    "No firewall, endpoint, account, or cloud system was contacted."
)


@dataclass(frozen=True)
class ProviderOutcome:
    """What a provider reports about a preview, execution, or rollback.

    ``executed`` is true only when the provider actually performed its
    action. For MOCK that means writing a platform-side record; it never
    implies an external system changed.
    """

    provider: str
    accepted: bool
    executed: bool
    simulated: bool
    status: str
    result_summary: str
    failure_reason: str | None = None
    rollback_supported: bool = False
    rollback_reference: str | None = None
    changes: tuple[str, ...] = field(default_factory=tuple)
    detail: dict[str, Any] = field(default_factory=dict)


class ProviderTargetRejected(ValueError):
    """The provider cannot act on this target shape or value."""


class ResponseProvider(ABC):
    """Interface every Step 30 response provider must implement."""

    name: str = "base"
    supports_execution: bool = False
    supports_rollback: bool = False

    @abstractmethod
    def validate_target(self, target_type: str, target_reference: str) -> None:
        """Raise ProviderTargetRejected unless this provider can act on the target."""

    @abstractmethod
    def preview_action(self, request: dict[str, Any]) -> ProviderOutcome:
        """Describe the action without performing it. Must be pure."""

    @abstractmethod
    def execute_action(self, request: dict[str, Any]) -> ProviderOutcome:
        """Perform the provider's action. Only MOCK implements this."""

    @abstractmethod
    def rollback_action(self, request: dict[str, Any]) -> ProviderOutcome:
        """Compensate a previous execution using recorded prior state."""

    @abstractmethod
    def get_action_status(self, request: dict[str, Any]) -> ProviderOutcome:
        """Report recorded status for an action. Read-only."""


class MockResponseProvider(ResponseProvider):
    """Deterministic fixture provider (Step 30).

    Every method is a pure string/hash computation. There is no
    transport, no filesystem access, and no operating-system call
    available to it, so it cannot affect the host or the network. An
    "execution" appends a platform-side record describing the defensive
    step and returns a deterministic prior-state reference that a later
    authorized rollback can consume.
    """

    name = MOCK_PROVIDER
    supports_execution = True
    supports_rollback = True

    _MOCK_ONLY_NOTE = (
        "Mock provider: the defensive step was recorded inside the platform only. "
        "No firewall, endpoint, account, or cloud system was contacted or changed."
    )

    def validate_target(self, target_type: str, target_reference: str) -> None:
        """Shape + format validation only. Never resolves, never contacts."""
        reference = (target_reference or "").strip()
        if not reference:
            raise ProviderTargetRejected("Target reference must not be empty.")
        if len(reference) > 256:
            raise ProviderTargetRejected("Target reference is too long.")
        if target_type == "IP":
            try:
                ipaddress.ip_address(reference)
            except ValueError:
                raise ProviderTargetRejected(
                    f"Target is not a valid IP address: {reference!r}."
                ) from None
        elif target_type == TARGET_HASH:
            if not _HASH_LABEL.match(reference):
                raise ProviderTargetRejected(
                    "Target is not a recognized indicator hash length (32/40/64 hex characters)."
                )
        elif target_type in ("ACCOUNT", "ENDPOINT"):
            if not _ACCOUNT_LABEL.match(reference):
                raise ProviderTargetRejected(
                    f"Target is not a valid {target_type.lower()} reference: {reference!r}."
                )
        elif target_type in ("ASSET", TARGET_INDICATOR, "HOSTNAME"):
            if not _ACCOUNT_LABEL.match(reference.replace(".", "-")):
                raise ProviderTargetRejected(
                    f"Target is not a valid {target_type.lower()} reference: {reference!r}."
                )
        else:
            raise ProviderTargetRejected(f"Unsupported target type: {target_type!r}.")

    def _plan(self, request: dict[str, Any]) -> tuple[str, str, str]:
        action_type = str(request.get("action_type") or "UNKNOWN")
        target_type = str(request.get("target_type") or "UNKNOWN")
        target_reference = str(request.get("target_reference") or "")
        return action_type, target_type, target_reference

    def _wants_failure(self, target_reference: str) -> bool:
        return target_reference == FAILURE_SENTINEL

    def _prior_state(self, action_id: str) -> str:
        """Deterministic prior-state token. A hash, never a real system state."""
        canonical = json.dumps(["mock-provider-prior-state:v1", action_id], separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()[:32]

    def preview_action(self, request: dict[str, Any]) -> ProviderOutcome:
        action_type, target_type, target_reference = self._plan(request)
        return ProviderOutcome(
            provider=self.name,
            accepted=True,
            executed=False,
            simulated=True,
            status="SIMULATED",
            result_summary=(
                f"Dry run: {action_type} against {target_type}:{target_reference} would be "
                f"recorded by the mock provider only. {self._MOCK_ONLY_NOTE}"
            ),
            changes=(),
            detail={"dry_run": True, "would_execute": True, "action_type": action_type},
        )

    def execute_action(self, request: dict[str, Any]) -> ProviderOutcome:
        action_type, target_type, target_reference = self._plan(request)
        action_id = str(request.get("action_id") or "")
        if self._wants_failure(target_reference):
            # Documented, deterministic provider-side failure (see
            # FAILURE_SENTINEL). No rollback reference is issued because
            # no state was changed, so rollback must report UNSUPPORTED
            # rather than invent a previous state.
            return ProviderOutcome(
                provider=self.name,
                accepted=True,
                executed=False,
                simulated=True,
                status="FAILED",
                result_summary=(
                    f"Mock provider refused {action_type} against {target_type}:{target_reference}."
                ),
                failure_reason=(
                    "Mock provider reported a controlled failure. No state was changed and no "
                    "external system was contacted."
                ),
                rollback_supported=False,
                rollback_reference=None,
            )
        return ProviderOutcome(
            provider=self.name,
            accepted=True,
            executed=True,
            simulated=True,
            status="COMPLETED",
            result_summary=(
                f"Mock provider recorded {action_type} against "
                f"{target_type}:{target_reference}. {self._MOCK_ONLY_NOTE}"
            ),
            rollback_supported=True,
            rollback_reference=self._prior_state(action_id),
            changes=(f"platform_record:{action_type}:{target_type}",),
            detail={"dry_run": False, "would_execute": True, "action_type": action_type},
        )

    def rollback_action(self, request: dict[str, Any]) -> ProviderOutcome:
        action_type, target_type, target_reference = self._plan(request)
        prior_state = request.get("rollback_reference")
        if not prior_state:
            # Never guess what the previous state was.
            return ProviderOutcome(
                provider=self.name,
                accepted=False,
                executed=False,
                simulated=True,
                status="UNSUPPORTED",
                result_summary=(
                    "Rollback is not supported for this action: the provider recorded no prior "
                    "state to restore."
                ),
                failure_reason="No prior-state reference was recorded for this action.",
            )
        return ProviderOutcome(
            provider=self.name,
            accepted=True,
            executed=True,
            simulated=True,
            status="COMPLETED",
            result_summary=(
                f"Mock provider rolled back {action_type} against "
                f"{target_type}:{target_reference} to recorded prior state {prior_state}. "
                f"{self._MOCK_ONLY_NOTE}"
            ),
            rollback_supported=True,
            rollback_reference=str(prior_state),
            changes=(f"platform_rollback:{action_type}:{target_type}",),
        )

    def get_action_status(self, request: dict[str, Any]) -> ProviderOutcome:
        action_type, target_type, target_reference = self._plan(request)
        return ProviderOutcome(
            provider=self.name,
            accepted=True,
            executed=False,
            simulated=True,
            status="RECORDED",
            result_summary=(
                f"Mock provider has no external state for {action_type} against "
                f"{target_type}:{target_reference}; platform records only."
            ),
        )


class NotConfiguredProvider(ResponseProvider):
    """Refuses everything (Step 30 default for real integrations)."""

    name = NOT_CONFIGURED_PROVIDER
    supports_execution = False
    supports_rollback = False

    def validate_target(self, target_type: str, target_reference: str) -> None:
        raise ProviderTargetRejected(NOT_CONFIGURED_NOTE)

    def _refuse(self, verb: str) -> ProviderOutcome:
        return ProviderOutcome(
            provider=self.name,
            accepted=False,
            executed=False,
            simulated=True,
            status="NOT_CONFIGURED",
            result_summary=f"{verb} is unavailable: {NOT_CONFIGURED_NOTE}",
            failure_reason=NOT_CONFIGURED_NOTE,
        )

    def preview_action(self, request: dict[str, Any]) -> ProviderOutcome:
        return self._refuse("Preview")

    def execute_action(self, request: dict[str, Any]) -> ProviderOutcome:
        return self._refuse("Execution")

    def rollback_action(self, request: dict[str, Any]) -> ProviderOutcome:
        return self._refuse("Rollback")

    def get_action_status(self, request: dict[str, Any]) -> ProviderOutcome:
        return self._refuse("Status")


# Explicit server-side allowlist. Clients cannot name, add, or extend a
# provider anywhere: the only accepted names are these keys, and the only
# ways to obtain one are PROVIDER_SELECTION (action type) and the
# RESPONSE_PROVIDER setting.
PROVIDERS: dict[str, ResponseProvider] = {
    MOCK_PROVIDER: MockResponseProvider(),
    NOT_CONFIGURED_PROVIDER: NotConfiguredProvider(),
}

# Static action-type -> provider selection. No API field influences this.
PROVIDER_SELECTION: dict[str, str] = {
    ACTION_BLOCK_INDICATOR: MOCK_PROVIDER,
    ACTION_DISABLE_INDICATOR_BLOCK: MOCK_PROVIDER,
    ACTION_ISOLATE_ENDPOINT: MOCK_PROVIDER,
    ACTION_RELEASE_ENDPOINT: MOCK_PROVIDER,
    ACTION_DISABLE_ACCOUNT: MOCK_PROVIDER,
    ACTION_ENABLE_ACCOUNT: MOCK_PROVIDER,
}

# Action types that reverse a previous defensive step. They are always
# the exact inverse of the matching forward action and are never allowed
# to be paired with a different target type.
ROLLBACK_ACTIONS = (
    ACTION_DISABLE_INDICATOR_BLOCK,
    ACTION_RELEASE_ENDPOINT,
    ACTION_ENABLE_ACCOUNT,
)

# Reverse action for each forward action, used to validate that a
# rollback request is asking for the correct inverse.
ROLLBACK_PAIRS: dict[str, str] = {
    ACTION_BLOCK_INDICATOR: ACTION_DISABLE_INDICATOR_BLOCK,
    ACTION_ISOLATE_ENDPOINT: ACTION_RELEASE_ENDPOINT,
    ACTION_DISABLE_ACCOUNT: ACTION_ENABLE_ACCOUNT,
}


def is_controlled_action(action_type: str) -> bool:
    """True only for the Step 30 controlled defensive action types."""
    return action_type in CONTROLLED_ACTION_TYPES


def allowed_target_types(action_type: str) -> tuple[str, ...]:
    """Target types an action may address (empty tuple for unknown actions)."""
    return ACTION_TARGET_TYPES.get(action_type, ())


def select_provider_name(action_type: str) -> str:
    """Registry name for an action type. Unknown types get NOT_CONFIGURED."""
    return PROVIDER_SELECTION.get(action_type, NOT_CONFIGURED_PROVIDER)


def get_provider(name: str) -> ResponseProvider:
    """Return an allowlisted provider or raise KeyError."""
    return PROVIDERS[name]


__all__ = [
    "ACTION_BLOCK_INDICATOR",
    "ACTION_DISABLE_ACCOUNT",
    "ACTION_DISABLE_INDICATOR_BLOCK",
    "ACTION_ENABLE_ACCOUNT",
    "ACTION_ISOLATE_ENDPOINT",
    "ACTION_RELEASE_ENDPOINT",
    "ACTION_TARGET_TYPES",
    "CONTROLLED_ACTION_TYPES",
    "CONTROLLED_TARGET_TYPES",
    "FAILURE_SENTINEL",
    "MOCK_PROVIDER",
    "NOT_CONFIGURED_NOTE",
    "NOT_CONFIGURED_PROVIDER",
    "PROVIDERS",
    "PROVIDER_CLOUD",
    "PROVIDER_DEFENDER",
    "PROVIDER_ENDPOINT_MANAGER",
    "PROVIDER_FIREWALL",
    "PROVIDER_SELECTION",
    "PROVIDER_WAZUH",
    "ROLLBACK_ACTIONS",
    "ROLLBACK_PAIRS",
    "TARGET_ENDPOINT",
    "TARGET_HASH",
    "TARGET_INDICATOR",
    "MockResponseProvider",
    "NotConfiguredProvider",
    "ProviderOutcome",
    "ProviderTargetRejected",
    "ResponseProvider",
    "allowed_target_types",
    "get_provider",
    "is_controlled_action",
    "select_provider_name",
]
