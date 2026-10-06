"""Response executor interface (Steps 13 + 19, simulation only).

``ResponseExecutor.execute`` takes a stored proposal and returns a
result dict. The interface is intentionally narrow — action, no
credentials, no callbacks, no transport — so future trusted adapters
can implement it without widening what any executor is *able* to do.

Step 19 adds strongly typed Pydantic contracts (``AdapterRequest`` /
``AdapterResult`` in ``schemas.responses``) and an explicit
allow-listed registry of simulation-only adapters. Every registered
adapter is pure: no subprocesses, no sockets, no file or OS access, no
external calls of any kind. Each always reports ``executed: False`` /
``simulated: True`` with truthful simulation language. Future
real-action adapters are NOT registered here; nothing in this module —
or any caller — can select an executor by client input
(``get_executor`` raises ``KeyError`` for unknown names, and the server
selects adapters from a static action-type map only).

Only ``SimulationResponseExecutor`` ("simulation") existed in Step 13
and its wire shape is frozen by regression tests; the Step 19 registry
adds ``SIMULATION``, ``EVIDENCE_COLLECTION_SIMULATION``,
``FIREWALL_SIMULATION`` and ``ISOLATION_SIMULATION`` as distinct
simulation-only flavors. Firewall/isolation names describe the class of
integration they *would* preview — their implementations simulate and
never connect to Windows Defender Firewall, netsh, PowerShell,
iptables, nftables, endpoint APIs, or cloud security APIs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

from app.models.responses import ResponseAction
from app.schemas.responses import AdapterRequest, AdapterResult
from app.services.response_service import validate_target

SIMULATION_ADAPTER = "simulation"

# Step 19 registry names (all simulation-only; see module docstring).
ADAPTER_SIMULATION = "SIMULATION"
ADAPTER_EVIDENCE_COLLECTION = "EVIDENCE_COLLECTION_SIMULATION"
ADAPTER_FIREWALL = "FIREWALL_SIMULATION"
ADAPTER_ISOLATION = "ISOLATION_SIMULATION"

SIMULATION_ONLY_NOTE = "Simulation completed; no external system was modified."


class ResponseExecutor(ABC):
    """Interface every response executor must implement."""

    name: str = "base"

    @abstractmethod
    def execute(self, action: ResponseAction) -> dict[str, Any]:
        """Return a result dict for a stored proposal. Must not cause side effects."""


class SimulationAdapterBase(ResponseExecutor):
    """Shared pure-simulation behavior (Step 19).

    Subclasses differ only in registry name and truthful flavor text.
    ``describe`` is the typed pure core; ``execute`` preserves the
    frozen Step 13 wire shape for backward compatibility.
    """

    name = SIMULATION_ADAPTER
    # Flavor sentence naming what this adapter class simulates WITHOUT doing.
    flavor: str = "Action would be simulated only."

    def build_request(
        self, action: ResponseAction, adapter_name: str | None = None
    ) -> AdapterRequest:
        return AdapterRequest(
            adapter_type=adapter_name or self.name,
            action_type=getattr(action, "action_type", "UNKNOWN"),
            target_type=getattr(action, "target_type", "UNKNOWN"),
            target_reference=getattr(action, "target_reference", ""),
            incident_id=getattr(action, "incident_id", ""),
            response_id=getattr(action, "id", ""),
            dry_run=True,
            requested_by=getattr(action, "requested_by", "unknown"),
            approved_by=getattr(action, "approved_by", None),
            policy_version=getattr(action, "policy_version", "1.0.0"),
        )

    def describe(self, request: AdapterRequest, would_execute: bool) -> AdapterResult:
        """Pure typed simulation of a request. No side effects of any kind."""
        return AdapterResult(
            accepted=True,
            executed=False,
            simulated=True,
            status="SIMULATED",
            adapter_type=request.adapter_type,
            action_type=request.action_type,
            target=f"{request.target_type}:{request.target_reference}",
            started_at=None,
            completed_at=None,
            result_summary=f"{self.flavor} {SIMULATION_ONLY_NOTE}",
            failure_reason=None,
            evidence=[],
            would_execute=would_execute,
        )

    def validate_target(self, target_type: str, target_reference: str) -> None:
        """Strict target check via the shared Step 18/19 validator.

        Raises InvalidResponseError on malformed or unsupported targets.
        Never resolves hostnames, never opens connections.
        """
        validate_target(target_type, target_reference)

    def preview(self, request: AdapterRequest, would_execute: bool) -> AdapterResult:
        """Future-adapter contract: what would happen, without doing it.

        Simulation-only in Step 19 for every registered adapter.
        """
        return self.describe(request, would_execute)

    def execute(self, action: ResponseAction) -> dict[str, Any]:
        result = self.describe(self.build_request(action), would_execute=False)
        return {
            "action_id": action.id,
            "action_type": action.action_type,
            "target": f"{action.target_type}:{action.target_reference}",
            "dry_run": True,
            "would_execute": result.would_execute,
            "result": result.status,
            "explanation": result.result_summary,
            "adapter": self.name,
            "simulated_at": datetime.now(UTC).replace(tzinfo=None).isoformat(),
        }


class SimulationResponseExecutor(SimulationAdapterBase):
    """Deterministic simulation: describes, never performs."""

    name = SIMULATION_ADAPTER

    _EXPLANATIONS = {
        "ISOLATE_ASSET": "Action would request isolating the asset from the network.",
        "BLOCK_IP": "Action would request blocking the specified IP.",
        "BLOCK_DOMAIN": "Action would request blocking the specified domain.",
        "DISABLE_ACCOUNT": "Action would request disabling the specified account.",
        "QUARANTINE_ASSET": "Action would request quarantining the specified asset.",
        "FIREWALL_RULE": "Action would request creating the described firewall rule.",
        "REMEDIATION": "Action would request the described remediation steps.",
    }

    def describe(self, request: AdapterRequest, would_execute: bool) -> AdapterResult:
        base = super().describe(request, would_execute)
        explanation = self._EXPLANATIONS.get(request.action_type, "Action would be simulated only.")
        return base.model_copy(
            update={
                "result_summary": f"{explanation} No real action was executed. Simulation only."
            }
        )


class EvidenceCollectionSimulationAdapter(SimulationAdapterBase):
    """Simulated evidence-collection preview (Step 19, references only)."""

    name = ADAPTER_EVIDENCE_COLLECTION
    flavor = (
        "Evidence collection would gather stored references for review. "
        "No real evidence was collected from any external system."
    )


class GenericSimulationAdapter(SimulationAdapterBase):
    """Generic simulation flavor under the canonical SIMULATION name."""

    name = ADAPTER_SIMULATION
    flavor = "Action would be simulated only."


class FirewallSimulationAdapter(SimulationAdapterBase):
    """Simulated firewall-rule preview (Step 19, never applied).

    Names the firewall-rule class of integration for future contract
    discussions only. No rule is created, previewed against, or sent to
    any firewall product or API.
    """

    name = ADAPTER_FIREWALL
    flavor = (
        "A firewall rule change would be previewed here in a future stage. "
        "No firewall was contacted and no rule was created, modified, or applied."
    )


class IsolationSimulationAdapter(SimulationAdapterBase):
    """Simulated isolation preview (Step 19, never performed).

    Names the host-isolation class of integration for future contract
    discussions only. No host is isolated, quarantined, or contacted.
    """

    name = ADAPTER_ISOLATION
    flavor = (
        "Host isolation would be previewed here in a future stage. "
        "No host was isolated, quarantined, shut down, or contacted."
    )


# Explicit allowlist. The server always selects from this map via
# select_adapter_name(); clients cannot name an adapter anywhere.
EXECUTORS: dict[str, ResponseExecutor] = {
    SIMULATION_ADAPTER: SimulationResponseExecutor(),
    ADAPTER_SIMULATION: GenericSimulationAdapter(),
    ADAPTER_EVIDENCE_COLLECTION: EvidenceCollectionSimulationAdapter(),
    ADAPTER_FIREWALL: FirewallSimulationAdapter(),
    ADAPTER_ISOLATION: IsolationSimulationAdapter(),
}

# Static action-type -> adapter selection (Step 19). Server-side only;
# there is no API field that influences this mapping.
ADAPTER_SELECTION: dict[str, str] = {
    "BLOCK_IP": ADAPTER_FIREWALL,
    "BLOCK_DOMAIN": ADAPTER_FIREWALL,
    "FIREWALL_RULE": ADAPTER_FIREWALL,
    "ISOLATE_ASSET": ADAPTER_ISOLATION,
    "QUARANTINE_ASSET": ADAPTER_ISOLATION,
    "COLLECT_EVIDENCE": ADAPTER_EVIDENCE_COLLECTION,
}


def select_adapter_name(action_type: str) -> str:
    """Return the registry name for an action type (static map, Step 19).

    Unknown action types fall back to generic SIMULATION so previews
    stay truthful; unknown ADAPTER names are still rejected by
    get_executor.
    """
    return ADAPTER_SELECTION.get(action_type, ADAPTER_SIMULATION)


def get_executor(name: str) -> ResponseExecutor:
    """Return an allowlisted executor or raise KeyError."""
    return EXECUTORS[name]


__all__ = [
    "ADAPTER_EVIDENCE_COLLECTION",
    "ADAPTER_FIREWALL",
    "ADAPTER_ISOLATION",
    "ADAPTER_SELECTION",
    "ADAPTER_SIMULATION",
    "EXECUTORS",
    "SIMULATION_ADAPTER",
    "SIMULATION_ONLY_NOTE",
    "EvidenceCollectionSimulationAdapter",
    "FirewallSimulationAdapter",
    "GenericSimulationAdapter",
    "IsolationSimulationAdapter",
    "ResponseExecutor",
    "SimulationAdapterBase",
    "SimulationResponseExecutor",
    "get_executor",
    "select_adapter_name",
]
