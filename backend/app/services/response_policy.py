"""Deterministic response policy (Steps 13 + 18, decisions only).

``evaluate_for_execution`` answers whether a stored proposal may proceed
to an executor. It is a pure function of the stored row:
no clock, no randomness, no network, no execution of any kind. Four
outcomes, all deterministic:

- ``ALLOW_SIMULATION`` — approved AND dry-run previewed
  (``DRY_RUN_COMPLETED``): simulation may run.
- ``ALLOW_SAFE_EXECUTION`` (Step 18) — a safe foundation action in
  ``APPROVED`` or ``DRY_RUN_COMPLETED``: the platform-record-only
  executor may run. Safe actions never touch external systems.
- ``REQUIRE_APPROVAL`` — ``PROPOSED`` (needs operator approval) or
  ``APPROVED`` (approved but not yet previewed): execution refused
  until the workflow advances.
- ``DENY`` — any other status, unknown action type, missing incident
  reference, or a non-dry-run proposal: execution refused.

``policy_version`` and the human-readable reason travel with every
decision and are persisted on denial/execution audit rows.
"""

from __future__ import annotations

from typing import Any

from app.models.responses import ResponseAction
from app.services.response_service import (
    ACTION_TYPES,
    POLICY_VERSION,
    STATUS_APPROVED,
    STATUS_DRY_RUN_COMPLETED,
    STATUS_PROPOSED,
    is_safe_action,
)

DECISION_ALLOW = "ALLOW_SIMULATION"
DECISION_ALLOW_SAFE = "ALLOW_SAFE_EXECUTION"
DECISION_REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
DECISION_DENY = "DENY"


def evaluate_for_execution(action: ResponseAction | None) -> dict[str, Any]:
    """Decide whether a stored proposal may run on the simulation executor."""
    if action is None:
        return {
            "decision": DECISION_DENY,
            "policy_version": POLICY_VERSION,
            "reason": "No such response proposal exists.",
        }
    if action.action_type not in ACTION_TYPES:
        return {
            "decision": DECISION_DENY,
            "policy_version": POLICY_VERSION,
            "reason": f"Action type is not allowlisted: {action.action_type}.",
        }
    if action.dry_run is not True:
        return {
            "decision": DECISION_DENY,
            "policy_version": POLICY_VERSION,
            "reason": "Only dry-run proposals may execute (simulation only).",
        }
    if is_safe_action(action.action_type):
        if action.status in (STATUS_APPROVED, STATUS_DRY_RUN_COMPLETED):
            return {
                "decision": DECISION_ALLOW_SAFE,
                "policy_version": POLICY_VERSION,
                "reason": (
                    "Approved safe foundation action; platform-record-only "
                    "execution permitted. No external change will occur."
                ),
            }
        if action.status == STATUS_PROPOSED:
            return {
                "decision": DECISION_REQUIRE_APPROVAL,
                "policy_version": POLICY_VERSION,
                "reason": "Operator approval is required.",
            }
        return {
            "decision": DECISION_DENY,
            "policy_version": POLICY_VERSION,
            "reason": f"Status {action.status} does not permit execution.",
        }
    if action.status == STATUS_DRY_RUN_COMPLETED:
        return {
            "decision": DECISION_ALLOW,
            "policy_version": POLICY_VERSION,
            "reason": "Approved and dry-run previewed; simulation permitted.",
        }
    if action.status in (STATUS_PROPOSED, STATUS_APPROVED):
        return {
            "decision": DECISION_REQUIRE_APPROVAL,
            "policy_version": POLICY_VERSION,
            "reason": (
                "Operator approval is required."
                if action.status == STATUS_PROPOSED
                else "Dry-run preview is required before execution."
            ),
        }
    return {
        "decision": DECISION_DENY,
        "policy_version": POLICY_VERSION,
        "reason": f"Status {action.status} does not permit execution.",
    }


__all__ = [
    "DECISION_ALLOW",
    "DECISION_ALLOW_SAFE",
    "DECISION_DENY",
    "DECISION_REQUIRE_APPROVAL",
    "evaluate_for_execution",
]
