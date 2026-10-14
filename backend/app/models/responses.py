"""Response proposals and audit trail (Step 12, dry-run / approval only).

A ``ResponseAction`` is a *representation* of something an operator might
one day want to do — it is not an instruction to do it. There is no
executor in this codebase, no state that means "executed", and no code
path that touches any external system. Statuses:

    PROPOSED -> APPROVED | REJECTED | CANCELLED | DRY_RUN_COMPLETED
    DRY_RUN_COMPLETED -> APPROVED | REJECTED | CANCELLED
    APPROVED -> CANCELLED
    REJECTED, CANCELLED, EXPIRED -> (terminal)

``APPROVED`` means "approved for a future execution layer that does not
exist yet" — it must never be read or displayed as executed. ``EXPIRED``
is reserved for a future policy layer; nothing transitions to it
automatically because no background processes exist. ``dry_run`` is
always true; any attempt to create a non-dry-run proposal is rejected.

Identity is deterministic: ``sha256("response-action:v1" |
incident_id | action_type | target_type | target_reference |
requested_by)`` — replays return the existing row unchanged (never
resurrected, never duplicated).

``ResponseAudit`` appends one row per lifecycle event (proposed,
approved, rejected, cancelled, dry-run completed) with actor, status
transition, and policy version. Audit rows record platform-side
workflow only and never claim an external action occurred.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def _utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class ResponseAction(Base):
    __tablename__ = "response_actions"

    # Deterministic identity (see module docstring).
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(16), nullable=False)
    target_reference: Mapped[str] = mapped_column(String(256), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    requested_by: Mapped[str] = mapped_column(String(128), nullable=False)
    # String(32): must fit the longest lifecycle value, DRY_RUN_COMPLETED (17).
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PROPOSED", index=True)
    dry_run: Mapped[bool] = mapped_column(nullable=False, default=True)
    policy_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0.0")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now()
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    extra_metadata: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    # Set to "SIMULATED" once the simulation executor has run through the
    # execute endpoint. No other value is possible in Step 13: there is no
    # real-execution path, so this column can never claim one happened.
    execution_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Step 18 (additive): approval identity and safe-execution outcome.
    # approved_by is stamped once on approval and never rewritten (no
    # transition re-enters APPROVED). started_at/completed_at bound the
    # RUNNING window; result_summary/failure_reason record the honest
    # platform-side outcome of safe actions only.
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Step 30 (additive): controlled defensive-response governance. These
    # columns are populated only for Step 30 action types; every Step
    # 12/13/18/19 row keeps the defaults below, which are the honest
    # Step 12-19 posture (dry-run only, never approved for execution,
    # no rollback capability, no stored target proof).
    #
    # provider          - registry name chosen server-side; never supplied
    #                    by a client. "MOCK" records a platform-side
    #                    action; "NOT_CONFIGURED" refuses.
    # policy_decision   - one of response_governance.POLICY_DECISIONS.
    # approval_required - whether a second, distinct human must approve.
    # rollback_supported/rollback_state/rollback_reference - rollback is
    #                    only ever marked supported when the provider
    #                    actually returned prior-state information; it is
    #                    never guessed and never fabricated.
    # target_evidence   - JSON list of the stored incident event ids that
    #                    justify the target (server-derived, not client).
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="MOCK")
    policy_decision: Mapped[str] = mapped_column(String(32), nullable=False, default="DRY_RUN_ONLY")
    approval_required: Mapped[bool] = mapped_column(nullable=False, default=True)
    rollback_supported: Mapped[bool] = mapped_column(nullable=False, default=False)
    rollback_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    rollback_reference: Mapped[str | None] = mapped_column(String(128), nullable=True)
    target_evidence: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    audit: Mapped[list[ResponseAudit]] = relationship(
        "ResponseAudit",
        back_populates="action",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    rollbacks: Mapped[list[ResponseRollback]] = relationship(
        "ResponseRollback",
        back_populates="action",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class ResponseAudit(Base):
    __tablename__ = "response_audit"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    action_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("response_actions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    incident_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    previous_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    new_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0.0")
    # Client-side microsecond default (not server now()): audit order must
    # distinguish rapid successive events, which SQLite's second-precision
    # CURRENT_TIMESTAMP cannot. The migration keeps a server default only
    # as a fallback for non-ORM inserts.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, default=_utcnow_naive
    )

    action: Mapped[ResponseAction] = relationship("ResponseAction", back_populates="audit")
    # Step 31: correlation id of the request that produced this audit row,
    # so an approval/execution/rollback can be tied back to the HTTP
    # request and its server-side log line. Nullable because rows written
    # outside a request (bootstrap, tests, scripts) have none, and never
    # caller-supplied: it is the sanitised value from
    # app.core.request_context.
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # Step 41 (additive): optional operator-supplied reason for a rejection
    # decision. NULL for every other lifecycle event and for rows written
    # before this column existed. It never annotates the requester's
    # ``ResponseAction.reason``: that column keeps its own meaning, and the
    # approver's rationale lives here, on the append-only audit row it
    # belongs to. Sanitised (trimmed, bounded) by the governance service
    # before it is stored.
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)


class ResponseExecution(Base):
    """Persisted simulation result (Step 13).

    Exactly one row per response action (UNIQUE action_id). The row
    records what a simulation *would* have done: ``would_execute`` is
    always false and ``result`` is always ``"SIMULATED"``. Re-execution
    returns this stored row unchanged — the simulation is never re-run
    over live state because there is no live state to act on.
    """

    __tablename__ = "response_executions"

    # Deterministic identity: sha256("response-execution:v1" | action_id).
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    action_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("response_actions.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    incident_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    adapter: Mapped[str] = mapped_column(String(32), nullable=False, default="simulation")
    dry_run: Mapped[bool] = mapped_column(nullable=False, default=True)
    would_execute: Mapped[bool] = mapped_column(nullable=False, default=False)
    result: Mapped[str] = mapped_column(String(16), nullable=False, default="SIMULATED")
    explanation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    policy_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0.0")
    simulated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now()
    )


class ResponseRollback(Base):
    """Recorded rollback attempt for an executed response (Step 30).

    Exactly one row per action (UNIQUE action_id), created only when an
    authorized operator explicitly requests a rollback — never
    automatically, and never speculatively. ``result`` is one of
    ``COMPLETED`` / ``FAILED`` / ``UNSUPPORTED``: a provider that cannot
    supply prior-state information reports ``UNSUPPORTED`` with an
    honest explanation instead of fabricating a compensating action.
    """

    __tablename__ = "response_rollbacks"

    # Deterministic identity: sha256("response-rollback:v1" | action_id).
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    action_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("response_actions.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    incident_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="MOCK")
    result: Mapped[str] = mapped_column(String(16), nullable=False, default="UNSUPPORTED")
    explanation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    policy_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0.0")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now()
    )

    action: Mapped[ResponseAction] = relationship("ResponseAction", back_populates="rollbacks")
