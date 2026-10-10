"""Phase 2 risk consistency: align every incident's risk snapshot.

Revision ID: phase2_risk_consistency
Revises: phase2_step12_guard_sqlstate_fix
Create Date: 2026-10-09

``RiskAssessment`` is the authoritative risk record; ``Incident.risk_score``
and ``Incident.risk_assessment_id`` are a denormalized compatibility mirror.
Two earlier behaviours let that mirror drift:

* ``recompute_risk`` and ``calculate_incident_risk`` wrote the assessment but
  never refreshed the incident, so an incident scored before a source change
  kept a stale ``risk_score``;
* the ``risk_assessment_id`` foreign key is ``ON DELETE SET NULL``, so deleting
  an assessment nulled the link but left the old score behind.

The service paths are fixed forward; this revision repairs the rows already
stored, deterministically and idempotently:

1. the incident's own current-version assessment exists -> point at it and copy
   its score (the desired steady state);
2. otherwise the linked assessment still exists -> keep the link, copy *its*
   score (corrects a stale snapshot);
3. otherwise -> clear both columns, so a score can never outlive its
   assessment. A cleared snapshot is distinguishable from a valid assessment
   whose score is ``0``.

``downgrade()`` is a deliberate no-op: the columns predate this revision, and
there is no single prior value to restore once rows have been reconciled. The
identity hash is frozen here rather than imported from ``risk_service`` so a
future version bump cannot retroactively change what this migration computes.

Design notes:

* **Both dialects.** Pure ``SELECT``/``UPDATE``; no DDL, no dialect-specific
  SQL, so the SQLite ``upgrade head`` in the Step 12 verification and a real
  PostgreSQL install both succeed.
* **Idempotent.** Re-running reads current state and rewrites the same
  deterministic target; there is nothing to double-apply.
* **Bounded memory.** ``executemany`` per incident; no ORM, no sessions.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "phase2_risk_consistency"
down_revision: str | None = "phase2_step12_guard_sqlstate_fix"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Frozen copies of the identity inputs as of this revision (see module note).
IDENTITY_NAMESPACE = "risk-assessment:v1"
SCORING_VERSION = "1.0.0"
ENTITY_INCIDENT = "incident"

_INCIDENTS_SQL = "SELECT id, risk_assessment_id FROM incidents"
_ASSESSMENTS_SQL = "SELECT id, score FROM risk_assessments"
_UPDATE_SQL = (
    "UPDATE incidents SET risk_assessment_id = :assessment_id, risk_score = :score "
    "WHERE id = :incident_id"
)


def own_assessment_id(incident_id: str, version: str = SCORING_VERSION) -> str:
    """The incident's current-version assessment id, exactly as the service computes it."""
    canonical = json.dumps(
        [IDENTITY_NAMESPACE, version, ENTITY_INCIDENT, incident_id], separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def decide_snapshot(
    incident_id: str,
    linked_id: str | None,
    assessments: dict[str, int],
    version: str = SCORING_VERSION,
) -> tuple[str | None, int | None]:
    """Pure: the reconciled ``(risk_assessment_id, risk_score)`` for one incident."""
    own_id = own_assessment_id(incident_id, version)
    if own_id in assessments:
        return own_id, int(assessments[own_id])
    if linked_id is not None and linked_id in assessments:
        return linked_id, int(assessments[linked_id])
    return None, None


def build_backfill(
    incidents: list[tuple[str, str | None]],
    assessments: dict[str, int],
    version: str = SCORING_VERSION,
) -> list[dict[str, object]]:
    """Pure: the ``executemany`` parameter sets for the reconciliation."""
    return [
        {
            "assessment_id": snapshot_id,
            "score": score,
            "incident_id": incident_id,
        }
        for incident_id, linked_id in incidents
        for snapshot_id, score in [decide_snapshot(incident_id, linked_id, assessments, version)]
    ]


def upgrade() -> None:
    bind = op.get_bind()
    assessments = {
        str(row.id): int(row.score) for row in bind.execute(sa.text(_ASSESSMENTS_SQL))
    }
    incidents = [
        (str(row.id), None if row.risk_assessment_id is None else str(row.risk_assessment_id))
        for row in bind.execute(sa.text(_INCIDENTS_SQL))
    ]
    params = build_backfill(incidents, assessments)
    if params:
        bind.execute(sa.text(_UPDATE_SQL), params)


def downgrade() -> None:
    """No-op: the columns predate this revision and the data is reconciled, not added."""
