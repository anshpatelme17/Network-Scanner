"""Step 31: hardening indexes and audit request correlation.

Revision ID: step31_hardening
Revises: step30_controlled_response
Create Date: 2026-09-30

Additive and reversible. Two nullable ``request_id`` columns (incident
and response audit trails) plus eight indexes that back queries the
hardening review identified as unindexed:

* ``response_actions.expires_at`` — the Step 30 expiry sweep filters on
  ``status IN (...) AND expires_at IS NOT NULL AND expires_at <= now``
  and orders by ``expires_at``; it ran on every response list/detail
  read as an unindexed scan + sort.
* ``response_actions.provider`` / ``policy_decision`` — policy verdicts
  and provider reporting group by these.
* ``response_actions.target_reference`` — target lookups for a given
  incident.
* ``response_audit.request_id`` / ``incident_audits.request_id`` — request
  correlation lookups.
* ``response_audit.created_at`` — every audit read orders by
  ``created_at`` (id tiebreak).
* ``incident_audits.action`` / ``incident_audits.created_at`` — incident
  audit filtering and ordering.

No table is dropped, no existing column is narrowed or renamed, and no row
is rewritten. The ``downgrade`` removes only what this migration added, so
a rollback cannot lose audit history.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step31_hardening"
down_revision: str | None = "step30_controlled_response"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("response_audit", sa.Column("request_id", sa.String(64), nullable=True))
    op.add_column("incident_audits", sa.Column("request_id", sa.String(64), nullable=True))

    op.create_index("ix_response_audit_request_id", "response_audit", ["request_id"])
    op.create_index("ix_response_audit_created_at", "response_audit", ["created_at"])
    op.create_index("ix_incident_audits_request_id", "incident_audits", ["request_id"])
    op.create_index("ix_incident_audits_action", "incident_audits", ["action"])
    op.create_index("ix_incident_audits_created_at", "incident_audits", ["created_at"])
    op.create_index("ix_response_actions_expires_at", "response_actions", ["expires_at"])
    op.create_index("ix_response_actions_provider", "response_actions", ["provider"])
    op.create_index("ix_response_actions_policy_decision", "response_actions", ["policy_decision"])
    op.create_index(
        "ix_response_actions_target_reference", "response_actions", ["target_reference"]
    )


def downgrade() -> None:
    op.drop_index("ix_response_actions_target_reference", table_name="response_actions")
    op.drop_index("ix_response_actions_policy_decision", table_name="response_actions")
    op.drop_index("ix_response_actions_provider", table_name="response_actions")
    op.drop_index("ix_response_actions_expires_at", table_name="response_actions")
    op.drop_index("ix_incident_audits_created_at", table_name="incident_audits")
    op.drop_index("ix_incident_audits_action", table_name="incident_audits")
    op.drop_index("ix_incident_audits_request_id", table_name="incident_audits")
    op.drop_index("ix_response_audit_created_at", table_name="response_audit")
    op.drop_index("ix_response_audit_request_id", table_name="response_audit")
    op.drop_column("incident_audits", "request_id")
    op.drop_column("response_audit", "request_id")
