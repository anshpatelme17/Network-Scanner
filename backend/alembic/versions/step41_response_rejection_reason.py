"""Step 41: optional rejection reason on the response audit trail.

Revision ID: step41_response_rejection_reason
Revises: phase2_risk_consistency
Create Date: 2026-10-11

Additive only: ``response_audit`` gains a nullable ``detail`` column, the
same column its four sibling audit tables (``incident_audits``,
``auth_audits``, ``event_audits``, ``correlation_audits``) have carried
since Step 17. It stores the operator-supplied reason recorded when a
consequential response request is rejected.

Existing rows keep NULL, so no historical audit row is rewritten and no
Step 12/13/18/19/30/40 semantics change. The append-only guard is
unaffected: it refuses UPDATE and DELETE, never INSERT, so a new row
with a populated ``detail`` persists exactly as any other audit row does.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step41_response_rejection_reason"
down_revision: str | None = "phase2_risk_consistency"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("response_audit", sa.Column("detail", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("response_audit", "detail")
