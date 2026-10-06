"""Step 9: correlation records over normalized events.

Revision ID: step9_correlations
Revises: step3_security_events
Create Date: 2026-09-27

Creates ``correlations`` and ``correlation_evidence``. Correlation rows
carry deterministic application-assigned IDs (never database-generated
sequences that could diverge); evidence links are unique per
(correlation, event) so reprocessing can never duplicate links.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "step9_correlations"
down_revision: str | None = "step3_security_events"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "correlations",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("rule_id", sa.String(32), nullable=False),
        sa.Column("rule_name", sa.String(128), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("explanation", sa.Text(), nullable=False, server_default=""),
        sa.Column("primary_ip", sa.String(45), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("window_start", sa.DateTime(), nullable=False),
        sa.Column("window_end", sa.DateTime(), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    for name, columns in [
        ("ix_correlations_rule_id", ["rule_id"]),
        ("ix_correlations_status", ["status"]),
        ("ix_correlations_severity", ["severity"]),
        ("ix_correlations_primary_ip", ["primary_ip"]),
    ]:
        op.create_index(name, "correlations", columns)

    op.create_table(
        "correlation_evidence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "correlation_id",
            sa.String(64),
            sa.ForeignKey("correlations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "event_id",
            sa.String(36),
            sa.ForeignKey("security_events.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("role", sa.String(16), nullable=False, server_default="related"),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint("correlation_id", "event_id", name="uq_correlation_event"),
    )
    for name, columns in [
        ("ix_correlation_evidence_correlation_id", ["correlation_id"]),
        ("ix_correlation_evidence_event_id", ["event_id"]),
        ("ix_evidence_correlation_position", ["correlation_id", "position"]),
    ]:
        op.create_index(name, "correlation_evidence", columns)


def downgrade() -> None:
    op.drop_table("correlation_evidence")
    op.drop_table("correlations")
