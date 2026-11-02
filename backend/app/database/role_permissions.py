"""Reviewed PostgreSQL runtime grants for application tables.

The bootstrap SQL applies this matrix to the existing schema. Every future
Alembic revision that creates a table must call ``runtime_grant_sql`` in that
revision; defaults intentionally grant no runtime table or sequence rights.
"""

from __future__ import annotations

RUNTIME_TABLE_PRIVILEGES: dict[str, tuple[str, ...]] = {
    "assets": ("SELECT", "INSERT", "UPDATE"),
    "discovered_services": ("SELECT", "INSERT", "DELETE"),
    "scan_jobs": ("SELECT", "INSERT", "UPDATE"),
    "scan_audit": ("SELECT", "INSERT"),
    "security_events": ("SELECT", "INSERT", "UPDATE"),
    "event_audits": ("SELECT", "INSERT"),
    "correlations": ("SELECT", "INSERT", "UPDATE"),
    "correlation_evidence": ("SELECT", "INSERT", "UPDATE"),
    "correlation_audits": ("SELECT", "INSERT"),
    "risk_assessments": ("SELECT", "INSERT", "UPDATE", "DELETE"),
    "risk_audits": ("SELECT", "INSERT"),
    "incidents": ("SELECT", "INSERT", "UPDATE"),
    "incident_audits": ("SELECT", "INSERT"),
    "incident_evidence": ("SELECT", "INSERT"),
    "incident_relationships": ("SELECT", "INSERT", "UPDATE", "DELETE"),
    "response_actions": ("SELECT", "INSERT", "UPDATE"),
    "response_audit": ("SELECT", "INSERT"),
    "response_executions": ("SELECT", "INSERT"),
    "response_rollbacks": ("SELECT", "INSERT"),
    "users": ("SELECT", "INSERT", "UPDATE"),
    "revoked_tokens": ("SELECT", "INSERT"),
    "auth_audits": ("SELECT", "INSERT"),
    "vulnerabilities": ("SELECT", "INSERT", "UPDATE"),
    "vulnerability_audits": ("SELECT", "INSERT"),
    "ingestion_checkpoints": ("SELECT", "INSERT", "UPDATE"),
}


def runtime_grant_sql(table_name: str) -> str:
    """Return the reviewed table grant for a future migration.

    Unknown tables fail closed. Table names are selected from the fixed map,
    never interpolated from migration input.
    """
    try:
        privileges = RUNTIME_TABLE_PRIVILEGES[table_name]
    except KeyError:
        raise ValueError("No reviewed runtime grant exists for this table.") from None
    privilege_list = ", ".join(privileges)
    return f"GRANT {privilege_list} ON TABLE public.{table_name} TO sec_runtime"
