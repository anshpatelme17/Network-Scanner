"""Incident accountability query cost (Step 53).

Step 53 investigated the read queries behind the Phase 4 accountability
surfaces - the per-action audit feed, the incident timeline, and the
incident activity feed - looking for query-level inefficiencies that
could be removed without changing behaviour. The investigation found the
reads already index-backed and free of N+1, so no production change was
made; this module records the evidence and locks the good plans in, so a
future edit that drops an index or turns an indexed predicate into an
unindexed one fails loudly instead of silently degrading to a table scan.

Evidence (``EXPLAIN QUERY PLAN`` on the SQLite test engine), each read
filtered by the entity it is scoped to:

* ``GET /api/v1/incidents/{id}/activity`` filters ``response_audit`` by
  ``incident_id`` -> ``SEARCH response_audit USING INDEX
  ix_response_audit_incident_id`` (no scan); its ``COUNT`` uses the same
  index.
* ``GET /api/v2/responses/{action_id}/audit`` filters by ``action_id`` ->
  ``SEARCH response_audit USING INDEX ix_response_audit_action_id``.
* ``GET /api/v1/incidents/{id}/timeline`` incident-audit read filters
  ``incident_audits`` by ``incident_id`` -> ``SEARCH incident_audits USING
  INDEX ix_incident_audits_incident_id``.
* the timeline response-audit read applies the same ``incident_id``
  predicate -> ``SEARCH response_audit USING INDEX
  ix_response_audit_incident_id``.

Every one of these still asks SQLite for a ``TEMP B-TREE`` to satisfy
``ORDER BY created_at, id``. That sort is in-memory and bounded by the
rows matching a single incident or a single action - a handful of
lifecycle rows - so it is not meaningful work. Removing it would need
composite indexes ``(incident_id, created_at, id)`` and ``(action_id,
created_at, id)``, i.e. a schema migration; Step 53 is deliberately
query-level and the residual cost is negligible, so no index was added.

The reads are also already free of the usual mistakes: the response
action types are resolved with one batched ``IN`` (never one query per
row), pagination is one ``COUNT`` plus one bounded page query, and no
``ResponseAction``/``Incident`` relationship accessor is touched while
serialising, so there is no lazy-load N+1. The only loop that issues a
query per row is the bounded expiry sweep (``MAX_EXPIRY_SCAN``), which
the read endpoints deliberately never call.

Out of scope, noted for honesty: the incident *listing* orders by
``created_at`` with no supporting index and therefore scans ``incidents``.
Listing is not one of the accountability surfaces and a fix would be a
schema migration, so it is left unchanged.
"""

from __future__ import annotations

from sqlalchemy import desc, func, select, text

from app.database.session import get_engine
from app.models.incidents import IncidentAudit
from app.models.responses import ResponseAudit


def _plan(statement) -> str:
    engine = get_engine()
    sql = str(statement.compile(engine, compile_kwargs={"literal_binds": True}))
    with engine.connect() as connection:
        rows = connection.execute(text(f"EXPLAIN QUERY PLAN {sql}")).fetchall()
    return " | ".join(str(row[-1]) for row in rows)


def test_activity_read_uses_the_incident_index_without_a_scan(clean_db):
    plan = _plan(
        select(ResponseAudit)
        .where(ResponseAudit.incident_id == "inc-x")
        .order_by(ResponseAudit.created_at, ResponseAudit.id)
        .limit(50)
        .offset(0)
    )
    assert "SEARCH response_audit USING INDEX ix_response_audit_incident_id" in plan
    assert "SCAN response_audit" not in plan


def test_activity_count_uses_the_same_index(clean_db):
    plan = _plan(
        select(func.count(ResponseAudit.id)).where(ResponseAudit.incident_id == "inc-x")
    )
    assert "SEARCH response_audit USING INDEX ix_response_audit_incident_id" in plan
    assert "SCAN response_audit" not in plan


def test_v2_audit_read_uses_the_action_index_without_a_scan(clean_db):
    plan = _plan(
        select(ResponseAudit)
        .where(ResponseAudit.action_id == "act-x")
        .order_by(ResponseAudit.created_at, ResponseAudit.id)
        .limit(50)
        .offset(0)
    )
    assert "SEARCH response_audit USING INDEX ix_response_audit_action_id" in plan
    assert "SCAN response_audit" not in plan


def test_timeline_incident_audits_use_the_incident_index(clean_db):
    plan = _plan(
        select(IncidentAudit)
        .where(IncidentAudit.incident_id == "inc-x")
        .order_by(IncidentAudit.created_at, IncidentAudit.id)
    )
    assert "SEARCH incident_audits USING INDEX ix_incident_audits_incident_id" in plan
    assert "SCAN incident_audits" not in plan


def test_timeline_response_audits_use_the_incident_index(clean_db):
    plan = _plan(
        select(ResponseAudit)
        .where(ResponseAudit.incident_id == "inc-x")
        .order_by(desc(ResponseAudit.created_at), desc(ResponseAudit.id))
        .limit(200)
    )
    assert "SEARCH response_audit USING INDEX ix_response_audit_incident_id" in plan
    assert "SCAN response_audit" not in plan
