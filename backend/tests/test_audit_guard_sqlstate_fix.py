"""The SQLSTATE fix for the database append-only guard, and what it guarantees.

Two halves, deliberately separated:

* **Always runs.** The revision's own contract: it chains onto Step 12, replaces
  only the function body, keeps ``restrict_violation``, and turns ``%`` into a
  real ``%s`` conversion. Step 12's migration is left exactly as applied, and a
  test says so.
* **Runs only against a real server.** The behaviour that matters: an
  ``UPDATE`` and a ``DELETE`` of an audit row are both refused with SQLSTATE
  23001, the message names the table and the refused operation, and an
  ``INSERT`` is still accepted. These skip when no PostgreSQL is reachable
  rather than passing on the strength of an absent server.
"""

import importlib.util
import os
import re
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
VERSIONS = BACKEND_ROOT / "alembic" / "versions"
FIX_PATH = VERSIONS / "phase2_step12_guard_sqlstate_fix.py"
STEP12_PATH = VERSIONS / "phase2_step12_audit_immutability.py"

LIVE_DATABASE_URL = os.getenv("VERIFY_RUNTIME_DATABASE_URL")


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fix = _load(FIX_PATH, "p2s12_sqlstate_fix")
step12 = _load(STEP12_PATH, "p2s12_original")


def _guard_body(ddl: str) -> str:
    return ddl.split("$audit_append_only$")[1]


# ---------------------------------------------------------------------------
# Revision graph
# ---------------------------------------------------------------------------


def test_the_fix_chains_onto_step12():
    assert fix.down_revision == step12.revision


def test_the_chain_stays_linear_and_single_headed():
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    script = ScriptDirectory.from_config(config)

    assert len(script.get_heads()) == 1
    ancestry: set[str] = set()
    cursor = script.get_heads()[0]
    while cursor is not None:
        ancestry.add(cursor)
        revision = script.get_revision(cursor)
        cursor = revision.down_revision if revision is not None else None
    assert {step12.revision, fix.revision} <= ancestry


def test_step12_was_not_rewritten():
    """An applied migration is history; the repair goes forward, not backwards."""
    source = STEP12_PATH.read_text(encoding="utf-8")
    assert "% is append-only" in source
    # The broken template appears exactly once in Step 12: in the body it
    # installs. Touching it would make the recorded history disagree with the
    # database it claims to describe.
    assert source.count("% is append-only") == 1
    assert "%s is append-only" not in source
    # The same broken text is reproduced here only so `downgrade()` can put it
    # back, and it is exactly the template Step 12 installed.
    installed = step12.build_upgrade_statements("postgresql")[0]
    template = re.search(r"'audit_append_only:[^']*'", installed).group(0)
    assert template == f"'{fix.PREVIOUS_MESSAGE_TEMPLATE}'"


# ---------------------------------------------------------------------------
# The defect and its repair
# ---------------------------------------------------------------------------


def test_the_bare_percent_is_what_breaks_postgres():
    """`%` plus a space is not a conversion specification.

    Stated as a property of the template rather than of PostgreSQL's error
    text, so the test keeps its meaning if the wording changes.
    """
    broken = fix.PREVIOUS_MESSAGE_TEMPLATE
    assert "% is" in broken
    # Every `%` in the broken template is followed by a space.
    percent_positions = [i for i, ch in enumerate(broken) if ch == "%"]
    assert percent_positions
    assert all(broken[i + 1] == " " for i in percent_positions)


def test_the_fixed_template_uses_real_conversion_specifications():
    template = fix.MESSAGE_TEMPLATE
    assert "% is" not in template
    directives = re.findall(r"%(.)", template)
    assert set(directives) == {"s"}
    assert template.count("%s") == 2


def test_upgrade_installs_the_fixed_body():
    (statement,) = fix.build_upgrade_statements("postgresql")
    assert statement.startswith(f"CREATE OR REPLACE FUNCTION {fix.GUARD_FUNCTION}()")
    assert fix.MESSAGE_TEMPLATE in statement
    assert fix.PREVIOUS_MESSAGE_TEMPLATE not in statement


def test_downgrade_restores_the_previous_body_exactly():
    (statement,) = fix.build_downgrade_statements("postgresql")
    assert fix.PREVIOUS_MESSAGE_TEMPLATE in statement


def test_the_guard_keeps_restrict_violation_in_both_directions():
    for builder in (fix.build_upgrade_statements, fix.build_downgrade_statements):
        (statement,) = builder("postgresql")
        assert "ERRCODE = 'restrict_violation'" in statement
    assert fix.RESTRICT_VIOLATION == "restrict_violation"


def test_restrict_violation_is_condition_name_23001():
    """The SQLSTATE this must produce, per PostgreSQL's Appendix A error codes."""
    try:
        from psycopg import errors as pg_errors
    except ImportError:
        pytest.skip("psycopg not installed")
    assert pg_errors.RestrictViolation.sqlstate == "23001"


def test_only_the_function_body_changes():
    """No table DDL: the triggers already point at this function name."""
    upgrade = fix.build_upgrade_statements("postgresql")
    downgrade = fix.build_downgrade_statements("postgresql")
    for statement in (*upgrade, *downgrade):
        assert statement.lstrip().upper().startswith("CREATE OR REPLACE FUNCTION")
        for forbidden in ("CREATE TRIGGER", "DROP TRIGGER", "ALTER TABLE", "DROP TABLE"):
            assert forbidden not in statement.upper()


def test_the_triggers_still_block_update_and_delete_and_not_insert():
    """The fix must not have disturbed Step 12's enforcement shape."""
    triggers = [
        s for s in step12.build_upgrade_statements("postgresql") if s.startswith("CREATE TRIGGER")
    ]
    assert len(triggers) == 8
    for statement in triggers:
        assert "BEFORE UPDATE OR DELETE" in statement
        assert "INSERT" not in statement.upper()
        assert f"EXECUTE FUNCTION {fix.GUARD_FUNCTION}()" in statement


@pytest.mark.parametrize("dialect", ["sqlite", "mysql", "mssql"])
def test_both_directions_are_a_noop_on_unsupported_dialects(dialect):
    assert fix.build_upgrade_statements(dialect) == ()
    assert fix.build_downgrade_statements(dialect) == ()


# ---------------------------------------------------------------------------
# Executed against a real PostgreSQL
# ---------------------------------------------------------------------------


@pytest.fixture()
def live():
    if not LIVE_DATABASE_URL:
        pytest.skip("VERIFY_RUNTIME_DATABASE_URL is not set; no server to test against")
    try:
        import psycopg
    except ImportError:
        pytest.skip("psycopg not installed")
    try:
        connection = psycopg.connect(LIVE_DATABASE_URL, autocommit=True)
    except Exception as exc:  # noqa: BLE001 - a URL can be set with nothing listening
        pytest.skip(f"PostgreSQL is not reachable: {str(exc).splitlines()[0][:100]}")
    try:
        yield connection
    finally:
        connection.close()


def _install(connection):
    for statement in fix.build_upgrade_statements("postgresql"):
        connection.execute(statement)


def _audit_columns(cursor, table):
    cursor.execute(
        """
        SELECT a.attname
        FROM pg_attribute a
        WHERE a.attrelid = %s::regclass AND a.attnum > 0 AND NOT a.attisdropped
        """,
        (table,),
    )
    return [row[0] for row in cursor.fetchall()]


def test_update_is_refused_with_23001_on_every_audit_table(live):
    _install(live)
    for table in step12.AUDIT_TABLES:
        columns = _audit_columns(live.cursor(), table)
        assert columns, table
        target = columns[0]
        with pytest.raises(Exception) as raised:
            live.execute(f"UPDATE {table} SET {target} = {target}")
        assert raised.value.sqlstate == "23001", f"{table}: {raised.value}"


def test_delete_is_refused_with_23001_on_every_audit_table(live):
    _install(live)
    for table in step12.AUDIT_TABLES:
        with pytest.raises(Exception) as raised:
            live.execute(f"DELETE FROM {table}")
        assert raised.value.sqlstate == "23001", f"{table}: {raised.value}"


def test_the_refusal_names_the_table_and_the_operation(live):
    _install(live)
    for operation, statement in (
        ("UPDATE", "UPDATE auth_audits SET id = id"),
        ("DELETE", "DELETE FROM auth_audits"),
    ):
        with pytest.raises(Exception) as raised:
            live.execute(statement)
        message = str(raised.value)
        assert "auth_audits" in message, operation
        assert operation in message, operation
        assert "append-only" in message, operation


#: Parent rows needed before an audit row can reference them. The audit tables
#: carry foreign keys onto live domain tables, and those constraints are not
#: deferrable, so an INSERT probe has to satisfy them or it proves nothing
#: about the guard. Ordered parents-first; every row is rolled back.
PARENT_ROWS = (
    "INSERT INTO assets (id, ip_address) VALUES ('step13-asset', '203.0.113.7')",
    "INSERT INTO correlations (id, rule_id, rule_name, title, severity, window_start, window_end)"
    " VALUES ('step13-corr', 'step13', 'step13-rule', 'step13', 'LOW',"
    " '2026-01-01 00:00:00', '2026-01-01 00:05:00')",
    "INSERT INTO risk_assessments (id, entity_type, entity_id, score, severity, scoring_version)"
    " VALUES ('step13-risk', 'asset', 'step13-asset', 1, 'LOW', '1.0.0')",
    "INSERT INTO discovered_services (id, asset_id, port)"
    " VALUES ('step13-svc', 'step13-asset', 443)",
    "INSERT INTO security_events (id, event_time, source_type, source_name, event_type,"
    " severity, title, fingerprint)"
    " VALUES ('step13-event', '2026-01-01 00:00:00', 'step13', 'step13', 'probe',"
    " 'LOW', 'step13', 'step13-fingerprint')",
    "INSERT INTO incidents (id, incident_key, title, severity, correlation_id, first_seen,"
    " last_seen)"
    " VALUES ('step13-inc', 'step13', 'step13', 'LOW', 'step13-corr',"
    " '2026-01-01 00:00:00', '2026-01-01 00:00:00')",
    "INSERT INTO response_actions (id, incident_id, action_type, target_type, target_reference,"
    " reason, requested_by)"
    " VALUES ('step13-action', 'step13-inc', 'REVIEW', 'asset', 'step13-asset',"
    " 'step13', 'step13')",
    "INSERT INTO scan_jobs (id, target, profile) VALUES ('step13-scan', 'step13-asset', 'step13')",
    "INSERT INTO vulnerabilities (id, asset_id, scanner, scanner_finding_id, title, severity)"
    " VALUES ('step13-vuln', 'step13-asset', 'step13', 'step13', 'step13', 'LOW')",
)

#: One INSERT per audit table, referencing the parents above.
INSERT_PROBES = {
    "auth_audits": "INSERT INTO auth_audits (id, event) VALUES ('step13', 'probe')",
    "correlation_audits": (
        "INSERT INTO correlation_audits (id, correlation_id, action, actor)"
        " VALUES ('step13', 'step13-corr', 'probe', 'step13')"
    ),
    "event_audits": (
        "INSERT INTO event_audits (id, event_id, action, actor)"
        " VALUES ('step13', 'step13-event', 'probe', 'step13')"
    ),
    "incident_audits": (
        "INSERT INTO incident_audits (id, incident_id, action, actor)"
        " VALUES ('step13', 'step13-inc', 'probe', 'step13')"
    ),
    "response_audit": (
        "INSERT INTO response_audit"
        " (id, action_id, incident_id, event, actor, policy_version)"
        " VALUES ('step13', 'step13-action', 'step13-inc', 'probe', 'step13', '1.0.0')"
    ),
    "risk_audits": (
        "INSERT INTO risk_audits"
        " (id, assessment_id, actor, new_score, classification)"
        " VALUES ('step13', 'step13-risk', 'step13', 1, 'LOW')"
    ),
    "scan_audit": (
        "INSERT INTO scan_audit (id, scan_id, event, actor)"
        " VALUES ('step13', 'step13-scan', 'probe', 'step13')"
    ),
    "vulnerability_audits": (
        "INSERT INTO vulnerability_audits"
        " (id, vulnerability_id, event, actor)"
        " VALUES ('step13', 'step13-vuln', 'probe', 'step13')"
    ),
}


def _seeded_inserts(live):
    """Insert every parent row, then every audit row, in one transaction."""
    for statement in PARENT_ROWS:
        live.execute(statement)
    for table, statement in INSERT_PROBES.items():
        live.execute(statement)
        with live.cursor() as cursor:
            cursor.execute(f"SELECT count(*) FROM {table} WHERE id = 'step13'")
            assert cursor.fetchone()[0] == 1, table


def test_insert_is_still_accepted_on_every_audit_table(live):
    """The guard fires only for UPDATE/DELETE; recording must be untouched.

    Everything runs inside a transaction that is rolled back, so an append-only
    table this test cannot clean up is not left holding a test row.
    """
    _install(live)
    assert set(INSERT_PROBES) == set(step12.AUDIT_TABLES)
    live.autocommit = False
    try:
        _seeded_inserts(live)
    except Exception as exc:  # noqa: BLE001
        live.rollback()
        live.autocommit = True
        pytest.fail(f"an audit INSERT was refused: {exc}")
    else:
        live.rollback()
    finally:
        live.autocommit = True


def test_no_probe_row_survives_the_rolled_back_insert(live):
    """Proof the INSERT probe really was discarded, not merely undone later."""
    _install(live)
    live.autocommit = False
    try:
        _seeded_inserts(live)
    finally:
        live.rollback()
        live.autocommit = True
    for table in step12.AUDIT_TABLES:
        with live.cursor() as cursor:
            cursor.execute(f"SELECT count(*) FROM {table} WHERE id = 'step13'")
            assert cursor.fetchone()[0] == 0, table


def test_the_insert_refusal_check_does_not_depend_on_the_database_being_empty(live):
    """The parents above are ordinary rows, so INSERT is proven on a live DB."""
    with live.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM auth_audits")
        assert cursor.fetchone()[0] > 0, "the probe would be vacuous on an empty table"


def test_the_previous_body_really_did_fail_with_22023(live):
    """Why the fix exists, proven rather than asserted in a comment.

    Installing the old body must reproduce the wrong SQLSTATE. Without this the
    migration could be 'fixing' a defect that never occurred.
    """
    for statement in fix.build_downgrade_statements("postgresql"):
        live.execute(statement)
    try:
        with pytest.raises(Exception) as raised:
            live.execute("DELETE FROM auth_audits")
        assert raised.value.sqlstate == "22023"
        assert "format()" in str(raised.value)
    finally:
        _install(live)
    with pytest.raises(Exception) as raised:
        live.execute("DELETE FROM auth_audits")
    assert raised.value.sqlstate == "23001"
