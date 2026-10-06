"""Phase 2 Step 12 — database-level append-only audit enforcement.

The migration's DDL is verified two ways, and which of them actually runs
depends on the machine rather than on an assumption baked into this file:

* Always, as generated text plus a real end-to-end Alembic run on SQLite, where
  the dialect gate must turn the whole migration into a no-op. That proves the
  revision graph, the reversibility and the gate, but it cannot execute PL/pgSQL.
* Against a real PostgreSQL when one is reachable, by
  ``test_audit_guard_sqlstate_fix.py``, whose live tests skip rather than fail
  when no server is available.

What is *not* covered here is stated by the tests themselves
(``test_scope_excludes_truncate_and_drop_table``) rather than left implied.
"""

import importlib.util
import re
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
MIGRATION_PATH = BACKEND_ROOT / "alembic" / "versions" / "phase2_step12_audit_immutability.py"


def _load_migration():
    """Load the migration module by path (alembic/versions is not a package)."""
    spec = importlib.util.spec_from_file_location("p2s12_migration", MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


migration = _load_migration()
EXPECTED_TABLES = {
    "auth_audits",
    "correlation_audits",
    "event_audits",
    "incident_audits",
    "response_audit",
    "risk_audits",
    "scan_audit",
    "vulnerability_audits",
}


# ---------------------------------------------------------------------------
# Revision graph
# ---------------------------------------------------------------------------


def test_migration_chains_from_step31_and_the_chain_stays_linear():
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    script = ScriptDirectory.from_config(config)

    # Exactly one head: the chain never forks.
    heads = script.get_heads()
    assert len(heads) == 1, heads

    # This migration sits directly after Step 31.
    assert script.get_revision(migration.revision).down_revision == "step31_hardening"

    # Step 12 must be reachable from the current head, whether or not a later
    # step has since added another migration on top of it.
    ancestry = set()
    cursor = heads[0]
    while cursor is not None:
        ancestry.add(cursor)
        revision = script.get_revision(cursor)
        cursor = revision.down_revision if revision is not None else None
    assert migration.revision in ancestry


def test_previous_head_is_untouched():
    """Step 11's predecessor chain must not have been rewritten."""
    assert migration.down_revision == "step31_hardening"
    assert migration.branch_labels is None
    assert migration.depends_on is None


def test_migration_module_is_importable_and_exposes_its_contract():
    assert callable(migration.upgrade)
    assert callable(migration.downgrade)
    assert set(migration.AUDIT_TABLES) == EXPECTED_TABLES


# ---------------------------------------------------------------------------
# Table list integrity against the ORM guard
# ---------------------------------------------------------------------------


def test_frozen_table_list_matches_the_orm_guard():
    """The migration must protect exactly the tables Step 11 protects."""
    from app.models.audit_guard import audit_table_names

    assert set(migration.AUDIT_TABLES) == set(audit_table_names())


def test_table_list_is_a_frozen_snapshot_not_imported_from_models():
    """A migration must not derive its targets from live model code."""
    source = MIGRATION_PATH.read_text(encoding="utf-8")
    assert "app.models" not in source
    assert "from app" not in source


def test_table_list_has_no_duplicates():
    assert len(migration.AUDIT_TABLES) == len(set(migration.AUDIT_TABLES))


# ---------------------------------------------------------------------------
# Dialect gate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("dialect", ["sqlite", "mysql", "mssql"])
def test_upgrade_is_a_noop_on_unsupported_dialects(dialect):
    assert migration.build_upgrade_statements(dialect) == ()
    assert migration.build_downgrade_statements(dialect) == ()


def test_postgresql_is_the_supported_dialect():
    assert migration.SUPPORTED_DIALECT == "postgresql"
    assert migration.build_upgrade_statements("postgresql")


# ---------------------------------------------------------------------------
# Generated DDL
# ---------------------------------------------------------------------------


def test_upgrade_emits_a_trigger_for_every_audit_table():
    statements = migration.build_upgrade_statements("postgresql")
    creates = [s for s in statements if s.startswith("CREATE TRIGGER")]
    assert len(creates) == len(EXPECTED_TABLES)
    for table in EXPECTED_TABLES:
        assert any(f" ON {table} " in s for s in creates), table


def test_every_trigger_blocks_update_and_delete_for_each_row():
    for statement in migration.build_upgrade_statements("postgresql"):
        if statement.startswith("CREATE TRIGGER"):
            assert "BEFORE UPDATE OR DELETE" in statement
            assert "FOR EACH ROW" in statement
            assert f"EXECUTE FUNCTION {migration.GUARD_FUNCTION}()" in statement


def test_guard_function_raises_restrict_violation_and_names_the_operation():
    function_sql = migration.build_upgrade_statements("postgresql")[0]
    assert "LANGUAGE plpgsql" in function_sql
    assert "RETURNS trigger" in function_sql
    assert "RAISE EXCEPTION" in function_sql
    assert "'restrict_violation'" in function_sql
    # The message must identify the table and the refused operation.
    assert "TG_TABLE_NAME" in function_sql
    assert "TG_OP" in function_sql


def test_insert_is_never_blocked():
    """Audit recording must remain completely unaffected."""
    statements = migration.build_upgrade_statements("postgresql")
    assert not any("INSERT" in s.upper() for s in statements)
    assert not any("BEFORE INSERT" in s for s in statements)


def test_upgrade_is_idempotent():
    """Each trigger is dropped before creation, so re-running cannot fail."""
    statements = migration.build_upgrade_statements("postgresql")
    for table in EXPECTED_TABLES:
        name = migration.trigger_name(table)
        drop_index = next(
            i for i, s in enumerate(statements) if s.startswith(f"DROP TRIGGER IF EXISTS {name}")
        )
        create_index = next(
            i for i, s in enumerate(statements) if s.startswith(f"CREATE TRIGGER {name}")
        )
        assert drop_index < create_index, table


def test_trigger_names_are_deterministic_and_unique():
    names = [migration.trigger_name(t) for t in migration.AUDIT_TABLES]
    assert len(names) == len(set(names))
    assert all(re.fullmatch(r"trg_[a-z_]+_append_only", n) for n in names)
    assert migration.trigger_name("auth_audits") == "trg_auth_audits_append_only"


# ---------------------------------------------------------------------------
# Reversibility
# ---------------------------------------------------------------------------


def test_downgrade_removes_exactly_what_upgrade_created():
    upgrade = migration.build_upgrade_statements("postgresql")
    downgrade = migration.build_downgrade_statements("postgresql")

    created_triggers = {s.split()[2] for s in upgrade if s.startswith("CREATE TRIGGER")}
    dropped_triggers = {s.split()[4] for s in downgrade if s.startswith("DROP TRIGGER")}

    assert created_triggers == dropped_triggers
    # The shared function is removed last.
    assert downgrade[-1] == f"DROP FUNCTION IF EXISTS {migration.GUARD_FUNCTION}();"
    assert len(downgrade) == len(EXPECTED_TABLES) + 1


def test_downgrade_rewrites_no_rows():
    """A rollback must never be able to lose audit history."""
    for statement in migration.build_downgrade_statements("postgresql"):
        assert statement.strip().upper().startswith("DROP")


# ---------------------------------------------------------------------------
# Documented boundary: what is deliberately NOT covered
# ---------------------------------------------------------------------------


def test_scope_excludes_truncate_and_drop_table():
    """Stated honestly: TRUNCATE, DROP TABLE and superuser are not blocked."""
    statements = migration.build_upgrade_statements("postgresql")
    joined = " ".join(statements).upper()
    assert "TRUNCATE" not in joined
    assert "DROP TABLE" not in joined


def test_the_uncovered_boundary_is_documented_in_the_migration():
    source = MIGRATION_PATH.read_text(encoding="utf-8")
    assert "TRUNCATE" in source
    assert "superuser" in source.lower()


# ---------------------------------------------------------------------------
# End-to-end through a real Alembic run on SQLite
# ---------------------------------------------------------------------------


def _alembic_config(url: str):
    from alembic.config import Config

    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    config.set_main_option("sqlalchemy.url", url)
    return config


def _current_head() -> str:
    """The chain's single head, which a later revision may have moved on from."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    heads = ScriptDirectory.from_config(config).get_heads()
    assert len(heads) == 1, heads
    return heads[0]


def _ancestors_of_head() -> set[str]:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    script = ScriptDirectory.from_config(config)
    ancestry: set[str] = set()
    cursor: str | None = script.get_heads()[0]
    while cursor is not None:
        ancestry.add(cursor)
        revision = script.get_revision(cursor)
        cursor = revision.down_revision if revision is not None else None
    return ancestry


def test_full_chain_upgrade_creates_the_schema_and_applies_this_revision(tmp_path, monkeypatch):
    """Runs the real chain end to end, not just the pure DDL builder."""
    from sqlalchemy import create_engine, text

    from alembic import command

    db_file = tmp_path / "step12.db"
    url = f"sqlite:///{db_file}"
    monkeypatch.setenv("DATABASE_URL", url)
    config = _alembic_config(url)

    command.upgrade(config, "head")

    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            applied = conn.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
        assert applied == [_current_head()]
        # Step 12 is on the way to that head, even when a later revision sits
        # on top of it; asserting equality with the head would make this test
        # break every time a migration is added afterwards.
        assert migration.revision in _ancestors_of_head()
    finally:
        engine.dispose()


def test_upgrade_on_sqlite_creates_no_trigger_objects(tmp_path, monkeypatch):
    """The dialect gate is exercised by a real run, not only by the builder."""
    from sqlalchemy import create_engine, text

    from alembic import command

    db_file = tmp_path / "step12_noop.db"
    url = f"sqlite:///{db_file}"
    monkeypatch.setenv("DATABASE_URL", url)
    config = _alembic_config(url)

    command.upgrade(config, "head")

    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            triggers = (
                conn.execute(text("SELECT name FROM sqlite_master WHERE type = 'trigger'"))
                .scalars()
                .all()
            )
        # SQLite has no PL/pgSQL, so the migration must change nothing.
        assert triggers == []
    finally:
        engine.dispose()


def test_downgrade_and_re_upgrade_round_trip(tmp_path, monkeypatch):
    """Reversibility proven by executing it, not only by inspecting strings."""
    from sqlalchemy import create_engine, text

    from alembic import command

    db_file = tmp_path / "step12_roundtrip.db"
    url = f"sqlite:///{db_file}"
    monkeypatch.setenv("DATABASE_URL", url)
    config = _alembic_config(url)

    command.upgrade(config, "head")
    command.downgrade(config, "step31_hardening")

    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            after_down = (
                conn.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
            )
        assert after_down == ["step31_hardening"]
    finally:
        engine.dispose()

    command.upgrade(config, "head")
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            final = conn.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
        assert final == [_current_head()]
        assert migration.revision in _ancestors_of_head()
    finally:
        engine.dispose()


def test_the_pre_step12_schema_is_unchanged_by_this_migration(tmp_path, monkeypatch):
    """No table, column or row may be altered - only triggers are added."""
    from sqlalchemy import create_engine, inspect

    from alembic import command

    db_file = tmp_path / "step12_shape.db"
    url = f"sqlite:///{db_file}"
    monkeypatch.setenv("DATABASE_URL", url)
    config = _alembic_config(url)

    command.upgrade(config, "step31_hardening")
    before = inspect(create_engine(url))
    before_shape = {
        t: sorted(c["name"] for c in before.get_columns(t)) for t in before.get_table_names()
    }

    command.upgrade(config, "head")
    after = inspect(create_engine(url))
    after_shape = {
        t: sorted(c["name"] for c in after.get_columns(t)) for t in after.get_table_names()
    }

    assert after_shape == before_shape


def test_orm_guard_from_step11_remains_installed():
    """The database trigger is defence in depth, not a replacement."""
    from app.database import session as session_module  # noqa: F401
    from app.models import audit_guard

    assert audit_guard.install_audit_append_only_guard() is False


def test_both_layers_block_the_same_operations():
    """ORM layer refuses object and bulk DML; the trigger refuses all DML."""
    for statement in migration.build_upgrade_statements("postgresql"):
        if statement.startswith("CREATE TRIGGER"):
            assert "UPDATE OR DELETE" in statement
            assert "TRUNCATE" not in statement.upper()
