"""Source-level SEC-02 configuration and privilege tests (no PostgreSQL)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.core.config import Settings, get_settings
from app.database.credentials import (
    migration_database_url,
    read_database_url_file,
    set_migration_owner,
)
from app.database.role_permissions import (
    RUNTIME_TABLE_PRIVILEGES,
    runtime_grant_sql,
)

EXPECTED_RUNTIME_TABLE_PRIVILEGES = {
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


def test_runtime_settings_read_secret_file_and_hide_connection_string(tmp_path, monkeypatch):
    secret_file = tmp_path / "runtime-dsn"
    secret_file.write_text(
        "postgresql+psycopg://runtime_user:synthetic%40credential@db/security_platform\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_URL_FILE", str(secret_file))

    settings = Settings(_env_file=None)

    assert settings.database_url.startswith("postgresql+psycopg://runtime_user:")
    assert "synthetic%40credential" not in repr(settings)
    assert "synthetic%40credential" not in str(settings.model_dump())


def test_runtime_settings_reject_direct_and_file_credential_ambiguity(tmp_path, monkeypatch):
    secret_file = tmp_path / "runtime-dsn"
    secret_file.write_text("postgresql://runtime_user:synthetic@db/security_platform")
    monkeypatch.setenv("DATABASE_URL_FILE", str(secret_file))
    monkeypatch.setenv("DATABASE_URL", "sqlite://")

    with pytest.raises(ValueError, match="Configure DATABASE_URL_FILE or DATABASE_URL"):
        Settings(_env_file=None)


def test_missing_runtime_connection_is_reported_without_a_secret(tmp_path, monkeypatch):
    from app.core import config as config_module

    get_settings.cache_clear()
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL_FILE", raising=False)
    monkeypatch.setattr(config_module, "Settings", lambda: Settings(_env_file=None))

    with pytest.raises(RuntimeError, match="DATABASE_URL_FILE or DATABASE_URL is required"):
        get_settings()
    get_settings.cache_clear()


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        (None, "could not be read"),
        ("", "is empty"),
        ("synthetic-first-line\nsynthetic-second-line", "must contain one line"),
    ],
)
def test_secret_file_failures_are_safe(tmp_path, contents, message):
    secret_file = tmp_path / "connection-secret"
    if contents is not None:
        secret_file.write_text(contents, encoding="utf-8")

    with pytest.raises(ValueError, match=f"DATABASE_URL_FILE {message}") as exc_info:
        read_database_url_file(str(secret_file), "DATABASE_URL_FILE")
    assert "synthetic-first-line" not in str(exc_info.value)
    assert "synthetic-second-line" not in str(exc_info.value)


def test_migration_connection_requires_its_own_file_and_never_falls_back(tmp_path):
    with pytest.raises(ValueError, match="MIGRATION_DATABASE_URL_FILE is required"):
        migration_database_url({"DATABASE_URL": "synthetic-runtime-value"})

    secret_file = tmp_path / "migration-dsn"
    secret_file.write_text("postgresql://migrator:synthetic@db/security_platform")
    result = migration_database_url({"MIGRATION_DATABASE_URL_FILE": str(secret_file)})
    assert result.startswith("postgresql://migrator:")


def test_migration_role_switch_is_explicit_and_precedes_migration_configuration():
    class Connection:
        def __init__(self):
            self.operations = []
            self.in_transaction = False
            self.current_user = "sec_migrator"

        def exec_driver_sql(self, statement):
            self.operations.append(statement)
            self.in_transaction = True
            if statement == "SET ROLE sec_owner":
                self.current_user = "sec_owner"
            return Result(self)

        def commit(self):
            self.operations.append("COMMIT")
            self.in_transaction = False

        def rollback(self):
            self.operations.append("ROLLBACK")
            self.in_transaction = False

    class Result:
        def __init__(self, connection):
            self.connection = connection

        def fetchone(self):
            return "sec_migrator", self.connection.current_user

    connection = Connection()
    set_migration_owner(connection)
    assert connection.operations == [
        "SET ROLE sec_owner",
        "SELECT session_user, current_user",
        "COMMIT",
        "SELECT session_user, current_user",
        "COMMIT",
    ]
    assert connection.current_user == "sec_owner"
    assert not connection.in_transaction

    alembic_source = (
        Path(__file__).parents[1] / "alembic" / "env.py"
    ).read_text(encoding="utf-8")
    online_source = alembic_source.split("def run_migrations_online()", maxsplit=1)[1]
    assert online_source.index("set_migration_owner(connection)") < online_source.index(
        "context.configure(connection=connection"
    ) < online_source.index("context.begin_transaction()")
    assert "SELECT session_user, current_user" in Path(
        __file__
    ).parents[1].joinpath("app", "database", "credentials.py").read_text(
        encoding="utf-8"
    )
    credentials_source = Path(__file__).parents[1].joinpath(
        "app", "database", "credentials.py"
    ).read_text(encoding="utf-8")
    assert credentials_source.count("connection.commit()") == 2
    assert "SET LOCAL ROLE" not in credentials_source
    assert "RESET ROLE" not in credentials_source
    assert "cannot prove session_user/current_user" in alembic_source


@pytest.mark.parametrize(
    "identities",
    [
        ("secuser", "sec_owner"),
        ("sec_migrator", "secuser"),
        ("sec_runtime", "sec_owner"),
    ],
)
def test_migration_role_verification_rejects_incorrect_identities(identities):
    class Connection:
        def exec_driver_sql(self, statement):
            return self

        def fetchone(self):
            return identities

    with pytest.raises(RuntimeError, match="migration identity verification failed") as exc:
        set_migration_owner(Connection())
    assert "postgresql" not in str(exc.value)
    assert "password" not in str(exc.value)


@pytest.mark.parametrize("failed_statement", ["SET ROLE sec_owner", "SELECT session_user, current_user"])
def test_migration_identity_verification_fails_closed_on_driver_errors(failed_statement):
    class Connection:
        def exec_driver_sql(self, statement):
            if statement == failed_statement:
                raise RuntimeError("synthetic connection credential detail")
            return self

        def fetchone(self):
            return "sec_migrator", "sec_owner"

    with pytest.raises(RuntimeError, match="migration identity verification failed") as exc:
        set_migration_owner(Connection())
    assert "synthetic" not in str(exc.value)


def test_failed_migration_identity_verification_prevents_alembic_configuration():
    class Connection:
        def exec_driver_sql(self, statement):
            return self

        def fetchone(self):
            return "sec_runtime", "sec_owner"

        def rollback(self):
            pass

    configured = []
    with pytest.raises(RuntimeError, match="migration identity verification failed"):
        set_migration_owner(Connection())
        configured.append("context.configure")
    assert configured == []


def test_runtime_grant_matrix_matches_provisioning_grants():
    sql_path = Path(__file__).parents[2] / "scripts" / (
        "provision_postgres_least_privilege.sql"
    )
    sql = sql_path.read_text(encoding="utf-8")
    statements = re.findall(
        r"GRANT ([A-Z, ]+) ON TABLE(.*?)TO sec_runtime;", sql, flags=re.DOTALL
    )
    actual: dict[str, tuple[str, ...]] = {}
    for privilege_text, table_text in statements:
        privileges = tuple(item.strip() for item in privilege_text.split(","))
        for table_name in re.findall(r"public\.([a-z_]+)", table_text):
            actual[table_name] = privileges

    # This independent approved fixture prevents matching mistakes in the
    # Python map and SQL script from validating one another.
    assert RUNTIME_TABLE_PRIVILEGES == EXPECTED_RUNTIME_TABLE_PRIVILEGES
    assert actual == EXPECTED_RUNTIME_TABLE_PRIVILEGES
    assert RUNTIME_TABLE_PRIVILEGES["discovered_services"] == (
        "SELECT",
        "INSERT",
        "DELETE",
    )
    assert "alembic_version" not in actual
    assert all(
        not ({"UPDATE", "DELETE"} & set(privileges))
        for table, privileges in actual.items()
        if table.endswith("audit") or table.endswith("audits")
    )


def test_future_runtime_grants_fail_closed_for_unknown_tables():
    assert runtime_grant_sql("correlation_evidence") == (
        "GRANT SELECT, INSERT, UPDATE ON TABLE "
        "public.correlation_evidence TO sec_runtime"
    )
    with pytest.raises(ValueError, match="No reviewed runtime grant"):
        runtime_grant_sql("alembic_version")


def test_provisioning_preserves_database_and_schema_owners_and_has_no_broad_defaults():
    sql_path = Path(__file__).parents[2] / "scripts" / (
        "provision_postgres_least_privilege.sql"
    )
    sql = sql_path.read_text(encoding="utf-8").lower()

    assert "alter database security_platform owner" not in sql
    assert "alter schema public owner" not in sql
    assert "alter default privileges for role sec_owner" in sql
    assert "pg_default_acl" in sql
    assert "aclexplode" in sql
    assert "pg_auth_members" in sql
    assert "stop before" in sql or "stopped:" in sql
    preflight_end = sql.index("$preflight$;")
    first_role_change = sql.index("create role sec_owner")
    assert preflight_end < first_role_change
    assert "existing global or public default acls require explicit review" in sql
    assert "database acls require explicit review" in sql
    assert "public schema acls require explicit review" in sql
    assert "table or column acls require explicit review" in sql
    assert "audit function acls require explicit review" in sql
    assert "grant all on all tables" not in sql
    assert "grant all on all sequences" not in sql
    assert "grant truncate" not in sql
    assert "grant trigger" not in sql
    assert "revoke all privileges on function public.audit_append_only_guard()" in sql


def test_provisioning_preconditions_precede_every_role_or_owner_change():
    sql = (
        Path(__file__).parents[2] / "scripts" / "provision_postgres_least_privilege.sql"
    ).read_text(encoding="utf-8").lower()
    preflight_end = sql.index("$preflight$;")
    mutations = [
        sql.index("create role sec_owner"),
        sql.index("alter table public.alembic_version owner"),
        sql.index("alter function public.audit_append_only_guard() owner"),
    ]
    assert preflight_end < min(mutations)


def test_provisioning_rejects_database_owner_mismatch():
    sql = (
        Path(__file__).parents[2] / "scripts" / "provision_postgres_least_privilege.sql"
    ).read_text(encoding="utf-8").lower()
    assert "r.rolname = 'secuser'" in sql
    assert "database owner must be secuser" in sql


def test_provisioning_rejects_public_schema_owner_mismatch():
    sql = (
        Path(__file__).parents[2] / "scripts" / "provision_postgres_least_privilege.sql"
    ).read_text(encoding="utf-8").lower()
    assert "r.rolname = 'pg_database_owner'" in sql
    assert "public schema owner must be pg_database_owner" in sql


def test_provisioning_rejects_public_schema_create_with_or_without_grant_option():
    sql = (
        Path(__file__).parents[2] / "scripts" / "provision_postgres_least_privilege.sql"
    ).read_text(encoding="utf-8").lower()
    assert "acl.grantee = 0" in sql
    assert "acl.is_grantable or acl.privilege_type = 'create'" in sql
    assert "revoke create on schema public from public" in sql
    assert "revoke all on schema public" not in sql


def test_provisioning_requires_exact_audit_trigger_event_bits():
    sql = (
        Path(__file__).parents[2] / "scripts" / "provision_postgres_least_privilege.sql"
    ).read_text(encoding="utf-8").lower()
    reviewed_trigger_bits = 1 | 2 | 8 | 16
    assert reviewed_trigger_bits == 27
    assert "and t.tgtype = 27" in sql
    assert "t.tgtype &" not in sql
    for extra_event_bit in (4, 32):  # INSERT and TRUNCATE
        assert (reviewed_trigger_bits | extra_event_bit) != 27


def test_compose_separates_runtime_and_migration_secrets():
    compose_path = Path(__file__).parents[2] / "docker-compose.yml"
    compose = compose_path.read_text(encoding="utf-8")
    backend = compose.split("  backend:", maxsplit=1)[1].split("  migrator:", maxsplit=1)[0]
    migrator = compose.split("  migrator:", maxsplit=1)[1].split("  frontend:", maxsplit=1)[0]

    assert "DATABASE_URL_FILE: /run/secrets/sec_runtime_database_url" in backend
    assert "sec_migration_database_url" not in backend
    assert "MIGRATION_DATABASE_URL_FILE: /run/secrets/sec_migration_database_url" in migrator
    assert "sec_runtime_database_url" not in migrator
    assert "pgdata:/var/lib/postgresql/data" in compose


def test_secret_paths_are_ignored_and_windows_acl_check_is_documented():
    root = Path(__file__).parents[2]
    ignore = (root / ".gitignore").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")

    assert "/secrets/" in ignore
    assert "/secrets/postgres_bootstrap_password" in ignore
    assert "/secrets/sec_runtime_database_url" in ignore
    assert "/secrets/sec_migration_database_url" in ignore
    assert "icacls.exe" in readme
    assert "does not prove or enforce" in readme.lower()
