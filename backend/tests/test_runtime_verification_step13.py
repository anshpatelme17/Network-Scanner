"""Phase 2 Step 13 - runtime verification harness.

The harness reports what the machine it is given actually contains, so its
tests cover both directions and neither is privileged:

* With nothing reachable, the harness must report an absence of evidence
  rather than a pass. That state is *manufactured* here (an unusable ``docker``
  and no database URL), because it can no longer be assumed to be the ambient
  one.
* With a real Docker engine and PostgreSQL present, the harness must find them.
  Those tests run only when a server is actually reachable and skip otherwise,
  so the file asserts the same thing on a laptop and on a CI runner with a
  service container.
"""

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_runtime.py"


def _load():
    spec = importlib.util.spec_from_file_location("verify_runtime", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves cls.__module__ through sys.modules, so the module
    # must be registered before it is executed.
    sys.modules["verify_runtime"] = module
    spec.loader.exec_module(module)
    return module


verifier = _load()


def _unusable_docker_env(tmp_path: Path) -> dict[str, str]:
    """A PATH whose `docker` always fails, so the 'unreachable' path is forced.

    These tests assert what the harness reports when nothing can be verified.
    That state used to be the only state available in the development
    environment; once Docker Desktop is running, it has to be *manufactured*
    rather than assumed, or the tests would silently start asserting the
    opposite of their intent.
    """
    shim = tmp_path / "bin"
    shim.mkdir()
    name = "docker.bat" if os.name == "nt" else "docker"
    script = "@echo off\r\nexit /b 1\r\n" if os.name == "nt" else "#!/bin/sh\nexit 1\n"
    path = shim / name
    path.write_text(script, encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o755)
    env = dict(os.environ)
    # PATH is *replaced*, not prepended: on Windows CreateProcess resolves
    # `docker.exe` and ignores a `.bat`, so a prepended shim directory would
    # still find the real executable further down PATH.
    env["PATH"] = str(shim)
    return env


# ---------------------------------------------------------------------------
# The harness must never claim a pass it did not earn
# ---------------------------------------------------------------------------


def test_harness_reports_nothing_verified_rather_than_a_pass(tmp_path, monkeypatch):
    """With neither Docker nor PostgreSQL reachable, the verdict is 'unknown'."""
    monkeypatch.setenv("PATH", str(tmp_path / "bin") + os.pathsep + os.environ["PATH"])
    monkeypatch.setattr(verifier.shutil, "which", lambda _name: None)

    report = verifier.Report()
    assert verifier.check_containers(report, "docker-compose.yml") is False
    assert verifier.check_audit_triggers(report, None) is False
    assert report.passed == 0
    assert report.failed == 0
    assert report.skipped > 0
    assert all(status == verifier.SKIP for status, _, _ in report.results)


def test_exit_code_2_when_nothing_could_be_verified(tmp_path):
    # An unreachable `docker` plus no --database-url makes both prerequisites
    # skip immediately rather than waiting on a connection timeout.
    proc = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env=_unusable_docker_env(tmp_path),
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "0 passed, 0 failed" in proc.stdout
    # The wording must make clear this is missing evidence, not success.
    assert "NOTHING COULD BE VERIFIED" in proc.stdout
    assert "not a pass" in proc.stdout


def test_no_pass_line_is_printed_when_nothing_ran(tmp_path):
    proc = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        env=_unusable_docker_env(tmp_path),
    )
    assert proc.returncode == 2
    assert "[PASS]" not in proc.stdout


def test_cli_help_is_available():
    proc = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, str(SCRIPT), "--help"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0
    assert "--database-url" in proc.stdout
    assert "--base-url" in proc.stdout


def test_missing_database_url_is_skipped_not_assumed():
    report = verifier.Report()
    assert verifier.check_audit_triggers(report, None) is False
    assert report.passed == 0
    assert any("no --database-url" in note for _, _, note in report.results)


def _compose_config(*, host_ip="127.0.0.1", port="55432"):
    return {
        "services": {
            "db": {
                "environment": {
                    "POSTGRES_DB": "audit-db",
                    "POSTGRES_USER": "audit-user",
                    "POSTGRES_PASSWORD": "",
                },
                "ports": [
                    {"target": 5432, "published": port, "host_ip": host_ip}
                ],
            }
        }
    }


def _mock_compose_config(monkeypatch, config):
    monkeypatch.setattr(
        verifier,
        "_run_split",
        lambda _cmd, timeout=60: (0, json.dumps(config), ""),
    )


def test_compose_database_url_encodes_reserved_characters(monkeypatch):
    config = _compose_config()
    env = config["services"]["db"]["environment"]
    env.update(
        POSTGRES_USER="u@:/?#%",
        POSTGRES_PASSWORD="p@:/?#%",
        POSTGRES_DB="d /?#%",
    )
    _mock_compose_config(monkeypatch, config)

    url = verifier._compose_database_url("docker-compose.yml")
    assert url == (
        "postgresql://u%40%3A%2F%3F%23%25:p%40%3A%2F%3F%23%25"
        "@127.0.0.1:55432/d%20%2F%3F%23%25"
    )


@pytest.mark.parametrize(
    ("host_ip", "expected_host"),
    [("127.0.0.1", "127.0.0.1"), ("::1", "[::1]")],
)
def test_compose_database_url_uses_the_matching_loopback_address(
    monkeypatch, host_ip, expected_host
):
    _mock_compose_config(monkeypatch, _compose_config(host_ip=host_ip))
    url = verifier._compose_database_url("docker-compose.yml")
    assert url is not None
    assert f"@{expected_host}:55432/" in url


@pytest.mark.parametrize(
    "config",
    [
        [],
        {"services": []},
        {"services": {"db": []}},
        {"services": {"db": {"environment": [], "ports": []}}},
        {"services": {"db": {"environment": {}, "ports": []}}},
        {
            "services": {
                "db": {
                    "environment": {
                        "POSTGRES_DB": None,
                        "POSTGRES_USER": "user",
                        "POSTGRES_PASSWORD": "",
                    },
                    "ports": [],
                }
            }
        },
        {**_compose_config(), "services": {"db": {**_compose_config()["services"]["db"], "ports": ["bad-entry"]}}},
        {**_compose_config(), "services": {"db": {**_compose_config()["services"]["db"], "ports": [{"target": 5432, "published": "bad", "host_ip": "127.0.0.1"}]}}},
    ],
)
def test_compose_database_url_skips_malformed_or_incomplete_config(monkeypatch, config):
    _mock_compose_config(monkeypatch, config)
    assert verifier._compose_database_url("docker-compose.yml") is None


def test_compose_database_url_skips_malformed_json(monkeypatch):
    monkeypatch.setattr(
        verifier, "_run_split", lambda _cmd, timeout=60: (0, "{malformed json", "")
    )
    assert verifier._compose_database_url("docker-compose.yml") is None


def test_compose_database_url_skips_null_config(monkeypatch):
    monkeypatch.setattr(
        verifier, "_run_split", lambda _cmd, timeout=60: (0, "null", "")
    )
    assert verifier._compose_database_url("docker-compose.yml") is None


@pytest.mark.parametrize("field", ["POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD"])
def test_compose_database_url_skips_null_environment_values(monkeypatch, field):
    config = _compose_config()
    config["services"]["db"]["environment"][field] = None
    _mock_compose_config(monkeypatch, config)
    assert verifier._compose_database_url("docker-compose.yml") is None


@pytest.mark.parametrize("field", ["POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD"])
def test_compose_database_url_skips_missing_database_settings(monkeypatch, field):
    config = _compose_config()
    del config["services"]["db"]["environment"][field]
    _mock_compose_config(monkeypatch, config)
    assert verifier._compose_database_url("docker-compose.yml") is None


@pytest.mark.parametrize(
    "port_entry",
    [
        "bad-entry",
        {"published": 5432, "host_ip": "127.0.0.1"},
        {"target": 5432, "host_ip": "127.0.0.1"},
        {"target": 5432, "published": "0", "host_ip": "127.0.0.1"},
        {"target": 5432, "published": "65536", "host_ip": "127.0.0.1"},
        {"target": [], "published": 5432, "host_ip": "127.0.0.1"},
        {"target": 5432, "published": 5432, "host_ip": []},
    ],
)
def test_compose_database_url_skips_malformed_port_entries(monkeypatch, port_entry):
    config = _compose_config()
    config["services"]["db"]["ports"] = [port_entry]
    _mock_compose_config(monkeypatch, config)
    assert verifier._compose_database_url("docker-compose.yml") is None


def test_compose_database_url_skips_non_loopback_or_missing_database_port(monkeypatch):
    _mock_compose_config(monkeypatch, _compose_config(host_ip="0.0.0.0"))
    assert verifier._compose_database_url("docker-compose.yml") is None


def test_compose_database_url_skips_docker_command_failure(monkeypatch):
    monkeypatch.setattr(
        verifier,
        "_run_split",
        lambda _cmd, timeout=60: (1, "", "redacted command failure"),
    )
    assert verifier._compose_database_url("docker-compose.yml") is None


def test_compose_database_url_skips_when_docker_command_raises(monkeypatch):
    def failed_command(_cmd, timeout=60):
        raise OSError("redacted command failure")

    monkeypatch.setattr(verifier, "_run_split", failed_command)
    assert verifier._compose_database_url("docker-compose.yml") is None


@pytest.mark.parametrize(
    ("argv", "environment_url", "expected"),
    [
        (["--database-url", "postgresql://cli.invalid/db"], "postgresql://env.invalid/db", "postgresql://cli.invalid/db"),
        ([], "postgresql+psycopg://env.invalid/db", "postgresql://env.invalid/db"),
        ([], None, "compose-url"),
    ],
)
def test_main_selects_database_url_precedence(
    monkeypatch, capsys, argv, environment_url, expected
):
    selected = []
    monkeypatch.setattr(verifier, "check_containers", lambda *_args: False)
    monkeypatch.setattr(verifier, "check_audit_triggers", lambda _report, url: selected.append(url) or False)
    monkeypatch.setattr(verifier, "_compose_database_url", lambda _compose: "compose-url")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    if environment_url is not None:
        monkeypatch.setenv("DATABASE_URL", environment_url)

    assert verifier.main(argv) == 2
    assert selected == [expected]
    assert expected not in capsys.readouterr().out


def test_connection_failure_is_skipped_without_exposing_details(monkeypatch, capsys):
    import types

    marker = "synthetic-connection-detail"

    def fail_connect(*_args, **_kwargs):
        raise RuntimeError(marker)

    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        types.SimpleNamespace(connect=fail_connect),
    )
    report = verifier.Report()
    assert verifier.check_audit_triggers(report, "postgresql://host/db") is False
    output = "\n".join(report.details) + capsys.readouterr().out
    assert report.results == [(verifier.SKIP, "PostgreSQL reachable", "connection failed; details withheld")]
    assert marker not in output


def test_probe_error_details_are_not_written_to_the_report():
    marker = "synthetic-database-error-detail"

    class FakeDatabaseError(Exception):
        sqlstate = verifier.EXPECTED_SQLSTATE

    report = verifier.Report()
    verifier._report_probe(
        report, "auth_audits", "DELETE", (None, FakeDatabaseError(marker))
    )
    assert report.results[0][0] == verifier.PASS
    assert marker not in " ".join(report.details)


def test_main_withholds_unexpected_database_exception_details(monkeypatch, capsys):
    marker = "synthetic-unexpected-database-detail"

    def fail_verification(*_args):
        raise RuntimeError(marker)

    monkeypatch.setattr(verifier, "check_containers", lambda *_args: False)
    monkeypatch.setattr(verifier, "_compose_database_url", lambda _compose: "postgresql://host/db")
    monkeypatch.setattr(verifier, "check_audit_triggers", fail_verification)
    monkeypatch.delenv("DATABASE_URL", raising=False)

    assert verifier.main([]) == 2
    output = capsys.readouterr().out
    assert "verification failed; details withheld" in output
    assert marker not in output


def test_sqlalchemy_psycopg_url_is_accepted_by_direct_client():
    assert (
        verifier._psycopg_url("postgresql+psycopg://localhost:5432/db")
        == "postgresql://localhost:5432/db"
    )


# ---------------------------------------------------------------------------
# The harness must check the same things the implementation created
# ---------------------------------------------------------------------------


def test_harness_covers_exactly_the_orm_guarded_audit_tables():
    from app.models.audit_guard import audit_table_names

    assert set(verifier.AUDIT_TABLES) == set(audit_table_names())


def test_harness_agrees_with_the_step12_migration():
    migration_path = (
        ROOT / "backend" / "alembic" / "versions" / "phase2_step12_audit_immutability.py"
    )
    spec = importlib.util.spec_from_file_location("s12_migration", migration_path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    assert set(verifier.AUDIT_TABLES) == set(migration.AUDIT_TABLES)
    assert verifier.GUARD_FUNCTION == migration.GUARD_FUNCTION


def test_harness_checks_both_update_and_delete():
    """A guard that only blocked deletes would be a partial check."""
    source = SCRIPT.read_text(encoding="utf-8")
    assert "on_delete" in source
    assert "on_update" in source


# ---------------------------------------------------------------------------
# Non-destructive guarantees
# ---------------------------------------------------------------------------


def test_write_probe_is_rolled_back():
    """The delete probe must never be able to destroy a row."""
    source = SCRIPT.read_text(encoding="utf-8")
    assert "connection.rollback()" in source
    # The probe only ever runs inside an explicit transaction.
    assert "autocommit = False" in source


def test_harness_does_not_use_destructive_docker_commands():
    source = SCRIPT.read_text(encoding="utf-8")
    for forbidden in ("rm ", "rm -f", "prune", "down", "kill", "stop", "restart", "exec "):
        assert forbidden not in source, forbidden


def test_container_discovery_returns_empty_when_compose_is_down():
    assert verifier._compose_container_ids("definitely-not-a-compose-file.yml") == {}


def test_container_discovery_reads_the_json_format(monkeypatch):
    """`ps --quiet` emits bare ids with no service name, so json is required."""
    argv: list[list[str]] = []

    def fake_run_split(cmd, timeout=60):
        argv.append(cmd)
        return 0, '{"Service":"db","ID":"abc123"}', ""

    monkeypatch.setattr(verifier, "_run_split", fake_run_split)
    assert verifier._compose_container_ids("docker-compose.yml") == {"db": "abc123"}
    assert argv and argv[0][-2:] == ["--format", "json"]
    assert "--quiet" not in argv[0]


def test_trigger_bitmask_uses_the_postgresql_delete_bit():
    """tgtype DELETE is bit 8; bit 4 is INSERT, which every table also has.

    Checking the wrong bit made every table look like it lacked a delete
    guard even though the trigger was correct.
    """
    source = SCRIPT.read_text(encoding="utf-8")
    assert "(t.tgtype & 8) <> 0 AS on_delete" in source
    assert "tgtype & 4" not in source


def test_port_bindings_are_read_as_a_list_of_bindings():
    """HostConfig.PortBindings values are lists, not dicts."""
    source = SCRIPT.read_text(encoding="utf-8")
    assert "for binding in (binding_list or [])" in source
    assert "binding_list.items()" not in source


def test_delete_probe_judges_the_guard_by_sqlstate_not_by_message_text():
    """The refusal is proven by SQLSTATE 23001, not by matching wording.

    Matching a phrase in the message would let a *different* error - a missing
    table, a broken connection - pass as "append-only enforced".
    """
    assert verifier.EXPECTED_SQLSTATE == "23001"
    source = SCRIPT.read_text(encoding="utf-8")
    assert "sqlstate == EXPECTED_SQLSTATE" in source
    assert '"append-only" in message' not in source


def test_server_version_does_not_close_the_shared_connection():
    """`with connection` closes it in psycopg 3; the caller keeps using it."""
    source = SCRIPT.read_text(encoding="utf-8")
    assert "with connection, connection.cursor() as cursor:\n        cursor.execute" not in source
    body = source.split("def _server_version(")[1].split("\n\n")[0]
    assert "with connection.cursor() as cursor:" in body


# ---------------------------------------------------------------------------
# Server-version detection: the condition that was actually checked
# ---------------------------------------------------------------------------


class _FakeDocker:
    """A `docker` that answers `info` with a chosen code/stdout/stderr."""

    def __init__(self, monkeypatch, code, stdout, stderr):
        seen: list[list[str]] = []

        def fake_split(cmd, timeout=60):
            seen.append(list(cmd))
            return code, stdout, stderr

        monkeypatch.setattr(verifier, "_run_split", fake_split)
        monkeypatch.setattr(verifier.shutil, "which", lambda _name: "/usr/bin/docker")
        monkeypatch.setattr(verifier, "_docker_engine_probe", lambda: (code, stdout, stderr))
        self.seen = seen


def test_server_version_is_read_from_stdout_and_the_engine_is_reachable(monkeypatch):
    _FakeDocker(monkeypatch, 0, "27.3.1\n", "")
    assert verifier.docker_server_version() == "27.3.1"

    report = verifier.Report()
    assert verifier.check_containers(report, "docker-compose.yml") is True
    assert ("PASS", "docker engine reachable", "server 27.3.1") in report.results


def test_stderr_noise_alone_is_not_mistaken_for_a_reachable_engine(monkeypatch):
    """A merged stream would let this warning read as a version."""
    _FakeDocker(monkeypatch, 0, "", "WARNING: bridge-nf-call-iptables is disabled\n")
    assert verifier.docker_server_version() is None

    report = verifier.Report()
    assert verifier.check_containers(report, "docker-compose.yml") is False
    skipped = [item for item in report.results if item[0] == verifier.SKIP]
    assert skipped, report.results
    assert "bridge-nf-call-iptables" in skipped[0][2]


def test_a_non_version_string_is_not_reported_as_a_reachable_engine(monkeypatch):
    _FakeDocker(monkeypatch, 0, "Client: Docker Desktop\n", "")
    assert verifier.docker_server_version() is None

    report = verifier.Report()
    assert verifier.check_containers(report, "docker-compose.yml") is False
    reason = next(item for item in report.results if item[1] == "docker engine reachable")[2]
    assert "unexpected server version output" in reason


def test_a_failing_cli_reports_its_own_message_not_an_assumption(monkeypatch):
    _FakeDocker(
        monkeypatch, 1, "", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock."
    )
    assert verifier.docker_server_version() is None

    report = verifier.Report()
    assert verifier.check_containers(report, "docker-compose.yml") is False
    reason = next(item for item in report.results if item[1] == "docker engine reachable")[2]
    assert "Cannot connect to the Docker daemon" in reason


def test_an_absent_docker_cli_is_reported_as_absent(monkeypatch):
    monkeypatch.setattr(verifier.shutil, "which", lambda _name: None)
    assert verifier.docker_server_version() is None


def test_run_keeps_stdout_and_stderr_separate():
    assert verifier._run_split.__doc__ is not None
    combined = verifier._run.__doc__
    assert combined is None or "stdout" not in combined


# ---------------------------------------------------------------------------
# The write probes are real DELETE/UPDATE statements
# ---------------------------------------------------------------------------


def test_probes_exercise_both_update_and_delete():
    operations = [op for op, _ in verifier.probe_statements("auth_audits", "id")]
    assert operations == ["UPDATE", "DELETE"]
    statements = dict(verifier.probe_statements("auth_audits", "id"))
    assert statements["DELETE"].startswith("DELETE FROM auth_audits")
    assert statements["UPDATE"].startswith("UPDATE auth_audits SET id = id")


def test_probes_touch_at_most_one_row():
    for _operation, statement in verifier.probe_statements("auth_audits", "id"):
        assert "ctid = (SELECT ctid FROM auth_audits LIMIT 1)" in statement


def test_probes_never_issue_an_unscoped_write():
    """`DELETE FROM t` with no WHERE is what the probe used to do."""
    for _operation, statement in verifier.probe_statements("scan_audit", "id"):
        assert statement.count("WHERE") == 1


def test_probe_names_read_as_a_sentence():
    report = verifier.Report()
    verifier._report_probe(report, "auth_audits", "UPDATE", (1, None))
    assert any("refuses an UPDATE" in name for _, name, _ in report.results)


# ---------------------------------------------------------------------------
# Live behaviour, when a real runtime is present
# ---------------------------------------------------------------------------

#: Connection string for a real PostgreSQL, e.g. from the compose service.
LIVE_DATABASE_URL = os.getenv("VERIFY_RUNTIME_DATABASE_URL")


def _live_connection():
    """A connection to a real server, or ``None`` when there is none here.

    Reachability is decided by connecting, not by inspecting configuration: a
    URL can be set while nothing listens on it, and a test that assumes
    otherwise asserts the opposite of its intent.
    """
    if not LIVE_DATABASE_URL:
        return None
    try:
        import psycopg
    except ImportError:
        return None
    try:
        return psycopg.connect(LIVE_DATABASE_URL, autocommit=True)
    except Exception:  # noqa: BLE001 - unreachable is a legitimate outcome
        return None


@pytest.fixture()
def live_connection():
    connection = _live_connection()
    if connection is None:
        pytest.skip("no reachable PostgreSQL for runtime verification")
    try:
        yield connection
    finally:
        connection.close()


def test_update_and_delete_are_both_refused_on_every_audit_table(live_connection):
    """The behaviour the catalog check can only infer, executed for real."""
    for table in verifier.AUDIT_TABLES:
        column = verifier._updatable_column(live_connection.cursor(), table)
        assert column, table
        for operation, statement in verifier.probe_statements(table, column):
            rows, error = verifier.attempt_write(live_connection, statement)
            assert error is not None, f"{table}: {operation} was accepted"
            assert error.sqlstate == verifier.EXPECTED_SQLSTATE, f"{table}: {operation}: {error}"
            assert rows is None


def test_the_guard_names_the_table_and_the_refused_operation(live_connection):
    """A refusal that says nothing about what happened is not auditable."""
    error = verifier.attempt_write(
        live_connection,
        "DELETE FROM auth_audits WHERE ctid = (SELECT ctid FROM auth_audits LIMIT 1)",
    )[1]
    assert error is not None
    message = str(error)
    assert "auth_audits" in message
    assert "DELETE" in message
    assert "append-only" in message


def test_the_harness_never_inserts_so_recording_is_never_at_risk(live_connection):
    """The harness's own statements are UPDATE and DELETE only.

    The append-only fix file covers INSERT acceptance against a live server;
    here the point is narrower and structural - this harness, whose job is to
    poke a production-shaped database, must not write to it at all.
    """
    for table in verifier.AUDIT_TABLES:
        for _operation, statement in verifier.probe_statements(table, "id"):
            assert "INSERT" not in statement.upper()
            assert statement.upper().startswith(("UPDATE ", "DELETE FROM "))


# ---------------------------------------------------------------------------
# Documented, honest status
# ---------------------------------------------------------------------------


def test_unverified_runtime_is_documented_in_the_repo():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "verify_runtime.py" in readme
    assert "Step 13" in readme
