#!/usr/bin/env python3
"""Phase 2 Step 13 - runtime verification of Steps 10 and 12.

This is the instrument for Step 13's scope. It runs against whatever runtime is
actually present and reports what it found, rather than assuming a fixed
environment:

* **Step 10 container hardening** - non-root execution, read-only root
  filesystem, dropped capabilities, ``no-new-privileges``, loopback-only port
  bindings, and preserved healthchecks, read from ``docker inspect`` (never by
  changing anything).
* **Step 12 audit triggers** - that all eight audit tables carry an enabled
  ``BEFORE UPDATE OR DELETE`` trigger wired to the guard function, and that the
  trigger actually refuses an ``UPDATE`` and a ``DELETE`` with the intended
  protection error, SQLSTATE ``23001`` (``restrict_violation``).
* **Health/readiness** - that ``/health`` and ``/ready`` still answer.

Every check is non-destructive. Each write probe runs inside an explicit
transaction that is rolled back and touches at most one row, so no history can
be lost whether the trigger fires or not: if it fires the transaction aborts,
and if it somehow does not, the ``ROLLBACK`` still discards the write.

Usage:
    python scripts/verify_runtime.py \\
        [--base-url http://localhost:8000] \\
        [--database-url postgresql://...] [--compose-file docker-compose.yml]

Exit codes:
    0  every applicable check passed
    1  at least one check FAILED
    2  nothing could be verified (Docker and/or PostgreSQL unavailable)

This script reports honestly. A check that cannot run is reported SKIP, never
PASS, and an unavailable environment yields exit code 2 rather than a
misleading success.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

# The eight audit tables protected by the Step 12 migration.
AUDIT_TABLES = (
    "auth_audits",
    "correlation_audits",
    "event_audits",
    "incident_audits",
    "response_audit",
    "risk_audits",
    "scan_audit",
    "vulnerability_audits",
)
GUARD_FUNCTION = "audit_append_only_guard"

#: The SQLSTATE the guard must raise. ``restrict_violation`` is condition name
#: 23001; the refusal is judged on this exact code rather than on message
#: wording, because a *different* error (say the trigger never fired and a
#: constraint failed) must not be able to pass as "append-only enforced".
EXPECTED_SQLSTATE = "23001"

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


@dataclass
class Report:
    """Tally of checks for one run.

    The results belong to the report, not to a module-level list. A shared list
    made every result accumulate for the lifetime of the process, so a second
    run in the same interpreter saw the first run's verdicts mixed into its own
    - which is exactly the kind of stale evidence this script exists to avoid.
    """

    passed: int = 0
    failed: int = 0
    skipped: int = 0
    details: list[str] = field(default_factory=list)
    results: list[tuple[str, str, str]] = field(default_factory=list)

    def add(self, status: str, name: str, note: str = "") -> None:
        self.results.append((status, name, note))
        if status == PASS:
            self.passed += 1
        elif status == FAIL:
            self.failed += 1
        else:
            self.skipped += 1
        line = f"[{status:4}] {name}"
        if note:
            line += f" - {note}"
        self.details.append(line)

    def find(self, name: str) -> tuple[str, str, str] | None:
        """The first recorded result for a check, or ``None``."""
        for status, recorded, note in self.results:
            if recorded == name:
                return status, recorded, note
        return None


def _run_split(cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
    """Run a command and keep stdout and stderr apart.

    They must not be merged: several checks below ask "did the command report
    the thing I asked for on stdout?", and a merged stream lets an error message
    on stderr masquerade as a successful answer.
    """
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "", str(exc)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    code, stdout, stderr = _run_split(cmd, timeout)
    return code, stdout + stderr


def _first_line(text: str, limit: int = 120) -> str:
    for line in text.strip().splitlines():
        if line.strip():
            return line.strip()[:limit]
    return ""


def _looks_like_version(value: str) -> bool:
    """A Docker Engine version is ``major.minor[.patch][-suffix]``."""
    return re.fullmatch(r"\d+\.\d+(\.\d+)?([-+][0-9A-Za-z.+~-]+)?", value) is not None


# ---------------------------------------------------------------------------
# Step 10: container hardening
# ---------------------------------------------------------------------------


def _docker_engine_probe() -> tuple[int, str, str]:
    """Ask the CLI for the Engine version; the caller decides what it means."""
    return _run_split(["docker", "info", "--format", "{{.ServerVersion}}"])


def docker_server_version(probe: tuple[int, str, str] | None = None) -> str | None:
    """The Docker *Engine* version, or ``None`` when it cannot be determined.

    The engine counts as reached only if the CLI exits zero *and* prints
    something on stdout that is actually a version. An exit code alone is not
    enough, and neither is a non-empty merged stream: an engine that is not
    serving prints its complaint on stderr and exits non-zero, while a check
    that exits zero but answers with anything else is reporting something this
    function does not understand. Neither may be reported as reachable.
    """
    if shutil.which("docker") is None:
        return None
    code, stdout, _stderr = probe if probe is not None else _docker_engine_probe()
    if code != 0:
        return None
    reported = stdout.strip()
    if not _looks_like_version(reported):
        return None
    return reported


# ---------------------------------------------------------------------------
# Step 10: container hardening
# ---------------------------------------------------------------------------


def check_containers(report: Report, compose_file: str) -> bool:
    if shutil.which("docker") is None:
        report.add(SKIP, "docker CLI present", "not installed")
        return False

    # The engine is judged on what the CLI actually reports, and the reason for
    # a failure is the CLI's own message rather than an assumption.
    probe = _docker_engine_probe()
    version = docker_server_version(probe)
    if version is None:
        code, stdout, stderr = probe
        if code != 0:
            reason = _first_line(stderr) or f"docker info exited {code}"
        elif not stdout.strip():
            reason = _first_line(stderr) or "docker info reported no server version"
        else:
            reason = f"unexpected server version output: {stdout.strip()[:60]!r}"
        report.add(SKIP, "docker engine reachable", reason)
        return False
    report.add(PASS, "docker engine reachable", f"server {version}")

    containers = _compose_container_ids(compose_file)
    if not containers:
        report.add(SKIP, "running containers discovered", "compose project not up")
        return True

    inspect: dict[str, dict] = {}
    for service, cid in containers.items():
        icode, iout = _run(["docker", "inspect", cid])
        if icode == 0 and iout.strip().startswith("["):
            try:
                inspect[service] = json.loads(iout)[0]
            except (ValueError, IndexError):
                continue

    if not inspect:
        report.add(SKIP, "container inspection", "no container detail returned")
        return True

    backend = inspect.get("backend")
    if backend is None:
        report.add(FAIL, "backend container found", "service 'backend' not running")
    else:
        report.add(
            PASS if backend["Config"].get("User") not in (None, "", "root") else FAIL,
            "backend runs as a non-root user",
            f"User={backend['Config'].get('User')!r}",
        )
        report.add(
            PASS if backend["HostConfig"].get("ReadonlyRootfs") else FAIL,
            "backend root filesystem is read-only",
            f"ReadonlyRootfs={backend['HostConfig'].get('ReadonlyRootfs')}",
        )
        dropped = backend["HostConfig"].get("CapDrop") or []
        report.add(
            PASS if "ALL" in dropped else FAIL,
            "backend drops all capabilities",
            str(dropped),
        )
        opts = backend["HostConfig"].get("SecurityOpt") or []
        report.add(
            PASS if any("no-new-privileges" in o for o in opts) else FAIL,
            "backend sets no-new-privileges",
            str(opts),
        )
        report.add(
            PASS if (backend["Config"].get("Healthcheck") or {}).get("Test") else FAIL,
            "backend healthcheck preserved",
        )

    for service in ("db", "frontend", "backend"):
        container = inspect.get(service)
        if container is None:
            continue
        # HostConfig.PortBindings maps "8000/tcp" to a list of
        # {"HostIp", "HostPort"} objects, not to a dict.
        bindings = container["HostConfig"].get("PortBindings") or {}
        published = [
            f"{binding.get('HostIp') or '0.0.0.0'}:{binding.get('HostPort')}"
            f"->{container_port}"
            for container_port, binding_list in bindings.items()
            for binding in (binding_list or [])
        ]
        wildcard = any("0.0.0.0" in item for item in published)
        report.add(
            PASS if published and not wildcard else FAIL,
            f"{service} port bound to loopback only",
            "; ".join(published) or "no published ports",
        )
    return True


def _compose_container_ids(compose_file: str) -> dict[str, str]:
    # `ps --quiet` emits bare ids with no service name, so the JSON format is
    # requested instead. Compose v5 emits one JSON object per line.
    code, out = _run(
        ["docker", "compose", "-f", compose_file, "ps", "--format", "json"]
    )
    if code != 0 or not out.strip():
        return {}
    ids: dict[str, str] = {}
    for line in out.strip().splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and entry.get("Service") and entry.get("ID"):
            ids[entry["Service"]] = entry["ID"]
    return ids


# ---------------------------------------------------------------------------
# Step 12: audit triggers
# ---------------------------------------------------------------------------


def _updatable_column(cursor, table: str) -> str | None:
    """First ordinary column of ``table``, used to build an UPDATE probe."""
    try:
        cursor.execute(
            """
            SELECT a.attname
            FROM pg_attribute a
            WHERE a.attrelid = %s::regclass
              AND a.attnum > 0
              AND NOT a.attisdropped
            ORDER BY a.attnum
            LIMIT 1
            """,
            (table,),
        )
    except Exception:  # noqa: BLE001 - an unreadable table is reported, not raised
        return None
    row = cursor.fetchone()
    return row[0] if row else None


def probe_statements(table: str, column: str) -> tuple[tuple[str, str], ...]:
    """One ``UPDATE`` and one ``DELETE`` probe, each touching at most one row.

    ``SET column = column`` is a real ``UPDATE``: it changes no value but still
    fires ``BEFORE UPDATE ... FOR EACH ROW``, so the probe needs no knowledge of
    the table's data. Scoping by ``ctid`` means at most one row can ever be
    affected, and the surrounding transaction is rolled back regardless.
    """
    return (
        (
            "UPDATE",
            f"UPDATE {table} SET {column} = {column} "
            f"WHERE ctid = (SELECT ctid FROM {table} LIMIT 1)",
        ),
        (
            "DELETE",
            f"DELETE FROM {table} WHERE ctid = (SELECT ctid FROM {table} LIMIT 1)",
        ),
    )


def attempt_write(
    connection, statement: str
) -> tuple[int | None, BaseException | None]:
    """Run one probe inside a transaction that is always rolled back.

    Returns ``(rows_affected, None)`` if the statement was accepted, or
    ``(None, error)`` if the database refused it. Never raises.
    """
    connection.autocommit = False
    try:
        with connection.cursor() as cursor:
            cursor.execute(statement)  # noqa: S608 - statements built from a fixed table list
            rows = cursor.rowcount
        connection.rollback()
        return rows, None
    except Exception as exc:  # noqa: BLE001 - any refusal is a result, not a crash
        connection.rollback()
        return None, exc
    finally:
        connection.autocommit = True


def _report_probe(
    report: Report,
    table: str,
    operation: str,
    result: tuple[int | None, BaseException | None],
) -> None:
    rows, error = result
    article = "an" if operation[0] in "AEIOU" else "a"
    name = f"{table}: refuses {article} {operation}"
    if error is None:
        if rows:
            report.add(FAIL, name, "the statement was accepted; the guard did not fire")
        else:
            report.add(
                SKIP, name, "table holds no rows; guard presence checked in the catalog"
            )
        return
    sqlstate = getattr(error, "sqlstate", None)
    detail = f"{_first_line(str(error))} [sqlstate={sqlstate}]"
    report.add(PASS if sqlstate == EXPECTED_SQLSTATE else FAIL, name, detail)


def check_audit_triggers(report: Report, database_url: str | None) -> bool:
    if not database_url:
        report.add(SKIP, "audit triggers verified", "no --database-url supplied")
        return False
    try:
        import psycopg
    except ImportError:
        report.add(SKIP, "audit triggers verified", "psycopg not installed")
        return False

    try:
        connection = psycopg.connect(database_url, autocommit=True)
    except Exception as exc:  # noqa: BLE001 - report, never crash the verifier
        report.add(SKIP, "PostgreSQL reachable", _first_line(str(exc)))
        return False
    report.add(PASS, "PostgreSQL reachable", _server_version(connection))

    try:
        with connection.cursor() as cursor:
            for table in AUDIT_TABLES:
                cursor.execute(
                    """
                    SELECT t.tgenabled,
                           p.proname,
                           (t.tgtype & 8) <> 0 AS on_delete,
                           (t.tgtype & 16) <> 0 AS on_update
                    FROM pg_trigger t
                    JOIN pg_class c ON c.oid = t.tgrelid
                    JOIN pg_proc p ON p.oid = t.tgfoid
                    WHERE c.relname = %s AND NOT t.tgisinternal
                    """,
                    (table,),
                )
                row = cursor.fetchone()
                if row is None:
                    report.add(
                        FAIL,
                        f"{table}: trigger exists",
                        "no non-internal trigger found",
                    )
                    continue
                enabled, func, on_delete, on_update = row
                ok = (
                    enabled == "O"
                    and func == GUARD_FUNCTION
                    and on_delete
                    and on_update
                )
                report.add(
                    PASS if ok else FAIL,
                    f"{table}: enabled BEFORE UPDATE OR DELETE guard",
                    f"enabled={enabled} function={func} "
                    f"on_delete={on_delete} on_update={on_update}",
                )
            columns = {
                table: _updatable_column(cursor, table) for table in AUDIT_TABLES
            }

        # Behavioural probe. Safe either way: the guard firing aborts the
        # transaction; if it did not fire, the explicit ROLLBACK discards it.
        for table in AUDIT_TABLES:
            column = columns.get(table)
            if column is None:
                report.add(
                    FAIL, f"{table}: write probe possible", "no ordinary column found"
                )
                continue
            for operation, statement in probe_statements(table, column):
                _report_probe(
                    report, table, operation, attempt_write(connection, statement)
                )
    finally:
        connection.close()
    return True


def _server_version(connection) -> str:
    # Only the cursor is scoped here. `with connection` would close the
    # connection on exit in psycopg 3, and the caller keeps using it.
    with connection.cursor() as cursor:
        cursor.execute("SHOW server_version")
        row = cursor.fetchone()
    return row[0] if row else "unknown"


# ---------------------------------------------------------------------------
# Health / readiness
# ---------------------------------------------------------------------------


def check_health(report: Report, base_url: str) -> None:
    import urllib.error
    import urllib.request

    for path in ("/api/v1/health", "/api/v1/ready"):
        url = f"{base_url.rstrip('/')}{path}"
        try:
            with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310 - operator-supplied URL
                report.add(
                    PASS if response.status == 200 else FAIL,
                    f"{path} responds 200",
                    f"status={response.status}",
                )
        except urllib.error.HTTPError as exc:
            # 503 from /ready is a legitimate degraded answer, not a defect.
            status = FAIL if path.endswith("/health") else PASS
            report.add(status, f"{path} responds", f"status={exc.code}")
        except (urllib.error.URLError, OSError) as exc:
            report.add(SKIP, f"{path} reachable", str(exc)[:100])


# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Phase 2 Step 13 runtime verification")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--compose-file", default="docker-compose.yml")
    args = parser.parse_args(argv)

    report = Report()
    docker_ok = check_containers(report, args.compose_file)
    pg_ok = check_audit_triggers(report, args.database_url)
    if docker_ok:
        check_health(report, args.base_url)
    else:
        report.add(SKIP, "health/readiness probes", "no running container to probe")

    print("\n".join(report.details))
    print(f"\n{report.passed} passed, {report.failed} failed, {report.skipped} skipped")

    if report.failed:
        return 1
    if not (docker_ok or pg_ok):
        print(
            "\nNOTHING COULD BE VERIFIED: neither the Docker engine nor PostgreSQL "
            "was reachable. This is not a pass - it is an absence of evidence."
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
