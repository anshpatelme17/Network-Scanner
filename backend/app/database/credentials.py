"""Read database connection secrets from mounted files without echoing them."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path


def read_database_url_file(path: str | None, setting_name: str) -> str:
    """Read a non-empty DSN from a secret file using safe error messages."""
    if not isinstance(path, str) or not path.strip():
        raise ValueError(f"{setting_name} is required.")
    try:
        database_url = Path(path).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        raise ValueError(f"{setting_name} could not be read.") from None
    if not database_url:
        raise ValueError(f"{setting_name} is empty.")
    if "\n" in database_url or "\r" in database_url:
        raise ValueError(f"{setting_name} must contain one line.")
    return database_url


def migration_database_url(environ: Mapping[str, str] | None = None) -> str:
    """Return only the migration DSN; never fall back to runtime credentials."""
    source = os.environ if environ is None else environ
    path = source.get("MIGRATION_DATABASE_URL_FILE")
    if not path:
        raise ValueError("MIGRATION_DATABASE_URL_FILE is required for Alembic.")
    return read_database_url_file(path, "MIGRATION_DATABASE_URL_FILE")


def set_migration_owner(connection) -> None:
    """Switch roles and verify the dedicated migration identity.

    This runs before Alembic configuration can issue any DDL. Generic errors
    intentionally omit connection and driver details.
    """
    try:
        connection.exec_driver_sql("SET ROLE sec_owner")
        identities = connection.exec_driver_sql(
            "SELECT session_user, current_user"
        ).fetchone()
        if identities != ("sec_migrator", "sec_owner"):
            raise RuntimeError

        # SQLAlchemy 2.x autobegins on the SET ROLE / SELECT statements.
        # COMMIT ends this verification transaction without resetting the
        # session-level role selected by SET ROLE.
        connection.commit()

        # Confirm that the role survived the transaction boundary, then end
        # this read transaction too so Alembic starts with a clean connection.
        identities = connection.exec_driver_sql(
            "SELECT session_user, current_user"
        ).fetchone()
        if identities != ("sec_migrator", "sec_owner"):
            raise RuntimeError
        connection.commit()
    except Exception:  # noqa: BLE001 - driver errors can contain connection details
        try:
            connection.rollback()
        except Exception:  # noqa: BLE001 - preserve the generic failure
            pass
        raise RuntimeError("SEC-02 migration identity verification failed.") from None
