"""Alembic environment: runs with the dedicated migration identity.

Step 1 ships with no domain migrations; this file wires the metadata so
future ``alembic revision --autogenerate`` picks up new models.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig

from sqlalchemy import create_engine, pool

from alembic import context

# Ensure ``backend/`` is importable so ``app.models`` resolves.
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import app.models  # noqa: E402,F401
from app.database.base import Base  # noqa: E402
from app.database.credentials import migration_database_url, set_migration_owner  # noqa: E402

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


target_metadata = Base.metadata


def run_migrations_offline() -> None:
    # An offline script has no session to authenticate or inspect, so it
    # cannot prove session_user/current_user before emitting migration DDL.
    raise RuntimeError(
        "SEC-02 requires online Alembic execution with verified migration roles."
    )


def run_migrations_online() -> None:
    connectable = create_engine(migration_database_url(), poolclass=pool.NullPool)
    with connectable.connect() as connection:
        # This must precede context configuration and all migration DDL so
        # every object is created as sec_owner, not sec_migrator.
        set_migration_owner(connection)
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
