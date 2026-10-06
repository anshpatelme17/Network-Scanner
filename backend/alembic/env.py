"""Alembic environment: runs migrations against DATABASE_URL.

Step 1 ships with no domain migrations; this file wires the metadata so
future ``alembic revision --autogenerate`` picks up new models.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

# Ensure ``backend/`` is importable so ``app.models`` resolves.
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import app.models  # noqa: E402,F401
from app.core.config import get_settings  # noqa: E402
from app.database.base import Base  # noqa: E402

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _database_url() -> str:
    override = os.environ.get("DATABASE_URL")
    if override:
        return override
    try:
        return get_settings().database_url
    except Exception:  # noqa: BLE001
        return "postgresql+psycopg://secuser:changeme_in_env@db:5432/security_platform"


config.set_main_option("sqlalchemy.url", _database_url())

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
