# ruff: noqa: I001
from __future__ import annotations

import logging
import os
import sys
from typing import Any, cast

from alembic import context as alembic_context
from sqlalchemy import engine_from_config, pool
from sqlalchemy.engine import Engine

# Ensure project root on path for Base import
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tacacs_server.db.engine import Base  # noqa: E402

context: Any = alembic_context
config = context.config

# Propagate Alembic logs to the application's root logger
# This ensures Alembic uses the same JSON formatter and handlers
alembic_logger = logging.getLogger("alembic")
alembic_logger.handlers = []
alembic_logger.propagate = True
# Never use fileConfig - always propagate to root logger for consistent formatting
# This ensures Alembic logs use the application's JSON formatter

target_metadata = Base.metadata


def get_url() -> str:
    env_url = os.getenv("ALEMBIC_DATABASE_URL")
    if env_url:
        return env_url
    return cast(str, config.get_main_option("sqlalchemy.url"))


def run_migrations_offline() -> None:
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    url = get_url()
    connectable: Engine = engine_from_config(
        config.get_section(config.config_ini_section) or {},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        url=url,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
