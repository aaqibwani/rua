"""Alembic environment.

The database URL comes from ``rua.config`` — that is, from ``DATABASE_URL`` — and not
from ``alembic.ini``. Two reasons: one source of truth for the connection string, and
no credential in a committed file.

The URL is handed to ``create_engine`` directly rather than through
``config.set_main_option``. Alembic runs main options through ConfigParser
interpolation, so a password containing a literal ``%`` would raise there.
"""

from __future__ import annotations

import contextlib
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from rua.config import get_settings
from rua.db import Base

# Importing the models package registers every table on Base.metadata so that
# `alembic revision --autogenerate` can see them. Added in milestone 2; tolerated
# as absent here so that `alembic upgrade head` works on the current tree.
with contextlib.suppress(ModuleNotFoundError):  # pragma: no cover
    import rua.models  # noqa: F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _url() -> str:
    return get_settings().database_url


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting."""
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Connect and run migrations in a transaction."""
    engine = create_engine(_url(), poolclass=pool.NullPool, future=True)
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
