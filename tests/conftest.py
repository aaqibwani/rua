"""Shared test fixtures.

Required settings are placed in the environment before any ``rua`` module is
imported, so ``Settings()`` can be constructed without a ``.env`` file. Real
environment variables take precedence over ``.env`` in pydantic-settings, which
keeps these tests deterministic on a developer machine that has one.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

TEST_ENV = {
    # 127.0.0.1, not localhost. Docker publishes the port on IPv4 only, and on
    # Windows `localhost` resolves to ::1 first, where the connect blocks until
    # the OS gives up. connect_timeout turns any such stall into a fast failure.
    "DATABASE_URL": (
        "postgresql+psycopg://rua:testpassword@127.0.0.1:5432/rua_test?connect_timeout=5"
    ),
    "SECRET_KEY": "t" * 48,
}

for _key, _value in TEST_ENV.items():
    os.environ.setdefault(_key, _value)


@pytest.fixture(autouse=True)
def clear_settings_cache():
    """Drop the cached Settings around every test.

    ``get_settings`` is ``lru_cache``d for the process; without this, a test that
    monkeypatches an environment variable would silently read another test's values.
    """
    from rua.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def env_example_path() -> Path:
    return REPO_ROOT / ".env.example"


@pytest.fixture
def clean_db() -> Iterator:
    """A committed, empty database, and a session onto it.

    The rollback-isolated ``db_session`` fixture cannot be used for anything that
    goes through the HTTP stack: the setup-gate middleware opens its own session
    outside request scope, so it would never see uncommitted rows. These tests
    commit for real and truncate before each one instead.
    """
    from sqlalchemy import inspect, text
    from sqlalchemy.exc import SQLAlchemyError

    from rua.crypto import reset_cache as reset_crypto
    from rua.db import get_engine, reset_engine, session_scope
    from rua.security import reset_cache as reset_security

    reset_engine()
    reset_crypto()
    reset_security()

    try:
        engine = get_engine()
        with engine.connect() as probe:
            if not inspect(probe).has_table("domain"):
                pytest.skip("schema not migrated; run `alembic upgrade head` first")
    except SQLAlchemyError as exc:
        pytest.skip(f"no database reachable: {type(exc).__name__}")

    def truncate() -> None:
        with session_scope() as session:
            session.execute(text("TRUNCATE setting, admin_user, domain RESTART IDENTITY CASCADE"))

    truncate()
    with session_scope() as session:
        yield session
    truncate()
    reset_engine()


@pytest.fixture
def client(clean_db):
    """A TestClient on a freshly-built app, so middleware state is not shared."""
    from fastapi.testclient import TestClient

    from rua.main import create_app

    with TestClient(create_app(), follow_redirects=False) as test_client:
        yield test_client


@pytest.fixture
def db_session() -> Iterator:
    """A session wrapped in a transaction that is always rolled back.

    Nothing this fixture yields ever reaches disk, so these tests can run against
    a developer's own database without disturbing it. Skips rather than fails when
    no database is reachable, so `pytest` still works with only the pure unit
    tests available; CI always has one, so the DB tests always run there.
    """
    from sqlalchemy import delete, inspect
    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy.orm import Session

    from rua.db import get_engine, reset_engine

    reset_engine()
    engine = get_engine()

    try:
        connection = engine.connect()
    except SQLAlchemyError as exc:
        pytest.skip(f"no database reachable: {type(exc).__name__}")

    # begin() must come first. Any query — including the has_table() probe below —
    # autobegins a transaction, and an explicit begin() after that raises.
    transaction = connection.begin()

    if not inspect(connection).has_table("domain"):
        transaction.rollback()
        connection.close()
        pytest.skip("schema not migrated; run `alembic upgrade head` first")

    session = Session(bind=connection, join_transaction_mode="create_savepoint")

    # Start from empty inside the transaction, so row counts are absolute rather
    # than relative to whatever the developer happens to have seeded.
    from rua.models import Domain

    session.execute(delete(Domain))
    session.flush()

    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()
        reset_engine()
