"""Database engine, session handling and the declarative base.

Synchronous SQLAlchemy, deliberately. The scheduler, the DNS checker and (from
milestone 4) parsedmarc are all synchronous; FastAPI runs sync path operations in a
threadpool, so a sync engine avoids maintaining two dialects of everything for no
measured benefit. Revisit only if a real concurrency problem shows up.
"""

from __future__ import annotations

import functools
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from rua.config import get_settings
from rua.logging import get_logger

log = get_logger(__name__)


class Base(DeclarativeBase):
    """Declarative base shared by every model and seen by Alembic autogenerate."""


@functools.lru_cache(maxsize=1)
def get_engine() -> Engine:
    """Return the process-wide engine, created on first use.

    Lazy so that importing this module — which the CLI and the tests both do —
    does not require a reachable database.
    """
    settings = get_settings()
    return create_engine(
        settings.database_url,
        # Recycle dead connections rather than failing a request after the
        # database restarts underneath a long-lived scheduler process.
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
        pool_recycle=1800,
        # Never True: echoed SQL includes bound parameters, and those include the
        # encrypted credential blob and password hashes.
        echo=False,
        future=True,
    )


@functools.lru_cache(maxsize=1)
def get_sessionmaker() -> sessionmaker[Session]:
    """Return the process-wide session factory."""
    return sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Provide a transactional scope: commit on success, roll back on error."""
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_session() -> Iterator[Session]:
    """FastAPI dependency yielding a session for the life of one request."""
    with session_scope() as session:
        yield session


def check_connection() -> bool:
    """Return whether a trivial query succeeds.

    The failure detail is logged, never returned. ``/healthz`` is unauthenticated
    and a SQLAlchemy error string can contain the DSN, including the password.
    """
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        log.error("database_health_check_failed", error_type=type(exc).__name__)
        return False
    except Exception as exc:  # configuration errors, bad driver, unresolvable host
        log.error("database_health_check_errored", error_type=type(exc).__name__)
        return False
    return True


def reset_engine() -> None:
    """Dispose the engine and clear the caches. For tests and config reloads."""
    if get_engine.cache_info().currsize:
        get_engine().dispose()
    get_engine.cache_clear()
    get_sessionmaker.cache_clear()
