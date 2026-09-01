"""Shared test fixtures.

Required settings are placed in the environment before any ``rua`` module is
imported, so ``Settings()`` can be constructed without a ``.env`` file. Real
environment variables take precedence over ``.env`` in pydantic-settings, which
keeps these tests deterministic on a developer machine that has one.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

TEST_ENV = {
    "DATABASE_URL": "postgresql+psycopg://rua:testpassword@localhost:5432/rua_test",
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
