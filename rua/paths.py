"""Filesystem locations of packaged assets.

Resolved relative to this module so they work identically from a source checkout
and from the installed package inside the container, where the working directory
is /app but the package lives in /venv.
"""

from __future__ import annotations

import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"


def alembic_ini() -> Path:
    """Locate alembic.ini, which sits beside the package rather than inside it.

    A source checkout has it at the repo root next to ``rua/``. The container
    installs the package into /venv but copies the source tree to /app, the
    working directory, so the fallback is the current directory. ``RUA_ALEMBIC_INI``
    overrides both for anyone running from somewhere else.
    """
    override = os.environ.get("RUA_ALEMBIC_INI")
    if override:
        return Path(override)
    beside = PACKAGE_DIR.parent / "alembic.ini"
    if beside.exists():
        return beside
    return Path.cwd() / "alembic.ini"
