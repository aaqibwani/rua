"""Filesystem locations of packaged assets.

Resolved relative to this module so they work identically from a source checkout
and from the installed package inside the container, where the working directory
is /app but the package lives in /venv.
"""

from __future__ import annotations

from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"
