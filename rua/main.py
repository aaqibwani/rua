"""FastAPI application — the JSON API and, from milestone 7, the frontend.

One package serves both. There is no separate frontend build, no bundler and no
Node toolchain; see the "Recommended frontend approach" section of the handoff spec
for why.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Response, status

from rua import __version__
from rua.config import get_settings
from rua.db import check_connection
from rua.logging import configure_logging, get_logger

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Configure logging and report readiness once, at start-up."""
    settings = get_settings()
    configure_logging(settings.log_level)
    log.info(
        "starting",
        version=__version__,
        base_url=settings.base_url,
        alerting_enabled=settings.alerting_enabled,
    )
    yield
    log.info("stopping", version=__version__)


def create_app() -> FastAPI:
    """Build the application.

    A factory rather than a bare module-level app so tests can construct an
    instance with settings overridden.
    """
    return FastAPI(
        title="Rua",
        summary="Email-authentication posture for one Microsoft 365 tenant",
        version=__version__,
        lifespan=lifespan,
        # FastAPI's built-in docs load Swagger UI and ReDoc from a public CDN.
        # "No telemetry, and no outbound call the operator did not configure" is a
        # documented promise, so the interactive docs stay off. The schema itself
        # is served locally and costs nothing.
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json",
    )


app = create_app()


@app.get("/healthz", tags=["ops"], summary="Liveness and database connectivity")
def healthz(response: Response) -> dict[str, Any]:
    """Report process health and database reachability.

    Returns 200 when the database answers and 503 when it does not, so the
    Compose and Docker healthchecks fail an instance that cannot serve traffic.

    The body carries no diagnostic detail on purpose: this endpoint is
    unauthenticated and reachable from wherever the container is exposed.
    """
    database_ok = check_connection()
    if not database_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ok" if database_ok else "degraded",
        "version": __version__,
        "database": "ok" if database_ok else "error",
    }
