"""FastAPI application — the JSON API and the server-rendered frontend.

One package serves both. There is no separate frontend build, no bundler and no
Node toolchain; see the "Recommended frontend approach" section of the handoff
spec for why.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import APIRouter, FastAPI, Response, status
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from rua import __version__
from rua.api import router as api_router
from rua.config import get_settings
from rua.db import check_connection
from rua.logging import configure_logging, get_logger
from rua.middleware import SetupGateMiddleware
from rua.paths import STATIC_DIR
from rua.routes import pages_router, setup_router
from rua.routes.pages import render_error
from rua.security import SESSION_COOKIE, SESSION_MAX_AGE_SECONDS, session_secret

log = get_logger(__name__)
ops_router = APIRouter()


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
    settings = get_settings()

    app = FastAPI(
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

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(ops_router)
    app.include_router(pages_router)
    app.include_router(setup_router)
    app.include_router(api_router)

    # Unhandled exceptions become the spec's error state rather than a bare 500.
    app.add_exception_handler(Exception, render_error)

    # Order matters: middleware added last runs first, so the session must be
    # available by the time the setup gate looks at the request.
    app.add_middleware(SetupGateMiddleware)
    app.add_middleware(
        SessionMiddleware,
        secret_key=session_secret(),
        session_cookie=SESSION_COOKIE,
        max_age=SESSION_MAX_AGE_SECONDS,
        same_site="lax",
        # BASE_URL tells us whether this deployment is served over TLS. Marking
        # the cookie Secure on a plain-http deployment would silently break login.
        https_only=settings.base_url.startswith("https://"),
    )
    return app


@ops_router.get("/healthz", tags=["ops"], summary="Liveness and database connectivity")
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


# Built after the routers are declared, so the factory returns a complete app.
# uvicorn imports this symbol; tests call create_app() for an isolated instance.
app = create_app()
