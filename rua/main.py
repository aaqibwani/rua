"""FastAPI application — the JSON API and the server-rendered frontend.

One package serves both. There is no separate frontend build, no bundler and no
Node toolchain; see the "Recommended frontend approach" section of the handoff
spec for why.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import APIRouter, Depends, FastAPI, Request, Response, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from rua import __version__
from rua.config import get_settings
from rua.db import check_connection, get_session
from rua.logging import configure_logging, get_logger
from rua.middleware import SetupGateMiddleware
from rua.paths import STATIC_DIR, TEMPLATES_DIR
from rua.queries import domain_posture_counts
from rua.routes import setup_router
from rua.security import SESSION_COOKIE, SESSION_MAX_AGE_SECONDS, session_secret
from rua.settings_store import is_demo_mode, is_setup_complete

log = get_logger(__name__)
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

ops_router = APIRouter()
home_router = APIRouter()


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
    app.include_router(home_router)
    app.include_router(setup_router)

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


@home_router.get("/", response_class=HTMLResponse, name="home")
def home(request: Request, session: Annotated[Session, Depends(get_session)]) -> Response:
    """Landing page after setup, and where "Explore with sample data" arrives.

    A holding page until milestone 7 builds the dashboard and milestone 8 the
    day-zero waiting state. It shows the DNS-derived counts because those are
    real and available now — the half of the product that works before a single
    report arrives — rather than pretending there is nothing to see yet.
    """
    counts = domain_posture_counts(session)
    return templates.TemplateResponse(
        request,
        "home.html",
        {
            "version": __version__,
            "demo_mode": is_demo_mode(session) and not is_setup_complete(session),
            "setup_complete": is_setup_complete(session),
            "counts": counts,
            "total_domains": sum(counts.values()),
        },
    )


# Built after the routers are declared, so the factory returns a complete app.
# uvicorn imports this symbol; tests call create_app() for an isolated instance.
app = create_app()
