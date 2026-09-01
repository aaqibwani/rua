"""Request middleware.

One job today: make the first-run wizard unavoidable before setup, and
unreachable after it.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from rua.db import session_scope
from rua.logging import get_logger
from rua.settings_store import is_setup_complete

log = get_logger(__name__)

# Reachable regardless of setup state. /healthz in particular must answer before
# setup, or the container healthcheck fails a correctly-deployed instance and
# Compose restarts it in a loop the operator cannot escape.
EXEMPT_PATHS = frozenset({"/healthz", "/openapi.json", "/favicon.ico"})
EXEMPT_PREFIXES = ("/static",)


class SetupGateMiddleware(BaseHTTPMiddleware):
    """Route everything to the wizard until setup completes, then seal it."""

    def __init__(self, app) -> None:
        super().__init__(app)
        # Setup completes exactly once and never reverts, so the True result can
        # be latched. Until then every request checks, which is the cheap case:
        # a fresh deployment has one user clicking through five steps.
        self._complete = False

    def _setup_complete(self) -> bool:
        if self._complete:
            return True
        try:
            with session_scope() as session:
                complete = is_setup_complete(session)
        except Exception as exc:
            # A database that is down is not a reason to bounce every request
            # into a wizard that also needs the database. Let the request through
            # and let the real handler produce a real error.
            log.error("setup_gate_check_failed", error_type=type(exc).__name__)
            return True
        self._complete = complete
        return complete

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        path = request.url.path
        if path in EXEMPT_PATHS or path.startswith(EXEMPT_PREFIXES):
            return await call_next(request)

        in_wizard = path == "/setup" or path.startswith("/setup/")

        if not self._setup_complete():
            if not in_wizard:
                return RedirectResponse("/setup", status_code=303)
        elif in_wizard:
            # PINNED: the wizard cannot be re-entered to reconfigure ingestion
            # behind the checks. Credential changes belong in Settings.
            return RedirectResponse("/", status_code=303)

        return await call_next(request)
