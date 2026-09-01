"""Request middleware.

One job today: make the first-run wizard unavoidable before setup, and
unreachable after it.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from fastapi.responses import PlainTextResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from rua.db import session_scope
from rua.logging import get_logger
from rua.settings_store import is_demo_mode, is_setup_complete

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

    def _state(self) -> tuple[bool, bool] | None:
        """``(setup_complete, demo_mode)``, or None when the answer is unknown.

        None matters. Treating a database failure as "complete" sealed the wizard
        and served the post-setup page, telling an operator whose database was
        down that setup had finished. Treating it as "incomplete" would be just
        as wrong on a configured deployment. Neither is a fact, so the caller
        says so instead of guessing.

        Only ``complete`` is latched. Demo mode is turned on mid-session by the
        wizard's "Explore with sample data", so caching it would leave the gate
        redirecting the very request that just enabled it.
        """
        if self._complete:
            return True, False
        try:
            with session_scope() as session:
                complete = is_setup_complete(session)
                demo = is_demo_mode(session)
        except Exception as exc:
            log.error("setup_gate_check_failed", error_type=type(exc).__name__)
            return None
        self._complete = complete
        return complete, demo

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        path = request.url.path
        if path in EXEMPT_PATHS or path.startswith(EXEMPT_PREFIXES):
            return await call_next(request)

        in_wizard = path == "/setup" or path.startswith("/setup/")
        state = self._state()

        if state is None:
            # /healthz is already exempt above and reports the real cause.
            return PlainTextResponse(
                "Rua cannot reach its database, so it cannot tell whether setup is "
                "complete. See /healthz and the container logs.",
                status_code=503,
            )

        complete, demo = state

        if complete:
            if in_wizard:
                # PINNED: the wizard cannot be re-entered to reconfigure ingestion
                # behind the checks. Credential changes belong in Settings.
                return RedirectResponse("/", status_code=303)
        elif not demo and not in_wizard:
            return RedirectResponse("/setup", status_code=303)
        # Demo mode with setup unfinished: both the dashboard and the wizard stay
        # open, because the operator is meant to look around and then go back and
        # finish. Nothing here marks setup complete.

        return await call_next(request)
