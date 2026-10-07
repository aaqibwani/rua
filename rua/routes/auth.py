"""Local login for the dashboard.

The wizard creates one administrator; this is where that account is used. Once
setup is complete every page and API path requires a signed-in session (see
:class:`rua.middleware.SetupGateMiddleware`). Before setup completes there is
nothing to protect and no account to protect it with, so the gate sends people
to the wizard instead.

Deliberately minimal, and documented as such in the README and SECURITY.md:
there is no rate limiting, no lockout and no password reset. The account exists
so a fresh deployment is not claimable by whoever reaches the URL first; real
access control is a proxy or a VPN in front of the container.
"""

from __future__ import annotations

import datetime as dt
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from rua import __version__
from rua.db import get_session
from rua.logging import get_logger
from rua.models import AdminUser
from rua.paths import TEMPLATES_DIR
from rua.routes.setup import CSRF_FIELD, CSRF_SESSION_KEY, csrf_token
from rua.security import constant_time_equals, verify_password

log = get_logger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

SessionDep = Annotated[Session, Depends(get_session)]

SESSION_USER_KEY = "admin_id"
LOGIN_PATH = "/login"


def is_signed_in(request: Request) -> bool:
    return request.session.get(SESSION_USER_KEY) == 1


def sign_in(request: Request) -> None:
    """Mark the session as the administrator's. Called on login and on wizard completion."""
    request.session[SESSION_USER_KEY] = 1


def _safe_next(raw: str | None) -> str:
    """Only same-origin paths; an absolute URL here would be an open redirect."""
    if raw and raw.startswith("/") and not raw.startswith("//"):
        return raw
    return "/"


@router.get(LOGIN_PATH, response_class=HTMLResponse, name="login")
def login_form(request: Request, next: str = "/") -> Response:
    if is_signed_in(request):
        return RedirectResponse(_safe_next(next), status_code=303)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"version": __version__, "csrf_token": csrf_token(request), "next": _safe_next(next)},
    )


@router.post(LOGIN_PATH, response_class=HTMLResponse, name="login_submit")
def login_submit(
    request: Request,
    session: SessionDep,
    email: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
    next: Annotated[str, Form()] = "/",
    csrf_token_field: Annotated[str, Form(alias=CSRF_FIELD)] = "",
) -> Response:
    expected = request.session.get(CSRF_SESSION_KEY)
    if not expected or not constant_time_equals(expected, csrf_token_field):
        raise HTTPException(status_code=403, detail="Invalid or missing form token.")

    admin = session.scalar(select(AdminUser).where(AdminUser.email == email.strip().lower()))
    # Verify against a real hash even when the email is unknown, so a wrong email
    # and a wrong password take the same time. The dummy is a fixed argon2 hash
    # of nothing in particular.
    stored = admin.password_hash if admin else _DUMMY_HASH
    ok, rehash = verify_password(stored, password)
    if admin is None or not ok:
        log.warning("login_failed", email_known=admin is not None)
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "version": __version__,
                "csrf_token": csrf_token(request),
                "next": _safe_next(next),
                "error": "That email and password do not match.",
                "email": email,
            },
            status_code=200,
        )

    if rehash:
        admin.password_hash = rehash
    admin.last_login_at = dt.datetime.now(dt.UTC)
    session.flush()
    sign_in(request)
    log.info("login_succeeded")
    return RedirectResponse(_safe_next(next), status_code=303)


@router.post("/logout", name="logout")
def logout(request: Request, csrf_token_field: Annotated[str, Form(alias=CSRF_FIELD)] = ""):
    expected = request.session.get(CSRF_SESSION_KEY)
    if not expected or not constant_time_equals(expected, csrf_token_field):
        raise HTTPException(status_code=403, detail="Invalid or missing form token.")
    request.session.pop(SESSION_USER_KEY, None)
    return RedirectResponse(LOGIN_PATH, status_code=303)


# argon2id hash of a random string, used only to equalise timing on unknown emails.
_DUMMY_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb21lc2FsdA$"
    "Qm9ndXNIYXNoRm9yVGltaW5nRXF1YWxpc2F0aW9uT25seQ"
)
