"""The first-run setup wizard.

Server-rendered forms with two small islands of vanilla JS. Every step-advance is
a POST that persists before rendering the next step, which is what makes progress
survive a restart.
"""

from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from rua import __version__, wizard
from rua import settings_store as store
from rua.db import get_session
from rua.logging import get_logger
from rua.paths import TEMPLATES_DIR
from rua.security import MIN_PASSWORD_LENGTH, constant_time_equals
from rua.seed import seed_demo

log = get_logger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

SessionDep = Annotated[Session, Depends(get_session)]

RAIL = [
    {"n": 1, "title": "Administrator", "note": "Local account"},
    {"n": 2, "title": "App registration", "note": "Entra and Exchange"},
    {"n": 3, "title": "Credentials", "note": "Tenant, client, secret"},
    {"n": 4, "title": "Report mailbox", "note": "Where reports arrive"},
    {"n": 5, "title": "Review", "note": "Start ingesting"},
]

HEADS = {
    1: {
        "title": "Create the administrator account",
        "blurb": "This instance has no users yet. The account you create here can configure "
        "ingestion and add others later.",
    },
    2: {
        "title": "Register the app in Entra",
        "blurb": "The dashboard reads one mailbox and your verified domain list. Nothing else, "
        "and nothing leaves this deployment.",
    },
    3: {
        "title": "Paste the credentials",
        "blurb": "Three values from the registration you just created. They are stored "
        "encrypted and never displayed again.",
    },
    4: {
        "title": "Point at the report mailbox",
        "blurb": "The shared mailbox your DMARC and TLS-RPT reports already arrive in.",
    },
    5: {
        "title": "Everything checks out",
        "blurb": "Ingestion starts as soon as you finish. The dashboard will be empty until "
        "the first reports land.",
    },
}


def _scoping_script(mode: str, mailbox: str, client_id: str) -> str:
    """The PowerShell an operator runs to scope the app to one mailbox."""
    address = mailbox or "dmarc-reports@yourdomain.com"
    app_id = client_id or "<application-client-id>"

    if mode == wizard.SCOPING_POLICY:
        return (
            "Connect-ExchangeOnline\n\n"
            f"New-ApplicationAccessPolicy `\n"
            f"  -AppId {app_id} `\n"
            f"  -PolicyScopeGroupId {address} `\n"
            f"  -AccessRight RestrictAccess `\n"
            f'  -Description "Rua: report mailbox only"\n\n'
            "# Should return Denied for anything else\n"
            f"Test-ApplicationAccessPolicy -Identity someone-else@yourdomain.com -AppId {app_id}"
        )

    return (
        "Connect-ExchangeOnline\n\n"
        "# ObjectId is from Enterprise applications, NOT App registrations —\n"
        "# the two pages show different values.\n"
        f"New-ServicePrincipal -AppId {app_id} -ObjectId <enterprise-app-object-id> "
        '-DisplayName "Rua"\n\n'
        'New-ManagementScope -Name "Rua report mailbox" `\n'
        f"  -RecipientRestrictionFilter \"PrimarySmtpAddress -eq '{address}'\"\n\n"
        "New-ManagementRoleAssignment -App <enterprise-app-object-id> `\n"
        '  -Role "Application Mail.Read" `\n'
        '  -CustomResourceScope "Rua report mailbox"\n\n'
        "# Bypasses the permission cache, so it answers immediately\n"
        f"Test-ServicePrincipalAuthorization -Identity {app_id} -Resource {address}"
    )


CSRF_SESSION_KEY = "csrf"
CSRF_FIELD = "csrf_token"


def csrf_token(request: Request) -> str:
    """Per-session CSRF token, minted on first render.

    The wizard is unauthenticated by construction — it runs before any account
    exists — so a same-site form post from another page could otherwise drive it.
    The token is compared in constant time and lives in the signed session cookie.
    """
    token = request.session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        request.session[CSRF_SESSION_KEY] = token
    return token


def _context(request: Request, state: wizard.WizardState, error: str | None = None) -> dict:
    graph_text, graph_tone = wizard.GRAPH_TONE[state.graph_status]
    mailbox_text, mailbox_tone = wizard.MAILBOX_TONE[state.mailbox_status]

    return {
        "request": request,
        "csrf_token": csrf_token(request),
        "version": __version__,
        "state": state,
        "steps": RAIL,
        "head": HEADS[state.step],
        "error": error,
        "min_password_length": MIN_PASSWORD_LENGTH,
        "can_advance": state.can_advance_from(state.step),
        "next_label": "Start ingesting" if state.step == wizard.LAST_STEP else "Continue",
        "graph_text": graph_text,
        "graph_tone": graph_tone,
        "mailbox_text": mailbox_text,
        "mailbox_tone": mailbox_tone,
        # With RBAC, Mail.Read is granted in Exchange and must NOT also be granted
        # in Entra — the two grants union into an unscoped one.
        "entra_permissions": (
            "Domain.Read.All"
            if state.scoping_mode == wizard.SCOPING_RBAC
            else "Mail.Read\nDomain.Read.All"
        ),
        "scoping_script": _scoping_script(state.scoping_mode, state.mailbox, state.client_id),
        # `ok` drives the mark. A green tick beside "not tested" would be the
        # wizard asserting the very thing the final step is about to refuse.
        "summary": [
            {
                "label": "Administrator account",
                "value": state.admin_email or "not set",
                "ok": state.admin_exists,
            },
            {
                "label": "Graph connection",
                "value": "tested" if state.graph_ok else "not tested",
                "ok": state.graph_ok,
            },
            {
                "label": "Report mailbox",
                "value": state.mailbox or "not set",
                "ok": state.mailbox_ok,
            },
            {
                "label": "Scoping",
                "value": "App RBAC"
                if state.scoping_mode == wizard.SCOPING_RBAC
                else "access policy",
                "ok": True,
            },
        ],
    }


@router.get("/setup", name="setup_root")
def setup_root(session: SessionDep) -> RedirectResponse:
    state = wizard.load_state(session)
    return RedirectResponse(f"/setup/{state.step}", status_code=303)


@router.get("/setup/{step}", name="setup_step")
def setup_step(request: Request, step: int, session: SessionDep):
    state = wizard.load_state(session)
    # Clamp rather than 404: a bookmarked future step should land somewhere sane.
    if step != state.step and wizard.FIRST_STEP <= step <= state.step:
        wizard.save_step(session, step)
        state = wizard.load_state(session)
    elif step != state.step:
        return RedirectResponse(f"/setup/{state.step}", status_code=303)
    return templates.TemplateResponse(request, "setup/wizard.html", _context(request, state))


@router.post("/setup", name="setup_submit")
def setup_submit(
    request: Request,
    session: SessionDep,
    step: Annotated[int, Form()],
    action: Annotated[str, Form()] = "next",
    name: Annotated[str, Form()] = "",
    email: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
    scoping_mode: Annotated[str, Form()] = wizard.SCOPING_RBAC,
    tenant_id: Annotated[str, Form()] = "",
    client_id: Annotated[str, Form()] = "",
    client_secret: Annotated[str, Form()] = "",
    mailbox: Annotated[str, Form()] = "",
    csrf_token_field: Annotated[str, Form(alias=CSRF_FIELD)] = "",
):
    expected = request.session.get(CSRF_SESSION_KEY)
    if not expected or not constant_time_equals(expected, csrf_token_field):
        # The wizard runs before any account exists, so there is no login to
        # lean on; the token is what stops another page driving setup.
        raise HTTPException(status_code=403, detail="Invalid or missing form token.")

    # Never trust the client's idea of which step it is on. The hidden field only
    # says which form was rendered; the database says how far setup has actually
    # got, and an advance from a step the operator has not reached must not count.
    persisted = wizard.load_state(session).step
    if step != persisted:
        return RedirectResponse(f"/setup/{persisted}", status_code=303)

    error: str | None = None

    # "Explore with sample data" is a detour, not a submission: it must work from
    # any step without the current step being valid or even filled in. Persisting
    # inputs here would make step 1 raise "set a password" and swallow the action
    # before it ever ran.
    if action == "sample":
        seed_demo(session)
        store.set_bool(session, store.SETUP_DEMO_MODE, True)
        log.info("demo_mode_enabled", from_step=step)
        return RedirectResponse("/", status_code=303)

    # Persist this step's inputs before doing anything else, so a failure below
    # still leaves the operator's typing on disk.
    try:
        if step == 1 and action != "back":
            state = wizard.load_state(session)
            if password:
                wizard.create_admin(session, name.strip(), email.strip(), password)
            elif state.admin_exists:
                # Revisiting step 1: the password box is blank because a hash
                # cannot be rendered back into one. Keep the existing password.
                wizard.update_admin_profile(session, name.strip(), email.strip())
            else:
                error = "Set a password to create the administrator account."
        elif step == 2:
            wizard.save_scoping_mode(session, scoping_mode)
        elif step == 3:
            wizard.save_credentials(
                session, tenant_id.strip(), client_id.strip(), client_secret.strip() or None
            )
        elif step == 4:
            wizard.save_mailbox(session, mailbox.strip())
    except ValueError as exc:
        error = str(exc)

    if error is None:
        if action == "test_graph":
            result = wizard.run_graph_test(session)
            error = result.error if not result.ok else None
        elif action == "test_mailbox":
            result = wizard.run_mailbox_test(session)
            error = result.error if not result.ok else None
        elif action == "back":
            wizard.save_step(session, step - 1)
        elif action == "next":
            state = wizard.load_state(session)
            if not state.can_advance_from(step):
                error = "Finish the check on this step before continuing."
            elif step == wizard.LAST_STEP:
                try:
                    wizard.complete_setup(session)
                    return RedirectResponse("/", status_code=303)
                except wizard.SetupIncomplete as exc:
                    error = str(exc)
            else:
                wizard.save_step(session, step + 1)

    state = wizard.load_state(session)
    return templates.TemplateResponse(
        request, "setup/wizard.html", _context(request, state, error), status_code=200
    )
