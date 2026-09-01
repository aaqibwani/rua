"""First-run setup wizard: state, persistence and the rules that gate it.

Five steps. Progress is written to the database after every step, so closing the
browser or restarting the container resumes where it left off — the rail's footer
promises exactly that: "Progress is saved after each step. You can close this and
come back."

Two rules are load-bearing and both are enforced here rather than in the UI:

**The wizard cannot complete without both verifications passing.** A deployment
that looks configured but silently never ingests is the worst outcome for this
tool, so :func:`complete_setup` re-checks the stored verdicts and refuses.

**Editing an input invalidates the verification that depended on it.** Not by
clearing a flag — by bumping a generation counter that every verdict is stamped
with. A verdict from an older generation is ignored. The prototype had a real bug
here: editing a field while a test was in flight reset the status to idle but did
not cancel the pending timer, so the stale result landed ~1s later and marked the
step passed. A counter makes that impossible regardless of ordering.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from rua import settings_store as store
from rua.graph import (
    ENTRA_PERMISSIONS_POLICY,
    ENTRA_PERMISSIONS_RBAC,
    GraphClient,
    GraphCredentials,
    MailboxTest,
    TokenTest,
)
from rua.logging import get_logger
from rua.models import AdminUser
from rua.security import hash_password

log = get_logger(__name__)

FIRST_STEP = 1
LAST_STEP = 5

SCOPING_RBAC = "rbac"
SCOPING_POLICY = "policy"

# Status line copy and tone, from the design. Keys are the persisted verdicts.
GRAPH_TONE = {
    "idle": ("Not tested yet", "muted"),
    "running": ("Testing…", "muted"),
    "ok": ("Connected", "ok"),
    "fail": ("Failed", "gap"),
}
MAILBOX_TONE = {
    "idle": ("Not verified yet", "muted"),
    "running": ("Checking…", "muted"),
    "ok": ("Mailbox reachable", "ok"),
    "fail": ("Unreachable", "gap"),
}


@dataclass
class WizardState:
    """Everything the wizard templates need. Carries no secret."""

    step: int = FIRST_STEP
    complete: bool = False

    admin_exists: bool = False
    admin_name: str = ""
    admin_email: str = ""

    tenant_id: str = ""
    client_id: str = ""
    # The secret itself is never loaded into state: "never logged, never returned
    # by any endpoint, never redisplayed after entry". Only whether one is stored.
    has_secret: bool = False

    mailbox: str = ""
    scoping_mode: str = SCOPING_RBAC

    graph_status: str = "idle"
    graph_facts: list[dict[str, str]] = field(default_factory=list)
    graph_error: str | None = None

    mailbox_status: str = "idle"
    mailbox_facts: list[dict[str, str]] = field(default_factory=list)
    mailbox_error: str | None = None

    @property
    def graph_ok(self) -> bool:
        return self.graph_status == "ok"

    @property
    def mailbox_ok(self) -> bool:
        return self.mailbox_status == "ok"

    def can_advance_from(self, step: int) -> bool:
        """Steps 3 and 4 are gated on their verification; the rest are not."""
        if step == 3:
            return self.graph_ok
        if step == 4:
            return self.mailbox_ok
        return True

    @property
    def credentials_present(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.has_secret)


# ─── Load ────────────────────────────────────────────────────────────────────


def load_state(session: Session) -> WizardState:
    admin = session.scalar(select(AdminUser).limit(1))

    state = WizardState(
        step=store.get_int(session, store.SETUP_STEP, FIRST_STEP),
        complete=store.is_setup_complete(session),
        admin_exists=admin is not None,
        admin_name=admin.name if admin else "",
        admin_email=admin.email if admin else "",
        tenant_id=store.get(session, store.GRAPH_TENANT_ID, "") or "",
        client_id=store.get(session, store.GRAPH_CLIENT_ID, "") or "",
        has_secret=store.get(session, store.GRAPH_CLIENT_SECRET) is not None,
        mailbox=store.get(session, store.GRAPH_MAILBOX, "") or "",
        scoping_mode=store.get(session, store.SETUP_SCOPING_MODE, SCOPING_RBAC) or SCOPING_RBAC,
    )

    # A verdict counts only if it was produced against the inputs still in place.
    # Each is checked against its own counter: naming the mailbox on step 4 must
    # not retroactively un-test the token that was verified on step 3.
    if store.get_int(session, store.VERIFY_GRAPH_OK, -1) == store.graph_generation(session):
        state.graph_status = "ok"
        state.graph_facts = store.get_json(session, store.VERIFY_GRAPH_FACTS, []) or []
    if store.get_int(session, store.VERIFY_MAILBOX_OK, -1) == store.mailbox_generation(session):
        state.mailbox_status = "ok"
        state.mailbox_facts = store.get_json(session, store.VERIFY_MAILBOX_FACTS, []) or []

    return state


# ─── Mutations ───────────────────────────────────────────────────────────────


def save_step(session: Session, step: int) -> None:
    store.set_int(session, store.SETUP_STEP, max(FIRST_STEP, min(LAST_STEP, step)))


def create_admin(session: Session, name: str, email: str, password: str) -> AdminUser:
    """Create or update the single local administrator.

    Re-running step 1 updates the existing row rather than failing: the DB pins
    the primary key to 1, so there is only ever one account to update.
    """
    existing = session.scalar(select(AdminUser).limit(1))
    password_hash = hash_password(password)

    if existing is None:
        admin = AdminUser(id=1, name=name, email=email, password_hash=password_hash)
        session.add(admin)
    else:
        admin = existing
        admin.name = name
        admin.email = email
        admin.password_hash = password_hash

    session.flush()
    # Note the absence of the password and the hash from this log line.
    log.info("admin_account_saved", email=email, created=existing is None)
    return admin


def update_admin_profile(session: Session, name: str, email: str) -> None:
    """Change the administrator's name or email without touching the password.

    Step 1 is revisitable, and on a revisit the password field renders blank
    because a hash cannot be turned back into a password. Submitting the step
    again must therefore not be read as "set an empty password".
    """
    admin = session.scalar(select(AdminUser).limit(1))
    if admin is None:
        raise SetupIncomplete("No administrator account exists yet.")
    if name:
        admin.name = name
    if email:
        admin.email = email
    session.flush()
    log.info("admin_profile_updated", email=admin.email)


def save_credentials(
    session: Session,
    tenant_id: str,
    client_id: str,
    client_secret: str | None,
) -> bool:
    """Persist Graph credentials. Returns whether the Graph verdict was reset.

    ``client_secret`` of ``None`` or empty means "unchanged". That case is not
    cosmetic: on resume the secret field renders blank because the stored value
    is never sent to the browser, so treating a blank submission as an edit would
    wipe a working secret and invalidate a passing test every time the operator
    stepped back through the wizard.
    """
    changed = (
        (store.get(session, store.GRAPH_TENANT_ID, "") or "") != tenant_id
        or (store.get(session, store.GRAPH_CLIENT_ID, "") or "") != client_id
        or bool(client_secret)
    )

    store.set_value(session, store.GRAPH_TENANT_ID, tenant_id)
    store.set_value(session, store.GRAPH_CLIENT_ID, client_id)
    if client_secret:
        store.set_value(session, store.GRAPH_CLIENT_SECRET, client_secret)

    if changed:
        # Both verdicts: a different tenant or client makes the previous mailbox
        # probe as meaningless as the previous token test.
        store.bump_credentials_generation(session)
        log.info("graph_credentials_changed_verifications_reset")
    return changed


def save_mailbox(session: Session, mailbox: str) -> bool:
    """Persist the report mailbox. Returns whether the verdict was reset."""
    changed = (store.get(session, store.GRAPH_MAILBOX, "") or "") != mailbox
    store.set_value(session, store.GRAPH_MAILBOX, mailbox)
    if changed:
        # Only the mailbox verdict. The token test did not depend on which
        # mailbox was named, and on a first run the mailbox is necessarily set
        # after the token test passes.
        store.bump_mailbox_generation(session)
        log.info("report_mailbox_changed_verification_reset")
    return changed


def save_scoping_mode(session: Session, mode: str) -> None:
    store.set_value(
        session,
        store.SETUP_SCOPING_MODE,
        mode if mode in (SCOPING_RBAC, SCOPING_POLICY) else SCOPING_RBAC,
    )


# ─── Verification ────────────────────────────────────────────────────────────


def _credentials(session: Session) -> GraphCredentials | None:
    tenant = store.get(session, store.GRAPH_TENANT_ID)
    client = store.get(session, store.GRAPH_CLIENT_ID)
    secret = store.get(session, store.GRAPH_CLIENT_SECRET)
    if not (tenant and client and secret):
        return None
    return GraphCredentials(tenant_id=tenant, client_id=client, client_secret=secret)


def run_graph_test(session: Session) -> TokenTest:
    """Acquire a token and record the verdict against the credentials generation."""
    generation = store.graph_generation(session)
    credentials = _credentials(session)
    if credentials is None:
        return TokenTest(ok=False, error="Enter all three values before testing.")

    # Which Entra grants to insist on depends on the scoping mode: under RBAC,
    # Mail.Read lives in Exchange and must be absent from Entra, so demanding it
    # in the token's roles claim would fail every correctly-configured tenant.
    mode = store.get(session, store.SETUP_SCOPING_MODE, SCOPING_RBAC) or SCOPING_RBAC
    required = ENTRA_PERMISSIONS_RBAC if mode == SCOPING_RBAC else ENTRA_PERMISSIONS_POLICY

    result = GraphClient(credentials).test_token(required=required)
    _record(
        session,
        store.graph_generation,
        generation,
        result.ok,
        store.VERIFY_GRAPH_OK,
        store.VERIFY_GRAPH_AT,
        store.VERIFY_GRAPH_FACTS,
        result.facts(),
    )
    log.info("graph_token_test", ok=result.ok, permissions=result.permissions, scoping=mode)
    return result


def run_mailbox_test(session: Session) -> MailboxTest:
    """Prove the app can read the report mailbox.

    Under RBAC this is also the only proof that Mail.Read was granted at all, so
    it carries more weight than the design's "Verify access" label suggests.
    """
    generation = store.mailbox_generation(session)
    credentials = _credentials(session)
    if credentials is None:
        return MailboxTest(ok=False, error="Test the Graph connection first.")

    mailbox = store.get(session, store.GRAPH_MAILBOX)
    if not mailbox:
        return MailboxTest(ok=False, error="Enter the mailbox address before verifying.")

    result = GraphClient(credentials).test_mailbox(mailbox)
    _record(
        session,
        store.mailbox_generation,
        generation,
        result.ok,
        store.VERIFY_MAILBOX_OK,
        store.VERIFY_MAILBOX_AT,
        store.VERIFY_MAILBOX_FACTS,
        result.facts(),
    )
    log.info("mailbox_access_test", ok=result.ok, mailbox=mailbox)
    return result


def _record(
    session: Session,
    read_generation: Callable[[Session], int],
    generation: int,
    ok: bool,
    ok_key: str,
    at_key: str,
    facts_key: str,
    facts: list[dict[str, str]],
) -> None:
    """Stamp a verdict with the generation it was produced against.

    If the inputs changed while the check was running, the counter has already
    moved on and this write lands as a stale value that ``load_state`` ignores.
    """
    if read_generation(session) != generation:
        log.info("verification_result_discarded_superseded", key=ok_key)
        return
    if ok:
        store.set_int(session, ok_key, generation)
        store.set_value(session, at_key, dt.datetime.now(dt.UTC).isoformat())
        store.set_json(session, facts_key, facts)
    else:
        store.delete(session, ok_key)
        store.delete(session, facts_key)


# ─── Completion ──────────────────────────────────────────────────────────────


class SetupIncomplete(RuntimeError):
    """Completion was attempted while a precondition was unmet."""


def complete_setup(session: Session) -> None:
    """Mark setup finished. Refuses unless every precondition genuinely holds.

    PINNED: the wizard cannot complete without a successful Graph test and a
    successful mailbox verification. Checked here, against persisted state, so a
    forged POST straight to the final step cannot skip it.
    """
    state = load_state(session)

    problems = []
    if not state.admin_exists:
        problems.append("the administrator account has not been created")
    if not state.credentials_present:
        problems.append("the Graph credentials are incomplete")
    if not state.graph_ok:
        problems.append("the Graph connection test has not passed")
    if not state.mailbox_ok:
        problems.append("the report mailbox has not been verified")

    if problems:
        raise SetupIncomplete("Setup cannot complete: " + "; ".join(problems) + ".")

    store.set_bool(session, store.SETUP_COMPLETE, True)
    store.set_int(session, store.SETUP_STEP, LAST_STEP)
    log.info("setup_completed", mailbox=state.mailbox)
