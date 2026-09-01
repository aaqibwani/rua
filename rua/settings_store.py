"""Configuration held in the database rather than the environment.

Anything an operator sets through the UI lives here: the Graph credentials, the
report mailbox, and the wizard's progress. Environment variables (``rua.config``)
stay for deployment-level settings that must be readable before the database is.

Values flagged ``encrypted`` are Fernet tokens (:mod:`rua.crypto`). Only the Graph
client secret is encrypted today. The tenant and client IDs are stored in the
clear on purpose: they are public identifiers that appear in the token endpoint
URL and in the Entra portal, and encrypting them would imply a confidentiality
property we do not actually provide while making it impossible for an operator to
see which tenant a deployment points at without the key.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from rua.crypto import DecryptionError, decrypt, encrypt
from rua.logging import get_logger
from rua.models import Setting

log = get_logger(__name__)


# ─── Keys ────────────────────────────────────────────────────────────────────
# Namespaced so a listing is self-describing. Adding one means adding it here,
# not scattering string literals through the routes.

SETUP_STEP = "setup.step"
SETUP_COMPLETE = "setup.complete"
SETUP_SCOPING_MODE = "setup.scoping_mode"  # "rbac" | "policy"

GRAPH_TENANT_ID = "graph.tenant_id"
GRAPH_CLIENT_ID = "graph.client_id"
GRAPH_CLIENT_SECRET = "graph.client_secret"
GRAPH_MAILBOX = "graph.mailbox"

VERIFY_GRAPH_OK = "verify.graph.ok"
VERIFY_GRAPH_AT = "verify.graph.at"
VERIFY_GRAPH_FACTS = "verify.graph.facts"
VERIFY_MAILBOX_OK = "verify.mailbox.ok"
VERIFY_MAILBOX_AT = "verify.mailbox.at"
VERIFY_MAILBOX_FACTS = "verify.mailbox.facts"

# Verification results are stamped with the generation of the inputs they were
# produced against, and honoured only at the current generation. That is what
# stops a slow in-flight check from resurrecting a pass after its inputs changed.
#
# There are two counters, not one, and the asymmetry is deliberate:
#
#   credentials change -> both verdicts die (a new tenant makes the old mailbox
#                         probe meaningless as well as the old token test)
#   mailbox changes    -> only the mailbox verdict dies (the token test did not
#                         depend on which mailbox was named)
#
# A single shared counter looks stricter but is actually broken: on a first run
# the operator necessarily sets the mailbox *after* passing the token test, so a
# shared counter invalidates the token test they just watched succeed, and the
# final step then refuses to complete with a message that contradicts the screen.
VERIFY_GENERATION_GRAPH = "verify.generation.graph"
VERIFY_GENERATION_MAILBOX = "verify.generation.mailbox"

ENCRYPTED_KEYS = frozenset({GRAPH_CLIENT_SECRET})


# ─── Primitives ──────────────────────────────────────────────────────────────


def get(session: Session, key: str, default: str | None = None) -> str | None:
    """Read a setting, decrypting if it was stored encrypted."""
    row = session.get(Setting, key)
    if row is None or row.value is None:
        return default
    if not row.encrypted:
        return row.value
    try:
        return decrypt(row.value)
    except DecryptionError:
        # SECRET_KEY almost certainly rotated. Surface as absent rather than
        # raising, so the wizard can ask for the value again instead of 500ing.
        log.error("setting_decrypt_failed", key=key)
        return default


def set_value(session: Session, key: str, value: str | None) -> None:
    """Write a setting, encrypting it when the key is marked as secret."""
    should_encrypt = key in ENCRYPTED_KEYS and value is not None
    stored = encrypt(value) if should_encrypt else value

    row = session.get(Setting, key)
    if row is None:
        session.add(Setting(key=key, value=stored, encrypted=should_encrypt))
    else:
        row.value = stored
        row.encrypted = should_encrypt
    session.flush()


def delete(session: Session, key: str) -> None:
    row = session.get(Setting, key)
    if row is not None:
        session.delete(row)
        session.flush()


def get_bool(session: Session, key: str, default: bool = False) -> bool:
    raw = get(session, key)
    return default if raw is None else raw == "1"


def set_bool(session: Session, key: str, value: bool) -> None:
    set_value(session, key, "1" if value else "0")


def get_int(session: Session, key: str, default: int = 0) -> int:
    raw = get(session, key)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        log.warning("setting_not_an_integer", key=key)
        return default


def set_int(session: Session, key: str, value: int) -> None:
    set_value(session, key, str(value))


def get_json(session: Session, key: str, default: Any = None) -> Any:
    raw = get(session, key)
    if raw is None:
        return default
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        log.warning("setting_not_valid_json", key=key)
        return default


def set_json(session: Session, key: str, value: Any) -> None:
    set_value(session, key, json.dumps(value, separators=(",", ":")))


# ─── Derived ─────────────────────────────────────────────────────────────────


def is_setup_complete(session: Session) -> bool:
    """Whether the first-run wizard has been finished.

    Drives the middleware in both directions: every request goes to the wizard
    until this is true, and the wizard is closed once it is.
    """
    return get_bool(session, SETUP_COMPLETE)


def graph_generation(session: Session) -> int:
    return get_int(session, VERIFY_GENERATION_GRAPH, default=0)


def mailbox_generation(session: Session) -> int:
    return get_int(session, VERIFY_GENERATION_MAILBOX, default=0)


def bump_credentials_generation(session: Session) -> None:
    """A credential changed: both verdicts are now meaningless."""
    _bump(session, VERIFY_GENERATION_GRAPH)
    _bump(session, VERIFY_GENERATION_MAILBOX)


def bump_mailbox_generation(session: Session) -> None:
    """The mailbox changed: the token test still stands, the probe does not."""
    _bump(session, VERIFY_GENERATION_MAILBOX)


def _bump(session: Session, key: str) -> int:
    """Increment a counter in the database rather than in Python.

    ``UPDATE ... SET value = value::int + 1`` is atomic; a read-modify-write is
    not, and two edits arriving together would collapse into one increment and
    leave a superseded verdict looking current.
    """
    from sqlalchemy import text

    result = session.execute(
        text(
            "INSERT INTO setting (key, value, encrypted, updated_at) "
            "VALUES (:key, '1', false, now()) "
            "ON CONFLICT (key) DO UPDATE "
            "SET value = (setting.value::int + 1)::text, updated_at = now() "
            "RETURNING value"
        ),
        {"key": key},
    )
    value = int(result.scalar_one())
    session.flush()
    # The row was changed behind the ORM's back, so drop any cached copy.
    stale = session.get(Setting, key)
    if stale is not None:
        session.refresh(stale)
    return value


def all_settings(session: Session) -> dict[str, str]:
    """Every non-secret setting, for the Settings screen and for debugging.

    Encrypted values are reported as a fixed marker, never decrypted here — the
    wizard copy promises the client secret is "never displayed again".
    """
    rows = session.scalars(select(Setting)).all()
    return {row.key: ("<encrypted>" if row.encrypted else (row.value or "")) for row in rows}
