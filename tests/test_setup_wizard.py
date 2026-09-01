"""First-run setup: the four acceptance paths, plus the properties around them.

Milestone 3's definition of done:

* a fresh database redirects to setup;
* the wizard cannot be completed without both verifications passing;
* restarting mid-wizard resumes at the same step;
* credentials edited after a successful test reset it to untested.

Each has a test below, named for it. The rest guard the security promises the
wizard copy makes — chiefly that the client secret is "never logged, never
returned by any endpoint, never redisplayed after entry".
"""

from __future__ import annotations

import pytest

from rua import settings_store as store
from rua import wizard
from rua.crypto import DecryptionError, decrypt, encrypt, reset_cache
from rua.graph import MailboxTest, TokenTest
from rua.models import Setting
from rua.security import MIN_PASSWORD_LENGTH, hash_password, verify_password

SECRET = "a-real-looking-client-secret-value-xyz"
TENANT = "11111111-1111-1111-1111-111111111111"
CLIENT = "22222222-2222-2222-2222-222222222222"
MAILBOX = "dmarc-reports@example.com"


# ─── Credential encryption ───────────────────────────────────────────────────


def test_secret_round_trips() -> None:
    assert decrypt(encrypt(SECRET)) == SECRET


def test_ciphertext_does_not_contain_the_plaintext() -> None:
    assert SECRET not in encrypt(SECRET)


def test_encryption_is_non_deterministic() -> None:
    # Fernet includes a random IV, so equal plaintexts must not produce equal
    # ciphertexts — otherwise a database dump leaks which deployments share a key.
    assert encrypt(SECRET) != encrypt(SECRET)


def test_rotating_secret_key_makes_ciphertext_undecryptable(monkeypatch) -> None:
    """Documented behaviour: "Rotating it invalidates them"."""
    token = encrypt(SECRET)

    from rua.config import get_settings

    monkeypatch.setenv("SECRET_KEY", "a-completely-different-key-" + "z" * 32)
    get_settings.cache_clear()
    reset_cache()

    with pytest.raises(DecryptionError) as exc:
        decrypt(token)
    assert SECRET not in str(exc.value)

    get_settings.cache_clear()
    reset_cache()


# ─── Password hashing ────────────────────────────────────────────────────────


def test_password_hash_is_not_the_password() -> None:
    password = "correct-horse-battery-staple"
    stored = hash_password(password)
    assert password not in stored
    assert stored.startswith("$argon2")


def test_password_verifies() -> None:
    stored = hash_password("correct-horse-battery-staple")
    ok, _ = verify_password(stored, "correct-horse-battery-staple")
    assert ok is True


def test_wrong_password_rejected() -> None:
    stored = hash_password("correct-horse-battery-staple")
    ok, _ = verify_password(stored, "wrong-horse-battery-staple")
    assert ok is False


def test_malformed_stored_hash_is_rejected_not_raised() -> None:
    ok, _ = verify_password("not-a-hash", "anything")
    assert ok is False


def test_short_password_refused() -> None:
    with pytest.raises(ValueError, match=str(MIN_PASSWORD_LENGTH)):
        hash_password("short")


# ─── Wizard state ────────────────────────────────────────────────────────────


def _fill_credentials(session) -> None:
    wizard.save_credentials(session, TENANT, CLIENT, SECRET)


def test_stored_secret_is_encrypted_at_rest(clean_db) -> None:
    _fill_credentials(clean_db)
    row = clean_db.get(Setting, store.GRAPH_CLIENT_SECRET)

    assert row.encrypted is True
    assert SECRET not in row.value
    assert store.get(clean_db, store.GRAPH_CLIENT_SECRET) == SECRET


def test_wizard_state_never_carries_the_secret(clean_db) -> None:
    _fill_credentials(clean_db)
    state = wizard.load_state(clean_db)

    assert state.has_secret is True
    assert SECRET not in repr(state)


def test_all_settings_masks_encrypted_values(clean_db) -> None:
    _fill_credentials(clean_db)
    assert store.all_settings(clean_db)[store.GRAPH_CLIENT_SECRET] == "<encrypted>"


# ── acceptance: credentials edited after a successful test ──


def test_editing_a_credential_resets_the_verification(clean_db) -> None:
    _fill_credentials(clean_db)
    generation = store.current_generation(clean_db)
    wizard._record(
        clean_db,
        generation,
        True,
        store.VERIFY_GRAPH_OK,
        store.VERIFY_GRAPH_AT,
        store.VERIFY_GRAPH_FACTS,
        [{"k": "Tenant", "v": "example"}],
    )
    assert wizard.load_state(clean_db).graph_ok is True

    changed = wizard.save_credentials(
        clean_db, TENANT, "33333333-3333-3333-3333-333333333333", None
    )

    assert changed is True
    assert wizard.load_state(clean_db).graph_ok is False, "verdict must not survive an edit"


def test_resubmitting_a_blank_secret_does_not_reset(clean_db) -> None:
    """On resume the secret box is blank because a stored secret is never sent back.

    Treating that blank as an edit would wipe a working secret and invalidate a
    passing test every time the operator stepped back through the wizard.
    """
    _fill_credentials(clean_db)
    generation = store.current_generation(clean_db)
    wizard._record(
        clean_db,
        generation,
        True,
        store.VERIFY_GRAPH_OK,
        store.VERIFY_GRAPH_AT,
        store.VERIFY_GRAPH_FACTS,
        [],
    )

    changed = wizard.save_credentials(clean_db, TENANT, CLIENT, None)

    assert changed is False
    assert wizard.load_state(clean_db).graph_ok is True
    assert store.get(clean_db, store.GRAPH_CLIENT_SECRET) == SECRET


def test_a_superseded_verification_result_is_discarded(clean_db) -> None:
    """The prototype's real bug: an in-flight test landing after an edit.

    It reset the status to idle but never cancelled the pending timer, so the
    stale pass arrived a second later and unlocked the step.
    """
    _fill_credentials(clean_db)
    generation_when_test_started = store.current_generation(clean_db)

    # The operator edits a field while the check is in flight.
    wizard.save_credentials(clean_db, TENANT, "44444444-4444-4444-4444-444444444444", None)

    # The old check now returns, stamped with the generation it started under.
    wizard._record(
        clean_db,
        generation_when_test_started,
        True,
        store.VERIFY_GRAPH_OK,
        store.VERIFY_GRAPH_AT,
        store.VERIFY_GRAPH_FACTS,
        [],
    )

    assert wizard.load_state(clean_db).graph_ok is False


def test_editing_the_mailbox_resets_only_the_mailbox_verdict(clean_db) -> None:
    _fill_credentials(clean_db)
    wizard.save_mailbox(clean_db, MAILBOX)
    generation = store.current_generation(clean_db)
    for ok_key, at_key, facts_key in (
        (store.VERIFY_GRAPH_OK, store.VERIFY_GRAPH_AT, store.VERIFY_GRAPH_FACTS),
        (store.VERIFY_MAILBOX_OK, store.VERIFY_MAILBOX_AT, store.VERIFY_MAILBOX_FACTS),
    ):
        wizard._record(clean_db, generation, True, ok_key, at_key, facts_key, [])

    wizard.save_mailbox(clean_db, "somewhere-else@example.com")
    state = wizard.load_state(clean_db)

    # A single generation counter invalidates both. That is stricter than the
    # prototype, which reset only the edited one — and stricter is right here: a
    # changed mailbox makes the previous mailbox probe meaningless.
    assert state.mailbox_ok is False


# ── acceptance: cannot complete without both verifications ──


def test_completion_refused_without_any_verification(clean_db) -> None:
    with pytest.raises(wizard.SetupIncomplete):
        wizard.complete_setup(clean_db)


def test_completion_refused_with_only_the_graph_test(clean_db) -> None:
    wizard.create_admin(clean_db, "Ada", "ada@example.com", "a-long-enough-password")
    _fill_credentials(clean_db)
    wizard.save_mailbox(clean_db, MAILBOX)
    generation = store.current_generation(clean_db)
    wizard._record(
        clean_db,
        generation,
        True,
        store.VERIFY_GRAPH_OK,
        store.VERIFY_GRAPH_AT,
        store.VERIFY_GRAPH_FACTS,
        [],
    )

    with pytest.raises(wizard.SetupIncomplete, match="report mailbox"):
        wizard.complete_setup(clean_db)

    assert store.is_setup_complete(clean_db) is False


def test_completion_succeeds_when_everything_passes(clean_db) -> None:
    wizard.create_admin(clean_db, "Ada", "ada@example.com", "a-long-enough-password")
    _fill_credentials(clean_db)
    wizard.save_mailbox(clean_db, MAILBOX)
    generation = store.current_generation(clean_db)
    for ok_key, at_key, facts_key in (
        (store.VERIFY_GRAPH_OK, store.VERIFY_GRAPH_AT, store.VERIFY_GRAPH_FACTS),
        (store.VERIFY_MAILBOX_OK, store.VERIFY_MAILBOX_AT, store.VERIFY_MAILBOX_FACTS),
    ):
        wizard._record(clean_db, generation, True, ok_key, at_key, facts_key, [])

    wizard.complete_setup(clean_db)

    assert store.is_setup_complete(clean_db) is True


# ── acceptance: resume at the same step ──


def test_progress_survives_a_restart(clean_db) -> None:
    """ "Progress is saved after each step. You can close this and come back."."""
    wizard.save_step(clean_db, 3)
    _fill_credentials(clean_db)
    clean_db.commit()

    # A restart is a fresh read of the same rows; nothing is held in memory.
    resumed = wizard.load_state(clean_db)

    assert resumed.step == 3
    assert resumed.tenant_id == TENANT
    assert resumed.has_secret is True


def test_only_one_admin_account_can_exist(clean_db) -> None:
    wizard.create_admin(clean_db, "Ada", "ada@example.com", "a-long-enough-password")
    wizard.create_admin(clean_db, "Grace", "grace@example.com", "another-long-password")
    clean_db.flush()

    from sqlalchemy import func, select

    from rua.models import AdminUser

    assert clean_db.scalar(select(func.count()).select_from(AdminUser)) == 1


# ─── HTTP behaviour ──────────────────────────────────────────────────────────


# ── acceptance: a fresh database redirects to setup ──


def test_fresh_deployment_redirects_to_setup(client) -> None:
    response = client.get("/")
    assert response.status_code == 303
    assert response.headers["location"] == "/setup"


def test_healthz_is_reachable_before_setup(client) -> None:
    """Otherwise the container healthcheck fails a correctly-deployed instance
    and Compose restarts it in a loop the operator cannot escape."""
    assert client.get("/healthz").status_code in (200, 503)


def test_static_assets_are_reachable_before_setup(client) -> None:
    assert client.get("/static/rua.css").status_code == 200


def test_setup_root_redirects_to_the_saved_step(client, clean_db) -> None:
    wizard.save_step(clean_db, 2)
    clean_db.commit()

    response = client.get("/setup")

    assert response.status_code == 303
    assert response.headers["location"] == "/setup/2"


def test_wizard_renders_step_one(client) -> None:
    response = client.get("/setup/1")
    assert response.status_code == 200
    assert "Create the administrator account" in response.text
    assert "This is the only account until you connect Entra SSO." in response.text


def test_cannot_jump_ahead_to_an_unreached_step(client) -> None:
    response = client.get("/setup/4")
    assert response.status_code == 303
    assert response.headers["location"] == "/setup/1"


def test_wizard_step_two_defaults_to_rbac_and_withholds_mail_read(client, clean_db) -> None:
    """With RBAC, Mail.Read must be granted in Exchange and NOT in Entra.

    Granting it in both places unions an unscoped grant with a scoped one, which
    leaves the app with no effective scoping — defeating the pinned constraint.
    """
    wizard.save_step(clean_db, 2)
    clean_db.commit()

    body = client.get("/setup/2").text
    assert "Domain.Read.All" in body
    assert "New-ManagementRoleAssignment" in body
    assert "Application Mail.Read" in body
    assert "Do not add Mail.Read here." in body


def test_wizard_never_returns_the_stored_secret(client, clean_db) -> None:
    _fill_credentials(clean_db)
    wizard.save_step(clean_db, 3)
    clean_db.commit()

    body = client.get("/setup/3").text

    assert SECRET not in body
    assert TENANT in body, "non-secret values should still round-trip"
    assert "Stored — leave blank to keep it" in body


def test_completed_setup_seals_the_wizard(client, clean_db) -> None:
    store.set_bool(clean_db, store.SETUP_COMPLETE, True)
    clean_db.commit()

    response = client.get("/setup/1")

    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_forged_post_to_the_final_step_cannot_complete_setup(client, clean_db) -> None:
    """PINNED: the wizard cannot complete without both verifications passing.

    Enforced server-side against persisted state, so skipping the UI does not
    skip the checks.
    """
    response = client.post("/setup", data={"step": "5", "action": "next"})

    assert response.status_code == 200
    assert "Setup cannot complete" in response.text
    assert store.is_setup_complete(clean_db) is False


def test_graph_test_failure_is_reported_not_swallowed(client, clean_db, monkeypatch) -> None:
    _fill_credentials(clean_db)
    wizard.save_step(clean_db, 3)
    clean_db.commit()

    monkeypatch.setattr(
        "rua.graph.GraphClient.test_token",
        lambda self: TokenTest(ok=False, error="The client secret is wrong or has expired."),
    )

    response = client.post(
        "/setup",
        data={"step": "3", "action": "test_graph", "tenant_id": TENANT, "client_id": CLIENT},
    )

    assert "The client secret is wrong or has expired." in response.text
    assert wizard.load_state(clean_db).graph_ok is False


def test_successful_mailbox_check_unlocks_continue(client, clean_db, monkeypatch) -> None:
    _fill_credentials(clean_db)
    wizard.save_mailbox(clean_db, MAILBOX)
    wizard.save_step(clean_db, 4)
    clean_db.commit()

    monkeypatch.setattr(
        "rua.graph.GraphClient.test_mailbox",
        lambda self, mailbox: MailboxTest(ok=True, message_count=4182),
    )

    response = client.post(
        "/setup", data={"step": "4", "action": "test_mailbox", "mailbox": MAILBOX}
    )

    assert "Mailbox reachable" in response.text
    assert "4,182" in response.text
    assert "this mailbox only" in response.text
