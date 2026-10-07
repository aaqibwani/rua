"""Local login: the dashboard is sealed behind the administrator once setup completes."""

from __future__ import annotations

import re

from rua import settings_store as store
from rua.wizard import create_admin, reset_setup

EMAIL = "ops@example.com"
PASSWORD = "correct horse battery staple"


def _complete(session) -> None:
    create_admin(session, "Ops", EMAIL, PASSWORD)
    store.set_bool(session, store.SETUP_COMPLETE, True)
    session.commit()


def _csrf(client, path: str = "/login") -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', client.get(path).text)
    assert match, f"no CSRF token at {path}"
    return match.group(1)


def _login(client, email: str = EMAIL, password: str = PASSWORD, next_path: str = "/"):
    return client.post(
        "/login",
        data={"email": email, "password": password, "next": next_path, "csrf_token": _csrf(client)},
    )


def test_pages_redirect_to_login_once_setup_is_complete(client, clean_db) -> None:
    _complete(clean_db)
    response = client.get("/domains?days=7")
    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=%2Fdomains%3Fdays%3D7"


def test_api_answers_401_rather_than_redirecting(client, clean_db) -> None:
    _complete(clean_db)
    response = client.get("/api/domains")
    assert response.status_code == 401
    assert response.json() == {"detail": "Sign in required"}


def test_healthz_and_static_stay_open(client, clean_db) -> None:
    _complete(clean_db)
    assert client.get("/healthz").status_code in (200, 503)
    assert client.get("/static/rua.css").status_code == 200


def test_login_with_the_right_password_then_the_dashboard_opens(client, clean_db) -> None:
    _complete(clean_db)
    response = _login(client, next_path="/domains?days=7")
    assert response.status_code == 303
    assert response.headers["location"] == "/domains?days=7"
    assert client.get("/domains?days=7").status_code == 200
    assert client.get("/api/domains").status_code == 200
    assert "Sign out" in client.get("/overview").text


def test_wrong_password_stays_on_the_form_with_an_error(client, clean_db) -> None:
    _complete(clean_db)
    response = _login(client, password="not it, not even close")
    assert response.status_code == 200
    assert "do not match" in response.text
    assert client.get("/domains").status_code == 303, "still signed out"


def test_unknown_email_gets_the_same_answer(client, clean_db) -> None:
    _complete(clean_db)
    response = _login(client, email="nobody@example.com")
    assert response.status_code == 200 and "do not match" in response.text


def test_email_match_is_case_insensitive(client, clean_db) -> None:
    _complete(clean_db)
    assert _login(client, email="OPS@Example.com").status_code == 303


def test_login_requires_the_csrf_token(client, clean_db) -> None:
    _complete(clean_db)
    response = client.post("/login", data={"email": EMAIL, "password": PASSWORD, "next": "/"})
    assert response.status_code == 403


def test_next_cannot_be_an_absolute_url(client, clean_db) -> None:
    _complete(clean_db)
    response = _login(client, next_path="https://evil.example/")
    assert response.headers["location"] == "/"
    client.cookies.clear()  # sign out; a signed-in visit to /login redirects away
    response = _login(client, next_path="//evil.example/")
    assert response.headers["location"] == "/"


def test_logout_ends_the_session(client, clean_db) -> None:
    _complete(clean_db)
    _login(client)
    token = _csrf(client, "/overview")
    response = client.post("/logout", data={"csrf_token": token})
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert client.get("/overview").status_code == 303


def test_login_records_last_login(client, clean_db) -> None:
    from sqlalchemy import select

    from rua.models import AdminUser

    _complete(clean_db)
    _login(client)
    clean_db.expire_all()
    assert clean_db.scalar(select(AdminUser.last_login_at)) is not None


def test_demo_mode_is_not_gated(client, clean_db) -> None:
    """Before setup completes there is no account to protect anything with."""
    store.set_bool(clean_db, store.SETUP_DEMO_MODE, True)
    clean_db.commit()
    assert client.get("/domains").status_code == 200
    assert "Sign out" not in client.get("/domains").text


def test_login_page_before_setup_redirects_to_the_wizard(client, clean_db) -> None:
    assert client.get("/login").status_code == 303
    assert client.get("/login").headers["location"] == "/setup"


def test_reset_setup_reopens_the_wizard_and_keeps_the_account(client, clean_db) -> None:
    from sqlalchemy import func, select

    from rua.models import AdminUser, Domain
    from rua.seed import seed_demo

    _complete(clean_db)
    seed_demo(clean_db)
    store.set_value(clean_db, store.GRAPH_CLIENT_SECRET, "secret")
    store.set_bool(clean_db, store.VERIFY_GRAPH_OK, True)
    clean_db.commit()

    reset_setup(clean_db)
    clean_db.commit()

    assert store.is_setup_complete(clean_db) is False
    assert store.get(clean_db, store.GRAPH_CLIENT_SECRET) is None
    assert store.get_bool(clean_db, store.VERIFY_GRAPH_OK) is False
    assert clean_db.scalar(select(func.count()).select_from(AdminUser)) == 1
    assert clean_db.scalar(select(func.count()).select_from(Domain)) == 60
    # The gate is latched per app instance; a fresh one sees the wizard again.
    from fastapi.testclient import TestClient

    from rua.main import create_app

    with TestClient(create_app(), follow_redirects=False) as fresh:
        assert fresh.get("/").headers["location"] == "/setup"
        assert fresh.get("/setup").headers["location"] == "/setup/3"


def test_cli_has_the_release_subcommands() -> None:
    from rua.cli import _build_parser

    for name in ("migrate", "reset-setup", "retention"):
        assert _build_parser().parse_args([name]).command == name
