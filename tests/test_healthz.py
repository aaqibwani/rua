"""Health endpoint tests.

``/healthz`` backs both the Docker HEALTHCHECK and the Compose healthcheck, so the
status code — not just the body — is load-bearing. It is also unauthenticated, so it
must not leak diagnostic detail.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from rua import __version__
from rua.main import app


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_healthz_returns_200_when_the_database_answers(client, monkeypatch) -> None:
    monkeypatch.setattr("rua.main.check_connection", lambda: True)
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__, "database": "ok"}


def test_healthz_returns_503_when_the_database_is_unreachable(client, monkeypatch) -> None:
    # The Compose healthcheck must fail an instance that cannot serve traffic.
    monkeypatch.setattr("rua.main.check_connection", lambda: False)
    response = client.get("/healthz")
    assert response.status_code == 503
    assert response.json() == {"status": "degraded", "version": __version__, "database": "error"}


def test_healthz_reports_the_package_version(client, monkeypatch) -> None:
    monkeypatch.setattr("rua.main.check_connection", lambda: True)
    assert client.get("/healthz").json()["version"] == __version__


def test_healthz_leaks_no_connection_detail(client, monkeypatch) -> None:
    """A SQLAlchemy error string can carry the DSN, password included."""
    monkeypatch.setattr("rua.main.check_connection", lambda: False)
    body = client.get("/healthz").text
    for secret in ("postgresql", "psycopg", "password", "testpassword", "@localhost"):
        assert secret not in body.lower(), f"/healthz body leaked {secret!r}"


def test_interactive_docs_are_disabled(client) -> None:
    # Swagger UI and ReDoc pull assets from a public CDN. "No outbound call the
    # operator did not configure" is a documented promise.
    #
    # Asserted on the route table rather than on a 404: since milestone 3 the
    # setup gate redirects unknown paths to the wizard, so a status code alone
    # would no longer distinguish "not registered" from "bounced by middleware".
    from rua.main import app

    paths = {route.path for route in app.routes if hasattr(route, "path")}
    assert "/docs" not in paths
    assert "/redoc" not in paths

    for path in ("/docs", "/redoc"):
        response = client.get(path, follow_redirects=False)
        assert response.status_code != 200
        assert "swagger" not in response.text.lower()


def test_openapi_schema_is_served_locally(client) -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert response.json()["info"]["version"] == __version__
