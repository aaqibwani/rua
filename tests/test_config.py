"""Configuration tests.

``.env.example`` is the contract between a deployment and ``rua.config``. The last
two tests enforce that literally: a variable documented there but missing from
``Settings`` is a bug, and so is the reverse.

Every test here builds ``Settings`` through :func:`make_settings`, which passes
``_env_file=None`` and runs with the relevant environment variables stripped. Without
both, a developer's local ``.env`` or a stray exported variable would leak into the
assertions about defaults.
"""

from __future__ import annotations

import re
import traceback
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from rua.config import MIN_SECRET_KEY_LENGTH, ConfigurationError, Settings, get_settings

VALID: dict[str, Any] = {
    "database_url": "postgresql+psycopg://rua:pw@postgres:5432/rua",
    "secret_key": "s" * MIN_SECRET_KEY_LENGTH,
}

# Documented in .env.example for docker-compose.yml, deliberately not a Settings field.
COMPOSE_ONLY = {"POSTGRES_PASSWORD"}


@pytest.fixture(autouse=True)
def isolate_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip every settings variable so the environment cannot colour the results."""
    for name in Settings.model_fields:
        monkeypatch.delenv(name.upper(), raising=False)
    for name in COMPOSE_ONLY:
        monkeypatch.delenv(name, raising=False)


def make_settings(**overrides: Any) -> Settings:
    """Build Settings from explicit values only — no environment, no .env file."""
    return Settings(_env_file=None, **{**VALID, **overrides})


# ─── Defaults ────────────────────────────────────────────────────────────────


def test_defaults_match_the_documented_ones() -> None:
    s = make_settings()
    assert s.base_url == "http://localhost:8080"
    assert s.ingest_interval_minutes == 60
    assert s.domain_sync_hour == 3
    assert s.retention_raw_days == 90
    assert s.retention_rollup_days == 730
    assert s.alert_webhook_url is None
    assert s.log_level == "INFO"


# ─── Database URL ────────────────────────────────────────────────────────────


def test_bare_postgresql_scheme_is_normalised_to_psycopg() -> None:
    # psycopg2 is not a dependency; a bare postgresql:// URL would fail at connect
    # time with an unhelpful error. Normalising is friendlier than rejecting.
    s = make_settings(database_url="postgresql://rua:pw@postgres:5432/rua")
    assert s.database_url == "postgresql+psycopg://rua:pw@postgres:5432/rua"


@pytest.mark.parametrize(
    "url", ["", "  ", "sqlite:///rua.db", "mysql://rua@localhost/rua", "not-a-url"]
)
def test_non_postgres_urls_are_rejected(url: str) -> None:
    with pytest.raises(ValidationError):
        make_settings(database_url=url)


# ─── Secret key ──────────────────────────────────────────────────────────────


def test_short_secret_key_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_settings(secret_key="short")


def test_secret_key_is_not_leaked_by_repr() -> None:
    s = make_settings()
    assert VALID["secret_key"] not in repr(s)
    assert VALID["secret_key"] not in str(s)


def test_get_settings_does_not_echo_a_rejected_secret_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bad SECRET_KEY must not be printed at start-up.

    Pydantic attaches the rejected input to its own ValidationError, so a deployment
    with a weak key would otherwise write it to stdout on every boot — and boot
    output is what gets pasted into bug reports. get_settings() converts it to a
    scrubbed ConfigurationError and suppresses the original with `from None`.
    """
    weak = "hunter2-far-too-short"
    monkeypatch.setenv("DATABASE_URL", VALID["database_url"])
    monkeypatch.setenv("SECRET_KEY", weak)
    get_settings.cache_clear()

    with pytest.raises(ConfigurationError) as exc:
        get_settings()

    # What actually reaches stdout is the formatted traceback, so assert on that
    # rather than on the exception attributes.
    formatted = "".join(traceback.format_exception(exc.value))
    assert weak not in formatted, "the rejected SECRET_KEY appeared in the traceback"
    assert weak not in str(exc.value), "the rejected SECRET_KEY appeared in the message"

    # `raise ... from None` clears __cause__ and sets __suppress_context__; it does
    # not clear __context__, and the pydantic error still hangs off it. Suppression
    # is what keeps it out of the printed traceback.
    assert exc.value.__cause__ is None
    assert exc.value.__suppress_context__ is True

    assert "SECRET_KEY" in str(exc.value), "the field name should still be named"


def test_get_settings_names_every_missing_required_variable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # get_settings() reads ./.env by design, and a developer running this from the
    # repo root has one. Move to an empty directory so "missing" really is missing.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    get_settings.cache_clear()

    with pytest.raises(ConfigurationError) as exc:
        get_settings()

    message = str(exc.value)
    assert "DATABASE_URL" in message
    assert "SECRET_KEY" in message
    assert ".env.example" in message


# ─── Retention ───────────────────────────────────────────────────────────────


def test_rollup_retention_must_outlive_raw_retention() -> None:
    # Otherwise the nightly job deletes aggregates before the raw rows they came from.
    with pytest.raises(ValidationError):
        make_settings(retention_raw_days=90, retention_rollup_days=30)


def test_equal_retention_windows_are_allowed() -> None:
    assert (
        make_settings(retention_raw_days=90, retention_rollup_days=90).retention_rollup_days == 90
    )


# ─── Scheduling ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("hour", [-1, 24, 99])
def test_domain_sync_hour_must_be_a_valid_utc_hour(hour: int) -> None:
    with pytest.raises(ValidationError):
        make_settings(domain_sync_hour=hour)


@pytest.mark.parametrize("hour", [0, 3, 23])
def test_valid_domain_sync_hours_are_accepted(hour: int) -> None:
    assert make_settings(domain_sync_hour=hour).domain_sync_hour == hour


# ─── Alerting ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_webhook_means_alerting_is_off(blank: str) -> None:
    # "Unset means silence" — .env.example. An empty string must not become a POST target.
    s = make_settings(alert_webhook_url=blank)
    assert s.alert_webhook_url is None
    assert s.alerting_enabled is False


def test_configured_webhook_enables_alerting() -> None:
    assert make_settings(alert_webhook_url="https://example.invalid/hook").alerting_enabled is True


def test_webhook_requires_a_scheme() -> None:
    with pytest.raises(ValidationError):
        make_settings(alert_webhook_url="example.invalid/hook")


# ─── Misc ────────────────────────────────────────────────────────────────────


def test_base_url_trailing_slash_is_stripped() -> None:
    assert make_settings(base_url="https://rua.example.com/").base_url == "https://rua.example.com"


def test_base_url_requires_a_scheme() -> None:
    with pytest.raises(ValidationError):
        make_settings(base_url="rua.example.com")


def test_log_level_is_case_insensitive() -> None:
    assert make_settings(log_level="debug").log_level == "DEBUG"


def test_unknown_log_level_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_settings(log_level="CHATTY")


# ─── The contract ────────────────────────────────────────────────────────────


def _documented_variables(path: Path) -> set[str]:
    """Every ``NAME=`` assignment in .env.example, ignoring comments."""
    names = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([A-Z][A-Z0-9_]*)=", line)
        if match:
            names.add(match.group(1))
    return names


def test_env_example_exists(env_example_path: Path) -> None:
    assert env_example_path.is_file(), ".env.example is the config contract; it must exist"


def test_every_documented_variable_has_a_settings_field(env_example_path: Path) -> None:
    documented = _documented_variables(env_example_path) - COMPOSE_ONLY
    fields = {name.upper() for name in Settings.model_fields}
    missing = documented - fields
    assert not missing, (
        f".env.example documents variables Settings does not read: {sorted(missing)}"
    )


def test_every_settings_field_is_documented(env_example_path: Path) -> None:
    documented = _documented_variables(env_example_path)
    fields = {name.upper() for name in Settings.model_fields}
    undocumented = fields - documented
    assert not undocumented, (
        f"Settings reads variables .env.example does not document: {sorted(undocumented)}"
    )
