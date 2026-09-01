"""Application configuration.

Every field here corresponds to a variable in ``.env.example``, which is the contract
between a deployment and this application. Adding a setting means adding it there too,
with the same name and a documented default.

Microsoft Graph credentials are deliberately absent. They are entered in the first-run
wizard and stored encrypted in the database with ``SECRET_KEY``; they never live in the
environment and are never redisplayed.
"""

from __future__ import annotations

import functools
from typing import Literal

from pydantic import Field, SecretStr, ValidationError, ValidationInfo, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

# Long enough that a Fernet key derived from it has real entropy behind it. The wizard
# stores a Graph client secret under this key, so a weak value is a real exposure.
MIN_SECRET_KEY_LENGTH = 32


class Settings(BaseSettings):
    """Settings loaded from the environment, falling back to ``.env``."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        # POSTGRES_PASSWORD is read by docker-compose.yml, not by the application.
        # It is present in .env and must not be treated as an unexpected variable.
        extra="ignore",
    )

    # ─── Required ────────────────────────────────────────────────────────────

    database_url: str = Field(
        description="SQLAlchemy URL for PostgreSQL, using the psycopg (v3) driver.",
    )
    secret_key: SecretStr = Field(
        description="Encrypts stored Graph credentials and signs session cookies.",
    )

    # ─── Optional ────────────────────────────────────────────────────────────

    base_url: str = Field(
        default="http://localhost:8080",
        description="External URL of this deployment, without a trailing slash.",
    )
    ingest_interval_minutes: int = Field(default=60, ge=1, le=1440)
    domain_sync_hour: int = Field(default=3, ge=0, le=23)
    retention_raw_days: int = Field(default=90, ge=1)
    retention_rollup_days: int = Field(default=730, ge=1)
    alert_webhook_url: str | None = Field(default=None)
    log_level: LogLevel = Field(default="INFO")

    # ─── Validation ──────────────────────────────────────────────────────────

    @field_validator("database_url")
    @classmethod
    def _require_postgres_with_psycopg(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("DATABASE_URL must not be empty")
        if v.startswith("postgresql://"):
            # Bare `postgresql://` resolves to psycopg2, which is not a dependency.
            # Normalise rather than fail: this is the single most common misconfiguration.
            return v.replace("postgresql://", "postgresql+psycopg://", 1)
        if not v.startswith("postgresql+psycopg://"):
            raise ValueError(
                "DATABASE_URL must be a PostgreSQL URL using the psycopg driver, "
                "e.g. postgresql+psycopg://rua:PASSWORD@postgres:5432/rua"
            )
        return v

    @field_validator("secret_key")
    @classmethod
    def _require_strong_secret(cls, v: SecretStr) -> SecretStr:
        raw = v.get_secret_value()
        if len(raw) < MIN_SECRET_KEY_LENGTH:
            # The value itself is never echoed, here or anywhere else.
            raise ValueError(
                f"SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters. "
                'Generate one with: python -c "import secrets; '
                'print(secrets.token_urlsafe(48))"'
            )
        if raw.strip() != raw:
            raise ValueError("SECRET_KEY must not have leading or trailing whitespace")
        return v

    @field_validator("base_url")
    @classmethod
    def _strip_trailing_slash(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if not v.startswith(("http://", "https://")):
            raise ValueError("BASE_URL must start with http:// or https://")
        return v

    @field_validator("alert_webhook_url", mode="before")
    @classmethod
    def _blank_webhook_means_unset(cls, v: object) -> object:
        # An unset webhook must be silence, not an error and not an empty POST target.
        if isinstance(v, str) and not v.strip():
            return None
        return v

    @field_validator("alert_webhook_url")
    @classmethod
    def _webhook_must_be_https(cls, v: str | None) -> str | None:
        if v is not None and not v.startswith(("http://", "https://")):
            raise ValueError("ALERT_WEBHOOK_URL must start with http:// or https://")
        return v

    @field_validator("retention_rollup_days")
    @classmethod
    def _rollups_outlive_raw(cls, v: int, info: ValidationInfo) -> int:
        raw = info.data.get("retention_raw_days")
        if raw is not None and v < raw:
            raise ValueError(
                f"RETENTION_ROLLUP_DAYS ({v}) must be >= RETENTION_RAW_DAYS ({raw}); "
                "otherwise the nightly job would delete aggregates before the raw rows "
                "they were built from."
            )
        return v

    @field_validator("log_level", mode="before")
    @classmethod
    def _uppercase_log_level(cls, v: object) -> object:
        return v.strip().upper() if isinstance(v, str) else v

    # ─── Derived ─────────────────────────────────────────────────────────────

    @property
    def alerting_enabled(self) -> bool:
        """Unset webhook means silence — see ``.env.example``."""
        return self.alert_webhook_url is not None


class ConfigurationError(RuntimeError):
    """The environment does not satisfy the contract in ``.env.example``."""


def _describe(exc: ValidationError) -> str:
    """Render a validation failure without echoing any submitted value.

    Pydantic attaches the offending input to every error it raises. For most
    settings that is helpful; for ``SECRET_KEY`` it means a misconfigured
    deployment prints the key to stdout on every start-up, and start-up output is
    exactly what ends up pasted into a bug report. Only the field name and the
    message are reproduced here.
    """
    lines = []
    for err in exc.errors(include_url=False, include_input=False, include_context=False):
        location = ".".join(str(part) for part in err["loc"]) or "(root)"
        message = err["msg"].removeprefix("Value error, ")
        lines.append(f"  {location.upper()}: {message}")
    return "Invalid configuration. See .env.example for the contract.\n" + "\n".join(lines)


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings, constructed once.

    Cached so that a missing or invalid variable fails once, loudly, at first use
    rather than intermittently. Tests that need different values should call
    ``get_settings.cache_clear()``.

    This is the only sanctioned way to build ``Settings``. Constructing the model
    directly propagates pydantic's own ``ValidationError``, which carries the
    rejected input; this wrapper raises a scrubbed ``ConfigurationError`` instead
    and suppresses the original with ``from None`` so it cannot surface in a
    chained traceback.
    """
    try:
        return Settings()  # type: ignore[call-arg]  # values come from env/.env
    except ValidationError as exc:
        raise ConfigurationError(_describe(exc)) from None
