"""Local administrator authentication.

One account, as the wizard copy says: "This is the only account until you connect
Entra SSO." There is no registration endpoint and no password reset — the account
is created once, during setup, and a fresh deployment is claimed by whoever
reaches it first, which is why SECURITY.md tells operators to put Rua behind a
proxy.

Passwords are hashed with Argon2id via ``argon2-cffi``. Sessions are signed
cookies handled by Starlette's ``SessionMiddleware``; the signing key is derived
from ``SECRET_KEY`` rather than being the raw value, so rotating one thing rotates
everything consistently.
"""

from __future__ import annotations

import base64
import functools
import hmac

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from rua.config import get_settings

# Distinct from the credential-encryption label in rua.crypto, so a weakness in
# one context cannot be pivoted into the other.
_SESSION_INFO = b"rua:session-signing:v1"

# The wizard's password placeholder promises "At least 12 characters" and the
# prototype never enforced it. Enforced here, server-side.
MIN_PASSWORD_LENGTH = 12

SESSION_COOKIE = "rua_session"
SESSION_MAX_AGE_SECONDS = 60 * 60 * 12


@functools.lru_cache(maxsize=1)
def _hasher() -> PasswordHasher:
    # argon2-cffi's defaults track the current OWASP guidance; pinning our own
    # numbers here would silently rot. Left explicit so a future change is a
    # deliberate edit rather than a library upgrade nobody noticed.
    return PasswordHasher()


def hash_password(password: str) -> str:
    """Hash a password for storage. The plaintext is never returned or logged."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    return _hasher().hash(password)


def verify_password(stored_hash: str, password: str) -> tuple[bool, str | None]:
    """Check a password against a stored hash.

    Returns ``(ok, new_hash)``. ``new_hash`` is non-None when argon2's parameters
    have moved on and the hash should be rewritten — free upgrades on login.

    A wrong password and a malformed stored hash both return ``False``; neither
    the password nor the hash appears in any exception that escapes.
    """
    try:
        _hasher().verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False, None

    if _hasher().check_needs_rehash(stored_hash):
        return True, _hasher().hash(password)
    return True, None


@functools.lru_cache(maxsize=1)
def session_secret() -> str:
    """Derive the session-cookie signing key from ``SECRET_KEY``."""
    secret = get_settings().secret_key.get_secret_value()
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_SESSION_INFO,
    ).derive(secret.encode("utf-8"))
    return base64.urlsafe_b64encode(derived).decode("ascii")


def constant_time_equals(left: str, right: str) -> bool:
    """Compare two strings without leaking their contents through timing."""
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def reset_cache() -> None:
    """Drop derived material. For tests and for a settings reload."""
    _hasher.cache_clear()
    session_secret.cache_clear()
