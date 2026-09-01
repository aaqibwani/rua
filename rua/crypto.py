"""Encryption of secrets held at rest.

Only one secret is stored today — the Microsoft Graph client secret entered in the
setup wizard — but the same envelope is used for anything else that needs it.

``SECRET_KEY`` is an operator-chosen string of arbitrary length, not a Fernet key.
It is run through HKDF-SHA256 with a fixed info label to produce the 32 bytes
Fernet needs. Using the raw value would force operators to generate a
base64-encoded 32-byte key by hand, and a derivation also means a future second
purpose can get its own independent key from the same input by changing the label.

Rotating ``SECRET_KEY`` makes existing ciphertext undecryptable. That is the
documented behaviour ("Rotating it invalidates them"), and :func:`decrypt` reports
it as a distinct error so the UI can say so rather than showing a generic failure.
"""

from __future__ import annotations

import base64
import functools

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from rua.config import get_settings

# Changing this label invalidates every stored ciphertext. It is not a secret; it
# exists to domain-separate this key from any other use of SECRET_KEY.
_HKDF_INFO = b"rua:credential-encryption:v1"


class DecryptionError(RuntimeError):
    """Ciphertext could not be decrypted.

    Almost always means ``SECRET_KEY`` changed since the value was written. The
    message deliberately carries no ciphertext and no key material.
    """


@functools.lru_cache(maxsize=1)
def _fernet() -> Fernet:
    secret = get_settings().secret_key.get_secret_value()
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        # No salt: the key must be reproducible across restarts from SECRET_KEY
        # alone, and HKDF without a salt is well defined (RFC 5869 §3.1). The
        # entropy comes from SECRET_KEY, whose minimum length config enforces.
        salt=None,
        info=_HKDF_INFO,
    ).derive(secret.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt(plaintext: str) -> str:
    """Encrypt a secret for storage. Returns a Fernet token as ASCII text."""
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(token: str) -> str:
    """Decrypt a stored secret.

    Raises :class:`DecryptionError` rather than letting ``InvalidToken`` escape,
    so callers can distinguish "the key rotated" from a programming error.
    """
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        raise DecryptionError(
            "Stored value could not be decrypted. This usually means SECRET_KEY "
            "changed since it was saved; re-enter the credential in Settings."
        ) from exc


def reset_cache() -> None:
    """Drop the derived key. For tests and for a settings reload."""
    _fernet.cache_clear()
