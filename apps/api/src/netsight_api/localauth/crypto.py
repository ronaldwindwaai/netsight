"""Envelope encryption for stored TOTP secrets (ADR 0010).

A TOTP secret is a bearer credential for the account's second factor, so it
is encrypted at rest with AES-GCM under a key derived from
``NETSIGHT_SESSION_SECRET``. The secret is only ever returned in plaintext to
the enrolling client.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LENGTH: Final = 32  # AES-256
NONCE_LENGTH: Final = 12  # 96-bit nonce, the AES-GCM standard
_PREFIX: Final = "v1"


class SecretEncryptionError(RuntimeError):
    """Raised when a stored secret cannot be decrypted."""


def _derive_key(master_secret: str) -> bytes:
    """Derive a purpose-scoped AES key from the session secret."""
    if not master_secret:
        raise SecretEncryptionError("no session secret configured")
    return hashlib.sha256(f"netsight:mfa:{master_secret}".encode()).digest()


def encrypt_secret(plaintext: str, master_secret: str) -> str:
    """Encrypt a TOTP secret, returning ``v1:<b64 nonce>:<b64 ciphertext>``."""
    key = _derive_key(master_secret)
    nonce = os.urandom(NONCE_LENGTH)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), _PREFIX.encode("utf-8"))
    return ":".join(
        (
            _PREFIX,
            base64.urlsafe_b64encode(nonce).decode("ascii"),
            base64.urlsafe_b64encode(ciphertext).decode("ascii"),
        )
    )


def decrypt_secret(payload: str, master_secret: str) -> str:
    """Decrypt a stored TOTP secret.

    Uses constant-time comparison for the associated data so a wrong master
    secret cannot be distinguished from a corrupted record by timing.
    """
    try:
        version, nonce_b64, ciphertext_b64 = payload.split(":", 2)
    except (AttributeError, ValueError) as exc:
        raise SecretEncryptionError("stored secret is malformed") from exc

    if not hmac.compare_digest(version, _PREFIX):
        raise SecretEncryptionError("unsupported secret format")

    try:
        nonce = base64.urlsafe_b64decode(nonce_b64)
        ciphertext = base64.urlsafe_b64decode(ciphertext_b64)
    except Exception as exc:
        raise SecretEncryptionError("stored secret is malformed") from exc

    if len(nonce) != NONCE_LENGTH:
        raise SecretEncryptionError("stored secret is malformed")

    try:
        plaintext = AESGCM(_derive_key(master_secret)).decrypt(
            nonce,
            ciphertext,
            _PREFIX.encode("utf-8"),
        )
    except InvalidTag as exc:
        raise SecretEncryptionError("stored secret could not be decrypted") from exc

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SecretEncryptionError("stored secret is malformed") from exc


def is_encrypted(payload: str | None) -> bool:
    """Report whether ``payload`` looks like an encrypted secret envelope."""
    if not isinstance(payload, str):
        return False
    version, separator, remainder = payload.partition(":")
    return bool(separator) and hmac.compare_digest(version, _PREFIX) and remainder.count(":") == 1