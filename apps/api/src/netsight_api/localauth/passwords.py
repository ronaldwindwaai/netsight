"""Password hashing and policy for Netsight-managed credentials (ADR 0010).

Passwords are stored with Argon2id only. Verification is constant-time and
always performs a real Argon2 verification, even for accounts that do not
exist, so response timing does not disclose whether an account is registered.
"""

from __future__ import annotations

import hmac
import secrets
import unicodedata
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHash,
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)

# OWASP-recommended Argon2id parameters: 64 MiB, time cost 3, parallelism 4.
DEFAULT_TIME_COST = 3
DEFAULT_MEMORY_COST_KIB = 64 * 1024
DEFAULT_PARALLELISM = 4

MIN_PASSWORD_LENGTH = 12
# Bounds the Argon2 cost against a request-size denial of service.
MAX_PASSWORD_LENGTH = 1024

_hasher = PasswordHasher(
    time_cost=DEFAULT_TIME_COST,
    memory_cost=DEFAULT_MEMORY_COST_KIB,
    parallelism=DEFAULT_PARALLELISM,
)

# A throwaway hash used to spend equivalent CPU when an account is unknown, so
# "no such user" and "wrong password" are indistinguishable by timing.
_DECOY_HASH = _hasher.hash(secrets.token_urlsafe(32))


class PasswordPolicyError(ValueError):
    """Raised when a candidate password violates the policy."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# A short denylist of passwords that appear constantly in credential-stuffing
# lists. This is a floor, not a substitute for length and MFA.
_COMMON_PASSWORDS = frozenset(
    {
        "123456789012",
        "1234567890123",
        "administrator",
        "changeme1234",
        "iloveyou1234",
        "letmein12345",
        "password1234",
        "password12345",
        "qwerty123456",
        "netsight1234",
    }
)


@dataclass(frozen=True)
class PasswordCheck:
    ok: bool
    code: str | None = None
    message: str | None = None


def check_password_policy(password: str) -> PasswordCheck:
    """Validate a candidate password against the deployment policy."""
    if not isinstance(password, str):
        return PasswordCheck(False, "PASSWORD_INVALID", "Password is not valid")

    if len(password) < MIN_PASSWORD_LENGTH:
        return PasswordCheck(
            False,
            "PASSWORD_TOO_SHORT",
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters",
        )

    if len(password) > MAX_PASSWORD_LENGTH:
        return PasswordCheck(
            False,
            "PASSWORD_TOO_LONG",
            "Password exceeds the maximum permitted length",
        )

    # Normalised comparison for the denylist only: a password that normalises
    # to a common value is still weak even when decorated.
    try:
        normalised = unicodedata.normalize("NFKC", password).casefold()
    except (TypeError, ValueError):
        return PasswordCheck(False, "PASSWORD_INVALID", "Password is not valid")

    if normalised in _COMMON_PASSWORDS:
        return PasswordCheck(
            False,
            "PASSWORD_TOO_COMMON",
            "This password is too common; choose a unique one",
        )

    return PasswordCheck(True)


def hash_password(password: str) -> str:
    """Return an Argon2id PHC string for ``password``."""
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    if len(password) > MAX_PASSWORD_LENGTH:
        # Never hash an unbounded input.
        raise ValueError("password exceeds the maximum permitted length")
    return str(_hasher.hash(password))


def _spend_verification(candidate: str) -> None:
    """Burn equivalent CPU on a throwaway hash.

    Keeps the cost of "no such account" indistinguishable from a real
    verification. Any exception is expected: the decoy never matches.
    """
    try:
        _hasher.verify(_DECOY_HASH, candidate)
    except (VerifyMismatchError, VerificationError, InvalidHash, InvalidHashError):
        pass


def verify_password(stored_hash: str | None, candidate: str) -> bool:
    """Verify ``candidate`` against ``stored_hash``.

    When ``stored_hash`` is absent or malformed a decoy verification is still
    performed so that a missing account costs the same as a wrong password.
    """
    if not isinstance(candidate, str) or len(candidate) > MAX_PASSWORD_LENGTH:
        _spend_verification(secrets.token_urlsafe(16))
        return False

    if not stored_hash:
        _spend_verification(candidate)
        return False

    try:
        _hasher.verify(stored_hash, candidate)
    except (VerifyMismatchError, VerificationError, InvalidHash, InvalidHashError):
        # Covers a wrong password, a malformed hash, and unsupported parameters.
        # None of these may surface as an error to the caller.
        return False
    return True


def needs_rehash(stored_hash: str | None) -> bool:
    """Report whether a stored hash should be upgraded to current parameters."""
    if not stored_hash:
        return True
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except (InvalidHash, InvalidHashError, VerificationError):
        return True


def constant_time_equals(left: str, right: str) -> bool:
    """Compare two strings without leaking their contents by timing."""
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
