"""Single-use recovery codes for lost authenticators (ADR 0010).

Codes are generated with ``secrets``, stored only as Argon2id hashes, and
consumed on first use so a leaked database cannot be replayed.
"""

from __future__ import annotations

import secrets
from typing import Final

from netsight_api.localauth.passwords import hash_password, verify_password

RECOVERY_CODE_COUNT: Final = 10
# Unambiguous alphabet: no O/0, I/1, or similar, because these codes are read
# off a printed sheet and typed by hand.
_ALPHABET: Final = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_GROUPS: Final = 2
_GROUP_SIZE: Final = 5


def canonical_code(code: str) -> str:
    """Return the canonical comparison form of a recovery code.

    Codes are displayed as ``AAAAA-BBBBB`` but hashed and compared without the
    separator, so a user may type them with the separator, without it, in a
    different case, or with spaces.
    """
    if not isinstance(code, str):
        return ""
    return code.strip().upper().replace(" ", "").replace("-", "")


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Return ``count`` formatted recovery codes."""
    if count < 1 or count > 20:
        raise ValueError("recovery code count out of range")

    codes: list[str] = []
    for _ in range(count):
        body = "".join(secrets.choice(_ALPHABET) for _ in range(_GROUPS * _GROUP_SIZE))
        codes.append(f"{body[:_GROUP_SIZE]}-{body[_GROUP_SIZE:]}")
    return codes


def hash_recovery_codes(codes: list[str]) -> list[str]:
    """Return Argon2id hashes of the canonical form, for storage."""
    return [hash_password(canonical_code(code)) for code in codes]


def consume_recovery_code(stored_hashes: list[str], candidate: str) -> str | None:
    """Return the consumed hash when ``candidate`` matches, else ``None``.

    Every stored hash is verified so that a candidate which matches nothing
    still costs comparable work to one that matches, and the caller can delete
    the returned hash. Argon2 verification is constant-time per entry.
    """
    normalised = canonical_code(candidate)
    if not normalised:
        return None

    matched: str | None = None
    for stored in stored_hashes:
        if verify_password(stored, normalised):
            matched = matched or stored
    return matched