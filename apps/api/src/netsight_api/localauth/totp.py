"""TOTP (RFC 6238) for Netsight local accounts (ADR 0010).

Implemented against the standard library only. The construction is short and
auditable (HMAC-SHA-1 over an 8-byte big-endian counter, dynamic truncation),
and the test suite verifies it against the published RFC test vectors.

Compatibility note: HMAC-SHA-1 with a 6-digit code and a 30-second step is
deliberate. It is what authenticator applications expect, and RFC 6238
mandates SHA-1 as the default. This is a one-time-password construction, not a
password hash, so SHA-1's collision weakness is not the relevant risk.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import Final

DIGITS: Final = 6
PERIOD_SECONDS: Final = 30
SECRET_BYTES: Final = 20
# Accept one step either side to tolerate clock drift, and nothing more.
ALLOWED_DRIFT_STEPS: Final = 1
ISSUER: Final = "Netsight"
ALGORITHM: Final = "SHA1"


def generate_secret() -> str:
    """Return a new base32 TOTP secret."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    if not isinstance(secret, str) or not secret:
        raise ValueError("secret must be a non-empty base32 string")
    padded = secret.upper() + "=" * (-len(secret) % 8)
    try:
        raw = base64.b32decode(padded, casefold=True)
    except Exception as exc:  # binascii.Error and friends
        raise ValueError("secret is not valid base32") from exc
    if len(raw) < 16:
        raise ValueError("secret is too short")
    return raw


def _hotp(key: bytes, counter: int, digits: int = DIGITS) -> str:
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


def generate_code(secret: str, for_time: float | None = None) -> str:
    """Return the TOTP code for ``secret`` at ``for_time`` (default: now)."""
    key = _decode_secret(secret)
    timestamp = time.time() if for_time is None else for_time
    counter = int(timestamp // PERIOD_SECONDS)
    return _hotp(key, counter)


def verify_code(
    secret: str,
    candidate: str,
    *,
    for_time: float | None = None,
    drift_steps: int = ALLOWED_DRIFT_STEPS,
    last_used_counter: int | None = None,
) -> int | None:
    """Verify ``candidate`` and return the matched counter, or ``None``.

    ``last_used_counter`` rejects replay: once a step's code is accepted, the
    same step cannot be reused. Without this, a shoulder-surfed or logged code
    would remain valid for the rest of its window.
    """
    if not isinstance(candidate, str):
        return None
    normalised = candidate.strip().replace(" ", "").replace("-", "")
    if len(normalised) != DIGITS or not normalised.isdigit():
        return None

    try:
        key = _decode_secret(secret)
    except ValueError:
        return None

    timestamp = time.time() if for_time is None else for_time
    current = int(timestamp // PERIOD_SECONDS)

    # Prefer the newest step so replay protection records the freshest counter.
    for offset in range(-drift_steps, drift_steps + 1):
        counter = current + offset
        expected = _hotp(key, counter)
        if hmac.compare_digest(expected, normalised):
            if last_used_counter is not None and counter <= last_used_counter:
                return None
            return counter
    return None


def provisioning_uri(secret: str, account: str) -> str:
    """Return the ``otpauth://`` URI an authenticator app scans."""
    from urllib.parse import quote

    label = quote(f"{ISSUER}:{account}", safe="")
    return (
        f"otpauth://totp/{label}"
        f"?secret={secret.upper()}"
        f"&issuer={quote(ISSUER, safe='')}"
        f"&algorithm={ALGORITHM}"
        f"&digits={DIGITS}"
        f"&period={PERIOD_SECONDS}"
    )


def qr_code_svg(secret: str, account: str) -> str:
    """Return an inline SVG QR code for the provisioning URI.

    Uses the SVG factory so no native imaging library is pulled in.
    """
    import io

    import qrcode
    import qrcode.image.svg

    image = qrcode.make(provisioning_uri(secret, account), image_factory=qrcode.image.svg.SvgImage)
    buffer = io.BytesIO()
    image.save(buffer)
    return buffer.getvalue().decode("utf-8")
