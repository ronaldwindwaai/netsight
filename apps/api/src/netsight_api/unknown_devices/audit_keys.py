"""A keyed fingerprint of an identifier for the audit trail (Step 8 review fix, security low).

The audit trail may say "the same person was assigned twice" without saying who. A plain hash of a
short identifier can be reversed by trying candidates, so the fingerprint is an HMAC under the
audit key the platform already has (``NETSIGHT_AUDIT_FILTER_KEY``, else the identity evidence-id
key ``NETSIGHT_IDENTITY_ID_KEY``; at least 32 characters). With no usable key the fingerprint is
**omitted**, never degraded to a plain hash; one warning says so.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from collections.abc import Mapping
from typing import Final

from netsight_api.identity.id_key import ID_KEY_ENV

_LOGGER: Final = logging.getLogger("netsight_api")

AUDIT_KEY_ENV: Final = "NETSIGHT_AUDIT_FILTER_KEY"
MIN_KEY_LENGTH: Final = 32
FINGERPRINT_LENGTH: Final = 16
_CONTEXT: Final = b"netsight.audit.unknown-device.v1"
_warned = False


def _key(env: Mapping[str, str]) -> bytes | None:
    dedicated = env.get(AUDIT_KEY_ENV, "").strip()
    if dedicated:
        # A dedicated key that is too short is not replaced by another key: that would be a
        # silent change of what the fingerprints mean.
        return dedicated.encode() if len(dedicated) >= MIN_KEY_LENGTH else None
    configured = env.get(ID_KEY_ENV, "").strip()
    return configured.encode() if len(configured) >= MIN_KEY_LENGTH else None


def keyed_fingerprint(name: str, value: str, env: Mapping[str, str] | None = None) -> str | None:
    """``HMAC-SHA256(key, context | name | value)``, truncated; ``None`` without a usable key."""
    global _warned
    key = _key(os.environ if env is None else env)
    if key is None:
        if not _warned:
            _warned = True
            _LOGGER.warning(
                "no audit key of %d characters is configured (%s or %s); "
                "unknown-device audit fingerprints are omitted",
                MIN_KEY_LENGTH,
                AUDIT_KEY_ENV,
                ID_KEY_ENV,
            )
        return None
    message = b"\x00".join((_CONTEXT, name.encode(), value.encode("utf-8", "surrogatepass")))
    return hmac.new(key, message, hashlib.sha256).hexdigest()[:FINGERPRINT_LENGTH]


def reset_for_tests() -> None:
    global _warned
    _warned = False
