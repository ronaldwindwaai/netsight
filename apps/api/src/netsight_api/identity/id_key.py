"""The server secret behind opaque evidence ids.

A caller who may see an endpoint but not the person behind it still gets evidence ids, so two links
can be seen to rest on one record. A source's native ids can embed a user name or an account id and
are usually guessable, so an unkeyed hash would let that caller confirm a guess. The id is therefore
a keyed HMAC under ``NETSIGHT_IDENTITY_ID_KEY``.

Fail closed: without a usable key (at least 32 characters) nothing opaque is minted and the caller
gets ``unknown``. Only ``NETSIGHT_ENV=development`` may fall back to a random per-process key (ids
then change on restart), and says so once in the log.
"""

from __future__ import annotations

import logging
import os
import secrets
from typing import Final

ID_KEY_ENV: Final = "NETSIGHT_IDENTITY_ID_KEY"
MIN_KEY_LENGTH: Final = 32
_LOGGER = logging.getLogger("netsight_api")
_DEVELOPMENT_KEY: bytes | None = None


class IdKeyUnavailable(RuntimeError):
    """No usable evidence-id key is configured (and this is not a development run)."""


def evidence_id_key() -> bytes:
    global _DEVELOPMENT_KEY
    configured = os.environ.get(ID_KEY_ENV, "").strip()
    if len(configured) >= MIN_KEY_LENGTH:
        return configured.encode()
    if os.environ.get("NETSIGHT_ENV", "").strip().lower() != "development":
        raise IdKeyUnavailable(f"{ID_KEY_ENV} must be set to at least {MIN_KEY_LENGTH} characters")
    if _DEVELOPMENT_KEY is None:
        _DEVELOPMENT_KEY = secrets.token_bytes(MIN_KEY_LENGTH)
        _LOGGER.warning(
            "evidence id key generated for this process only; set %s for stable ids", ID_KEY_ENV
        )
    return _DEVELOPMENT_KEY
