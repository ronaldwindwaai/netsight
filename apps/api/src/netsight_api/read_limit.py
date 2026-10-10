"""Per-identity read rate limit for the incident, security and traffic read surfaces.

Reuses the in-memory sliding-window ``RateLimiter`` that already guards writes, so it
has the same per-worker limitation (see THREAT-MODEL). Authorisation runs first: an
unauthorised caller gets 401/403, never a 429 that would reveal the limiter state.
"""

from __future__ import annotations

import math

from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity

READ_LIMIT_PER_MINUTE = 300
_READ_WINDOW_SECONDS = 60.0
_read_limiter = RateLimiter()


def enforce_read_limit(identity: Identity, family: str) -> None:
    """Raise 429 when ``identity`` exceeds the read budget for ``family``."""
    if not _read_limiter.allow(
        f"{family}:{identity.id}", READ_LIMIT_PER_MINUTE, _READ_WINDOW_SECONDS
    ):
        raise ApiError(
            429,
            "RATE_LIMITED",
            "Too many requests; slow down",
            headers={"Retry-After": str(math.ceil(_READ_WINDOW_SECONDS))},
        )
