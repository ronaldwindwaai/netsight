"""Limits that are global, not per identity, for the one question that cannot be cached.

A question about a past time cannot share a snapshot (the window differs with every ``at``), so each
one fans out to every evidence source. The per-identity budget stops one caller; it does not stop
many callers, or a handful of sessions, from multiplying the upstream load. Two guards cover that:

* a global budget of historical resolves per minute, across all identities;
* a cap on how many such reads run at once (a non-blocking slot: busy is refused, never queued).

Both are per worker process, like every other in-memory limiter here (see THREAT-MODEL).
Every refusal carries a static ``reason`` so the audit trail never needs to echo input.
"""

from __future__ import annotations

import math
from collections.abc import Iterator
from contextlib import contextmanager
from threading import BoundedSemaphore
from typing import Final

from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.errors import ApiError

HISTORICAL_GLOBAL_LIMIT_PER_MINUTE = 20
MAX_CONCURRENT_HISTORICAL = 2
BUSY_MESSAGE: Final = "The history lookup is busy; retry shortly"
_WINDOW_SECONDS: Final = 60.0
_GLOBAL_KEY: Final = "identity-resolve-historical"

_limiter = RateLimiter()
_slots = BoundedSemaphore(MAX_CONCURRENT_HISTORICAL)


class Refusal(ApiError):
    """An intentional refusal with a static, audit-safe reason code."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        reason: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(status_code, code, message, headers=headers)
        self.reason = reason


def admit_historical() -> None:
    """Spend one unit of the global historical budget, or refuse with 429."""
    if not _limiter.allow(_GLOBAL_KEY, HISTORICAL_GLOBAL_LIMIT_PER_MINUTE, _WINDOW_SECONDS):
        raise Refusal(
            429,
            "RATE_LIMITED",
            "Too many requests; slow down",
            "global-limit",
            headers={"Retry-After": str(math.ceil(_WINDOW_SECONDS))},
        )


@contextmanager
def historical_slot() -> Iterator[None]:
    """Hold one of the concurrent-read slots for the duration of the block, or refuse with 503."""
    if not _slots.acquire(blocking=False):
        raise Refusal(503, "IDENTITY_BUSY", BUSY_MESSAGE, "busy", headers={"Retry-After": "5"})
    try:
        yield
    finally:
        _slots.release()


def reset_for_tests() -> None:
    """A fresh budget and fresh slots (the tests' fixture calls this)."""
    global _limiter, _slots
    _limiter = RateLimiter()
    _slots = BoundedSemaphore(MAX_CONCURRENT_HISTORICAL)
