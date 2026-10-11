"""Admission control for heavy flow-store reads, per identity and across identities, in this worker.

The per-identity rate limit stops a fast caller; it does not stop many sessions from multiplying the
load on ClickHouse, or one session from holding several slow reads at once. A heavy read (the
Explorer's five queries, the applications and destinations roll-ups, the baseline load) therefore
takes a slot for its duration, under two rules:

* **One per identity.** An identity runs one heavy read at a time; a second is refused with 429 and
  ``Retry-After``. Opening five tabs does not open five reads.
* **A slot kept back for the detail tier.** Of ``MAX_CONCURRENT_HEAVY`` slots, ``RESERVED_FOR_DETAIL``
  are usable only by callers holding ``traffic:read-detail``, so a crowd of aggregate readers can not
  starve the investigation work.

When no slot is free the request is refused with 503 and ``Retry-After`` rather than queued, so a slow
store can not pile up requests behind it. State is per worker process, like every other in-memory
limit here (see THREAT-MODEL).

The event loop is single-threaded, so plain counters are enough: there is no ``await`` between the
check and the increment.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Final

from netsight_api.errors import ApiError

MAX_CONCURRENT_HEAVY: int = 3
RESERVED_FOR_DETAIL: int = 1
BUSY_CODE: Final = "TRAFFIC_BUSY"
IDENTITY_BUSY_CODE: Final = "TRAFFIC_CONCURRENCY"
REFUSAL_CODES: Final = frozenset({BUSY_CODE, IDENTITY_BUSY_CODE})
BUSY_MESSAGE: Final = "The flow source is busy; retry shortly"
IDENTITY_BUSY_MESSAGE: Final = "A traffic read is already running for this account; retry shortly"

_active = 0
_running: set[str] = set()


def _capacity(*, detail: bool) -> int:
    return MAX_CONCURRENT_HEAVY if detail else max(0, MAX_CONCURRENT_HEAVY - RESERVED_FOR_DETAIL)


@asynccontextmanager
async def heavy_read(identity_id: str, *, detail: bool) -> AsyncIterator[None]:
    """Hold one slot for the duration of the block, or refuse (429 per identity, 503 when full)."""
    global _active
    if identity_id in _running:
        raise ApiError(429, IDENTITY_BUSY_CODE, IDENTITY_BUSY_MESSAGE, headers={"Retry-After": "5"})
    if _active >= _capacity(detail=detail):
        raise ApiError(503, BUSY_CODE, BUSY_MESSAGE, headers={"Retry-After": "5"})
    _active += 1
    _running.add(identity_id)
    try:
        yield
    finally:
        _active -= 1
        _running.discard(identity_id)


def reset_for_tests() -> None:
    """A fresh budget (the tests' autouse fixture calls this)."""
    global _active
    _active = 0
    _running.clear()
