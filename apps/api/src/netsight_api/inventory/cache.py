"""A one-entry, short-lived cache for a read of several external systems (Step 8).

Inventory, IPAM and the unknown-device scan each read NetBox, LibreNMS and Wazuh. A page refresh or
two operators opening the same screen must not multiply those reads, so one result is kept for a
few seconds and concurrent callers wait for the one load. A failed load is not cached. The lock is
bound to the running event loop (a test, or a reloaded worker, gets a fresh one).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable


class TtlCache[T]:
    def __init__(self, ttl_seconds: float, clock: Callable[[], float] = time.monotonic) -> None:
        self._ttl = ttl_seconds
        self._clock = clock
        self._entry: tuple[float, T] | None = None
        self._lock: asyncio.Lock | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    def _lock_here(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._lock is None or self._loop is not loop:
            self._lock, self._loop = asyncio.Lock(), loop
        return self._lock

    async def get(self, load: Callable[[], Awaitable[T]]) -> T:
        async with self._lock_here():
            if self._entry is not None:
                taken, value = self._entry
                if 0 <= self._clock() - taken < self._ttl:
                    return value
            value = await load()
            self._entry = (self._clock(), value)
            return value

    def clear(self) -> None:
        self._entry = None
