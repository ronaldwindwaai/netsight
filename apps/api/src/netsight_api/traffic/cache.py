"""A small bounded, time-limited cache with per-key single flight.

Used for the baseline inputs: they cost several scans of weeks of flows and change slowly, so one
load per window per ``ttl_seconds`` is shared by every caller (the inputs hold no per-user data, so
the cache is shared across identities). Bounded in entries, never grows without limit, never caches a
failure, and concurrent requests for the same key share one load.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Hashable
from typing import Any


class TtlCache:
    def __init__(
        self,
        ttl_seconds: float = 300.0,
        max_entries: int = 16,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        self._clock = clock
        self._entries: dict[Hashable, tuple[float, Any]] = {}
        self._locks: dict[Hashable, asyncio.Lock] = {}

    def __len__(self) -> int:
        return len(self._entries)

    def _fresh(self, key: Hashable) -> tuple[bool, Any]:
        entry = self._entries.get(key)
        if entry is None:
            return False, None
        if 0 <= self._clock() - entry[0] < self._ttl:
            return True, entry[1]
        del self._entries[key]
        return False, None

    def _store(self, key: Hashable, value: Any) -> None:
        self._entries.pop(key, None)
        while len(self._entries) >= self._max:
            del self._entries[next(iter(self._entries))]
        self._entries[key] = (self._clock(), value)

    async def get_or_load[T](self, key: Hashable, loader: Callable[[], Awaitable[T]]) -> T:
        hit, value = self._fresh(key)
        if hit:
            return value  # type: ignore[no-any-return]
        lock = self._locks.setdefault(key, asyncio.Lock())
        try:
            async with lock:
                hit, value = self._fresh(key)
                if hit:
                    return value  # type: ignore[no-any-return]
                loaded = await loader()
                self._store(key, loaded)
                return loaded
        finally:
            if not lock.locked() and self._locks.get(key) is lock:
                del self._locks[key]
