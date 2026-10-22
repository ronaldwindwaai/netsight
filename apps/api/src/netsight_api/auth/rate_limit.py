"""In-memory sliding-window rate limiter for authentication endpoints.

Protects the OIDC entry points against credential stuffing and token
endpoint abuse. State is per-process; a shared store (for example
Redis) should back this in multi-worker production deployments.
"""

from __future__ import annotations

import time
from collections import deque
from threading import Lock
from typing import Final

PRUNE_INTERVAL_SECONDS: Final = 60.0


class RateLimiter:
    """Keys whose hits have all expired are deleted by a sweep at most every
    ``PRUNE_INTERVAL_SECONDS`` (on the next call), so one-off keys (an address that never comes
    back) cannot accumulate without bound."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._hits: dict[str, deque[float]] = {}
        self._windows: dict[str, float] = {}
        self._next_prune = 0.0

    def __len__(self) -> int:
        with self._lock:
            return len(self._hits)

    def allow(self, key: str, limit: int, window_seconds: float) -> bool:
        if limit <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            hits = self._hits.setdefault(key, deque())
            self._windows[key] = window_seconds
            while hits and now - hits[0] > window_seconds:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)
            self._windows.pop(key, None)

    def _prune(self, now: float) -> None:
        if now < self._next_prune:
            return
        self._next_prune = now + PRUNE_INTERVAL_SECONDS
        for key in list(self._hits):
            hits, window = self._hits[key], self._windows[key]
            while hits and now - hits[0] > window:
                hits.popleft()
            if not hits:
                del self._hits[key], self._windows[key]


_limiter = RateLimiter()


def rate_limiter() -> RateLimiter:
    return _limiter


def auth_rate_limiter() -> RateLimiter:
    return _limiter
