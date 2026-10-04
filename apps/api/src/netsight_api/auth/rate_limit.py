"""In-memory sliding-window rate limiter for authentication endpoints.

Protects the OIDC entry points against credential stuffing and token
endpoint abuse. State is per-process; a shared store (for example
Redis) should back this in multi-worker production deployments.
"""

from __future__ import annotations

import time
from collections import deque
from threading import Lock


class RateLimiter:
    def __init__(self) -> None:
        self._lock = Lock()
        self._hits: dict[str, deque[float]] = {}

    def allow(self, key: str, limit: int, window_seconds: float) -> bool:
        if limit <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] > window_seconds:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)


_limiter = RateLimiter()


def rate_limiter() -> RateLimiter:
    return _limiter


def auth_rate_limiter() -> RateLimiter:
    return _limiter
