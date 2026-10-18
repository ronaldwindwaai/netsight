"""In-flight TOTP enrolment secrets.

A generated secret is held here between the two enrolment steps and is never
written to the account until activation succeeds. Bounded and short-lived so a
half-finished enrolment cannot accumulate.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

ENROLMENT_TTL_SECONDS = 600.0
MAX_PENDING = 64


class PendingEnrolmentStore:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, tuple[str, float]] = {}
        self._clock = clock

    def _now(self) -> float:
        return float(self._clock())

    def _prune_locked(self) -> None:
        now = self._now()
        for key in [
            key
            for key, (_secret, created) in self._entries.items()
            if now - created > ENROLMENT_TTL_SECONDS
        ]:
            del self._entries[key]
        overflow = len(self._entries) - MAX_PENDING
        if overflow > 0:
            oldest = sorted(self._entries.items(), key=lambda item: item[1][1])
            for key, _value in oldest[:overflow]:
                self._entries.pop(key, None)

    def put(self, identity_id: str, secret: str) -> None:
        with self._lock:
            self._prune_locked()
            self._entries[identity_id] = (secret, self._now())

    def take(self, identity_id: str) -> str | None:
        """Fetch and remove the pending secret, so it is single-use."""
        with self._lock:
            self._prune_locked()
            entry = self._entries.pop(identity_id, None)
        if entry is None:
            return None
        secret, created = entry
        if self._now() - created > ENROLMENT_TTL_SECONDS:
            return None
        return secret

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


_store = PendingEnrolmentStore()


def pending_enrolment_store() -> PendingEnrolmentStore:
    return _store


def reset_pending_enrolment_store() -> None:
    """Test-only helper; never call from request handling."""
    global _store
    _store = PendingEnrolmentStore()
