"""Pending authentication state for the OIDC redirect round-trip.

Holds the nonce, PKCE verifier and return target keyed by the opaque
``state`` value. Entries are short-lived and single-use.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from threading import Lock

from netsight_api.auth.providers import ProviderId

PENDING_TTL_SECONDS = 600.0


@dataclass
class PendingAuth:
    provider: ProviderId
    nonce: str
    code_verifier: str
    redirect_to: str
    created_at: float
    # Wall-clock time (epoch seconds) a step-up was requested; the returning token must have
    # authenticated after it, so an older token cannot be replayed to satisfy a step-up.
    step_up_requested_at: float | None = None


class PendingAuthStore:
    def __init__(self) -> None:
        self._lock = Lock()
        self._pending: dict[str, PendingAuth] = {}

    def put(
        self,
        state: str,
        provider: ProviderId,
        nonce: str,
        code_verifier: str,
        redirect_to: str,
        step_up_requested_at: float | None = None,
    ) -> None:
        with self._lock:
            self._prune_locked()
            self._pending[state] = PendingAuth(
                provider=provider,
                nonce=nonce,
                code_verifier=code_verifier,
                redirect_to=redirect_to,
                created_at=time.monotonic(),
                step_up_requested_at=step_up_requested_at,
            )

    def take(self, state: str) -> PendingAuth | None:
        with self._lock:
            entry = self._pending.pop(state, None)
            if entry is None:
                return None
            if time.monotonic() - entry.created_at > PENDING_TTL_SECONDS:
                return None
            return entry

    def _prune_locked(self) -> None:
        now = time.monotonic()
        expired = [
            state
            for state, entry in self._pending.items()
            if now - entry.created_at > PENDING_TTL_SECONDS
        ]
        for state in expired:
            del self._pending[state]


_pending_store = PendingAuthStore()


def pending_auth_store() -> PendingAuthStore:
    return _pending_store
