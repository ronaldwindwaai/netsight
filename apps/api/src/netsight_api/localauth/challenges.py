"""Pending second-factor challenges.

A password alone never yields a session (ADR 0010). A verified password
produces a short-lived, single-use challenge bound to the account and the
client address; only redeeming that challenge with a valid second factor
issues a session.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

CHALLENGE_TTL_SECONDS = 300.0
# Bound the pending set so repeated password successes cannot exhaust memory.
MAX_PENDING_CHALLENGES = 512


@dataclass
class MfaChallenge:
    id: str
    username: str
    client_ip: str
    roles: frozenset[str]
    email: str | None
    created_at: float
    # Set when MFA enrolment is being completed rather than a login.
    enrollment: bool = False
    consumed: bool = field(default=False)


class ChallengeStore:
    """Thread-safe store of pending second-factor challenges."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._lock = threading.Lock()
        self._challenges: dict[str, MfaChallenge] = {}
        self._clock = clock

    def _now(self) -> float:
        return float(self._clock())

    def _prune_locked(self) -> None:
        now = self._now()
        for challenge_id in [
            key
            for key, challenge in self._challenges.items()
            if now - challenge.created_at > CHALLENGE_TTL_SECONDS or challenge.consumed
        ]:
            del self._challenges[challenge_id]

        overflow = len(self._challenges) - MAX_PENDING_CHALLENGES
        if overflow > 0:
            oldest = sorted(self._challenges.values(), key=lambda item: item.created_at)
            for challenge in oldest[:overflow]:
                self._challenges.pop(challenge.id, None)

    def issue(
        self,
        *,
        username: str,
        client_ip: str,
        roles: frozenset[str],
        email: str | None,
        enrollment: bool = False,
    ) -> MfaChallenge:
        """Create and store a new pending challenge."""
        challenge = MfaChallenge(
            id=secrets.token_urlsafe(32),
            username=username,
            client_ip=client_ip,
            roles=frozenset(roles),
            email=email,
            created_at=self._now(),
            enrollment=enrollment,
        )
        with self._lock:
            self._prune_locked()
            self._challenges[challenge.id] = challenge
        return challenge

    def redeem(self, challenge_id: str, client_ip: str) -> MfaChallenge | None:
        """Consume a challenge if it is valid for ``client_ip``.

        Single use: a challenge is removed on the first attempt regardless of
        whether the supplied second factor was correct, so an attacker cannot
        brute-force codes against one challenge id.
        """
        if not isinstance(challenge_id, str) or not challenge_id:
            return None

        with self._lock:
            self._prune_locked()
            challenge = self._challenges.get(challenge_id)
            if challenge is None:
                return None
            # Remove before validating the second factor.
            del self._challenges[challenge_id]

        if self._now() - challenge.created_at > CHALLENGE_TTL_SECONDS:
            return None
        if not secrets.compare_digest(challenge.client_ip, client_ip):
            return None
        return challenge

    def pending_count(self) -> int:
        with self._lock:
            return len(self._challenges)


_challenges = ChallengeStore()


def challenge_store() -> ChallengeStore:
    return _challenges


def reset_challenge_store() -> None:
    """Test-only helper; never call from request handling."""
    global _challenges
    _challenges = ChallengeStore()
