"""Rate limiting for the local credential endpoints (ADR 0010).

Separate from the federated auth limiter so that local password guessing
cannot exhaust the OIDC budget, and vice versa. Limits apply per client
address and per account, so neither a single host nor a single account can be
attacked unbounded.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

# Password step. Tight, because a correct password is the only route to a
# challenge.
LOGIN_ATTEMPTS_PER_WINDOW = 5
# Second factor. Also tight, but slightly higher to tolerate a mistyped code.
MFA_ATTEMPTS_PER_WINDOW = 8
WINDOW_SECONDS = 300.0


class SlidingWindowLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}
        self._clock = clock

    def _now(self) -> float:
        return float(self._clock())

    def allow(self, key: str, limit: int, window: float = WINDOW_SECONDS) -> bool:
        if limit <= 0:
            return True
        now = self._now()
        with self._lock:
            hits = [moment for moment in self._hits.get(key, []) if now - moment < window]
            if len(hits) >= limit:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            return True

    def retry_after(self, key: str, window: float = WINDOW_SECONDS) -> int:
        """Seconds until the window frees a slot, at least 1 when blocked."""
        now = self._now()
        with self._lock:
            hits = sorted(moment for moment in self._hits.get(key, []) if now - moment < window)
        if not hits:
            return 0
        return max(1, int(window - (now - hits[0])) + 1)

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()


class LocalAuthLimiter:
    """Wraps the two limiters the local login flow needs."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._password = SlidingWindowLimiter(clock)
        self._mfa = SlidingWindowLimiter(clock)

    def allow_password(self, client_ip: str, username: str) -> bool:
        """Limit on both the client address and the account."""
        if not self._password.allow(f"pw:ip:{client_ip}", LOGIN_ATTEMPTS_PER_WINDOW):
            return False
        return self._password.allow(f"pw:user:{username.lower()}", LOGIN_ATTEMPTS_PER_WINDOW)

    def password_retry_after(self, client_ip: str, username: str) -> int:
        return max(
            self._password.retry_after(f"pw:ip:{client_ip}"),
            self._password.retry_after(f"pw:user:{username.lower()}"),
        )

    def allow_mfa(self, client_ip: str, username: str) -> bool:
        if not self._mfa.allow(f"mfa:ip:{client_ip}", MFA_ATTEMPTS_PER_WINDOW):
            return False
        return self._mfa.allow(f"mfa:user:{username.lower()}", MFA_ATTEMPTS_PER_WINDOW)

    def mfa_retry_after(self, client_ip: str, username: str) -> int:
        return max(
            self._mfa.retry_after(f"mfa:ip:{client_ip}"),
            self._mfa.retry_after(f"mfa:user:{username.lower()}"),
        )

    def clear(self) -> None:
        self._password.clear()
        self._mfa.clear()


_limiter = LocalAuthLimiter()


def local_auth_limiter() -> LocalAuthLimiter:
    return _limiter


def reset_local_auth_limiter() -> None:
    """Test-only helper; never call from request handling."""
    global _limiter
    _limiter = LocalAuthLimiter()
