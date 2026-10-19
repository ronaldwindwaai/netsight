"""Local account store with escalating lockout (ADR 0010).

Deliberately narrow so a durable store (PostgreSQL) can replace it without
touching the auth flow, matching the pattern used by ``SessionStore``.

The store never holds a plaintext password or a plaintext TOTP secret.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field, replace

from netsight_api.localauth.passwords import MAX_PASSWORD_LENGTH, verify_password

# Lockout schedule keyed by consecutive failures. The final entry is a plateau
# so a determined attacker cannot be punished into a permanent outage, but the
# wait is long enough to make online guessing impractical.
LOCKOUT_SCHEDULE_SECONDS: tuple[int, ...] = (0, 0, 15, 60, 300, 900, 3600, 3600)
MAX_TRACKED_FAILURES: int = len(LOCKOUT_SCHEDULE_SECONDS) - 1

MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 64


class UsernameRejected(ValueError):
    """Raised when a username is not acceptable."""


def validate_username(username: str) -> str:
    """Validate and normalise a username.

    Usernames are compared case-insensitively so ``Ops`` and ``ops`` cannot be
    registered as two accounts.
    """
    if not isinstance(username, str):
        raise UsernameRejected("username is not valid")

    normalised = username.strip()
    if len(normalised) < MIN_USERNAME_LENGTH or len(normalised) > MAX_USERNAME_LENGTH:
        raise UsernameRejected(
            f"username must be {MIN_USERNAME_LENGTH}-{MAX_USERNAME_LENGTH} characters"
        )

    lowered = normalised.lower()
    if any(character.isspace() for character in normalised):
        raise UsernameRejected("username must not contain whitespace")
    if not all(
        character.isalnum() or character in {".", "-", "_", "@"} for character in normalised
    ):
        raise UsernameRejected("username contains unsupported characters")

    return lowered


@dataclass
class LocalAccount:
    """A Netsight-managed account. Never holds plaintext secrets."""

    username: str
    password_hash: str
    roles: frozenset[str]
    # Argon2id hash of the encrypted-envelope TOTP secret, once activated.
    encrypted_totp: str | None = None
    totp_enrolled_at: float | None = None
    recovery_code_hashes: list[str] = field(default_factory=list)
    # Counter of the last accepted TOTP step, for replay rejection.
    last_totp_counter: int | None = None
    consecutive_failures: int = 0
    locked_until: float = 0.0
    password_changed_at: float = 0.0
    mfa_required: bool = True
    enabled: bool = True

    def is_locked(self, now: float) -> bool:
        return now < self.locked_until

    def lockout_seconds_remaining(self, now: float) -> int:
        if not self.is_locked(now):
            return 0
        return int(max(0.0, self.locked_until - now))

    def with_totp_enrolled(
        self,
        *,
        encrypted_totp: str,
        recovery_code_hashes: Iterable[str],
        now: float,
    ) -> LocalAccount:
        return replace(
            self,
            encrypted_totp=encrypted_totp,
            totp_enrolled_at=now,
            recovery_code_hashes=list(recovery_code_hashes),
            last_totp_counter=None,
        )

    def record_failure(self, now: float) -> None:
        self.consecutive_failures = min(self.consecutive_failures + 1, MAX_TRACKED_FAILURES)
        self.locked_until = now + LOCKOUT_SCHEDULE_SECONDS[self.consecutive_failures]

    def record_success(self) -> None:
        self.consecutive_failures = 0
        self.locked_until = 0.0

    def is_mfa_active(self) -> bool:
        return self.encrypted_totp is not None


@dataclass(frozen=True)
class PasswordChallenge:
    """Result of the password step of a local login."""

    ok: bool
    account: LocalAccount | None
    locked_seconds: int = 0
    # True when the account requires a second factor before a session is issued.
    mfa_required: bool = False


class LocalAccountStore:
    """Thread-safe in-memory store for Netsight-managed accounts."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._lock = threading.Lock()
        self._accounts: dict[str, LocalAccount] = {}
        self._clock = clock

    def _now(self) -> float:
        return float(self._clock())

    def create(
        self,
        username: str,
        password_hash: str,
        roles: Iterable[str],
        *,
        mfa_required: bool = True,
        enabled: bool = True,
    ) -> LocalAccount:
        key = validate_username(username)
        if len(password_hash) > MAX_PASSWORD_LENGTH * 8:
            raise ValueError("password hash is implausibly long")

        now = self._now()
        account = LocalAccount(
            username=key,
            password_hash=password_hash,
            roles=frozenset(roles),
            password_changed_at=now,
            mfa_required=mfa_required,
            enabled=enabled,
        )
        with self._lock:
            if key in self._accounts:
                raise UsernameRejected("username is already registered")
            self._accounts[key] = account
        return account

    def get(self, username: str) -> LocalAccount | None:
        try:
            key = validate_username(username)
        except UsernameRejected:
            return None
        with self._lock:
            return self._accounts.get(key)

    def save(self, account: LocalAccount) -> None:
        with self._lock:
            self._accounts[account.username] = account

    def list_usernames(self) -> list[str]:
        with self._lock:
            return sorted(self._accounts)

    def __len__(self) -> int:
        with self._lock:
            return len(self._accounts)

    def __iter__(self) -> Iterator[LocalAccount]:
        with self._lock:
            return iter(list(self._accounts.values()))

    def delete(self, username: str) -> bool:
        try:
            key = validate_username(username)
        except UsernameRejected:
            return False
        with self._lock:
            return self._accounts.pop(key, None) is not None

    # -- authentication ----------------------------------------------------

    def authenticate_password(self, username: str, password: str) -> PasswordChallenge:
        """Verify a password without disclosing whether the account exists.

        An unknown account still performs a full Argon2 verification inside
        ``verify_password``, so the caller always returns the same failure.
        """
        account = self.get(username)
        now = self._now()

        if account is None or not account.enabled:
            return PasswordChallenge(ok=False, account=None)

        if account.is_locked(now):
            return PasswordChallenge(
                ok=False,
                account=None,
                locked_seconds=account.lockout_seconds_remaining(now),
            )

        if not verify_password(account.password_hash, password):
            account.record_failure(now)
            self.save(account)
            return PasswordChallenge(ok=False, account=None)

        # A successful password still leaves a pending account: the session is
        # only issued after the second factor is verified.
        return PasswordChallenge(
            ok=True,
            account=account,
            mfa_required=account.mfa_required or account.is_mfa_active(),
        )

    def register_failure(self, username: str) -> None:
        """Record a failed second-factor attempt against the account."""
        account = self.get(username)
        if account is None:
            return
        account.record_failure(self._now())
        self.save(account)

    def register_success(self, username: str) -> None:
        """Clear failures after a fully completed login."""
        account = self.get(username)
        if account is None:
            return
        account.record_success()
        self.save(account)
