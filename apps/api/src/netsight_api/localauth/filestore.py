"""Durable local account store (ADR 0010).

The in-memory store is a convenience for tests only: a separate process (the
operator CLI) could never see accounts the API held in RAM. This store
persists to a JSON file so an account created on the host is usable by the
running service, and survives a restart.

Postgres remains the production target for a multi-node deployment; this file
store keeps a single-host deployment honest in the meantime. Both keep the
same invariants:

* the password is only ever stored as an Argon2id hash;
* the TOTP secret is only ever stored as an encrypted envelope;
* recovery codes are only ever stored as hashes.

The file is written atomically with 0600 permissions and is owned by the
service account.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from netsight_api.localauth.passwords import MAX_PASSWORD_LENGTH, verify_password
from netsight_api.localauth.store import (
    LOCKOUT_SCHEDULE_SECONDS,
    MAX_TRACKED_FAILURES,
    MAX_USERNAME_LENGTH,
    MIN_USERNAME_LENGTH,
    LocalAccount,
    PasswordChallenge,
    UsernameRejected,
    validate_username,
)

SCHEMA_VERSION = 1
DEFAULT_ACCOUNT_FILE = Path("~/.local/state/netsight/local-accounts.json").expanduser()


class AccountFileError(RuntimeError):
    """Raised when the account file cannot be read or written safely."""


def account_file_path() -> Path:
    """Resolve the account file, honouring ``NETSIGHT_LOCAL_ACCOUNT_FILE``."""
    configured = os.environ.get("NETSIGHT_LOCAL_ACCOUNT_FILE", "").strip()
    if configured:
        return Path(configured).expanduser()
    return DEFAULT_ACCOUNT_FILE


@dataclass(frozen=True)
class SerialisedAccount:
    username: str
    password_hash: str
    roles: list[str]
    encrypted_totp: str | None
    totp_enrolled_at: float | None
    recovery_code_hashes: list[str]
    last_totp_counter: int | None
    consecutive_failures: int
    locked_until: float
    password_changed_at: float
    mfa_required: bool
    enabled: bool


def _to_serialisable(account: LocalAccount) -> SerialisedAccount:
    return SerialisedAccount(
        username=account.username,
        password_hash=account.password_hash,
        roles=sorted(account.roles),
        encrypted_totp=account.encrypted_totp,
        totp_enrolled_at=account.totp_enrolled_at,
        recovery_code_hashes=list(account.recovery_code_hashes),
        last_totp_counter=account.last_totp_counter,
        consecutive_failures=account.consecutive_failures,
        # Lockout state is per-process wall-clock, not monotonic, so it must be
        # persisted as an absolute epoch to survive a restart.
        locked_until=account.locked_until,
        password_changed_at=account.password_changed_at,
        mfa_required=account.mfa_required,
        enabled=account.enabled,
    )


def _from_serialisable(raw: SerialisedAccount) -> LocalAccount:
    return LocalAccount(
        username=raw.username,
        password_hash=raw.password_hash,
        roles=frozenset(raw.roles),
        encrypted_totp=raw.encrypted_totp,
        totp_enrolled_at=raw.totp_enrolled_at,
        recovery_code_hashes=list(raw.recovery_code_hashes),
        last_totp_counter=raw.last_totp_counter,
        consecutive_failures=raw.consecutive_failures,
        locked_until=raw.locked_until,
        password_changed_at=raw.password_changed_at,
        mfa_required=raw.mfa_required,
        enabled=raw.enabled,
    )


class FileAccountStore:
    """Local account store backed by a JSON file."""

    def __init__(
        self,
        path: Path | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._path = path or account_file_path()
        # Lockout timestamps are wall-clock so they survive a restart.
        self._clock = clock
        self._lock = threading.RLock()
        self._accounts: dict[str, LocalAccount] = {}
        self._loaded = False

    # -- persistence --------------------------------------------------------

    def load(self) -> None:
        """Load accounts from disk. Safe to call repeatedly."""
        with self._lock:
            self._accounts = {}
            self._loaded = True
            if not self._path.exists():
                return
            try:
                document = json.loads(self._path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise AccountFileError(f"account file is unreadable: {self._path}") from exc

            if not isinstance(document, dict) or document.get("version") != SCHEMA_VERSION:
                raise AccountFileError("account file has an unsupported schema version")

            entries = document.get("accounts")
            if not isinstance(entries, list):
                return

            for entry in entries:
                if not isinstance(entry, dict):
                    raise AccountFileError("account file contains a malformed entry")
                try:
                    account = _from_serialisable(SerialisedAccount(**entry))
                except TypeError as exc:
                    raise AccountFileError("account file contains an unknown field") from exc
                self._accounts[account.username] = account

    def _require_loaded(self) -> None:
        if not self._loaded:
            self.load()

    def flush(self) -> None:
        """Write accounts to disk atomically with 0600 permissions."""
        with self._lock:
            self._require_loaded()
            document = {
                "version": SCHEMA_VERSION,
                "accounts": [asdict(_to_serialisable(a)) for a in self._accounts.values()],
            }
            self._path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self._path.with_suffix(f"{self._path.suffix}.tmp")
            payload = json.dumps(document, indent=2, sort_keys=True)
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    handle.write(payload)
            except OSError as exc:
                temporary.unlink(missing_ok=True)
                raise AccountFileError(f"cannot write account file: {self._path}") from exc
            os.replace(temporary, self._path)
            # Re-assert the mode: os.replace preserves the temp file's mode, but
            # an existing destination may predate this call.
            os.chmod(self._path, 0o600)

    # -- CRUD ---------------------------------------------------------------

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

        with self._lock:
            self._require_loaded()
            if key in self._accounts:
                raise UsernameRejected("username is already registered")
            account = LocalAccount(
                username=key,
                password_hash=password_hash,
                roles=frozenset(roles),
                password_changed_at=self._clock(),
                mfa_required=mfa_required,
                enabled=enabled,
            )
            self._accounts[key] = account
            self.flush()
        return account

    def get(self, username: str) -> LocalAccount | None:
        try:
            key = validate_username(username)
        except UsernameRejected:
            return None
        with self._lock:
            self._require_loaded()
            account = self._accounts.get(key)
            # Return a snapshot so a caller cannot mutate the store without
            # persisting the change.
            return replace(account) if account is not None else None

    def save(self, account: LocalAccount) -> None:
        with self._lock:
            self._require_loaded()
            self._accounts[account.username] = account
            self.flush()

    def list_usernames(self) -> list[str]:
        with self._lock:
            self._require_loaded()
            return sorted(self._accounts)

    def __len__(self) -> int:
        with self._lock:
            self._require_loaded()
            return len(self._accounts)

    def __iter__(self) -> Any:
        with self._lock:
            self._require_loaded()
            return iter([replace(account) for account in self._accounts.values()])

    def delete(self, username: str) -> bool:
        try:
            key = validate_username(username)
        except UsernameRejected:
            return False
        with self._lock:
            self._require_loaded()
            removed = self._accounts.pop(key, None) is not None
            if removed:
                self.flush()
        return removed

    # -- authentication ----------------------------------------------------

    def authenticate_password(self, username: str, password: str) -> PasswordChallenge:
        account = self.get(username)
        now = self._clock()

        if account is None or not account.enabled:
            return PasswordChallenge(ok=False, account=None)

        if account.is_locked(now):
            return PasswordChallenge(
                ok=False,
                account=None,
                locked_seconds=account.lockout_seconds_remaining(now),
            )

        if not verify_password(account.password_hash, password):
            self.register_failure(account.username)
            return PasswordChallenge(ok=False, account=None)

        return PasswordChallenge(
            ok=True,
            account=account,
            mfa_required=account.mfa_required or account.is_mfa_active(),
        )

    def register_failure(self, username: str) -> None:
        account = self.get(username)
        if account is None:
            return
        account.record_failure(self._clock())
        self.save(account)

    def register_success(self, username: str) -> None:
        account = self.get(username)
        if account is None:
            return
        account.record_success()
        self.save(account)


# Guard against a stale constant drifting from the in-memory store.
assert MAX_TRACKED_FAILURES == len(LOCKOUT_SCHEDULE_SECONDS) - 1
assert MIN_USERNAME_LENGTH < MAX_USERNAME_LENGTH

__all__ = [
    "SCHEMA_VERSION",
    "AccountFileError",
    "FileAccountStore",
    "account_file_path",
]
