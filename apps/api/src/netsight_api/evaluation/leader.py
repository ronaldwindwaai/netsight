"""Single-evaluator guarantee: one leader lock per database.

Two evaluators on one database would double-page and race on incident creation, so evaluation is
a hard single-writer job. The scheduler runs cycles only while it holds the leader lock; every
other process idles and retries each interval. Losing the lock (the session died, the database
restarted, someone else holds it) stops evaluation at once and drops the in-memory engine state,
so a later takeover starts clean.

``PostgresLeaderLock`` is a session-level advisory lock on a *dedicated* connection: PostgreSQL
frees it when that session ends, however it ends, so a crashed evaluator cannot keep the lock.
``try_acquire`` never blocks. ``still_held`` is a cheap round trip on the same connection: if the
session is alive the lock is held.
"""

from __future__ import annotations

import logging
import threading
from typing import Final, Protocol

import psycopg

from netsight_api.storage.connection import Connection, PostgresSettings

_LOGGER: Final = logging.getLogger("netsight_api.evaluation")
# Arbitrary, fixed 64-bit key for "the Netsight alert evaluator" (advisory locks are per database).
EVALUATOR_LOCK_KEY: Final = 0x4E53_4556_414C_0001
_KEEPALIVE: Final = {
    "keepalives": 1,
    "keepalives_idle": 30,
    "keepalives_interval": 10,
    "keepalives_count": 3,
}


class LeaderLock(Protocol):
    def try_acquire(self) -> bool:
        """Take the lock if it is free; never waits. True when this process now holds it."""
        ...

    def still_held(self) -> bool:
        """True only when this process verifiably still holds the lock."""
        ...

    def release(self) -> None:
        """Give the lock up (idempotent)."""
        ...


class LeaseBoard:
    """Shared state for ``InMemoryLeaderLock`` instances: who holds the lock, if anyone."""

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self.owner: object | None = None

    def take(self, who: object) -> bool:
        with self._guard:
            if self.owner is None or self.owner is who:
                self.owner = who
                return True
            return False

    def give_up(self, who: object) -> None:
        with self._guard:
            if self.owner is who:
                self.owner = None

    def seize(self, who: object | None) -> None:
        """Test hook: another party takes (or, with None, frees) the lock regardless."""
        with self._guard:
            self.owner = who

    def holds(self, who: object) -> bool:
        with self._guard:
            return self.owner is who


class InMemoryLeaderLock:
    """Unit-test implementation of ``LeaderLock``."""

    def __init__(self, board: LeaseBoard) -> None:
        self._board = board

    def try_acquire(self) -> bool:
        return self._board.take(self)

    def still_held(self) -> bool:
        return self._board.holds(self)

    def release(self) -> None:
        self._board.give_up(self)


class PostgresLeaderLock:
    def __init__(self, settings: PostgresSettings, *, key: int = EVALUATOR_LOCK_KEY) -> None:
        self._settings = settings
        self._key = key
        self._conn: Connection | None = None
        self._guard = threading.Lock()

    def try_acquire(self) -> bool:
        with self._guard:
            if self._conn is not None:
                return self._alive()
            try:
                conn = self._settings.connect(autocommit=True, **_KEEPALIVE)
            except psycopg.Error:
                return False
            try:
                row = conn.execute(
                    "SELECT pg_try_advisory_lock(%s) AS got", (self._key,)
                ).fetchone()
            except psycopg.Error:
                conn.close()
                return False
            if row is not None and row["got"]:
                self._conn = conn
                return True
            conn.close()
            return False

    def still_held(self) -> bool:
        with self._guard:
            return self._conn is not None and self._alive()

    def release(self) -> None:
        with self._guard:
            self._drop()

    def _alive(self) -> bool:
        assert self._conn is not None
        try:
            self._conn.execute("SELECT 1").fetchone()
        except psycopg.Error:
            _LOGGER.warning("evaluator lock session lost")
            self._drop()
            return False
        return True

    def _drop(self) -> None:
        conn, self._conn = self._conn, None
        if conn is None:
            return
        try:
            conn.close()  # closing the session frees its advisory locks
        except psycopg.Error:
            pass
