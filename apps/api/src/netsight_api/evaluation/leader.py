"""Single-evaluator guarantee: one leader lock per database.

Two evaluators on one database would double-page and race on incident creation, so evaluation is
a hard single-writer job. The scheduler runs cycles only while it holds the leader lock; every
other process idles and retries each interval. Losing the lock (the session died, the database
restarted, someone else holds it) stops evaluation at once and drops the in-memory engine state,
so a later takeover starts clean.

``PostgresLeaderLock`` is a session-level advisory lock on a *dedicated* connection: PostgreSQL
frees it when that session ends, however it ends, so a crashed evaluator cannot keep the lock.
``try_acquire`` never blocks. ``still_held`` asks the server, on the same connection and under a
timeout, whether this backend is still granted the advisory lock (``pg_locks``); a session that is
alive but no longer holds the lock, a failed round trip and a timed-out one all mean "lost".
``release`` never waits for a check in progress.

``DATABASE_URL`` must reach PostgreSQL directly or through a session-mode pooler. PgBouncer in
transaction or statement mode multiplexes sessions, so the lock would belong to whichever server
session happened to run the statement: advisory locks do not work there.
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
# Keepalives find a dead peer on an idle connection; ``tcp_user_timeout`` bounds how long data
# written to a black-holed (partitioned) connection may stay unacknowledged. Without it a probe on
# a silently dead link can block for the OS retransmission limit (about a quarter of an hour).
TCP_USER_TIMEOUT_MS: Final = 30_000
DEFAULT_CHECK_TIMEOUT_SECONDS: Final = 10.0
_LIVENESS_OPTIONS: Final = {
    "keepalives": 1,
    "keepalives_idle": 30,
    "keepalives_interval": 10,
    "keepalives_count": 3,
    "tcp_user_timeout": TCP_USER_TIMEOUT_MS,
}
# The lock is real only if the server lists it as granted to *this* backend: a live session that
# lost (or never took) the advisory lock must not pass for the leader. ``pg_try_advisory_lock``
# with a bigint key is recorded as classid = high 32 bits, objid = low 32 bits, objsubid = 1.
_HOLDS_LOCK: Final = (
    "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND granted "
    "AND pid = pg_backend_pid() AND classid::bigint = %s AND objid::bigint = %s "
    "AND objsubid = 1) AS held"
)


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
    def __init__(
        self,
        settings: PostgresSettings,
        *,
        key: int = EVALUATOR_LOCK_KEY,
        check_timeout_seconds: float = DEFAULT_CHECK_TIMEOUT_SECONDS,
    ) -> None:
        self._settings = settings
        self._key = key
        self._class_id = (key >> 32) & 0xFFFFFFFF  # how pg_locks splits a bigint advisory key
        self._object_id = key & 0xFFFFFFFF
        self._check_timeout = check_timeout_seconds
        self._conn: Connection | None = None
        self._guard = threading.Lock()  # protects ``_conn``; no liveness check or close runs under it (only ``_acquire``'s connect does)

    def try_acquire(self) -> bool:
        with self._guard:
            conn = self._conn
            if conn is None:
                return self._acquire()
        return self._verify(conn)

    def still_held(self) -> bool:
        with self._guard:
            conn = self._conn
        return conn is not None and self._verify(conn)

    def release(self) -> None:
        with self._guard:
            conn, self._conn = self._conn, None
        _close(conn)  # outside the guard: a check blocked on this connection must not delay it

    def _acquire(self) -> bool:
        try:
            conn = self._settings.connect(autocommit=True, **_LIVENESS_OPTIONS)
        except psycopg.Error:
            return False
        try:
            row = conn.execute("SELECT pg_try_advisory_lock(%s) AS got", (self._key,)).fetchone()
        except psycopg.Error:
            _close(conn)
            return False
        if row is not None and row["got"]:
            self._conn = conn
            return True
        _close(conn)
        return False

    def _verify(self, conn: Connection) -> bool:
        """Ask the server (bounded by the check timeout) whether this very backend still holds
        the advisory lock; anything but a clear yes drops the session and means "not the leader"."""
        if self._probe(conn):
            return True
        _LOGGER.warning("evaluator lock lost")
        with self._guard:
            if self._conn is conn:
                self._conn = None
        _close(conn)
        return False

    def _probe(self, conn: Connection) -> bool:
        """The lock query on a helper thread, so a network partition (a round trip that never
        returns) costs at most the check timeout instead of a TCP timeout."""
        outcome: list[bool] = []

        def ask() -> None:
            try:
                row = conn.execute(_HOLDS_LOCK, (self._class_id, self._object_id)).fetchone()
                outcome.append(row is not None and bool(row["held"]))
            except Exception:  # noqa: BLE001 - any failure to confirm the lock is a lost lock
                outcome.append(False)

        checker = threading.Thread(target=ask, name="netsight-lease-check", daemon=True)
        checker.start()
        checker.join(self._check_timeout)
        return bool(outcome) and outcome[0]


def _close(conn: Connection | None) -> None:
    if conn is None:
        return
    try:
        conn.close()  # closing the session frees its advisory locks
    except psycopg.Error:
        pass
