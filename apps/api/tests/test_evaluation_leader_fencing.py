"""Review fixes for the leader lock: the liveness check verifies the advisory lock itself, runs
under a timeout so a network partition cannot stall evaluation, ``release`` never waits on a
blocked check, and the connection carries a TCP user timeout.

A fake connection stands in for PostgreSQL (no network); the live suite covers the real server.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import psycopg

from netsight_api.evaluation.leader import EVALUATOR_LOCK_KEY, PostgresLeaderLock


class FakeCursor:
    def __init__(self, row: dict[str, Any] | None) -> None:
        self._row = row

    def fetchone(self) -> dict[str, Any] | None:
        return self._row


class FakeConnection:
    """Answers the two statements the lock issues; can hang, fail, or deny the lock."""

    def __init__(self, *, holds: bool = True, hang: threading.Event | None = None) -> None:
        self.holds = holds
        self.hang = hang
        self.fail = False
        self.closed = False
        self.statements: list[tuple[str, tuple[Any, ...]]] = []

    def execute(self, statement: str, params: tuple[Any, ...] = ()) -> FakeCursor:
        self.statements.append((statement, params))
        if self.hang is not None:
            self.hang.wait(10)
        if self.fail:
            raise psycopg.OperationalError("connection lost")
        if "pg_try_advisory_lock" in statement:
            return FakeCursor({"got": True})
        return FakeCursor({"held": self.holds})

    def close(self) -> None:
        self.closed = True


class FakeSettings:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection
        self.connect_kwargs: dict[str, Any] = {}

    def connect(self, **kwargs: Any) -> FakeConnection:
        self.connect_kwargs = kwargs
        return self.connection


def acquired(connection: FakeConnection, **options: Any) -> tuple[PostgresLeaderLock, FakeSettings]:
    settings = FakeSettings(connection)
    lock = PostgresLeaderLock(settings, **options)  # type: ignore[arg-type]
    assert lock.try_acquire() is True
    return lock, settings


def test_the_leader_connection_carries_a_tcp_user_timeout_and_keepalives() -> None:
    _, settings = acquired(FakeConnection())
    assert settings.connect_kwargs["autocommit"] is True
    assert settings.connect_kwargs["keepalives"] == 1
    assert 1_000 <= settings.connect_kwargs["tcp_user_timeout"] <= 30_000


def test_still_held_asks_the_server_whether_this_backend_holds_the_advisory_lock() -> None:
    connection = FakeConnection()
    lock, _ = acquired(connection)
    assert lock.still_held() is True
    statement, params = connection.statements[-1]
    assert "pg_locks" in statement and "pg_backend_pid()" in statement
    assert "advisory" in statement and "granted" in statement
    classid, objid = (EVALUATOR_LOCK_KEY >> 32) & 0xFFFFFFFF, EVALUATOR_LOCK_KEY & 0xFFFFFFFF
    assert params == (classid, objid)


def test_a_live_session_that_no_longer_holds_the_lock_is_not_the_leader() -> None:
    connection = FakeConnection()
    lock, _ = acquired(connection)
    connection.holds = False  # the session answers, but the lock is gone
    assert lock.still_held() is False
    assert connection.closed is True  # and the stale session is dropped


def test_a_failed_check_means_the_lock_is_lost() -> None:
    connection = FakeConnection()
    lock, _ = acquired(connection)
    connection.fail = True
    assert lock.still_held() is False
    assert lock.still_held() is False  # nothing left to ask


def test_a_hung_check_times_out_as_lost_instead_of_stalling_the_evaluator() -> None:
    hang = threading.Event()
    connection = FakeConnection()
    lock, _ = acquired(connection, check_timeout_seconds=0.2)
    connection.hang = hang
    started = time.monotonic()
    try:
        assert lock.still_held() is False
        assert time.monotonic() - started < 3
    finally:
        hang.set()


def test_release_does_not_wait_for_a_blocked_check() -> None:
    hang = threading.Event()
    connection = FakeConnection()
    lock, _ = acquired(connection, check_timeout_seconds=5)
    connection.hang = hang
    checker = threading.Thread(target=lock.still_held, daemon=True)
    checker.start()
    time.sleep(0.2)  # the check is now blocked inside the connection
    started = time.monotonic()
    try:
        lock.release()
        assert time.monotonic() - started < 1
        assert connection.closed is True
    finally:
        hang.set()
        checker.join(timeout=10)


def test_try_acquire_on_a_held_lock_is_verified_the_same_way() -> None:
    connection = FakeConnection()
    lock, _ = acquired(connection)
    connection.holds = False
    assert lock.try_acquire() is False
    assert connection.closed is True


def test_a_failed_connection_or_a_taken_lock_is_not_leadership() -> None:
    class Unreachable:
        def connect(self, **_kwargs: Any) -> FakeConnection:
            raise psycopg.OperationalError("down")

    assert PostgresLeaderLock(Unreachable()).try_acquire() is False  # type: ignore[arg-type]

    taken = FakeConnection()
    taken.execute = lambda statement, params=(): FakeCursor({"got": False})  # type: ignore[method-assign,assignment]
    lock = PostgresLeaderLock(FakeSettings(taken))  # type: ignore[arg-type]
    assert lock.try_acquire() is False and taken.closed is True

    broken = FakeConnection()
    broken.fail = True
    assert PostgresLeaderLock(FakeSettings(broken)).try_acquire() is False  # type: ignore[arg-type]
    assert broken.closed is True


def test_a_session_that_fails_to_close_is_still_released() -> None:
    connection = FakeConnection()

    def explode() -> None:
        raise psycopg.OperationalError("already gone")

    connection.close = explode  # type: ignore[method-assign]
    lock, _ = acquired(connection)
    lock.release()
    assert lock.still_held() is False
