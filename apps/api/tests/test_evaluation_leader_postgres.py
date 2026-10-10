"""The single-evaluator advisory lock against real PostgreSQL (skipped without
NETSIGHT_TEST_PG_DSN): one holder per database, freed when the holder's session ends."""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Iterator

import psycopg
import pytest
from pg_support import PG_DSN, requires_pg

from netsight_api.evaluation.leader import PostgresLeaderLock
from netsight_api.evaluation.wiring import run_scheduler
from netsight_api.storage.connection import PostgresSettings

pytestmark = requires_pg


@pytest.fixture
def locks() -> Iterator[tuple[PostgresLeaderLock, PostgresLeaderLock, PostgresLeaderLock]]:
    assert PG_DSN
    settings = PostgresSettings(dsn=PG_DSN)
    key = secrets.randbits(62)  # a private key per test, so tests never contend
    made = tuple(PostgresLeaderLock(settings, key=key) for _ in range(3))
    yield made  # type: ignore[misc]
    for lock in made:
        lock.release()


def test_only_one_connection_holds_the_lock_at_a_time(
    locks: tuple[PostgresLeaderLock, PostgresLeaderLock, PostgresLeaderLock],
) -> None:
    first, second, third = locks
    assert first.try_acquire() is True
    assert first.try_acquire() is True  # idempotent for the holder
    assert second.try_acquire() is False and second.still_held() is False
    first.release()
    assert first.still_held() is False
    assert second.try_acquire() is True
    assert third.try_acquire() is False


def test_a_killed_session_frees_the_lock_and_the_holder_notices() -> None:
    assert PG_DSN
    settings = PostgresSettings(dsn=PG_DSN)
    key = secrets.randbits(62)
    holder, rival = PostgresLeaderLock(settings, key=key), PostgresLeaderLock(settings, key=key)
    try:
        assert holder.try_acquire()
        with psycopg.connect(PG_DSN, autocommit=True) as admin:
            admin.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_locks "
                "WHERE locktype = 'advisory' AND granted AND objid::bigint = %s AND pid <> pg_backend_pid()",
                (key & 0xFFFFFFFF,),
            )
        assert holder.still_held() is False  # the next check sees the dead session
        assert rival.try_acquire() is True
    finally:
        holder.release()
        rival.release()


class Counting:
    def __init__(self) -> None:
        self.cycles = 0
        self.resets = 0

    async def run_cycle(self) -> None:
        self.cycles += 1

    def reset_state(self) -> None:
        self.resets += 1


@pytest.mark.asyncio
async def test_two_schedulers_on_one_database_run_one_evaluator() -> None:
    assert PG_DSN
    settings = PostgresSettings(dsn=PG_DSN)
    key = secrets.randbits(62)
    one, two = Counting(), Counting()
    stop_one, stop_two = asyncio.Event(), asyncio.Event()
    task_one = asyncio.create_task(
        run_scheduler(one, 0.02, stop_one, lock=PostgresLeaderLock(settings, key=key))
    )
    await _until(lambda: one.cycles >= 2)
    task_two = asyncio.create_task(
        run_scheduler(two, 0.02, stop_two, lock=PostgresLeaderLock(settings, key=key))
    )
    await asyncio.sleep(0.3)
    assert two.cycles == 0  # idle while the first holds the lock
    stop_one.set()
    await task_one
    await _until(lambda: two.cycles >= 1)  # the session ended, so the lock was free
    stop_two.set()
    await task_two


async def _until(condition: object, seconds: float = 10.0) -> None:
    check = condition
    assert callable(check)

    async def poll() -> None:
        while not check():
            await asyncio.sleep(0.01)

    await asyncio.wait_for(poll(), timeout=seconds)
