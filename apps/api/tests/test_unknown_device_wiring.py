"""Wiring of the unknown-device store, scanner and scheduled scan from the environment (Step 8c).

The scheduled scan is off by default. Enabled, it needs ``DATABASE_URL`` and runs only under its own
advisory lock; an invalid setting fails start-up rather than silently running something different.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from fastapi.testclient import TestClient

from netsight_api.main import app
from netsight_api.storage.unknown_devices import InMemoryUnknownDeviceRepository
from netsight_api.unknown_devices import wiring
from netsight_api.unknown_devices.policy import POLICY_ENV

PG_URL = "postgresql://netsight:not-a-real-password@127.0.0.1:1/netsight"


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (wiring.ENABLED_ENV, wiring.INTERVAL_ENV, "DATABASE_URL", POLICY_ENV):
        monkeypatch.delenv(name, raising=False)
    wiring.reset_for_tests()


def test_the_scheduled_scan_is_off_by_default() -> None:
    assert wiring.scan_enabled({}) is False
    assert wiring.build_scan_service({}) is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1", True),
        ("true", True),
        ("YES", True),
        ("on", True),
        ("0", False),
        ("false", False),
        ("no", False),
        ("off", False),
        ("", False),
    ],
)
def test_the_switch_accepts_only_explicit_words(raw: str, expected: bool) -> None:
    assert wiring.scan_enabled({wiring.ENABLED_ENV: raw}) is expected


@pytest.mark.parametrize("raw", ["maybe", "2", "enabled", "tru"])
def test_any_other_value_fails_start_up(raw: str) -> None:
    with pytest.raises(ValueError):
        wiring.scan_enabled({wiring.ENABLED_ENV: raw})


@pytest.mark.parametrize(
    ("raw", "expected"), [("", 900), ("300", 300), ("86400", 86400), ("900", 900)]
)
def test_the_interval_is_bounded(raw: str, expected: int) -> None:
    assert wiring.scan_interval({wiring.INTERVAL_ENV: raw}) == expected


@pytest.mark.parametrize("raw", ["299", "86401", "0", "-1", "x", "1.5", "٣٠٠"])
def test_an_unusable_interval_fails_start_up(raw: str) -> None:
    with pytest.raises(ValueError):
        wiring.scan_interval({wiring.INTERVAL_ENV: raw})


def test_enabling_the_scan_without_a_database_fails_start_up() -> None:
    with pytest.raises(ValueError):
        wiring.build_scan_service({wiring.ENABLED_ENV: "1"})
    with pytest.raises(ValueError):
        wiring.build_scan_service({wiring.ENABLED_ENV: "1", "DATABASE_URL": "mysql://x"})


def test_enabling_the_scan_builds_a_service_with_its_own_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", PG_URL)
    service = wiring.build_scan_service(
        {wiring.ENABLED_ENV: "1", wiring.INTERVAL_ENV: "600", "DATABASE_URL": PG_URL}
    )
    assert service is not None and service.interval_seconds == 600
    assert "not-a-real-password" not in repr(service)


def test_without_a_database_url_there_is_no_store() -> None:
    assert wiring.get_optional_store() is None


def test_a_database_url_that_is_not_postgres_gives_a_store_that_fails_instead_of_leaking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", "mysql://user:hunter2@db/x")
    store: Any = wiring.get_optional_store()
    with pytest.raises(Exception) as excinfo:
        store.counts()
    assert "hunter2" not in str(excinfo.value)


def test_the_policy_is_parsed_once_per_distinct_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    first = wiring._policy_for('{"version": 1, "default_severity": "low"}', "")
    again = wiring._policy_for('{"version": 1, "default_severity": "low"}', "")
    assert first is again and first.state == "configured"


@pytest.mark.asyncio
async def test_starting_a_disabled_scan_runs_nothing() -> None:
    runtime = wiring.start_scan(None)
    assert runtime.task is None
    await runtime.shutdown()


@pytest.mark.asyncio
async def test_an_enabled_scan_runs_while_it_leads_and_stops_cleanly() -> None:
    from netsight_api.evaluation.leader import InMemoryLeaderLock, LeaseBoard

    class Cycles:
        def __init__(self) -> None:
            self.runs = 0
            self.ran = asyncio.Event()

        async def run_cycle(self) -> None:
            self.runs += 1
            self.ran.set()

    cycles = Cycles()
    service = wiring.ScanService(cycles, 300, InMemoryLeaderLock(LeaseBoard()))  # type: ignore[arg-type]
    runtime = wiring.start_scan(service)
    await asyncio.wait_for(cycles.ran.wait(), 5)
    await runtime.shutdown()
    assert cycles.runs >= 1 and runtime.task is not None and runtime.task.done()


@pytest.mark.asyncio
async def test_a_scan_that_does_not_hold_the_lock_does_not_run() -> None:
    from netsight_api.evaluation.leader import InMemoryLeaderLock, LeaseBoard

    class Cycles:
        runs = 0

        async def run_cycle(self) -> None:
            self.runs += 1

    board = LeaseBoard()
    board.seize(object())  # another worker leads
    cycles = Cycles()
    runtime = wiring.start_scan(wiring.ScanService(cycles, 300, InMemoryLeaderLock(board)))  # type: ignore[arg-type]
    await asyncio.sleep(0.2)
    await runtime.shutdown()
    assert cycles.runs == 0


def test_the_application_starts_with_the_scan_disabled_and_exposes_no_task() -> None:
    with TestClient(app) as client:
        assert client.get("/api/v1/health").status_code == 200
        assert app.state.unknown_scan_task is None
    assert InMemoryUnknownDeviceRepository  # the in-memory store stays importable for tests only
