"""The WAN collector against real PostgreSQL (skipped without NETSIGHT_TEST_PG_DSN).

Proves, with the production role split (the collector's INSERT-only role writes, the API's
SELECT-only role reads): the collector's rounds land in the append-only partitioned tables and the
SLA computed from PostgreSQL equals the SLA computed from the in-memory store for the same data;
one leader per database (a key of its own, independent of the evaluator's).
"""

from __future__ import annotations

import asyncio
import json
import secrets
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pg_support import PG_DSN, requires_pg
from wan_support import SplitRoleStore, provision_wan

from netsight_api.evaluation.leader import EVALUATOR_LOCK_KEY, PostgresLeaderLock
from netsight_api.evaluation.wiring import run_scheduler
from netsight_api.storage.connection import PostgresSettings
from netsight_api.storage.wan import InMemoryWanSampleRepository
from netsight_api.wan import sla
from netsight_api.wan.collector import WanCollector
from netsight_api.wan.config import load_wan_links
from netsight_api.wan.sla import Sample
from netsight_api.wan.sla_report import build_export, build_sla
from netsight_api.wan.wiring import WAN_COLLECTOR_LOCK_KEY

pytestmark = requires_pg

NOW = datetime(2026, 10, 11, 12, 0, 0, tzinfo=UTC)
SEP = datetime(2026, 9, 1, tzinfo=UTC)
CONFIG = load_wan_links(
    {
        "NETSIGHT_WAN_LINKS": json.dumps(
            [
                {
                    "id": "fibre-1",
                    "name": "Primary fibre",
                    "role": "primary",
                    "isp": "Example ISP",
                    "probe_targets": ["probe-a.example"],
                    "probe_location": "branch",
                    "uptime_target_pct": 99.0,
                }
            ]
        )
    }
)


@pytest.fixture
def runtime_store() -> Iterator[SplitRoleStore]:
    with provision_wan() as database:
        yield SplitRoleStore(database)


class Prober:
    location = "branch"
    probe_kinds = frozenset({"icmp"})

    def __init__(self, status: str = "pass") -> None:
        self.status = status

    async def probe(self, *, kind: str, target: str, vantage: str | None) -> Any:
        from netsight_api.diagnostics import Observation

        return Observation(
            kind=kind,  # type: ignore[arg-type]
            label="x",
            status=self.status,  # type: ignore[arg-type]
            location="branch",
            latency_ms=6.5,
        )


def test_the_collector_writes_through_the_app_role_and_the_rows_read_back(
    runtime_store: SplitRoleStore,
) -> None:
    ticks = iter(NOW + timedelta(minutes=n) for n in range(100))
    collector = WanCollector(
        links=CONFIG.links,
        store=runtime_store,
        local=None,
        exporters=[Prober()],  # type: ignore[list-item]
        interval_seconds=60,
        clock=lambda: next(ticks),
    )
    reports = [asyncio.run(collector.run_cycle()) for _ in range(3)]
    assert [r.recorded for r in reports] == [1, 1, 1]
    window = (NOW - timedelta(hours=1), NOW + timedelta(hours=1))
    cycles = runtime_store.cycles_between("fibre-1", *window)
    assert [c.state for c in cycles] == ["up", "up", "up"]
    samples = runtime_store.samples_between("fibre-1", *window)
    assert [(s.probe, s.target, s.location, s.latency_ms) for _, s in samples] == [
        ("icmp", "probe-a.example", "branch", 6.5)
    ] * 3


def populate(store: Any) -> None:
    pattern = ["pass"] * 100 + ["fail"] * 15 + ["pass"] * 30
    for minute, outcome in enumerate(pattern):
        rows = [
            Sample("icmp", "probe-a.example", outcome, 5.0 if outcome == "pass" else None, "branch")
        ]  # type: ignore[arg-type]
        rows.append(Sample("dns", "dns-check.example", "pass", 9.0))
        store.record_cycle(
            sla.build_cycle("fibre-1", SEP + timedelta(minutes=minute), 60, rows), rows
        )


def test_the_sla_and_the_export_from_postgres_equal_those_from_memory(
    runtime_store: SplitRoleStore,
) -> None:
    memory = InMemoryWanSampleRepository()
    populate(memory)
    populate(runtime_store)
    assert build_sla(CONFIG, runtime_store, "2026-09", NOW) == build_sla(
        CONFIG, memory, "2026-09", NOW
    )
    assert build_export(CONFIG, runtime_store, "2026-09", NOW) == build_export(
        CONFIG, memory, "2026-09", NOW
    )
    item = build_sla(CONFIG, runtime_store, "2026-09", NOW).links[0]
    assert item.down_seconds == 15 * 60 and item.outage_count == 1


def test_the_scheduler_samples_only_while_it_holds_the_wan_lock(
    runtime_store: SplitRoleStore,
) -> None:
    assert PG_DSN
    settings = PostgresSettings(dsn=PG_DSN)
    key = secrets.randbits(62)  # private key: tests never contend with each other
    leader, rival = PostgresLeaderLock(settings, key=key), PostgresLeaderLock(settings, key=key)

    async def scenario() -> tuple[int, int]:
        counts = [0, 0]

        class Runner:
            def __init__(self, slot: int) -> None:
                self.slot = slot

            async def run_cycle(self) -> None:
                counts[self.slot] += 1

        stop = asyncio.Event()
        tasks = [
            asyncio.create_task(run_scheduler(Runner(0), 30, stop, lock=leader)),
            asyncio.create_task(run_scheduler(Runner(1), 30, stop, lock=rival)),
        ]
        await asyncio.sleep(0.5)
        stop.set()
        await asyncio.gather(*tasks)
        return counts[0], counts[1]

    try:
        assert sorted(asyncio.run(scenario())) == [0, 1]
    finally:
        leader.release()
        rival.release()


def test_the_wan_and_evaluator_locks_do_not_contend() -> None:
    assert PG_DSN
    settings = PostgresSettings(dsn=PG_DSN)
    # the real keys are fixed, so use them only if free: a developer database may have the app running
    evaluator = PostgresLeaderLock(settings, key=EVALUATOR_LOCK_KEY)
    collector = PostgresLeaderLock(settings, key=WAN_COLLECTOR_LOCK_KEY)
    try:
        if not evaluator.try_acquire():
            pytest.skip("an evaluator already holds the real lock in this database")
        if not collector.try_acquire():
            pytest.skip("a collector already holds the real lock in this database")
        assert evaluator.still_held() and collector.still_held()
    finally:
        evaluator.release()
        collector.release()
