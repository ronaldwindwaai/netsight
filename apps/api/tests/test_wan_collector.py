"""The WAN probe-sample collector (Step 5b): bounded, read-only, honest about what it saw.

It reuses the existing allow-listed probe clients (it adds no probe capability and no network
reach) and appends one cycle per link per round. A probe that fails, hangs or raises is an
*unknown* sample, never a pass; a link no probe source serves records nothing (a gap, which the
SLA shows as unknown, not as up or down).
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from netsight_api.diagnostics import Observation
from netsight_api.storage.errors import StorageError, StorageUnavailableError
from netsight_api.storage.wan import InMemoryWanSampleRepository
from netsight_api.wan import collector as wan_collector
from netsight_api.wan.collector import WanCollector
from netsight_api.wan.config import load_wan_links

CLOCK = datetime(2026, 10, 11, 10, 0, 7, 123456, tzinfo=UTC)


def links(*entries: dict[str, Any]) -> tuple[Any, ...]:
    return load_wan_links({"NETSIGHT_WAN_LINKS": json.dumps(list(entries))}).links


def entry(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "fibre-1",
        "name": "Primary fibre",
        "role": "primary",
        "probe_targets": ["probe-a.example", "probe-b.example"],
        "probe_location": "branch",
        "dns_target": "dns-check.example",
    }
    base.update(overrides)
    return base


class FakeProbe:
    """A BlackboxClient with scripted outcomes (``status`` or an exception per target)."""

    def __init__(
        self,
        location: str | None,
        outcomes: dict[str, Any] | None = None,
        *,
        kinds: frozenset[str] | None = None,
        latency: float | None = 8.0,
    ) -> None:
        self.location = location
        self.outcomes = outcomes or {}
        self.probe_kinds = kinds
        self.latency = latency
        self.calls: list[tuple[str, str]] = []

    async def probe(self, *, kind: str, target: str, vantage: str | None) -> Observation:
        self.calls.append((kind, target))
        outcome = self.outcomes.get(target, "pass")
        if isinstance(outcome, Exception):
            raise outcome
        if callable(outcome):
            await outcome()
        return Observation(
            kind=kind,  # type: ignore[arg-type]
            label=f"{kind} {target}",
            status=outcome,
            vantage=None,
            location=self.location,  # type: ignore[arg-type]
            latency_ms=self.latency if outcome == "pass" else None,
            detail="free text that must never be stored: http://secret.internal/x",
        )


def exporter(location: str = "branch", outcomes: dict[str, Any] | None = None) -> FakeProbe:
    return FakeProbe(location, outcomes, kinds=frozenset({"icmp", "tcp", "http", "https"}))


def make(
    declared: tuple[Any, ...],
    *,
    local: FakeProbe | None = None,
    exporters: tuple[FakeProbe, ...] = (),
    store: Any = None,
    interval: int = 60,
    deadline: float | None = None,
) -> tuple[WanCollector, InMemoryWanSampleRepository]:
    repo = store if store is not None else InMemoryWanSampleRepository()
    return (
        WanCollector(
            links=declared,
            store=repo,
            local=local,
            exporters=exporters,
            interval_seconds=interval,
            clock=lambda: CLOCK,
            deadline_seconds=deadline,
        ),
        repo,
    )


def stored(repo: InMemoryWanSampleRepository, link: str = "fibre-1") -> Any:
    start = CLOCK - timedelta(hours=1)
    end = CLOCK + timedelta(hours=1)
    return repo.cycles_between(link, start, end), repo.samples_between(link, start, end)


def run(coro: Any) -> Any:
    return asyncio.run(coro)


# --- what is probed, and by whom -------------------------------------------------------------------------


def test_a_link_with_a_location_is_probed_by_the_exporter_there_with_icmp() -> None:
    there, elsewhere = exporter("branch"), exporter("cloud-external")
    collector, repo = make(links(entry()), exporters=(elsewhere, there))
    report = run(collector.run_cycle())
    assert report.recorded == 1
    assert there.calls == [("icmp", "probe-a.example"), ("icmp", "probe-b.example")]
    assert elsewhere.calls == []
    cycles, samples = stored(repo)
    assert [(s.probe, s.target, s.outcome, s.location) for _, s in samples] == [
        ("icmp", "probe-a.example", "pass", "branch"),
        ("icmp", "probe-b.example", "pass", "branch"),
    ]
    assert cycles[0].state == "up" and cycles[0].interval_seconds == 60


def test_the_exporter_cannot_resolve_names_so_no_dns_sample_is_taken_for_it() -> None:
    collector, repo = make(links(entry()), exporters=(exporter("branch"),))
    run(collector.run_cycle())
    assert all(s.probe != "dns" for _, s in stored(repo)[1])


def test_a_link_without_a_location_uses_the_local_prober_for_tcp_and_dns() -> None:
    local = FakeProbe(None)
    collector, repo = make(links(entry(probe_location=None)), local=local)
    run(collector.run_cycle())
    assert local.calls == [
        ("tcp", "probe-a.example"),
        ("tcp", "probe-b.example"),
        ("dns", "dns-check.example"),
    ]
    probes = [s.probe for _, s in stored(repo)[1]]
    assert probes == ["tcp", "tcp", "dns"]


def test_a_local_prober_deployed_at_the_links_location_serves_it() -> None:
    local = FakeProbe("branch")
    collector, _ = make(links(entry()), local=local)
    assert run(collector.run_cycle()).recorded == 1
    assert ("tcp", "probe-a.example") in local.calls


def test_a_link_nobody_serves_records_nothing_not_even_an_unknown() -> None:
    collector, repo = make(links(entry()), local=FakeProbe(None), exporters=(exporter("wifi"),))
    report = run(collector.run_cycle())
    assert (report.recorded, report.skipped) == (0, 1)
    assert stored(repo) == ([], [])


def test_no_probe_sources_at_all_records_nothing() -> None:
    collector, repo = make(links(entry()))
    assert run(collector.run_cycle()).skipped == 1
    assert stored(repo) == ([], [])


def test_a_link_with_no_probe_targets_records_nothing() -> None:
    collector, repo = make(links(entry(probe_targets=[])), exporters=(exporter(),))
    assert run(collector.run_cycle()).skipped == 1
    assert stored(repo) == ([], [])


# --- outcomes ----------------------------------------------------------------------------------------------


def test_failures_and_unknowns_are_recorded_as_themselves() -> None:
    probe = exporter("branch", {"probe-a.example": "fail", "probe-b.example": "unknown"})
    collector, repo = make(links(entry()), exporters=(probe,))
    run(collector.run_cycle())
    cycles, samples = stored(repo)
    assert [s.outcome for _, s in samples] == ["fail", "unknown"]
    assert cycles[0].state == "unknown"  # a failure with an unanswered target is not "down"
    assert samples[0][1].latency_ms is None


def test_all_targets_failing_is_a_down_cycle() -> None:
    probe = exporter("branch", {"probe-a.example": "fail", "probe-b.example": "fail"})
    collector, repo = make(links(entry()), exporters=(probe,))
    run(collector.run_cycle())
    assert stored(repo)[0][0].state == "down"


def test_a_raising_probe_is_an_unknown_sample_and_leaks_nothing() -> None:
    probe = exporter("branch", {"probe-a.example": RuntimeError("boom http://secret.internal")})
    collector, repo = make(links(entry()), exporters=(probe,))
    run(collector.run_cycle())
    samples = stored(repo)[1]
    assert [s.outcome for _, s in samples] == ["unknown", "pass"]
    assert "secret" not in repr(samples)


def test_a_hung_probe_is_bounded_and_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    async def hang() -> None:
        await asyncio.sleep(30)

    monkeypatch.setattr(wan_collector, "PROBE_TIMEOUT_SECONDS", 0.05)
    probe = exporter("branch", {"probe-a.example": hang})
    collector, repo = make(links(entry()), exporters=(probe,))
    run(collector.run_cycle())
    assert [s.outcome for _, s in stored(repo)[1]] == ["unknown", "pass"]


def test_probe_text_is_never_stored() -> None:
    collector, repo = make(links(entry()), exporters=(exporter(),))
    run(collector.run_cycle())
    assert "secret.internal" not in repr(stored(repo))


def test_an_unexpected_status_from_a_source_is_unknown_never_a_pass() -> None:
    probe = exporter("branch", {"probe-a.example": "healthy", "probe-b.example": "pass"})
    collector, repo = make(links(entry()), exporters=(probe,))
    run(collector.run_cycle())
    assert stored(repo)[1][0][1].outcome == "unknown"


# --- time ---------------------------------------------------------------------------------------------------


def test_the_cycle_time_is_the_start_of_the_round_in_whole_seconds_utc() -> None:
    collector, repo = make(links(entry()), exporters=(exporter(),), interval=90)
    run(collector.run_cycle())
    cycle = stored(repo)[0][0]
    assert cycle.sampled_at == CLOCK.replace(microsecond=0)
    assert cycle.interval_seconds == 90


def test_a_second_round_in_the_same_second_is_skipped_not_an_error() -> None:
    collector, repo = make(links(entry()), exporters=(exporter(),))
    assert run(collector.run_cycle()).recorded == 1
    again = run(collector.run_cycle())
    assert (again.recorded, again.skipped) == (0, 1)
    assert len(stored(repo)[0]) == 1


# --- failure isolation ---------------------------------------------------------------------------------------


def test_a_failing_store_for_one_link_does_not_stop_the_others() -> None:
    class Flaky(InMemoryWanSampleRepository):
        def record_cycle(self, cycle: Any, samples: Any) -> None:
            if cycle.link_id == "fibre-1":
                raise StorageError("postgresql://u:p@h/db is down")
            super().record_cycle(cycle, samples)

    declared = links(entry(), entry(id="lte-1", name="LTE", role="backup"))
    collector, repo = make(declared, exporters=(exporter(),), store=Flaky())
    report = run(collector.run_cycle())
    assert (report.recorded, report.failed) == (1, 1)
    assert stored(repo, "lte-1")[0] and not stored(repo, "fibre-1")[0]


def test_a_slow_link_past_the_cycle_deadline_records_nothing_but_does_not_block_others() -> None:
    async def hang() -> None:
        await asyncio.sleep(30)

    slow = exporter("branch", {"probe-a.example": hang, "probe-b.example": hang})
    fast = exporter("cloud-external")
    declared = links(
        entry(), entry(id="lte-1", name="LTE", role="backup", probe_location="cloud-external")
    )
    collector, repo = make(declared, exporters=(slow, fast), deadline=0.2)
    # the per-probe timeout is long, so only the deadline can cut the slow link short
    report = run(collector.run_cycle())
    assert (report.recorded, report.failed) == (1, 1)
    assert not stored(repo, "fibre-1")[0] and stored(repo, "lte-1")[0]


def test_probing_is_concurrent_across_links_but_every_link_is_probed_once_per_round() -> None:
    a, b = exporter("branch"), exporter("cloud-external")
    declared = links(
        entry(), entry(id="lte-1", name="LTE", role="backup", probe_location="cloud-external")
    )
    collector, _ = make(declared, exporters=(a, b))
    run(collector.run_cycle())
    assert len(a.calls) == 2 and len(b.calls) == 2


def test_the_collector_exposes_no_way_to_change_or_remove_stored_evidence() -> None:
    names = {n for n in dir(WanCollector) if not n.startswith("_")}
    assert names == {"run_cycle", "reset_state"}


# --- fail closed when the database cannot take the write (database review H1 / LOW) -----------------------


def test_a_missing_month_partition_is_a_logged_refusal_and_stores_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("ERROR", logger="netsight_api")
    store = InMemoryWanSampleRepository(partitioned_months=frozenset())
    collector, repo = make(links(entry()), exporters=(exporter(),), store=store)
    report = run(collector.run_cycle())
    assert (report.recorded, report.skipped, report.failed) == (0, 0, 1)
    assert stored(repo)[0] == []
    messages = " ".join(r.getMessage() for r in caplog.records)
    assert "partition" in messages and "migrate" in messages


def test_the_partitioned_month_records_normally() -> None:
    store = InMemoryWanSampleRepository(partitioned_months={(CLOCK.year, CLOCK.month)})
    collector, _ = make(links(entry()), exporters=(exporter(),), store=store)
    assert run(collector.run_cycle()).recorded == 1


def test_a_transient_database_failure_is_failed_and_never_skipped() -> None:
    class Flaky(InMemoryWanSampleRepository):
        def record_cycle(self, *args: Any, **kwargs: Any) -> None:
            raise StorageUnavailableError("deadlock")

    collector, _ = make(links(entry()), exporters=(exporter(),), store=Flaky())
    report = run(collector.run_cycle())
    assert (report.recorded, report.skipped, report.failed) == (0, 0, 1)
