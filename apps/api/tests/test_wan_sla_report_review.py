"""Review follow-ups for the SLA report: truncation signalling, redaction and closed-month caching.

Helpers are shared with ``test_wan_sla_report``. Each test names the review finding it closes.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from test_wan_sla_report import (
    NOW,
    SEP,
    add,
    declare,
    export_of,
    link,
    parse,
    run_cycles,
    sla_of,
)

from netsight_api.storage.errors import StorageError
from netsight_api.storage.wan import InMemoryWanSampleRepository
from netsight_api.wan import sla_report as report
from netsight_api.wan.sla_report import (
    BASIS,
    CSV_COLUMNS,
    ClosedMonthCache,
    build_export,
    build_sla,
    export_csv,
)

NOV = datetime(2026, 11, 20, tzinfo=UTC)  # well after October closed


def many_outages(store: InMemoryWanSampleRepository, **kwargs: Any) -> None:
    for minute in range(0, 40, 2):
        add(store, SEP + timedelta(minutes=minute), ["fail"], **kwargs)


# --- CSV truncation -------------------------------------------------------------------------------


def test_csv_of_a_truncated_export_ends_with_a_sentinel_row_and_a_fail_safe_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(report, "MAX_EXPORT_WINDOWS", 3)
    store = InMemoryWanSampleRepository()
    many_outages(store)
    run_cycles(store, SEP, 2, ["pass"], link_id="lte-1")
    config = declare(link(), link(id="lte-1", name="LTE", role="backup"))
    export = export_of(config, store)
    assert export.links[0].windows_truncated is True
    assert export.links[1].windows_truncated is False
    rows = parse(export_csv(export))
    kinds = [row[CSV_COLUMNS.index("kind")] for row in rows[1:]]
    assert kinds.count("truncated") == 1 and kinds[-1] == "truncated"
    last = dict(zip(CSV_COLUMNS, rows[-1], strict=True))
    assert last["link_id"] == "fibre-1" and last["month"] == "2026-09"
    assert "INCOMPLETE" in last["sources"] and "3" in last["sources"]
    assert last["started_at"] == "" and last["ended_at"] == ""
    assert last["duration_seconds"] == "" and last["sample_count"] == ""


def test_csv_of_a_complete_export_has_no_sentinel() -> None:
    store = InMemoryWanSampleRepository()
    run_cycles(store, SEP, 5, ["fail"])
    rows = parse(export_csv(export_of(declare(link()), store)))
    assert all(row[CSV_COLUMNS.index("kind")] != "truncated" for row in rows[1:])


def test_the_sla_response_says_when_the_export_windows_would_be_cut(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = InMemoryWanSampleRepository()
    many_outages(store)
    assert sla_of(declare(link()), store).links[0].windows_truncated is False
    monkeypatch.setattr(report, "MAX_EXPORT_WINDOWS", 3)
    assert sla_of(declare(link()), store).links[0].windows_truncated is True


def test_an_unreadable_link_has_no_truncation_flag() -> None:
    class Flaky(InMemoryWanSampleRepository):
        def cycles_between(self, link_id: str, *args: Any, **kwargs: Any) -> Any:
            if link_id == "lte-1":
                raise StorageError("x")
            return super().cycles_between(link_id, *args, **kwargs)

    config = declare(link(), link(id="lte-1", name="LTE", role="backup"))
    good, broken = sla_of(config, Flaky()).links
    assert good.windows_truncated is False and broken.windows_truncated is None


def test_the_basis_states_that_evidence_is_only_as_trustworthy_as_its_recording_host() -> None:
    assert "only as trustworthy as the host" in BASIS
    assert "not signed" in BASIS


# --- detail redaction (internet:read_detail) ---------------------------------------------------------


def test_the_export_withholds_the_isp_name_without_the_detail_permission() -> None:
    store = InMemoryWanSampleRepository()
    run_cycles(store, SEP, 5, ["fail"])
    export = export_of(declare(link()), store, detail=False)
    assert export.detail_redacted is True and export.links[0].isp is None
    assert export.links[0].link.down_seconds is not None  # the evidence itself is still there
    row = parse(export_csv(export))[1]
    assert row[CSV_COLUMNS.index("isp")] == ""
    assert "Example ISP" not in export_csv(export) + export.model_dump_json()


def test_the_export_default_is_redacted_fail_closed() -> None:
    export = build_export(declare(link()), InMemoryWanSampleRepository(), "2026-09", NOW)
    assert export.detail_redacted is True and export.links[0].isp is None


# --- closed months are cached (immutable), open months never ------------------------------------------


class CountingStore(InMemoryWanSampleRepository):
    def __init__(self) -> None:
        super().__init__()
        self.reads = 0

    def cycles_between(self, *args: Any, **kwargs: Any) -> Any:
        self.reads += 1
        return super().cycles_between(*args, **kwargs)


def test_a_closed_month_is_computed_once_and_recomputation_is_identical() -> None:
    store = CountingStore()
    run_cycles(store, SEP, 30, ["pass"])
    cache = ClosedMonthCache()
    first = build_sla(declare(link()), store, "2026-09", NOW, cache=cache)
    second = build_sla(declare(link()), store, "2026-09", NOW, cache=cache)
    assert store.reads == 1 and first == second
    assert first == build_sla(declare(link()), store, "2026-09", NOW)  # no cache: same figures


def test_the_export_of_a_closed_month_is_cached_with_its_sources() -> None:
    store = CountingStore()
    run_cycles(store, SEP, 30, ["pass"])
    cache = ClosedMonthCache()
    first = build_export(declare(link()), store, "2026-09", NOW, detail=True, cache=cache)
    second = build_export(declare(link()), store, "2026-09", NOW, detail=True, cache=cache)
    assert store.reads == 1 and first == second and first.links[0].sources
    # the SLA entry carries no sources, so it is a separate cache entry
    build_sla(declare(link()), store, "2026-09", NOW, cache=cache)
    assert store.reads == 2


def test_the_open_month_and_the_settling_hour_are_never_cached() -> None:
    store = CountingStore()
    run_cycles(store, datetime(2026, 10, 11, 11, 0, tzinfo=UTC), 30, ["pass"])
    cache = ClosedMonthCache()
    build_sla(declare(link()), store, "2026-10", NOW, cache=cache)
    build_sla(declare(link()), store, "2026-10", NOW, cache=cache)
    assert store.reads == 2
    settling = datetime(2026, 11, 1, 0, 30, tzinfo=UTC)  # October ended, a late round may land
    build_sla(declare(link()), store, "2026-10", settling, cache=cache)
    build_sla(declare(link()), store, "2026-10", settling, cache=cache)
    assert store.reads == 4
    build_sla(declare(link()), store, "2026-10", NOV, cache=cache)
    build_sla(declare(link()), store, "2026-10", NOV, cache=cache)
    assert store.reads == 5


def test_a_failed_read_is_never_cached() -> None:
    class Flaky(CountingStore):
        fail = True

        def cycles_between(self, *args: Any, **kwargs: Any) -> Any:
            if self.fail:
                raise StorageError("x")
            return super().cycles_between(*args, **kwargs)

    store = Flaky()
    cache = ClosedMonthCache()
    assert build_sla(declare(link()), store, "2026-09", NOW, cache=cache).state == "unknown"
    store.fail = False
    run_cycles(store, SEP, 3, ["pass"])
    assert build_sla(declare(link()), store, "2026-09", NOW, cache=cache).state == "ok"


def test_the_cache_key_includes_the_uptime_target_and_the_cache_is_bounded() -> None:
    store = CountingStore()
    run_cycles(store, SEP, 30, ["pass"])
    cache = ClosedMonthCache(max_entries=2)
    build_sla(declare(link(uptime_target_pct=99.0)), store, "2026-09", NOW, cache=cache)
    build_sla(declare(link(uptime_target_pct=99.5)), store, "2026-09", NOW, cache=cache)
    assert store.reads == 2
    build_sla(declare(link(uptime_target_pct=99.9)), store, "2026-09", NOW, cache=cache)
    assert len(cache) == 2  # the oldest entry was evicted
    build_sla(declare(link(uptime_target_pct=99.0)), store, "2026-09", NOW, cache=cache)
    assert store.reads == 4
    cache.clear()
    assert len(cache) == 0


def test_the_cache_never_serves_one_link_the_figures_of_another() -> None:
    store = CountingStore()
    run_cycles(store, SEP, 30, ["pass"])
    run_cycles(store, SEP, 30, ["fail"], link_id="lte-1")
    cache = ClosedMonthCache()
    config = declare(link(), link(id="lte-1", name="LTE", role="backup"))
    first, second = build_sla(config, store, "2026-09", NOW, cache=cache).links
    assert first.down_seconds == 0 and second.down_seconds == 30 * 60 + 30
