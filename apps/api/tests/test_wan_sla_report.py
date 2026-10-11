"""Monthly SLA figures and the ISP-dispute evidence export (Step 5b).

Everything is computed from stored probe cycles by ``wan.sla``; this layer only assembles the
contract. Gaps in sampling are ``unknown`` windows (zero probe rounds), never up and never down.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from netsight_api.contracts import validate
from netsight_api.storage.errors import StorageError
from netsight_api.storage.wan import InMemoryWanSampleRepository
from netsight_api.wan import sla
from netsight_api.wan.config import WanConfig, load_wan_links
from netsight_api.wan.sla import Sample
from netsight_api.wan.sla_report import (
    BASIS,
    CSV_COLUMNS,
    build_export,
    build_sla,
    export_csv,
)

NOW = datetime(2026, 10, 11, 12, 0, 0, tzinfo=UTC)
SEP = datetime(2026, 9, 1, tzinfo=UTC)


def declare(*links: dict[str, Any]) -> WanConfig:
    return load_wan_links({"NETSIGHT_WAN_LINKS": json.dumps(list(links))})


def link(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "fibre-1",
        "name": "Primary fibre",
        "role": "primary",
        "isp": "Example ISP",
        "probe_targets": ["probe-a.example"],
        "probe_location": "branch",
        "dns_target": "dns-check.example",
        "uptime_target_pct": 99.9,
    }
    base.update(overrides)
    return base


def add(
    store: InMemoryWanSampleRepository,
    when: datetime,
    outcomes: list[str],
    *,
    link_id: str = "fibre-1",
    dns: bool = True,
) -> None:
    rows = [
        Sample("icmp", "probe-a.example", o, 5.0 if o == "pass" else None, "branch")
        for o in outcomes
    ]  # type: ignore[arg-type]
    if dns:
        rows.append(Sample("dns", "dns-check.example", "pass", 9.0))
    store.record_cycle(sla.build_cycle(link_id, when, 60, rows), rows)


def run_cycles(
    store: InMemoryWanSampleRepository,
    start: datetime,
    minutes: int,
    outcomes: list[str],
    **kwargs: Any,
) -> None:
    for minute in range(minutes):
        add(store, start + timedelta(minutes=minute), outcomes, **kwargs)


def sla_of(config: WanConfig, store: Any, month: str = "2026-09", now: datetime = NOW) -> Any:
    response = build_sla(config, store, month, now)
    validate("internet_sla_response", json.loads(response.model_dump_json(by_alias=True)))
    return response


def export_of(
    config: WanConfig,
    store: Any,
    month: str = "2026-09",
    now: datetime = NOW,
    *,
    detail: bool = True,
) -> Any:
    export = build_export(config, store, month, now, detail=detail)
    validate("internet_sla_export", json.loads(export.model_dump_json(by_alias=True)))
    return export


# --- states ----------------------------------------------------------------------------------------


def test_no_declared_links_or_a_bad_declaration_carry_no_links() -> None:
    store = InMemoryWanSampleRepository()
    for config_state in ("not-connected", "unknown"):
        response = sla_of(WanConfig(config_state), store)  # type: ignore[arg-type]
        assert response.state == config_state and response.links == []
        assert response.period_start is None and response.period_end is None
        assert response.month == "2026-09"


def test_no_sample_store_is_not_connected_for_the_whole_surface() -> None:
    response = sla_of(declare(link()), None)
    assert response.state == "not-connected" and response.links == []
    assert export_of(declare(link()), None).state == "not-connected"


def test_a_store_that_fails_for_every_link_is_unknown_and_leaks_nothing() -> None:
    class Broken(InMemoryWanSampleRepository):
        def cycles_between(self, *args: Any, **kwargs: Any) -> Any:
            raise StorageError("dsn postgresql://u:p@h/db")

    response = sla_of(declare(link()), Broken())
    assert response.state == "unknown" and response.links == []
    assert response.period_start is None and response.period_end is None
    assert "postgresql" not in response.model_dump_json()


def test_one_unreadable_link_does_not_hide_a_readable_one() -> None:
    class Flaky(InMemoryWanSampleRepository):
        def cycles_between(self, link_id: str, *args: Any, **kwargs: Any) -> Any:
            if link_id == "lte-1":
                raise StorageError("boom")
            return super().cycles_between(link_id, *args, **kwargs)

    store = Flaky()
    run_cycles(store, SEP, 10, ["pass"])
    config = declare(link(), link(id="lte-1", name="LTE", role="backup"))
    response = sla_of(config, store)
    assert response.state == "ok"
    assert [item.state for item in response.links] == ["ok", "unknown"]


@pytest.mark.parametrize("month", ["2026-13", "2026-10-01", "", "2024-01", "2027-01", "abc"])
def test_a_month_outside_the_server_bounds_is_refused(month: str) -> None:
    with pytest.raises(ValueError, match="month"):
        build_sla(declare(link()), InMemoryWanSampleRepository(), month, NOW)
    with pytest.raises(ValueError, match="month"):
        build_export(declare(link()), InMemoryWanSampleRepository(), month, NOW)


def test_the_exact_instant_a_month_starts_is_an_empty_but_honest_period() -> None:
    start_of_month = datetime(2026, 10, 1, tzinfo=UTC)
    store = InMemoryWanSampleRepository()
    response = sla_of(declare(link()), store, "2026-10", start_of_month)
    assert response.state == "ok"
    assert response.period_start == response.period_end == start_of_month
    item = response.links[0]
    assert item.state == "ok" and item.total_seconds == 0
    assert (item.up_seconds, item.down_seconds, item.degraded_seconds, item.unknown_seconds) == (
        0,
        0,
        0,
        0,
    )
    assert item.uptime_pct is None and item.coverage_pct == 0.0 and item.windows_truncated is False
    export = export_of(declare(link()), store, "2026-10", start_of_month)
    assert export.state == "ok" and export.links[0].windows == []
    assert parse(export_csv(export)) == [list(CSV_COLUMNS)]


def test_a_month_in_the_future_is_still_refused() -> None:
    with pytest.raises(ValueError, match="month"):
        build_sla(
            declare(link()),
            InMemoryWanSampleRepository(),
            "2026-11",
            datetime(2026, 10, 31, 23, 59, 59, tzinfo=UTC),
        )


def test_a_clock_with_fractions_of_a_second_still_adds_up() -> None:
    store = InMemoryWanSampleRepository()
    run_cycles(store, datetime(2026, 10, 11, 11, 0, tzinfo=UTC), 30, ["pass"])
    now = NOW + timedelta(microseconds=700_000)
    item = sla_of(declare(link()), store, "2026-10", now).links[0]
    parts = item.up_seconds + item.degraded_seconds + item.down_seconds + item.unknown_seconds
    assert item.state == "ok" and parts == item.total_seconds


# --- figures ---------------------------------------------------------------------------------------


def test_a_past_month_has_its_calendar_bounds_and_adds_up() -> None:
    store = InMemoryWanSampleRepository()
    run_cycles(store, SEP, 60, ["pass"])
    response = sla_of(declare(link()), store)
    assert response.state == "ok"
    assert response.period_start == SEP and response.period_end == datetime(2026, 10, 1, tzinfo=UTC)
    item = response.links[0]
    assert item.total_seconds == 30 * 86400
    assert item.up_seconds == 60 * 60 + 30  # the last cycle covers its interval plus half
    assert item.up_seconds + item.degraded_seconds + item.down_seconds + item.unknown_seconds == (
        item.total_seconds
    )
    assert item.uptime_pct == 100.0 and item.outage_count == 0 and item.violations == []
    assert item.cycle_count == 60


def test_the_current_month_ends_now() -> None:
    store = InMemoryWanSampleRepository()
    run_cycles(store, datetime(2026, 10, 11, 11, 0, tzinfo=UTC), 30, ["pass"])
    response = sla_of(declare(link()), store, "2026-10")
    assert response.period_end == NOW
    assert response.links[0].total_seconds == int(
        (NOW - datetime(2026, 10, 1, tzinfo=UTC)).total_seconds()
    )


def test_outages_degraded_time_and_a_violation_are_computed() -> None:
    store = InMemoryWanSampleRepository()
    run_cycles(store, SEP, 100, ["pass", "pass"])
    run_cycles(store, SEP + timedelta(minutes=100), 20, ["fail", "fail"])
    run_cycles(store, SEP + timedelta(minutes=120), 10, ["pass", "fail"])
    run_cycles(store, SEP + timedelta(minutes=130), 70, ["pass", "pass"])
    item = sla_of(declare(link()), store).links[0]
    assert item.down_seconds == 20 * 60
    assert item.degraded_seconds == 10 * 60
    assert item.outage_count == 1 and item.longest_outage_seconds == 20 * 60
    # known time is 200 minutes + the 30 s grace of the last cycle; target 99.9 is missed
    assert item.uptime_pct is not None and item.uptime_pct < 99.9
    assert [(v.kind, v.target_pct) for v in item.violations] == [("uptime-below-target", 99.9)]
    assert item.uptime_target_pct == 99.9


def test_no_configured_target_means_no_violation() -> None:
    store = InMemoryWanSampleRepository()
    run_cycles(store, SEP, 10, ["fail"])
    item = sla_of(declare(link(uptime_target_pct=None)), store).links[0]
    assert item.down_seconds > 0 and item.violations == [] and item.uptime_target_pct is None


def test_a_month_with_no_samples_is_all_unknown_not_up() -> None:
    item = sla_of(declare(link()), InMemoryWanSampleRepository()).links[0]
    assert item.state == "ok"
    assert (item.up_seconds, item.down_seconds, item.degraded_seconds) == (0, 0, 0)
    assert item.unknown_seconds == item.total_seconds
    assert item.uptime_pct is None and item.coverage_pct == 0.0 and item.violations == []


def test_links_are_independent() -> None:
    store = InMemoryWanSampleRepository()
    run_cycles(store, SEP, 30, ["fail"], link_id="lte-1")
    run_cycles(store, SEP, 30, ["pass"])
    config = declare(link(), link(id="lte-1", name="LTE", role="backup"))
    first, second = sla_of(config, store).links
    assert (first.down_seconds, second.down_seconds) == (0, 30 * 60 + 30)


# --- the evidence export ----------------------------------------------------------------------------


def test_the_export_lists_outage_degraded_and_unknown_windows_with_counts_and_sources() -> None:
    store = InMemoryWanSampleRepository()
    run_cycles(store, SEP, 10, ["pass", "pass"])
    run_cycles(store, SEP + timedelta(minutes=10), 5, ["fail", "fail"])
    run_cycles(store, SEP + timedelta(minutes=15), 5, ["pass", "fail"])
    # then silence for the rest of the month: a gap, not "up"
    export = export_of(declare(link()), store)
    item = export.links[0]
    assert export.basis == BASIS
    assert [(w.kind, w.duration_seconds, w.sample_count) for w in item.windows[:2]] == [
        ("down", 5 * 60, 5),
        ("degraded", 5 * 60 + 30, 5),
    ]
    gap = item.windows[-1]
    assert gap.kind == "unknown" and gap.sample_count == 0
    assert gap.ended_at == datetime(2026, 10, 1, tzinfo=UTC)
    assert all(w.kind != "up" for w in item.windows) and item.windows_truncated is False
    assert item.isp == "Example ISP" and export.detail_redacted is False
    assert [(s.probe, s.target, s.location) for s in item.sources] == [
        ("dns", "dns-check.example", None),
        ("icmp", "probe-a.example", "branch"),
    ]
    assert item.link.down_seconds == 5 * 60


def test_the_export_never_infers_beyond_the_samples() -> None:
    export = export_of(declare(link()), InMemoryWanSampleRepository())
    item = export.links[0]
    assert [(w.kind, w.sample_count) for w in item.windows] == [("unknown", 0)]
    assert item.windows[0].duration_seconds == item.link.total_seconds


def test_the_window_list_is_bounded_and_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    import netsight_api.wan.sla_report as report

    monkeypatch.setattr(report, "MAX_EXPORT_WINDOWS", 3)
    store = InMemoryWanSampleRepository()
    for minute in range(0, 40, 2):
        add(store, SEP + timedelta(minutes=minute), ["fail"])
    item = export_of(declare(link()), store).links[0]
    assert len(item.windows) == 3 and item.windows_truncated is True
    assert item.link.outage_count == 20  # the figures are never truncated


def test_an_unreadable_link_exports_no_evidence_but_does_not_hide_the_others() -> None:
    class Flaky(InMemoryWanSampleRepository):
        def probe_sources(self, link_id: str, *args: Any, **kwargs: Any) -> Any:
            if link_id == "lte-1":
                raise StorageError("x")
            return super().probe_sources(link_id, *args, **kwargs)

    store = Flaky()
    run_cycles(store, SEP, 5, ["pass"])
    run_cycles(store, SEP, 5, ["pass"], link_id="lte-1")
    config = declare(link(), link(id="lte-1", name="LTE", role="backup"))
    good, broken = export_of(config, store).links
    assert good.link.state == "ok" and good.sources and good.windows
    assert broken.link.state == "unknown" and broken.windows == [] and broken.sources == []
    assert broken.link.up_seconds is None


# --- CSV ----------------------------------------------------------------------------------------------


def parse(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))


def test_csv_has_a_fixed_header_one_row_per_window_and_crlf_lines() -> None:
    store = InMemoryWanSampleRepository()
    run_cycles(store, SEP, 5, ["fail"])
    export = export_of(declare(link()), store)
    text = export_csv(export)
    rows = parse(text)
    assert tuple(rows[0]) == CSV_COLUMNS
    assert len(rows) == 1 + len(export.links[0].windows)
    assert text.endswith("\r\n") and "\n" not in text.replace("\r\n", "")
    down = next(row for row in rows[1:] if row[CSV_COLUMNS.index("kind")] == "down")
    record = dict(zip(CSV_COLUMNS, down, strict=True))
    assert record["month"] == "2026-09" and record["link_id"] == "fibre-1"
    assert record["link_name"] == "Primary fibre" and record["isp"] == "Example ISP"
    assert record["started_at"] == "2026-09-01T00:00:00Z"
    assert record["ended_at"] == "2026-09-01T00:05:30Z"
    assert record["duration_seconds"] == "330" and record["sample_count"] == "5"
    assert record["sources"] == "dns:dns-check.example;icmp:probe-a.example@branch"


def test_csv_is_deterministic_and_carries_unknown_gaps() -> None:
    store = InMemoryWanSampleRepository()
    run_cycles(store, SEP, 3, ["pass"])
    first = export_csv(export_of(declare(link()), store))
    second = export_csv(export_of(declare(link()), store))
    assert first == second
    assert ",unknown," in first


def test_csv_neutralises_spreadsheet_formulas_and_quotes_awkward_text() -> None:
    store = InMemoryWanSampleRepository()
    run_cycles(store, SEP, 3, ["fail"])
    config = declare(link(name='=HYPERLINK("http://x","y"), ok', isp="+cmd|' /C calc'!A0"))
    rows = parse(export_csv(export_of(config, store)))
    name = rows[1][CSV_COLUMNS.index("link_name")]
    isp = rows[1][CSV_COLUMNS.index("isp")]
    assert name.startswith("'=") and isp.startswith("'+")
    for row in rows[1:]:
        for cell in row:
            assert not cell.startswith(("=", "+", "@", "\t", "\r"))


def test_csv_of_a_non_ok_export_is_just_the_header() -> None:
    rows = parse(export_csv(export_of(declare(link()), None)))
    assert rows == [list(CSV_COLUMNS)]


def test_csv_leaves_no_row_for_an_unreadable_link() -> None:
    class Broken(InMemoryWanSampleRepository):
        def cycles_between(self, *args: Any, **kwargs: Any) -> Any:
            raise StorageError("x")

    assert parse(export_csv(export_of(declare(link()), Broken()))) == [list(CSV_COLUMNS)]
