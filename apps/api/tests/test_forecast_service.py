"""The capacity forecast service (Step 13): states, sources, thresholds and advisory text.

A fake flow source stands in for ClickHouse. These pin the honest behaviour: no source is
``not-connected``, an unreadable one is ``unknown``, too little history is ``insufficient-data``, a
missing day is never zero, and a recommendation is advice with evidence that nothing executes.
"""

from __future__ import annotations

import ast
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from forecast_support import GB, LAST, NOW, FakeSource, day, growing, totals

from netsight_api.contracts import validate
from netsight_api.forecast import service


async def build(
    source: FakeSource | None,
    *,
    horizon: int = 7,
    history: int = 56,
    limit: int | None = None,
):
    return await service.build_capacity_forecast(
        source=source, now=NOW, horizon_days=horizon, history_days=history, traffic_limit=limit
    )


def traffic(response):
    return next(s for s in response.series if s.id == "traffic-volume")


# --- states -----------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_flow_source_is_not_connected_and_carries_nothing() -> None:
    response = await build(None)
    assert response.state == "not-connected"
    series = traffic(response)
    assert (series.state, series.reason) == ("not-connected", "no-source")
    assert series.history == [] and series.forecast == [] and series.method is None
    assert [r.kind for r in response.recommendations] == ["connect-history-source"] * 3


@pytest.mark.asyncio
async def test_an_unreadable_source_is_unknown_and_never_leaks_the_error() -> None:
    response = await build(FakeSource(error=RuntimeError("password=hunter2 at 10.0.0.9")))
    series = traffic(response)
    assert (series.state, series.reason) == ("unknown", "source-unreadable")
    assert "hunter2" not in json.dumps(response.model_dump(mode="json"))
    assert response.state == "unknown"


@pytest.mark.asyncio
async def test_enough_history_gives_a_labelled_forecast_of_exactly_the_horizon() -> None:
    source = FakeSource(totals(growing(30)))
    response = await build(source, horizon=10)
    series = traffic(response)
    assert response.state == "ok" and response.is_forecast is True
    assert response.history_through == LAST.isoformat() and response.horizon_days == 10
    assert series.state == "ok" and len(series.forecast) == 10 and len(series.history) == 30
    assert series.forecast[0].day == (LAST + timedelta(days=1)).isoformat()
    assert series.method is not None and series.method.name == "linear-trend"
    assert series.source_observed_at is not None
    # one fixed 120-day read whatever the requested window, so a caller cannot multiply scans
    assert source.calls == [(LAST - timedelta(days=119), LAST + timedelta(days=1))]


@pytest.mark.asyncio
async def test_too_little_history_keeps_the_measured_days_and_projects_nothing() -> None:
    response = await build(FakeSource(totals(growing(9))))
    series = traffic(response)
    assert (series.state, series.reason) == ("insufficient-data", "too-few-days")
    assert len(series.history) == 9 and series.forecast == [] and series.method is None
    assert response.state == "insufficient-data"
    assert "collect-more-history" in [r.kind for r in response.recommendations]


@pytest.mark.asyncio
async def test_a_reachable_store_with_no_flows_is_insufficient_not_unknown() -> None:
    series = traffic(await build(FakeSource(totals({}))))
    assert (series.state, series.reason) == ("insufficient-data", "too-few-days")
    assert series.history == [] and series.source_observed_at is None


@pytest.mark.asyncio
async def test_a_missing_day_is_counted_and_never_filled_with_zero() -> None:
    values = growing(30)
    del values[day(10)]
    series = traffic(await build(FakeSource(totals(values)), history=30))
    assert series.state == "ok" and series.history_missing_days == 1
    assert day(10).isoformat() not in [p.day for p in series.history]
    assert all(p.value > 0 for p in series.history)


@pytest.mark.asyncio
async def test_a_first_day_the_store_only_partly_covers_is_dropped() -> None:
    values = growing(30)
    oldest = min(values)
    started_late = datetime.combine(oldest, datetime.min.time(), tzinfo=UTC) + timedelta(hours=14)
    series = traffic(
        await build(FakeSource(totals(values, first_flow_at=started_late)), history=30)
    )
    assert oldest.isoformat() not in [p.day for p in series.history]
    assert len(series.history) == 29 and series.history_missing_days == 0  # before the data began


@pytest.mark.asyncio
async def test_a_last_day_the_collector_stopped_during_is_not_shown_as_measured() -> None:
    values = growing(30)
    newest = max(values)
    stopped = datetime.combine(newest, datetime.min.time(), tzinfo=UTC) + timedelta(hours=9)
    series = traffic(await build(FakeSource(totals(values, last_flow_at=stopped)), history=30))
    assert newest.isoformat() not in [p.day for p in series.history]
    assert series.history_missing_days == 1  # excluded days are counted, never filled with zero


@pytest.mark.asyncio
async def test_a_last_day_covered_to_its_end_is_kept() -> None:
    values = growing(30)
    newest = max(values)
    near_end = datetime.combine(newest, datetime.min.time(), tzinfo=UTC) + timedelta(
        hours=23, minutes=30
    )
    series = traffic(await build(FakeSource(totals(values, last_flow_at=near_end)), history=30))
    assert newest.isoformat() in [p.day for p in series.history]


@pytest.mark.asyncio
async def test_a_day_with_hours_of_no_flows_inside_the_window_is_excluded_not_measured() -> None:
    values = growing(30)
    outage = day(10)
    hours = {d: 24 for d in values} | {outage: 11}  # a collector outage: 13 hours silent
    series = traffic(await build(FakeSource(totals(values, hours_covered=hours)), history=30))
    assert outage.isoformat() not in [p.day for p in series.history]
    assert series.history_missing_days == 1 and series.state == "ok"
    assert all(p.value > 0 for p in series.history)


@pytest.mark.asyncio
async def test_a_day_missing_only_a_couple_of_quiet_hours_is_kept() -> None:
    values = growing(30)
    hours = {d: 24 for d in values} | {day(10): service.MIN_COVERED_HOURS}
    series = traffic(await build(FakeSource(totals(values, hours_covered=hours)), history=30))
    assert day(10).isoformat() in [p.day for p in series.history]


@pytest.mark.asyncio
async def test_a_source_that_cannot_report_hours_does_not_exclude_days() -> None:
    series = traffic(await build(FakeSource(totals(growing(30), hours_covered=None)), history=30))
    assert len(series.history) == 30 and series.history_missing_days == 0


@pytest.mark.asyncio
async def test_wan_and_inventory_are_not_connected_because_no_source_gives_their_history() -> None:
    response = await build(FakeSource(totals(growing(30))))
    others = [s for s in response.series if s.id != "traffic-volume"]
    assert {s.id for s in others} == {"wan-utilisation", "inventory-growth"}
    for series in others:
        assert (series.state, series.reason) == ("not-connected", "no-history-source")
        assert series.history == [] and series.forecast == []


@pytest.mark.asyncio
async def test_the_response_is_contract_valid_and_deterministic() -> None:
    source = FakeSource(totals(growing(40)))
    first, second = await build(source), await build(source)
    assert first == second
    validate("forecast_response", json.loads(first.model_dump_json(by_alias=True)))


@pytest.mark.asyncio
async def test_unsupported_windows_are_programming_errors() -> None:
    with pytest.raises(ValueError):
        await build(None, horizon=0)
    with pytest.raises(ValueError):
        await build(None, history=13)
    with pytest.raises(ValueError):
        await build(None, limit=0)


# --- thresholds and advice ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_configured_limit_gets_a_derived_crossing_and_a_review_recommendation() -> None:
    values = growing(30, start=100 * GB, step=GB)  # last measured 129 GB, +1 GB a day
    response = await build(FakeSource(totals(values)), horizon=7, limit=133 * GB)
    series = traffic(response)
    assert series.threshold is not None and series.threshold.basis == "operator-configured"
    assert series.crossing is not None
    assert series.crossing.point_day == (LAST + timedelta(days=4)).isoformat()  # 133 GB
    review = next(r for r in response.recommendations if r.kind == "capacity-review")
    assert review.advisory is True and review.executable is False
    assert series.crossing.point_day in review.title
    assert any("133" in line for line in review.evidence)


@pytest.mark.asyncio
async def test_a_limit_beyond_the_horizon_gives_an_empty_crossing_and_no_warning() -> None:
    response = await build(FakeSource(totals(growing(30))), limit=10_000 * GB)
    series = traffic(response)
    assert series.crossing is not None
    assert (series.crossing.point_day, series.crossing.upper_day) == (None, None)
    assert not [r for r in response.recommendations if r.kind.startswith("capacity")]


@pytest.mark.asyncio
async def test_strong_growth_without_a_limit_suggests_setting_one() -> None:
    response = await build(FakeSource(totals(growing(30, start=10 * GB, step=2 * GB))), horizon=14)
    kinds = [r.kind for r in response.recommendations]
    assert "growth-no-limit" in kinds and "capacity-review" not in kinds
    advice = next(r for r in response.recommendations if r.kind == "growth-no-limit")
    assert any("%" in line for line in advice.evidence)


@pytest.mark.asyncio
async def test_quiet_weekends_are_reported_as_headroom_with_the_numbers() -> None:
    values = {}
    for back in range(42):
        d = day(back)
        values[d] = 20 * GB if d.weekday() >= 5 else 100 * GB
    response = await build(FakeSource(totals(values)))
    rec = next(r for r in response.recommendations if r.kind == "weekend-headroom")
    assert rec.series_id == "traffic-volume"
    assert any("weekend" in line.lower() for line in rec.evidence)


@pytest.mark.asyncio
async def test_a_steady_series_gets_no_advice_about_nothing() -> None:
    values = {day(back): 100 * GB + (back % 3) * GB for back in range(30)}
    kinds = [r.kind for r in (await build(FakeSource(totals(values)))).recommendations]
    assert "growth-no-limit" not in kinds and "weekend-headroom" not in kinds


def test_forecast_code_cannot_create_or_run_an_action() -> None:
    root = Path(service.__file__).parent
    forbidden = {"actions", "netsight_api.actions", "executor", "subprocess", "socket"}
    for path in sorted(root.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text("utf-8"))):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""] + [a.name for a in node.names]
            for name in names:
                assert not any(
                    name == bad or name.startswith(f"{bad}.") or name.endswith(f".{bad}")
                    for bad in forbidden
                ), f"{path.name} imports {name}"


# --- review fixes (Step 13 code and security review) --------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("behind", [1, 2, 3])
async def test_history_that_ends_a_few_days_early_is_still_forecast_from_its_newest_day(
    behind: int,
) -> None:
    values = {d: v for d, v in growing(40).items() if d <= day(behind)}
    series = traffic(await build(FakeSource(totals(values)), horizon=5))
    assert series.state == "ok", series.detail
    newest = max(values)
    assert series.forecast[0].day == (newest + timedelta(days=1)).isoformat()
    assert series.history[-1].day == newest.isoformat()


@pytest.mark.asyncio
async def test_history_that_ends_four_days_early_is_too_old_to_project_from() -> None:
    values = {d: v for d, v in growing(40).items() if d <= day(4)}
    series = traffic(await build(FakeSource(totals(values))))
    assert (series.state, series.reason) == ("insufficient-data", "history-stale")


@pytest.mark.asyncio
async def test_an_internal_bug_is_not_reported_as_an_unreadable_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(*_: object, **__: object) -> None:
        raise ValueError("a bug")

    monkeypatch.setattr(service, "_traffic_series", broken)
    with pytest.raises(ValueError):
        await build(FakeSource(totals(growing(30))))


@pytest.mark.asyncio
async def test_a_requested_window_is_a_slice_of_the_one_read() -> None:
    source = FakeSource(totals(growing(120)))
    short = traffic(await build(source, history=30))
    long = traffic(await build(source, history=90))
    assert (len(short.history), len(long.history)) == (30, 90)
    assert short.history == long.history[-30:]


@pytest.mark.asyncio
async def test_a_first_day_at_the_edge_of_the_read_is_kept_because_older_data_may_exist() -> None:
    values = growing(120)
    oldest = min(values)
    late = datetime.combine(oldest, datetime.min.time(), tzinfo=UTC) + timedelta(hours=14)
    series = traffic(await build(FakeSource(totals(values, first_flow_at=late)), history=120))
    assert oldest.isoformat() in [p.day for p in series.history]
