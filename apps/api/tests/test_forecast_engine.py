"""The forecast arithmetic (Step 13): linear trend and weekly seasonal-naive over observed days.

Pure functions of an observed series, a window and a horizon: no clock, no I/O. A day the source did
not report is absent (never zero), and a series too short, too gappy or too old is refused rather than
extrapolated.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from netsight_api.forecast import engine

FIRST = date(2026, 9, 1)  # a Tuesday


def series(values: list[int], *, start: date = FIRST) -> dict[date, int]:
    return {start + timedelta(days=i): v for i, v in enumerate(values)}


def last_of(values: dict[date, int]) -> date:
    return max(values)


def run(
    observed: dict[date, int], horizon: int = 7, *, first: date = FIRST, last: date | None = None
):
    return engine.project(
        observed, first_day=first, last_day=last or last_of(observed), horizon_days=horizon
    )


# --- linear trend ---------------------------------------------------------------------------------


def test_a_perfect_line_is_continued_exactly_with_no_band_width() -> None:
    observed = series([100 + 10 * i for i in range(20)])
    result = run(observed, 3)
    assert isinstance(result, engine.Forecast)
    assert result.method.name == "linear-trend"
    assert result.method.slope_per_day == 10
    assert [p.day for p in result.points] == [FIRST + timedelta(days=20 + i) for i in range(3)]
    assert [p.value for p in result.points] == [300, 310, 320]
    assert all(p.lower == p.upper == p.value for p in result.points)


def test_noise_gives_a_band_that_contains_the_point_and_widens_with_the_horizon() -> None:
    noise = [0, 7, -5, 3, -9, 6, -2, 8, -7, 1, 5, -6, 4, -3, 9, -8, 2, -1, 6, -4]
    observed = series([1000 + 20 * i + n for i, n in enumerate(noise)])
    result = run(observed, 10)
    assert isinstance(result, engine.Forecast)
    widths = [p.upper - p.lower for p in result.points]
    assert all(p.lower <= p.value <= p.upper for p in result.points)
    assert widths == sorted(widths) and widths[-1] > widths[0] > 0


def test_a_falling_series_never_forecasts_below_zero() -> None:
    observed = series([400 - 20 * i for i in range(20)])  # reaches 20 on the last day
    result = run(observed, 5)
    assert isinstance(result, engine.Forecast)
    assert [p.value for p in result.points] == [0, 0, 0, 0, 0]
    assert all(p.lower == 0 for p in result.points)


def test_missing_days_are_left_out_of_the_fit_not_counted_as_zero() -> None:
    full = series([100 + 10 * i for i in range(24)])
    for gap in (5, 6, 13):
        del full[FIRST + timedelta(days=gap)]
    result = run(full, 2)
    assert isinstance(result, engine.Forecast)
    assert result.method.slope_per_day == 10
    assert [p.value for p in result.points] == [340, 350]
    assert result.method.observed_days == 21


def test_values_round_half_up_to_whole_bytes() -> None:
    observed = series([10, 11] * 7 + [10, 11])  # mean 10.5, no trend
    result = run(observed, 1)
    assert isinstance(result, engine.Forecast)
    assert isinstance(result.points[0].value, int)


def test_the_result_is_deterministic() -> None:
    observed = series([500 + (i * 37) % 23 + 5 * i for i in range(30)])
    assert run(observed, 7) == run(observed, 7)


# --- seasonal naive (weekly) ------------------------------------------------------------------------


def test_a_weekly_pattern_is_repeated_when_it_beats_the_trend() -> None:
    week = [100, 100, 100, 100, 100, 20, 20]  # FIRST is a Tuesday, so index 4,5 are Sat, Sun
    observed = series(week * 6)
    result = run(observed, 7)
    assert isinstance(result, engine.Forecast)
    assert result.method.name == "seasonal-naive-weekly"
    assert result.method.slope_per_day is None
    assert [p.value for p in result.points] == week
    assert result.method.seasonal_mae == 0
    assert result.method.linear_mae is not None and result.method.linear_mae > 0
    assert "same weekday" in result.method.why


def test_a_pure_trend_keeps_the_linear_method_even_with_enough_history_for_seasons() -> None:
    observed = series([100 + 10 * i for i in range(40)])
    result = run(observed, 7)
    assert isinstance(result, engine.Forecast)
    assert result.method.name == "linear-trend"
    assert result.method.seasonal_mae is not None  # it was considered and lost


def test_seasonal_is_not_considered_under_four_weeks_of_history() -> None:
    week = [100, 100, 100, 100, 100, 20, 20]
    result = run(series(week * 3), 7)
    assert isinstance(result, engine.Forecast)
    assert result.method.name == "linear-trend"
    assert result.method.seasonal_mae is None


# --- refusals ---------------------------------------------------------------------------------------


def test_too_few_observed_days_is_insufficient() -> None:
    result = run(series([100 + i for i in range(13)]), 3)
    assert result == engine.Insufficient("too-few-days", result.detail)  # type: ignore[union-attr]
    assert "13" in result.detail and "14" in result.detail


def test_too_many_missing_days_is_insufficient() -> None:
    observed = series([100 + i for i in range(40)])
    for i in range(0, 40, 3):  # drop every third day: 14 missing of 40
        del observed[FIRST + timedelta(days=i)]
    result = run(observed, 3, last=FIRST + timedelta(days=39))
    assert isinstance(result, engine.Insufficient) and result.reason == "too-many-gaps"


def test_history_that_stops_days_before_the_window_end_is_stale() -> None:
    observed = series([100 + i for i in range(20)])
    last = FIRST + timedelta(days=24)  # five days after the newest observation
    result = run(observed, 3, last=last)
    assert isinstance(result, engine.Insufficient) and result.reason == "history-stale"


def test_a_horizon_longer_than_half_the_observed_days_is_insufficient() -> None:
    observed = series([100 + i for i in range(14)])
    assert isinstance(run(observed, 7), engine.Forecast)
    result = run(observed, 8)
    assert isinstance(result, engine.Insufficient) and result.reason == "horizon-too-long"


def test_bad_inputs_are_programming_errors() -> None:
    observed = series([100 + i for i in range(20)])
    with pytest.raises(ValueError):
        run(observed, 0)
    with pytest.raises(ValueError):
        run(observed, 31)
    with pytest.raises(ValueError):
        run({**observed, FIRST - timedelta(days=1): 5}, 3)  # before the window
    with pytest.raises(ValueError):
        run({**observed, FIRST: -1}, 3)
    with pytest.raises(ValueError):
        run({**observed, FIRST: True}, 3)  # type: ignore[dict-item]


# --- review fixes (Step 13 code and security review) --------------------------------------------------


def test_the_forecast_starts_the_day_after_the_newest_observation_not_after_the_window_end() -> (
    None
):
    observed = series([100 + 10 * i for i in range(20)])  # newest observation: FIRST + 19
    window_end = FIRST + timedelta(days=21)  # two days newer than the newest observation
    result = run(observed, 3, last=window_end)
    assert isinstance(result, engine.Forecast)
    assert [p.day for p in result.points] == [FIRST + timedelta(days=20 + i) for i in range(3)]
    assert [p.value for p in result.points] == [300, 310, 320]  # continues the line, no jump


def test_the_band_uses_the_student_t_value_for_the_degrees_of_freedom() -> None:
    assert engine.t_95(12) == pytest.approx(2.179)
    assert engine.t_95(30) == pytest.approx(2.042)
    assert (
        engine.t_95(31) >= engine.t_95(60) >= engine.t_95(118) >= 1.96
    )  # never narrower than normal
    noise = [0, 7, -5, 3, -9, 6, -2, 8, -7, 1, 5, -6, 4, -3]
    observed = series([1000 + 20 * i + n for i, n in enumerate(noise)])  # 14 days, 12 d.o.f.
    result = run(observed, 1)
    assert isinstance(result, engine.Forecast)
    xs = list(range(14))
    mean_x = sum(xs) / 14
    sxx = sum((x - mean_x) ** 2 for x in xs)
    ys = [1000 + 20 * i + n for i, n in enumerate(noise)]
    slope = sum((x - mean_x) * (y - sum(ys) / 14) for x, y in zip(xs, ys)) / sxx
    intercept = sum(ys) / 14 - slope * mean_x
    sse = sum((y - (intercept + slope * x)) ** 2 for x, y in zip(xs, ys))
    s = (sse / 12) ** 0.5
    expected = 2.179 * s * (1 + 1 / 14 + (14 - mean_x) ** 2 / sxx) ** 0.5
    point = result.points[0]
    assert abs((point.upper - point.lower) / 2 - expected) <= 1.0


def test_the_linear_explanation_never_claims_a_weekly_repeat_lost_when_it_could_not_be_built() -> (
    None
):
    week = [100, 100, 100, 100, 100, 20, 20]
    observed = series(week * 8)  # 56 days, FIRST + 55 is the newest
    next_weekday = (FIRST + timedelta(days=56)).weekday()
    for back in (7, 14, 21, 28):  # the weekday of the first forecast day, missing four weeks back
        observed.pop(FIRST + timedelta(days=56 - back), None)
    result = run(observed, 7, last=FIRST + timedelta(days=55))
    assert isinstance(result, engine.Forecast) and next_weekday is not None
    assert result.method.name == "linear-trend"
    assert "not more accurate" not in result.method.why
    assert "could not" in result.method.why


def test_every_explanation_fits_the_contract_even_with_the_largest_numbers() -> None:
    big = 10**15
    observed = series([big - (i % 3) * 10**12 for i in range(60)])
    result = run(observed, 30, last=FIRST + timedelta(days=59))
    assert isinstance(result, engine.Forecast)
    assert len(result.method.why) <= 300
