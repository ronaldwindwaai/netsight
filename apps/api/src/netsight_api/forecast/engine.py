"""Deterministic daily forecast: a straight-line trend or a weekly repeat, never a model.

The question asked is *if the last weeks keep going the way they went, what are the next days
likely to look like?* The answer is arithmetic over source-reported daily values, reproducible from
the same input and explainable in two sentences. There is no training, no hidden state, no external
data and no tuning to make a chart look better.

1. **Observed days.** Only days the source reported (``observed``). A day with no data is *absent*,
   never zero: a collector outage must not look like a traffic drop. Absent days are left out of
   every fit.
2. **Minimum history.** At least ``MIN_OBSERVED_DAYS`` observed days; no more than ``MAX_GAP_RATIO``
   of the window missing; the newest observation no more than ``STALE_DAYS`` before the window end;
   a horizon of at most half the observed days. Otherwise the result is :class:`Insufficient` with a
   reason and no points. Nothing is extrapolated from too little.
3. **Linear trend.** Ordinary least squares on (day number, value). The band is the textbook
   approximate 95 % prediction interval ``t * s * sqrt(1 + 1/n + (x - mean)^2 / Sxx)`` with ``s`` the
   residual standard deviation and ``t`` the two-sided 95 % Student-t value for ``n - 2`` degrees of
   freedom (a table, rounded up between rows, so a short history is not given a normal-sized band). It describes the spread of the history around
   the line, not the chance that behaviour changes; a perfectly regular history gives a band of zero
   width, which is not a claim of certainty.
4. **Weekly seasonal naive.** Considered only with ``MIN_SEASONAL_DAYS`` observed days. Each
   forecast day repeats the same weekday from the latest week observed; the band is
   ``t * rms(error) * sqrt(weeks ahead)`` (``t`` for ``pairs - 1`` degrees of freedom) where the errors are ``value - value one week earlier``
   over the history. It is used only when its mean absolute error on those days is *lower* than the
   straight line's on the same days (the line is judged in-sample, which favours the line).
5. **Anchor.** A forecast always starts the day after the *newest observed* day, so it continues
   the measurements without a jump even when the newest day is one to ``STALE_DAYS`` behind the
   window end (the days in between are forecast, never measured).
6. **Clamping and rounding.** A quantity cannot be negative, so values and band edges are floored at
   zero. Everything is rounded half up to a whole number.

The result says which method ran and why; the numbers are a forecast, never a measurement.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Final, Literal

MIN_OBSERVED_DAYS: Final = 14
MIN_SEASONAL_DAYS: Final = 28
MIN_SEASONAL_PAIRS: Final = 14
MAX_GAP_RATIO: Final = 0.25
STALE_DAYS: Final = 3
MAX_HORIZON_DAYS: Final = 30
# Two-sided 95 % Student-t values by degrees of freedom; beyond the table the next row down is used
# (a larger value than the true one), and past 120 degrees of freedom the normal 1.96.
_T95: Final = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262,
    10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131, 16: 2.120, 17: 2.110,
    18: 2.101, 19: 2.093, 20: 2.086, 21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060,
    26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
}  # fmt: skip
_T95_STEPS: Final = ((40, 2.042), (60, 2.021), (120, 2.000))
Z_95: Final = 1.96
_WEEK: Final = 7
_MAX_WEEKS_BACK: Final = 4

InsufficientReason = Literal["too-few-days", "too-many-gaps", "history-stale", "horizon-too-long"]
MethodName = Literal["linear-trend", "seasonal-naive-weekly"]


@dataclass(frozen=True)
class Projection:
    day: date
    value: int
    lower: int
    upper: int


@dataclass(frozen=True)
class Method:
    name: MethodName
    why: str
    observed_days: int
    slope_per_day: int | None
    linear_mae: int
    seasonal_mae: int | None


@dataclass(frozen=True)
class Forecast:
    method: Method
    points: tuple[Projection, ...]


@dataclass(frozen=True)
class Insufficient:
    reason: InsufficientReason
    detail: str


def t_95(degrees_of_freedom: int) -> float:
    """The two-sided 95 % Student-t value, rounded up between table rows (never too narrow)."""
    if degrees_of_freedom < 1:
        raise ValueError("degrees of freedom must be at least one")
    if degrees_of_freedom in _T95:
        return _T95[degrees_of_freedom]
    return next((t for limit, t in _T95_STEPS if degrees_of_freedom <= limit), Z_95)


def round_half_up(value: float) -> int:
    return math.floor(value + 0.5)


def _validated(observed: Mapping[date, int], first_day: date, last_day: date, horizon: int) -> None:
    if not 1 <= horizon <= MAX_HORIZON_DAYS:
        raise ValueError("the horizon is outside the supported range")
    if not first_day <= last_day:
        raise ValueError("the window is empty")
    for day, value in observed.items():
        if not first_day <= day <= last_day:
            raise ValueError("an observed day lies outside the window")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("an observed value must be a non-negative whole number")


def _insufficient(
    observed: Mapping[date, int], first_day: date, last_day: date, horizon: int
) -> Insufficient | None:
    count = len(observed)
    if count < MIN_OBSERVED_DAYS:
        return Insufficient(
            "too-few-days",
            f"{count} observed days; at least {MIN_OBSERVED_DAYS} are needed before a forecast is made.",
        )
    behind = (last_day - max(observed)).days
    if behind > STALE_DAYS:
        return Insufficient(
            "history-stale",
            f"The newest observed day is {behind} days before the end of the window "
            f"(more than {STALE_DAYS}); the history is too old to project from.",
        )
    window = (last_day - first_day).days + 1
    missing = window - count
    if missing / window > MAX_GAP_RATIO:
        return Insufficient(
            "too-many-gaps",
            f"{missing} of {window} days have no data (more than {int(MAX_GAP_RATIO * 100)} %); "
            "gaps are never filled in.",
        )
    if horizon > count // 2:
        return Insufficient(
            "horizon-too-long",
            f"A {horizon}-day forecast needs at least {2 * horizon} observed days; "
            f"{count} are available.",
        )
    return None


@dataclass(frozen=True)
class _Line:
    intercept: float
    slope: float
    count: int
    mean_x: float
    sxx: float
    spread: float

    def at(self, x: float) -> float:
        return self.intercept + self.slope * x

    def half_band(self, x: float) -> float:
        reach = 1 + 1 / self.count + (x - self.mean_x) ** 2 / self.sxx
        return t_95(self.count - 2) * self.spread * math.sqrt(reach)


def _fit(points: Sequence[tuple[int, int]]) -> _Line:
    count = len(points)
    mean_x = math.fsum(x for x, _ in points) / count
    mean_y = math.fsum(y for _, y in points) / count
    sxx = math.fsum((x - mean_x) ** 2 for x, _ in points)
    slope = math.fsum((x - mean_x) * (y - mean_y) for x, y in points) / sxx
    intercept = mean_y - slope * mean_x
    sse = math.fsum((y - (intercept + slope * x)) ** 2 for x, y in points)
    return _Line(intercept, slope, count, mean_x, sxx, math.sqrt(sse / (count - 2)))


def _projection(day: date, value: float, half: float) -> Projection:
    return Projection(
        day=day,
        value=max(0, round_half_up(value)),
        lower=max(0, round_half_up(value - half)),
        upper=max(0, round_half_up(value + half)),
    )


def _weekly_errors(observed: Mapping[date, int]) -> list[tuple[date, int]]:
    """``value - value a week earlier`` for every observed day whose week-earlier day is observed."""
    return [
        (day, value - observed[day - timedelta(days=_WEEK)])
        for day, value in sorted(observed.items())
        if day - timedelta(days=_WEEK) in observed
    ]


def _seasonal_points(
    observed: Mapping[date, int], anchor: date, horizon: int, half_unit: float
) -> tuple[Projection, ...] | None:
    points: list[Projection] = []
    for step in range(1, horizon + 1):
        day = anchor + timedelta(days=step)
        weeks_ahead = math.ceil(step / _WEEK)
        source = next(
            (
                day - timedelta(days=_WEEK * back)
                for back in range(weeks_ahead, weeks_ahead + _MAX_WEEKS_BACK)
                if day - timedelta(days=_WEEK * back) in observed
            ),
            None,
        )
        if source is None:
            return None
        points.append(_projection(day, observed[source], half_unit * math.sqrt(weeks_ahead)))
    return tuple(points)


@dataclass(frozen=True)
class _Fit:
    """What the straight line knows about the history, shared by both methods' explanations."""

    line: _Line
    days: tuple[date, ...]
    first_day: date
    missing: int
    linear_mae: int
    seasonal_mae: int | None
    seasonal_note: str


def project(
    observed: Mapping[date, int], *, first_day: date, last_day: date, horizon_days: int
) -> Forecast | Insufficient:
    """Forecast ``horizon_days`` days after the newest observed day, from the days observed in
    the window ``first_day`` to ``last_day``."""
    _validated(observed, first_day, last_day, horizon_days)
    refusal = _insufficient(observed, first_day, last_day, horizon_days)
    if refusal is not None:
        return refusal
    days = tuple(sorted(observed))
    anchor = days[-1]
    line = _fit([((day - first_day).days, observed[day]) for day in days])
    resid = {day: abs(observed[day] - line.at((day - first_day).days)) for day in days}
    missing = (last_day - first_day).days + 1 - len(days)

    errors = _weekly_errors(observed)
    if len(days) < MIN_SEASONAL_DAYS or len(errors) < MIN_SEASONAL_PAIRS:
        mae = round_half_up(math.fsum(resid.values()) / len(resid))
        return _linear(_Fit(line, days, first_day, missing, mae, None, ""), anchor, horizon_days)

    compared = [day for day, _ in errors]
    linear_mae = round_half_up(math.fsum(resid[d] for d in compared) / len(compared))
    seasonal_mae = round_half_up(math.fsum(abs(e) for _, e in errors) / len(errors))
    rms = math.sqrt(math.fsum(e * e for _, e in errors) / len(errors))
    half_unit = t_95(len(errors) - 1) * rms
    points = _seasonal_points(observed, anchor, horizon_days, half_unit)
    if points is not None and seasonal_mae < linear_mae:
        why = (
            "Each forecast day repeats the same weekday from the latest week observed. On the "
            "history this was more accurate than a straight-line trend (mean absolute error "
            f"{seasonal_mae} against {linear_mae})."
        )
        return Forecast(
            Method("seasonal-naive-weekly", why, len(days), None, linear_mae, seasonal_mae), points
        )
    note = (
        " Repeating the same weekday could not be applied: a forecast weekday had no observation "
        f"in the last {_MAX_WEEKS_BACK + 1} weeks."
        if points is None
        else " Repeating the same weekday was also tried and was not more accurate "
        f"(mean absolute error {seasonal_mae} against {linear_mae})."
    )
    return _linear(
        _Fit(line, days, first_day, missing, linear_mae, seasonal_mae, note), anchor, horizon_days
    )


def _linear(fit: _Fit, anchor: date, horizon: int) -> Forecast:
    ahead = (anchor - fit.first_day).days
    points = tuple(
        _projection(
            anchor + timedelta(days=step),
            fit.line.at(ahead + step),
            fit.line.half_band(ahead + step),
        )
        for step in range(1, horizon + 1)
    )
    why = (
        f"A straight-line trend fitted to {len(fit.days)} observed days "
        f"({fit.missing} missing days left out)." + fit.seasonal_note
    )
    method = Method(
        "linear-trend",
        why,
        len(fit.days),
        round_half_up(fit.line.slope),
        fit.linear_mae,
        fit.seasonal_mae,
    )
    return Forecast(method, points)
