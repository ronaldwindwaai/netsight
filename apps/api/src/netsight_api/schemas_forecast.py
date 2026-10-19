"""Typed boundary models for capacity forecasting (Step 13).

Mirrors ``contracts/json-schema/forecast.schema.json``, the OpenAPI components and the browser
parsers (shared vectors: ``contracts/test-vectors/forecast.vectors.json``).

Honesty rules, enforced here and not only by construction:

* every value after the last measured day is a **forecast**: it lives in ``forecast`` (never in
  ``history``), carries a band, and the response says so (``is_forecast`` and ``notice``);
* a series that is not ``ok`` has no method, no projected point and no crossing; a series without a
  source has no history either. A point is never invented to fill a chart;
* the series states and the response state agree (``ok`` only when some series is ``ok``);
* a threshold is only ever an operator's, and the crossing days are *derived* from the forecast and
  that threshold, so they cannot disagree with the chart;
* a recommendation is advice: ``advisory`` is always true and ``executable`` always false, and it has
  no field that could carry an action.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Annotated, Final, Literal

from pydantic import AwareDatetime, Field, model_validator

from netsight_api.schemas import ApiModel

ForecastState = Literal["ok", "insufficient-data", "not-connected", "unknown"]
SeriesId = Literal["traffic-volume", "wan-utilisation", "inventory-growth"]
Unit = Literal["bytes-per-day", "percent", "devices"]
Reason = Literal[
    "no-source",
    "no-history-source",
    "source-unreadable",
    "too-few-days",
    "too-many-gaps",
    "history-stale",
    "horizon-too-long",
]
MethodName = Literal["linear-trend", "seasonal-naive-weekly"]
RecommendationKind = Literal[
    "capacity-review",
    "capacity-watch",
    "growth-no-limit",
    "weekend-headroom",
    "connect-history-source",
    "collect-more-history",
]

NOTICE: Final = (
    "Forecast, not measurement. Values after the last measured day are projections from past "
    "source-reported data. They are not observations and can be wrong."
)
MAX_VALUE: Final = 10**15
MIN_OBSERVED: Final = 14
MAX_HISTORY_DAYS: Final = 120
MAX_HORIZON_DAYS: Final = 30
MAX_RECOMMENDATIONS: Final = 8
DAY_PATTERN: Final = r"^\d{4}-\d{2}-\d{2}$"
_NO_HISTORY_REASONS: Final = frozenset({"no-source", "no-history-source"})
_INSUFFICIENT_REASONS: Final = frozenset(
    {"too-few-days", "too-many-gaps", "history-stale", "horizon-too-long"}
)

Value = Annotated[int, Field(ge=0, le=MAX_VALUE, strict=True)]
Day = Annotated[str, Field(min_length=10, max_length=10, pattern=DAY_PATTERN)]


def parse_day(value: str) -> date:
    """A real calendar date; ``ValueError`` for ``2026-02-30`` (the pattern alone allows it)."""
    return date.fromisoformat(value)


def _real_day(value: str | None) -> str | None:
    if value is not None:
        parse_day(value)
    return value


class ForecastHistoryPoint(ApiModel):
    day: Day
    value: Value

    @model_validator(mode="after")
    def _a_real_day(self) -> ForecastHistoryPoint:
        _real_day(self.day)
        return self


class ForecastPoint(ApiModel):
    day: Day
    value: Value
    lower: Value
    upper: Value

    @model_validator(mode="after")
    def _the_band_contains_the_point(self) -> ForecastPoint:
        _real_day(self.day)
        if not self.lower <= self.value <= self.upper:
            raise ValueError("the band must contain the forecast value")
        return self


class ForecastMethod(ApiModel):
    name: MethodName
    why: str = Field(min_length=1, max_length=400)
    observed_days: int = Field(ge=MIN_OBSERVED, le=MAX_HISTORY_DAYS, strict=True)
    slope_per_day: int | None = Field(..., ge=-MAX_VALUE, le=MAX_VALUE, strict=True)
    linear_mae: Value
    seasonal_mae: Value | None
    band: Literal["approximate-95-percent"]

    @model_validator(mode="after")
    def _fields_match_the_method(self) -> ForecastMethod:
        seasonal = self.name == "seasonal-naive-weekly"
        if seasonal != (self.slope_per_day is None):
            raise ValueError("a trend has a slope and a weekly repeat has none")
        if seasonal and self.seasonal_mae is None:
            raise ValueError("a weekly repeat reports its error")
        return self


class ForecastThreshold(ApiModel):
    value: int = Field(ge=1, le=MAX_VALUE, strict=True)
    basis: Literal["operator-configured"]


class ForecastCrossing(ApiModel):
    point_day: Day | None
    upper_day: Day | None

    @model_validator(mode="after")
    def _the_upper_band_is_never_later(self) -> ForecastCrossing:
        point, upper = _real_day(self.point_day), _real_day(self.upper_day)
        if point is not None and (upper is None or parse_day(upper) > parse_day(point)):
            raise ValueError("the upper band reaches a limit no later than the forecast does")
        return self


def crossing_for(points: list[ForecastPoint], limit: int) -> ForecastCrossing:
    """The first day the point forecast, and the first day the upper band, reach ``limit``."""
    return ForecastCrossing(
        point_day=next((p.day for p in points if p.value >= limit), None),
        upper_day=next((p.day for p in points if p.upper >= limit), None),
    )


class ForecastSeries(ApiModel):
    id: SeriesId
    name: str = Field(min_length=1, max_length=80)
    unit: Unit
    state: ForecastState
    reason: Reason | None
    detail: str | None = Field(..., min_length=1, max_length=400)
    source_observed_at: AwareDatetime | None
    history: list[ForecastHistoryPoint] = Field(max_length=MAX_HISTORY_DAYS)
    history_missing_days: int = Field(ge=0, le=MAX_HISTORY_DAYS, strict=True)
    method: ForecastMethod | None
    forecast: list[ForecastPoint] = Field(max_length=MAX_HORIZON_DAYS)
    threshold: ForecastThreshold | None
    crossing: ForecastCrossing | None

    @model_validator(mode="after")
    def _state_decides_what_is_present(self) -> ForecastSeries:
        if self.state == "ok":
            self._check_ok()
        else:
            self._check_not_ok()
        _check_days(self.history, self.forecast)
        return self

    def _check_ok(self) -> None:
        if self.reason is not None or self.method is None or not self.forecast:
            raise ValueError("an ok series has a method and points and no reason")
        if len(self.history) < MIN_OBSERVED or self.method.observed_days != len(self.history):
            raise ValueError("an ok series states the measured days its method used")
        if (self.threshold is None) != (self.crossing is None):
            raise ValueError("a crossing exists exactly when a threshold does")
        if self.threshold is not None and self.crossing != crossing_for(
            self.forecast, self.threshold.value
        ):
            raise ValueError("the crossing is derived from the forecast and the threshold")

    def _check_not_ok(self) -> None:
        if self.method is not None or self.forecast or self.threshold or self.crossing:
            raise ValueError("a series that is not ok has no method, point, threshold or crossing")
        if self.reason is None or self.detail is None:
            raise ValueError("a series that is not ok says why")
        if self.state == "insufficient-data":
            if self.reason not in _INSUFFICIENT_REASONS:
                raise ValueError("insufficient data names a history reason")
        elif self.history or self.history_missing_days:
            raise ValueError("a series without a readable source has no measured days")
        elif self.state == "not-connected" and self.reason not in _NO_HISTORY_REASONS:
            raise ValueError("not-connected names a missing source")
        elif self.state == "unknown" and self.reason != "source-unreadable":
            raise ValueError("unknown names an unreadable source")


def _check_days(history: list[ForecastHistoryPoint], forecast: list[ForecastPoint]) -> None:
    previous: date | None = None
    for point in history:
        day = parse_day(point.day)
        if previous is not None and day <= previous:
            raise ValueError("measured days are in strictly increasing order")
        previous = day
    expected = None if previous is None else previous + timedelta(days=1)
    for projected in forecast:
        day = parse_day(projected.day)
        if expected is not None and day != expected:
            raise ValueError("forecast days follow the last measured day, one per day")
        expected = day + timedelta(days=1)


class ForecastRecommendation(ApiModel):
    id: str = Field(min_length=3, max_length=64, pattern=r"^[a-z][a-z0-9-]{2,63}$")
    kind: RecommendationKind
    series_id: SeriesId
    title: str = Field(min_length=1, max_length=120)
    advice: str = Field(min_length=1, max_length=500)
    evidence: list[Annotated[str, Field(min_length=1, max_length=400)]] = Field(
        min_length=1, max_length=5
    )
    advisory: Literal[True]
    executable: Literal[False]


class ForecastResponse(ApiModel):
    state: ForecastState
    generated_at: AwareDatetime
    is_forecast: Literal[True]
    notice: Literal[
        "Forecast, not measurement. Values after the last measured day are projections "
        "from past source-reported data. They are not observations and can be wrong."
    ]
    horizon_days: int = Field(ge=1, le=MAX_HORIZON_DAYS, strict=True)
    history_days: int = Field(ge=MIN_OBSERVED, le=MAX_HISTORY_DAYS, strict=True)
    history_through: Day | None
    series: list[ForecastSeries] = Field(min_length=1, max_length=3)
    recommendations: list[ForecastRecommendation] = Field(max_length=MAX_RECOMMENDATIONS)

    @model_validator(mode="after")
    def _the_parts_agree(self) -> ForecastResponse:
        _real_day(self.history_through)
        ids = [s.id for s in self.series]
        if len(set(ids)) != len(ids):
            raise ValueError("each series appears once")
        if self.state != overall_state([s.state for s in self.series]):
            raise ValueError("the overall state follows from the series states")
        if any(len(s.forecast) != self.horizon_days for s in self.series if s.state == "ok"):
            raise ValueError("every forecast covers exactly the horizon")
        return self


def overall_state(states: list[ForecastState]) -> ForecastState:
    """``ok`` when any series has a forecast, else the least-informative explanation that applies."""
    for state in ("ok", "insufficient-data", "unknown"):
        if state in states:
            return state
    return "not-connected"
