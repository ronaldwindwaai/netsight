"""Advisory optimisation text, each line backed by the numbers it came from.

Deterministic rules over the finished series, no model. A recommendation is **advice for a person**:
``advisory`` is always true, ``executable`` always false, and nothing here imports or calls the
Action Request framework. Rules that need data stay silent when the data is not there; an
unexplained recommendation is worse than none.

* ``capacity-review`` / ``capacity-watch`` - the forecast (or only its upper band) reaches a limit the
  operator configured within the horizon;
* ``growth-no-limit`` - strong forecast growth and no configured limit to warn against;
* ``weekend-headroom`` - weekends carry well under the weekday volume (bulk transfers could be moved
  there; this is an observation, not a plan);
* ``connect-history-source`` / ``collect-more-history`` - the series cannot be forecast yet.
"""

from __future__ import annotations

from typing import Final

from netsight_api.schemas_forecast import (
    MAX_RECOMMENDATIONS,
    ForecastHistoryPoint,
    ForecastRecommendation,
    ForecastSeries,
    RecommendationKind,
    Unit,
    parse_day,
)

GROWTH_NOTICE_PERCENT: Final = 20
WEEKEND_RATIO_PERCENT: Final = 60
MIN_WEEKEND_DAYS: Final = 4
MIN_WEEKDAYS: Final = 10
_SATURDAY: Final = 5


def amount(value: int, unit: Unit) -> str:
    """A value in words a person reads: decimal bytes, a percent, a device count."""
    if unit == "percent":
        return f"{value} %"
    if unit == "devices":
        return f"{value} devices"
    units = ((10**3, "kB"), (10**6, "MB"), (10**9, "GB"), (10**12, "TB"))
    for index in range(len(units) - 1, -1, -1):
        limit, name = units[index]
        if value < limit:
            continue
        shown = round(value / limit, 1)
        if shown >= 1000 and index + 1 < len(units):  # 999.95 kB reads as 1.0 MB, not 1000.0 kB
            limit, name = units[index + 1]
            shown = round(value / limit, 1)
        return f"{shown:.1f} {name}/day"
    return f"{value} B/day"


def _make(
    kind: RecommendationKind,
    series: ForecastSeries,
    title: str,
    advice: str,
    evidence: list[str],
) -> ForecastRecommendation:
    return ForecastRecommendation(
        id=f"{kind}-{series.id}",
        kind=kind,
        series_id=series.id,
        title=title,
        advice=advice,
        evidence=evidence,
        advisory=True,
        executable=False,
    )


def _source_gap(series: ForecastSeries) -> list[ForecastRecommendation]:
    if series.state == "not-connected":
        return [
            _make(
                "connect-history-source",
                series,
                f"Connect a history source for {series.name.lower()}",
                "This cannot be forecast until a source reports its history. Netsight does not "
                "estimate what no source has reported.",
                [series.detail or "No source is connected for this series."],
            )
        ]
    if series.state == "insufficient-data":
        return [
            _make(
                "collect-more-history",
                series,
                f"Wait for more history of {series.name.lower()}",
                "A forecast starts when the minimum history exists. Until then nothing is projected.",
                [
                    series.detail or "Not enough history.",
                    (
                        f"{len(series.history)} measured days; {series.history_missing_days} "
                        "days without data in the window."
                    ),
                ],
            )
        ]
    return []


def _limit_advice(series: ForecastSeries) -> list[ForecastRecommendation]:
    threshold, crossing, method = series.threshold, series.crossing, series.method
    if threshold is None or crossing is None or method is None:
        return []
    limit = amount(threshold.value, series.unit)
    last = series.history[-1]
    if crossing.point_day is not None:
        point = next(p for p in series.forecast if p.day == crossing.point_day)
        return [
            _make(
                "capacity-review",
                series,
                f"Review capacity before {crossing.point_day}",
                "The forecast reaches the limit you configured. Decide whether the limit or the "
                "capacity should change; Netsight changes nothing.",
                [
                    (
                        f"Forecast {amount(point.value, series.unit)} on {point.day} "
                        f"(band {amount(point.lower, series.unit)} to "
                        f"{amount(point.upper, series.unit)})."
                    ),
                    f"Configured limit: {limit}.",
                    f"Latest measured day {last.day}: {amount(last.value, series.unit)}.",
                    method.why,
                ],
            )
        ]
    if crossing.upper_day is not None:
        return [
            _make(
                "capacity-watch",
                series,
                f"Watch capacity: the upper band reaches the limit on {crossing.upper_day}",
                "The most likely forecast stays under the limit, but the upper edge of the band "
                "does not. Re-check as more days are measured.",
                [
                    f"Upper band reaches {limit} on {crossing.upper_day}.",
                    f"Latest measured day {last.day}: {amount(last.value, series.unit)}.",
                    method.why,
                ],
            )
        ]
    return []


def _growth(series: ForecastSeries) -> list[ForecastRecommendation]:
    if series.threshold is not None or series.method is None or not series.forecast:
        return []
    recent = [p.value for p in series.history[-len(series.forecast) :]]
    before = sum(recent) / len(recent)
    ahead = sum(p.value for p in series.forecast) / len(series.forecast)
    if before <= 0:
        return []
    percent = round((ahead - before) * 100 / before)
    if percent < GROWTH_NOTICE_PERCENT:
        return []
    return [
        _make(
            "growth-no-limit",
            series,
            f"{series.name} is forecast to grow {percent} %",
            "No limit is configured, so no crossing can be reported. Consider configuring one "
            "that matches the capacity you have.",
            [
                (
                    f"Average of the next {len(series.forecast)} forecast days "
                    f"{amount(round(ahead), series.unit)} against "
                    f"{amount(round(before), series.unit)} over the last {len(recent)} measured "
                    f"days (+{percent} %)."
                ),
                series.method.why,
            ],
        )
    ]


def _is_weekend(point: ForecastHistoryPoint) -> bool:
    return parse_day(point.day).weekday() >= _SATURDAY


def _weekends(series: ForecastSeries) -> list[ForecastRecommendation]:
    weekend = [p.value for p in series.history if _is_weekend(p)]
    weekday = [p.value for p in series.history if not _is_weekend(p)]
    if len(weekend) < MIN_WEEKEND_DAYS or len(weekday) < MIN_WEEKDAYS:
        return []
    if sum(weekend) * len(weekday) * 100 >= sum(weekday) * len(weekend) * WEEKEND_RATIO_PERCENT:
        return []
    return [
        _make(
            "weekend-headroom",
            series,
            "Weekends carry much less than weekdays",
            "Large scheduled transfers such as backups or updates might fit the quieter days. "
            "This is an observation of past volume, not a plan.",
            [
                (
                    "Weekend days averaged "
                    f"{amount(round(sum(weekend) / len(weekend)), series.unit)} "
                    f"({len(weekend)} days measured)."
                ),
                (
                    "Weekdays averaged "
                    f"{amount(round(sum(weekday) / len(weekday)), series.unit)} "
                    f"({len(weekday)} days measured)."
                ),
            ],
        )
    ]


def recommend(series: list[ForecastSeries]) -> list[ForecastRecommendation]:
    """Advice for ``series`` in a fixed order, at most ``MAX_RECOMMENDATIONS`` lines."""
    found: list[ForecastRecommendation] = []
    for one in series:
        if one.state == "ok":
            found += _limit_advice(one) + _growth(one) + _weekends(one)
        else:
            found += _source_gap(one)
    return found[:MAX_RECOMMENDATIONS]
