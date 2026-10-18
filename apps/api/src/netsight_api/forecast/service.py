"""Building the capacity forecast response from a flow source (Step 13).

Read-only and computed on read: nothing is stored. The one real series is the organisation-wide daily
byte total from the flow source. Link utilisation and inventory growth are listed as ``not-connected``
because no source in this deployment reports their history (LibreNMS and NetBox are read for the
current state only); they are listed, with the reason, so the gap is visible rather than silent.

Honesty rules, in one place:

* no flow source: ``not-connected``; a source that fails: ``unknown`` (the error text is never
  returned); a reachable source with too little history: ``insufficient-data`` with the days it had;
* the window is whole UTC days ending with the last *complete* day; a day with no flows is absent,
  never zero; a first day the store covers only from mid-day is dropped as partial; days before the
  store's first complete day are not "missing", they are before the history began;
* every projected value lives in ``forecast`` with a band and the response is labelled a forecast;
* a limit comes only from the operator; the crossing days are derived from the forecast.
"""

from __future__ import annotations

import logging
from datetime import UTC, date, datetime, timedelta
from typing import Any, Final

from netsight_api.forecast import engine
from netsight_api.forecast.recommend import recommend
from netsight_api.forecast.source import DailyTotals, DailyTotalsSource
from netsight_api.schemas_forecast import (
    MAX_HISTORY_DAYS,
    MAX_HORIZON_DAYS,
    MAX_VALUE,
    MIN_OBSERVED,
    NOTICE,
    ForecastHistoryPoint,
    ForecastMethod,
    ForecastPoint,
    ForecastResponse,
    ForecastSeries,
    ForecastThreshold,
    crossing_for,
    overall_state,
)

_LOGGER: Final = logging.getLogger("netsight_api")
PARTIAL_DAY_GRACE: Final = timedelta(hours=1)
READ_DAYS: Final = MAX_HISTORY_DAYS
TRAFFIC_NAME: Final = "Network traffic volume"
_NO_HISTORY: Final = (
    "No source in this deployment reports this series' history. LibreNMS and NetBox are read for "
    "the current state only, and Netsight does not store a history of its own for it."
)
_SERIES_BASE: Final[dict[str, Any]] = {
    "source_observed_at": None,
    "history": [],
    "history_missing_days": 0,
    "method": None,
    "forecast": [],
    "threshold": None,
    "crossing": None,
}


def _not_connected(
    series_id: str, name: str, unit: str, reason: str, detail: str
) -> ForecastSeries:
    return ForecastSeries.model_validate(
        {
            **_SERIES_BASE,
            "id": series_id,
            "name": name,
            "unit": unit,
            "state": "not-connected",
            "reason": reason,
            "detail": detail,
        }
    )


def _unknown_traffic() -> ForecastSeries:
    return ForecastSeries.model_validate(
        {
            **_SERIES_BASE,
            "id": "traffic-volume",
            "name": TRAFFIC_NAME,
            "unit": "bytes-per-day",
            "state": "unknown",
            "reason": "source-unreadable",
            "detail": "The flow source is configured but could not be read.",
        }
    )


def _usable_days(totals: DailyTotals, read_first: date) -> dict[date, int]:
    """Observed days, without a first day the store only covers from mid-day.

    Only a first day *after* the start of the read can be partial: a first day at the very edge
    of the read may simply have older data behind it, so it is kept.
    """
    days = dict(totals.daily)
    if not days:
        return days
    first = min(days)
    started = totals.first_flow_at
    if first > read_first and started is not None and started.astimezone(UTC).date() == first:
        midnight = datetime.combine(first, datetime.min.time(), tzinfo=UTC)
        if started - midnight > PARTIAL_DAY_GRACE:
            del days[first]
    return days


def _history(days: dict[date, int]) -> list[ForecastHistoryPoint]:
    return [ForecastHistoryPoint(day=d.isoformat(), value=v) for d, v in sorted(days.items())]


def _traffic_series(
    totals: DailyTotals, *, first_day: date, last_day: date, horizon: int, limit: int | None
) -> ForecastSeries:
    read_first = last_day - timedelta(days=READ_DAYS - 1)
    usable = _usable_days(totals, read_first)
    days = {d: v for d, v in usable.items() if d >= first_day}
    start = min(days) if days else first_day
    missing = (last_day - start).days + 1 - len(days) if days else 0
    common = {
        "id": "traffic-volume",
        "name": TRAFFIC_NAME,
        "unit": "bytes-per-day",
        "source_observed_at": totals.last_flow_at if days else None,
        "history": _history(days),
        "history_missing_days": missing,
    }
    result = engine.project(days, first_day=start, last_day=last_day, horizon_days=horizon)
    if isinstance(result, engine.Insufficient):
        return ForecastSeries.model_validate(
            {
                **_SERIES_BASE,
                **common,
                "state": "insufficient-data",
                "reason": result.reason,
                "detail": result.detail,
            }
        )
    points = [
        ForecastPoint(day=p.day.isoformat(), value=p.value, lower=p.lower, upper=p.upper)
        for p in result.points
    ]
    method = result.method
    return ForecastSeries.model_validate(
        {
            **_SERIES_BASE,
            **common,
            "state": "ok",
            "reason": None,
            "detail": None,
            "method": ForecastMethod(
                name=method.name,
                why=method.why,
                observed_days=method.observed_days,
                slope_per_day=method.slope_per_day,
                linear_mae=method.linear_mae,
                seasonal_mae=method.seasonal_mae,
                band="approximate-95-percent",
            ),
            "forecast": points,
            "threshold": None
            if limit is None
            else ForecastThreshold(value=limit, basis="operator-configured"),
            "crossing": None if limit is None else crossing_for(points, limit),
        }
    )


async def read_daily_totals(source: DailyTotalsSource, *, last_day: date) -> DailyTotals:
    """The one fixed read behind every window: ``READ_DAYS`` whole UTC days ending ``last_day``.

    The same read serves any requested history length (the window is a slice of it), so a caller
    cannot multiply flow-store scans by varying the window. Raises whatever the source raises.
    """
    return await source.daily_totals(
        first_day=last_day - timedelta(days=READ_DAYS - 1), end_day=last_day + timedelta(days=1)
    )


def _check_arguments(horizon: int, history: int, limit: int | None) -> None:
    if not 1 <= horizon <= MAX_HORIZON_DAYS:
        raise ValueError("the horizon is outside the supported range")
    if not MIN_OBSERVED <= history <= MAX_HISTORY_DAYS:
        raise ValueError("the history window is outside the supported range")
    if limit is not None and not 1 <= limit <= MAX_VALUE:
        raise ValueError("the limit is outside the supported range")


def last_complete_day(now: datetime) -> date:
    return now.astimezone(UTC).date() - timedelta(days=1)


def assemble(
    *,
    connected: bool,
    totals: DailyTotals | None,
    now: datetime,
    horizon_days: int,
    history_days: int,
    traffic_limit: int | None,
) -> ForecastResponse:
    """The response from a finished read: ``connected`` False is not-connected, ``totals`` None with
    a connected source is unknown (the read failed), otherwise the forecast over the requested slice."""
    _check_arguments(horizon_days, history_days, traffic_limit)
    last_day = last_complete_day(now)
    if not connected:
        traffic = _not_connected(
            "traffic-volume",
            TRAFFIC_NAME,
            "bytes-per-day",
            "no-source",
            "No flow source is configured.",
        )
    elif totals is None:
        traffic = _unknown_traffic()
    else:
        traffic = _traffic_series(
            totals,
            first_day=last_day - timedelta(days=history_days - 1),
            last_day=last_day,
            horizon=horizon_days,
            limit=traffic_limit,
        )
    series = [
        traffic,
        _not_connected(
            "wan-utilisation", "WAN link utilisation", "percent", "no-history-source", _NO_HISTORY
        ),
        _not_connected(
            "inventory-growth", "Inventory growth", "devices", "no-history-source", _NO_HISTORY
        ),
    ]
    return ForecastResponse(
        state=overall_state([s.state for s in series]),
        generated_at=now,
        is_forecast=True,
        notice=NOTICE,
        horizon_days=horizon_days,
        history_days=history_days,
        history_through=last_day.isoformat(),
        series=series,
        recommendations=recommend(series),
    )


async def build_capacity_forecast(
    *,
    source: DailyTotalsSource | None,
    now: datetime,
    horizon_days: int,
    history_days: int,
    traffic_limit: int | None,
) -> ForecastResponse:
    """Read the source (if any) and assemble: only the read itself is a source boundary."""
    totals: DailyTotals | None = None
    if source is not None:
        try:
            totals = await read_daily_totals(source, last_day=last_complete_day(now))
        except Exception as error:  # noqa: BLE001 - the source boundary: any failure is `unknown`
            _LOGGER.warning(
                "capacity forecast read failed", extra={"error_type": type(error).__name__}
            )
    return assemble(
        connected=source is not None,
        totals=totals,
        now=now,
        horizon_days=horizon_days,
        history_days=history_days,
        traffic_limit=traffic_limit,
    )


def degraded(*, now: datetime, horizon_days: int, history_days: int) -> ForecastResponse:
    """The answer when a finished response failed its own contract: nothing is shown as data."""
    _check_arguments(horizon_days, history_days, None)
    series = [
        _unknown_traffic(),
        _not_connected(
            "wan-utilisation", "WAN link utilisation", "percent", "no-history-source", _NO_HISTORY
        ),
        _not_connected(
            "inventory-growth", "Inventory growth", "devices", "no-history-source", _NO_HISTORY
        ),
    ]
    return ForecastResponse(
        state="unknown",
        generated_at=now,
        is_forecast=True,
        notice=NOTICE,
        horizon_days=horizon_days,
        history_days=history_days,
        history_through=(now.astimezone(UTC).date() - timedelta(days=1)).isoformat(),
        series=series,
        recommendations=[],
    )
