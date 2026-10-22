"""Capacity forecast routes (Step 13): ``/api/v1/forecast/...``. Read-only, advisory.

* ``GET /forecast/capacity`` - the forecast, per series, with advisory recommendations;
* ``GET /forecast/capacity/export`` - the capacity report: the same response as CSV.

Authorise (``forecast:read`` / ``forecast:export``), then the per-identity rate limit (so an
unauthorised caller never learns limiter state), then a strict query (unknown, repeated or malformed
parameters are a 422 that echoes nothing). The flow store is read once per UTC day in one fixed
120-day window whatever the requested window is (a request is a slice of it), the result is shared
for a few minutes by every caller (it holds no per-person data) and a read takes an admission
slot. A failed read is never kept as a result, but it is remembered for a few seconds so a store
that is down is not hammered and waiters fail fast. The answer is explicit:

* no flow source: ``not-connected``; unreadable: ``unknown``; too little history:
  ``insufficient-data`` (HTTP 200, never an empty success and never a projected point);
* a body that fails its own canonical contract is not sent as data: it degrades to ``unknown``;
* every value after the last measured day is a forecast and the response says so;
* there is no write route and no route that creates or runs an Action Request: advice is text.

Every read and refusal is audited (actor, state, counts and window sizes; never a value). Responses
are ``Cache-Control: no-store``.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from functools import lru_cache
from typing import Annotated, Any, Final, cast

from fastapi import APIRouter, Depends, Request, Response

from netsight_api.contracts import ContractViolation, validate
from netsight_api.errors import ApiError
from netsight_api.forecast import report, service, wiring
from netsight_api.forecast.source import DailyTotals, DailyTotalsSource
from netsight_api.rbac import Identity, Permission
from netsight_api.read_query import QueryError, integer, single_values
from netsight_api.read_support import no_store, reader, rejected
from netsight_api.schemas import ErrorEnvelope
from netsight_api.schemas_forecast import ForecastResponse
from netsight_api.traffic import audit_trail
from netsight_api.traffic.cache import TtlCache
from netsight_api.traffic.route_support import admit

_LOGGER: Final = logging.getLogger("netsight_api")

router = APIRouter(prefix="/forecast", tags=["forecast"])

READ_LIMIT_PER_MINUTE: Final = 30
EXPORT_LIMIT_PER_MINUTE: Final = 6
CACHE_TTL_SECONDS: Final = 300.0
FAILURE_TTL_SECONDS: Final = 15.0
DEFAULT_HORIZON_DAYS: Final = 14
DEFAULT_HISTORY_DAYS: Final = 56
READ_ACTION: Final = "forecast.capacity.read"
EXPORT_ACTION: Final = "forecast.capacity.export"
EXPORT_FILENAME: Final = "netsight-capacity-forecast.csv"
_PARAMETERS: Final = frozenset({"horizon_days", "history_days"})
_ERRORS: Final[dict[int | str, dict[str, Any]]] = {
    401: {"model": ErrorEnvelope, "description": "Authentication required"},
    403: {"model": ErrorEnvelope, "description": "Permission denied"},
    422: {"model": ErrorEnvelope, "description": "Invalid request"},
    429: {"model": ErrorEnvelope, "description": "Read rate limit exceeded"},
    503: {"model": ErrorEnvelope, "description": "The flow source is busy"},
}


def get_now() -> datetime:
    return datetime.now(UTC)


def get_history_source() -> DailyTotalsSource | None:
    """The ClickHouse-backed flow source when configured; ``None`` is ``not-connected``."""
    from netsight_api import main

    source = main.get_optional_traffic_source()
    return cast("DailyTotalsSource", source) if hasattr(source, "daily_totals") else None


def get_traffic_limit() -> int | None:
    return wiring.traffic_daily_limit()


@dataclass(frozen=True)
class ForecastCaches:
    """The shared read (one entry per UTC day boundary) and the short memory of a failed read."""

    reads: TtlCache
    failures: TtlCache


@lru_cache(maxsize=1)
def _forecast_caches() -> ForecastCaches:
    return ForecastCaches(
        reads=TtlCache(ttl_seconds=CACHE_TTL_SECONDS, max_entries=4),
        failures=TtlCache(ttl_seconds=FAILURE_TTL_SECONDS, max_entries=4),
    )


def get_forecast_caches() -> ForecastCaches:
    return _forecast_caches()


Source = Annotated[DailyTotalsSource | None, Depends(get_history_source)]
Now = Annotated[datetime, Depends(get_now)]
Limit = Annotated[int | None, Depends(get_traffic_limit)]
Caches = Annotated[ForecastCaches, Depends(get_forecast_caches)]


def _reader(permission: Permission, action: str, family: str, limit: Callable[[], int]) -> Any:
    return Depends(reader(permission, action, family, limit))


ReadReader = Annotated[
    Identity,
    _reader(Permission.FORECAST_READ, READ_ACTION, "forecast", lambda: READ_LIMIT_PER_MINUTE),
]
ExportReader = Annotated[
    Identity,
    _reader(
        Permission.FORECAST_EXPORT,
        EXPORT_ACTION,
        "forecast-export",
        lambda: EXPORT_LIMIT_PER_MINUTE,
    ),
]


class _Unreadable(Exception):
    """The flow store could not be read (or was just seen failing); carries nothing."""


def _window(request: Request, identity: Identity, action: str) -> tuple[int, int]:
    try:
        values = single_values(request, _PARAMETERS)
        horizon = integer(values, "horizon_days", DEFAULT_HORIZON_DAYS, 1, 30)
        history = integer(values, "history_days", DEFAULT_HISTORY_DAYS, 14, 120)
    except QueryError:
        raise rejected(request, identity, action) from None
    return horizon, history


def _checked(body: ForecastResponse) -> ForecastResponse | None:
    try:
        validate("forecast_response", json.loads(body.model_dump_json(by_alias=True)))
    except ContractViolation:
        _LOGGER.error("forecast response failed its canonical contract")
        return None
    return body


async def read_totals(
    request: Request,
    identity: Identity,
    action: str,
    *,
    source: DailyTotalsSource | None,
    last_day: date,
    caches: ForecastCaches,
) -> DailyTotals | None:
    """The shared 120-day read, or ``None`` when there is no source or it cannot be read."""
    if source is None:
        return None
    key = last_day.isoformat()

    async def load() -> DailyTotals:
        if caches.failures.peek(key):
            raise _Unreadable
        try:
            async with admit(request, identity, action, detail=False):
                return await service.read_daily_totals(source, last_day=last_day)
        except ApiError:
            raise
        except Exception as error:  # noqa: BLE001 - the source boundary: any failure is `unknown`
            _LOGGER.warning(
                "capacity forecast read failed", extra={"error_type": type(error).__name__}
            )
            caches.failures.put(key, True)
            raise _Unreadable from None

    try:
        found: DailyTotals = await caches.reads.get_or_load(key, load)
    except _Unreadable:
        return None
    return found


async def _forecast(
    request: Request,
    identity: Identity,
    action: str,
    *,
    source: DailyTotalsSource | None,
    now: datetime,
    limit: int | None,
    caches: ForecastCaches,
    horizon: int,
    history: int,
) -> ForecastResponse:
    totals = await read_totals(
        request,
        identity,
        action,
        source=source,
        last_day=service.last_complete_day(now),
        caches=caches,
    )
    built = service.assemble(
        connected=source is not None,
        totals=totals,
        now=now,
        horizon_days=horizon,
        history_days=history,
        traffic_limit=limit,
    )
    return _checked(built) or service.degraded(now=now, horizon_days=horizon, history_days=history)


def _audit(
    request: Request, identity: Identity, action: str, body: ForecastResponse, **extra: int | str
) -> None:
    audit_trail.read(
        request,
        identity.id,
        action,
        failure=body.state == "unknown",
        state=body.state,
        horizon_days=body.horizon_days,
        history_days=body.history_days,
        series_ok=sum(1 for s in body.series if s.state == "ok"),
        recommendation_count=len(body.recommendations),
        **extra,
    )


@router.get(
    "/capacity",
    response_model=ForecastResponse,
    responses=_ERRORS,
    operation_id="getCapacityForecast",
)
async def capacity_forecast(
    request: Request,
    response: Response,
    identity: ReadReader,
    source: Source,
    now: Now,
    limit: Limit,
    caches: Caches,
) -> ForecastResponse:
    """Forecasts from source-reported history (forecast, not measurement) and advisory text."""
    no_store(response)
    horizon, history = _window(request, identity, READ_ACTION)
    body = await _forecast(
        request,
        identity,
        READ_ACTION,
        source=source,
        now=now,
        limit=limit,
        caches=caches,
        horizon=horizon,
        history=history,
    )
    _audit(request, identity, READ_ACTION, body)
    return body


@router.get(
    "/capacity/export",
    response_model=None,
    responses={
        **_ERRORS,
        200: {
            "description": "The capacity report as CSV",
            "content": {"text/csv": {"schema": {"type": "string"}}},
        },
    },
    operation_id="exportCapacityForecast",
)
async def export_capacity_forecast(
    request: Request,
    identity: ExportReader,
    source: Source,
    now: Now,
    limit: Limit,
    caches: Caches,
) -> Response:
    """The capacity report: measured and forecast days as CSV, every row labelled."""
    horizon, history = _window(request, identity, EXPORT_ACTION)
    body = await _forecast(
        request,
        identity,
        EXPORT_ACTION,
        source=source,
        now=now,
        limit=limit,
        caches=caches,
        horizon=horizon,
        history=history,
    )
    _audit(request, identity, EXPORT_ACTION, body, format="csv", row_count=report.row_count(body))
    return Response(
        content=report.export_csv(body),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{EXPORT_FILENAME}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
