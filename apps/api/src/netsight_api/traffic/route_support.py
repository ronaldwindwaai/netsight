"""Plumbing shared by the four traffic routes: windows, source reads, failures, audited refusals.

Nothing here knows a route's response shape. A refusal is audited with a static reason code before it
is raised, a source failure is logged by type only, and a heavy read always runs inside an admission
slot (``traffic.guards``) so the busy and per-identity refusals are audited in one place.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime

from fastapi import Request, Response

from netsight_api.alerting_route_support import correlation_id
from netsight_api.errors import ApiError
from netsight_api.rbac import Identity
from netsight_api.schemas import TrafficPreset, TrafficTimeRange
from netsight_api.timewindow import resolve_window
from netsight_api.traffic import audit_trail, guards
from netsight_api.traffic.filters import FilterError, reject_unknown_parameters

_LOGGER = logging.getLogger("netsight_api")

WINDOW_PARAMETERS = frozenset({"preset", "from", "to"})


@dataclass(frozen=True)
class Window:
    """A validated request window and the contract object that echoes it."""

    start: datetime
    end: datetime
    time_range: TrafficTimeRange

    @property
    def seconds(self) -> int:
        return int((self.end - self.start).total_seconds())


def no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


def unprocessable(error: FilterError | ApiError) -> ApiError:
    """A 422 whose message names the filter and a static reason, never the value that was sent."""
    if isinstance(error, ApiError):
        return error
    return ApiError(422, "VALIDATION_ERROR", str(error))


def reject(
    request: Request, identity: Identity, action: str, error: FilterError | ApiError
) -> ApiError:
    """Audit a rejected request with a static reason and return the 422 to raise."""
    audit_trail.failed(request, identity.id, action, audit_trail.reason_for(error))
    return unprocessable(error)


def time_range(start: datetime, end: datetime, preset: TrafficPreset | None) -> TrafficTimeRange:
    return TrafficTimeRange.model_validate({"from": start, "to": end, "preset": preset})


def parse_window(
    request: Request,
    identity: Identity,
    action: str,
    preset: TrafficPreset,
    start: datetime | None,
    end: datetime | None,
    allowed: frozenset[str],
) -> Window:
    """Refuse unknown or repeated parameters and out-of-range windows (422, audited)."""
    try:
        reject_unknown_parameters(request.query_params.multi_items(), allowed)
        resolved_start, resolved_end, resolved = resolve_window(preset, start, end)
    except (FilterError, ApiError) as error:
        raise reject(request, identity, action, error) from error
    return Window(resolved_start, resolved_end, time_range(resolved_start, resolved_end, resolved))


async def capture[T](operation: Awaitable[T]) -> T | Exception:
    """Await a source read, returning the error instead of raising it (cancellation propagates)."""
    try:
        return await operation
    except Exception as exc:  # noqa: BLE001 - deliberate source-read boundary
        return exc


def log_failure(request: Request, what: str, error: BaseException) -> None:
    _LOGGER.warning(
        what,
        extra={
            "correlation_id": correlation_id(request),
            "source": "clickhouse",
            "error_type": type(error).__name__,
        },
    )


@asynccontextmanager
async def admit(
    request: Request, identity: Identity, action: str, *, detail: bool
) -> AsyncIterator[None]:
    """A heavy-read slot for the caller; a refusal is audited (busy / identity-busy) and raised."""
    try:
        async with guards.heavy_read(identity.id, detail=detail):
            yield
    except ApiError as refusal:
        if refusal.code in guards.REFUSAL_CODES:
            reason = "identity-busy" if refusal.code == guards.IDENTITY_BUSY_CODE else "busy"
            audit_trail.failed(request, identity.id, action, reason)
        raise


async def heavy_read[T](
    request: Request,
    identity: Identity,
    action: str,
    *,
    detail: bool,
    read: Callable[[], Awaitable[T]],
) -> T | Exception:
    """Run a flow-store read in a heavy-read slot; a source failure is returned, a refusal raised.

    The coroutine is created inside the slot, so a refusal never leaves an un-awaited coroutine.
    """
    async with admit(request, identity, action, detail=detail):
        return await capture(read())
