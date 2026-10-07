"""Server-bounded time windows shared by the traffic and security surfaces."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

from netsight_api.errors import ApiError
from netsight_api.schemas import TrafficPreset

PRESETS: Mapping[str, timedelta] = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
}
MAX_WINDOW = timedelta(days=31)


def resolve_window(
    preset: TrafficPreset,
    start: datetime | None,
    end: datetime | None,
) -> tuple[datetime, datetime, TrafficPreset | None]:
    """Resolve the requested window: explicit bounds or a bounded preset.

    Windows are server-bounded per API guidelines. Invalid combinations
    fail with 422 rather than silently substituting a different range.
    """
    if (start is None) != (end is None):
        raise ApiError(422, "VALIDATION_ERROR", "from and to must be provided together")
    if start is not None and end is not None:
        if start.tzinfo is None or end.tzinfo is None:
            raise ApiError(422, "VALIDATION_ERROR", "from and to must be timezone-aware")
        if start >= end:
            raise ApiError(422, "VALIDATION_ERROR", "from must be before to")
        if end - start > MAX_WINDOW:
            raise ApiError(422, "VALIDATION_ERROR", "time window exceeds 31 days")
        return start.astimezone(UTC), end.astimezone(UTC), None
    duration = PRESETS.get(preset)
    if duration is None:
        raise ApiError(422, "VALIDATION_ERROR", "unknown time preset")
    now = datetime.now(UTC)
    return now - duration, now, preset
