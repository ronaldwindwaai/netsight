"""Shared builders for the forecast tests (Step 13): a fake flow source and synthetic daily series."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from netsight_api.forecast.source import DailyTotals

NOW = datetime(2026, 10, 18, 6, 0, tzinfo=UTC)
LAST = date(2026, 10, 17)  # the last complete UTC day
GB = 10**9


def day(back: int) -> date:
    """The day ``back`` days before the last complete day."""
    return LAST - timedelta(days=back)


class FakeSource:
    def __init__(self, totals: DailyTotals | None = None, error: Exception | None = None) -> None:
        self.totals, self.error = totals, error
        self.calls: list[tuple[date, date]] = []

    async def daily_totals(self, *, first_day: date, end_day: date) -> DailyTotals:
        self.calls.append((first_day, end_day))
        if self.error is not None:
            raise self.error
        assert self.totals is not None
        return self.totals


def totals(values: dict[date, int], *, first_flow_at: datetime | None = None) -> DailyTotals:
    if not values:
        return DailyTotals({}, None, None)
    first = first_flow_at or datetime.combine(min(values), datetime.min.time(), tzinfo=UTC)
    return DailyTotals(
        dict(values), first, datetime.combine(max(values), datetime.max.time(), tzinfo=UTC)
    )


def growing(days: int, *, start: int = 100 * GB, step: int = GB) -> dict[date, int]:
    return {day(days - 1 - i): start + step * i for i in range(days)}
