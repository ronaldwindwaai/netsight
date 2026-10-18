"""What the forecast surface asks of a flow source, and the values it gets back.

The Protocol is the only thing the service knows about the flow store: no SQL, no vendor column
names. A read is bounded by a window of whole UTC days, returns source-reported values only, and
signals a failure by raising (never by returning an empty success). A day the source holds no flow
for is *absent* from ``daily``; it is never reported as zero.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from typing import Protocol


@dataclass(frozen=True)
class DailyTotals:
    """Bytes per whole UTC day, plus the first and last flow the source holds in the window.

    ``first_flow_at`` and ``last_flow_at`` are ``None`` when the window holds no flow at all.
    ``first_flow_at`` lets the caller drop a first day the store only partly covers (retention
    starts mid-day); ``last_flow_at`` does the same for a newest day the collector stopped during.

    ``hours_covered`` is how many distinct UTC hours of each day held at least one flow, or ``None``
    when the source cannot say. A day with long silent stretches (a collector outage) understates
    its bytes; the caller excludes such a day rather than present it as measured.
    """

    daily: dict[date, int]
    first_flow_at: datetime | None
    last_flow_at: datetime | None
    hours_covered: dict[date, int] | None = None


class DailyTotalsSource(Protocol):
    async def daily_totals(self, *, first_day: date, end_day: date) -> DailyTotals:
        """Total bytes per UTC day for ``first_day <= day < end_day`` (at most 120 days)."""
        ...
