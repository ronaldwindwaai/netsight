"""What a flow source must offer the traffic surface, and the values it hands back.

The Protocol is the only thing the routes know about the flow store: no SQL, no vendor column
names. Every read is bounded by a window and a row limit, returns source-reported values or ``None``,
and signals a failure by raising (never by returning an empty success). Results are frozen values.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

from netsight_api.schemas_traffic import (
    ApplicationRow,
    DestinationRow,
    FilterName,
    FlowAggregations,
    TrafficFlow,
)
from netsight_api.traffic.filters import FlowFilterSet


@dataclass(frozen=True)
class Exploration:
    """Filtered rows plus aggregations; ``unsupported`` filters mean nothing was read."""

    flows: tuple[TrafficFlow, ...]
    aggregations: FlowAggregations | None
    unsupported: tuple[FilterName, ...]
    observed_at: datetime | None


@dataclass(frozen=True)
class ApplicationsRead:
    rows: tuple[ApplicationRow, ...]
    total_bytes: int | None
    previous_range: tuple[datetime, datetime] | None
    unsupported: tuple[Literal["application"], ...]
    observed_at: datetime | None


@dataclass(frozen=True)
class DestinationsRead:
    rows: tuple[DestinationRow, ...]
    total_bytes: int
    first_seen_since: datetime
    observed_at: datetime | None


@dataclass(frozen=True)
class FirstSeenRow:
    """An ASN or destination first seen inside the window (not in the look-back before it).

    ``endpoints`` is how many distinct source addresses sent to it in the window (``None``: the
    source did not say); the aggregate tier is only shown rows that enough sources stood behind.
    """

    kind: Literal["first-seen-asn", "first-seen-destination"]
    asn: int | None
    address: str | None
    domain: str | None
    first_seen: datetime
    bytes: int
    endpoints: int | None = None


@dataclass(frozen=True)
class AnomalyInputs:
    """Raw hourly counters for the baseline comparison.

    ``hourly_total`` doubles as coverage: an hour is present exactly when the source holds any flow
    for it. ``hourly_apps`` is ordered by volume inside the window (largest first).
    """

    hourly_total: dict[int, int]
    hourly_apps: dict[str, dict[int, int]]
    applications_reported: bool
    oldest: datetime | None
    first_seen: tuple[FirstSeenRow, ...]
    observed_at: datetime | None


class ExplorerSource(Protocol):
    """Bounded, read-only, parameterised flow reads for the Step 7 surfaces."""

    async def explore(
        self,
        *,
        start: datetime,
        end: datetime,
        limit: int,
        filters: FlowFilterSet,
        include_rows: bool = True,
    ) -> Exploration: ...

    async def applications(
        self, *, start: datetime, end: datetime, limit: int
    ) -> ApplicationsRead: ...

    async def destinations(
        self, *, start: datetime, end: datetime, limit: int
    ) -> DestinationsRead: ...

    async def anomaly_inputs(
        self, *, first_hour: datetime, last_hour: datetime
    ) -> AnomalyInputs: ...
