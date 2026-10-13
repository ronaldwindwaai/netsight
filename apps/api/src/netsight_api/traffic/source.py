"""What a flow source must offer the traffic surface, and the values it hands back.

The Protocol is the only thing the routes know about the flow store: no SQL, no vendor column
names. Every read is bounded by a window and a row limit, returns source-reported values or ``None``,
and signals a failure by raising (never by returning an empty success). Results are frozen values.

Two timestamps travel with a result. ``observed_at`` is the newest flow behind *this* answer (the
filtered rows). ``source_observed_at`` is the newest flow the source holds in the window at all, not
tied to any filter or cohort: it is what the aggregate tier is told, because the newest time of a
filtered answer can describe a single machine's last activity. Every ``endpoints`` figure and
``internal_endpoints`` counts endpoints inside the organisation (``traffic.addresses``), the cohort
denominator.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
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
    source_observed_at: datetime | None = None


@dataclass(frozen=True)
class ApplicationsRead:
    rows: tuple[ApplicationRow, ...]
    total_bytes: int | None
    previous_range: tuple[datetime, datetime] | None
    unsupported: tuple[Literal["application"], ...]
    observed_at: datetime | None
    source_observed_at: datetime | None = None


@dataclass(frozen=True)
class DestinationsRead:
    rows: tuple[DestinationRow, ...]
    total_bytes: int
    first_seen_since: datetime
    observed_at: datetime | None
    source_observed_at: datetime | None = None


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

    ``sources_total`` and ``sources_by_application`` are the distinct internal endpoints behind the
    observed window as a whole and behind each listed application (``None`` / absent: the source did
    not say, which the aggregate tier treats as too few). They are the cohort denominator of a series.
    """

    hourly_total: dict[int, int]
    hourly_apps: dict[str, dict[int, int]]
    applications_reported: bool
    oldest: datetime | None
    first_seen: tuple[FirstSeenRow, ...]
    observed_at: datetime | None
    sources_total: int | None = None
    sources_by_application: Mapping[str, int] = field(default_factory=dict)


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
