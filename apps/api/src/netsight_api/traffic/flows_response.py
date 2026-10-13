"""The ``ok`` Flow Explorer response: rows by tier, attribution by role, aggregates by cohort.

The route decides *who is asking* (``FlowsQuery``); this module turns one source answer into the
response that caller may see:

* the detail tier gets rows and aggregates as read; the aggregate tier gets aggregates only (its rows
  were never read), held to the small-cohort rule (a small answer is withheld whole, a small item is
  withheld individually), without destinations inside the organisation, and told the source's own
  freshness rather than the newest time of the filtered answer;
* people are named only through the identity service, and only as far as the role's ``users:*``
  permission goes (see ``traffic.attribution``).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from netsight_api.rbac import Identity, Permission, is_allowed
from netsight_api.schemas_traffic import (
    AttributionStatus,
    TrafficFlowsResponse,
)
from netsight_api.traffic import cohort
from netsight_api.traffic.attribution import attribute_flows
from netsight_api.traffic.filters import FlowFilterSet
from netsight_api.traffic.responses import freshness_for_tier
from netsight_api.traffic.route_support import Window
from netsight_api.traffic.source import Exploration

AttributionLevel = Literal["person", "endpoint", "none"]


@dataclass(frozen=True)
class FlowsQuery:
    """A validated Explorer request and the tier of the caller who made it."""

    filters: FlowFilterSet
    window: Window
    detail: bool
    level: AttributionLevel
    minimum: int | None  # the cohort minimum for the aggregate tier; None for the detail tier


def attribution_level(identity: Identity, *, restricted: bool) -> AttributionLevel:
    if restricted:
        return "none"
    if is_allowed(identity, Permission.USERS_READ.value):
        return "person"
    if is_allowed(identity, Permission.USERS_READ_LIMITED.value):
        return "endpoint"
    return "none"


def withheld_status(level: AttributionLevel) -> AttributionStatus:
    """The attribution status before (or without) asking the identity service."""
    return AttributionStatus(
        level=level, state="withheld" if level == "none" else "not-evaluated", as_of=None
    )


async def ok_response(
    result: Exploration, query: FlowsQuery, service: Any, now: datetime
) -> TrafficFlowsResponse:
    """The ``ok`` body for one source answer (the caller validates it against the contract)."""
    flows = list(result.flows) if query.detail else []
    status = withheld_status(query.level)
    if query.level != "none":
        attributed = await attribute_flows(service, flows, level=query.level, now=now)
        status, flows = attributed.status, list(attributed.flows)
    aggregations, cohort_status = cohort.explorer_view(result.aggregations, query.minimum)
    return TrafficFlowsResponse(
        state="ok",
        time_range=query.window.time_range,
        filters=query.filters.to_model(),
        unsupported=[],
        flows_restricted=not query.detail,
        attribution=status,
        flows=flows,
        aggregations=aggregations,
        cohort=cohort_status,
        freshness=freshness_for_tier(
            query.window.end,
            result.observed_at,
            result.source_observed_at,
            aggregate=query.minimum is not None,
        ),
    )
