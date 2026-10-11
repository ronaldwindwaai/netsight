"""The ``ok`` Applications and Destinations responses: policy classification, then the cohort rule.

Approval, risk and reputation come only from the operator policy. What each tier is then shown:

* the detail tier gets the rows as read, internal destinations included and labelled;
* the aggregate tier loses the destinations inside the organisation and any endpoint count below the
  cohort minimum (``traffic.cohort``), and the response says whether anything was withheld.
"""

from __future__ import annotations

from netsight_api.schemas_traffic import (
    PolicyStatus,
    TrafficApplicationsResponse,
    TrafficDestinationsResponse,
)
from netsight_api.traffic import cohort
from netsight_api.traffic.policy import TrafficPolicy
from netsight_api.traffic.responses import freshness_for
from netsight_api.traffic.route_support import Window, time_range
from netsight_api.traffic.source import ApplicationsRead, DestinationsRead


def applications_ok(
    result: ApplicationsRead, policy: TrafficPolicy, window: Window, minimum: int | None
) -> TrafficApplicationsResponse:
    classified = [
        row.model_copy(
            update={
                "risk": policy.application_risk(row.application),
                "approval": policy.application_approval(row.application),
            }
        )
        for row in result.rows
    ]
    rows, cohort_status = cohort.withhold_small_counts(classified, minimum)
    previous = (
        time_range(result.previous_range[0], result.previous_range[1], None)
        if result.previous_range is not None
        else None
    )
    return TrafficApplicationsResponse(
        state="ok",
        time_range=window.time_range,
        previous_range=previous,
        policy=PolicyStatus(state=policy.state),
        unsupported=[],
        total_bytes=result.total_bytes,
        items=rows,
        cohort=cohort_status,
        freshness=freshness_for(window.end, result.observed_at),
    )


def destinations_ok(
    result: DestinationsRead, policy: TrafficPolicy, window: Window, minimum: int | None
) -> TrafficDestinationsResponse:
    classified = [
        row.model_copy(
            update={"reputation": policy.destination_reputation(row.address, row.domain, row.asn)}
        )
        for row in result.rows
    ]
    visible = cohort.external_destinations(classified) if minimum is not None else classified
    rows, cohort_status = cohort.withhold_small_counts(visible, minimum)
    return TrafficDestinationsResponse(
        state="ok",
        time_range=window.time_range,
        first_seen_since=result.first_seen_since,
        policy=PolicyStatus(state=policy.state),
        total_bytes=result.total_bytes,
        items=rows,
        cohort=cohort_status,
        freshness=freshness_for(window.end, result.observed_at),
    )
