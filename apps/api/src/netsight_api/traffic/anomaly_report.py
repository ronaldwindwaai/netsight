"""Turn baseline inputs into the ``/traffic/anomalies`` response: evidence with context, never a verdict.

The arithmetic is ``traffic.anomaly``; this module attaches what the operator configured and what
the source reported:

* **Context, not a verdict.** Outside working hours (from the operator policy, ``None`` when none is
  configured) is context. When an hour above its baseline falls outside working hours the response
  lists the common legitimate causes (backups, updates, cloud sync, ...); it never says "malicious".
* **First-seen needs history.** An ASN or destination is "first seen" only against a look-back. If the
  source holds less than ``REQUIRED_HISTORY_DAYS`` of history before the window, everything would
  look new, so none is flagged and the status says why.
* **Bounded.** At most 50 anomalies and 20 first-seen rows are listed (the full anomaly count is
  reported), and the evaluation is bounded to a week of hours and eleven series.
* **Small cohorts.** The aggregate tier is not shown a first-seen ASN or destination that fewer than
  the cohort minimum of source addresses reached (``traffic.cohort``); the response says when rows
  were withheld.
* **Daylight saving.** The weeks compared are fixed 168-hour UTC weeks, so when the policy time zone
  changes its offset between the first baseline week and the end of the range, the local hour of the
  earlier weeks is shifted by one. The response flags that (``evaluation.daylight_saving``).
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta
from typing import Any, Final

from netsight_api.schemas import TrafficTimeRange
from netsight_api.schemas_traffic import (
    Anomaly,
    AnomalyContext,
    AnomalySubject,
    BaselineMethod,
    CohortStatus,
    DaylightSaving,
    Evaluation,
    FirstSeen,
    FirstSeenStatus,
    LegitimatePattern,
    TrafficAnomaliesResponse,
    WorkingHours,
)
from netsight_api.traffic import anomaly as alg
from netsight_api.traffic import cohort
from netsight_api.traffic.addresses import is_internal_address
from netsight_api.traffic.policy import TrafficPolicy
from netsight_api.traffic.responses import freshness_for
from netsight_api.traffic.source import AnomalyInputs, FirstSeenRow

REQUIRED_HISTORY_DAYS: Final = 7
MAX_ANOMALIES: Final = 50
MAX_FIRST_SEEN: Final = 20
MAX_WINDOW: Final = timedelta(days=7)
HOUR: Final = timedelta(hours=1)

LEGITIMATE_PATTERNS: Final[tuple[LegitimatePattern, ...]] = (
    "backup",
    "cloud-sync",
    "cctv-or-nvr",
    "patching-or-updates",
    "replication",
    "scheduled-maintenance",
    "antivirus-update",
    "authorised-remote-work",
)

METHOD: Final = BaselineMethod(
    algorithm="same-hour-of-week-median-mad",
    weeks=alg.WEEKS,
    min_weeks=alg.MIN_WEEKS,
    threshold=alg.THRESHOLD,
    min_difference_bytes=alg.MIN_DIFFERENCE_BYTES,
)


def observation_hours(window_start: datetime, window_end: datetime) -> tuple[datetime, datetime]:
    """The whole hours judged: the last complete hour back as many hours as the window spans.

    The current, partial hour is never judged (its counters are still growing). A window of one hour
    judges the last complete hour; the span is at most a week.
    """
    last = window_end.replace(minute=0, second=0, microsecond=0)
    span = max(1, min(math.ceil((window_end - window_start) / HOUR), alg.MAX_BUCKETS))
    return last - span * HOUR, last


def evaluation_status(evaluated: int, insufficient: int) -> str:
    if evaluated == 0:
        return "insufficient-baseline" if insufficient else "no-data"
    return "partial" if insufficient else "evaluated"


def _context(policy: TrafficPolicy, hour: datetime, *, above: bool) -> AnomalyContext:
    outside = policy.outside_working_hours(hour)
    patterns = list(LEGITIMATE_PATTERNS) if outside is True and above else []
    return AnomalyContext(outside_working_hours=outside, common_legitimate_patterns=patterns)


def _daylight_saving(
    policy: TrafficPolicy, first_hour: datetime, last_hour: datetime
) -> DaylightSaving:
    """Whether the policy zone's offset changed anywhere from the oldest baseline week to the end."""
    changed = policy.daylight_saving_change(first_hour - timedelta(weeks=alg.WEEKS), last_hour)
    if changed is None:
        return "not-applicable"
    return "crossed" if changed else "none"


def _first_seen_rows(
    rows: tuple[FirstSeenRow, ...], policy: TrafficPolicy, minimum: int | None
) -> tuple[list[FirstSeen], CohortStatus]:
    external = tuple(
        row
        for row in rows
        if row.kind == "first-seen-asn"
        or (row.address is not None and not is_internal_address(row.address))
    )
    visible, status = cohort.first_seen_view(external, minimum)
    ordered = sorted(visible, key=lambda r: (-r.bytes, r.kind, r.asn or 0, r.address or ""))
    return [
        FirstSeen(
            kind=row.kind,
            asn=row.asn,
            address=row.address,
            domain=row.domain,
            first_seen=row.first_seen,
            bytes=row.bytes,
            context=_context(
                policy,
                row.first_seen.replace(minute=0, second=0, microsecond=0),
                above=True,
            ),
        )
        for row in ordered[:MAX_FIRST_SEEN]
    ], status


def _history(inputs: AnomalyInputs, first_hour: datetime) -> FirstSeenStatus:
    enough = inputs.oldest is not None and inputs.oldest <= first_hour - timedelta(
        days=REQUIRED_HISTORY_DAYS
    )
    return FirstSeenStatus(
        state="sufficient" if enough else "insufficient",
        required_days=REQUIRED_HISTORY_DAYS,
        oldest=inputs.oldest,
    )


def _anomaly(found: alg.RawAnomaly, policy: TrafficPolicy) -> Anomaly:
    return Anomaly(
        kind="volume-deviation",
        subject=AnomalySubject(kind=found.kind, label=found.label),
        bucket_start=found.bucket_start,
        bucket_end=found.bucket_start + HOUR,
        direction=found.direction,
        observed=found.observed,
        baseline=found.baseline,
        baseline_samples=found.samples,
        difference=found.difference,
        ratio=found.ratio,
        score=found.score,
        confidence=found.confidence,
        context=_context(policy, found.bucket_start, above=found.direction == "above"),
    )


def _evaluation(
    outcome: alg.EvaluationOutcome,
    inputs: AnomalyInputs,
    policy: TrafficPolicy,
    first_hour: datetime,
    last_hour: datetime,
) -> Evaluation:
    return Evaluation(
        status=evaluation_status(outcome.evaluated, outcome.insufficient),  # type: ignore[arg-type]
        series=outcome.series,
        buckets=outcome.buckets,
        evaluated=outcome.evaluated,
        insufficient_baseline=outcome.insufficient,
        no_data=outcome.no_data,
        anomalies_total=len(outcome.anomalies),
        application_series="evaluated" if inputs.applications_reported else "not-reported",
        daylight_saving=_daylight_saving(policy, first_hour, last_hour),
    )


def build_anomalies(
    inputs: AnomalyInputs,
    policy: TrafficPolicy,
    *,
    time_range: TrafficTimeRange,
    first_hour: datetime,
    last_hour: datetime,
    minimum: int | None = None,
) -> TrafficAnomaliesResponse:
    """The ``ok`` response for one set of baseline inputs.

    ``minimum`` is the cohort minimum for the aggregate tier (``None``: the detail tier).
    """
    series = [alg.SeriesData("total", None, inputs.hourly_total)] + [
        alg.SeriesData("application", name, hours) for name, hours in inputs.hourly_apps.items()
    ]
    outcome = alg.evaluate_series(
        series,
        frozenset(inputs.hourly_total),
        int(first_hour.timestamp()),
        int(last_hour.timestamp()),
    )
    history = _history(inputs, first_hour)
    first_seen, cohort_status = (
        _first_seen_rows(inputs.first_seen, policy, minimum)
        if history.state == "sufficient"
        else ([], cohort.first_seen_view((), minimum)[1])
    )
    return TrafficAnomaliesResponse(
        state="ok",
        time_range=time_range,
        evaluated_range=TrafficTimeRange.model_validate(
            {"from": first_hour, "to": last_hour, "preset": None}
        ),
        method=METHOD,
        working_hours=WorkingHours(state=policy.working_hours_state, timezone=policy.timezone_name),
        evaluation=_evaluation(outcome, inputs, policy, first_hour, last_hour),
        first_seen_status=history,
        anomalies=[_anomaly(found, policy) for found in outcome.anomalies[:MAX_ANOMALIES]],
        first_seen=first_seen,
        cohort=cohort_status,
        freshness=freshness_for(last_hour, inputs.observed_at),
    )


def static_fields(time_range: TrafficTimeRange, policy: TrafficPolicy) -> dict[str, Any]:
    """The fields of a ``not-connected`` or ``unknown`` response: no values, nothing the source said.

    Bound once per request (``functools.partial``) onto ``responses.static_response``, which adds the
    state, the freshness and the (not applied) cohort rule.
    """
    return {
        "time_range": time_range,
        "evaluated_range": None,
        "method": METHOD,
        "working_hours": WorkingHours(
            state=policy.working_hours_state, timezone=policy.timezone_name
        ),
        "evaluation": Evaluation(
            status="no-data",
            series=0,
            buckets=0,
            evaluated=0,
            insufficient_baseline=0,
            no_data=0,
            anomalies_total=0,
            application_series="not-reported",
            daylight_saving="not-applicable",
        ),
        "first_seen_status": FirstSeenStatus(
            state="unknown", required_days=REQUIRED_HISTORY_DAYS, oldest=None
        ),
        "anomalies": [],
        "first_seen": [],
    }
