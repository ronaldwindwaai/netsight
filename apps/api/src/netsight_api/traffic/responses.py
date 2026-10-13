"""Shared pieces of the traffic responses: source freshness and the static states."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel

from netsight_api.contracts import validate
from netsight_api.schemas import Freshness
from netsight_api.schemas_traffic import cohort_not_applied

FRESH_THRESHOLD = timedelta(hours=1)
SOURCE_NAME = "clickhouse"


def freshness_for(window_end: datetime, observed_at: datetime | None) -> Freshness:
    """Source-reported recency for an ``ok`` read.

    ``fresh`` when the newest flow is within an hour of the window end, ``stale`` when the source
    lags the window, ``unknown`` when no row carried a timestamp (the read succeeded but reports no
    currency).
    """
    if observed_at is None:
        return Freshness(state="unknown", observed_at=None, source=SOURCE_NAME)
    return Freshness(
        state="fresh" if observed_at >= window_end - FRESH_THRESHOLD else "stale",
        observed_at=observed_at,
        source=SOURCE_NAME,
    )


def freshness_for_tier(
    window_end: datetime,
    observed_at: datetime | None,
    source_observed_at: datetime | None,
    *,
    aggregate: bool,
) -> Freshness:
    """Freshness the caller's tier may be told.

    The newest flow behind a *filtered* answer can be one machine's last activity, so the aggregate
    tier is told the source's own newest flow in the window (not tied to any filter or cohort) and
    never falls back to the filtered time: a source that reports none yields ``unknown``. The detail
    tier keeps the time of the answer it asked for.
    """
    return freshness_for(window_end, source_observed_at if aggregate else observed_at)


def no_freshness(*, connected: bool) -> Freshness:
    """Freshness for a state that carries no values (nothing was read, or the read failed)."""
    return Freshness(state="unknown", observed_at=None, source=SOURCE_NAME if connected else None)


def checked[M: BaseModel](name: str, body: M) -> M:
    """The canonical contract at the boundary, on every return path."""
    validate(name, body.model_dump(mode="json", by_alias=True))
    return body


def static_response[M: BaseModel](
    name: str,
    model: type[M],
    state: Literal["not-connected", "unknown"],
    *,
    connected: bool,
    **fields: Any,
) -> M:
    """A ``not-connected`` or ``unknown`` response: no values, no freshness, no cohort rule applied.

    The one place the static states of all four traffic responses are built. The route binds what is
    specific to it (the window, the filters, the policy status) with ``functools.partial`` and passes
    only the state and whether a source is configured; the result is checked against its schema.
    """
    body = model(
        state=state,
        freshness=no_freshness(connected=connected),
        cohort=cohort_not_applied(),
        **fields,
    )
    return checked(name, body)
