"""The small-cohort rule for the aggregate tier (security review HIGH-2).

An aggregate answer that is really about one machine is that machine's traffic: "application =
BitTorrent" over a window that only one host used says what that host did, without naming it. The
aggregate tier (``traffic:read`` without ``traffic:read-detail``) is therefore held to a minimum
cohort of ``k`` distinct source addresses:

* an Explorer answer whose filtered window covers fewer than ``k`` source addresses is **withheld
  whole** (volume, timeline, mix, destinations), not thinned: the byte count of a one-host answer *is*
  that host's usage, and two overlapping filters could otherwise be subtracted to isolate it;
* an endpoint count below ``k`` on an application or destination row is withheld (``null``);
* a first-seen ASN or destination that fewer than ``k`` sources reached is not listed;
* a destination inside the organisation is not listed at all.

Every response says whether the rule was applied (``cohort``) so the UI can explain an emptier
answer. The detail tier is not subject to the rule. ``k`` is ``NETSIGHT_TRAFFIC_MIN_COHORT`` (default
5, at least 2); a value that is missing is the default and one that is invalid is the default too
(and logged once), never a weaker rule.

The rule limits what one answer discloses. It does not stop a determined caller from differencing two
answers that are each above the minimum, which is why every read is rate limited and audited.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Sequence
from typing import Final

from netsight_api.schemas_traffic import (
    MAX_COHORT,
    MIN_COHORT_FLOOR,
    ApplicationRow,
    CohortStatus,
    DestinationRow,
    FlowAggregations,
    cohort_not_applied,
)
from netsight_api.traffic.source import FirstSeenRow

_LOGGER = logging.getLogger("netsight_api")

MIN_COHORT_ENV: Final = "NETSIGHT_TRAFFIC_MIN_COHORT"
DEFAULT_MIN_COHORT: Final = 5
_DIGITS = re.compile(r"[0-9]{1,5}")
_warned: set[str] = set()


def min_cohort() -> int:
    """The configured minimum cohort; the default when unset, and when invalid (logged once)."""
    raw = os.environ.get(MIN_COHORT_ENV, "").strip()
    if not raw:
        return DEFAULT_MIN_COHORT
    if _DIGITS.fullmatch(raw) and MIN_COHORT_FLOOR <= int(raw) <= MAX_COHORT:
        return int(raw)
    if raw not in _warned:
        _warned.add(raw)
        _LOGGER.warning(
            "%s must be a whole number from %d to %d; using the default of %d",
            MIN_COHORT_ENV,
            MIN_COHORT_FLOOR,
            MAX_COHORT,
            DEFAULT_MIN_COHORT,
        )
    return DEFAULT_MIN_COHORT


def _status(state: str, minimum: int) -> CohortStatus:
    return CohortStatus(state=state, minimum=minimum)  # type: ignore[arg-type]


def explorer_view(
    aggregations: FlowAggregations | None, minimum: int | None
) -> tuple[FlowAggregations | None, CohortStatus]:
    """The aggregations the caller may see, and how the cohort rule treated them."""
    if minimum is None:
        return aggregations, cohort_not_applied()
    if aggregations is None or aggregations.volume.source_addresses < minimum:
        return None, _status("too-few-sources", minimum)
    external = [share for share in aggregations.destinations if share.scope == "external"]
    return aggregations.model_copy(update={"destinations": external}), _status(
        "sufficient", minimum
    )


def external_destinations(rows: Sequence[DestinationRow]) -> list[DestinationRow]:
    """Only the destinations outside the organisation, ranked 1..n again."""
    kept = [row for row in rows if row.scope == "external"]
    return [row.model_copy(update={"rank": rank}) for rank, row in enumerate(kept, start=1)]


def withhold_small_counts[R: (ApplicationRow, DestinationRow)](
    rows: Sequence[R], minimum: int | None
) -> tuple[list[R], CohortStatus]:
    """Rows with an endpoint count below the minimum lose the count (it becomes ``null``)."""
    if minimum is None:
        return list(rows), cohort_not_applied()
    shown: list[R] = []
    withheld = False
    for row in rows:
        if row.endpoints is not None and row.endpoints < minimum:
            withheld = True
            shown.append(row.model_copy(update={"endpoints": None}))
        else:
            shown.append(row)
    return shown, _status("too-few-sources" if withheld else "sufficient", minimum)


def first_seen_view(
    rows: tuple[FirstSeenRow, ...], minimum: int | None
) -> tuple[tuple[FirstSeenRow, ...], CohortStatus]:
    """Drop first-seen rows few sources reached; a row with no count is dropped too (fail closed)."""
    if minimum is None:
        return rows, cohort_not_applied()
    shown = tuple(row for row in rows if row.endpoints is not None and row.endpoints >= minimum)
    state = "sufficient" if len(shown) == len(rows) else "too-few-sources"
    return shown, _status(state, minimum)
