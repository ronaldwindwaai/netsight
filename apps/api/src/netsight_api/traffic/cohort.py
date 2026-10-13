"""The small-cohort rule for the aggregate tier (security reviews, HIGH-2 and the re-reviews).

An aggregate answer that is really about one machine is that machine's traffic: "application =
BitTorrent" over a window that only one host used says what that host did, without naming it. The
aggregate tier (``traffic:read`` without ``traffic:read-detail``) is therefore held to a minimum
cohort of ``k`` distinct **internal endpoints** (the inside-the-organisation side of each flow, by
direction, under the classifier in ``traffic.addresses``; never every source address, which one host
talking to many remote servers would inflate):

* an Explorer answer whose filtered window covers fewer than ``k`` internal endpoints is **withheld
  whole** (volume, timeline, mix, destinations), not thinned: the byte count of a one-host answer *is*
  that host's usage, and two overlapping filters could otherwise be subtracted to isolate it;
* a row that fewer than ``k`` stood behind (application, destination, an Explorer mix item or
  destination share) keeps its name and loses everything that describes it: bytes, packets, share, the
  earlier bytes of its trend, endpoint count, first and last seen, domain, ASN and country. It says
  ``withheld`` and is listed after the shown rows, so neither its figures nor its position tell what
  it carried; ranks run 1..n again. The bytes of a withheld Explorer mix item are merged into "other";
* a source that does not say how many endpoints stood behind something is treated as too few;
* an hourly series that fewer than ``k`` endpoints contributed to is not evaluated or reported, and the
  totals count only the series that pass;
* a first-seen ASN or destination that fewer than ``k`` sources reached is not listed;
* a destination inside the organisation is not listed at all.

Every response says whether the rule was applied (``cohort``) so the UI can explain an emptier
answer. The detail tier is not subject to the rule. ``k`` is ``NETSIGHT_TRAFFIC_MIN_COHORT`` (default
5, at least 2); a value that is missing is the default and one that is invalid is the default too
(and logged once), never a weaker rule.

The rule limits what one answer discloses. It does not stop a determined caller from differencing two
answers that are each above the minimum, which is why every read is rate limited and audited (see
docs/02-security/THREAT-MODEL.md, "Residual query-difference risk").
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Callable, Sequence
from typing import Final, Protocol

from netsight_api.schemas_traffic import (
    MAX_COHORT,
    MIN_COHORT_FLOOR,
    ApplicationMix,
    ApplicationMixItem,
    ApplicationRow,
    AppTrend,
    CohortStatus,
    DestinationRow,
    DestinationShare,
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


class _HasEndpoints(Protocol):
    @property
    def endpoints(self) -> int | None: ...


def _below(endpoints: int | None, minimum: int) -> bool:
    """Too few: a count under the minimum, or no count at all (the source did not say)."""
    return endpoints is None or endpoints < minimum


def _withhold[R: _HasEndpoints](
    rows: Sequence[R],
    minimum: int,
    withheld_form: Callable[[R], R],
    name: Callable[[R], str],
) -> tuple[list[R], bool]:
    """Shown rows first (in their order), then the withheld ones by name; whether any were."""
    shown = [row for row in rows if not _below(row.endpoints, minimum)]
    hidden = [row for row in rows if _below(row.endpoints, minimum)]
    hidden.sort(key=lambda row: name(row).casefold())
    return [*shown, *(withheld_form(row) for row in hidden)], bool(hidden)


# --- the Explorer ------------------------------------------------------------------------------------


def _withheld_share(share: DestinationShare) -> DestinationShare:
    return share.model_copy(
        update={
            "visibility": "withheld",
            "bytes": None,
            "share": None,
            "endpoints": None,
            "host": None,
        }
    )


def _withheld_mix_item(item: ApplicationMixItem) -> ApplicationMixItem:
    return item.model_copy(
        update={"visibility": "withheld", "bytes": None, "share": None, "endpoints": None}
    )


def _mix_view(mix: ApplicationMix | None, minimum: int) -> tuple[ApplicationMix | None, bool]:
    """The application mix with small items withheld; their bytes are merged into "other"."""
    if mix is None:
        return None, False
    items, withheld = _withhold(
        mix.items, minimum, _withheld_mix_item, lambda item: item.application or ""
    )
    shown = sum(item.bytes or 0 for item in items)
    return mix.model_copy(update={"items": items, "other_bytes": mix.total_bytes - shown}), withheld


def explorer_view(
    aggregations: FlowAggregations | None, minimum: int | None
) -> tuple[FlowAggregations | None, CohortStatus]:
    """The aggregations the caller may see, and how the cohort rule treated them."""
    if minimum is None:
        return aggregations, cohort_not_applied()
    if aggregations is None or _below(aggregations.volume.internal_endpoints, minimum):
        return None, _status("too-few-sources", minimum)
    external = [share for share in aggregations.destinations if share.scope == "external"]
    shares, shares_withheld = _withhold(
        external, minimum, _withheld_share, lambda share: share.address
    )
    mix, mix_withheld = _mix_view(aggregations.application_mix, minimum)
    state = "too-few-sources" if shares_withheld or mix_withheld else "sufficient"
    view = aggregations.model_copy(update={"destinations": shares, "application_mix": mix})
    return view, _status(state, minimum)


# --- Applications and Destinations -------------------------------------------------------------------


def _withheld_application(row: ApplicationRow) -> ApplicationRow:
    return row.model_copy(
        update={
            "visibility": "withheld",
            "bytes": None,
            "packets": None,
            "share": None,
            "endpoints": None,
            "users": None,
            "trend": AppTrend(state="unknown", previous_bytes=None, change_ratio=None),
        }
    )


def _withheld_destination(row: DestinationRow) -> DestinationRow:
    return row.model_copy(
        update={
            "visibility": "withheld",
            "bytes": None,
            "packets": None,
            "share": None,
            "endpoints": None,
            "users": None,
            "domain": None,
            "asn": None,
            "country": None,
            "first_seen": None,
            "last_seen": None,
        }
    )


def _renumbered[R: (ApplicationRow, DestinationRow)](rows: Sequence[R]) -> list[R]:
    return [row.model_copy(update={"rank": rank}) for rank, row in enumerate(rows, start=1)]


def external_destinations(rows: Sequence[DestinationRow]) -> list[DestinationRow]:
    """Only the destinations outside the organisation, ranked 1..n again."""
    return _renumbered([row for row in rows if row.scope == "external"])


def withhold_small_applications(
    rows: Sequence[ApplicationRow], minimum: int | None
) -> tuple[list[ApplicationRow], CohortStatus]:
    """Applications behind fewer than ``minimum`` endpoints are withheld whole and listed last."""
    if minimum is None:
        return list(rows), cohort_not_applied()
    kept, withheld = _withhold(rows, minimum, _withheld_application, lambda row: row.application)
    return _renumbered(kept), _status("too-few-sources" if withheld else "sufficient", minimum)


def withhold_small_destinations(
    rows: Sequence[DestinationRow], minimum: int | None
) -> tuple[list[DestinationRow], CohortStatus]:
    """Destinations behind fewer than ``minimum`` endpoints are withheld whole and listed last."""
    if minimum is None:
        return list(rows), cohort_not_applied()
    kept, withheld = _withhold(rows, minimum, _withheld_destination, lambda row: row.address)
    return _renumbered(kept), _status("too-few-sources" if withheld else "sufficient", minimum)


# --- Anomalies ---------------------------------------------------------------------------------------


def first_seen_view(
    rows: tuple[FirstSeenRow, ...], minimum: int | None
) -> tuple[tuple[FirstSeenRow, ...], CohortStatus]:
    """Drop first-seen rows few sources reached; a row with no count is dropped too (fail closed)."""
    if minimum is None:
        return rows, cohort_not_applied()
    shown = tuple(row for row in rows if not _below(row.endpoints, minimum))
    state = "sufficient" if len(shown) == len(rows) else "too-few-sources"
    return shown, _status(state, minimum)


def series_passes(sources: int | None, minimum: int | None) -> bool:
    """Whether an hourly series may be evaluated and reported: the detail tier always, else k+."""
    return minimum is None or not _below(sources, minimum)


def anomalies_status(
    first_seen_status: CohortStatus, series_withheld: int, minimum: int | None
) -> CohortStatus:
    """One verdict for the anomalies response: too few if a first-seen row or a series was withheld."""
    if minimum is None:
        return first_seen_status
    withheld = first_seen_status.state == "too-few-sources" or series_withheld > 0
    return _status("too-few-sources" if withheld else "sufficient", minimum)
