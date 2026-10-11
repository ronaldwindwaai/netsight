"""Typed boundary models for the traffic intelligence surface (Step 7).

Mirrors ``contracts/json-schema/traffic-flows.schema.json``, ``traffic-applications.schema.json``,
``traffic-destinations.schema.json`` and ``traffic-anomalies.schema.json``, the OpenAPI components of
the same names and the browser parser (``api-contracts-traffic-explorer.ts``). The shared vectors in
``contracts/test-vectors/traffic.vectors.json`` drive all four verdicts.

Honesty rules, enforced here and not only by construction:

* every figure is source-reported or ``None``; a state that is not ``ok`` carries no rows and no
  totals; a filter the flow source cannot honour makes the read ``unknown`` (never silently
  unfiltered);
* a person is named only through the identity service and only with its basis. ``unknown`` carries
  no person; ``inferred`` is capped at 0.7; an ambiguous answer picks nobody. A row's attribution
  must agree with the response-level attribution status (a role that may not see people sees none);
* the aggregate tier (``traffic:read`` without ``traffic:read-detail``) is protected against small
  cohorts: when the figures would describe fewer than ``cohort.minimum`` source addresses they are
  withheld and ``cohort.state`` says ``too-few-sources`` (never a silently emptier answer), and a
  destination inside the organisation is not listed to that tier;
* an anomaly is a documented comparison, not a verdict: it carries its baseline, the observed value,
  the difference and a confidence, and nothing below the stated threshold, minimum difference or
  minimum number of comparable weeks is ever reported. Outside working hours is context only.

Every name, label, domain and application is untrusted source text: it is carried as data and never
interpreted.
"""

from __future__ import annotations

import math
from datetime import timedelta
from typing import Annotated, Literal

from pydantic import AwareDatetime, ConfigDict, Field, model_validator

from netsight_api.schemas import ApiModel, Freshness, TrafficState, TrafficTimeRange


class TrafficModel(ApiModel):
    """Strict boundary model: no coercion ("yes" is not a boolean, "5" is not an integer)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)


INFERRED_CEILING = 0.7
TREND_FLAT_BAND = 0.1
_UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_DEVICE_ID_PATTERN = f"^device-{_UUID}$"
_PERSON_ID_PATTERN = f"^person-{_UUID}$"
_RATIO_TOLERANCE = 1e-6

FilterName = Literal[
    "source_ip",
    "destination_ip",
    "device",
    "vlan",
    "application",
    "protocol",
    "port",
    "country",
    "asn",
    "direction",
]
FlowProtocol = Literal["tcp", "udp", "icmp", "other"]
FlowDirection = Literal["inbound", "outbound", "internal", "unknown"]
IdentityBasis = Literal["observed", "inferred", "unknown"]
IdentityReason = Literal[
    "declared-assignment",
    "indirect-evidence",
    "low-confidence",
    "name-match",
    "conflicting-evidence",
    "no-evidence",
    "expired",
    "multiple-candidates",
    "shared-address",
    "vpn-no-session",
    "guest-network",
    "ip-only",
    "source-unavailable",
    "restricted",
]
_INFERRED_REASONS = frozenset(
    {
        "declared-assignment",
        "indirect-evidence",
        "low-confidence",
        "name-match",
        "conflicting-evidence",
    }
)
_UNKNOWN_REASONS = frozenset(
    {
        "no-evidence",
        "expired",
        "conflicting-evidence",
        "multiple-candidates",
        "shared-address",
        "vpn-no-session",
        "guest-network",
        "ip-only",
        "source-unavailable",
        "restricted",
    }
)
AttributionLevel = Literal["person", "endpoint", "none"]
AttributionState = Literal["ok", "not-connected", "unknown", "withheld", "not-evaluated"]
CohortState = Literal["not-applied", "sufficient", "too-few-sources"]
DestinationScope = Literal["external", "internal"]
DaylightSaving = Literal["not-applicable", "none", "crossed"]
MIN_COHORT_FLOOR = 2
MAX_COHORT = 1000
PolicyState = Literal["not-configured", "configured", "invalid"]
LegitimatePattern = Literal[
    "backup",
    "cloud-sync",
    "cctv-or-nvr",
    "patching-or-updates",
    "replication",
    "scheduled-maintenance",
    "antivirus-update",
    "authorised-remote-work",
]

Share = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
Count = Annotated[int, Field(ge=0)]
Label = Annotated[str, Field(min_length=1, max_length=128)]


def _unique(values: list[str], what: str) -> None:
    if len(set(values)) != len(values):
        raise ValueError(f"{what} must be unique")


def _sequential(ranks: list[int], what: str) -> None:
    if ranks != list(range(1, len(ranks) + 1)):
        raise ValueError(f"{what} ranks run 1..n in order")


class CohortStatus(TrafficModel):
    """The small-cohort rule as applied to this answer.

    ``not-applied``: the caller holds the detail tier (or nothing was read), so no rule was applied.
    ``sufficient``: the aggregate tier, and the figures describe at least ``minimum`` source addresses.
    ``too-few-sources``: the aggregate tier, and something was withheld because fewer than ``minimum``
    source addresses stood behind it (an Explorer answer, an endpoint count, a first-seen destination).
    """

    state: CohortState
    minimum: int | None = Field(..., ge=MIN_COHORT_FLOOR, le=MAX_COHORT)

    @model_validator(mode="after")
    def _consistent(self) -> CohortStatus:
        if (self.state == "not-applied") != (self.minimum is None):
            raise ValueError("only an applied cohort rule states its minimum")
        return self


def cohort_not_applied() -> CohortStatus:
    return CohortStatus(state="not-applied", minimum=None)


# --- Flow Explorer -------------------------------------------------------------------------------


class FlowFilters(TrafficModel):
    """The filters that were applied (allow-listed fields only), echoed from the request."""

    source_ip: str | None = Field(..., min_length=2, max_length=45)
    destination_ip: str | None = Field(..., min_length=2, max_length=45)
    device: str | None = Field(..., min_length=1, max_length=128)
    vlan: int | None = Field(..., ge=0, le=4094)
    application: str | None = Field(..., min_length=1, max_length=128)
    protocol: FlowProtocol | None = Field(...)
    port: int | None = Field(..., ge=0, le=65535)
    country: str | None = Field(..., min_length=2, max_length=2, pattern=r"^[A-Z]{2}$")
    asn: int | None = Field(..., ge=1, le=4294967295)
    direction: Literal["inbound", "outbound", "internal"] | None = Field(...)


class PersonRef(TrafficModel):
    id: str = Field(min_length=1, max_length=128, pattern=_PERSON_ID_PATTERN)
    label: Label | None


class DeviceRef(TrafficModel):
    id: str = Field(min_length=1, max_length=128, pattern=_DEVICE_ID_PATTERN)
    label: Label | None


class AttributionStatus(TrafficModel):
    """What the caller may be told about the person behind an address, and whether it was answered."""

    level: AttributionLevel
    state: AttributionState
    as_of: AwareDatetime | None

    @model_validator(mode="after")
    def _consistent(self) -> AttributionStatus:
        if self.level == "none" and self.state not in ("withheld", "not-evaluated"):
            raise ValueError("a role that sees no attribution has nothing answered")
        if self.state == "withheld" and self.level != "none":
            raise ValueError("withheld means the level is none")
        if (self.state == "ok") != (self.as_of is not None):
            raise ValueError("only an answered attribution has a time")
        return self


class FlowAttribution(TrafficModel):
    """Who was behind the source address, with its basis. An address alone is never identity."""

    basis: IdentityBasis
    reason: IdentityReason | None
    confidence: float | None = Field(..., ge=0, le=1, allow_inf_nan=False)
    ambiguous: bool
    person: PersonRef | None
    device: DeviceRef | None

    @model_validator(mode="after")
    def _honest(self) -> FlowAttribution:
        if self.basis == "unknown":
            if self.person is not None or self.confidence is not None:
                raise ValueError("an unknown attribution names nobody and has no confidence")
            if self.reason not in _UNKNOWN_REASONS:
                raise ValueError("an unknown attribution carries an unknown-class reason")
            return self
        if self.person is None or self.confidence is None or self.ambiguous:
            raise ValueError(f"a {self.basis} attribution names one person with a confidence")
        if self.basis == "observed" and self.reason is not None:
            raise ValueError("an observed attribution carries no reason")
        if self.basis == "inferred":
            if self.reason not in _INFERRED_REASONS:
                raise ValueError("an inferred attribution carries an inferred reason")
            if self.confidence > INFERRED_CEILING:
                raise ValueError("an inferred attribution is capped at 0.7")
        return self


class TrafficFlow(TrafficModel):
    """One high-volume flow row; every enrichment field is source-reported."""

    observed_at: AwareDatetime
    source_ip: str = Field(min_length=1, max_length=45)
    source_device_id: str | None = Field(..., pattern=_DEVICE_ID_PATTERN, max_length=43)
    destination_ip: str = Field(min_length=1, max_length=45)
    destination_host: str | None = Field(..., min_length=1, max_length=255)
    protocol: FlowProtocol
    destination_port: int | None = Field(..., ge=0, le=65535)
    bytes: int = Field(ge=0)
    packets: int | None = Field(..., ge=0)
    direction: FlowDirection
    application: str | None = Field(..., min_length=1, max_length=255)
    attribution: FlowAttribution | None


class TimelineBucket(TrafficModel):
    start: AwareDatetime
    bytes: Count
    packets: Count | None
    flows: Count


class Volume(TrafficModel):
    bytes: Count
    packets: Count | None
    flows: Count
    source_addresses: Count
    destination_addresses: Count


class ApplicationMixItem(TrafficModel):
    application: str | None = Field(..., min_length=1, max_length=255)
    bytes: Count
    share: Share | None


class ApplicationMix(TrafficModel):
    items: list[ApplicationMixItem] = Field(max_length=11)
    other_bytes: Count
    total_bytes: Count

    @model_validator(mode="after")
    def _adds_up(self) -> ApplicationMix:
        if sum(item.bytes for item in self.items) + self.other_bytes != self.total_bytes:
            raise ValueError("the application mix adds up to its total")
        return self


class DestinationShare(TrafficModel):
    address: str = Field(min_length=1, max_length=45)
    host: str | None = Field(..., min_length=1, max_length=255)
    scope: DestinationScope
    bytes: Count
    share: Share | None


class FlowAggregations(TrafficModel):
    """Bounded aggregations over the whole filtered window (not over the listed rows)."""

    bucket_seconds: int = Field(ge=60, le=86400)
    timeline: list[TimelineBucket] = Field(max_length=200)
    volume: Volume
    application_mix: ApplicationMix | None
    destinations: list[DestinationShare] = Field(max_length=10)


class TrafficFlowsResponse(TrafficModel):
    state: TrafficState
    time_range: TrafficTimeRange
    filters: FlowFilters
    unsupported: list[FilterName] = Field(max_length=10)
    flows_restricted: bool
    attribution: AttributionStatus
    flows: list[TrafficFlow] = Field(max_length=500)
    aggregations: FlowAggregations | None
    cohort: CohortStatus
    freshness: Freshness

    @model_validator(mode="after")
    def _honest(self) -> TrafficFlowsResponse:
        if self.state != "ok" and (self.flows or self.aggregations is not None):
            raise ValueError("non-ok traffic state must not carry flows or aggregations")
        if self.flows_restricted and (self.flows or self.attribution.level != "none"):
            raise ValueError("restricted flows carry no rows and no attribution")
        self._cohort_rule()
        _unique(list(self.unsupported), "unsupported")
        if self.unsupported and self.state != "unknown":
            raise ValueError("an unsupported filter makes the read unknown, never unfiltered")
        self._attribution_matches_rows()
        return self

    def _cohort_rule(self) -> None:
        """The aggregate tier (restricted rows) is held to the cohort rule; the detail tier is not."""
        applied = self.cohort.state != "not-applied"
        if self.state != "ok":
            if applied:
                raise ValueError("a read that returned nothing applied no cohort rule")
            return
        if applied != self.flows_restricted:
            raise ValueError("exactly the aggregate tier is held to the cohort rule")
        if self.cohort.state == "too-few-sources" and self.aggregations is not None:
            raise ValueError("too few sources: the aggregates are withheld, not thinned")
        internal = self.aggregations is not None and any(
            share.scope == "internal" for share in self.aggregations.destinations
        )
        if self.flows_restricted and internal:
            raise ValueError("the aggregate tier is not told about internal destinations")

    def _attribution_matches_rows(self) -> None:
        rows = [flow.attribution for flow in self.flows]
        status = self.attribution
        if status.state != "ok":
            if any(row is not None for row in rows):
                raise ValueError("rows are attributed only when the identity service answered")
            return
        if self.flows and any(row is None for row in rows):
            raise ValueError("an answered attribution covers every row")
        if status.level == "endpoint" and any(row and row.person for row in rows):
            raise ValueError("the endpoint level never names a person")


def _endpoint_counts_follow_cohort(
    state: str, cohort: CohortStatus, counts: list[int | None]
) -> None:
    """Under the cohort rule no listed endpoint count is below the minimum; a withheld one is null."""
    if state != "ok":
        if cohort.state != "not-applied":
            raise ValueError("a read that returned nothing applied no cohort rule")
        return
    minimum = cohort.minimum
    below = minimum is not None and any(count is not None and count < minimum for count in counts)
    if cohort.state == "sufficient" and below:
        raise ValueError("a count below the cohort minimum is withheld, not listed")
    if cohort.state == "too-few-sources" and all(count is not None for count in counts):
        raise ValueError("too few sources: at least one endpoint count is withheld")


# --- Applications ---------------------------------------------------------------------------------


class PolicyStatus(TrafficModel):
    """Whether an operator policy file classified approval, risk and reputation."""

    state: PolicyState


class AppTrend(TrafficModel):
    """Change against the immediately preceding window of equal length; flat is within 10 percent."""

    state: Literal["up", "down", "flat", "new", "unknown"]
    previous_bytes: Count | None
    change_ratio: float | None = Field(..., ge=-1, allow_inf_nan=False)

    @model_validator(mode="after")
    def _consistent(self) -> AppTrend:
        if self.state == "unknown":
            if self.previous_bytes is not None or self.change_ratio is not None:
                raise ValueError("an unknown trend carries no figures")
        elif self.state == "new":
            if self.previous_bytes != 0 or self.change_ratio is not None:
                raise ValueError("a new application had no earlier traffic and has no ratio")
        else:
            if not self.previous_bytes or self.change_ratio is None:
                raise ValueError("a trend needs earlier traffic and a ratio")
            ratio = self.change_ratio
            if self.state == "up" and not ratio > TREND_FLAT_BAND:
                raise ValueError("up means more than 10 percent above the earlier window")
            if self.state == "down" and not ratio < -TREND_FLAT_BAND:
                raise ValueError("down means more than 10 percent below the earlier window")
            if self.state == "flat" and abs(ratio) > TREND_FLAT_BAND:
                raise ValueError("flat means within 10 percent of the earlier window")
        return self


class ApplicationRow(TrafficModel):
    rank: int = Field(ge=1, le=100)
    application: str = Field(min_length=1, max_length=255)
    category: str | None = Field(..., min_length=1, max_length=128)
    bytes: Count
    packets: Count | None
    share: Share | None
    endpoints: Count | None
    users: Count | None
    trend: AppTrend
    risk: Literal["low", "medium", "high", "unknown"]
    approval: Literal["approved", "unapproved", "unknown"]

    @model_validator(mode="after")
    def _trend_matches_bytes(self) -> ApplicationRow:
        previous = self.trend.previous_bytes
        if (
            self.trend.state in ("up", "down", "flat")
            and previous
            and self.trend.change_ratio is not None
        ):
            expected = (self.bytes - previous) / previous
            if abs(self.trend.change_ratio - expected) > _RATIO_TOLERANCE:
                raise ValueError("the trend ratio is the change in bytes over the earlier bytes")
        return self


class TrafficApplicationsResponse(TrafficModel):
    state: TrafficState
    time_range: TrafficTimeRange
    previous_range: TrafficTimeRange | None
    policy: PolicyStatus
    unsupported: list[Literal["application"]] = Field(max_length=1)
    total_bytes: Count | None
    items: list[ApplicationRow] = Field(max_length=100)
    cohort: CohortStatus
    freshness: Freshness

    @model_validator(mode="after")
    def _honest(self) -> TrafficApplicationsResponse:
        if self.state != "ok" and (
            self.items or self.total_bytes is not None or self.previous_range is not None
        ):
            raise ValueError("non-ok traffic state must not carry values")
        _endpoint_counts_follow_cohort(self.state, self.cohort, [i.endpoints for i in self.items])
        _unique(list(self.unsupported), "unsupported")
        if self.unsupported and self.state != "unknown":
            raise ValueError("an unsupported field makes the read unknown")
        if self.state == "ok":
            if self.total_bytes is None:
                raise ValueError("an ok read states its total")
            if sum(item.bytes for item in self.items) > self.total_bytes:
                raise ValueError("the rows cannot exceed the total")
        _sequential([item.rank for item in self.items], "application")
        return self


# --- Destinations -----------------------------------------------------------------------------------


class DestinationRow(TrafficModel):
    rank: int = Field(ge=1, le=100)
    address: str = Field(min_length=1, max_length=45)
    scope: DestinationScope
    domain: str | None = Field(..., min_length=1, max_length=255)
    asn: int | None = Field(..., ge=1, le=4294967295)
    country: str | None = Field(..., min_length=2, max_length=2, pattern=r"^[A-Z]{2}$")
    first_seen: AwareDatetime | None
    last_seen: AwareDatetime
    bytes: Count
    packets: Count | None
    share: Share | None
    endpoints: Count | None
    users: Count | None
    reputation: Literal["allow-listed", "deny-listed", "unknown"]

    @model_validator(mode="after")
    def _ordered(self) -> DestinationRow:
        if self.first_seen is not None and self.first_seen > self.last_seen:
            raise ValueError("a destination is first seen before it is last seen")
        return self


class TrafficDestinationsResponse(TrafficModel):
    state: TrafficState
    time_range: TrafficTimeRange
    first_seen_since: AwareDatetime | None
    policy: PolicyStatus
    total_bytes: Count | None
    items: list[DestinationRow] = Field(max_length=100)
    cohort: CohortStatus
    freshness: Freshness

    @model_validator(mode="after")
    def _honest(self) -> TrafficDestinationsResponse:
        if self.state != "ok" and (
            self.items or self.total_bytes is not None or self.first_seen_since is not None
        ):
            raise ValueError("non-ok traffic state must not carry values")
        _endpoint_counts_follow_cohort(self.state, self.cohort, [i.endpoints for i in self.items])
        if self.cohort.state != "not-applied" and any(i.scope == "internal" for i in self.items):
            raise ValueError("the aggregate tier is not told about internal destinations")
        if self.state == "ok":
            if self.total_bytes is None:
                raise ValueError("an ok read states its total")
            if sum(item.bytes for item in self.items) > self.total_bytes:
                raise ValueError("the rows cannot exceed the total")
        _sequential([item.rank for item in self.items], "destination")
        since = self.first_seen_since
        if since is not None and any(
            i.first_seen is not None and i.first_seen < since for i in self.items
        ):
            raise ValueError("first seen is never earlier than the look-back")
        return self


# --- Anomalies ----------------------------------------------------------------------------------------


class BaselineMethod(TrafficModel):
    """The deterministic comparison; see docs/12-implementation/TRAFFIC-BASELINES.md."""

    algorithm: Literal["same-hour-of-week-median-mad"]
    weeks: int = Field(ge=1, le=8)
    min_weeks: int = Field(ge=1, le=8)
    threshold: float = Field(gt=0, allow_inf_nan=False)
    min_difference_bytes: Count

    @model_validator(mode="after")
    def _ordered(self) -> BaselineMethod:
        if self.min_weeks > self.weeks:
            raise ValueError("the minimum number of weeks cannot exceed the weeks compared")
        return self


class WorkingHours(TrafficModel):
    state: PolicyState
    timezone: str | None = Field(..., min_length=1, max_length=64)

    @model_validator(mode="after")
    def _consistent(self) -> WorkingHours:
        if (self.state == "configured") != (self.timezone is not None):
            raise ValueError("only configured working hours name a time zone")
        return self


class Evaluation(TrafficModel):
    """How much of the window could be judged against a baseline."""

    status: Literal["evaluated", "partial", "insufficient-baseline", "no-data"]
    series: Count
    buckets: Count
    evaluated: Count
    insufficient_baseline: Count
    no_data: Count
    anomalies_total: Count
    application_series: Literal["evaluated", "not-reported"]
    daylight_saving: DaylightSaving

    @model_validator(mode="after")
    def _consistent(self) -> Evaluation:
        if self.evaluated + self.insufficient_baseline + self.no_data != self.buckets:
            raise ValueError("every bucket is evaluated, insufficient or without data")
        if self.evaluated == 0 and self.anomalies_total != 0:
            raise ValueError("nothing is flagged without a baseline")
        if self.evaluated == 0 and self.insufficient_baseline == 0:
            expected = "no-data"
        elif self.evaluated == 0:
            expected = "insufficient-baseline"
        elif self.insufficient_baseline == 0:
            expected = "evaluated"
        else:
            expected = "partial"
        if self.status != expected:
            raise ValueError(f"the status of these counts is {expected}")
        return self


class FirstSeenStatus(TrafficModel):
    """First-seen flags need history before the window; without it everything would look new."""

    state: Literal["sufficient", "insufficient", "unknown"]
    required_days: int = Field(ge=1, le=31)
    oldest: AwareDatetime | None

    @model_validator(mode="after")
    def _consistent(self) -> FirstSeenStatus:
        if self.state == "unknown" and self.oldest is not None:
            raise ValueError("unknown history has no oldest record")
        return self


class AnomalyContext(TrafficModel):
    """Context, not a verdict: outside working hours is not malicious."""

    outside_working_hours: bool | None
    common_legitimate_patterns: list[LegitimatePattern] = Field(max_length=8)

    @model_validator(mode="after")
    def _unique(self) -> AnomalyContext:
        _unique(list(self.common_legitimate_patterns), "patterns")
        return self


class AnomalySubject(TrafficModel):
    kind: Literal["total", "application"]
    label: str | None = Field(..., min_length=1, max_length=255)

    @model_validator(mode="after")
    def _consistent(self) -> AnomalySubject:
        if (self.kind == "application") != (self.label is not None):
            raise ValueError("only an application subject has a label")
        return self


class Anomaly(TrafficModel):
    kind: Literal["volume-deviation"]
    subject: AnomalySubject
    bucket_start: AwareDatetime
    bucket_end: AwareDatetime
    direction: Literal["above", "below"]
    observed: Count
    baseline: Count
    baseline_samples: int = Field(ge=1, le=8)
    difference: int
    ratio: float | None = Field(..., ge=0, allow_inf_nan=False)
    score: float = Field(allow_inf_nan=False)
    confidence: Literal["low", "medium", "high"]
    context: AnomalyContext

    @model_validator(mode="after")
    def _arithmetic(self) -> Anomaly:
        start = self.bucket_start
        if start.minute or start.second or start.microsecond:
            raise ValueError("a bucket starts on the hour")
        if self.bucket_end - start != timedelta(hours=1):
            raise ValueError("a bucket is one hour")
        if self.difference != self.observed - self.baseline:
            raise ValueError("the difference is the observed value minus the baseline")
        if (self.direction == "above") != (self.difference > 0) or self.difference == 0:
            raise ValueError("the direction follows the sign of the difference")
        if (self.ratio is None) != (self.baseline == 0):
            raise ValueError("the ratio exists exactly when the baseline is not zero")
        if self.ratio is not None:
            expected = self.observed / self.baseline
            if not math.isclose(self.ratio, expected, rel_tol=_RATIO_TOLERANCE, abs_tol=1e-9):
                raise ValueError("the ratio is observed over baseline")
        return self


class FirstSeen(TrafficModel):
    kind: Literal["first-seen-asn", "first-seen-destination"]
    asn: int | None = Field(..., ge=1, le=4294967295)
    address: str | None = Field(..., min_length=1, max_length=45)
    domain: str | None = Field(..., min_length=1, max_length=255)
    first_seen: AwareDatetime
    bytes: Count
    context: AnomalyContext

    @model_validator(mode="after")
    def _consistent(self) -> FirstSeen:
        if self.kind == "first-seen-asn":
            if self.asn is None or self.address is not None or self.domain is not None:
                raise ValueError("a first-seen ASN names the ASN only")
        elif self.address is None:
            raise ValueError("a first-seen destination names its address")
        return self


class TrafficAnomaliesResponse(TrafficModel):
    state: TrafficState
    time_range: TrafficTimeRange
    evaluated_range: TrafficTimeRange | None
    method: BaselineMethod
    working_hours: WorkingHours
    evaluation: Evaluation
    first_seen_status: FirstSeenStatus
    anomalies: list[Anomaly] = Field(max_length=50)
    first_seen: list[FirstSeen] = Field(max_length=20)
    cohort: CohortStatus
    freshness: Freshness

    @model_validator(mode="after")
    def _honest(self) -> TrafficAnomaliesResponse:
        if self.state != "ok" and (
            self.anomalies or self.first_seen or self.evaluated_range is not None
        ):
            raise ValueError("non-ok traffic state must not carry values")
        if self.state != "ok" and self.cohort.state != "not-applied":
            raise ValueError("a read that returned nothing applied no cohort rule")
        if self.evaluation.status in ("insufficient-baseline", "no-data") and self.anomalies:
            raise ValueError("no anomaly is reported without a sufficient baseline")
        if self.first_seen_status.state != "sufficient" and self.first_seen:
            raise ValueError("no first-seen flag is raised without history")
        if len(self.anomalies) > self.evaluation.anomalies_total:
            raise ValueError("the anomaly count covers every listed anomaly")
        method = self.method
        for item in self.anomalies:
            if (
                abs(item.score) < method.threshold
                or item.baseline_samples < method.min_weeks
                or item.baseline_samples > method.weeks
                or abs(item.difference) < method.min_difference_bytes
            ):
                raise ValueError("an anomaly meets the stated threshold, samples and difference")
        return self
