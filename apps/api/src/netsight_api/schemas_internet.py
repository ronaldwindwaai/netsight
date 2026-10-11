"""Typed boundary models for the Internet/WAN surface (Step 5).

Mirrors ``contracts/json-schema/internet.schema.json`` and ``internet-sla.schema.json``, the
OpenAPI components and the browser parsers (shared vectors in ``contracts/test-vectors``).

Honesty rules, enforced here and not only by construction:

* a block whose ``state`` is not ``ok`` carries no values (``not-connected`` and ``unknown`` never
  assert a number, a status or an address);
* every measured value is the source's own or ``null``: a null is "not reported", never zero;
* the ``configured`` object holds operator declarations (ISP, gateway), labelled as such, not
  telemetry;
* ``failover`` and each link's ``status`` are derived by a documented rule from source-reported
  state and are labelled ``inferred``; they are ``unknown`` whenever a source is silent.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, model_validator

from netsight_api.schemas import ApiModel, Freshness, InterfaceOperStatus
from netsight_api.schemas_diagnostics import ProbeLocation

BlockState = Literal["not-connected", "unknown", "ok"]
LinkRole = Literal["primary", "backup"]
LinkStatus = Literal["up", "degraded", "down", "unknown"]
ProbeOutcome = Literal["pass", "fail", "unknown"]
FailoverState = Literal["single-link", "normal", "failed-over", "all-down", "unknown"]
FailoverBasis = Literal["inferred", "unknown"]
WindowKind = Literal["down", "degraded", "unknown"]

LINK_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{0,47}$"
MONTH_PATTERN = r"^[0-9]{4}-(0[1-9]|1[0-2])$"
MAX_LINKS = 8
MAX_EXPORT_WINDOWS = 2000
MAX_EXPORT_SOURCES = 64

LinkId = Annotated[str, Field(pattern=LINK_ID_PATTERN, min_length=1, max_length=48)]
Seconds = Annotated[int, Field(ge=0, le=10_000_000)]
Percent = Annotated[float, Field(ge=0, le=100, allow_inf_nan=False)]
Millis = Annotated[float, Field(ge=0, le=3_600_000, allow_inf_nan=False)]


class WanConfigured(ApiModel):
    """Operator declarations. Not telemetry: the UI labels them "configured"."""

    isp: str | None = Field(..., min_length=1, max_length=128)
    gateway: str | None = Field(..., min_length=1, max_length=45)
    probe_location: ProbeLocation | None


class WanInterfaceReading(ApiModel):
    """LibreNMS interface metrics for the declared port; each value reported or ``null``."""

    state: BlockState
    oper_status: InterfaceOperStatus | None
    capacity_bps: int | None = Field(..., ge=0)
    rx_bps: int | None = Field(..., ge=0)
    tx_bps: int | None = Field(..., ge=0)
    # Derived: the larger of rx/tx over capacity, only when all three are known and capacity > 0.
    utilisation_pct: float | None = Field(..., ge=0, le=1000, allow_inf_nan=False)
    public_ip: str | None = Field(..., min_length=1, max_length=45)
    freshness: Freshness

    @model_validator(mode="after")
    def _non_ok_carries_no_values(self) -> WanInterfaceReading:
        if self.state != "ok" and any(
            value is not None
            for value in (
                self.oper_status,
                self.capacity_bps,
                self.rx_bps,
                self.tx_bps,
                self.utilisation_pct,
                self.public_ip,
            )
        ):
            raise ValueError("a non-ok interface reading must not carry values")
        return self


class WanQuality(ApiModel):
    """Latency, jitter, loss and DNS computed from the stored probe samples of the last window."""

    state: BlockState
    latency_ms: Millis | None
    jitter_ms: Millis | None
    loss_pct: Percent | None
    dns_status: ProbeOutcome | None
    dns_latency_ms: Millis | None
    sample_count: int = Field(ge=0, le=100_000)
    window_seconds: Seconds
    freshness: Freshness

    @model_validator(mode="after")
    def _non_ok_carries_no_values(self) -> WanQuality:
        if self.state != "ok" and (
            self.sample_count != 0
            or any(
                value is not None
                for value in (
                    self.latency_ms,
                    self.jitter_ms,
                    self.loss_pct,
                    self.dns_status,
                    self.dns_latency_ms,
                )
            )
        ):
            raise ValueError("a non-ok quality reading must not carry values")
        return self


class WanAvailability(ApiModel):
    """Month-to-date availability and the outage in progress, from stored probe cycles."""

    state: BlockState
    period_start: AwareDatetime | None
    period_end: AwareDatetime | None
    uptime_pct: Percent | None
    coverage_pct: Percent | None
    current_outage_started_at: AwareDatetime | None
    current_outage_seconds: Seconds | None
    freshness: Freshness

    @model_validator(mode="after")
    def _consistent(self) -> WanAvailability:
        values = (
            self.period_start,
            self.period_end,
            self.uptime_pct,
            self.coverage_pct,
            self.current_outage_started_at,
            self.current_outage_seconds,
        )
        if self.state != "ok" and any(value is not None for value in values):
            raise ValueError("a non-ok availability reading must not carry values")
        if (self.current_outage_started_at is None) != (self.current_outage_seconds is None):
            raise ValueError("an outage has a start and a duration, or neither")
        return self


class WanLink(ApiModel):
    id: LinkId
    name: str = Field(min_length=1, max_length=128)
    role: LinkRole
    configured: WanConfigured
    # Derived (inferred) from the interface state and the latest probe round; see the build plan.
    status: LinkStatus
    interface: WanInterfaceReading
    quality: WanQuality
    availability: WanAvailability


class WanFailover(ApiModel):
    state: FailoverState
    basis: FailoverBasis

    @model_validator(mode="after")
    def _basis_matches_state(self) -> WanFailover:
        if (self.state == "unknown") != (self.basis == "unknown"):
            raise ValueError("failover is unknown exactly when its basis is unknown")
        return self


def _withholds_detail(link: WanLink) -> bool:
    """True when none of the ``internet:read_detail`` fields of ``link`` carries a value."""
    return all(
        value is None
        for value in (
            link.configured.isp,
            link.configured.gateway,
            link.interface.public_ip,
            link.interface.rx_bps,
            link.interface.tx_bps,
            link.interface.utilisation_pct,
        )
    )


class InternetResponse(ApiModel):
    state: BlockState
    generated_at: AwareDatetime
    links: list[WanLink] = Field(max_length=MAX_LINKS)
    failover: WanFailover
    # True when the caller lacks internet:read_detail: the ISP name, gateway, public IP and
    # per-link throughput are withheld (null), so a null there is "restricted", not "not reported".
    detail_redacted: bool

    @model_validator(mode="after")
    def _non_ok_carries_no_links(self) -> InternetResponse:
        if self.state != "ok" and (self.links or self.failover.state != "unknown"):
            raise ValueError("a non-ok internet response must not carry links")
        if self.detail_redacted and not all(_withholds_detail(link) for link in self.links):
            raise ValueError("a redacted internet response must not carry restricted detail")
        return self


# --- SLA ----------------------------------------------------------------------------------------


class SlaViolation(ApiModel):
    kind: Literal["uptime-below-target"]
    target_pct: Percent
    actual_pct: Percent


class SlaLink(ApiModel):
    link_id: LinkId
    name: str = Field(min_length=1, max_length=128)
    state: BlockState
    uptime_target_pct: float | None = Field(..., gt=0, le=100, allow_inf_nan=False)
    total_seconds: Seconds | None
    up_seconds: Seconds | None
    degraded_seconds: Seconds | None
    down_seconds: Seconds | None
    unknown_seconds: Seconds | None
    uptime_pct: Percent | None
    coverage_pct: Percent | None
    outage_count: int | None = Field(..., ge=0, le=1_000_000)
    longest_outage_seconds: Seconds | None
    cycle_count: int | None = Field(..., ge=0, le=1_000_000)
    # True when the export lists fewer windows than the month holds (the figures stay complete).
    windows_truncated: bool | None
    violations: list[SlaViolation] = Field(max_length=8)

    @model_validator(mode="after")
    def _consistent(self) -> SlaLink:
        figures = (
            self.total_seconds,
            self.up_seconds,
            self.degraded_seconds,
            self.down_seconds,
            self.unknown_seconds,
            self.outage_count,
            self.longest_outage_seconds,
            self.cycle_count,
            self.windows_truncated,
        )
        if self.state != "ok":
            if any(v is not None for v in (*figures, self.uptime_pct, self.coverage_pct)):
                raise ValueError("a non-ok SLA link must not carry figures")
            if self.violations:
                raise ValueError("a non-ok SLA link must not carry violations")
            return self
        if any(v is None for v in figures) or self.coverage_pct is None:
            raise ValueError("an ok SLA link carries every figure")
        parts = (self.up_seconds, self.degraded_seconds, self.down_seconds, self.unknown_seconds)
        if sum(p for p in parts if p is not None) != self.total_seconds:
            raise ValueError("the SLA seconds must add up to the period")
        return self


class SlaResponse(ApiModel):
    state: BlockState
    month: str = Field(pattern=MONTH_PATTERN, min_length=7, max_length=7)
    period_start: AwareDatetime | None
    period_end: AwareDatetime | None
    generated_at: AwareDatetime
    links: list[SlaLink] = Field(max_length=MAX_LINKS)

    @model_validator(mode="after")
    def _non_ok_carries_no_links(self) -> SlaResponse:
        if self.state != "ok" and (self.links or self.period_start or self.period_end):
            raise ValueError("a non-ok SLA response must not carry links or a period")
        if self.state == "ok" and (self.period_start is None or self.period_end is None):
            raise ValueError("an ok SLA response names its period")
        return self


class ExportWindow(ApiModel):
    kind: WindowKind
    started_at: AwareDatetime
    ended_at: AwareDatetime
    duration_seconds: Seconds
    # Probe rounds inside the window; 0 for a gap in sampling (no round, so nothing is known).
    sample_count: int = Field(ge=0, le=1_000_000)

    @model_validator(mode="after")
    def _ordered(self) -> ExportWindow:
        if self.ended_at <= self.started_at:
            raise ValueError("a window ends after it starts")
        return self


class ExportSource(ApiModel):
    probe: Literal["icmp", "tcp", "dns"]
    target: str = Field(min_length=1, max_length=253)
    location: ProbeLocation | None


class ExportLink(ApiModel):
    link: SlaLink
    isp: str | None = Field(..., min_length=1, max_length=128)
    sources: list[ExportSource] = Field(max_length=MAX_EXPORT_SOURCES)
    windows: list[ExportWindow] = Field(max_length=MAX_EXPORT_WINDOWS)
    windows_truncated: bool

    @model_validator(mode="after")
    def _non_ok_carries_no_evidence(self) -> ExportLink:
        if self.link.state != "ok" and (self.sources or self.windows or self.windows_truncated):
            raise ValueError("a non-ok export link must not carry evidence")
        return self


class SlaExport(ApiModel):
    state: BlockState
    month: str = Field(pattern=MONTH_PATTERN, min_length=7, max_length=7)
    period_start: AwareDatetime | None
    period_end: AwareDatetime | None
    generated_at: AwareDatetime
    # Fixed statement of what the evidence is and is not (no text from any source).
    basis: str = Field(min_length=1, max_length=1000)
    # True when the caller lacks internet:read_detail: the ISP name is withheld (null).
    detail_redacted: bool
    links: list[ExportLink] = Field(max_length=MAX_LINKS)

    @model_validator(mode="after")
    def _non_ok_carries_no_links(self) -> SlaExport:
        if self.state != "ok" and (self.links or self.period_start or self.period_end):
            raise ValueError("a non-ok export must not carry links or a period")
        if self.detail_redacted and any(item.isp is not None for item in self.links):
            raise ValueError("a redacted export must not carry the ISP name")
        if self.state == "ok" and (self.period_start is None or self.period_end is None):
            raise ValueError("an ok export names its period")
        return self
