"""Typed boundary models for IPAM (Step 8b).

Mirrors ``contracts/json-schema/ipam.schema.json``, the OpenAPI components and the browser parsers
(shared vectors: ``contracts/test-vectors/ipam.vectors.json``).

Honesty rules, enforced here and not only by construction:

* prefixes, VLANs and the intended addresses are NetBox's; an address is ``active`` only when
  telemetry saw it within the window, ``stale`` only when telemetry was readable and did not, and
  ``unknown`` when no telemetry could be read: absence of a witness is never turned into a verdict;
* utilisation is shown with its basis, is derived by one stated rule (``percent_of``), and is not
  claimed at all (``unknown``) when the addresses could not be read or the capacity is not
  meaningful (a huge IPv6 prefix);
* a count that could not be read is ``null``, never zero;
* a non-ok list carries no rows.
"""

from __future__ import annotations

import ipaddress
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, model_validator

from netsight_api.schemas import ApiModel
from netsight_api.schemas_inventory import BlockState
from netsight_api.schemas_sources import SourceStatus, check_unique_sources

UUID_PATTERN = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
PREFIX_ID_PATTERN = rf"^ipam-prefix-{UUID_PATTERN}$"
VLAN_ID_PATTERN = rf"^ipam-vlan-{UUID_PATTERN}$"
ADDRESS_ID_PATTERN = rf"^ipam-address-{UUID_PATTERN}$"
MAX_COUNT = 1_000_000
MAX_SIZE = 4_294_967_296
MAX_PAGE_SIZE = 100
MAX_LISTED_RANGES = 16

UtilisationState = Literal["ok", "unknown"]
UtilisationBasis = Literal[
    "netbox-addresses",
    "netbox-and-discovered",
    "marked-utilized",
    "capacity-not-meaningful",
    "addresses-unavailable",
]
Activity = Literal["active", "stale", "unknown", "reserved"]
AddressSource = Literal["netbox", "discovered", "both"]
TelemetrySource = Literal["librenms", "wazuh"]

PrefixId = Annotated[str, Field(min_length=48, max_length=48, pattern=PREFIX_ID_PATTERN)]
Count = Annotated[int, Field(ge=0, le=MAX_COUNT)]
OptionalCount = Annotated[int | None, Field(ge=0, le=MAX_COUNT)]


def percent_of(used: int, capacity: int) -> float:
    """used over capacity as a percentage with one decimal, rounded half up, at most 100.

    Integer arithmetic only, so the API, the schema checks and the browser agree to the last digit.
    """
    if capacity <= 0:
        return 100.0
    tenths = (used * 1000 + capacity // 2) // capacity
    return min(tenths, 1000) / 10


def _one_family(first: str, last: str) -> int:
    a, b = ipaddress.ip_address(first), ipaddress.ip_address(last)
    if a.version != b.version:
        raise ValueError("an address range stays in one family")
    return int(b) - int(a) + 1


class IpamCounts(ApiModel):
    prefixes: OptionalCount
    vlans: OptionalCount
    addresses: OptionalCount
    reserved_ranges: OptionalCount
    active_addresses: OptionalCount
    stale_addresses: OptionalCount
    unknown_activity_addresses: OptionalCount
    discovered_only_addresses: OptionalCount

    @model_validator(mode="after")
    def _activity_fits_the_addresses(self) -> IpamCounts:
        judged = [self.active_addresses, self.stale_addresses, self.unknown_activity_addresses]
        if self.addresses is not None and all(v is not None for v in judged):
            seen_only = self.discovered_only_addresses or 0
            if sum(v for v in judged if v is not None) > self.addresses + seen_only:
                raise ValueError("activity counts exceed the addresses")
        return self


class IpamTelemetry(ApiModel):
    state: BlockState
    window_seconds: int = Field(ge=3600, le=604800)
    sources: list[TelemetrySource] = Field(max_length=2)

    @model_validator(mode="after")
    def _state_matches_the_sources(self) -> IpamTelemetry:
        if len(set(self.sources)) != len(self.sources):
            raise ValueError("a source is listed once")
        if (self.state == "ok") != bool(self.sources):
            raise ValueError("telemetry is ok exactly when a source was read")
        return self


class IpamUtilisation(ApiModel):
    state: UtilisationState
    basis: UtilisationBasis
    capacity: int | None = Field(..., ge=0, le=MAX_SIZE)
    netbox_addresses: int | None = Field(..., ge=0, le=MAX_COUNT)
    discovered_only: int | None = Field(..., ge=0, le=MAX_COUNT)
    used: int | None = Field(..., ge=0, le=MAX_COUNT * 2)
    reserved: int | None = Field(..., ge=0, le=MAX_SIZE)
    free: int | None = Field(..., ge=0, le=MAX_SIZE)
    percent: float | None = Field(..., ge=0, le=100, allow_inf_nan=False)

    @model_validator(mode="after")
    def _figures_follow_the_basis(self) -> IpamUtilisation:
        figures = (
            self.netbox_addresses,
            self.discovered_only,
            self.used,
            self.reserved,
            self.free,
            self.percent,
        )
        if self.state == "unknown":
            if any(v is not None for v in figures):
                raise ValueError("an unknown utilisation carries no figure")
            return self
        if self.basis in ("capacity-not-meaningful", "addresses-unavailable"):
            raise ValueError("this basis cannot be ok")
        if self.basis == "marked-utilized":
            if self.percent != 100:
                raise ValueError("a prefix marked utilized is 100 percent")
            return self
        if self.basis == "netbox-addresses" and self.discovered_only != 0:
            raise ValueError("netbox-addresses counts no discovered address")
        required = (
            self.capacity,
            self.netbox_addresses,
            self.discovered_only,
            self.used,
            self.percent,
        )
        if any(v is None for v in required):
            raise ValueError("a computed utilisation carries its figures")
        if (self.reserved is None) != (self.free is None):
            raise ValueError("reserved and free are both reported or both not")
        assert self.capacity is not None and self.netbox_addresses is not None  # checked above
        assert self.discovered_only is not None and self.used is not None
        assert self.percent is not None
        if self.used != self.netbox_addresses + self.discovered_only:
            raise ValueError("used is the NetBox addresses plus the discovered ones")
        if self.percent != percent_of(self.used, self.capacity):
            raise ValueError("percent is used over capacity")
        if (
            self.free is not None
            and self.reserved is not None
            and self.free != max(0, self.capacity - self.used - self.reserved)
        ):
            raise ValueError("free is capacity less used and reserved")
        return self


class IpamReservedRange(ApiModel):
    start: str = Field(min_length=2, max_length=45)
    end: str = Field(min_length=2, max_length=45)
    size: int = Field(ge=1, le=MAX_SIZE)

    @model_validator(mode="after")
    def _size_is_the_span(self) -> IpamReservedRange:
        try:
            span = _one_family(self.start, self.end)
        except ValueError as error:
            raise ValueError("a range is two addresses of one family") from error
        if span < 1 or span != self.size:
            raise ValueError("size is the span from start to end")
        return self


class IpamPrefixVlan(ApiModel):
    vid: int = Field(ge=1, le=4094)
    name: str = Field(min_length=1, max_length=128)


class IpamPrefix(ApiModel):
    id: PrefixId
    prefix: str = Field(min_length=3, max_length=64)
    version: Literal[4, 6]
    vrf: str | None = Field(..., min_length=1, max_length=128)
    status: str | None = Field(..., min_length=1, max_length=64)
    site: str | None = Field(..., min_length=1, max_length=128)
    role: str | None = Field(..., min_length=1, max_length=128)
    vlan: IpamPrefixVlan | None
    description: str | None = Field(..., min_length=1, max_length=128)
    parent_id: PrefixId | None
    depth: int = Field(ge=0, le=128)
    children: Count
    utilisation: IpamUtilisation
    reserved_ranges: list[IpamReservedRange] = Field(max_length=MAX_LISTED_RANGES)
    reserved_ranges_total: Count

    @model_validator(mode="after")
    def _a_canonical_network_in_a_consistent_tree(self) -> IpamPrefix:
        try:
            network = ipaddress.ip_network(self.prefix, strict=True)
        except ValueError as error:
            raise ValueError("prefix is a network in canonical form") from error
        if str(network) != self.prefix or network.version != self.version:
            raise ValueError("prefix is canonical and matches its family")
        if (self.parent_id is None) != (self.depth == 0):
            raise ValueError("only a root prefix has depth 0")
        if self.parent_id == self.id:
            raise ValueError("a prefix is not its own parent")
        if len(self.reserved_ranges) > self.reserved_ranges_total:
            raise ValueError("more ranges listed than exist")
        return self


class IpamVlan(ApiModel):
    id: str = Field(min_length=46, max_length=46, pattern=VLAN_ID_PATTERN)
    vid: int = Field(ge=1, le=4094)
    name: str = Field(min_length=1, max_length=128)
    status: str | None = Field(..., min_length=1, max_length=64)
    site: str | None = Field(..., min_length=1, max_length=128)
    group: str | None = Field(..., min_length=1, max_length=128)
    description: str | None = Field(..., min_length=1, max_length=128)
    prefix_count: OptionalCount


class IpamAddress(ApiModel):
    id: str = Field(min_length=49, max_length=49, pattern=ADDRESS_ID_PATTERN)
    address: str = Field(min_length=2, max_length=45)
    version: Literal[4, 6]
    prefix_id: PrefixId | None
    vrf: str | None = Field(..., min_length=1, max_length=128)
    status: str | None = Field(..., min_length=1, max_length=64)
    dns_name: str | None = Field(..., min_length=1, max_length=255)
    description: str | None = Field(..., min_length=1, max_length=128)
    source: AddressSource
    activity: Activity
    seen_by: list[TelemetrySource] = Field(max_length=2)
    last_seen: AwareDatetime | None

    @model_validator(mode="after")
    def _activity_rests_on_a_witness(self) -> IpamAddress:
        try:
            parsed = ipaddress.ip_address(self.address)
        except ValueError as error:
            raise ValueError("address is an IP address") from error
        if str(parsed) != self.address or parsed.version != self.version:
            raise ValueError("address is canonical and matches its family")
        if len(set(self.seen_by)) != len(self.seen_by):
            raise ValueError("a witness is listed once")
        if self.activity == "active":
            if not self.seen_by or self.last_seen is None:
                raise ValueError("active needs a witness and a time")
        elif self.seen_by or self.last_seen is not None:
            raise ValueError("only an active address has a witness")
        if self.source == "discovered" and (
            self.activity != "active" or self.status is not None or self.dns_name is not None
        ):
            raise ValueError("an address only telemetry saw is active and has no NetBox data")
        if self.activity == "stale" and self.source != "netbox":
            raise ValueError("stale means NetBox has it and nothing saw it")
        return self


class IpamActivityCounts(ApiModel):
    active: Count
    stale: Count
    unknown: Count
    reserved: Count


def _check_listing(
    sources: list[SourceStatus], telemetry: IpamTelemetry, state: BlockState
) -> None:
    check_unique_sources(sources, must_include="netbox")
    read = {s.source for s in sources if s.state == "ok"}
    if not set(telemetry.sources) <= read:
        raise ValueError("telemetry names only sources that were read")
    del state


class _Listing(ApiModel):
    state: BlockState
    generated_at: AwareDatetime
    sources: list[SourceStatus] = Field(max_length=3)
    telemetry: IpamTelemetry
    page: int = Field(ge=1, le=100_000)
    page_size: int = Field(ge=1, le=MAX_PAGE_SIZE)
    total: Count

    def check_rows(self, ids: list[str]) -> None:
        _check_listing(self.sources, self.telemetry, self.state)
        if self.state != "ok":
            if ids or self.total != 0:
                raise ValueError("without NetBox there are no rows")
            return
        if len(ids) > self.page_size or len(ids) > self.total:
            raise ValueError("a page holds at most page_size rows and at most the total")
        if len(set(ids)) != len(ids):
            raise ValueError("a row is listed once")


class IpamPrefixList(_Listing):
    items: list[IpamPrefix] = Field(max_length=MAX_PAGE_SIZE)

    @model_validator(mode="after")
    def _rows(self) -> IpamPrefixList:
        self.check_rows([i.id for i in self.items])
        return self


class IpamVlanList(_Listing):
    items: list[IpamVlan] = Field(max_length=MAX_PAGE_SIZE)

    @model_validator(mode="after")
    def _rows(self) -> IpamVlanList:
        self.check_rows([i.id for i in self.items])
        return self


class IpamAddressList(_Listing):
    activity_counts: IpamActivityCounts | None
    items: list[IpamAddress] = Field(max_length=MAX_PAGE_SIZE)

    @model_validator(mode="after")
    def _rows(self) -> IpamAddressList:
        self.check_rows([i.id for i in self.items])
        if self.state != "ok":
            if self.activity_counts is not None:
                raise ValueError("without NetBox there are no counts")
            return self
        counts = self.activity_counts
        if counts is None:
            raise ValueError("an ok answer carries its counts")
        everything = counts.active + counts.stale + counts.unknown + counts.reserved
        if len(self.items) > everything or self.total > everything:
            raise ValueError("the counts cover every row")
        return self


class IpamSummaryResponse(ApiModel):
    state: BlockState
    generated_at: AwareDatetime
    sources: list[SourceStatus] = Field(max_length=3)
    telemetry: IpamTelemetry
    counts: IpamCounts | None

    @model_validator(mode="after")
    def _counts_only_when_ok(self) -> IpamSummaryResponse:
        _check_listing(self.sources, self.telemetry, self.state)
        if (self.state == "ok") != (self.counts is not None):
            raise ValueError("only an ok answer carries counts")
        return self
