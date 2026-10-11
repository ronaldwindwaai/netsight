"""Typed boundary models for the asset inventory (Step 8).

Mirrors ``contracts/json-schema/inventory.schema.json``, the OpenAPI components and the browser
parsers (shared vectors: ``contracts/test-vectors/inventory.vectors.json``).

Honesty rules, enforced here and not only by construction:

* every field carries its provenance: ``netbox`` (only NetBox reported it), ``discovered`` (only
  telemetry did), ``both`` (they agree), ``conflict`` (they differ; the value is NetBox's, the
  authority for intended state, and both readings are kept) or ``unknown`` (nobody reported it);
* the asset class comes only from the operator's NetBox role/type map (``role-map`` /
  ``type-map``), is ``unclassified`` when the map has no entry, and is ``unknown-asset`` only for an
  asset NetBox does not know: telemetry never classifies;
* without NetBox (``not-connected`` / ``unknown``) there are no rows and no counts, because every
  "unknown to NetBox" claim would be unfounded;
* the counts add up: a summary that does not match its own rows is refused.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, StrictBool, model_validator

from netsight_api.schemas import ApiModel, DeviceStatus
from netsight_api.schemas_sources import SourceStatus, check_unique_sources

AssetClass = Literal[
    "network-device",
    "server",
    "access-point",
    "endpoint",
    "cctv",
    "printer",
    "iot",
    "unknown-asset",
    "unclassified",
]
MAPPED_CLASSES: tuple[AssetClass, ...] = (
    "network-device",
    "server",
    "access-point",
    "endpoint",
    "cctv",
    "printer",
    "iot",
)
ClassBasis = Literal["role-map", "type-map", "unmapped", "not-in-netbox"]
ItemSource = Literal["netbox", "discovered", "both"]
Provenance = Literal["netbox", "discovered", "both", "conflict", "unknown"]
ReconcileStatus = Literal[
    "reconciled",
    "missing-discovered",
    "unknown-discovered",
    "status-mismatch",
    "ambiguous",
    "not-checked",
]
BlockState = Literal["not-connected", "unknown", "ok"]
AliasSource = Literal["netbox", "librenms", "wazuh"]

DEVICE_ID_PATTERN = r"^device-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
MAX_PAGE_SIZE = 100
MAX_ITEMS = 1_000_000

Count = Annotated[int, Field(ge=0, le=MAX_ITEMS)]


class InventoryField(ApiModel):
    value: str | None = Field(..., min_length=1, max_length=255)
    provenance: Provenance
    netbox: str | None = Field(..., min_length=1, max_length=255)
    discovered: str | None = Field(..., min_length=1, max_length=255)

    @model_validator(mode="after")
    def _provenance_matches_the_readings(self) -> InventoryField:
        netbox, discovered, value = self.netbox, self.discovered, self.value
        shape = {
            "netbox": netbox is not None and discovered is None and value == netbox,
            "discovered": netbox is None and discovered is not None and value == discovered,
            "both": netbox is not None and netbox == discovered and value == netbox,
            # NetBox is the authority for intended state, so a conflict keeps NetBox's value.
            "conflict": netbox is not None
            and discovered is not None
            and netbox != discovered
            and value == netbox,
            "unknown": netbox is None and discovered is None and value is None,
        }
        if not shape[self.provenance]:
            raise ValueError("the provenance does not match the readings")
        return self


class InventoryReconcile(ApiModel):
    status: ReconcileStatus
    detail: str | None = Field(..., min_length=1, max_length=255)


class InventoryAlias(ApiModel):
    source: AliasSource
    native_id: str = Field(min_length=1, max_length=255)


class InventoryItem(ApiModel):
    id: str = Field(min_length=43, max_length=43, pattern=DEVICE_ID_PATTERN)
    asset_class: AssetClass
    class_basis: ClassBasis
    source: ItemSource
    known: StrictBool
    name: InventoryField
    site: InventoryField
    ip_address: InventoryField
    mac_address: InventoryField
    role: str | None = Field(..., min_length=1, max_length=128)
    device_type: str | None = Field(..., min_length=1, max_length=128)
    intended_status: str | None = Field(..., min_length=1, max_length=64)
    observed_status: DeviceStatus | None
    reconcile: InventoryReconcile
    sources: list[InventoryAlias] = Field(min_length=1, max_length=3)

    @model_validator(mode="after")
    def _class_and_presence_agree(self) -> InventoryItem:
        in_netbox = self.source in ("netbox", "both")
        if self.known != in_netbox:
            raise ValueError("known means present in NetBox")
        if not in_netbox:
            if (
                self.asset_class != "unknown-asset"
                or self.class_basis != "not-in-netbox"
                or self.role is not None
                or self.device_type is not None
                or self.intended_status is not None
            ):
                raise ValueError("an asset NetBox does not know has no class, role or type")
        else:
            expected: tuple[AssetClass, ...]
            if self.class_basis == "unmapped":
                expected = ("unclassified",)
            elif self.class_basis in ("role-map", "type-map"):
                expected = MAPPED_CLASSES
            else:
                raise ValueError("a NetBox asset has a NetBox class basis")
            if self.asset_class not in expected:
                raise ValueError("the class does not match its basis")
        if self.source == "netbox" and self.observed_status is not None:
            raise ValueError("nothing observed this asset")
        return self

    @model_validator(mode="after")
    def _fields_and_aliases_match_the_presence(self) -> InventoryItem:
        in_netbox = self.source in ("netbox", "both")
        in_discovery = self.source in ("discovered", "both")
        for reading in (self.name, self.site, self.ip_address, self.mac_address):
            if not in_netbox and reading.netbox is not None:
                raise ValueError("NetBox reported a value for an asset it does not know")
            if not in_discovery and reading.discovered is not None:
                raise ValueError("telemetry reported a value for an asset it never saw")
        if self.name.provenance == "unknown":
            raise ValueError("an asset always has a name")
        if (in_netbox and self.name.netbox is None) or (
            in_discovery and self.name.discovered is None
        ):
            raise ValueError("the name comes from every source that knows the asset")
        sources = [alias.source for alias in self.sources]
        if len(set(sources)) != len(sources):
            raise ValueError("a source identifies the asset once")
        if ("netbox" in sources) != in_netbox:
            raise ValueError("the NetBox identifier belongs to a NetBox asset")
        if any(s in sources for s in ("librenms", "wazuh")) != in_discovery:
            raise ValueError("a discovered identifier belongs to a discovered asset")
        return self


class InventoryClassCount(ApiModel):
    asset_class: AssetClass
    count: Count


class InventorySourceCount(ApiModel):
    source: ItemSource
    count: Count


class InventorySummary(ApiModel):
    total: Count
    known: Count
    unknown: Count
    by_class: list[InventoryClassCount] = Field(max_length=9)
    by_source: list[InventorySourceCount] = Field(max_length=3)

    @model_validator(mode="after")
    def _counts_add_up(self) -> InventorySummary:
        if self.total != self.known + self.unknown:
            raise ValueError("total is known plus unknown")
        classes = [row.asset_class for row in self.by_class]
        origins = [row.source for row in self.by_source]
        if len(set(classes)) != len(classes) or len(set(origins)) != len(origins):
            raise ValueError("each class and source is counted once")
        if sum(row.count for row in self.by_class) != self.total:
            raise ValueError("class counts add up to the total")
        if sum(row.count for row in self.by_source) != self.total:
            raise ValueError("source counts add up to the total")
        in_netbox = sum(row.count for row in self.by_source if row.source != "discovered")
        if in_netbox != self.known:
            raise ValueError("known counts the assets NetBox has")
        return self


class InventoryListResponse(ApiModel):
    state: BlockState
    generated_at: AwareDatetime
    page: int = Field(ge=1, le=100_000)
    page_size: int = Field(ge=1, le=MAX_PAGE_SIZE)
    total: Count
    sources: list[SourceStatus] = Field(max_length=3)
    summary: InventorySummary | None
    items: list[InventoryItem] = Field(max_length=MAX_PAGE_SIZE)

    @model_validator(mode="after")
    def _rows_need_netbox(self) -> InventoryListResponse:
        check_unique_sources(self.sources, must_include="netbox")
        if self.state != "ok":
            if self.items or self.total != 0 or self.summary is not None:
                raise ValueError("without NetBox there are no rows and no counts")
            return self
        if self.summary is None:
            raise ValueError("an ok answer carries its counts")
        if len(self.items) > self.page_size or len(self.items) > self.total:
            raise ValueError("a page holds at most page_size rows and at most the total")
        ids = [item.id for item in self.items]
        if len(set(ids)) != len(ids):
            raise ValueError("an asset is listed once")
        return self


class InventoryDetailResponse(ApiModel):
    state: BlockState
    generated_at: AwareDatetime
    sources: list[SourceStatus] = Field(max_length=3)
    item: InventoryItem | None

    @model_validator(mode="after")
    def _item_only_when_ok(self) -> InventoryDetailResponse:
        check_unique_sources(self.sources, must_include="netbox")
        if (self.state == "ok") != (self.item is not None):
            raise ValueError("only an ok answer carries the asset")
        return self


class InventorySummaryResponse(ApiModel):
    state: BlockState
    generated_at: AwareDatetime
    sources: list[SourceStatus] = Field(max_length=3)
    summary: InventorySummary | None

    @model_validator(mode="after")
    def _counts_only_when_ok(self) -> InventorySummaryResponse:
        check_unique_sources(self.sources, must_include="netbox")
        if (self.state == "ok") != (self.summary is not None):
            raise ValueError("only an ok answer carries counts")
        return self
