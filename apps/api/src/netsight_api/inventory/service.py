"""The asset inventory: read the sources, merge, then filter, count and page (Step 8a).

NetBox is the authority for intended state. Without it (not configured, or unreadable) there are no
rows and no counts, because every "NetBox does not know this" claim would be unfounded; LibreNMS and
Wazuh failing only degrade what can be compared (and are named in ``sources``). The Wazuh agent list
is used only when the operator has configured the NetBox custom field that joins an agent to a
device (``NETSIGHT_NETBOX_WAZUH_AGENT_FIELD``): without it an agent cannot be said to be unknown to
NetBox, so the source is reported ``not-connected`` for this purpose and never read.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Protocol

from netsight_api.adapters.librenms import DeviceCollection
from netsight_api.adapters.netbox import (
    DeviceAgentKeyCollection,
    NetboxAsset,
    RowCollection,
)
from netsight_api.adapters.wazuh import AgentInventory
from netsight_api.inventory.build import build_items
from netsight_api.inventory.cache import TtlCache
from netsight_api.inventory.classmap import ClassMap
from netsight_api.inventory.sources import SourceRead, not_connected, read_bounded
from netsight_api.schemas import DeviceStatus
from netsight_api.schemas_inventory import (
    AssetClass,
    BlockState,
    InventoryClassCount,
    InventoryItem,
    InventorySourceCount,
    InventorySummary,
    ItemSource,
)
from netsight_api.schemas_sources import SourceStatus

SOURCE_BUDGET_SECONDS: Final = 25.0
CACHE_TTL_SECONDS: Final = 30.0
AGENT_WINDOW: Final = timedelta(hours=24)
AGENT_LIMIT: Final = 2500
_CLASS_ORDER: Final[tuple[AssetClass, ...]] = (
    "network-device",
    "server",
    "access-point",
    "endpoint",
    "cctv",
    "printer",
    "iot",
    "unknown-asset",
    "unclassified",
)
_SOURCE_ORDER: Final[tuple[ItemSource, ...]] = ("both", "netbox", "discovered")


class NetboxInventoryReader(Protocol):
    async def inventory_assets(self) -> RowCollection[NetboxAsset]: ...

    async def device_agent_keys(self, field_name: str) -> DeviceAgentKeyCollection: ...


class DeviceReader(Protocol):
    async def devices(self) -> DeviceCollection: ...


class AgentReader(Protocol):
    async def agents(self, *, start: datetime, end: datetime, limit: int) -> AgentInventory: ...


@dataclass(frozen=True)
class InventorySnapshot:
    state: BlockState
    generated_at: datetime
    sources: tuple[SourceStatus, ...]
    items: tuple[InventoryItem, ...]
    summary: InventorySummary | None


@dataclass(frozen=True)
class InventoryFilters:
    asset_class: AssetClass | None = None
    site: str | None = None
    status: DeviceStatus | None = None
    source: ItemSource | None = None
    known: bool | None = None
    q: str | None = None

    def active(self) -> list[str]:
        """The names (never the values) of the filters in use, for the audit trail."""
        return [name for name in self.__dataclass_fields__ if getattr(self, name) is not None]


# --- pure helpers ---------------------------------------------------------------------------------------


def _matches(item: InventoryItem, f: InventoryFilters) -> bool:
    if f.asset_class is not None and item.asset_class != f.asset_class:
        return False
    if f.site is not None and f.site not in (item.site.netbox, item.site.discovered):
        return False
    if f.status is not None and item.observed_status != f.status:
        return False
    if f.source is not None and item.source != f.source:
        return False
    if f.known is not None and item.known != f.known:
        return False
    if f.q is not None:
        needle = f.q.casefold()
        haystack = (
            *(item.name.netbox, item.name.discovered),
            *(item.ip_address.netbox, item.ip_address.discovered),
            *(item.mac_address.netbox, item.mac_address.discovered),
        )
        if not any(value is not None and needle in value.casefold() for value in haystack):
            return False
    return True


def filter_items(items: Sequence[InventoryItem], filters: InventoryFilters) -> list[InventoryItem]:
    return [item for item in items if _matches(item, filters)]


def sort_items(items: Sequence[InventoryItem]) -> list[InventoryItem]:
    return sorted(items, key=lambda item: ((item.name.value or "").casefold(), item.id))


def page_items(items: Sequence[InventoryItem], *, page: int, page_size: int) -> list[InventoryItem]:
    start = (page - 1) * page_size
    return list(items[start : start + page_size])


def find_item(items: Sequence[InventoryItem], item_id: str) -> InventoryItem | None:
    return next((item for item in items if item.id == item_id), None)


def summarise(items: Sequence[InventoryItem]) -> InventorySummary:
    by_class: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for item in items:
        by_class[item.asset_class] = by_class.get(item.asset_class, 0) + 1
        by_source[item.source] = by_source.get(item.source, 0) + 1
    known = sum(1 for item in items if item.known)
    return InventorySummary(
        total=len(items),
        known=known,
        unknown=len(items) - known,
        by_class=[
            InventoryClassCount(asset_class=c, count=by_class[c])
            for c in _CLASS_ORDER
            if c in by_class
        ],
        by_source=[
            InventorySourceCount(source=s, count=by_source[s])
            for s in _SOURCE_ORDER
            if s in by_source
        ],
    )


# --- the service ----------------------------------------------------------------------------------------


class InventoryService:
    def __init__(
        self,
        *,
        netbox: NetboxInventoryReader | None,
        librenms: DeviceReader | None,
        wazuh: AgentReader | None,
        agent_field: str | None,
        class_map: ClassMap,
        clock: Clock,
        cache: TtlCache[InventorySnapshot],
    ) -> None:
        self._netbox = netbox
        self._librenms = librenms
        self._wazuh = wazuh
        self._agent_field = agent_field
        self._class_map = class_map
        self._clock = clock
        self._cache = cache

    async def snapshot(self) -> InventorySnapshot:
        return await self._cache.get(self._load)

    async def _read[T](self, name: str, call: Awaitable[T], now: datetime) -> SourceRead[T]:
        async def run() -> T:
            return await call

        return await read_bounded(name, run, budget=SOURCE_BUDGET_SECONDS, now=now)

    async def _read_wazuh(
        self, now: datetime
    ) -> SourceRead[tuple[AgentInventory, Mapping[str, str]]]:
        if self._wazuh is None or self._netbox is None or self._agent_field is None:
            return not_connected()
        field_name = self._agent_field
        agents, keys = await asyncio.gather(
            self._read(
                "wazuh",
                self._wazuh.agents(start=now - AGENT_WINDOW, end=now, limit=AGENT_LIMIT),
                now,
            ),
            self._read("netbox-agent-keys", self._netbox.device_agent_keys(field_name), now),
        )
        if not agents.ok or not keys.ok or agents.value is None or keys.value is None:
            return SourceRead("unknown")
        if agents.value.truncated:
            return SourceRead(
                "unknown"
            )  # a partial list hides agents: never presented as an answer
        mapping = {k.device_native_id: k.agent_key for k in keys.value.items}
        return SourceRead("ok", (agents.value, mapping), now)

    async def _load(self) -> InventorySnapshot:
        now = self._clock()
        assets, libre, wazuh = await asyncio.gather(
            self._read("netbox", self._netbox.inventory_assets(), now)
            if self._netbox is not None
            else _absent(),
            self._read("librenms", self._librenms.devices(), now)
            if self._librenms is not None
            else _absent(),
            self._read_wazuh(now),
        )
        sources = (
            assets.status("netbox"),
            libre.status("librenms"),
            wazuh.status("wazuh"),
        )
        if not assets.ok or assets.value is None:
            return InventorySnapshot(assets.state, now, sources, (), None)
        agents = wazuh.value[0].agents if wazuh.value is not None else None
        keys = wazuh.value[1] if wazuh.value is not None else None
        items = await asyncio.to_thread(
            build_items,
            netbox=assets.value.items,
            librenms=libre.value.items if libre.value is not None else None,
            wazuh=agents,
            agent_keys=keys,
            class_map=self._class_map,
        )
        return InventorySnapshot("ok", now, sources, tuple(sort_items(items)), summarise(items))


async def _absent[T]() -> SourceRead[T]:
    return not_connected()


class Clock(Protocol):
    def __call__(self) -> datetime: ...
