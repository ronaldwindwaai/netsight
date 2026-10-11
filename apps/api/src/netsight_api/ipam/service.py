"""IPAM: read NetBox's IPAM datasets and the telemetry that says what was seen (Step 8b).

NetBox is the authority for prefixes, VLANs, address records and reserved ranges. Its four datasets
fail independently (an older NetBox without ``ip-ranges`` must not hide the prefixes), so a failed
one is ``null`` in the result and the others are still shown. Telemetry is optional context:

* LibreNMS contributes the addresses of devices it currently reports up (the adapter exposes no poll
  time, so "seen" means "up at the moment of the read"; a device that was up an hour ago and is down
  now is not counted);
* Wazuh contributes agents whose last keep-alive (or status snapshot) is inside the window;
* when no telemetry source can be read, nothing is judged stale: the answer is ``unknown``.

The window is the operator's (``NETSIGHT_IPAM_STALE_WINDOW_HOURS``, 1 to 168, default 24); an invalid
value makes telemetry unusable rather than silently falling back to a different window.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Protocol

from netsight_api.adapters.librenms import DeviceCollection
from netsight_api.adapters.netbox import RowCollection
from netsight_api.adapters.netbox_ipam import NetboxAddress, NetboxPrefix, NetboxRange, NetboxVlan
from netsight_api.adapters.wazuh import AgentInventory, WazuhAgent
from netsight_api.inventory.cache import TtlCache
from netsight_api.inventory.sources import SourceRead, not_connected, read_bounded
from netsight_api.ipam.engine import IpamBuild, Seen, build_ipam
from netsight_api.schemas_inventory import BlockState
from netsight_api.schemas_ipam import IpamTelemetry, TelemetrySource
from netsight_api.schemas_sources import SourceStatus

_LOGGER: Final = logging.getLogger("netsight_api")

STALE_WINDOW_ENV: Final = "NETSIGHT_IPAM_STALE_WINDOW_HOURS"
DEFAULT_WINDOW: Final = timedelta(hours=24)
MIN_WINDOW_HOURS: Final = 1
MAX_WINDOW_HOURS: Final = 168
SOURCE_BUDGET_SECONDS: Final = 25.0
CACHE_TTL_SECONDS: Final = 30.0
AGENT_LIMIT: Final = 2500


class IpamReader(Protocol):
    async def prefixes(self) -> RowCollection[NetboxPrefix]: ...
    async def vlans(self) -> RowCollection[NetboxVlan]: ...
    async def ip_addresses(self) -> RowCollection[NetboxAddress]: ...
    async def reserved_ranges(self) -> RowCollection[NetboxRange]: ...


class DeviceReader(Protocol):
    async def devices(self) -> DeviceCollection: ...


class AgentReader(Protocol):
    async def agents(self, *, start: datetime, end: datetime, limit: int) -> AgentInventory: ...


class Clock(Protocol):
    def __call__(self) -> datetime: ...


@dataclass(frozen=True)
class IpamSnapshot:
    state: BlockState
    generated_at: datetime
    sources: tuple[SourceStatus, ...]
    telemetry: IpamTelemetry
    build: IpamBuild | None


def stale_window_from_env(env: Mapping[str, str]) -> timedelta | None:
    """The configured window; the default when unset; ``None`` (unusable) when invalid."""
    raw = env.get(STALE_WINDOW_ENV, "").strip()
    if not raw:
        return DEFAULT_WINDOW
    if not raw.isascii() or not raw.isdigit():
        _LOGGER.warning("the IPAM stale window is invalid; activity will not be judged")
        return None
    hours = int(raw)
    if not MIN_WINDOW_HOURS <= hours <= MAX_WINDOW_HOURS:
        _LOGGER.warning("the IPAM stale window is out of range; activity will not be judged")
        return None
    return timedelta(hours=hours)


def _merge(
    into: dict[str, Seen], address: str | None, source: TelemetrySource, when: datetime
) -> None:
    """Record that ``source`` saw ``address`` (ignored when it is not a usable host address)."""
    if address is None:
        return
    try:
        parsed = ipaddress.ip_address(address.strip())
    except ValueError:
        return
    if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
        return
    text = str(parsed)
    known = into.get(text)
    into[text] = (
        Seen(frozenset({source}), when)
        if known is None
        else Seen(known.sources | {source}, max(known.last_seen, when))
    )


def _librenms_seen(into: dict[str, Seen], devices: DeviceCollection) -> None:
    for device in devices.items:
        if device.status == "healthy" and device.ip_addresses:
            _merge(into, device.ip_addresses[0], "librenms", devices.observed_at)


def _wazuh_seen(into: dict[str, Seen], agents: tuple[WazuhAgent, ...], since: datetime) -> None:
    for agent in agents:
        if agent.status in ("never_connected", "pending"):
            continue
        last = agent.last_keep_alive or agent.observed_at
        if last >= since:
            _merge(into, agent.ip, "wazuh", last)


class IpamService:
    def __init__(
        self,
        *,
        netbox: IpamReader | None,
        librenms: DeviceReader | None,
        wazuh: AgentReader | None,
        stale_window: timedelta | None,
        clock: Clock,
        cache: TtlCache[IpamSnapshot],
    ) -> None:
        self._netbox = netbox
        self._librenms = librenms
        self._wazuh = wazuh
        self._window = stale_window
        self._clock = clock
        self._cache = cache

    async def snapshot(self) -> IpamSnapshot:
        return await self._cache.get(self._load)

    async def _read_netbox(self, now: datetime) -> _NetboxReads:
        netbox = self._netbox
        assert netbox is not None
        prefixes, vlans, addresses, ranges = await asyncio.gather(
            self._bounded("netbox-prefixes", netbox.prefixes(), now),
            self._bounded("netbox-vlans", netbox.vlans(), now),
            self._bounded("netbox-addresses", netbox.ip_addresses(), now),
            self._bounded("netbox-ranges", netbox.reserved_ranges(), now),
        )
        return _NetboxReads(prefixes, vlans, addresses, ranges)

    @staticmethod
    async def _bounded[T](name: str, call: Awaitable[T], now: datetime) -> SourceRead[T]:
        async def run() -> T:
            return await call

        return await read_bounded(name, run, budget=SOURCE_BUDGET_SECONDS, now=now)

    async def _load(self) -> IpamSnapshot:
        now = self._clock()
        window = self._window or DEFAULT_WINDOW
        netbox_reads, libre, wazuh = await asyncio.gather(
            self._read_netbox(now) if self._netbox is not None else _no_netbox(),
            self._bounded("librenms", self._librenms.devices(), now)
            if self._librenms is not None
            else _absent(),
            self._bounded(
                "wazuh", self._wazuh.agents(start=now - window, end=now, limit=AGENT_LIMIT), now
            )
            if self._wazuh is not None
            else _absent(),
        )
        agents = _usable_agents(wazuh)
        sources = (
            _netbox_status(netbox_reads, now),
            libre.status("librenms"),
            SourceStatus(
                source="wazuh",
                state="ok" if agents is not None else ("unknown" if wazuh.ok else wazuh.state),
                observed_at=wazuh.observed_at if agents is not None else None,
            ),
        )
        telemetry, seen = self._telemetry(libre, agents, window, now)
        if netbox_reads is None or sources[0].state != "ok":
            return IpamSnapshot(sources[0].state, now, sources, telemetry, None)
        build = await asyncio.to_thread(
            build_ipam,
            prefixes=netbox_reads.rows(netbox_reads.prefixes),
            vlans=netbox_reads.rows(netbox_reads.vlans),
            addresses=netbox_reads.rows(netbox_reads.addresses),
            ranges=netbox_reads.rows(netbox_reads.ranges),
            seen=seen,
        )
        return IpamSnapshot("ok", now, sources, telemetry, build)

    def _telemetry(
        self,
        libre: SourceRead[DeviceCollection],
        agents: tuple[WazuhAgent, ...] | None,
        window: timedelta,
        now: datetime,
    ) -> tuple[IpamTelemetry, dict[str, Seen] | None]:
        used: list[TelemetrySource] = []
        seen: dict[str, Seen] = {}
        if self._window is not None:
            if libre.ok and libre.value is not None:
                used.append("librenms")
                _librenms_seen(seen, libre.value)
            if agents is not None:
                used.append("wazuh")
                _wazuh_seen(seen, agents, now - window)
        configured = self._librenms is not None or self._wazuh is not None
        state: BlockState = "ok" if used else ("unknown" if configured else "not-connected")
        if self._window is None and configured:
            state = "unknown"
        telemetry = IpamTelemetry(
            state=state, window_seconds=int(window.total_seconds()), sources=used
        )
        return telemetry, (seen if used else None)


@dataclass(frozen=True)
class _NetboxReads:
    prefixes: SourceRead[RowCollection[NetboxPrefix]]
    vlans: SourceRead[RowCollection[NetboxVlan]]
    addresses: SourceRead[RowCollection[NetboxAddress]]
    ranges: SourceRead[RowCollection[NetboxRange]]

    @staticmethod
    def rows[T](read: SourceRead[RowCollection[T]]) -> tuple[T, ...] | None:
        return read.value.items if read.ok and read.value is not None else None

    def any_ok(self) -> bool:
        return any(r.ok for r in (self.prefixes, self.vlans, self.addresses, self.ranges))


def _usable_agents(read: SourceRead[AgentInventory]) -> tuple[WazuhAgent, ...] | None:
    """The agents, unless the read failed or was cut short (a partial list hides agents)."""
    if not read.ok or read.value is None or read.value.truncated:
        return None
    return read.value.agents


def _netbox_status(reads: _NetboxReads | None, now: datetime) -> SourceStatus:
    if reads is None:
        return SourceStatus(source="netbox", state="not-connected", observed_at=None)
    if reads.any_ok():
        return SourceStatus(source="netbox", state="ok", observed_at=now)
    return SourceStatus(source="netbox", state="unknown", observed_at=None)


async def _no_netbox() -> None:
    return None


async def _absent[T]() -> SourceRead[T]:
    return not_connected()
