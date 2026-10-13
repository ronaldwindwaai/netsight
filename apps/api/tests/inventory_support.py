"""Shared builders and fakes for the inventory, IPAM and unknown-device tests (Step 8)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from netsight_api.adapters import librenms as librenms_adapter
from netsight_api.adapters import netbox as netbox_adapter
from netsight_api.adapters.librenms import DeviceCollection
from netsight_api.adapters.netbox import (
    MacLookup,
    NetboxAsset,
    RowCollection,
    canonical_device_id,
)
from netsight_api.adapters.netbox_ipam import (
    MacMatch,
    NetboxAddress,
    NetboxPrefix,
    NetboxRange,
    NetboxVlan,
)
from netsight_api.adapters.wazuh import AgentInventory, WazuhAgent
from netsight_api.schemas import Device, DeviceSourceAlias, Freshness

NOW = datetime(2026, 10, 11, 12, 0, 0, tzinfo=UTC)
MINUTES_AGO = NOW - timedelta(minutes=5)


def device(
    source: str,
    native_id: str,
    name: str,
    *,
    ip: str | None = None,
    mac: str | None = None,
    status: str = "healthy",
    site: str | None = None,
    kind: str = "unknown",
) -> Device:
    canonical = (
        canonical_device_id(native_id)
        if source == "netbox"
        else librenms_adapter.canonical_device_id(native_id)
    )
    return Device(
        id=canonical,
        name=name,
        hostname=name,
        type=kind,
        status=status,  # type: ignore[arg-type]
        ip_addresses=[ip] if ip else [],
        mac_addresses=[mac] if mac else [],
        site_id=site,
        owner_identity_id=None,
        source_aliases=[DeviceSourceAlias(source=source, native_id=native_id)],
        freshness=Freshness(state="fresh", observed_at=NOW, source=source),
    )


def asset(
    native_id: str,
    name: str,
    *,
    ip: str | None = None,
    site: str | None = "HQ",
    role: str | None = "core-switch",
    device_type: str | None = "c9300",
    status: str = "active",
) -> NetboxAsset:
    return NetboxAsset(
        device=device(
            "netbox",
            native_id,
            name,
            ip=ip,
            site=site,
            status="healthy"
            if status == "active"
            else "offline"
            if status == "offline"
            else "unknown",
            kind=role or "unknown",
        ),
        role_slug=role,
        role_name=role.replace("-", " ").title() if role else None,
        type_slug=device_type,
        type_model=device_type.upper() if device_type else None,
        status=status,
    )


def agent(
    agent_id: str,
    name: str | None,
    ip: str | None,
    *,
    status: str = "active",
    seen: datetime = MINUTES_AGO,
) -> WazuhAgent:
    return WazuhAgent(agent_id, name, ip, status, seen, seen)


def rows[T](items: list[T], at: datetime = NOW, skipped: int = 0) -> RowCollection[T]:
    return RowCollection(tuple(items), at, skipped)


def prefix(
    native_id: str,
    cidr: str,
    *,
    status: str | None = "active",
    site: str | None = "HQ",
    vrf_id: str | None = None,
    vlan_id: str | None = None,
    vlan_vid: int | None = None,
    vlan_name: str | None = None,
    description: str | None = None,
    is_pool: bool = False,
    mark_utilized: bool = False,
) -> NetboxPrefix:
    import ipaddress

    network = ipaddress.ip_network(cidr, strict=False)
    return NetboxPrefix(
        native_id,
        str(network),
        network.version,
        vrf_id,
        None,
        status,
        site,
        None,
        vlan_id,
        vlan_vid,
        vlan_name,
        description,
        is_pool,
        mark_utilized,
    )


def vlan(native_id: str, vid: int, name: str, *, site: str | None = "HQ") -> NetboxVlan:
    return NetboxVlan(native_id, vid, name, "active", site, None, None)


def address(
    native_id: str,
    ip: str,
    *,
    status: str | None = "active",
    vrf_id: str | None = None,
    dns: str | None = None,
    assigned: bool = True,
) -> NetboxAddress:
    import ipaddress

    parsed = ipaddress.ip_address(ip)
    return NetboxAddress(native_id, ip, parsed.version, vrf_id, status, dns, None, assigned)


def reserved(native_id: str, start: str, end: str, *, vrf_id: str | None = None) -> NetboxRange:
    import ipaddress

    first, last = ipaddress.ip_address(start), ipaddress.ip_address(end)
    return NetboxRange(
        native_id, start, end, first.version, int(last) - int(first) + 1, vrf_id, "reserved", None
    )


class FakeNetbox:
    """A NetBox reader whose every read is a value or an exception (counts the calls)."""

    def __init__(
        self,
        assets: list[NetboxAsset] | Exception | None = None,
        *,
        prefixes: list[NetboxPrefix] | Exception | None = None,
        vlans: list[NetboxVlan] | Exception | None = None,
        addresses: list[NetboxAddress] | Exception | None = None,
        ranges: list[NetboxRange] | Exception | None = None,
        agent_keys: dict[str, str] | Exception | None = None,
        ip_assignments: dict[str, str] | Exception | None = None,
        macs: dict[str, list[MacMatch]] | Exception | None = None,
        skipped: int = 0,
    ) -> None:
        self.skipped = skipped  # malformed rows the adapter dropped, on every collection it returns
        self.lookups: list[str] = []
        self._assets = assets if assets is not None else []
        self._prefixes = prefixes if prefixes is not None else []
        self._vlans = vlans if vlans is not None else []
        self._addresses = addresses if addresses is not None else []
        self._ranges = ranges if ranges is not None else []
        self._agent_keys = agent_keys if agent_keys is not None else {}
        self._ip_assignments = ip_assignments if ip_assignments is not None else {}
        self._macs = macs if macs is not None else {}
        self.calls: list[str] = []

    def _read[T](self, name: str, value: T | Exception) -> T:
        self.calls.append(name)
        if isinstance(value, Exception):
            raise value
        return value

    async def inventory_assets(self) -> RowCollection[NetboxAsset]:
        return rows(self._read("inventory_assets", self._assets), skipped=self.skipped)

    async def prefixes(self) -> RowCollection[NetboxPrefix]:
        return rows(self._read("prefixes", self._prefixes))

    async def vlans(self) -> RowCollection[NetboxVlan]:
        return rows(self._read("vlans", self._vlans))

    async def ip_addresses(self) -> RowCollection[NetboxAddress]:
        return rows(self._read("ip_addresses", self._addresses))

    async def reserved_ranges(self) -> RowCollection[NetboxRange]:
        return rows(self._read("reserved_ranges", self._ranges))

    async def device_agent_keys(self, field_name: str) -> Any:
        keys = self._read("device_agent_keys", self._agent_keys)
        return netbox_adapter.DeviceAgentKeyCollection(
            tuple(netbox_adapter.DeviceAgentKey(n, k) for n, k in keys.items()),
            NOW,
            self.skipped,
        )

    async def ip_assignments(self) -> Any:
        mapping = self._read("ip_assignments", self._ip_assignments)
        return netbox_adapter.IpAssignmentCollection(
            tuple(
                netbox_adapter.IpAssignment(ip, native, native, None)
                for ip, native in mapping.items()
            ),
            NOW,
            self.skipped,
        )

    async def interfaces_by_mac(self, mac: str) -> MacLookup:
        table = self._read("interfaces_by_mac", self._macs)
        self.lookups.append(mac)
        return MacLookup(mac, tuple(table.get(mac, [])), NOW)


class FakeLibrenms:
    def __init__(self, devices: list[Device] | Exception) -> None:
        self._devices = devices
        self.calls = 0

    async def devices(self) -> DeviceCollection:
        self.calls += 1
        if isinstance(self._devices, Exception):
            raise self._devices
        return DeviceCollection(items=tuple(self._devices), observed_at=NOW)


class FakeWazuh:
    def __init__(
        self, agents: list[WazuhAgent] | Exception, *, truncated: bool = False, skipped: int = 0
    ) -> None:
        self._agents = agents
        self._truncated = truncated
        self._skipped = skipped
        self.calls: list[tuple[datetime, datetime, int]] = []

    async def agents(self, *, start: datetime, end: datetime, limit: int) -> AgentInventory:
        self.calls.append((start, end, limit))
        if isinstance(self._agents, Exception):
            raise self._agents
        return AgentInventory(tuple(self._agents), self._truncated, self._skipped)
