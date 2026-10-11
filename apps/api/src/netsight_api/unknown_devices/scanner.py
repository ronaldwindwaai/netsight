"""The unknown-device scan: read the sources, compare with NetBox, record findings (Step 8c).

What it reads (all read-only, through the clients the platform already has): NetBox devices, the
addresses it assigned to device interfaces and, per candidate MAC, the interfaces that carry it;
LibreNMS devices; Wazuh agents; and any ``EvidenceSource`` (DHCP, switch MAC table, Wi-Fi ...) that is
wired. What it writes: Netsight's own finding store, nothing else. **It never writes to NetBox or any
monitored system.**

A source it cannot read makes the answer smaller, never wrong:

* NetBox not configured, or devices or interface addresses unreadable: no comparison and no change
  at all (otherwise everything seen would look unknown);
* a discovery source unreadable or cut short: its endpoints are left out of this scan;
* NetBox unable to answer for one MAC (error, or past the lookup limit): that endpoint is
  *unverified*, counted and skipped, never recorded;
* the Wazuh agent list is used only when the keys that join agents to NetBox devices could be read
  (if the operator configured that join), because an unjoined agent would look unknown.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Protocol

from netsight_api.adapters.librenms import DeviceCollection
from netsight_api.adapters.netbox import (
    DeviceAgentKeyCollection,
    IpAssignmentCollection,
    MacLookup,
    NetboxAsset,
    RowCollection,
)
from netsight_api.adapters.wazuh import AgentInventory
from netsight_api.identity.engine import MAX_RECORDS, CorrelationIndex
from netsight_api.identity.model import KIND_PROFILES, CorrelationPolicy, EvidenceRecord, Relation
from netsight_api.identity.sources import EvidenceSource
from netsight_api.inventory.sources import SourceRead, not_connected, read_bounded
from netsight_api.reconcile import match_key
from netsight_api.schemas_inventory import BlockState
from netsight_api.schemas_sources import SourceStatus
from netsight_api.storage.unknown_devices import UnknownDeviceRepository
from netsight_api.unknown_devices import detect as d
from netsight_api.unknown_devices.policy import SeverityPolicy

_LOGGER: Final = logging.getLogger("netsight_api")

SOURCE_BUDGET_SECONDS: Final = 25.0
MAC_LOOKUP_BUDGET_SECONDS: Final = 10.0
MAX_MAC_LOOKUPS: Final = 100
MAC_CONCURRENCY: Final = 5
AGENT_WINDOW: Final = timedelta(hours=24)
AGENT_LIMIT: Final = 2500
EVIDENCE_WINDOW: Final = timedelta(hours=2)
EVIDENCE_LIMIT: Final = 2500


class NetboxScanReader(Protocol):
    async def inventory_assets(self) -> RowCollection[NetboxAsset]: ...
    async def ip_assignments(self) -> IpAssignmentCollection: ...
    async def device_agent_keys(self, field_name: str) -> DeviceAgentKeyCollection: ...
    async def interfaces_by_mac(self, mac: str) -> MacLookup: ...


class DeviceReader(Protocol):
    async def devices(self) -> DeviceCollection: ...


class AgentReader(Protocol):
    async def agents(self, *, start: datetime, end: datetime, limit: int) -> AgentInventory: ...


class Clock(Protocol):
    def __call__(self) -> datetime: ...


@dataclass(frozen=True)
class ScanResult:
    state: BlockState
    generated_at: datetime
    sources: tuple[SourceStatus, ...]
    created: int = 0
    refreshed: int = 0
    suppressed: int = 0
    unverified: int = 0
    truncated: bool = False


class UnknownDeviceScanner:
    def __init__(
        self,
        *,
        netbox: NetboxScanReader | None,
        librenms: DeviceReader | None,
        wazuh: AgentReader | None,
        agent_field: str | None,
        evidence_sources: Sequence[EvidenceSource],
        store: UnknownDeviceRepository,
        policy: SeverityPolicy,
        correlation: CorrelationPolicy,
        clock: Clock,
    ) -> None:
        self._netbox = netbox
        self._librenms = librenms
        self._wazuh = wazuh
        self._agent_field = agent_field
        self._evidence_sources = list(evidence_sources)
        self._store = store
        self._policy = policy
        self._correlation = correlation
        self._clock = clock

    async def run_cycle(self) -> ScanResult:
        """One scan, for the scheduler (which logs a failure and tries again next interval)."""
        return await self.scan()

    # -- reading --

    @staticmethod
    async def _bounded[T](name: str, call: Awaitable[T], now: datetime) -> SourceRead[T]:
        async def run() -> T:
            return await call

        return await read_bounded(name, run, budget=SOURCE_BUDGET_SECONDS, now=now)

    async def _netbox_facts(
        self, now: datetime
    ) -> tuple[SourceRead[object], d.NetboxFacts | None, dict[str, str]]:
        """NetBox's devices and addresses, or ``None`` facts when the comparison cannot be made."""
        assert self._netbox is not None
        assets, assignments = await asyncio.gather(
            self._bounded("netbox", self._netbox.inventory_assets(), now),
            self._bounded("netbox-ips", self._netbox.ip_assignments(), now),
        )
        if not (assets.ok and assignments.ok) or assets.value is None or assignments.value is None:
            return SourceRead("unknown"), None, {}
        names = {a.device.source_aliases[0].native_id: a.device.name for a in assets.value.items}
        facts = d.NetboxFacts(
            device_names=frozenset(
                key
                for a in assets.value.items
                for key in {match_key(a.device), a.device.name.strip().lower()}
            ),
            primary_ips={
                ip: a.device.name for a in assets.value.items for ip in a.device.ip_addresses
            },
            assigned_ips={
                i.address: i.device_name or i.device_native_id for i in assignments.value.items
            },
        )
        return SourceRead("ok", None, now), facts, names

    async def _agent_keys(self, now: datetime, names: dict[str, str]) -> SourceRead[dict[str, str]]:
        """agent id -> NetBox device name, when the operator configured the join."""
        if self._netbox is None or self._agent_field is None:
            return SourceRead("ok", {}, now)
        read = await self._bounded(
            "netbox-agent-keys", self._netbox.device_agent_keys(self._agent_field), now
        )
        if not read.ok or read.value is None:
            return SourceRead("unknown")
        return SourceRead(
            "ok",
            {
                k.agent_key: names.get(k.device_native_id, k.device_native_id)
                for k in read.value.items
            },
            now,
        )

    async def _evidence(self, now: datetime) -> tuple[list[EvidenceRecord], set[Relation]]:
        records: list[EvidenceRecord] = []
        capable: set[Relation] = set()
        for source in self._evidence_sources:
            read = await self._bounded(
                source.name,
                source.fetch(start=now - EVIDENCE_WINDOW, end=now, limit=EVIDENCE_LIMIT),
                now,
            )
            batch = read.value
            if not read.ok or batch is None or batch.truncated:
                continue
            if any(r.source != source.name or r.kind not in source.kinds for r in batch.records):
                _LOGGER.warning(
                    "an evidence source emitted records it does not own",
                    extra={"source": source.name},
                )
                continue
            records.extend(batch.records)
            for kind in source.kinds:
                capable |= set(KIND_PROFILES[kind].relations)
        return records[:MAX_RECORDS], capable

    # -- the scan --

    async def scan(self) -> ScanResult:
        now = self._clock()
        if self._netbox is None:
            return ScanResult(
                "not-connected",
                now,
                (SourceStatus(source="netbox", state="not-connected", observed_at=None),),
            )
        netbox_read, facts, names = await self._netbox_facts(now)
        libre = (
            await self._bounded("librenms", self._librenms.devices(), now)
            if self._librenms is not None
            else not_connected()
        )
        keys = await self._agent_keys(now, names) if facts is not None else SourceRead("unknown")
        wazuh_read = await self._wazuh_read(now, keys)
        sources = (
            SourceStatus(
                source="netbox",
                state=netbox_read.state if facts is not None else "unknown",
                observed_at=now if facts is not None else None,
            ),
            libre.status("librenms"),
            wazuh_read.status("wazuh"),
        )
        if facts is None:
            return ScanResult("unknown", now, sources)
        assert self._netbox is not None
        keyed = keys.value or {}
        records, capable = await self._evidence(now)
        observations = self._observations(libre, wazuh_read)
        index = await asyncio.to_thread(CorrelationIndex, records, self._correlation)
        candidates, truncated = d.collect_candidates(
            observations, records, index, self._correlation, now
        )
        facts = d.NetboxFacts(facts.device_names, facts.primary_ips, facts.assigned_ips, keyed)
        results = await self._lookups(d.macs_to_check(candidates, facts))
        outcome = d.detect(
            candidates,
            facts=facts,
            mac_results=results,
            index=index,
            policy=self._policy,
            capabilities=capable,
            now=now,
        )
        tally = {"created": 0, "refreshed": 0, "suppressed": 0}
        for detection in outcome.detections:
            observation = await asyncio.to_thread(self._store.observe, detection)
            tally[observation.outcome] += 1
        return ScanResult(
            "ok",
            now,
            sources,
            tally["created"],
            tally["refreshed"],
            tally["suppressed"],
            outcome.unverified,
            truncated,
        )

    async def _wazuh_read(
        self, now: datetime, keys: SourceRead[dict[str, str]]
    ) -> SourceRead[AgentInventory]:
        if self._wazuh is None:
            return not_connected()
        if not keys.ok:  # the join that would clear known agents is unreadable: do not judge them
            return SourceRead("unknown")
        read = await self._bounded(
            "wazuh", self._wazuh.agents(start=now - AGENT_WINDOW, end=now, limit=AGENT_LIMIT), now
        )
        if read.ok and read.value is not None and read.value.truncated:
            return SourceRead("unknown")
        return read

    @staticmethod
    def _observations(
        libre: SourceRead[DeviceCollection], wazuh: SourceRead[AgentInventory]
    ) -> list[d.Observed]:
        observed: list[d.Observed] = []
        if libre.ok and libre.value is not None:
            for device in libre.value.items:
                observed.append(
                    d.Observed(
                        "librenms",
                        "device-poll",
                        device.source_aliases[0].native_id,
                        libre.value.observed_at,
                        ip=device.ip_addresses[0] if device.ip_addresses else None,
                        mac=device.mac_addresses[0] if device.mac_addresses else None,
                        hostname=device.hostname or device.name,
                    )
                )
        if wazuh.ok and wazuh.value is not None:
            for agent in wazuh.value.agents:
                if agent.status in ("never_connected", "pending"):
                    continue
                observed.append(
                    d.Observed(
                        "wazuh",
                        "agent-status",
                        agent.agent_id,
                        agent.last_keep_alive or agent.observed_at,
                        ip=agent.ip,
                        hostname=agent.name,
                    )
                )
        return observed

    async def _lookups(self, macs: list[str]) -> dict[str, d.MacCheck]:
        assert self._netbox is not None
        netbox = self._netbox
        gate = asyncio.Semaphore(MAC_CONCURRENCY)
        results: dict[str, d.MacCheck] = {}

        async def one(mac: str) -> None:
            async with gate:
                try:
                    lookup = await asyncio.wait_for(
                        netbox.interfaces_by_mac(mac), MAC_LOOKUP_BUDGET_SECONDS
                    )
                except Exception as error:  # noqa: BLE001 - a source boundary: unverified, not unknown
                    _LOGGER.warning(
                        "netbox mac lookup failed", extra={"error_type": type(error).__name__}
                    )
                    results[mac] = d.MacCheck(
                        "not-checked", "NetBox could not be asked", incomplete=True
                    )
                    return
            results[mac] = (
                d.MacCheck("match", "NetBox has an interface with this MAC address")
                if lookup.matches
                else d.MacCheck("no-match")
            )

        await asyncio.gather(*(one(m) for m in macs[:MAX_MAC_LOOKUPS]))
        for mac in macs[MAX_MAC_LOOKUPS:]:
            results[mac] = d.MacCheck(
                "not-checked", "past the NetBox lookup limit for one scan", incomplete=True
            )
        return results


ScanFactory = Callable[[], UnknownDeviceScanner]
