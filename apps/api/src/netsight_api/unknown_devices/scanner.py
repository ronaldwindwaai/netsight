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
  (if the operator configured that join), because an unjoined agent would look unknown;
* NetBox rows dropped as malformed make the data incomplete: a positive match still clears, but no
  finding is made from it (the endpoint is *unverified*) and the source is reported in
  ``incomplete_sources``;
* one detection the store refuses (or that can not be built) is counted unverified, never aborting
  the others; a store that is *down* does fail the scan loudly.

Only one scan runs at a time, and not more than one a minute: the scheduled cycle and the API share
a ``ScanGuard``. A second request while one runs is refused (``ScanBusy``, HTTP 429 with
Retry-After); one inside the minimum interval gets the last result instead of a new scan.
"""

from __future__ import annotations

import asyncio
import logging
import math
import threading
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, replace
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
from netsight_api.audit import record_audit
from netsight_api.identity.engine import MAX_RECORDS, CorrelationIndex
from netsight_api.identity.model import KIND_PROFILES, CorrelationPolicy, EvidenceRecord, Relation
from netsight_api.identity.sources import EvidenceSource
from netsight_api.inventory.sources import SourceRead, not_connected, read_bounded
from netsight_api.reconcile import match_key
from netsight_api.schemas_inventory import BlockState
from netsight_api.schemas_sources import SourceName, SourceStatus
from netsight_api.schemas_unknown_devices import SYSTEM_ACTOR
from netsight_api.storage import InvalidOperationError, StorageConflictError
from netsight_api.storage.unknown_devices import UnknownDeviceRepository
from netsight_api.unknown_devices import detect as d
from netsight_api.unknown_devices.model import Detection
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
MIN_SCAN_INTERVAL_SECONDS: Final = 60.0
SCHEDULED_SCAN_ACTION: Final = "unknown-device.scan.scheduled"


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
    incomplete_sources: tuple[SourceName, ...] = ()


class ScanBusy(Exception):
    """Another scan is running; ``retry_after`` is a whole number of seconds (at least 1)."""

    def __init__(self, retry_after: int) -> None:
        super().__init__("a scan is already running")
        self.retry_after = max(1, retry_after)


class ScanGuard:
    """One scan at a time, and at least ``min_interval`` seconds apart.

    Non-blocking: a caller that finds a scan running is refused (``ScanBusy``), never queued, so a
    burst of requests costs one scan and one refusal each. A caller inside the minimum interval gets
    the last result. A failed scan is not remembered, so the next caller may try again at once.
    """

    def __init__(
        self,
        *,
        min_interval: float = MIN_SCAN_INTERVAL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._min_interval = min_interval
        self._clock = clock
        self._lock = threading.Lock()  # held across awaits on purpose: only acquired non-blocking
        self._last: ScanResult | None = None
        self._started_at = 0.0
        self._finished_at = 0.0

    async def run(self, scan: Callable[[], Awaitable[ScanResult]]) -> ScanResult:
        if not self._lock.acquire(blocking=False):
            raise ScanBusy(math.ceil(self._min_interval - (self._clock() - self._started_at)))
        try:
            now = self._clock()
            if self._last is not None and now - self._finished_at < self._min_interval:
                return self._last
            self._started_at = now
            result = await scan()
            self._last, self._finished_at = result, self._clock()
            return result
        finally:
            self._lock.release()


@dataclass(frozen=True)
class _Reads:
    """Everything one scan read from its sources before it compares anything."""

    netbox: SourceRead[object]
    facts: d.NetboxFacts | None
    libre: SourceRead[DeviceCollection]
    keys: SourceRead[dict[str, str]]
    wazuh: SourceRead[AgentInventory]

    def statuses(self, now: datetime) -> tuple[SourceStatus, ...]:
        return (
            SourceStatus(
                source="netbox",
                state=self.netbox.state if self.facts is not None else "unknown",
                observed_at=now if self.facts is not None else None,
            ),
            self.libre.status("librenms"),
            self.wazuh.status("wazuh"),
        )

    def incomplete(self) -> tuple[SourceName, ...]:
        names: list[SourceName] = []
        if self.facts is not None and self.facts.incomplete:
            names.append("netbox")
        if self.wazuh.value is not None and self.wazuh.value.skipped > 0:
            names.append("wazuh")
        return tuple(names)


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
        guard: ScanGuard | None = None,
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
        self._guard = guard

    async def run_cycle(self) -> ScanResult | None:
        """One scheduled scan. A scan already running (or just finished) is not an error."""
        try:
            result = await self.scan()
        except ScanBusy:
            _LOGGER.info("scheduled unknown-device scan skipped: a scan is already running")
            return None
        record_audit(
            SCHEDULED_SCAN_ACTION,
            outcome="success",
            actor_id=SYSTEM_ACTOR,
            correlation_id="scheduled-scan",
            state=result.state,
            created=result.created,
            refreshed=result.refreshed,
            suppressed=result.suppressed,
            unverified=result.unverified,
            truncated=result.truncated,
            incomplete=",".join(result.incomplete_sources),
        )
        return result

    async def scan(self) -> ScanResult:
        """Compare now. Through the shared guard when there is one (the API and the scheduler)."""
        if self._guard is None:
            return await self._scan()
        return await self._guard.run(self._scan)

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
            incomplete=assets.value.skipped > 0 or assignments.value.skipped > 0,
        )
        return SourceRead("ok", None, now), facts, names

    async def _agent_keys(
        self, now: datetime, names: dict[str, str]
    ) -> tuple[SourceRead[dict[str, str]], bool]:
        """agent id -> NetBox device name when the operator configured the join; and whether
        rows were dropped (then an agent's key may be missing, so no agent can be called unknown)."""
        if self._netbox is None or self._agent_field is None:
            return SourceRead("ok", {}, now), False
        read = await self._bounded(
            "netbox-agent-keys", self._netbox.device_agent_keys(self._agent_field), now
        )
        if not read.ok or read.value is None:
            return SourceRead("unknown"), False
        keys = {
            k.agent_key: names.get(k.device_native_id, k.device_native_id) for k in read.value.items
        }
        return SourceRead("ok", keys, now), read.value.skipped > 0

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

    async def _read_sources(self, now: datetime) -> _Reads:
        netbox_read, facts, names = await self._netbox_facts(now)
        libre = (
            await self._bounded("librenms", self._librenms.devices(), now)
            if self._librenms is not None
            else not_connected()
        )
        if facts is None:
            wazuh_read = await self._wazuh_read(now, SourceRead("unknown"))
            return _Reads(netbox_read, None, libre, SourceRead("unknown"), wazuh_read)
        keys, keys_incomplete = await self._agent_keys(now, names)
        wazuh_read = await self._wazuh_read(now, keys)
        if keys_incomplete:
            facts = replace(facts, incomplete=True)
        return _Reads(netbox_read, facts, libre, keys, wazuh_read)

    # -- the scan --

    async def _scan(self) -> ScanResult:
        now = self._clock()
        if self._netbox is None:
            return ScanResult(
                "not-connected",
                now,
                (SourceStatus(source="netbox", state="not-connected", observed_at=None),),
            )
        reads = await self._read_sources(now)
        if reads.facts is None:
            return ScanResult("unknown", now, reads.statuses(now))
        records, capable = await self._evidence(now)
        index = await asyncio.to_thread(CorrelationIndex, records, self._correlation)
        candidates, truncated = d.collect_candidates(
            self._observations(reads.libre, reads.wazuh), records, index, self._correlation, now
        )
        facts = replace(reads.facts, keyed_agents=reads.keys.value or {})
        results = await self._lookups(await self._lookup_order(candidates, facts))
        outcome = d.detect(
            candidates,
            facts=facts,
            mac_results=results,
            index=index,
            policy=self._policy,
            capabilities=capable,
            now=now,
        )
        tally, refused = await self._record(outcome.detections)
        unverified = outcome.unverified + refused
        if unverified:
            _LOGGER.warning(
                "unknown-device scan left endpoints unverified",
                extra={"unverified": unverified, "incomplete": ",".join(reads.incomplete())},
            )
        return ScanResult(
            "ok",
            now,
            reads.statuses(now),
            tally["created"],
            tally["refreshed"],
            tally["suppressed"],
            unverified,
            truncated,
            reads.incomplete(),
        )

    async def _lookup_order(
        self, candidates: Sequence[d.Candidate], facts: d.NetboxFacts
    ) -> list[str]:
        """The MACs to ask NetBox about, endpoints never seen before first, then the most recent."""
        keys = sorted({key for c in candidates for key in d.candidate_keys(c)})
        known = await asyncio.to_thread(self._store.known_subject_keys, keys)
        return d.macs_to_check(candidates, facts, known_subjects=known)

    async def _record(self, detections: Sequence[Detection]) -> tuple[dict[str, int], int]:
        """Write each detection; one the store refuses is unverified, a store that is down fails."""
        tally = {"created": 0, "refreshed": 0, "suppressed": 0}
        refused = 0
        for detection in detections:
            try:
                observation = await asyncio.to_thread(self._store.observe, detection)
            except (InvalidOperationError, StorageConflictError, ValueError):
                _LOGGER.warning("a detection could not be recorded; counted unverified")
                refused += 1
                continue
            tally[observation.outcome] += 1
        return tally, refused

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
