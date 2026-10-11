"""IPAM arithmetic (Step 8b): the prefix tree, utilisation with its basis, and active versus stale.

Pure: no I/O, no clock. NetBox says what is intended (prefixes, VLANs, address records, reserved
ranges); telemetry only says "seen within the window". Nothing is inferred from names, and anything
that cannot be known is stated as unknown rather than computed from a guess:

* the tree is containment of networks of the same VRF and family (never of names);
* utilisation = distinct addresses inside the prefix (NetBox's, plus those telemetry saw that NetBox
  lacks) over the usable capacity, with the basis it was computed on; it is ``unknown`` when the
  addresses could not be read or the capacity is meaningless (a huge IPv6 prefix);
* an address is ``active`` only when a telemetry source saw it, ``stale`` only when telemetry was
  readable and did not, ``unknown`` when it was not readable. Telemetry has no VRF, so it never
  vouches for an address that NetBox places in one;
* a reserved range counts once however it overlaps another, and not on top of addresses already used.
"""

from __future__ import annotations

import ipaddress
from bisect import bisect_left, bisect_right
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final
from uuid import NAMESPACE_URL, uuid5

from netsight_api.adapters.netbox_ipam import (
    NetboxAddress,
    NetboxPrefix,
    NetboxRange,
    NetboxVlan,
)
from netsight_api.schemas_ipam import (
    MAX_LISTED_RANGES,
    Activity,
    IpamActivityCounts,
    IpamAddress,
    IpamCounts,
    IpamPrefix,
    IpamPrefixVlan,
    IpamReservedRange,
    IpamUtilisation,
    IpamVlan,
    TelemetrySource,
    UtilisationBasis,
    percent_of,
)

_IPV6_MAX_HOST_BITS: Final = 16
_Group = tuple[str, int]  # (vrf id or "", address family)
_SOURCE_ORDER: Final[tuple[TelemetrySource, ...]] = ("librenms", "wazuh")


@dataclass(frozen=True)
class Seen:
    """Which telemetry sources saw an address within the window, and the latest time."""

    sources: frozenset[TelemetrySource]
    last_seen: datetime


@dataclass(frozen=True)
class IpamBuild:
    prefixes: tuple[IpamPrefix, ...] | None
    vlans: tuple[IpamVlan, ...] | None
    addresses: tuple[IpamAddress, ...] | None
    activity_counts: IpamActivityCounts | None
    counts: IpamCounts


@dataclass
class _Net:
    record: NetboxPrefix
    group: _Group
    start: int
    end: int
    length: int
    parent: int | None = None  # index into the sorted list
    depth: int = 0
    children: int = 0
    ranges: list[tuple[int, int]] | None = None


def _mint(kind: str, key: str) -> str:
    return f"ipam-{kind}-{uuid5(NAMESPACE_URL, f'urn:netsight:netbox:{kind}:{key}')}"


def _group(vrf_id: str | None, version: int) -> _Group:
    return (vrf_id or "", version)


# --- the tree ---------------------------------------------------------------------------------------------


def _sorted_networks(prefixes: Sequence[NetboxPrefix]) -> list[_Net]:
    nets: list[_Net] = []
    for record in prefixes:
        network = ipaddress.ip_network(record.prefix)
        nets.append(
            _Net(
                record,
                _group(record.vrf_id, record.version),
                int(network.network_address),
                int(network.broadcast_address),
                network.prefixlen,
            )
        )
    nets.sort(key=lambda n: (n.group, n.start, n.length, n.record.native_id))
    return nets


def _link_tree(nets: list[_Net]) -> None:
    """Parent, depth and child counts from containment, one sweep per VRF/family group."""
    stack: list[int] = []
    current: _Group | None = None
    for index, net in enumerate(nets):
        if net.group != current:
            stack, current = [], net.group
        while stack and nets[stack[-1]].end < net.start:
            stack.pop()
        net.parent = stack[-1] if stack else None
        net.depth = len(stack)
        if net.parent is not None:
            nets[net.parent].children += 1
        stack.append(index)


class _TreeIndex:
    """Find the smallest prefix of a group that contains a point or an interval."""

    def __init__(self, nets: list[_Net]) -> None:
        self._nets = nets
        self._positions: dict[_Group, tuple[list[int], list[int]]] = {}
        for index, net in enumerate(nets):
            starts, indexes = self._positions.setdefault(net.group, ([], []))
            starts.append(net.start)
            indexes.append(index)

    def smallest(self, group: _Group, first: int, last: int | None = None) -> int | None:
        found = self._positions.get(group)
        if found is None:
            return None
        starts, indexes = found
        position = bisect_right(starts, first) - 1
        candidate = indexes[position] if position >= 0 else None
        end = first if last is None else last
        while candidate is not None and not (
            self._nets[candidate].start <= first and self._nets[candidate].end >= end
        ):
            candidate = self._nets[candidate].parent
        return candidate


# --- capacity and counting --------------------------------------------------------------------------------


def _capacity(net: _Net) -> int | None:
    host_bits = (32 if net.record.version == 4 else 128) - net.length
    size = 1 << host_bits
    if net.record.version == 6:
        return size if host_bits <= _IPV6_MAX_HOST_BITS else None
    return size if net.record.is_pool or net.length >= 31 else size - 2


def _within(ints: list[int], start: int, end: int) -> list[int]:
    return ints[bisect_left(ints, start) : bisect_right(ints, end)]


def _merge(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _overlap(merged: list[tuple[int, int]], starts: list[int], start: int, end: int) -> int:
    """Addresses of ``[start, end]`` that fall inside the merged (disjoint, sorted) intervals."""
    total = 0
    index = max(0, bisect_right(starts, end) - 1)
    while index >= 0 and merged[index][1] >= start:
        total += max(0, min(end, merged[index][1]) - max(start, merged[index][0]) + 1)
        index -= 1
    return total


def _in_any(merged: list[tuple[int, int]], starts: list[int], value: int) -> bool:
    position = bisect_right(starts, value) - 1
    return position >= 0 and merged[position][1] >= value


@dataclass
class _Inputs:
    netbox_ints: dict[_Group, list[int]]
    discovered_ints: dict[_Group, list[int]]
    merged: dict[_Group, list[tuple[int, int]]]
    merged_starts: dict[_Group, list[int]]
    addresses_ok: bool
    ranges_ok: bool
    telemetry_ok: bool


def _utilisation(net: _Net, data: _Inputs) -> IpamUtilisation:
    record = net.record
    capacity = _capacity(net)
    if record.mark_utilized:
        return _marked(net, data, capacity)
    if not data.addresses_ok:
        return _unknown("addresses-unavailable", capacity)
    if capacity is None:
        return _unknown("capacity-not-meaningful", None)
    nb = _within(data.netbox_ints.get(net.group, []), net.start, net.end)
    disc = _within(data.discovered_ints.get(net.group, []), net.start, net.end)
    reserved = _reserved_in(net, data, nb, disc)
    used = len(nb) + len(disc)
    basis: UtilisationBasis = (
        "netbox-and-discovered" if data.telemetry_ok and not record.vrf_id else "netbox-addresses"
    )
    return IpamUtilisation(
        state="ok",
        basis=basis,
        capacity=capacity,
        netbox_addresses=len(nb),
        discovered_only=len(disc),
        used=used,
        reserved=reserved,
        free=None if reserved is None else max(0, capacity - used - reserved),
        percent=percent_of(used, capacity),
    )


def _unknown(basis: UtilisationBasis, capacity: int | None) -> IpamUtilisation:
    return IpamUtilisation(
        state="unknown",
        basis=basis,
        capacity=capacity if basis == "addresses-unavailable" else None,
        netbox_addresses=None,
        discovered_only=None,
        used=None,
        reserved=None,
        free=None,
        percent=None,
    )


def _marked(net: _Net, data: _Inputs, capacity: int | None) -> IpamUtilisation:
    nb = (
        _within(data.netbox_ints.get(net.group, []), net.start, net.end)
        if data.addresses_ok
        else None
    )
    disc = (
        _within(data.discovered_ints.get(net.group, []), net.start, net.end)
        if data.addresses_ok
        else None
    )
    used = None if nb is None or disc is None else len(nb) + len(disc)
    return IpamUtilisation(
        state="ok",
        basis="marked-utilized",
        capacity=capacity,
        netbox_addresses=None if nb is None else len(nb),
        discovered_only=None if disc is None else len(disc),
        used=used,
        reserved=None,
        free=None,
        percent=100,
    )


def _reserved_in(net: _Net, data: _Inputs, nb: list[int], disc: list[int]) -> int | None:
    if not data.ranges_ok:
        return None
    merged = data.merged.get(net.group, [])
    if not merged:
        return 0
    starts = data.merged_starts[net.group]
    covered = _overlap(merged, starts, net.start, net.end)
    already_used = sum(1 for value in {*nb, *disc} if _in_any(merged, starts, value))
    return max(0, covered - already_used)


# --- assembly ---------------------------------------------------------------------------------------------


def _range_listing(nets: list[_Net], index: _TreeIndex, ranges: Sequence[NetboxRange]) -> None:
    for item in ranges:
        group = _group(item.vrf_id, item.version)
        start, end = int(ipaddress.ip_address(item.start)), int(ipaddress.ip_address(item.end))
        owner = index.smallest(group, start, end)
        if owner is not None:
            holder = nets[owner]
            holder.ranges = (holder.ranges or []) + [(start, end)]


def _prefix_items(
    nets: list[_Net], vlan_by_native: Mapping[str, str], data: _Inputs
) -> tuple[IpamPrefix, ...]:
    del vlan_by_native
    ids = [_mint("prefix", n.record.native_id) for n in nets]
    items: list[IpamPrefix] = []
    for position, net in enumerate(nets):
        record = net.record
        listed = sorted(set(net.ranges or []))
        items.append(
            IpamPrefix(
                id=ids[position],
                prefix=record.prefix,
                version=record.version,  # type: ignore[arg-type]
                vrf=record.vrf_name or record.vrf_id,
                status=record.status,
                site=record.site,
                role=record.role,
                vlan=(
                    IpamPrefixVlan(vid=record.vlan_vid, name=record.vlan_name)
                    if record.vlan_vid is not None and record.vlan_name is not None
                    else None
                ),
                description=record.description,
                parent_id=None if net.parent is None else ids[net.parent],
                depth=net.depth,
                children=net.children,
                utilisation=_utilisation(net, data),
                reserved_ranges=[
                    IpamReservedRange(
                        start=str(_to_address(record.version, s)),
                        end=str(_to_address(record.version, e)),
                        size=e - s + 1,
                    )
                    for s, e in listed[:MAX_LISTED_RANGES]
                ],
                reserved_ranges_total=len(listed),
            )
        )
    return tuple(items)


def _to_address(version: int, value: int) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    return ipaddress.IPv4Address(value) if version == 4 else ipaddress.IPv6Address(value)


def _vlan_items(
    vlans: Sequence[NetboxVlan], prefixes: Sequence[NetboxPrefix] | None
) -> tuple[IpamVlan, ...]:
    named: dict[str, int] = defaultdict(int)
    for record in prefixes or []:
        if record.vlan_native_id is not None:
            named[record.vlan_native_id] += 1
    ordered = sorted(vlans, key=lambda v: (v.vid, v.name.casefold(), v.native_id))
    return tuple(
        IpamVlan(
            id=_mint("vlan", v.native_id),
            vid=v.vid,
            name=v.name,
            status=v.status,
            site=v.site,
            group=v.group,
            description=v.description,
            prefix_count=None if prefixes is None else named[v.native_id],
        )
        for v in ordered
    )


@dataclass(frozen=True)
class _Address:
    ip: int
    version: int
    record: NetboxAddress | None
    text: str


def _address_items(
    netbox: Sequence[NetboxAddress],
    seen: Mapping[str, Seen] | None,
    nets: list[_Net],
    index: _TreeIndex,
    prefix_ids: list[str],
) -> tuple[IpamAddress, ...]:
    global_netbox = {a.address for a in netbox if not a.vrf_id}
    rows: list[_Address] = [
        _Address(int(ipaddress.ip_address(a.address)), a.version, a, a.address) for a in netbox
    ]
    for text in seen or {}:
        if text not in global_netbox:
            parsed = ipaddress.ip_address(text)
            rows.append(_Address(int(parsed), parsed.version, None, text))
    rows.sort(key=lambda r: (r.version, r.ip, r.record.native_id if r.record else ""))
    items: list[IpamAddress] = []
    for row in rows:
        record = row.record
        witness = (
            seen.get(row.text)
            if seen is not None and (record is None or not record.vrf_id)
            else None
        )
        owner = index.smallest(_group(record.vrf_id if record else None, row.version), row.ip)
        activity = _activity(record, witness, seen is not None)
        items.append(
            IpamAddress(
                id=(
                    _mint("address", record.native_id)
                    if record
                    else f"ipam-address-{uuid5(NAMESPACE_URL, f'urn:netsight:discovered:address:{row.text}')}"
                ),
                address=row.text,
                version=row.version,  # type: ignore[arg-type]
                prefix_id=None if owner is None else prefix_ids[owner],
                vrf=None if record is None else (record.vrf_id or None),
                status=None if record is None else record.status,
                dns_name=None if record is None else record.dns_name,
                description=None if record is None else record.description,
                source="discovered" if record is None else ("both" if witness else "netbox"),
                activity=activity,
                seen_by=[s for s in _SOURCE_ORDER if witness and s in witness.sources],
                last_seen=witness.last_seen if witness else None,
            )
        )
    del nets
    return tuple(items)


def _activity(record: NetboxAddress | None, witness: Seen | None, telemetry_ok: bool) -> Activity:
    if witness is not None:
        return "active"
    if record is not None and record.status == "reserved":
        return "reserved"
    return "stale" if telemetry_ok else "unknown"


def build_ipam(
    *,
    prefixes: Sequence[NetboxPrefix] | None,
    vlans: Sequence[NetboxVlan] | None,
    addresses: Sequence[NetboxAddress] | None,
    ranges: Sequence[NetboxRange] | None,
    seen: Mapping[str, Seen] | None,
) -> IpamBuild:
    """Everything IPAM shows. ``None`` for a NetBox dataset (or telemetry) means it was unreadable."""
    nets = _sorted_networks(prefixes or [])
    _link_tree(nets)
    index = _TreeIndex(nets)
    if ranges is not None:
        _range_listing(nets, index, ranges)
    data = _inputs(addresses, ranges, seen)
    prefix_items = _prefix_items(nets, {}, data) if prefixes is not None else None
    prefix_ids = [p.id for p in prefix_items] if prefix_items is not None else []
    address_items = (
        _address_items(addresses, seen, nets, index, prefix_ids)
        if addresses is not None and prefixes is not None
        else _address_items(addresses, seen, [], _TreeIndex([]), [])
        if addresses is not None
        else None
    )
    activity = _activity_counts(address_items)
    return IpamBuild(
        prefixes=prefix_items,
        vlans=_vlan_items(vlans, prefixes) if vlans is not None else None,
        addresses=address_items,
        activity_counts=activity,
        counts=_counts(prefixes, vlans, addresses, ranges, seen, address_items, activity),
    )


def _inputs(
    addresses: Sequence[NetboxAddress] | None,
    ranges: Sequence[NetboxRange] | None,
    seen: Mapping[str, Seen] | None,
) -> _Inputs:
    netbox: dict[_Group, set[int]] = defaultdict(set)
    discovered: dict[_Group, set[int]] = defaultdict(set)
    global_ips: set[str] = set()
    for a in addresses or []:
        netbox[_group(a.vrf_id, a.version)].add(int(ipaddress.ip_address(a.address)))
        if not a.vrf_id:
            global_ips.add(a.address)
    for text in seen or {}:
        if text not in global_ips:
            parsed = ipaddress.ip_address(text)
            discovered[_group(None, parsed.version)].add(int(parsed))
    grouped: dict[_Group, list[tuple[int, int]]] = defaultdict(list)
    for item in ranges or []:
        grouped[_group(item.vrf_id, item.version)].append(
            (int(ipaddress.ip_address(item.start)), int(ipaddress.ip_address(item.end)))
        )
    merged = {group: _merge(intervals) for group, intervals in grouped.items()}
    return _Inputs(
        netbox_ints={g: sorted(v) for g, v in netbox.items()},
        discovered_ints={g: sorted(v) for g, v in discovered.items()},
        merged=merged,
        merged_starts={g: [s for s, _ in v] for g, v in merged.items()},
        addresses_ok=addresses is not None,
        ranges_ok=ranges is not None,
        telemetry_ok=seen is not None,
    )


def _activity_counts(items: tuple[IpamAddress, ...] | None) -> IpamActivityCounts | None:
    if items is None:
        return None
    tally = {"active": 0, "stale": 0, "unknown": 0, "reserved": 0}
    for item in items:
        tally[item.activity] += 1
    return IpamActivityCounts(**tally)


def _counts(
    prefixes: Sequence[NetboxPrefix] | None,
    vlans: Sequence[NetboxVlan] | None,
    addresses: Sequence[NetboxAddress] | None,
    ranges: Sequence[NetboxRange] | None,
    seen: Mapping[str, Seen] | None,
    items: tuple[IpamAddress, ...] | None,
    activity: IpamActivityCounts | None,
) -> IpamCounts:
    judged = seen is not None and activity is not None
    return IpamCounts(
        prefixes=None if prefixes is None else len(prefixes),
        vlans=None if vlans is None else len(vlans),
        addresses=None if addresses is None else len(addresses),
        reserved_ranges=None if ranges is None else len(ranges),
        active_addresses=activity.active if judged and activity else None,
        stale_addresses=activity.stale if judged and activity else None,
        unknown_activity_addresses=None if activity is None else activity.unknown,
        discovered_only_addresses=(
            sum(1 for i in items if i.source == "discovered")
            if judged and items is not None
            else None
        ),
    )
