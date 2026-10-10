"""The diagnostic path: User -> AP -> Access switch -> Core -> Firewall -> Server (S7 Step 4d).

Pure. The path is built only from the explicit topology (NetBox cables): starting at the
resolved target it follows one explicit cable per tier, outward: firewall, core, access switch,
access point. A tier that no explicit cable establishes is ``unknown``, and so is everything
beyond it because there is no link to follow. A tier with two candidate devices is not chosen
between. The user end is always unknown: end users are not in the explicit topology. Roles are
matched against a fixed vocabulary; an unrecognised role never becomes a tier.

Device names are untrusted source text: stripped of control characters and bounded, never
interpreted.
"""

from __future__ import annotations

import ipaddress
import unicodedata
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from itertools import pairwise
from typing import Final

from netsight_api.schemas import StoreState
from netsight_api.schemas_diagnostic_session import (
    PATH_TIERS,
    DiagnosticPath,
    DiagnosticPathHop,
    DiagnosticPathLink,
    PathTier,
    suspected_tier,
)
from netsight_api.schemas_diagnostics import FaultDomain

_MAX_NAME = 255

_ROLE_TIERS: Final[dict[str, PathTier]] = {
    **dict.fromkeys(
        ("access-point", "ap", "wireless-ap", "wifi-ap", "wap", "wireless-access-point"),
        "access-point",
    ),
    **dict.fromkeys(
        ("access-switch", "access", "edge-switch", "tor-switch", "top-of-rack", "tor"),
        "access-switch",
    ),
    **dict.fromkeys(("core", "core-switch", "core-router"), "core"),
    **dict.fromkeys(
        ("firewall", "fw", "ngfw", "next-gen-firewall", "security-appliance"), "firewall"
    ),
}
# Outward from the server: the order the chain is followed in.
_OUTWARD: Final[tuple[PathTier, ...]] = ("firewall", "core", "access-switch", "access-point")


@dataclass(frozen=True)
class TopologyDevice:
    """A NetBox device as the path needs it; ``role`` is the source's own role/type text."""

    device_id: str
    name: str
    role: str | None
    hostname: str | None
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class TopologyLink:
    """One explicit cable between two devices (undirected)."""

    a: str
    b: str


@dataclass(frozen=True)
class TopologyRead:
    """The topology source outcome: devices and cables exist only when the state is ok."""

    state: StoreState
    devices: tuple[TopologyDevice, ...]
    links: tuple[TopologyLink, ...]
    observed_at: datetime | None


def _clean_name(raw: str) -> str | None:
    printable = "".join(
        " " if unicodedata.category(ch) in {"Cc", "Cf", "Zl", "Zp"} else ch for ch in raw
    )
    cleaned = " ".join(printable.split())[:_MAX_NAME].strip()
    return cleaned or None


def _tier_of(device: TopologyDevice) -> PathTier | None:
    if device.role is None:
        return None
    key = "-".join(device.role.strip().lower().replace("_", " ").split())
    return _ROLE_TIERS.get(key)


def _bare_address(value: str) -> str:
    text = value.strip()
    try:
        return str(ipaddress.ip_interface(text).ip)
    except ValueError:
        return text.lower()


def _keys(device: TopologyDevice) -> set[str]:
    keys = {device.name.strip().lower()}
    if device.hostname:
        keys.add(device.hostname.strip().lower())
    keys.update(_bare_address(address) for address in device.addresses)
    keys.discard("")
    return keys


def resolve_target(devices: tuple[TopologyDevice, ...], target: str) -> TopologyDevice | None:
    """The one device the target names exactly (name, hostname or address); None if none or many."""
    wanted = _bare_address(target) if target.strip() else ""
    wanted_name = target.strip().lower()
    matches = [d for d in devices if wanted_name in _keys(d) or wanted in _keys(d)]
    return matches[0] if len(matches) == 1 else None


def _adjacency(read: TopologyRead) -> dict[str, list[str]]:
    known = {device.device_id for device in read.devices}
    neighbours: dict[str, list[str]] = defaultdict(list)
    for cable in read.links:
        if cable.a == cable.b or cable.a not in known or cable.b not in known:
            continue
        neighbours[cable.a].append(cable.b)
        neighbours[cable.b].append(cable.a)
    return neighbours


def _unknown(tier: PathTier, highlight: bool) -> DiagnosticPathHop:
    return DiagnosticPathHop(
        tier=tier,
        state="unknown",
        device_id=None,
        name=None,
        highlight="suspected" if highlight else None,
    )


def _chain(
    server: TopologyDevice, read: TopologyRead
) -> dict[PathTier, tuple[TopologyDevice, str]]:
    """tier -> (device, cleaned name) for every tier an explicit cable establishes."""
    by_id = {device.device_id: device for device in read.devices}
    neighbours = _adjacency(read)
    found: dict[PathTier, tuple[TopologyDevice, str]] = {}
    current = server
    used = {server.device_id}
    for tier in _OUTWARD:
        candidates: dict[str, tuple[TopologyDevice, str]] = {}
        for neighbour_id in neighbours.get(current.device_id, ()):
            neighbour = by_id[neighbour_id]
            name = _clean_name(neighbour.name)
            if neighbour_id in used or name is None or _tier_of(neighbour) != tier:
                continue
            candidates[neighbour_id] = (neighbour, name)
        if len(candidates) != 1:
            break  # nothing, or an ambiguous pair: no link to follow, so the rest stays unknown
        ((current, name),) = candidates.values()
        used.add(current.device_id)
        found[tier] = (current, name)
    return found


def build_path(read: TopologyRead, target: str, domain: FaultDomain | None) -> DiagnosticPath:
    """The explicit path around ``target``; ``domain`` only decides which tier is *suspected*."""
    if read.state != "ok":
        return DiagnosticPath(state=read.state, observed_at=None, hops=[], links=[])
    server = resolve_target(read.devices, target)
    server_name = None if server is None else _clean_name(server.name)
    if server is None or server_name is None or read.observed_at is None:
        return DiagnosticPath(state="unknown", observed_at=None, hops=[], links=[])

    found = _chain(server, read)
    found["server"] = (server, server_name)
    suspected = suspected_tier(domain)
    hops: list[DiagnosticPathHop] = []
    for tier in PATH_TIERS:
        marked = tier == suspected
        if tier in found:
            device, name = found[tier]
            hops.append(
                DiagnosticPathHop(
                    tier=tier,
                    state="known",
                    device_id=device.device_id,
                    name=name,
                    highlight="suspected" if marked else None,
                )
            )
        else:
            hops.append(_unknown(tier, marked))
    links = [
        DiagnosticPathLink(
            from_tier=left.tier,
            to_tier=right.tier,
            state="known" if left.state == "known" and right.state == "known" else "unknown",
        )
        for left, right in pairwise(hops)
    ]
    return DiagnosticPath(state="ok", observed_at=read.observed_at, hops=hops, links=links)
