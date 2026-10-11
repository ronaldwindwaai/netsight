"""Merging NetBox intended state with discovered telemetry into inventory items (Step 8a).

Pure: no I/O, no clock. NetBox is the authority for intended state; telemetry adds what NetBox
lacks, or disagrees (a conflict that keeps NetBox's value), and never replaces it.

Joins, and what they are not:

* NetBox <-> LibreNMS use the *same* hostname rule as the reconciliation (``reconcile.match_key``),
  so the inventory and ``/reconcile/findings`` cannot disagree about who is the same device. A name
  shared by more than one device on either side joins nothing and is ``ambiguous``: a name is not an
  identity, and picking one of two would be a guess.
* NetBox <-> Wazuh join only through the operator's NetBox custom field holding the agent id (the
  Step 6 rule). A key claimed by two NetBox devices joins neither. Without the join table no Wazuh
  agent may be passed in at all.
* The asset class comes only from the operator's map, for assets NetBox knows.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from netsight_api.adapters.netbox import NetboxAsset
from netsight_api.adapters.netbox_ipam import RowError, canonical_mac
from netsight_api.adapters.wazuh import WazuhAgent
from netsight_api.identity.model import device_ref
from netsight_api.inventory.classmap import ClassMap
from netsight_api.reconcile import Finding, match_key, reconcile
from netsight_api.schemas import Device, DeviceStatus
from netsight_api.schemas_inventory import (
    AssetClass,
    ClassBasis,
    InventoryAlias,
    InventoryField,
    InventoryItem,
    InventoryReconcile,
    ItemSource,
    Provenance,
    ReconcileStatus,
)

_AGENT_STATUS: Final[Mapping[str, DeviceStatus]] = {"active": "healthy", "disconnected": "offline"}
_MAX_VALUE: Final = 255


@dataclass(frozen=True)
class _Reading:
    """What the discovery side reports about one asset (LibreNMS first, Wazuh as the fallback)."""

    name: str | None
    ip: str | None
    mac: str | None
    status: DeviceStatus | None


def _norm_ip(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return value.strip()[:_MAX_VALUE] or None


def _norm_mac(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    try:
        return canonical_mac(value)
    except RowError:
        return value.strip().lower()[:_MAX_VALUE]


def _text(value: str | None) -> str | None:
    return value.strip()[:_MAX_VALUE] or None if value is not None else None


def _field(netbox: str | None, discovered: str | None) -> InventoryField:
    """One value with its provenance; a conflict keeps NetBox's value (the intended state)."""
    provenance: Provenance
    if netbox is None and discovered is None:
        provenance = "unknown"
    elif discovered is None:
        provenance = "netbox"
    elif netbox is None:
        provenance = "discovered"
    else:
        provenance = "both" if netbox == discovered else "conflict"
    value = netbox if netbox is not None else discovered
    return InventoryField(value=value, provenance=provenance, netbox=netbox, discovered=discovered)


def _libre_reading(device: Device) -> _Reading:
    return _Reading(
        _text(device.name),
        _norm_ip(device.ip_addresses[0] if device.ip_addresses else None),
        _norm_mac(device.mac_addresses[0] if device.mac_addresses else None),
        device.status,
    )


def _agent_reading(agent: WazuhAgent) -> _Reading:
    return _Reading(
        _text(agent.name) or f"wazuh-agent-{agent.agent_id}"[:_MAX_VALUE],
        _norm_ip(agent.ip),
        None,
        _AGENT_STATUS.get(agent.status, "unknown"),
    )


def _discovered(libre: Device | None, agent: WazuhAgent | None) -> _Reading | None:
    readings = [r for r in (libre and _libre_reading(libre), agent and _agent_reading(agent)) if r]
    if not readings:
        return None
    first = readings[0]
    for other in readings[1:]:
        first = _Reading(
            first.name or other.name,
            first.ip or other.ip,
            first.mac or other.mac,
            first.status or other.status,
        )
    return first


def _aliases(
    asset: NetboxAsset | None, libre: Device | None, agent: WazuhAgent | None
) -> list[InventoryAlias]:
    aliases: list[InventoryAlias] = []
    if asset is not None:
        aliases.append(
            InventoryAlias(source="netbox", native_id=asset.device.source_aliases[0].native_id)
        )
    if libre is not None:
        aliases.append(
            InventoryAlias(source="librenms", native_id=libre.source_aliases[0].native_id)
        )
    if agent is not None:
        aliases.append(InventoryAlias(source="wazuh", native_id=agent.agent_id))
    return aliases


def _item_id(asset: NetboxAsset | None, libre: Device | None, agent: WazuhAgent | None) -> str:
    if asset is not None:
        return asset.device.id
    if libre is not None:
        return libre.id
    assert agent is not None  # an item always has at least one source
    return device_ref("wazuh", agent.agent_id).id


def _make_item(
    asset: NetboxAsset | None,
    libre: Device | None,
    agent: WazuhAgent | None,
    reconcile_state: InventoryReconcile,
    class_map: ClassMap,
) -> InventoryItem:
    seen = _discovered(libre, agent)
    source: ItemSource = "both" if asset and seen else "netbox" if asset else "discovered"
    asset_class: AssetClass
    basis: ClassBasis
    if asset is None:
        asset_class, basis = "unknown-asset", "not-in-netbox"
    else:
        asset_class, basis = class_map.classify(asset.role_slug, asset.type_slug)
    netbox_device = asset.device if asset else None
    return InventoryItem(
        id=_item_id(asset, libre, agent),
        asset_class=asset_class,
        class_basis=basis,
        source=source,
        known=asset is not None,
        name=_field(
            _text(netbox_device.name) if netbox_device else None, seen.name if seen else None
        ),
        site=_field(_text(netbox_device.site_id) if netbox_device else None, None),
        ip_address=_field(
            _norm_ip(netbox_device.ip_addresses[0])
            if netbox_device and netbox_device.ip_addresses
            else None,
            seen.ip if seen else None,
        ),
        mac_address=_field(None, seen.mac if seen else None),
        role=_text(asset.role_name) if asset else None,
        device_type=_text(asset.type_model) if asset else None,
        intended_status=asset.status if asset else None,
        observed_status=seen.status if seen else None,
        reconcile=reconcile_state,
        sources=_aliases(asset, libre, agent),
    )


def _status(status: ReconcileStatus, detail: str | None) -> InventoryReconcile:
    return InventoryReconcile(status=status, detail=detail)


def _groups[T](items: Sequence[T], key: Callable[[T], str]) -> dict[str, list[T]]:
    grouped: dict[str, list[T]] = defaultdict(list)
    for item in items:
        grouped[key(item)].append(item)
    return grouped


def _agent_join(
    assets: Sequence[NetboxAsset], agents: Sequence[WazuhAgent], keys: Mapping[str, str]
) -> dict[str, WazuhAgent]:
    """NetBox native id -> the agent its custom field names (a key held twice joins neither)."""
    holders: dict[str, list[str]] = defaultdict(list)
    for native, key in keys.items():
        holders[key].append(native)
    by_id = {agent.agent_id: agent for agent in agents}
    native_ids = {a.device.source_aliases[0].native_id for a in assets}
    joined: dict[str, WazuhAgent] = {}
    for key, natives in holders.items():
        if len(natives) == 1 and natives[0] in native_ids and key in by_id:
            joined[natives[0]] = by_id[key]
    return joined


def build_items(
    *,
    netbox: Sequence[NetboxAsset],
    librenms: Sequence[Device] | None,
    wazuh: Sequence[WazuhAgent] | None,
    agent_keys: Mapping[str, str] | None,
    class_map: ClassMap,
) -> list[InventoryItem]:
    """Every asset any source reports, once. ``None`` for a source means it was not readable."""
    if wazuh and agent_keys is None:
        raise ValueError("Wazuh agents can only be listed with the NetBox join table")
    agents = list(wazuh or [])
    joined_agents = _agent_join(netbox, agents, agent_keys or {})
    used_agents = {a.agent_id for a in joined_agents.values()}

    nb_groups = _groups(netbox, lambda a: match_key(a.device))
    lb_groups = _groups(librenms or [], match_key)
    ambiguous = {
        key
        for key in {*nb_groups, *lb_groups}
        if len(nb_groups.get(key, [])) > 1 or len(lb_groups.get(key, [])) > 1
    }
    clean_nb = [a for k, g in nb_groups.items() if k not in ambiguous for a in g]
    clean_lb = [d for k, g in lb_groups.items() if k not in ambiguous for d in g]
    findings: list[Finding] = (
        reconcile([a.device for a in clean_nb], clean_lb) if librenms is not None else []
    )
    mismatch = {f.netbox_device_id: f for f in findings if f.kind == "status-mismatch"}
    missing = {f.netbox_device_id for f in findings if f.kind == "missing-discovered"}
    libre_by_key = {match_key(d): d for d in clean_lb}

    items: list[InventoryItem] = []
    joined_libre: set[str] = set()
    for asset in netbox:
        key = match_key(asset.device)
        libre = libre_by_key.get(key) if key not in ambiguous else None
        agent = joined_agents.get(asset.device.source_aliases[0].native_id)
        if libre is not None:
            joined_libre.add(libre.id)
        if key in ambiguous:
            state = _status("ambiguous", "More than one device shares this hostname")
        elif librenms is None and agent is None:
            state = _status("not-checked", "LibreNMS was not readable")
        elif asset.device.id in mismatch:
            state = _status("status-mismatch", mismatch[asset.device.id].detail)
        elif asset.device.id in missing and agent is None:
            state = _status("missing-discovered", "Intended device not seen by LibreNMS discovery")
        elif agent is not None and libre is None:
            why = "LibreNMS was not readable" if librenms is None else "LibreNMS did not list it"
            state = _status("reconciled", f"Seen by a Wazuh agent; {why}")
        else:
            state = _status("reconciled", None)
        items.append(_make_item(asset, libre, agent, state, class_map))

    for device in librenms or []:
        if device.id in joined_libre:
            continue
        if match_key(device) in ambiguous:
            state = _status("ambiguous", "More than one device shares this hostname")
        else:
            # Not joined and not ambiguous: reconciliation reports it as unknown-discovered too.
            state = _status("unknown-discovered", "Discovered device has no matching NetBox record")
        items.append(_make_item(None, device, None, state, class_map))
    for agent in agents:
        if agent.agent_id in used_agents:
            continue
        state = _status("unknown-discovered", "Wazuh agent has no matching NetBox record")
        items.append(_make_item(None, None, agent, state, class_map))
    return items
