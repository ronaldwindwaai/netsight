"""Row mapping for the NetBox IPAM and interface-MAC reads (Step 8).

A leaf of ``adapters.netbox``: pure functions from one NetBox REST row to a small frozen record, with
no I/O. A row that does not say what it must raises ``RowError``; the client skips and counts it, and
fails the whole read when most rows are bad (a changed API shape is not "no data"). Every text value is
untrusted NetBox content, bounded and kept as data. The shapes follow NetBox 3.x/4.x REST and are not
verified against a live NetBox in this build.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

MAX_TEXT = 128
CANONICAL_MAC = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
_MAC_SEPARATORS = re.compile(r"[^0-9a-fA-F]")
_MAX_VLAN_ID = 4094


class RowError(ValueError):
    """One NetBox row is unusable (the message is static and never carries row content)."""


@dataclass(frozen=True)
class AssetExtras:
    role_slug: str | None
    role_name: str | None
    type_slug: str | None
    type_model: str | None
    status: str | None


@dataclass(frozen=True)
class NetboxPrefix:
    native_id: str
    prefix: str
    version: int
    vrf_id: str | None
    vrf_name: str | None
    status: str | None
    site: str | None
    role: str | None
    vlan_native_id: str | None
    vlan_vid: int | None
    vlan_name: str | None
    description: str | None
    is_pool: bool
    mark_utilized: bool


@dataclass(frozen=True)
class NetboxVlan:
    native_id: str
    vid: int
    name: str
    status: str | None
    site: str | None
    group: str | None
    description: str | None


@dataclass(frozen=True)
class NetboxAddress:
    native_id: str
    address: str
    version: int
    vrf_id: str | None
    status: str | None
    dns_name: str | None
    description: str | None
    assigned: bool


@dataclass(frozen=True)
class NetboxRange:
    native_id: str
    start: str
    end: str
    version: int
    size: int
    vrf_id: str | None
    status: str | None
    description: str | None


@dataclass(frozen=True)
class MacMatch:
    device_native_id: str
    device_name: str | None
    interface_name: str | None


# --- small helpers ------------------------------------------------------------------------------------


def bounded_text(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()[:MAX_TEXT]
    return None


def native_text(value: object) -> str | None:
    if isinstance(value, bool) or not isinstance(value, int | str):
        return None
    text = str(value).strip()
    return text or None


def _display(value: object) -> str | None:
    """A relation NetBox renders as ``{"name": ..., "display": ...}`` or a plain string."""
    if isinstance(value, dict):
        return bounded_text(value.get("name")) or bounded_text(value.get("display"))
    return bounded_text(value)


def _slug(value: object) -> str | None:
    if not isinstance(value, dict):
        return None
    slug = bounded_text(value.get("slug"))
    return slug.lower() if slug else None


def status_value(row: dict[str, Any]) -> str | None:
    status = row.get("status")
    raw = status.get("value") if isinstance(status, dict) else status
    return raw.strip().lower()[:64] if isinstance(raw, str) and raw.strip() else None


def _required_id(row: dict[str, Any]) -> str:
    native = native_text(row.get("id"))
    if native is None:
        raise RowError("row has no id")
    return native


def _vrf(row: dict[str, Any]) -> tuple[str | None, str | None]:
    vrf = row.get("vrf")
    if not isinstance(vrf, dict):
        return None, None
    return native_text(vrf.get("id")), bounded_text(vrf.get("name"))


def canonical_mac(value: str) -> str:
    """The lower-case colon form of a MAC address, or ``RowError``. Used for rows, never for URLs."""
    digits = _MAC_SEPARATORS.sub("", value)
    if len(digits) != 12:
        raise RowError("not a MAC address")
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2)).lower()


def _interface_ip(value: object) -> ipaddress.IPv4Interface | ipaddress.IPv6Interface:
    if not isinstance(value, str):
        raise RowError("not an address")
    try:
        return ipaddress.ip_interface(value.strip())
    except ValueError as error:
        raise RowError("not an address") from error


# --- rows -----------------------------------------------------------------------------------------------


def asset_extras(row: dict[str, Any]) -> AssetExtras:
    role = row.get("role") if isinstance(row.get("role"), dict) else row.get("device_role")
    device_type = row.get("device_type")
    return AssetExtras(
        role_slug=_slug(role),
        role_name=_display(role),
        type_slug=_slug(device_type),
        type_model=(
            bounded_text(device_type.get("model")) or bounded_text(device_type.get("display"))
            if isinstance(device_type, dict)
            else None
        ),
        status=status_value(row),
    )


def parse_prefix(row: dict[str, Any]) -> NetboxPrefix:
    raw = row.get("prefix")
    if not isinstance(raw, str) or "/" not in raw:
        raise RowError("not a prefix")
    try:
        network = ipaddress.ip_network(raw.strip(), strict=False)
    except ValueError as error:
        raise RowError("not a prefix") from error
    vrf_id, vrf_name = _vrf(row)
    vlan = row.get("vlan")
    vid = vlan.get("vid") if isinstance(vlan, dict) else None
    return NetboxPrefix(
        native_id=_required_id(row),
        prefix=str(network),
        version=network.version,
        vrf_id=vrf_id,
        vrf_name=vrf_name,
        status=status_value(row),
        site=_display(row.get("site")),
        role=_display(row.get("role")),
        vlan_native_id=native_text(vlan.get("id")) if isinstance(vlan, dict) else None,
        vlan_vid=vid
        if isinstance(vid, int) and not isinstance(vid, bool) and 1 <= vid <= _MAX_VLAN_ID
        else None,
        vlan_name=bounded_text(vlan.get("name")) if isinstance(vlan, dict) else None,
        description=bounded_text(row.get("description")),
        is_pool=row.get("is_pool") is True,
        mark_utilized=row.get("mark_utilized") is True,
    )


def parse_vlan(row: dict[str, Any]) -> NetboxVlan:
    vid = row.get("vid")
    if isinstance(vid, bool) or not isinstance(vid, int) or not 1 <= vid <= _MAX_VLAN_ID:
        raise RowError("not a VLAN id")
    name = bounded_text(row.get("name"))
    if name is None:
        raise RowError("VLAN has no name")
    return NetboxVlan(
        native_id=_required_id(row),
        vid=vid,
        name=name,
        status=status_value(row),
        site=_display(row.get("site")),
        group=_display(row.get("group")),
        description=bounded_text(row.get("description")),
    )


def parse_address(row: dict[str, Any]) -> NetboxAddress:
    interface = _interface_ip(row.get("address"))
    assigned_type = row.get("assigned_object_type")
    return NetboxAddress(
        native_id=_required_id(row),
        address=str(interface.ip),
        version=interface.version,
        vrf_id=_vrf(row)[0],
        status=status_value(row),
        dns_name=bounded_text(row.get("dns_name")),
        description=bounded_text(row.get("description")),
        assigned=isinstance(assigned_type, str) and isinstance(row.get("assigned_object"), dict),
    )


def parse_range(row: dict[str, Any]) -> NetboxRange | None:
    """A reserved range, ``None`` when the row is another status (the filter is repeated here)."""
    if status_value(row) != "reserved":
        return None
    start, end = _interface_ip(row.get("start_address")), _interface_ip(row.get("end_address"))
    if start.version != end.version or int(end.ip) < int(start.ip):
        raise RowError("not an ordered range")
    computed = int(end.ip) - int(start.ip) + 1
    declared = row.get("size")
    size = (
        declared
        if isinstance(declared, int) and not isinstance(declared, bool) and declared >= 1
        else computed
    )
    return NetboxRange(
        native_id=_required_id(row),
        start=str(start.ip),
        end=str(end.ip),
        version=start.version,
        size=size,
        vrf_id=_vrf(row)[0],
        status="reserved",
        description=bounded_text(row.get("description")),
    )


def _row_macs(row: dict[str, Any]) -> list[str]:
    found: list[object] = [row.get("mac_address")]
    primary = row.get("primary_mac_address")
    if isinstance(primary, dict):
        found.append(primary.get("mac_address"))
    listed = row.get("mac_addresses")
    if isinstance(listed, list):
        found.extend(item.get("mac_address") for item in listed if isinstance(item, dict))
    macs: list[str] = []
    for value in found:
        if isinstance(value, str):
            try:
                macs.append(canonical_mac(value))
            except RowError:
                continue
    return macs


def parse_mac_match(row: dict[str, Any], wanted: str) -> MacMatch | None:
    """The interface as a match when it really carries ``wanted`` and belongs to a device."""
    if wanted not in _row_macs(row):
        return None
    device = row.get("device")
    device_id = native_text(device.get("id")) if isinstance(device, dict) else None
    if device_id is None or not isinstance(device, dict):
        return None
    return MacMatch(device_id, bounded_text(device.get("name")), bounded_text(row.get("name")))
