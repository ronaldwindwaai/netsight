"""Reconciliation between intended NetBox state and discovered LibreNMS devices.

NetBox is the intended source of truth. Discovered data must never silently
overwrite source-of-truth records; they are compared and mismatches surfaced.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from netsight_api.schemas import Device


@dataclass(frozen=True)
class Finding:
    kind: Literal["missing-discovered", "unknown-discovered", "status-mismatch"]
    netbox_device_id: str | None
    discovered_device_id: str | None
    detail: str


def match_key(device: Device) -> str:
    """The join key reconciliation uses (case-insensitive hostname, else name). Not an identity."""
    hostname = (device.hostname or "").strip().lower()
    if hostname:
        return hostname
    return device.name.strip().lower()


_match_key = match_key


def _netbox_status(device: Device) -> str:
    return "active" if device.status != "offline" else "offline"


def reconcile(netbox_devices: list[Device], discovered_devices: list[Device]) -> list[Finding]:
    netbox_by_key = {_match_key(d): d for d in netbox_devices}
    discovered_by_key = {_match_key(d): d for d in discovered_devices}

    findings: list[Finding] = []
    for key, netbox in netbox_by_key.items():
        discovered = discovered_by_key.get(key)
        if discovered is None:
            findings.append(
                Finding(
                    kind="missing-discovered",
                    netbox_device_id=netbox.id,
                    discovered_device_id=None,
                    detail="Intended device not seen by LibreNMS discovery",
                )
            )
            continue
        # Status mismatch: NetBox offline but LibreNMS healthy (or vice versa).
        netbox_is_active = netbox.status != "offline"
        discovered_is_active = discovered.status != "offline"
        if netbox_is_active != discovered_is_active:
            findings.append(
                Finding(
                    kind="status-mismatch",
                    netbox_device_id=netbox.id,
                    discovered_device_id=discovered.id,
                    detail=f"NetBox status={netbox.status}; discovered status={discovered.status}",
                )
            )

    for key, discovered in discovered_by_key.items():
        if key not in netbox_by_key:
            findings.append(
                Finding(
                    kind="unknown-discovered",
                    netbox_device_id=None,
                    discovered_device_id=discovered.id,
                    detail="Discovered device has no matching NetBox record",
                )
            )
    return findings
