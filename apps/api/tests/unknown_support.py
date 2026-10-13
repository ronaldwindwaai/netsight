"""Builders for unknown-device tests (Step 8c): evidence, chains, detections and findings."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from netsight_api.schemas_unknown_devices import (
    UnknownDeviceCheck,
    UnknownDeviceComparison,
    UnknownDeviceEndpoint,
    UnknownDeviceEvidenceRef,
    UnknownDeviceLinkSlot,
    UnknownDeviceProposedAction,
)
from netsight_api.unknown_devices.model import Detection, subject_key_for

NOW = datetime(2026, 10, 11, 12, 0, 0, tzinfo=UTC)
MAC = "aa:bb:cc:00:11:22"
IP = "10.0.5.9"
PORT_ID = "port-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc"
SWITCH_ID = "device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc"


def evidence(
    native: str = "librenms:9", kind: str = "device-poll", source: str = "librenms"
) -> UnknownDeviceEvidenceRef:
    return UnknownDeviceEvidenceRef(
        id=native, source=source, kind=kind, observed_at=NOW, confidence=None
    )


def observed(slot: str, value: str, **extra: Any) -> UnknownDeviceLinkSlot:
    return UnknownDeviceLinkSlot(
        slot=slot,  # type: ignore[arg-type]
        basis="observed",
        value=value,
        label=extra.get("label"),
        attachment_kind=extra.get("attachment_kind"),
        confidence=extra.get("confidence"),
        reason=None,
        evidence=extra.get("evidence", [evidence()]),
    )


def unknown(slot: str, reason: str = "source-unavailable") -> UnknownDeviceLinkSlot:
    return UnknownDeviceLinkSlot(
        slot=slot,  # type: ignore[arg-type]
        basis="unknown",
        value=None,
        label=None,
        attachment_kind=None,
        confidence=None,
        reason=reason,  # type: ignore[arg-type]
        evidence=[],
    )


def comparison(reason: str = "no-match", **results: str) -> UnknownDeviceComparison:
    """One check per field; ``results`` overrides the default ``no-match`` of any of them."""
    return UnknownDeviceComparison(
        checks=[
            UnknownDeviceCheck(
                field=name,  # type: ignore[arg-type]
                result=results.get(name, "no-match"),  # type: ignore[arg-type]
                detail=None
                if results.get(name, "no-match") != "not-checked"
                else "nothing observed",
            )
            for name in ("ip", "mac", "hostname")
        ],
        checked_at=NOW,
        reason=reason,  # type: ignore[arg-type]
    )


def action() -> UnknownDeviceProposedAction:
    return UnknownDeviceProposedAction(
        action_type="endpoint.isolate",
        state="proposed",
        risk="C",
        executable=False,
        awaiting="action-engine",
        rationale="Severity high by operator policy",
    )


def detection(
    *,
    ip: str | None = IP,
    mac: str | None = MAC,
    hostname: str | None = "printer-x",
    severity: str = "medium",
    basis: str = "policy-default",
    with_action: bool = False,
    port: bool = False,
    reason: str = "no-match",
    results: dict[str, str] | None = None,
    **checks: str,
) -> Detection:
    endpoint = UnknownDeviceEndpoint(ip=ip, mac=mac, hostname=hostname)
    chain = (
        observed("ip", ip) if ip else unknown("ip", "no-evidence"),
        observed("mac", mac) if mac else unknown("mac", "no-evidence"),
        unknown("attachment"),
        observed("port", "port-x", label="Gi1/0/7") if port else unknown("port"),
        unknown("vlan"),
    )
    return Detection(
        subject_key=subject_key_for(endpoint),
        endpoint=endpoint,
        chain=chain,
        comparison=comparison(reason, **{**checks, **(results or {})}),
        severity=severity,  # type: ignore[arg-type]
        severity_basis=basis,  # type: ignore[arg-type]
        proposed_action=action() if with_action else None,
    )
