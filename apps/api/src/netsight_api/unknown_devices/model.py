"""What one comparison of telemetry with NetBox concludes about one endpoint (Step 8c).

A ``Detection`` is the scanner's output and the store's input: the endpoint that was seen, the
evidence chain (only the links actually observed), the comparison with NetBox, the severity the
operator's policy gave it and, when the policy asks for it, a quarantine *recommendation*. It is
validated on construction by assembling the very finding the API will serve, so a detection the
contract would refuse can not reach storage.

The fingerprint says whether two detections of the same endpoint differ in anything an analyst
cares about (what was seen, which hops are known, what NetBox said, the severity). It leaves out
times, so a quiet endpoint seen again every few minutes writes nothing but a counter.

Identity policy. The **MAC is authoritative**: an endpoint with a MAC is that MAC, whatever address
it has now. An endpoint seen only by address is that address; one seen only by name is that name.
A finding is stored under one key, but a sighting is matched against *all* the keys of its
endpoint (``lookup_keys``): a false positive on a MAC also suppresses sightings of that endpoint
by address, and a finding opened by address is found again once the MAC is known. Two different
MACs are two endpoints even at one address (the address was reused).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from netsight_api.schemas_unknown_devices import (
    SYSTEM_ACTOR,
    Severity,
    SeverityBasis,
    UnknownDeviceComparison,
    UnknownDeviceEndpoint,
    UnknownDeviceFinding,
    UnknownDeviceLinkSlot,
    UnknownDeviceProposedAction,
    check_slots,
)

SUBJECT_KEY: Final = re.compile(
    r"^(?:mac:(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|ip:[0-9a-f.:]{2,45}|host:[a-z0-9._-]{1,127}|hash:[0-9a-f]{32})$"
)
_HOSTNAME: Final = re.compile(r"^[a-z0-9._-]{1,127}$")
_PLACEHOLDER_ID: Final = "unknown-device-00000000-0000-0000-0000-000000000000"
_PLACEHOLDER_TIME: Final = "2000-01-01T00:00:00+00:00"


def subject_key_for(endpoint: UnknownDeviceEndpoint) -> str:
    """The stable identity of an endpoint: its MAC, else its address, else its (normalised) name."""
    if endpoint.mac is not None:
        return f"mac:{endpoint.mac}"
    if endpoint.ip is not None:
        return f"ip:{endpoint.ip}"
    assert endpoint.hostname is not None  # an endpoint always has one of the three
    name = endpoint.hostname.strip().lower().rstrip(".")
    if _HOSTNAME.fullmatch(name):
        return f"host:{name}"
    return f"hash:{hashlib.sha256(name.encode()).hexdigest()[:32]}"


def lookup_keys(endpoint: UnknownDeviceEndpoint) -> tuple[str, ...]:
    """Every identity under which an earlier finding of this endpoint may have been stored."""
    keys: list[str] = []
    if endpoint.mac is not None:
        keys.append(f"mac:{endpoint.mac}")
    if endpoint.ip is not None:
        keys.append(f"ip:{endpoint.ip}")
    return tuple(keys) if keys else (subject_key_for(endpoint),)


def same_endpoint(stored: UnknownDeviceEndpoint, seen: UnknownDeviceEndpoint) -> bool:
    """Whether a sighting is of the endpoint a finding was opened for (MAC authoritative)."""
    if stored.mac is not None and seen.mac is not None:
        return stored.mac == seen.mac
    if stored.mac is not None or seen.mac is not None:
        return (
            stored.ip is not None and stored.ip == seen.ip
        )  # one MAC unknown: the address bridges
    if stored.ip is not None or seen.ip is not None:
        return stored.ip == seen.ip
    return subject_key_for(stored) == subject_key_for(seen)


def fingerprint_of(
    endpoint: UnknownDeviceEndpoint,
    chain: Sequence[UnknownDeviceLinkSlot],
    comparison: UnknownDeviceComparison,
    severity: str,
    severity_basis: str,
    proposed_action: UnknownDeviceProposedAction | None,
) -> str:
    """A hash of everything about a detection except when it was observed."""
    material = {
        "endpoint": [endpoint.ip, endpoint.mac, endpoint.hostname],
        "chain": [
            [
                s.slot,
                s.basis,
                s.value,
                s.attachment_kind,
                s.reason,
                sorted(e.id for e in s.evidence),
            ]
            for s in chain
        ],
        "checks": [[c.field, c.result] for c in comparison.checks],
        "reason": comparison.reason,
        "severity": [severity, severity_basis],
        "action": proposed_action is not None,
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


def significance_of(
    comparison: UnknownDeviceComparison,
    severity: str,
    severity_basis: str,
    proposed_action: UnknownDeviceProposedAction | None,
) -> str:
    """What decides how an analyst should treat the finding, apart from where it was seen."""
    return json.dumps(
        [
            severity,
            severity_basis,
            proposed_action is not None,
            [[c.field, c.result] for c in comparison.checks],
            comparison.reason,
        ]
    )


def finding_significance(finding: UnknownDeviceFinding) -> str:
    return significance_of(
        finding.comparison, finding.severity, finding.severity_basis, finding.proposed_action
    )


def finding_fingerprint(finding: UnknownDeviceFinding) -> str:
    return fingerprint_of(
        finding.endpoint,
        finding.chain,
        finding.comparison,
        finding.severity,
        finding.severity_basis,
        finding.proposed_action,
    )


@dataclass(frozen=True)
class Detection:
    subject_key: str
    endpoint: UnknownDeviceEndpoint
    chain: tuple[UnknownDeviceLinkSlot, ...]
    comparison: UnknownDeviceComparison
    severity: Severity
    severity_basis: SeverityBasis
    proposed_action: UnknownDeviceProposedAction | None = None

    def __post_init__(self) -> None:
        if SUBJECT_KEY.fullmatch(self.subject_key) is None:
            raise ValueError("the subject key is not well formed")
        if self.subject_key != subject_key_for(self.endpoint):
            raise ValueError("the subject key is the endpoint's identity")
        check_slots(self.chain)
        # Assemble the finding the API would serve: every cross-field rule of the contract applies.
        self.as_finding(_PLACEHOLDER_ID, _PLACEHOLDER_TIME)

    def as_finding(
        self, finding_id: str, observed_at: object, **overrides: object
    ) -> UnknownDeviceFinding:
        values: dict[str, object] = {
            "id": finding_id,
            "state": "new",
            "evidence_version": 1,
            "severity": self.severity,
            "severity_basis": self.severity_basis,
            "assignee_id": None,
            "first_seen_at": observed_at,
            "last_seen_at": observed_at,
            "seen_count": 1,
            "recurrence_of": None,
            "endpoint": self.endpoint,
            "chain": list(self.chain),
            "comparison": self.comparison,
            "proposed_action": self.proposed_action,
        }
        values.update(overrides)
        return UnknownDeviceFinding.model_validate(values)

    @property
    def lookup_keys(self) -> tuple[str, ...]:
        return lookup_keys(self.endpoint)

    def significance(self) -> str:
        return significance_of(
            self.comparison, self.severity, self.severity_basis, self.proposed_action
        )

    def fingerprint(self) -> str:
        return fingerprint_of(
            self.endpoint,
            self.chain,
            self.comparison,
            self.severity,
            self.severity_basis,
            self.proposed_action,
        )


__all__ = [
    "SYSTEM_ACTOR",
    "Detection",
    "finding_fingerprint",
    "finding_significance",
    "fingerprint_of",
    "lookup_keys",
    "same_endpoint",
    "significance_of",
    "subject_key_for",
]
