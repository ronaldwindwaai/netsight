"""The operator's severity policy for unknown devices (Step 8c).

Netsight does not decide how serious an unknown device is, nor when to recommend isolating one. The
operator says so in one JSON document (``NETSIGHT_UNKNOWN_DEVICE_POLICY_FILE`` path, or
``NETSIGHT_UNKNOWN_DEVICE_POLICY`` inline) and every severity traces to an entry in it::

    {"version": 1,
     "default_severity": "medium",
     "rules": [{"cidrs": ["10.20.0.0/16"], "severity": "high"},
               {"vlans": [30], "severity": "critical"}],
     "quarantine_recommended_at": "high"}

* the first rule that matches decides; a rule matches when any of its networks contains the
  observed address or any of its VLANs is the VLAN that was observed (a VLAN nobody observed
  matches nothing: it is never assumed);
* no document, or one that does not validate (``invalid``: half a policy is never applied), means
  the severity is ``unknown`` and no quarantine is ever recommended;
* ``quarantine_recommended_at`` is a threshold for a *recommendation*: nothing here (or anywhere in
  this release) executes an isolation, which belongs to the action engine.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, cast

from netsight_api.inventory.operator_file import DocumentState, read_operator_document
from netsight_api.schemas_unknown_devices import Severity, SeverityBasis

POLICY_ENV: Final = "NETSIGHT_UNKNOWN_DEVICE_POLICY"
POLICY_FILE_ENV: Final = "NETSIGHT_UNKNOWN_DEVICE_POLICY_FILE"
SUPPORTED_VERSION: Final = 1
MAX_RULES: Final = 100
MAX_ENTRIES_PER_RULE: Final = 50
_RANK: Final[Mapping[str, int]] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_TOP_LEVEL: Final = frozenset({"version", "default_severity", "rules", "quarantine_recommended_at"})
_RULE_KEYS: Final = frozenset({"cidrs", "vlans", "severity"})
_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class _PolicyError(ValueError):
    """The document does not validate (static message, never document content)."""


@dataclass(frozen=True)
class _Rule:
    networks: tuple[_Network, ...]
    vlans: frozenset[int]
    severity: Severity

    def matches(
        self, address: ipaddress.IPv4Address | ipaddress.IPv6Address | None, vlan: int | None
    ) -> bool:
        if address is not None and any(
            address.version == net.version and address in net for net in self.networks
        ):
            return True
        return vlan is not None and vlan in self.vlans


@dataclass(frozen=True)
class SeverityPolicy:
    state: DocumentState
    default: Severity | None = None
    rules: tuple[_Rule, ...] = ()
    quarantine_at: Severity | None = None

    def decide(self, ip: str | None, vlan: int | None) -> tuple[Severity, SeverityBasis]:
        """The severity and why: a rule, the default, or unknown when no policy decided it."""
        try:
            address = ipaddress.ip_address(ip) if ip is not None else None
        except ValueError:
            address = None
        for rule in self.rules:
            if rule.matches(address, vlan):
                return rule.severity, "policy-rule"
        if self.default is not None:
            return self.default, "policy-default"
        return "unknown", "no-policy"

    def recommends_quarantine(self, severity: Severity) -> bool:
        if self.quarantine_at is None or severity == "unknown":
            return False
        return _RANK[severity] >= _RANK[self.quarantine_at]


def _severity(value: object, *, allow_none: bool = False) -> Severity | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or value not in _RANK:
        raise _PolicyError("a severity is low, medium, high or critical")
    return cast(Severity, value)


def _rule(raw: object) -> _Rule:
    if not isinstance(raw, dict) or not set(raw) <= _RULE_KEYS:
        raise _PolicyError("a rule is an object of cidrs, vlans and severity")
    cidrs, vlans = raw.get("cidrs", []), raw.get("vlans", [])
    if not isinstance(cidrs, list) or not isinstance(vlans, list):
        raise _PolicyError("cidrs and vlans are lists")
    if not cidrs and not vlans:
        raise _PolicyError("a rule names a network or a VLAN")
    if len(cidrs) > MAX_ENTRIES_PER_RULE or len(vlans) > MAX_ENTRIES_PER_RULE:
        raise _PolicyError("a rule names at most the entry limit")
    networks: list[_Network] = []
    for cidr in cidrs:
        if not isinstance(cidr, str):
            raise _PolicyError("a network is text")
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError as error:
            raise _PolicyError("a network is a CIDR") from error
    for vlan in vlans:
        if isinstance(vlan, bool) or not isinstance(vlan, int) or not 1 <= vlan <= 4094:
            raise _PolicyError("a VLAN is a number from 1 to 4094")
    severity = _severity(raw.get("severity"))
    assert severity is not None
    return _Rule(tuple(networks), frozenset(vlans), severity)


def _parse(document: object) -> SeverityPolicy:
    if not isinstance(document, dict) or not set(document) <= _TOP_LEVEL:
        raise _PolicyError("unexpected document shape")
    if document.get("version") != SUPPORTED_VERSION:
        raise _PolicyError("unsupported version")
    rules = document.get("rules", [])
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise _PolicyError("rules are a list within the limit")
    return SeverityPolicy(
        "configured",
        default=_severity(document.get("default_severity"), allow_none=True),
        rules=tuple(_rule(r) for r in rules),
        quarantine_at=_severity(document.get("quarantine_recommended_at"), allow_none=True),
    )


def load_policy(env: Mapping[str, str]) -> SeverityPolicy:
    """The configured policy. Never raises: an unusable one is ``invalid`` and decides nothing."""
    document = read_operator_document(env, POLICY_ENV, POLICY_FILE_ENV)
    if document.state == "not-configured":
        return SeverityPolicy("not-configured")
    if document.state == "invalid":
        return SeverityPolicy("invalid")
    try:
        return _parse(document.data)
    except _PolicyError:
        return SeverityPolicy("invalid")
