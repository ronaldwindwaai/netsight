"""Which endpoints does telemetry see that NetBox does not know, and what is known about them (Step 8c).

Pure: no I/O, no clock beyond the ``now`` it is given. The inputs are what was *observed* (LibreNMS
devices and Wazuh agents today, and any ``EvidenceSource`` records such as DHCP leases, switch MAC
tables or Wi-Fi associations when an adapter for them exists), what NetBox *intends* (device names and
addresses, a MAC lookup per candidate) and the operator's severity policy.

* An endpoint is *known* the moment any observed field matches NetBox; only an endpoint where every
  field that could be asked about did not match is a finding. If NetBox could not be asked about an
  observed MAC (error, lookup limit) the endpoint is *unverified* and no finding is made: absence of an
  answer is never taken as "unknown to NetBox".
* The evidence chain is IP, MAC, switch or AP, port, VLAN. A hop is filled in only from evidence that
  asserts it (the Step 6 identity engine composes the records, so conflicting or expired evidence is
  handled by the same rules); every other hop is ``unknown`` with the reason: ``no-evidence`` when a
  connected source could have asserted it and did not, ``source-unavailable`` when no connected source
  can observe it at all.
* Public (shared) addresses are not devices on the network and are never candidates.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final

from netsight_api.identity.engine import CorrelationIndex
from netsight_api.identity.model import (
    Basis,
    CorrelationPolicy,
    EntityRef,
    EntityType,
    EvidenceRecord,
    Link,
    Reason,
    Relation,
    ip_ref,
    mac_ref,
)
from netsight_api.schemas_unknown_devices import (
    CheckResult,
    SlotName,
    SlotReason,
    UnknownDeviceCheck,
    UnknownDeviceComparison,
    UnknownDeviceEndpoint,
    UnknownDeviceEvidenceRef,
    UnknownDeviceLinkSlot,
    UnknownDeviceProposedAction,
)
from netsight_api.unknown_devices.model import Detection, subject_key_for
from netsight_api.unknown_devices.policy import SeverityPolicy

MAX_CANDIDATES: Final = 500
MAX_HOSTNAME: Final = 255
_SLOT_REASONS: Final = frozenset(
    {
        "declared-assignment",
        "indirect-evidence",
        "low-confidence",
        "name-match",
        "no-evidence",
        "expired",
        "conflicting-evidence",
        "source-unavailable",
        "guest-network",
    }
)
_ATTACHMENT: Final = ((Relation.MAC_SWITCH, "switch"), (Relation.MAC_AP, "ap"))
_QUARANTINE_RATIONALE: Final = "Severity {severity} reaches the operator's quarantine threshold"


@dataclass(frozen=True)
class Observed:
    """One telemetry source's report of an endpoint: any of address, MAC and name."""

    source: str
    kind: str
    native_id: str
    observed_at: datetime
    ip: str | None = None
    mac: str | None = None
    hostname: str | None = None


@dataclass(frozen=True)
class NetboxFacts:
    """What NetBox intends, reduced to what the comparison needs (all keys lower case)."""

    device_names: frozenset[str] = frozenset()
    primary_ips: Mapping[str, str] = field(default_factory=dict)
    assigned_ips: Mapping[str, str] = field(default_factory=dict)
    keyed_agents: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class MacCheck:
    """NetBox's answer for one MAC. ``incomplete``: it could not be asked (error or lookup limit)."""

    result: CheckResult
    detail: str | None = None
    incomplete: bool = False


@dataclass(frozen=True)
class Candidate:
    ip: str | None
    mac: str | None
    hostname: str | None
    observations: tuple[Observed, ...]


@dataclass(frozen=True)
class DetectResult:
    detections: tuple[Detection, ...]
    unverified: int


# --- candidates --------------------------------------------------------------------------------------------


def _clean_ip(value: str | None, correlation: CorrelationPolicy) -> str | None:
    if value is None:
        return None
    try:
        text = ip_ref(value).id
    except ValueError:
        return None
    address = ipaddress.ip_address(text)
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        return None
    return None if correlation.is_shared(text) else text


def _clean_mac(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return mac_ref(value).id
    except ValueError:
        return None


def _clean_name(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    return value.strip()[:MAX_HOSTNAME]


def _engine_pair(
    index: CorrelationIndex, subject: EntityRef, now: datetime
) -> tuple[str | None, str | None]:
    """The (ip, mac) the records pair with ``subject`` at ``now`` (resolved links only)."""
    ip = mac = None
    for link in index.resolve(subject, now).endpoint:
        if link.relation is Relation.IP_MAC and link.target is not None:
            ip = ip or _side(link, EntityType.IP)
            mac = mac or _side(link, EntityType.MAC)
    return ip, mac


def _side(link: Link, kind: EntityType) -> str | None:
    for entity in (link.source, link.target):
        if entity is not None and entity.type is kind:
            return entity.id
    return None


@dataclass
class _Draft:
    ip: str | None = None
    mac: str | None = None
    hostname: str | None = None
    observations: list[Observed] = field(default_factory=list)


class _Drafts:
    """Endpoints under construction, found again by MAC or by address."""

    def __init__(self) -> None:
        self._all: list[_Draft] = []
        self._by_mac: dict[str, _Draft] = {}
        self._by_ip: dict[str, _Draft] = {}
        self._by_name: dict[str, _Draft] = {}

    def find(self, ip: str | None, mac: str | None, name: str | None) -> _Draft:
        draft = self._by_mac.get(mac) if mac else None
        if draft is None and ip is not None:
            candidate = self._by_ip.get(ip)
            if candidate is not None and (mac is None or candidate.mac in (None, mac)):
                draft = candidate
        if draft is None and ip is None and mac is None and name is not None:
            draft = self._by_name.get(name.lower())
        if draft is None:
            draft = _Draft()
            self._all.append(draft)
        self._fill(draft, ip, mac, name)
        return draft

    def _fill(self, draft: _Draft, ip: str | None, mac: str | None, name: str | None) -> None:
        draft.ip = draft.ip or ip
        draft.mac = draft.mac or mac
        draft.hostname = draft.hostname or name
        if draft.mac:
            self._by_mac.setdefault(draft.mac, draft)
        if draft.ip:
            self._by_ip.setdefault(draft.ip, draft)
        if draft.hostname and not draft.ip and not draft.mac:
            self._by_name.setdefault(draft.hostname.lower(), draft)

    def all(self) -> list[_Draft]:
        return self._all


def collect_candidates(
    observations: Sequence[Observed],
    records: Sequence[EvidenceRecord],
    index: CorrelationIndex,
    correlation: CorrelationPolicy,
    now: datetime,
) -> tuple[list[Candidate], bool]:
    """Distinct endpoints, one per MAC (or per address without one); truncated when over the cap."""
    drafts = _Drafts()
    for obs in sorted(observations, key=lambda o: (o.source, o.native_id)):
        ip, mac, name = (
            _clean_ip(obs.ip, correlation),
            _clean_mac(obs.mac),
            _clean_name(obs.hostname),
        )
        if ip is None and mac is None and name is None:
            continue
        drafts.find(ip, mac, name).observations.append(obs)
    for record in records:
        for assertion in record.assertions:
            for entity in (assertion.a, assertion.b):
                if entity.type is EntityType.MAC:
                    drafts.find(None, entity.id, None)
                elif entity.type is EntityType.IP and _clean_ip(entity.id, correlation) is not None:
                    paired = _engine_pair(index, entity, now)[1]
                    drafts.find(entity.id, paired, None)
    candidates: list[Candidate] = []
    for draft in drafts.all():
        ip = draft.ip
        if ip is None and draft.mac is not None:
            ip = _clean_ip(_engine_pair(index, mac_ref(draft.mac), now)[0], correlation)
        if ip is None and draft.mac is None and draft.hostname is None:
            continue
        candidates.append(Candidate(ip, draft.mac, draft.hostname, tuple(draft.observations)))
    candidates.sort(key=lambda c: (c.mac or "", c.ip or "", (c.hostname or "").lower()))
    return candidates[:MAX_CANDIDATES], len(candidates) > MAX_CANDIDATES


def macs_to_check(candidates: Sequence[Candidate], facts: NetboxFacts | None = None) -> list[str]:
    """The MACs worth asking NetBox about: those of endpoints no other field already cleared."""
    return sorted(
        {
            c.mac
            for c in candidates
            if c.mac is not None
            and (
                facts is None
                or not (
                    _ip_check(c, facts).result == "match"
                    or _hostname_check(c, facts).result == "match"
                )
            )
        }
    )


# --- comparison with NetBox --------------------------------------------------------------------------------


def _ip_check(candidate: Candidate, facts: NetboxFacts) -> UnknownDeviceCheck:
    if candidate.ip is None:
        return UnknownDeviceCheck(
            field="ip", result="not-checked", detail="no address was observed"
        )
    owner = facts.primary_ips.get(candidate.ip) or facts.assigned_ips.get(candidate.ip)
    if owner is not None:
        return UnknownDeviceCheck(
            field="ip", result="match", detail="NetBox assigns this address to a device"
        )
    return UnknownDeviceCheck(field="ip", result="no-match", detail=None)


def _hostname_check(candidate: Candidate, facts: NetboxFacts) -> UnknownDeviceCheck:
    if any(
        o.source == "wazuh" and o.native_id in facts.keyed_agents for o in candidate.observations
    ):
        return UnknownDeviceCheck(
            field="hostname",
            result="match",
            detail="a NetBox device is joined to this agent by key",
        )
    if candidate.hostname is None:
        return UnknownDeviceCheck(
            field="hostname", result="not-checked", detail="no name was observed"
        )
    if candidate.hostname.strip().lower().rstrip(".") in facts.device_names:
        return UnknownDeviceCheck(
            field="hostname", result="match", detail="NetBox has a device of this name"
        )
    return UnknownDeviceCheck(field="hostname", result="no-match", detail=None)


def _mac_check(candidate: Candidate, results: Mapping[str, MacCheck]) -> UnknownDeviceCheck:
    if candidate.mac is None:
        return UnknownDeviceCheck(
            field="mac", result="not-checked", detail="no MAC address was observed"
        )
    answer = results.get(
        candidate.mac, MacCheck("not-checked", "NetBox was not asked", incomplete=True)
    )
    return UnknownDeviceCheck(field="mac", result=answer.result, detail=answer.detail)


# --- chain -------------------------------------------------------------------------------------------------


def _evidence(link: Link) -> list[UnknownDeviceEvidenceRef]:
    return [
        UnknownDeviceEvidenceRef(
            id=ref.id[:128],
            source=ref.source,
            kind=ref.kind.value,
            observed_at=ref.observed_at,
            confidence=ref.confidence,
        )
        for ref in link.evidence[:16]
    ]


def _observation_evidence(candidate: Candidate, which: str) -> list[UnknownDeviceEvidenceRef]:
    refs: list[UnknownDeviceEvidenceRef] = []
    for obs in candidate.observations:
        if getattr(obs, which) is not None:
            refs.append(
                UnknownDeviceEvidenceRef(
                    id=f"{obs.source}:{obs.native_id}"[:128],
                    source=obs.source,
                    kind=obs.kind,
                    observed_at=obs.observed_at,
                    confidence=None,
                )
            )
    return refs[:16]


def _unknown(name: SlotName, reason: SlotReason) -> UnknownDeviceLinkSlot:
    return UnknownDeviceLinkSlot(
        slot=name,
        basis="unknown",
        value=None,
        label=None,
        attachment_kind=None,
        confidence=None,
        reason=reason,
        evidence=[],
    )


def _reason(reason: Reason | None, default: SlotReason) -> SlotReason:
    return reason.value if reason is not None and reason.value in _SLOT_REASONS else default  # type: ignore[return-value]


def _slot_from(
    name: SlotName, link: Link, kind: EntityType, attachment: str | None = None
) -> UnknownDeviceLinkSlot:
    entity = next((e for e in (link.source, link.target) if e is not None and e.type is kind), None)
    if link.basis is Basis.UNKNOWN or entity is None:
        return _unknown(name, _reason(link.reason, "conflicting-evidence"))
    return UnknownDeviceLinkSlot(
        slot=name,
        basis=link.basis.value,  # type: ignore[arg-type]
        value=entity.id,
        label=entity.label,
        attachment_kind=attachment,  # type: ignore[arg-type]
        confidence=link.confidence,
        reason=None if link.basis is Basis.OBSERVED else _reason(link.reason, "indirect-evidence"),
        evidence=_evidence(link),
    )


def _link_for(links: Sequence[Link], relation: Relation) -> Link | None:
    matching = [link for link in links if link.relation is relation]
    matching.sort(
        key=lambda link: {Basis.OBSERVED: 0, Basis.INFERRED: 1, Basis.UNKNOWN: 2}[link.basis]
    )
    return matching[0] if matching else None


def _absent_reason(
    relations: Collection[Relation], capabilities: Collection[Relation]
) -> SlotReason:
    return "no-evidence" if any(r in capabilities for r in relations) else "source-unavailable"


def build_chain(
    candidate: Candidate,
    links: Sequence[Link],
    capabilities: Collection[Relation],
) -> tuple[UnknownDeviceLinkSlot, ...]:
    ip_link = _link_for(links, Relation.IP_MAC)
    if candidate.ip is not None:
        refs = _observation_evidence(candidate, "ip")
        if refs:
            ip_slot = UnknownDeviceLinkSlot(
                slot="ip",
                basis="observed",
                value=candidate.ip,
                label=None,
                attachment_kind=None,
                confidence=None,
                reason=None,
                evidence=refs,
            )
        elif ip_link is not None:
            ip_slot = _slot_from("ip", ip_link, EntityType.IP)
        else:
            ip_slot = _unknown("ip", "no-evidence")
    else:
        ip_slot = _unknown("ip", "no-evidence")
    if candidate.mac is not None:
        refs = _observation_evidence(candidate, "mac")
        if refs:
            mac_slot = UnknownDeviceLinkSlot(
                slot="mac",
                basis="observed",
                value=candidate.mac,
                label=None,
                attachment_kind=None,
                confidence=None,
                reason=None,
                evidence=refs,
            )
        else:
            mac_slot = (
                _slot_from("mac", ip_link, EntityType.MAC)
                if ip_link
                else _unknown("mac", "no-evidence")
            )
    else:
        mac_slot = _unknown("mac", "no-evidence")
    return (ip_slot, mac_slot, *_where(links, capabilities))


def _where(
    links: Sequence[Link], capabilities: Collection[Relation]
) -> tuple[UnknownDeviceLinkSlot, ...]:
    attachment: UnknownDeviceLinkSlot | None = None
    for relation, kind in _ATTACHMENT:
        link = _link_for(links, relation)
        if link is not None:
            attachment = _slot_from(
                "attachment", link, EntityType.SWITCH if kind == "switch" else EntityType.AP, kind
            )
            break
    port_link = _link_for(links, Relation.MAC_PORT)
    port = _slot_from("port", port_link, EntityType.PORT) if port_link else None
    vlan_link = _link_for(links, Relation.MAC_VLAN)
    vlan = _slot_from("vlan", vlan_link, EntityType.VLAN) if vlan_link else None
    if vlan is None and port is not None and port.value is not None:
        via_port = next(
            (
                l
                for l in links
                if l.relation is Relation.PORT_VLAN
                and port.value in (l.source.id, l.target.id if l.target else "")
            ),
            None,
        )
        vlan = _slot_from("vlan", via_port, EntityType.VLAN) if via_port else None
    return (
        attachment
        or _unknown(
            "attachment", _absent_reason((Relation.MAC_SWITCH, Relation.MAC_AP), capabilities)
        ),
        port or _unknown("port", _absent_reason((Relation.MAC_PORT,), capabilities)),
        vlan
        or _unknown("vlan", _absent_reason((Relation.MAC_VLAN, Relation.PORT_VLAN), capabilities)),
    )


def _vlan_number(slot: UnknownDeviceLinkSlot) -> int | None:
    if slot.value is not None and slot.value.startswith("vlan-") and slot.value[5:].isdigit():
        return int(slot.value[5:])
    return None


# --- the whole comparison ----------------------------------------------------------------------------------


def detect(
    candidates: Sequence[Candidate],
    *,
    facts: NetboxFacts,
    mac_results: Mapping[str, MacCheck],
    index: CorrelationIndex,
    policy: SeverityPolicy,
    capabilities: Collection[Relation],
    now: datetime,
) -> DetectResult:
    found: list[Detection] = []
    unverified = 0
    for candidate in sorted(candidates, key=lambda c: (c.mac or "", c.ip or "", c.hostname or "")):
        checks = (
            _ip_check(candidate, facts),
            _mac_check(candidate, mac_results),
            _hostname_check(candidate, facts),
        )
        if any(c.result == "match" for c in checks):
            continue
        mac_answer = mac_results.get(candidate.mac) if candidate.mac else None
        if candidate.mac is not None and (mac_answer is None or mac_answer.incomplete):
            unverified += (
                1  # NetBox could not be asked about this MAC: never read as "unknown to NetBox"
            )
            continue
        if all(c.result == "not-checked" for c in checks):
            unverified += 1
            continue
        subject = (
            mac_ref(candidate.mac)
            if candidate.mac
            else ip_ref(candidate.ip)
            if candidate.ip
            else None
        )
        links = list(index.resolve(subject, now).endpoint) if subject is not None else []
        chain = build_chain(candidate, links, capabilities)
        endpoint = UnknownDeviceEndpoint(
            ip=candidate.ip, mac=candidate.mac, hostname=candidate.hostname
        )
        severity, basis = policy.decide(candidate.ip, _vlan_number(chain[4]))
        action = (
            UnknownDeviceProposedAction(
                action_type="endpoint.isolate",
                state="proposed",
                risk="C",
                executable=False,
                awaiting="action-engine",
                rationale=_QUARANTINE_RATIONALE.format(severity=severity),
            )
            if policy.recommends_quarantine(severity)
            else None
        )
        found.append(
            Detection(
                subject_key=subject_key_for(endpoint),
                endpoint=endpoint,
                chain=chain,
                comparison=UnknownDeviceComparison(checks=list(checks), checked_at=now),
                severity=severity,
                severity_basis=basis,
                proposed_action=action,
            )
        )
    return DetectResult(tuple(found), unverified)
