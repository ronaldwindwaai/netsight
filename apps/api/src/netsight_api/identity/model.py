"""Domain model for identity correlation (PRD 10, 36; NS-043).

The chain is Person -> Account -> Device -> IP -> MAC -> Switch/AP -> Port -> VLAN. Sources never
assert a whole chain: each one is an ``EvidenceRecord`` that asserts one or a few *relations*
between two entities (a DHCP lease: IP <-> MAC; a RADIUS session: account <-> MAC, MAC <-> port;
a directory entry: person <-> account) for a validity window, with the source's own confidence.
The engine (``engine.py``) composes them; nothing here guesses.

Honesty rules the types enforce, not just document:

* every relation an evidence kind may assert is a fixed allow-list (``KIND_RELATIONS``): an IdP
  sign-in cannot assert a MAC binding, however the record is phrased;
* an evidence *kind* is either ``direct`` (the source observed the relation) or ``indirect`` (a
  declaration or a weak association). An indirect kind can never yield ``Basis.OBSERVED``;
* a link's basis is ``observed``, ``inferred`` or ``unknown`` and the invariants between basis,
  target, confidence, evidence and reason are checked on construction (``Link.__post_init__``);
* inferred confidence is capped (``INFERRED_CEILING``) so an inference can never look as sure as
  an observation;
* a person is never keyed by an e-mail address or a display name: ids are canonical
  ``person-<uuid>`` values minted per source (``person_ref``), labels are display text only.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import NAMESPACE_URL, uuid5

# A direct record at or above this confidence is "observed"; below it the link is "inferred".
OBSERVED_MIN_CONFIDENCE = 0.8
# No inferred link reports more than this, whatever the source claimed.
INFERRED_CEILING = 0.7
MAX_ASSERTIONS_PER_RECORD = 8
MAX_LABEL_LENGTH = 128
MAX_EVIDENCE_PER_LINK = 16
MAX_CANDIDATES = 8

_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_SOURCE_PATTERN = re.compile(r"[a-z0-9][a-z0-9_.-]{0,31}")
_MAC_PATTERN = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
_HOSTNAME_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?")
_VLAN_PATTERN = re.compile(r"vlan-([1-9][0-9]{0,3})")
# Address space that is private to one organisation. Anything else (public, documentation, CGNAT,
# multicast, ...) is shared by default: an address many hosts can appear behind is not identity.
_INTERNAL_SPACE = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
    )
)


class EntityType(StrEnum):
    PERSON = "person"
    ACCOUNT = "account"
    DEVICE = "device"
    IP = "ip"
    MAC = "mac"
    SWITCH = "switch"
    AP = "ap"
    PORT = "port"
    VLAN = "vlan"
    HOSTNAME = "hostname"


_ID_PATTERNS: Mapping[EntityType, re.Pattern[str]] = {
    EntityType.PERSON: re.compile(rf"person-{_UUID}"),
    EntityType.ACCOUNT: re.compile(rf"account-{_UUID}"),
    # A switch and an access point are devices in the canonical model: same id shape.
    EntityType.DEVICE: re.compile(rf"device-{_UUID}"),
    EntityType.SWITCH: re.compile(rf"device-{_UUID}"),
    EntityType.AP: re.compile(rf"device-{_UUID}"),
    EntityType.PORT: re.compile(rf"port-{_UUID}"),
    EntityType.MAC: _MAC_PATTERN,
    EntityType.HOSTNAME: _HOSTNAME_PATTERN,
}


def is_valid_entity_id(kind: EntityType, value: str) -> bool:
    """True when ``value`` is a canonical id for ``kind`` (the one rule shared with the API models)."""
    if kind is EntityType.IP:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False
        # One spelling per address: canonical text, no zone id, and IPv4-mapped IPv6 is the IPv4.
        mapped = ip.version == 6 and ip.ipv4_mapped is not None
        return str(ip) == value and not mapped and "%" not in value
    if kind is EntityType.VLAN:
        match = _VLAN_PATTERN.fullmatch(value)
        return match is not None and 1 <= int(match.group(1)) <= 4094
    return _ID_PATTERNS[kind].fullmatch(value) is not None


@dataclass(frozen=True)
class EntityRef:
    """One node of the chain. Identity is ``(type, id)``; the label is untrusted display text."""

    type: EntityType
    id: str
    label: str | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        if not is_valid_entity_id(self.type, self.id):
            raise ValueError(f"not a canonical {self.type.value} id")
        if self.label is not None and (
            not self.label.strip() or len(self.label) > MAX_LABEL_LENGTH
        ):
            raise ValueError("label must be non-blank text of at most 128 characters")

    @property
    def key(self) -> tuple[str, str]:
        return (self.type.value, self.id)


def _minted(kind: str, source: str, native_id: str) -> str:
    if not _SOURCE_PATTERN.fullmatch(source) or not native_id.strip():
        raise ValueError("source and native id are required")
    return f"{kind}-{uuid5(NAMESPACE_URL, f'urn:netsight:{source}:{kind}:{native_id}')}"


def _clean_label(label: str | None) -> str | None:
    if label is None:
        return None
    text = label.strip()
    return text[:MAX_LABEL_LENGTH] if text else None


def person_ref(source: str, native_id: str, label: str | None = None) -> EntityRef:
    return EntityRef(EntityType.PERSON, _minted("person", source, native_id), _clean_label(label))


def account_ref(source: str, native_id: str, label: str | None = None) -> EntityRef:
    return EntityRef(EntityType.ACCOUNT, _minted("account", source, native_id), _clean_label(label))


def device_ref(source: str, native_id: str, label: str | None = None) -> EntityRef:
    """Same scheme as ``adapters.netbox.canonical_device_id`` so ids agree across the platform."""
    return EntityRef(EntityType.DEVICE, _minted("device", source, native_id), _clean_label(label))


def switch_ref(source: str, native_id: str, label: str | None = None) -> EntityRef:
    return EntityRef(EntityType.SWITCH, _minted("device", source, native_id), _clean_label(label))


def ap_ref(source: str, native_id: str, label: str | None = None) -> EntityRef:
    return EntityRef(EntityType.AP, _minted("device", source, native_id), _clean_label(label))


def port_ref(device_id: str, name: str) -> EntityRef:
    if not name.strip():
        raise ValueError("a port needs a name")
    return EntityRef(
        EntityType.PORT, _minted("port", "netsight", f"{device_id}/{name}"), _clean_label(name)
    )


def ip_ref(address: str) -> EntityRef:
    ip = ipaddress.ip_address(address.strip())
    if ip.version == 6:
        if ip.scope_id is not None:
            raise ValueError("an address with a zone id is not an endpoint identity")
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
    return EntityRef(EntityType.IP, str(ip))


def mac_ref(address: str) -> EntityRef:
    digits = re.sub(r"[^0-9a-fA-F]", "", address)
    if len(digits) != 12:
        raise ValueError("not a MAC address")
    pairs = [digits[i : i + 2] for i in range(0, 12, 2)]
    return EntityRef(EntityType.MAC, ":".join(pairs).lower())


def vlan_ref(number: int, label: str | None = None) -> EntityRef:
    return EntityRef(EntityType.VLAN, f"vlan-{number}", _clean_label(label))


def hostname_ref(name: str) -> EntityRef:
    return EntityRef(EntityType.HOSTNAME, name.strip().lower().rstrip("."))


class Basis(StrEnum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class Reason(StrEnum):
    """Why a link is not simply observed. Required for every inferred and unknown link."""

    # inferred
    DECLARED_ASSIGNMENT = "declared-assignment"
    INDIRECT_EVIDENCE = "indirect-evidence"
    LOW_CONFIDENCE = "low-confidence"
    NAME_MATCH = "name-match"
    # unknown
    NO_EVIDENCE = "no-evidence"
    EXPIRED = "expired"
    CONFLICTING = "conflicting-evidence"
    MULTIPLE_CANDIDATES = "multiple-candidates"
    SHARED_ADDRESS = "shared-address"
    VPN_NO_SESSION = "vpn-no-session"
    GUEST_NETWORK = "guest-network"
    IP_ONLY = "ip-only"
    SOURCE_UNAVAILABLE = "source-unavailable"
    # The caller's role may see the endpoint but not who is behind it (users:read-limited).
    RESTRICTED = "restricted"


class EvidenceKind(StrEnum):
    DHCP_LEASE = "dhcp-lease"
    RADIUS_SESSION = "radius-session"
    VPN_SESSION = "vpn-session"
    WIFI_ASSOCIATION = "wifi-association"
    SWITCH_MAC_TABLE = "switch-mac-table"
    ENDPOINT_AGENT = "endpoint-agent"
    DIRECTORY_ACCOUNT = "directory-account"
    IDP_SIGNIN = "idp-signin"
    DNS_RECORD = "dns-record"
    ASSET_ASSIGNMENT = "asset-assignment"


class Relation(StrEnum):
    PERSON_ACCOUNT = "person-account"
    ACCOUNT_DEVICE = "account-device"
    PERSON_DEVICE = "person-device"
    ACCOUNT_MAC = "account-mac"
    ACCOUNT_IP = "account-ip"
    DEVICE_IP = "device-ip"
    DEVICE_MAC = "device-mac"
    IP_MAC = "ip-mac"
    MAC_SWITCH = "mac-switch"
    MAC_AP = "mac-ap"
    MAC_PORT = "mac-port"
    MAC_VLAN = "mac-vlan"
    PORT_VLAN = "port-vlan"
    HOSTNAME_IP = "hostname-ip"
    # Derived by the engine, never asserted by a source:
    HOSTNAME_DEVICE = "hostname-device"
    IDENTITY = "identity"


@dataclass(frozen=True)
class RelationSpec:
    a_type: EntityType
    b_type: EntityType
    # At one instant an ``a`` has at most one ``b`` / a ``b`` has at most one ``a``. Two direct
    # claims that disagree on an exclusive side are a conflict and are never resolved by picking.
    one_b_per_a: bool = False
    one_a_per_b: bool = False


_T = EntityType
RELATIONS: Mapping[Relation, RelationSpec] = {
    Relation.PERSON_ACCOUNT: RelationSpec(_T.PERSON, _T.ACCOUNT, one_a_per_b=True),
    Relation.ACCOUNT_DEVICE: RelationSpec(_T.ACCOUNT, _T.DEVICE),
    Relation.PERSON_DEVICE: RelationSpec(_T.PERSON, _T.DEVICE),
    Relation.ACCOUNT_MAC: RelationSpec(_T.ACCOUNT, _T.MAC, one_a_per_b=True),
    Relation.ACCOUNT_IP: RelationSpec(_T.ACCOUNT, _T.IP, one_a_per_b=True),
    Relation.DEVICE_IP: RelationSpec(_T.DEVICE, _T.IP, one_a_per_b=True),
    Relation.DEVICE_MAC: RelationSpec(_T.DEVICE, _T.MAC, one_a_per_b=True),
    Relation.IP_MAC: RelationSpec(_T.IP, _T.MAC, one_b_per_a=True),
    Relation.MAC_SWITCH: RelationSpec(_T.MAC, _T.SWITCH, one_b_per_a=True),
    Relation.MAC_AP: RelationSpec(_T.MAC, _T.AP, one_b_per_a=True),
    Relation.MAC_PORT: RelationSpec(_T.MAC, _T.PORT, one_b_per_a=True),
    Relation.MAC_VLAN: RelationSpec(_T.MAC, _T.VLAN, one_b_per_a=True),
    Relation.PORT_VLAN: RelationSpec(_T.PORT, _T.VLAN, one_b_per_a=True),
    Relation.HOSTNAME_IP: RelationSpec(_T.HOSTNAME, _T.IP),
}
DERIVED_RELATIONS = frozenset({Relation.HOSTNAME_DEVICE, Relation.IDENTITY})


@dataclass(frozen=True)
class KindProfile:
    direct: bool
    open_ttl: timedelta
    # Why a link supported only by this kind is inferred (None for direct kinds).
    inferred_reason: Reason | None
    relations: frozenset[Relation]


_R = Relation
KIND_PROFILES: Mapping[EvidenceKind, KindProfile] = {
    EvidenceKind.DHCP_LEASE: KindProfile(True, timedelta(hours=1), None, frozenset({_R.IP_MAC})),
    EvidenceKind.RADIUS_SESSION: KindProfile(
        True,
        timedelta(minutes=15),
        None,
        frozenset({_R.ACCOUNT_MAC, _R.MAC_PORT, _R.MAC_VLAN, _R.MAC_SWITCH, _R.MAC_AP}),
    ),
    EvidenceKind.VPN_SESSION: KindProfile(
        True, timedelta(minutes=15), None, frozenset({_R.ACCOUNT_IP})
    ),
    EvidenceKind.WIFI_ASSOCIATION: KindProfile(
        True,
        timedelta(minutes=15),
        None,
        frozenset({_R.MAC_AP, _R.MAC_VLAN, _R.ACCOUNT_MAC}),
    ),
    EvidenceKind.SWITCH_MAC_TABLE: KindProfile(
        True,
        timedelta(minutes=15),
        None,
        frozenset({_R.MAC_PORT, _R.MAC_SWITCH, _R.PORT_VLAN, _R.MAC_VLAN}),
    ),
    # Wazuh writes an agent-status snapshot about every 15 minutes, so an open record is trusted
    # for twice that.
    EvidenceKind.ENDPOINT_AGENT: KindProfile(
        True, timedelta(minutes=30), None, frozenset({_R.DEVICE_IP, _R.DEVICE_MAC})
    ),
    EvidenceKind.DIRECTORY_ACCOUNT: KindProfile(
        True, timedelta(hours=24), None, frozenset({_R.PERSON_ACCOUNT})
    ),
    EvidenceKind.IDP_SIGNIN: KindProfile(
        False,
        timedelta(minutes=30),
        Reason.INDIRECT_EVIDENCE,
        frozenset({_R.ACCOUNT_IP, _R.ACCOUNT_DEVICE}),
    ),
    EvidenceKind.DNS_RECORD: KindProfile(
        False, timedelta(minutes=5), Reason.INDIRECT_EVIDENCE, frozenset({_R.HOSTNAME_IP})
    ),
    EvidenceKind.ASSET_ASSIGNMENT: KindProfile(
        False,
        timedelta(hours=24),
        Reason.DECLARED_ASSIGNMENT,
        frozenset({_R.PERSON_DEVICE, _R.DEVICE_IP, _R.DEVICE_MAC}),
    ),
}


@dataclass(frozen=True)
class Assertion:
    """One relation a source asserts. ``a`` and ``b`` follow the relation's own orientation."""

    a: EntityRef
    relation: Relation
    b: EntityRef

    def __post_init__(self) -> None:
        spec = RELATIONS.get(self.relation)
        if spec is None:
            raise ValueError("a source cannot assert a derived relation")
        if self.a.type is not spec.a_type or self.b.type is not spec.b_type:
            raise ValueError("assertion endpoints do not match the relation")


def _aware_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True)
class EvidenceRecord:
    """What one source said, for one validity window, with its own confidence.

    ``(source, native_id)`` names the thing the source tracks (a lease, a session). When the same
    pair arrives twice the one observed later supersedes the other: that is how a session-stop
    replaces its still-open start. ``valid_to`` is ``None`` for a window with no recorded end; the
    engine then trusts it only for the kind's ``open_ttl`` after ``observed_at``.
    """

    source: str
    native_id: str
    kind: EvidenceKind
    observed_at: datetime
    valid_from: datetime
    valid_to: datetime | None
    confidence: float
    assertions: tuple[Assertion, ...]
    guest: bool = False

    def __post_init__(self) -> None:
        if not _SOURCE_PATTERN.fullmatch(self.source):
            raise ValueError("source must be a short lower-case identifier")
        if not self.native_id.strip() or len(self.native_id) > 128:
            raise ValueError("native_id must be non-blank text of at most 128 characters")
        if (
            isinstance(self.confidence, bool)
            or not isinstance(self.confidence, int | float)
            or not math.isfinite(self.confidence)
            or not 0.0 <= self.confidence <= 1.0
        ):
            raise ValueError("confidence must be a number from 0 to 1")
        object.__setattr__(self, "observed_at", _aware_utc(self.observed_at, "observed_at"))
        object.__setattr__(self, "valid_from", _aware_utc(self.valid_from, "valid_from"))
        if self.valid_to is not None:
            object.__setattr__(self, "valid_to", _aware_utc(self.valid_to, "valid_to"))
            if self.valid_to <= self.valid_from:
                raise ValueError("valid_to must be after valid_from")
        if not 1 <= len(self.assertions) <= MAX_ASSERTIONS_PER_RECORD:
            raise ValueError("a record carries 1 to 8 assertions")
        allowed = KIND_PROFILES[self.kind].relations
        if any(item.relation not in allowed for item in self.assertions):
            raise ValueError(f"{self.kind.value} cannot assert that relation")

    @property
    def id(self) -> str:
        return f"{self.source}:{self.native_id}"

    @property
    def direct(self) -> bool:
        return KIND_PROFILES[self.kind].direct

    @property
    def effective_end(self) -> datetime:
        if self.valid_to is not None:
            return self.valid_to
        return self.observed_at + KIND_PROFILES[self.kind].open_ttl


@dataclass(frozen=True)
class CorrelationPolicy:
    """Network classification the engine needs and cannot learn from evidence.

    ``shared_cidrs``: NAT egress and similar many-to-one ranges. Everything outside RFC 1918 / ULA /
    link-local space is shared too unless listed in ``internal_cidrs`` (an organisation's own
    public block). ``vpn_cidrs``: VPN client pools (identity only through a VPN session).
    ``guest_cidrs`` and ``guest_vlans``: guest/BYOD networks that are never attributed to a person.
    ``static_cidrs``: server and static-assignment ranges, where an address belongs to whoever the
    register says. A host-agent's claim to an address there is not evidence of who holds it (a rogue
    agent could otherwise report a server's address and weaken its attribution), so it is ignored.

    Deployment prerequisite: ``guest_cidrs``/``guest_vlans`` and ``shared_cidrs`` are not learned.
    A guest or shared network that is not listed is treated like any other internal range.
    """

    shared_cidrs: tuple[str, ...] = ()
    internal_cidrs: tuple[str, ...] = ()
    vpn_cidrs: tuple[str, ...] = ()
    guest_cidrs: tuple[str, ...] = ()
    guest_vlans: tuple[int, ...] = ()
    static_cidrs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("shared_cidrs", "internal_cidrs", "vpn_cidrs", "guest_cidrs", "static_cidrs"):
            for cidr in getattr(self, name):
                ipaddress.ip_network(cidr, strict=False)  # raises ValueError
        if any(not 1 <= vlan <= 4094 for vlan in self.guest_vlans):
            raise ValueError("a VLAN number is 1 to 4094")

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> CorrelationPolicy:
        def cidrs(name: str) -> tuple[str, ...]:
            return tuple(part.strip() for part in env.get(name, "").split(",") if part.strip())

        vlans = tuple(
            int(part)
            for part in env.get("NETSIGHT_IDENTITY_GUEST_VLANS", "").split(",")
            if part.strip()
        )
        return cls(
            shared_cidrs=cidrs("NETSIGHT_IDENTITY_SHARED_CIDRS"),
            internal_cidrs=cidrs("NETSIGHT_IDENTITY_INTERNAL_CIDRS"),
            vpn_cidrs=cidrs("NETSIGHT_IDENTITY_VPN_CIDRS"),
            guest_cidrs=cidrs("NETSIGHT_IDENTITY_GUEST_CIDRS"),
            guest_vlans=vlans,
            static_cidrs=cidrs("NETSIGHT_IDENTITY_STATIC_CIDRS"),
        )

    def _in(self, address: str, cidrs: tuple[str, ...]) -> bool:
        ip = ipaddress.ip_address(address)
        return any(ip in ipaddress.ip_network(cidr, strict=False) for cidr in cidrs)

    def is_shared(self, address: str) -> bool:
        """Public, CGNAT or configured NAT egress: many hosts behind one address."""
        ip = ipaddress.ip_address(address)
        if self._in(address, self.shared_cidrs):
            return True
        internal = any(ip in net for net in _INTERNAL_SPACE if net.version == ip.version)
        return not internal and not self._in(address, self.internal_cidrs)

    def is_vpn(self, address: str) -> bool:
        return self._in(address, self.vpn_cidrs)

    def is_guest_address(self, address: str) -> bool:
        return self._in(address, self.guest_cidrs)

    def is_static_address(self, address: str) -> bool:
        return self._in(address, self.static_cidrs)


# --- results ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceRef:
    """A pointer to the evidence behind a link: enough to drill down, nothing about the entities."""

    id: str
    source: str
    kind: EvidenceKind
    observed_at: datetime
    valid_from: datetime
    valid_to: datetime | None
    confidence: float

    @classmethod
    def of(cls, record: EvidenceRecord) -> EvidenceRef:
        return cls(
            record.id,
            record.source,
            record.kind,
            record.observed_at,
            record.valid_from,
            record.valid_to,
            record.confidence,
        )


@dataclass(frozen=True)
class Candidate:
    """One of several entities a link could point at. Its basis describes that candidate alone."""

    entity: EntityRef
    basis: Basis
    confidence: float | None
    evidence: tuple[EvidenceRef, ...]


@dataclass(frozen=True)
class Link:
    relation: Relation
    source: EntityRef
    target: EntityRef | None
    basis: Basis
    confidence: float | None
    valid_from: datetime | None
    valid_to: datetime | None
    as_of: datetime
    reason: Reason | None
    evidence: tuple[EvidenceRef, ...]
    ambiguous: bool = False
    candidates: tuple[Candidate, ...] = ()

    def __post_init__(self) -> None:
        if len(self.evidence) > MAX_EVIDENCE_PER_LINK or len(self.candidates) > MAX_CANDIDATES:
            raise ValueError("a link carries bounded evidence and candidates")
        if self.basis is Basis.OBSERVED:
            ok = (
                self.target is not None
                and self.confidence is not None
                and bool(self.evidence)
                and self.reason is None
                and not self.ambiguous
                and not self.candidates
            )
        elif self.basis is Basis.INFERRED:
            ok = (
                self.target is not None
                and self.confidence is not None
                and self.confidence <= INFERRED_CEILING
                and bool(self.evidence)
                and self.reason is not None
                and not self.ambiguous
                and not self.candidates
            )
        else:
            ok = (
                self.target is None
                and self.confidence is None
                and self.reason is not None
                and (len(self.candidates) >= 2 if self.ambiguous else not self.candidates)
            )
        if not ok:
            raise ValueError(f"a {self.basis.value} link violates the basis invariants")


@dataclass(frozen=True)
class Attribution:
    """Who is behind the subject: identified persons (``links``) or an honest answer why not.

    ``links`` holds one ``IDENTITY`` link per identified person, strongest first; it is empty when
    the basis is unknown. When the evidence names several persons at the same strength, or
    conflicts, ``ambiguous`` is set, ``links`` is empty and ``candidates`` lists them: the engine
    never picks one.
    """

    basis: Basis
    reason: Reason | None
    ambiguous: bool
    links: tuple[Link, ...]
    candidates: tuple[Candidate, ...]


@dataclass(frozen=True)
class Resolution:
    subject: EntityRef
    as_of: datetime
    attribution: Attribution
    endpoint: tuple[Link, ...]


@dataclass(frozen=True)
class Session:
    """One current way a person is on the network: wired, Wi-Fi or VPN, as an ordered link list."""

    kind: str
    links: tuple[Link, ...]
    basis: Basis
    confidence: float
    valid_from: datetime
    valid_to: datetime


@dataclass(frozen=True)
class PersonView:
    person: EntityRef
    as_of: datetime
    accounts: tuple[Link, ...]
    sessions: tuple[Session, ...]
    assigned_devices: tuple[Link, ...]


@dataclass(frozen=True)
class PersonSummary:
    person: EntityRef
    account_count: int
    assigned_device_count: int
    session_count: int
    vpn_session_count: int
    # observed/inferred when a current session is evidenced; unknown means "no session evidence",
    # which is not the same as offline.
    presence: Basis
    last_evidence_at: datetime | None
