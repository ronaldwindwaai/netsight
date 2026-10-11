"""Typed boundary models for the identity-correlation surface (Step 6).

Mirrors ``contracts/json-schema/identity.schema.json`` and ``identity-users.schema.json``, the
OpenAPI components and the browser parser (``api-contracts-identity.ts``); shared vectors live in
``contracts/test-vectors/identity.vectors.json``.

Honesty rules, enforced here and not only by construction:

* a correlation is ``observed``, ``inferred`` or ``unknown``. Observed needs a target, a
  confidence, a window and evidence and no reason; inferred is capped at 0.7 and carries a reason;
  unknown has no target and no confidence, and when it is ``ambiguous`` it lists two or more
  candidates (the engine never picks one);
* the endpoints of a link match its relation (an ``ip-mac`` link joins an IP and a MAC) and an
  ``identity`` link ends at a person;
* a session is as strong as its weakest link, an attribution as strong as its strongest;
* a non-ok state carries no values: no persons, no counts, no links.

Every ``label``, signature and subject value is untrusted source text: it is carried as data and
never interpreted.
"""

from __future__ import annotations

import ipaddress
from datetime import timedelta
from typing import Annotated, Literal

from pydantic import AwareDatetime, ConfigDict, Field, model_validator

from netsight_api.identity.model import (
    INFERRED_CEILING,
    EntityType,
    is_valid_entity_id,
)
from netsight_api.schemas import ApiModel, Freshness

EntityKind = Literal[
    "person", "account", "device", "ip", "mac", "switch", "ap", "port", "vlan", "hostname"
]
Basis = Literal["observed", "inferred", "unknown"]
KnownBasis = Literal["observed", "inferred"]
SourceState = Literal["not-connected", "unknown", "ok"]
Relation = Literal[
    "person-account",
    "account-device",
    "person-device",
    "account-mac",
    "account-ip",
    "device-ip",
    "device-mac",
    "ip-mac",
    "mac-switch",
    "mac-ap",
    "mac-port",
    "mac-vlan",
    "port-vlan",
    "hostname-ip",
    "hostname-device",
    "identity",
]
EvidenceKindName = Literal[
    "dhcp-lease",
    "radius-session",
    "vpn-session",
    "wifi-association",
    "switch-mac-table",
    "endpoint-agent",
    "directory-account",
    "idp-signin",
    "dns-record",
    "asset-assignment",
]
InferredReason = Literal[
    "declared-assignment",
    "indirect-evidence",
    "low-confidence",
    "name-match",
    "conflicting-evidence",
]
UnknownReason = Literal[
    "no-evidence",
    "expired",
    "conflicting-evidence",
    "multiple-candidates",
    "shared-address",
    "vpn-no-session",
    "guest-network",
    "ip-only",
    "source-unavailable",
    "restricted",
]
Reason = InferredReason | UnknownReason
SessionKind = Literal["wired", "wifi", "vpn", "network"]
Severity = Literal["info", "low", "medium", "high", "critical"]

_INFERRED_REASONS = frozenset(InferredReason.__args__)  # type: ignore[attr-defined]
_UNKNOWN_REASONS = frozenset(UnknownReason.__args__)  # type: ignore[attr-defined]
_BASIS_RANK = {"observed": 0, "inferred": 1, "unknown": 2}
_SOURCE_PATTERN = r"^[a-z0-9][a-z0-9_.-]{0,31}$"
_PERSON_ID_PATTERN = r"^person-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
_ADDRESS_PATTERN = r"^[0-9a-f:.]{2,45}$"
MAX_WINDOW = timedelta(days=31)
MAX_EVIDENCE = 16
MAX_CANDIDATES = 8
MAX_ENDPOINT_LINKS = 64
MAX_SESSION_LINKS = 80

Confidence = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
Label = Annotated[str, Field(min_length=1, max_length=128, pattern=r"\S")]

# relation -> (type of one end, type of the other). Orientation is the walk's, not the relation's.
_RELATION_TYPES: dict[str, tuple[str, str]] = {
    "person-account": ("person", "account"),
    "account-device": ("account", "device"),
    "person-device": ("person", "device"),
    "account-mac": ("account", "mac"),
    "account-ip": ("account", "ip"),
    "device-ip": ("device", "ip"),
    "device-mac": ("device", "mac"),
    "ip-mac": ("ip", "mac"),
    "mac-switch": ("mac", "switch"),
    "mac-ap": ("mac", "ap"),
    "mac-port": ("mac", "port"),
    "mac-vlan": ("mac", "vlan"),
    "port-vlan": ("port", "vlan"),
    "hostname-ip": ("hostname", "ip"),
    "hostname-device": ("hostname", "device"),
}
_IDENTITY_SUBJECTS = frozenset({"ip", "mac", "hostname", "device"})


class EntityRef(ApiModel):
    type: EntityKind
    id: str = Field(min_length=1, max_length=128)
    label: Label | None

    @model_validator(mode="after")
    def _canonical_id(self) -> EntityRef:
        if not is_valid_entity_id(EntityType(self.type), self.id):
            raise ValueError(f"not a canonical {self.type} id")
        return self

    @property
    def key(self) -> tuple[str, str]:
        return (self.type, self.id)


class EvidenceRef(ApiModel):
    id: str = Field(min_length=3, max_length=161, pattern=r"^[a-z0-9][a-z0-9_.-]{0,31}:.+$")
    source: str = Field(pattern=_SOURCE_PATTERN)
    kind: EvidenceKindName
    observed_at: AwareDatetime
    valid_from: AwareDatetime
    valid_to: AwareDatetime | None
    confidence: Confidence

    @model_validator(mode="after")
    def _window_is_ordered(self) -> EvidenceRef:
        if self.valid_to is not None and self.valid_to <= self.valid_from:
            raise ValueError("valid_to must be after valid_from")
        if not self.id.startswith(f"{self.source}:"):
            raise ValueError("the evidence id starts with its source")
        return self


class Candidate(ApiModel):
    entity: EntityRef
    basis: KnownBasis
    confidence: Confidence
    evidence: list[EvidenceRef] = Field(max_length=MAX_EVIDENCE)

    @model_validator(mode="after")
    def _inferred_is_capped(self) -> Candidate:
        if self.basis == "inferred" and self.confidence > INFERRED_CEILING:
            raise ValueError("an inferred candidate is capped at 0.7")
        return self


class IdentityLink(ApiModel):
    relation: Relation
    source: EntityRef
    target: EntityRef | None
    basis: Basis
    confidence: Confidence | None
    valid_from: AwareDatetime | None
    valid_to: AwareDatetime | None
    as_of: AwareDatetime
    reason: Reason | None
    evidence: list[EvidenceRef] = Field(max_length=MAX_EVIDENCE)
    ambiguous: bool
    candidates: list[Candidate] = Field(max_length=MAX_CANDIDATES)

    @model_validator(mode="after")
    def _basis_invariants(self) -> IdentityLink:
        if self.basis == "unknown":
            self._check_unknown()
        else:
            self._check_known()
        return self

    def _check_known(self) -> None:
        if (
            self.target is None
            or self.confidence is None
            or self.valid_from is None
            or self.valid_to is None
            or not self.evidence
            or self.ambiguous
            or self.candidates
        ):
            raise ValueError(f"a {self.basis} link needs a target, confidence, window and evidence")
        if self.basis == "observed" and self.reason is not None:
            raise ValueError("an observed link carries no reason")
        if self.basis == "inferred":
            if self.reason not in _INFERRED_REASONS:
                raise ValueError("an inferred link carries an inferred reason")
            if self.confidence > INFERRED_CEILING:
                raise ValueError("an inferred link is capped at 0.7")
        if self.valid_to <= self.valid_from:
            raise ValueError("valid_to must be after valid_from")
        self._check_endpoints(self.source, self.target)
        if self.source.key == self.target.key:
            raise ValueError("a link joins two different entities")

    def _check_unknown(self) -> None:
        if (
            self.target is not None
            or self.confidence is not None
            or self.valid_from is not None
            or self.valid_to is not None
            or self.reason not in _UNKNOWN_REASONS
        ):
            raise ValueError("an unknown link has no target, confidence or window, and a reason")
        if self.ambiguous != (len(self.candidates) >= 2) or (
            not self.ambiguous and self.candidates
        ):
            raise ValueError("ambiguous means two or more candidates, and only then")
        keys = [candidate.entity.key for candidate in self.candidates]
        if len(set(keys)) != len(keys):
            raise ValueError("candidates are distinct")
        if self.relation != "identity" and self.candidates:
            self._check_candidate_types()

    def _check_candidate_types(self) -> None:
        ends = _RELATION_TYPES.get(self.relation)
        if ends is None or self.source.type not in ends:
            raise ValueError("the source does not belong to the relation")
        other = ends[1] if self.source.type == ends[0] else ends[0]
        if any(candidate.entity.type != other for candidate in self.candidates):
            raise ValueError("candidates are the other end of the relation")

    def _check_endpoints(self, source: EntityRef, target: EntityRef) -> None:
        if self.relation == "identity":
            if target.type != "person" or source.type not in _IDENTITY_SUBJECTS:
                raise ValueError("an identity link runs from an address or device to a person")
            return
        a, b = _RELATION_TYPES[self.relation]
        if (source.type, target.type) not in {(a, b), (b, a)}:
            raise ValueError("the endpoints do not match the relation")


class IdentitySession(ApiModel):
    kind: SessionKind
    basis: KnownBasis
    confidence: Confidence
    valid_from: AwareDatetime
    valid_to: AwareDatetime
    links: list[IdentityLink] = Field(min_length=2, max_length=MAX_SESSION_LINKS)

    @model_validator(mode="after")
    def _chain_is_consistent(self) -> IdentitySession:
        first, second = self.links[0], self.links[1]
        if first.relation != "person-account":
            raise ValueError("a session starts at a person's account")
        if second.relation not in ("account-mac", "account-ip") or second.source != first.target:
            raise ValueError("the second link authenticates that account")
        if any(link.basis == "unknown" for link in self.links):
            raise ValueError("a session is made of observed or inferred links only")
        weakest = max((link.basis for link in self.links), key=_BASIS_RANK.__getitem__)
        if self.basis != weakest:
            raise ValueError("a session is as strong as its weakest link")
        lowest = min(link.confidence for link in self.links if link.confidence is not None)
        if abs(self.confidence - lowest) > 1e-9:
            raise ValueError("a session's confidence is its lowest link confidence")
        if self.valid_to <= self.valid_from:
            raise ValueError("valid_to must be after valid_from")
        return self


class Attribution(ApiModel):
    basis: Basis
    reason: Reason | None
    ambiguous: bool
    links: list[IdentityLink] = Field(max_length=MAX_CANDIDATES)
    candidates: list[Candidate] = Field(max_length=MAX_CANDIDATES)

    @model_validator(mode="after")
    def _invariants(self) -> Attribution:
        if any(link.relation != "identity" for link in self.links):
            raise ValueError("an attribution holds identity links")
        if self.basis == "unknown":
            self._check_unknown()
        else:
            self._check_known()
        return self

    def _check_known(self) -> None:
        if not self.links or self.ambiguous or self.candidates:
            raise ValueError(f"a {self.basis} attribution names its persons as links")
        if self.basis == "observed" and self.reason is not None:
            raise ValueError("an observed attribution carries no reason")
        if self.basis == "inferred" and self.reason not in _INFERRED_REASONS:
            raise ValueError("an inferred attribution carries an inferred reason")
        if any(link.basis == "unknown" for link in self.links):
            raise ValueError("an attribution link is observed or inferred")
        ranks = [_BASIS_RANK[link.basis] for link in self.links]
        if ranks != sorted(ranks) or self.basis != self.links[0].basis:
            raise ValueError("links run strongest first and the basis is the strongest")
        targets = [link.target.key for link in self.links if link.target is not None]
        if len(set(targets)) != len(targets):
            raise ValueError("each person appears once")

    def _check_unknown(self) -> None:
        if self.links or self.reason not in _UNKNOWN_REASONS:
            raise ValueError("an unknown attribution has no links and a reason")
        if self.ambiguous != (len(self.candidates) >= 2) or (
            not self.ambiguous and self.candidates
        ):
            raise ValueError("ambiguous means two or more candidates, and only then")
        keys = [candidate.entity.key for candidate in self.candidates]
        if len(set(keys)) != len(keys):
            raise ValueError("candidates are distinct")


class SourceStatus(ApiModel):
    source: str = Field(pattern=_SOURCE_PATTERN)
    state: SourceState
    record_count: int = Field(ge=0, le=5000)
    truncated: bool
    freshness: Freshness

    @model_validator(mode="after")
    def _non_ok_read_nothing(self) -> SourceStatus:
        if self.state != "ok" and (self.record_count != 0 or self.truncated):
            raise ValueError("a source that was not read carries no records")
        return self


class TimeWindow(ApiModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, str_strip_whitespace=True)

    from_: AwareDatetime = Field(..., alias="from")
    to: AwareDatetime

    @model_validator(mode="after")
    def _ordered_and_bounded(self) -> TimeWindow:
        if self.to <= self.from_:
            raise ValueError("the window ends after it starts")
        if self.to - self.from_ > MAX_WINDOW:
            raise ValueError("the window is at most 31 days")
        return self


def _state_matches_sources(state: SourceState, sources: list[SourceStatus]) -> None:
    """The state is derived: any source read is ok; else any failure is unknown; else not-connected."""
    names = [item.source for item in sources]
    if len(set(names)) != len(names):
        raise ValueError("each source appears once")
    states = {item.state for item in sources}
    expected: SourceState = (
        "ok" if "ok" in states else ("unknown" if "unknown" in states else "not-connected")
    )
    if state != expected:
        raise ValueError(f"the state must be {expected} for these sources")


class ResolveSubject(ApiModel):
    kind: Literal["ip", "mac", "hostname"]
    value: str = Field(min_length=1, max_length=128)


ResolveNote = Literal["register-is-current-state"]


class ResolveResponse(ApiModel):
    state: SourceState
    subject: ResolveSubject
    as_of: AwareDatetime
    window: TimeWindow
    sources: list[SourceStatus] = Field(max_length=8)
    attribution: Attribution
    endpoint: list[IdentityLink] = Field(max_length=MAX_ENDPOINT_LINKS)
    # Qualifies the answer: a past-time answer that rests on a register records current state only.
    notes: list[ResolveNote] = Field(max_length=4)

    @model_validator(mode="after")
    def _honest_state(self) -> ResolveResponse:
        _state_matches_sources(self.state, self.sources)
        if len(set(self.notes)) != len(self.notes):
            raise ValueError("each note appears once")
        if self.state != "ok" and (
            self.endpoint or self.attribution.basis != "unknown" or self.attribution.ambiguous
        ):
            raise ValueError("a non-ok state carries no links and attributes no one")
        return self


class UserSummary(ApiModel):
    id: str = Field(pattern=_PERSON_ID_PATTERN)
    display_name: Label | None
    account_count: int = Field(ge=0, le=1000)
    assigned_device_count: int = Field(ge=0, le=1000)
    session_count: int = Field(ge=0, le=1000)
    presence: Basis
    last_evidence_at: AwareDatetime | None

    @model_validator(mode="after")
    def _no_session_means_unknown(self) -> UserSummary:
        if self.presence == "unknown" and self.session_count != 0:
            raise ValueError("unknown presence has no sessions")
        return self


class UserTrafficItem(ApiModel):
    address: str = Field(min_length=2, max_length=45, pattern=_ADDRESS_PATTERN)
    bytes: int | None = Field(..., ge=0)
    covers_window: bool

    @model_validator(mode="after")
    def _canonical(self) -> UserTrafficItem:
        _canonical_address(self.address)
        if not self.covers_window and self.bytes is not None:
            raise ValueError("an address whose link does not cover the window reports no bytes")
        return self


def _canonical_address(value: str) -> None:
    try:
        if str(ipaddress.ip_address(value)) != value:
            raise ValueError("an address in canonical form")
    except ValueError as error:
        raise ValueError("an address in canonical form") from error


class UserTraffic(ApiModel):
    state: SourceState
    basis: Literal["inferred", "unknown"]
    window: TimeWindow | None
    top_n: int = Field(ge=0, le=100)
    items: list[UserTrafficItem] = Field(max_length=16)

    @model_validator(mode="after")
    def _honest(self) -> UserTraffic:
        if self.state != "ok":
            if self.basis != "unknown" or self.window is not None or self.top_n != 0 or self.items:
                raise ValueError("a non-ok traffic block carries no values")
        elif self.basis != "inferred" or self.window is None:
            raise ValueError("traffic is attributed by address, so it is inferred, with a window")
        addresses = [item.address for item in self.items]
        if len(set(addresses)) != len(addresses):
            raise ValueError("each address appears once")
        return self


class UserSecurityItem(ApiModel):
    event_id: str = Field(min_length=1, max_length=128)
    observed_at: AwareDatetime
    severity: Severity
    signature: str = Field(min_length=1, max_length=512)
    address: str = Field(min_length=2, max_length=45, pattern=_ADDRESS_PATTERN)
    link: IdentityLink

    @model_validator(mode="after")
    def _attributed(self) -> UserSecurityItem:
        _canonical_address(self.address)
        if self.link.relation != "identity" or self.link.basis == "unknown":
            raise ValueError("the event is attributed by an observed or inferred identity link")
        if self.link.source.type != "ip" or self.link.source.id != self.address:
            raise ValueError("the link is about the event's address")
        return self


class UserSecurity(ApiModel):
    state: SourceState
    window: TimeWindow | None
    items: list[UserSecurityItem] = Field(max_length=20)
    truncated: bool

    @model_validator(mode="after")
    def _honest(self) -> UserSecurity:
        if self.state != "ok":
            if self.window is not None or self.items or self.truncated:
                raise ValueError("a non-ok security block carries no values")
            return self
        if self.window is None:
            raise ValueError("an ok security block names its window")
        ids = [item.event_id for item in self.items]
        if len(set(ids)) != len(ids):
            raise ValueError("each event appears once")
        if any(not (self.window.from_ <= item.observed_at < self.window.to) for item in self.items):
            raise ValueError("events fall inside the window")
        return self


class UserProfile(ApiModel):
    id: str = Field(pattern=_PERSON_ID_PATTERN)
    display_name: Label | None
    accounts: list[IdentityLink] = Field(max_length=50)
    assigned_devices: list[IdentityLink] = Field(max_length=50)
    sessions: list[IdentitySession] = Field(max_length=50)

    @model_validator(mode="after")
    def _about_this_person(self) -> UserProfile:
        for link in self.accounts:
            if link.relation != "person-account":
                raise ValueError("an account link is a person-account link")
            # A disputed account is listed from the account's side: this person is a candidate.
            about_me = (
                link.source.id == self.id
                if link.target is not None
                else any(candidate.entity.id == self.id for candidate in link.candidates)
            )
            if not about_me:
                raise ValueError("an account link starts at this person")
        for link in self.assigned_devices:
            if (
                link.relation != "person-device"
                or link.source.id != self.id
                or link.basis != "inferred"
            ):
                raise ValueError("an assignment is a declaration (inferred) about this person")
        if any(session.links[0].source.id != self.id for session in self.sessions):
            raise ValueError("a session starts at this person")
        return self


class UserDetailResponse(ApiModel):
    state: SourceState
    as_of: AwareDatetime
    window: TimeWindow
    sources: list[SourceStatus] = Field(max_length=8)
    user: UserProfile | None
    traffic: UserTraffic | None
    security: UserSecurity | None

    @model_validator(mode="after")
    def _honest(self) -> UserDetailResponse:
        _state_matches_sources(self.state, self.sources)
        blocks = (self.user, self.traffic, self.security)
        if self.state != "ok" and any(block is not None for block in blocks):
            raise ValueError("a non-ok state carries no profile and no activity")
        if self.state == "ok" and any(block is None for block in blocks):
            raise ValueError("an ok state carries the profile and both activity blocks")
        return self


class UsersAggregateResponse(ApiModel):
    state: SourceState
    as_of: AwareDatetime
    window: TimeWindow
    sources: list[SourceStatus] = Field(max_length=8)
    people_total: int | None = Field(..., ge=0)
    with_observed_session: int | None = Field(..., ge=0)
    with_inferred_session: int | None = Field(..., ge=0)
    without_session_evidence: int | None = Field(..., ge=0)
    vpn_sessions: int | None = Field(..., ge=0)

    @model_validator(mode="after")
    def _honest(self) -> UsersAggregateResponse:
        _state_matches_sources(self.state, self.sources)
        counts = (
            self.people_total,
            self.with_observed_session,
            self.with_inferred_session,
            self.without_session_evidence,
            self.vpn_sessions,
        )
        if self.state != "ok":
            if any(count is not None for count in counts):
                raise ValueError("a non-ok state carries no counts")
            return self
        if any(count is None for count in counts):
            raise ValueError("an ok state carries every count")
        if (
            self.with_observed_session is not None
            and self.with_inferred_session is not None
            and self.without_session_evidence is not None
            and self.people_total
            != self.with_observed_session
            + self.with_inferred_session
            + self.without_session_evidence
        ):
            raise ValueError("the counts add up to the total")
        return self


class UserListResponse(ApiModel):
    state: SourceState
    as_of: AwareDatetime
    window: TimeWindow
    sources: list[SourceStatus] = Field(max_length=8)
    items: list[UserSummary] = Field(max_length=100)
    page: int = Field(ge=1, le=1000)
    page_size: int = Field(ge=1, le=100)
    total: int = Field(ge=0)

    @model_validator(mode="after")
    def _honest(self) -> UserListResponse:
        _state_matches_sources(self.state, self.sources)
        if self.state != "ok" and (self.items or self.total != 0):
            raise ValueError("a non-ok state carries no rows")
        if len(self.items) > self.page_size or self.total < len(self.items):
            raise ValueError("rows fit the page and the total")
        ids = [item.id for item in self.items]
        if len(set(ids)) != len(ids):
            raise ValueError("each person appears once")
        return self
