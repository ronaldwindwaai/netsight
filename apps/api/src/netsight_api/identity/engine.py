"""Pure, deterministic identity-correlation engine (PRD 10, 36).

``CorrelationIndex`` takes evidence records and a policy and answers three questions *at an
instant*: who is behind this IP, MAC or hostname (``resolve``), what is this person on the network
right now (``person_view``), and who is known (``people``). It reads no clock, performs no I/O and
depends on the order of its input in no way: records are de-duplicated and sorted first, every
choice breaks ties by identifier.

How it stays honest:

* **Time-bounded.** A record speaks only within ``[valid_from, effective_end)``; a session with no
  recorded end is trusted for a bounded time after it was last seen. Outside the window the link
  does not exist, and the answer says ``expired`` when the chain would have held at some other
  time, so the operator can tell "never seen" from "no longer true".
* **Conflicts are never resolved by picking.** If an exclusive relation (one MAC per IP, one
  account per MAC, one person per account ...) has two candidates at the instant, the hop is
  ``unknown`` and ``ambiguous`` with every candidate listed; persons reached only through a
  conflicted hop are candidates, not an identification.
* **A chain is as strong as its weakest hop.** Basis is the minimum over the hops, confidence the
  minimum of their confidences; inferred links are capped. Directly observed relations need a
  direct evidence kind at or above ``OBSERVED_MIN_CONFIDENCE``.
* **An IP address is never identity.** The walk from an address reaches a person only through an
  account or an assignment. Shared addresses (public, NAT egress, CGNAT) are never walked through,
  VPN pool addresses count only through a VPN session, guest networks are never attributed, and
  ports, VLANs, switches and access points are never bridges between endpoints.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime

from netsight_api.identity.model import (
    INFERRED_CEILING,
    KIND_PROFILES,
    MAX_CANDIDATES,
    MAX_EVIDENCE_PER_LINK,
    OBSERVED_MIN_CONFIDENCE,
    RELATIONS,
    Attribution,
    Basis,
    Candidate,
    CorrelationPolicy,
    EntityRef,
    EntityType,
    EvidenceKind,
    EvidenceRecord,
    EvidenceRef,
    Link,
    PersonSummary,
    PersonView,
    Reason,
    Relation,
    Resolution,
    Session,
)

MAX_RECORDS = 5000
MAX_DEPTH = 5
MAX_PATHS = 2000
MAX_ENDPOINT_LINKS = 64
NAME_MATCH_CONFIDENCE = 0.5

_BASIS_RANK: Mapping[Basis, int] = {Basis.OBSERVED: 0, Basis.INFERRED: 1, Basis.UNKNOWN: 2}
_R = Relation
_T = EntityType

# Which relations the person search may follow from each kind of entity. Accounts and persons
# are terminal-ish (an account leads only to its person) so the walk can never wander from one
# person's account to someone else's endpoint; attachments are not here at all.
_IDENTITY_STEPS: Mapping[EntityType, tuple[Relation, ...]] = {
    _T.HOSTNAME: (_R.HOSTNAME_DEVICE, _R.HOSTNAME_IP),
    _T.IP: (_R.IP_MAC, _R.DEVICE_IP, _R.ACCOUNT_IP),
    _T.MAC: (_R.IP_MAC, _R.DEVICE_MAC, _R.ACCOUNT_MAC),
    _T.DEVICE: (_R.DEVICE_IP, _R.DEVICE_MAC, _R.ACCOUNT_DEVICE, _R.PERSON_DEVICE),
    _T.ACCOUNT: (_R.PERSON_ACCOUNT,),
}
# What belongs to one endpoint. Never expands out of a port, VLAN, switch or access point: those
# carry many endpoints and are leaves.
_NETWORK_STEPS: Mapping[EntityType, tuple[Relation, ...]] = {
    _T.HOSTNAME: (_R.HOSTNAME_IP, _R.HOSTNAME_DEVICE),
    _T.IP: (_R.IP_MAC, _R.DEVICE_IP),
    _T.MAC: (_R.IP_MAC, _R.DEVICE_MAC, _R.MAC_PORT, _R.MAC_SWITCH, _R.MAC_AP, _R.MAC_VLAN),
    _T.DEVICE: (_R.DEVICE_IP, _R.DEVICE_MAC),
    _T.PORT: (_R.PORT_VLAN,),
}


@dataclass(frozen=True)
class _Edge:
    record: EvidenceRecord
    relation: Relation
    near: EntityRef
    far: EntityRef
    near_is_a: bool


@dataclass(frozen=True)
class _Hop:
    link: Link
    conflicted: bool
    records: tuple[EvidenceRecord, ...]
    # False only for the candidates of a conflict seen from the near side: the ambiguous link that
    # lists them is what the endpoint shows. A hop disputed from the far side stays listed, weakened.
    listed: bool = True


@dataclass(frozen=True)
class _Expansion:
    hops: tuple[_Hop, ...]
    conflicts: tuple[tuple[Link, tuple[EvidenceRecord, ...]], ...]


@dataclass(frozen=True)
class _Path:
    person: EntityRef
    hops: tuple[_Hop, ...]
    conflicted: bool

    @property
    def links(self) -> tuple[Link, ...]:
        return tuple(hop.link for hop in self.hops)


def _dedupe(records: Iterable[EvidenceRecord]) -> list[EvidenceRecord]:
    """One record per ``(source, native_id)``: the one observed last; an ended one beats an open one."""
    best: dict[str, EvidenceRecord] = {}
    for record in records:
        current = best.get(record.id)
        if current is None or _recency(record) > _recency(current):
            best[record.id] = record
    return [best[key] for key in sorted(best)]


def _recency(record: EvidenceRecord) -> tuple[datetime, int, datetime, str]:
    return (
        record.observed_at,
        0 if record.valid_to is None else 1,
        record.effective_end,
        repr(record.assertions),
    )


def _evidence(records: Iterable[EvidenceRecord]) -> tuple[EvidenceRef, ...]:
    unique = {record.id: record for record in records}
    ordered = sorted(unique.values(), key=lambda r: (-r.confidence, r.id))
    return tuple(EvidenceRef.of(record) for record in ordered[:MAX_EVIDENCE_PER_LINK])


def _is_observed_record(record: EvidenceRecord) -> bool:
    return record.direct and record.confidence >= OBSERVED_MIN_CONFIDENCE


def _inferred_reason(records: Sequence[EvidenceRecord]) -> Reason:
    if any(record.direct for record in records):
        return Reason.LOW_CONFIDENCE
    best = max(records, key=lambda r: (r.confidence, r.id))
    return KIND_PROFILES[best.kind].inferred_reason or Reason.INDIRECT_EVIDENCE


def _aggregate(
    relation: Relation,
    near: EntityRef,
    far: EntityRef,
    records: Sequence[EvidenceRecord],
    at: datetime,
) -> Link:
    """One resolved link from every record that supports the same pair."""
    observed = [r for r in records if _is_observed_record(r)]
    support = observed or list(records)
    valid_from = min(r.valid_from for r in support)
    valid_to = max(r.effective_end for r in support)
    top = max(r.confidence for r in support)
    if observed:
        return Link(
            relation,
            near,
            far,
            Basis.OBSERVED,
            top,
            valid_from,
            valid_to,
            at,
            None,
            _evidence([*observed, *[r for r in records if r not in observed]]),
        )
    return Link(
        relation,
        near,
        far,
        Basis.INFERRED,
        min(top, INFERRED_CEILING),
        valid_from,
        valid_to,
        at,
        _inferred_reason(records),
        _evidence(records),
    )


def _candidate(entity: EntityRef, link: Link) -> Candidate:
    return Candidate(entity, link.basis, link.confidence, link.evidence)


def _value(relation: Relation) -> str:
    return relation.value


def _conflict(
    entity: EntityRef,
    relation: Relation,
    links: Sequence[tuple[EntityRef, Link, list[_Edge]]],
    at: datetime,
) -> tuple[Link, tuple[EvidenceRecord, ...]]:
    """The unknown, ambiguous link standing for an exclusive relation with several claimants."""
    records = tuple(e.record for _, _, edges in links for e in edges)
    ranked = sorted(links, key=lambda item: (-(item[1].confidence or 0), item[0].id))
    candidates = tuple(_candidate(far, link) for far, link, _ in ranked[:MAX_CANDIDATES])
    link = Link(
        relation,
        entity,
        None,
        Basis.UNKNOWN,
        None,
        None,
        None,
        at,
        Reason.CONFLICTING,
        _evidence(records),
        True,
        candidates,
    )
    return link, records


class CorrelationIndex:
    def __init__(self, records: Sequence[EvidenceRecord], policy: CorrelationPolicy) -> None:
        if len(records) > MAX_RECORDS:
            raise ValueError(f"too many evidence records (maximum {MAX_RECORDS})")
        self._policy = policy
        self._records = _dedupe(records)
        self._edges: dict[tuple[str, str], list[_Edge]] = defaultdict(list)
        self._entities: dict[tuple[str, str], EntityRef] = {}
        for record in self._records:
            for item in record.assertions:
                self._edges[item.a.key].append(_Edge(record, item.relation, item.a, item.b, True))
                self._edges[item.b.key].append(_Edge(record, item.relation, item.b, item.a, False))
                for entity in (item.a, item.b):
                    known = self._entities.get(entity.key)
                    if known is None or (known.label is None and entity.label is not None):
                        self._entities[entity.key] = entity
        self._named: dict[str, list[EntityRef]] = defaultdict(list)
        for entity in sorted(self._entities.values(), key=lambda e: e.id):
            if entity.type is _T.DEVICE and entity.label:
                self._named[entity.label.strip().lower()].append(entity)

    # --- one hop ---------------------------------------------------------------------------------

    def _usable(self, edge: _Edge, at: datetime, ignore_time: bool) -> bool:
        record = edge.record
        if not ignore_time and not (record.valid_from <= at < record.effective_end):
            return False
        for entity in (edge.near, edge.far):
            if entity.type is not _T.IP:
                continue
            # A shared address is never a bridge between two endpoints or an identity.
            if self._policy.is_shared(entity.id):
                return False
            # A host-agent's claim to a static/server address is not evidence of who holds it.
            if record.kind is EvidenceKind.ENDPOINT_AGENT and self._policy.is_static_address(
                entity.id
            ):
                return False
        return True

    def _expand(
        self,
        entity: EntityRef,
        at: datetime,
        steps: Mapping[EntityType, tuple[Relation, ...]],
        *,
        ignore_time: bool = False,
    ) -> _Expansion:
        hops: list[_Hop] = []
        conflicts: list[tuple[Link, tuple[EvidenceRecord, ...]]] = []
        for relation, pairs in self._pairs_by_relation(entity, at, steps, ignore_time):
            relation_hops, conflict = self._expand_relation(
                entity, relation, pairs, at, ignore_time
            )
            hops.extend(relation_hops)
            if conflict is not None:
                conflicts.append(conflict)
        hops.extend(self._name_matches(entity, at, ignore_time, steps))
        return _Expansion(tuple(hops), tuple(conflicts))

    def _pairs_by_relation(
        self,
        entity: EntityRef,
        at: datetime,
        steps: Mapping[EntityType, tuple[Relation, ...]],
        ignore_time: bool,
    ) -> list[tuple[Relation, list[tuple[EntityRef, list[_Edge]]]]]:
        """The usable edges around ``entity``, grouped by relation and then by far entity."""
        wanted = set(steps.get(entity.type, ()))
        grouped: dict[tuple[Relation, tuple[str, str]], list[_Edge]] = defaultdict(list)
        for edge in self._edges.get(entity.key, ()):
            if edge.relation in wanted and self._usable(edge, at, ignore_time):
                grouped[(edge.relation, edge.far.key)].append(edge)
        by_relation: dict[Relation, list[tuple[EntityRef, list[_Edge]]]] = defaultdict(list)
        for (relation, _far_key), edges in sorted(grouped.items()):
            by_relation[relation].append((edges[0].far, edges))
        return [(relation, by_relation[relation]) for relation in sorted(by_relation, key=_value)]

    def _expand_relation(
        self,
        entity: EntityRef,
        relation: Relation,
        pairs: list[tuple[EntityRef, list[_Edge]]],
        at: datetime,
        ignore_time: bool,
    ) -> tuple[list[_Hop], tuple[Link, tuple[EvidenceRecord, ...]] | None]:
        """The hops one relation yields and, when it is exclusive and contested, the conflict."""
        spec = RELATIONS[relation]
        near_is_a = pairs[0][1][0].near_is_a
        exclusive = spec.one_b_per_a if near_is_a else spec.one_a_per_b
        conflicted = exclusive and len(pairs) >= 2 and not ignore_time
        links = [
            (far, _aggregate(relation, entity, far, [e.record for e in edges], at), edges)
            for far, edges in pairs
        ]
        hops: list[_Hop] = []
        for far, link, edges in links:
            disputed = (
                not conflicted
                and not ignore_time
                and self._far_side_disputed(relation, near_is_a, far, at)
            )
            hops.append(
                _Hop(
                    _disputed(link) if disputed else link,
                    conflicted or disputed,
                    tuple(e.record for e in edges),
                    listed=not conflicted,
                )
            )
        return hops, (_conflict(entity, relation, links, at) if conflicted else None)

    def _far_side_disputed(
        self, relation: Relation, near_is_a: bool, far: EntityRef, at: datetime
    ) -> bool:
        """True when ``far`` is claimed by two entities at once on an exclusive side of ``relation``.

        A contested address is contested from both ends: from the MAC's side the lease is still
        the lease, but it is no longer something to present as fact.
        """
        spec = RELATIONS[relation]
        if not (spec.one_a_per_b if near_is_a else spec.one_b_per_a):
            return False
        claimants = {
            edge.far.key
            for edge in self._edges.get(far.key, ())
            if edge.relation is relation and self._usable(edge, at, False)
        }
        return len(claimants) >= 2

    def _name_matches(
        self,
        entity: EntityRef,
        at: datetime,
        ignore_time: bool,
        steps: Mapping[EntityType, tuple[Relation, ...]],
    ) -> list[_Hop]:
        if entity.type is not _T.HOSTNAME or _R.HOSTNAME_DEVICE not in steps.get(_T.HOSTNAME, ()):
            return []
        hops: list[_Hop] = []
        for device in self._named.get(entity.id, ()):
            wanted = steps.get(_T.DEVICE, ())
            # Only what this walk may follow from a device: the network walk must not cite the
            # person-device records (who the device is assigned to) as evidence for a hostname.
            records = [
                e.record
                for e in self._edges.get(device.key, ())
                if e.relation in wanted and self._usable(e, at, ignore_time)
            ]
            if not records:
                continue
            hops.append(
                _Hop(
                    Link(
                        _R.HOSTNAME_DEVICE,
                        entity,
                        device,
                        Basis.INFERRED,
                        NAME_MATCH_CONFIDENCE,
                        min(r.valid_from for r in records),
                        max(r.effective_end for r in records),
                        at,
                        Reason.NAME_MATCH,
                        _evidence(records),
                    ),
                    False,
                    tuple(records),
                )
            )
        return hops

    # --- the network end of the chain ------------------------------------------------------------

    def _component(
        self, subject: EntityRef, at: datetime
    ) -> tuple[list[Link], list[EvidenceRecord], set[tuple[str, str]]]:
        """Links around ``subject`` in walk order, the records behind them and the entities reached."""
        links: list[Link] = []
        records: list[EvidenceRecord] = []
        seen_links: set[tuple[Relation, frozenset[tuple[str, str]]]] = set()
        seen_conflicts: set[tuple[Relation, tuple[str, str]]] = set()
        reached = {subject.key}
        queue: deque[EntityRef] = deque([subject])
        while queue and len(links) < MAX_ENDPOINT_LINKS:
            current = queue.popleft()
            expansion = self._expand(current, at, _NETWORK_STEPS)
            for conflict, conflict_records in expansion.conflicts:
                marker = (conflict.relation, current.key)
                if marker not in seen_conflicts:
                    seen_conflicts.add(marker)
                    links.append(conflict)
                    records.extend(conflict_records)
            for hop in expansion.hops:
                far = hop.link.target
                assert far is not None  # resolved hops always have a target
                pair = (hop.link.relation, frozenset({current.key, far.key}))
                if not hop.listed or pair in seen_links:
                    continue
                seen_links.add(pair)
                links.append(hop.link)
                records.extend(hop.records)
                if far.key not in reached:
                    reached.add(far.key)
                    queue.append(far)
        return links[:MAX_ENDPOINT_LINKS], records, reached

    def _is_guest(
        self, subject: EntityRef, records: Sequence[EvidenceRecord], reached: set[tuple[str, str]]
    ) -> bool:
        policy = self._policy
        for key in reached:
            kind, value = key
            if kind == _T.IP.value and policy.is_guest_address(value):
                return True
            if kind == _T.VLAN.value and int(value.removeprefix("vlan-")) in policy.guest_vlans:
                return True
        return (
            subject.type is _T.IP
            and policy.is_guest_address(subject.id)
            or any(record.guest for record in records)
        )

    # --- who is behind the subject -----------------------------------------------------------------

    def _paths(self, subject: EntityRef, at: datetime, *, ignore_time: bool) -> list[_Path]:
        found: list[_Path] = []

        def walk(
            entity: EntityRef, hops: tuple[_Hop, ...], visited: frozenset[tuple[str, str]]
        ) -> None:
            if len(hops) >= MAX_DEPTH or len(found) >= MAX_PATHS:
                return
            for hop in self._expand(entity, at, _IDENTITY_STEPS, ignore_time=ignore_time).hops:
                far = hop.link.target
                assert far is not None
                if far.key in visited:
                    continue
                path = (*hops, hop)
                if far.type is _T.PERSON:
                    found.append(_Path(far, path, any(h.conflicted for h in path)))
                else:
                    walk(far, path, visited | {far.key})

        walk(subject, (), frozenset({subject.key}))
        return found

    def _vpn_blocked(self, path: _Path) -> bool:
        """A VPN pool address is identity only through a VPN session."""
        for key in {
            entity.key
            for hop in path.hops
            for entity in (hop.link.source, hop.link.target)
            if entity is not None and entity.type is _T.IP and self._policy.is_vpn(entity.id)
        }:
            backed = any(
                record.kind is EvidenceKind.VPN_SESSION
                for hop in path.hops
                if key in {hop.link.source.key, hop.link.target.key if hop.link.target else key}
                for record in hop.records
            )
            if not backed:
                return True
        return False

    @staticmethod
    def _path_basis(path: _Path) -> tuple[Basis, float, Reason | None]:
        links = path.links
        basis = max((link.basis for link in links), key=lambda b: _BASIS_RANK[b])
        confidence = min(link.confidence for link in links if link.confidence is not None)
        reason: Reason | None = None
        if basis is Basis.INFERRED:
            weakest = min(
                (link for link in links if link.basis is Basis.INFERRED),
                key=lambda link: (link.confidence or 0.0, link.reason.value if link.reason else ""),
            )
            reason = weakest.reason
        return basis, confidence, reason

    def _identity_link(
        self, subject: EntityRef, path: _Path, at: datetime, *, conflicted_single: bool = False
    ) -> Link:
        basis, confidence, reason = self._path_basis(path)
        if conflicted_single:
            basis, confidence, reason = (
                Basis.INFERRED,
                min(confidence, INFERRED_CEILING),
                Reason.CONFLICTING,
            )
        records = [r for hop in path.hops for r in hop.records]
        return Link(
            _R.IDENTITY,
            subject,
            path.person,
            basis,
            confidence,
            max(link.valid_from for link in path.links if link.valid_from is not None),
            min(link.valid_to for link in path.links if link.valid_to is not None),
            at,
            reason,
            _evidence(records),
        )

    @staticmethod
    def _best_per_person(paths: Iterable[_Path]) -> dict[str, _Path]:
        best: dict[str, _Path] = {}
        for path in paths:
            basis, confidence, _ = CorrelationIndex._path_basis(path)
            rank = (
                _BASIS_RANK[basis],
                -confidence,
                len(path.hops),
                tuple(sorted(e.id for e in (r for h in path.hops for r in h.records))),
            )
            current = best.get(path.person.id)
            if current is None:
                best[path.person.id] = path
                continue
            cb, cc, _ = CorrelationIndex._path_basis(current)
            current_rank = (
                _BASIS_RANK[cb],
                -cc,
                len(current.hops),
                tuple(sorted(e.id for e in (r for h in current.hops for r in h.records))),
            )
            if rank < current_rank:
                best[path.person.id] = path
        return best

    def resolve(self, subject: EntityRef, at: datetime, *, degraded: bool = False) -> Resolution:
        """Who is behind ``subject`` at ``at``, and what the network says about it."""
        if subject.type is _T.IP and self._policy.is_shared(subject.id):
            return Resolution(subject, at, _unknown(Reason.SHARED_ADDRESS), ())
        endpoint, records, reached = self._component(subject, at)
        if self._is_guest(subject, records, reached):
            return Resolution(subject, at, _unknown(Reason.GUEST_NETWORK), tuple(endpoint))
        paths = self._paths(subject, at, ignore_time=False)
        usable = [p for p in paths if p.conflicted or not self._vpn_blocked(p)]
        vpn_blocked = len(usable) < len(paths)
        attribution = self._attribute(subject, usable, at)
        if attribution is None:
            attribution = _unknown(
                self._reason_without_person(subject, at, bool(endpoint), vpn_blocked, degraded)
            )
        return Resolution(subject, at, attribution, tuple(endpoint))

    def _reason_without_person(
        self, subject: EntityRef, at: datetime, has_active: bool, vpn_blocked: bool, degraded: bool
    ) -> Reason:
        expansion = self._expand(subject, at, _IDENTITY_STEPS)
        if any(hop.conflicted for hop in expansion.hops) or expansion.conflicts:
            return Reason.CONFLICTING
        if vpn_blocked:
            return Reason.VPN_NO_SESSION
        if self._paths(subject, at, ignore_time=True):
            return Reason.EXPIRED
        if has_active:
            return Reason.SOURCE_UNAVAILABLE if degraded else Reason.IP_ONLY
        return Reason.SOURCE_UNAVAILABLE if degraded else Reason.NO_EVIDENCE

    def _attribute(
        self, subject: EntityRef, paths: list[_Path], at: datetime
    ) -> Attribution | None:
        if not paths:
            return None
        every = self._best_per_person(paths)
        solid = self._best_per_person(p for p in paths if not p.conflicted)
        conflicted = any(p.conflicted for p in paths)
        if len(every) >= 2 and conflicted:
            return self._ambiguous(every, Reason.CONFLICTING)
        if len(every) == 1 and not solid:
            (only,) = every.values()
            link = self._identity_link(subject, only, at, conflicted_single=True)
            return Attribution(link.basis, link.reason, False, (link,), ())
        links = sorted(
            (self._identity_link(subject, p, at) for p in solid.values()),
            key=lambda link: (
                _BASIS_RANK[link.basis],
                -(link.confidence or 0.0),
                link.target.id if link.target else "",
            ),
        )
        top = links[0].basis
        leaders = [link for link in links if link.basis is top]
        if len(leaders) >= 2:
            return self._ambiguous(
                {pid: p for pid, p in solid.items() if self._path_basis(p)[0] is top},
                Reason.MULTIPLE_CANDIDATES,
            )
        return Attribution(top, leaders[0].reason, False, tuple(links), ())

    def _ambiguous(self, per_person: Mapping[str, _Path], reason: Reason) -> Attribution:
        ranked = sorted(per_person.values(), key=lambda p: (-self._path_basis(p)[1], p.person.id))
        candidates = tuple(
            Candidate(
                p.person,
                self._path_basis(p)[0],
                self._path_basis(p)[1],
                _evidence(r for h in p.hops for r in h.records),
            )
            for p in ranked[:MAX_CANDIDATES]
        )
        return Attribution(Basis.UNKNOWN, reason, True, (), candidates)

    # --- people ------------------------------------------------------------------------------------

    def _person(self, person_id: str) -> EntityRef | None:
        entity = self._entities.get((_T.PERSON.value, person_id))
        return entity

    def person_view(self, person_id: str, at: datetime) -> PersonView | None:
        person = self._person(person_id)
        if person is None:
            return None
        accounts, sessions, assigned = [], [], []
        expansion = self._expand(person, at, {_T.PERSON: (_R.PERSON_ACCOUNT, _R.PERSON_DEVICE)})
        for hop in expansion.hops:
            far = hop.link.target
            assert far is not None
            if hop.link.relation is _R.PERSON_DEVICE:
                assigned.append(hop.link)
                continue
            if hop.conflicted:
                continue  # a disputed account is listed from the account's side instead
            accounts.append(hop.link)
            sessions.extend(self._sessions(hop.link, far, at))
        accounts.extend(self._conflicting_accounts(person, at))
        ordered = sorted({_session_key(s): s for s in sessions}.values(), key=_session_key)
        return PersonView(person, at, tuple(accounts), tuple(ordered), tuple(assigned))

    def _conflicting_accounts(self, person: EntityRef, at: datetime) -> list[Link]:
        links: list[Link] = []
        for edge in self._edges.get(person.key, ()):
            if edge.relation is _R.PERSON_ACCOUNT and self._usable(edge, at, False):
                expansion = self._expand(edge.far, at, {_T.ACCOUNT: (_R.PERSON_ACCOUNT,)})
                links.extend(link for link, _ in expansion.conflicts)
        unique = {(link.source.key, link.relation): link for link in links}
        return [unique[key] for key in sorted(unique)]

    def _sessions(self, person_link: Link, account: EntityRef, at: datetime) -> list[Session]:
        sessions: list[Session] = []
        steps = {_T.ACCOUNT: (_R.ACCOUNT_MAC, _R.ACCOUNT_IP)}
        for hop in self._expand(account, at, steps).hops:
            if hop.conflicted:
                continue
            far = hop.link.target
            assert far is not None
            if far.type is _T.MAC:
                links, records, reached = self._component(far, at)
                if self._is_guest(far, records, reached):
                    continue
                # A session lists what is known; a dispute shows as the weakened link it caused.
                known = [item for item in links if item.basis is not Basis.UNKNOWN]
                trail = [person_link, hop.link, *known]
                kind = _access_kind(known)
            else:
                is_vpn = any(r.kind is EvidenceKind.VPN_SESSION for r in hop.records)
                if not is_vpn:
                    continue  # a sign-in from an address is not a live session
                trail = [person_link, hop.link]
                kind = "vpn"
            sessions.append(_session(kind, trail))
        return sessions

    def has_kind(self, kind: EvidenceKind) -> bool:
        """True when any record of ``kind`` is in the snapshot (whatever window it speaks for)."""
        return any(record.kind is kind for record in self._records)

    def knows(self, entity: EntityRef) -> bool:
        """True when any evidence, in any window, mentions the entity (a cheap pre-filter)."""
        return entity.key in self._edges

    def people(self, at: datetime) -> list[PersonSummary]:
        summaries: list[PersonSummary] = []
        for person in sorted(
            (e for e in self._entities.values() if e.type is _T.PERSON), key=lambda e: e.id
        ):
            view = self.person_view(person.id, at)
            assert view is not None
            presence = Basis.UNKNOWN
            if view.sessions:
                presence = (
                    Basis.OBSERVED
                    if any(s.basis is Basis.OBSERVED for s in view.sessions)
                    else Basis.INFERRED
                )
            evidence = [
                ref
                for link in (
                    *view.accounts,
                    *view.assigned_devices,
                    *(l for s in view.sessions for l in s.links),
                )
                for ref in link.evidence
            ]
            summaries.append(
                PersonSummary(
                    person,
                    len(view.accounts),
                    len(view.assigned_devices),
                    len(view.sessions),
                    sum(1 for session in view.sessions if session.kind == "vpn"),
                    presence,
                    max((ref.observed_at for ref in evidence), default=None),
                )
            )
        return summaries


# --- helpers -------------------------------------------------------------------------------------


def _disputed(link: Link) -> Link:
    """The same link, no longer presentable as fact: another claimant exists on its exclusive end."""
    return Link(
        link.relation,
        link.source,
        link.target,
        Basis.INFERRED,
        min(link.confidence if link.confidence is not None else 0.0, INFERRED_CEILING),
        link.valid_from,
        link.valid_to,
        link.as_of,
        Reason.CONFLICTING,
        link.evidence,
    )


def _unknown(reason: Reason) -> Attribution:
    return Attribution(Basis.UNKNOWN, reason, False, (), ())


def _access_kind(links: Sequence[Link]) -> str:
    relations = {link.relation for link in links}
    if Relation.MAC_AP in relations:
        return "wifi"
    if Relation.MAC_PORT in relations or Relation.MAC_SWITCH in relations:
        return "wired"
    return "network"


def _session(kind: str, trail: Sequence[Link]) -> Session:
    basis = max((link.basis for link in trail), key=lambda b: _BASIS_RANK[b])
    return Session(
        kind=kind,
        links=tuple(trail),
        basis=basis,
        confidence=min(link.confidence for link in trail if link.confidence is not None),
        valid_from=max(link.valid_from for link in trail if link.valid_from is not None),
        valid_to=min(link.valid_to for link in trail if link.valid_to is not None),
    )


def _session_key(session: Session) -> tuple[str, str]:
    anchor = session.links[1].target
    return (session.kind, anchor.id if anchor is not None else "")
