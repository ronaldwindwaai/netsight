"""Randomised invariants for the correlation engine (seeded, so a failure is reproducible).

Random evidence over a small pool of entities and times is the cheapest way to look for the one
combination nobody wrote a scenario for. The properties are the promises the product makes:

* the answer never depends on the order of the evidence;
* nothing is attributed to a person without an account or an assignment in the evidence, and an
  address on its own never is;
* an *observed* attribution rests only on direct evidence that is valid at the instant asked about,
  carries confidence of at least 0.8 and cites at least one direct record of that confidence;
* nothing inferred is reported above 0.7, whatever the source claimed;
* a conflict never yields a single confident pick: it is ambiguous (several candidates) or, for one
  candidate, an inferred link that says ``conflicting-evidence``;
* every link the engine produces satisfies the basis invariants (their constructor raises otherwise);
* evidence cited by an answer is evidence that was given.
"""

from __future__ import annotations

import random
from dataclasses import replace
from datetime import datetime

import pytest
from identity_support import (
    ALICE,
    ALICE_ACC,
    AP1,
    BOB,
    BOB_ACC,
    IP1,
    IP2,
    MAC_A,
    MAC_B,
    PC1,
    PC2,
    PORT1,
    VLAN10,
    agent,
    assignment,
    at,
    dhcp,
    directory,
    radius,
    signin,
    static_ip,
    vpn,
    wifi,
)

from netsight_api.identity import engine
from netsight_api.identity.engine import MAX_ENDPOINT_LINKS, CorrelationIndex
from netsight_api.identity.model import (
    INFERRED_CEILING,
    KIND_PROFILES,
    OBSERVED_MIN_CONFIDENCE,
    Basis,
    CorrelationPolicy,
    EvidenceRecord,
    Reason,
    ip_ref,
)

SUBJECTS = [IP1, IP2, MAC_A, MAC_B, ip_ref("203.0.113.9"), ip_ref("10.200.0.5")]
POLICY = CorrelationPolicy(vpn_cidrs=("10.200.0.0/24",), guest_vlans=(99,))
ACCOUNTS = [ALICE_ACC, BOB_ACC]
PEOPLE = [ALICE, BOB]


def random_record(rng: random.Random, n: int) -> EvidenceRecord:
    """One random record with a unique id (a repeated id is a supersede, covered elsewhere)."""
    record = _random_record(rng, n)
    return replace(record, native_id=f"{record.native_id}-{n}"[:128])


def _random_record(rng: random.Random, n: int) -> EvidenceRecord:
    start = at(rng.uniform(-1, 5))
    length = rng.uniform(0.2, 4)
    end = None if rng.random() < 0.2 else at((start - at(0)).total_seconds() / 3600 + length)
    ip = rng.choice([IP1, IP2, ip_ref("203.0.113.9"), ip_ref("10.200.0.5")])
    mac = rng.choice([MAC_A, MAC_B])
    account = rng.choice(ACCOUNTS)
    person = rng.choice(PEOPLE)
    device = rng.choice([PC1, PC2])
    kind = rng.choice(
        ["dhcp", "radius", "vpn", "signin", "wifi", "agent", "directory", "assign", "static"]
    )
    native = f"{kind}-{n}"
    if kind == "dhcp":
        return dhcp(
            ip, mac, start, end or at(9), native_id=native, confidence=rng.choice([0.95, 0.5])
        )
    if kind == "radius":
        return radius(
            account,
            mac,
            start,
            end,
            native_id=native,
            port=rng.choice([None, PORT1]),
            vlan=rng.choice([None, VLAN10]),
        )
    if kind == "vpn":
        return vpn(account, ip, start, end, native_id=native)
    if kind == "signin":
        return signin(account, ip, start)
    if kind == "wifi":
        return wifi(mac, AP1, start, end or at(9))
    if kind == "agent":
        return agent(device, ip, start, end, mac=rng.choice([None, mac]))
    if kind == "directory":
        return directory(person, account)
    if kind == "assign":
        return assignment(person, device)
    return static_ip(device, ip)


def scenario(seed: int) -> list[EvidenceRecord]:
    rng = random.Random(seed)
    return [random_record(rng, n) for n in range(rng.randint(2, 14))]


def active(record: EvidenceRecord, when: datetime) -> bool:
    return record.valid_from <= when < record.effective_end


def check_observed_needs_direct_evidence(links: tuple, seed: int, subject, hour) -> None:  # type: ignore[no-untyped-def,type-arg]
    """Every link that claims ``observed`` (an attribution also lists weaker persons after them)."""
    assert links[0].basis is Basis.OBSERVED
    for link in (item for item in links if item.basis is Basis.OBSERVED):
        where = (seed, subject.id, hour)
        assert link.confidence is not None and link.confidence >= OBSERVED_MIN_CONFIDENCE, where
        assert link.reason is None, where
        assert any(
            KIND_PROFILES[ref.kind].direct and ref.confidence >= OBSERVED_MIN_CONFIDENCE
            for ref in link.evidence
        ), where


def check_inferred_is_capped(links, attribution) -> None:  # type: ignore[no-untyped-def]
    for link in links:
        if link.basis is Basis.INFERRED:
            assert link.confidence is not None and link.confidence <= INFERRED_CEILING
    for candidate in attribution.candidates:
        if candidate.basis is Basis.INFERRED:
            assert candidate.confidence is not None and candidate.confidence <= INFERRED_CEILING


def check_conflict_is_never_a_confident_pick(attribution, seed, subject, hour) -> None:  # type: ignore[no-untyped-def]
    if attribution.reason not in (Reason.CONFLICTING, Reason.MULTIPLE_CANDIDATES):
        return
    where = (seed, subject.id, hour)
    assert attribution.basis is not Basis.OBSERVED, where
    if attribution.ambiguous:
        assert len(attribution.candidates) >= 2 and not attribution.links, where
    else:
        # one candidate seen only through a disputed hop: weakened and labelled, never plain
        assert len(attribution.links) <= 1, where
        assert all(
            link.basis is Basis.INFERRED and link.reason is Reason.CONFLICTING
            for link in attribution.links
        ), where


@pytest.mark.parametrize("seed", range(150))
def test_the_engine_keeps_its_promises_on_random_evidence(seed: int) -> None:
    records = scenario(seed)
    index = CorrelationIndex(records, POLICY)
    shuffled = records[:]
    random.Random(seed + 1).shuffle(shuffled)
    other = CorrelationIndex(shuffled, POLICY)
    given = {record.id: record for record in records}
    has_person_evidence = any(
        a.relation.value in ("person-account", "person-device")
        for record in records
        for a in record.assertions
    )
    for subject in SUBJECTS:
        for hour in (0.5, 2.0, 3.5, 5.0):
            when = at(hour)
            result = index.resolve(subject, when)
            assert result == other.resolve(subject, when)  # order independence
            links = (*result.endpoint, *result.attribution.links)
            for link in links:
                for ref in link.evidence:
                    assert ref.id in given
            attribution = result.attribution
            if not has_person_evidence:
                assert attribution.basis is Basis.UNKNOWN and not attribution.links
            if attribution.basis is Basis.OBSERVED:
                for link in attribution.links:
                    for ref in link.evidence:
                        record = given[ref.id]
                        assert active(record, when), (seed, subject, hour, ref.id)
                assert attribution.links and not attribution.ambiguous
                check_observed_needs_direct_evidence(attribution.links, seed, subject, hour)
            check_inferred_is_capped((*result.endpoint, *attribution.links), attribution)
            check_conflict_is_never_a_confident_pick(attribution, seed, subject, hour)
            if attribution.basis is Basis.UNKNOWN and attribution.ambiguous:
                assert len(attribution.candidates) >= 2 and not attribution.links
            if subject.id in ("203.0.113.9",):
                assert attribution.basis is Basis.UNKNOWN  # a public address is never identity


@pytest.mark.parametrize("seed", range(40))
def test_people_and_sessions_are_consistent_with_the_attribution(seed: int) -> None:
    records = scenario(seed)
    index = CorrelationIndex(records, POLICY)
    for hour in (1.0, 3.0):
        when = at(hour)
        for summary in index.people(when):
            view = index.person_view(summary.person.id, when)
            assert view is not None
            assert summary.session_count == len(view.sessions)
            for session in view.sessions:
                assert session.valid_from <= when < session.valid_to
                assert session.confidence <= 1 and session.links[0].target is not None
                assert all(link.basis is not Basis.UNKNOWN for link in session.links)
                observed_session = session.basis is Basis.OBSERVED
                assert observed_session == all(l.basis is Basis.OBSERVED for l in session.links)


# One resolve may not walk more than this many entities, and the whole directory not more than the
# second: a regression that made the walk wander (a shared port, a VLAN, an unbounded fan-out)
# raises the count long before it is slow. Counted work, not wall-clock time, so it cannot flake.
MAX_EXPANSIONS_PER_RESOLVE = 1_000
MAX_EXPANSIONS_FOR_PEOPLE = 2_000


def test_a_large_estate_is_answered_within_a_work_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    """5 000 records is the design bound: the engine must answer with bounded work, not stall."""
    expansions = {"count": 0}
    original = CorrelationIndex._expand

    def counting(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        expansions["count"] += 1
        return original(self, *args, **kwargs)

    monkeypatch.setattr(CorrelationIndex, "_expand", counting)
    rng = random.Random(7)
    records = [random_record(rng, n) for n in range(4_000)]
    index = CorrelationIndex(records, POLICY)
    for subject in SUBJECTS:
        before = expansions["count"]
        result = index.resolve(subject, at(2.0))
        assert expansions["count"] - before <= MAX_EXPANSIONS_PER_RESOLVE, subject.id
        assert len(result.endpoint) <= MAX_ENDPOINT_LINKS
    before = expansions["count"]
    assert len(index.people(at(2.0))) == 2
    assert expansions["count"] - before <= MAX_EXPANSIONS_FOR_PEOPLE
    assert engine.MAX_PATHS >= 1  # the path search keeps its own cap
