"""The pure identity-correlation engine (Step 6a): time-bounded, deterministic, never over-claiming.

Every scenario here is one of the PRD 36 edge cases (DHCP churn, shared devices, multiple devices
per person, NAT, VPN, guest/BYOD, expired sessions, conflicting evidence) or the rule that an IP
address alone is never identity.
"""

from __future__ import annotations

import itertools
import random
from datetime import timedelta

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
    SW1,
    T0,
    VLAN10,
    VLAN99,
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

from netsight_api.identity.engine import MAX_RECORDS, CorrelationIndex
from netsight_api.identity.model import (
    Assertion,
    Basis,
    CorrelationPolicy,
    EntityRef,
    EntityType,
    EvidenceKind,
    EvidenceRecord,
    Reason,
    Relation,
    hostname_ref,
    ip_ref,
)


def index(*records: EvidenceRecord, policy: CorrelationPolicy | None = None) -> CorrelationIndex:
    return CorrelationIndex(list(records), policy or CorrelationPolicy())


def person_ids(links: tuple) -> set[str]:  # type: ignore[type-arg]
    return {link.target.id for link in links if link.target is not None}


def candidate_ids(attribution) -> set[str]:  # type: ignore[no-untyped-def]
    return {candidate.entity.id for candidate in attribution.candidates}


# --- an IP address alone is never identity ---------------------------------------------------


def test_an_ip_with_only_a_lease_is_an_unattributed_endpoint() -> None:
    result = index(dhcp(IP1, MAC_A, at(0), at(2))).resolve(IP1, at(1))
    assert result.attribution.basis is Basis.UNKNOWN
    assert result.attribution.reason is Reason.IP_ONLY
    assert result.attribution.links == ()
    (link,) = [link for link in result.endpoint if link.relation is Relation.IP_MAC]
    assert link.basis is Basis.OBSERVED and link.target == MAC_A


def test_an_ip_with_no_evidence_at_all_is_unknown_not_empty_success() -> None:
    result = index().resolve(IP1, at(1))
    assert result.attribution.basis is Basis.UNKNOWN
    assert result.attribution.reason is Reason.NO_EVIDENCE
    assert result.endpoint == ()


def test_a_degraded_source_turns_silence_into_source_unavailable() -> None:
    result = index().resolve(IP1, at(1), degraded=True)
    assert result.attribution.reason is Reason.SOURCE_UNAVAILABLE


def test_evidence_that_never_involves_an_account_or_person_never_names_one() -> None:
    records = [
        dhcp(IP1, MAC_A, at(0), at(2)),
        agent(PC1, IP1, at(0), at(2), mac=MAC_A),
        wifi(MAC_A, AP1, at(0), at(2), vlan=VLAN10),
        radius(ALICE_ACC, MAC_B, at(0), at(2)),  # a different endpoint entirely
    ]
    result = index(*records).resolve(IP1, at(1))
    assert result.attribution.links == ()
    assert result.attribution.basis is Basis.UNKNOWN


# --- the observed chain ------------------------------------------------------------------------


def chain_records() -> list[EvidenceRecord]:
    return [
        dhcp(IP1, MAC_A, at(0), at(4)),
        radius(ALICE_ACC, MAC_A, at(1), at(3), port=PORT1, vlan=VLAN10),
        directory(ALICE, ALICE_ACC),
    ]


def test_ip_to_person_is_observed_only_when_every_hop_is_observed() -> None:
    result = index(*chain_records()).resolve(IP1, at(2))
    assert result.attribution.basis is Basis.OBSERVED
    (link,) = result.attribution.links
    assert link.relation is Relation.IDENTITY and link.target == ALICE
    assert link.basis is Basis.OBSERVED and link.reason is None
    assert {e.source for e in link.evidence} == {"dhcp", "radius", "directory"}
    assert link.confidence == pytest.approx(0.95)  # the weakest hop, never an average


def test_a_chain_is_valid_only_where_every_hop_is_valid() -> None:
    (link,) = index(*chain_records()).resolve(IP1, at(2)).attribution.links
    assert link.valid_from == at(1) and link.valid_to == at(3)  # the RADIUS session bounds it
    assert link.as_of == at(2)


def test_before_the_session_started_nothing_is_attributed() -> None:
    result = index(*chain_records()).resolve(IP1, at(0.5))
    assert result.attribution.basis is Basis.UNKNOWN
    assert result.attribution.reason is Reason.EXPIRED  # the evidence exists, just not at this time


def test_the_end_of_a_window_is_exclusive() -> None:
    idx = index(*chain_records())
    assert idx.resolve(IP1, at(3) - timedelta(seconds=1)).attribution.basis is Basis.OBSERVED
    assert idx.resolve(IP1, at(3)).attribution.reason is Reason.EXPIRED


def test_an_expired_session_ends_the_attribution_while_the_lease_remains() -> None:
    result = index(*chain_records()).resolve(IP1, at(3.5))
    assert result.attribution.basis is Basis.UNKNOWN
    assert result.attribution.reason is Reason.EXPIRED
    assert any(
        link.relation is Relation.IP_MAC for link in result.endpoint
    )  # the lease still holds


def test_an_open_session_is_only_trusted_for_a_bounded_time_after_it_was_last_seen() -> None:
    open_session = radius(ALICE_ACC, MAC_A, at(1), None, observed_at=at(1.1))
    idx = index(dhcp(IP1, MAC_A, at(0), at(8)), open_session, directory(ALICE, ALICE_ACC))
    assert idx.resolve(IP1, at(1.2)).attribution.basis is Basis.OBSERVED
    stale = idx.resolve(IP1, at(3))  # long after the last update: nobody confirmed it is still open
    assert stale.attribution.basis is Basis.UNKNOWN and stale.attribution.reason is Reason.EXPIRED


def test_a_later_stop_record_supersedes_the_open_record_of_the_same_session() -> None:
    opened = radius(ALICE_ACC, MAC_A, at(1), None, native_id="sess-1", observed_at=at(1))
    stopped = radius(ALICE_ACC, MAC_A, at(1), at(2), native_id="sess-1", observed_at=at(2.1))
    for order in ([opened, stopped], [stopped, opened]):
        idx = index(dhcp(IP1, MAC_A, at(0), at(8)), directory(ALICE, ALICE_ACC), *order)
        assert idx.resolve(IP1, at(1.5)).attribution.basis is Basis.OBSERVED
        assert idx.resolve(IP1, at(2.05)).attribution.reason is Reason.EXPIRED


# --- DHCP churn, shared devices, multiple devices ----------------------------------------------


def test_a_reused_dhcp_address_resolves_to_whoever_held_it_at_that_time() -> None:
    idx = index(
        dhcp(IP1, MAC_A, at(0), at(1)),
        dhcp(IP1, MAC_B, at(2), at(4)),
        radius(ALICE_ACC, MAC_A, at(0), at(1)),
        radius(BOB_ACC, MAC_B, at(2), at(4)),
        directory(ALICE, ALICE_ACC),
        directory(BOB, BOB_ACC),
    )
    assert person_ids(idx.resolve(IP1, at(0.5)).attribution.links) == {ALICE.id}
    assert idx.resolve(IP1, at(1.5)).attribution.basis is Basis.UNKNOWN  # between the two leases
    assert person_ids(idx.resolve(IP1, at(3)).attribution.links) == {BOB.id}


def test_overlapping_leases_for_one_address_are_ambiguous_never_picked() -> None:
    idx = index(
        dhcp(IP1, MAC_A, at(0), at(3)),
        dhcp(IP1, MAC_B, at(2), at(4)),
        radius(ALICE_ACC, MAC_A, at(0), at(3)),
        radius(BOB_ACC, MAC_B, at(2), at(4)),
        directory(ALICE, ALICE_ACC),
        directory(BOB, BOB_ACC),
    )
    result = idx.resolve(IP1, at(2.5))
    attribution = result.attribution
    assert attribution.basis is Basis.UNKNOWN and attribution.reason is Reason.CONFLICTING
    assert attribution.ambiguous is True
    assert attribution.links == ()  # nothing is asserted; the candidates are listed instead
    assert candidate_ids(attribution) == {ALICE.id, BOB.id}
    (conflict,) = [link for link in result.endpoint if link.relation is Relation.IP_MAC]
    assert conflict.target is None and conflict.ambiguous is True
    assert {c.entity for c in conflict.candidates} == {MAC_A, MAC_B}


def test_a_shared_pc_used_in_turn_attributes_by_time() -> None:
    idx = index(
        dhcp(IP1, MAC_A, at(0), at(10)),
        radius(ALICE_ACC, MAC_A, at(1), at(3)),
        radius(BOB_ACC, MAC_A, at(5), at(7)),
        directory(ALICE, ALICE_ACC),
        directory(BOB, BOB_ACC),
    )
    assert person_ids(idx.resolve(IP1, at(2)).attribution.links) == {ALICE.id}
    assert person_ids(idx.resolve(IP1, at(6)).attribution.links) == {BOB.id}
    assert idx.resolve(IP1, at(4)).attribution.basis is Basis.UNKNOWN


def test_two_simultaneous_users_of_one_device_are_ambiguous_with_both_listed() -> None:
    idx = index(
        dhcp(IP1, MAC_A, at(0), at(10)),
        radius(ALICE_ACC, MAC_A, at(1), at(5)),
        radius(BOB_ACC, MAC_A, at(2), at(6)),
        directory(ALICE, ALICE_ACC),
        directory(BOB, BOB_ACC),
    )
    attribution = idx.resolve(IP1, at(3)).attribution
    assert attribution.basis is Basis.UNKNOWN and attribution.ambiguous is True
    assert attribution.reason is Reason.CONFLICTING
    assert candidate_ids(attribution) == {ALICE.id, BOB.id}


def test_two_assigned_owners_of_a_shared_device_are_ambiguous_and_inferred_at_best() -> None:
    idx = index(
        agent(PC1, IP1, at(0), at(4)),
        assignment(ALICE, PC1),
        assignment(BOB, PC1),
    )
    attribution = idx.resolve(IP1, at(1)).attribution
    assert attribution.basis is Basis.UNKNOWN and attribution.ambiguous is True
    assert attribution.reason is Reason.MULTIPLE_CANDIDATES
    assert candidate_ids(attribution) == {ALICE.id, BOB.id}
    assert {c.basis for c in attribution.candidates} == {Basis.INFERRED}


def test_one_person_on_two_devices_has_two_sessions() -> None:
    idx = index(
        radius(ALICE_ACC, MAC_A, at(1), at(5), port=PORT1, vlan=VLAN10),
        radius(ALICE_ACC, MAC_B, at(1), at(5)),
        wifi(MAC_B, AP1, at(1), at(5), vlan=VLAN10),
        directory(ALICE, ALICE_ACC),
    )
    sessions = idx.person_view(ALICE.id, at(2)).sessions
    assert len(sessions) == 2
    assert {s.kind for s in sessions} == {"wired", "wifi"}
    assert all(s.basis is Basis.OBSERVED for s in sessions)


# --- inference stays inference ----------------------------------------------------------------


def test_a_declared_assignment_is_inferred_never_observed() -> None:
    idx = index(agent(PC1, IP1, at(0), at(4)), assignment(ALICE, PC1))
    result = idx.resolve(IP1, at(1))
    assert result.attribution.basis is Basis.INFERRED
    assert result.attribution.reason is Reason.DECLARED_ASSIGNMENT
    (link,) = result.attribution.links
    assert link.basis is Basis.INFERRED and link.target == ALICE
    assert link.confidence is not None and link.confidence <= 0.7


def test_a_sign_in_from_an_address_is_inferred_at_best() -> None:
    idx = index(signin(ALICE_ACC, IP1, at(1)), directory(ALICE, ALICE_ACC))
    result = idx.resolve(IP1, at(1.2))
    assert result.attribution.basis is Basis.INFERRED
    assert result.attribution.reason is Reason.INDIRECT_EVIDENCE


def test_a_direct_record_below_the_observed_confidence_is_inferred() -> None:
    idx = index(
        dhcp(IP1, MAC_A, at(0), at(4)),
        radius(ALICE_ACC, MAC_A, at(0), at(4), confidence=0.5),
        directory(ALICE, ALICE_ACC),
    )
    result = idx.resolve(IP1, at(1))
    assert result.attribution.basis is Basis.INFERRED
    assert result.attribution.reason is Reason.LOW_CONFIDENCE
    assert result.attribution.links[0].confidence == pytest.approx(0.5)


def test_an_observed_attribution_is_not_overturned_by_a_weaker_owner_but_both_are_listed() -> None:
    idx = index(
        dhcp(IP1, MAC_A, at(0), at(4)),
        radius(ALICE_ACC, MAC_A, at(0), at(4)),
        directory(ALICE, ALICE_ACC),
        agent(PC1, IP1, at(0), at(4), mac=MAC_A),
        assignment(BOB, PC1),
    )
    attribution = idx.resolve(IP1, at(1)).attribution
    assert attribution.basis is Basis.OBSERVED and attribution.ambiguous is False
    by_target = {link.target.id: link.basis for link in attribution.links if link.target}
    assert by_target == {ALICE.id: Basis.OBSERVED, BOB.id: Basis.INFERRED}


def test_a_conflicting_directory_mapping_is_ambiguous() -> None:
    idx = index(
        dhcp(IP1, MAC_A, at(0), at(4)),
        radius(ALICE_ACC, MAC_A, at(0), at(4)),
        directory(ALICE, ALICE_ACC),
        directory(BOB, ALICE_ACC),  # one account claimed by two people
    )
    attribution = idx.resolve(IP1, at(1)).attribution
    assert attribution.basis is Basis.UNKNOWN and attribution.ambiguous is True
    assert candidate_ids(attribution) == {ALICE.id, BOB.id}


# --- NAT, VPN, guest ----------------------------------------------------------------------------


def test_a_public_address_is_never_identity_even_with_a_sign_in() -> None:
    public = ip_ref("203.0.113.9")
    idx = index(signin(ALICE_ACC, public, at(1)), directory(ALICE, ALICE_ACC))
    result = idx.resolve(public, at(1.1))
    assert result.attribution.basis is Basis.UNKNOWN
    assert result.attribution.reason is Reason.SHARED_ADDRESS
    assert result.attribution.links == ()


def test_a_configured_nat_egress_address_is_never_identity() -> None:
    nat = ip_ref("10.9.9.9")
    policy = CorrelationPolicy(shared_cidrs=("10.9.9.0/24",))
    idx = index(signin(ALICE_ACC, nat, at(1)), directory(ALICE, ALICE_ACC), policy=policy)
    assert idx.resolve(nat, at(1.1)).attribution.reason is Reason.SHARED_ADDRESS


def test_a_shared_address_is_not_a_bridge_between_two_endpoints() -> None:
    nat = ip_ref("10.9.9.9")
    policy = CorrelationPolicy(shared_cidrs=("10.9.9.0/24",))
    idx = index(
        signin(ALICE_ACC, nat, at(1)),
        directory(ALICE, ALICE_ACC),
        dhcp(nat, MAC_A, at(0), at(4)),  # even if some lease names the egress address
        policy=policy,
    )
    assert idx.resolve(MAC_A, at(1.1)).attribution.links == ()


def test_a_vpn_address_is_identity_only_through_a_vpn_session() -> None:
    pool = ip_ref("10.200.0.5")
    policy = CorrelationPolicy(vpn_cidrs=("10.200.0.0/24",))
    with_session = index(
        vpn(ALICE_ACC, pool, at(1), at(3)), directory(ALICE, ALICE_ACC), policy=policy
    )
    result = with_session.resolve(pool, at(2))
    assert result.attribution.basis is Basis.OBSERVED and person_ids(result.attribution.links) == {
        ALICE.id
    }
    only_signin = index(signin(BOB_ACC, pool, at(2)), directory(BOB, BOB_ACC), policy=policy)
    blocked = only_signin.resolve(pool, at(2.1))
    assert blocked.attribution.basis is Basis.UNKNOWN
    assert blocked.attribution.reason is Reason.VPN_NO_SESSION


def test_a_sign_in_that_disagrees_with_the_vpn_session_is_a_conflict() -> None:
    pool = ip_ref("10.200.0.5")
    policy = CorrelationPolicy(vpn_cidrs=("10.200.0.0/24",))
    idx = index(
        vpn(ALICE_ACC, pool, at(1), at(3)),
        signin(BOB_ACC, pool, at(2)),
        directory(ALICE, ALICE_ACC),
        directory(BOB, BOB_ACC),
        policy=policy,
    )
    attribution = idx.resolve(pool, at(2.1)).attribution
    assert attribution.basis is Basis.UNKNOWN and attribution.ambiguous is True


def test_a_guest_network_address_is_not_attributed() -> None:
    guest = ip_ref("192.168.99.20")
    policy = CorrelationPolicy(guest_cidrs=("192.168.99.0/24",))
    idx = index(
        dhcp(guest, MAC_A, at(0), at(4)),
        radius(ALICE_ACC, MAC_A, at(0), at(4)),
        directory(ALICE, ALICE_ACC),
        policy=policy,
    )
    result = idx.resolve(guest, at(1))
    assert result.attribution.basis is Basis.UNKNOWN
    assert result.attribution.reason is Reason.GUEST_NETWORK


def test_a_guest_flagged_or_guest_vlan_endpoint_is_not_attributed() -> None:
    policy = CorrelationPolicy(guest_vlans=(99,))
    flagged = index(
        dhcp(IP1, MAC_A, at(0), at(4)),
        wifi(MAC_A, AP1, at(0), at(4), guest=True),
        radius(ALICE_ACC, MAC_A, at(0), at(4)),
        directory(ALICE, ALICE_ACC),
    )
    assert flagged.resolve(IP1, at(1)).attribution.reason is Reason.GUEST_NETWORK
    on_vlan = index(
        dhcp(IP1, MAC_A, at(0), at(4)),
        wifi(MAC_A, AP1, at(0), at(4), vlan=VLAN99),
        radius(ALICE_ACC, MAC_A, at(0), at(4)),
        directory(ALICE, ALICE_ACC),
        policy=policy,
    )
    assert on_vlan.resolve(IP1, at(1)).attribution.reason is Reason.GUEST_NETWORK


# --- the network end of the chain ---------------------------------------------------------------


def test_the_endpoint_carries_attachment_port_and_vlan_with_their_own_basis() -> None:
    idx = index(
        dhcp(IP1, MAC_A, at(0), at(4)),
        radius(ALICE_ACC, MAC_A, at(1), at(3), port=PORT1, vlan=VLAN10),
        agent(PC1, IP1, at(0), at(4), mac=MAC_A),
    )
    endpoint = {link.relation: link for link in idx.resolve(IP1, at(2)).endpoint}
    assert endpoint[Relation.MAC_PORT].target == PORT1
    assert endpoint[Relation.MAC_VLAN].target == VLAN10
    assert PC1 in (endpoint[Relation.DEVICE_IP].source, endpoint[Relation.DEVICE_IP].target)
    assert all(link.evidence for link in endpoint.values())
    assert all(link.as_of == at(2) for link in endpoint.values())


def test_a_mac_seen_on_two_access_points_at_once_is_ambiguous_not_picked() -> None:
    other_ap = EntityRef(EntityType.AP, SW1.id, "AP-OTHER")
    idx = index(wifi(MAC_A, AP1, at(0), at(3)), wifi(MAC_A, other_ap, at(1), at(4)))
    (link,) = [l for l in idx.resolve(MAC_A, at(2)).endpoint if l.relation is Relation.MAC_AP]
    assert link.target is None and link.ambiguous and len(link.candidates) == 2


# --- hostnames ---------------------------------------------------------------------------------


def test_a_hostname_is_only_a_name_match_so_never_better_than_inferred() -> None:
    idx = index(
        agent(PC1, IP1, at(0), at(4), mac=MAC_A),
        dhcp(IP1, MAC_A, at(0), at(4)),
        radius(ALICE_ACC, MAC_A, at(0), at(4)),
        directory(ALICE, ALICE_ACC),
    )
    result = idx.resolve(hostname_ref("pc-001"), at(1))
    assert result.attribution.basis is Basis.INFERRED
    assert result.attribution.reason is Reason.NAME_MATCH
    assert person_ids(result.attribution.links) == {ALICE.id}


def test_a_hostname_shared_by_two_devices_is_ambiguous() -> None:
    twin = EntityRef(EntityType.DEVICE, PC2.id, "pc-001")
    idx = index(
        agent(PC1, IP1, at(0), at(4)),
        agent(twin, IP2, at(0), at(4)),
        assignment(ALICE, PC1),
        assignment(BOB, twin),
    )
    attribution = idx.resolve(hostname_ref("PC-001"), at(1)).attribution
    assert attribution.basis is Basis.UNKNOWN and attribution.ambiguous is True


def test_an_unknown_hostname_is_unknown() -> None:
    result = index(agent(PC1, IP1, at(0), at(4))).resolve(hostname_ref("nope"), at(1))
    assert result.attribution.reason is Reason.NO_EVIDENCE


# --- the person view ---------------------------------------------------------------------------


def test_a_person_view_lists_sessions_assignments_and_accounts() -> None:
    idx = index(
        directory(ALICE, ALICE_ACC),
        radius(ALICE_ACC, MAC_A, at(1), at(3), port=PORT1, vlan=VLAN10),
        dhcp(IP1, MAC_A, at(0), at(4)),
        vpn(ALICE_ACC, ip_ref("10.200.0.5"), at(1), at(3)),
        assignment(ALICE, PC1),
        static_ip(PC1, IP2),
    )
    view = idx.person_view(ALICE.id, at(2))
    assert view is not None and view.person == ALICE
    assert {s.kind for s in view.sessions} == {"wired", "vpn"}
    wired = next(s for s in view.sessions if s.kind == "wired")
    assert {l.relation for l in wired.links} >= {
        Relation.PERSON_ACCOUNT,
        Relation.ACCOUNT_MAC,
        Relation.IP_MAC,
        Relation.MAC_PORT,
    }
    assert wired.basis is Basis.OBSERVED and wired.confidence == pytest.approx(0.95)
    (assigned,) = view.assigned_devices
    assert assigned.relation is Relation.PERSON_DEVICE and assigned.basis is Basis.INFERRED
    assert [l.target for l in view.accounts] == [ALICE_ACC]


def test_a_session_that_has_ended_is_not_current() -> None:
    idx = index(directory(ALICE, ALICE_ACC), radius(ALICE_ACC, MAC_A, at(1), at(3)))
    assert idx.person_view(ALICE.id, at(2)) is not None
    view = idx.person_view(ALICE.id, at(4))
    assert view is not None and view.sessions == ()


def test_a_session_through_a_shared_address_is_never_listed_as_an_endpoint() -> None:
    public = ip_ref("203.0.113.9")
    idx = index(directory(ALICE, ALICE_ACC), signin(ALICE_ACC, public, at(1)))
    view = idx.person_view(ALICE.id, at(1.1))
    assert view is not None and view.sessions == ()


def test_an_unknown_person_has_no_view() -> None:
    assert index(directory(ALICE, ALICE_ACC)).person_view(BOB.id, at(1)) is None


def test_people_are_listed_deterministically_with_counts() -> None:
    idx = index(
        directory(ALICE, ALICE_ACC),
        directory(BOB, BOB_ACC),
        radius(ALICE_ACC, MAC_A, at(1), at(3)),
        vpn(ALICE_ACC, ip_ref("10.200.0.5"), at(1), at(3)),
        assignment(BOB, PC1),
    )
    people = idx.people(at(2))
    assert [p.person for p in people] == sorted([ALICE, BOB], key=lambda p: p.id)
    by_id = {p.person.id: p for p in people}
    assert by_id[ALICE.id].session_count == 2 and by_id[ALICE.id].vpn_session_count == 1
    assert by_id[ALICE.id].presence is Basis.OBSERVED
    assert by_id[BOB.id].session_count == 0 and by_id[BOB.id].presence is Basis.UNKNOWN
    assert by_id[BOB.id].assigned_device_count == 1 and by_id[ALICE.id].account_count == 1


# --- determinism and bounds ----------------------------------------------------------------------


def test_the_result_does_not_depend_on_the_order_of_the_evidence() -> None:
    records = [
        dhcp(IP1, MAC_A, at(0), at(3)),
        dhcp(IP1, MAC_B, at(2), at(4)),
        radius(ALICE_ACC, MAC_A, at(0), at(3)),
        radius(BOB_ACC, MAC_B, at(2), at(4)),
        directory(ALICE, ALICE_ACC),
        directory(BOB, BOB_ACC),
        agent(PC1, IP1, at(0), at(4), mac=MAC_A),
        assignment(BOB, PC1),
    ]
    expected = index(*records).resolve(IP1, at(2.5))
    rng = random.Random(7)
    for _ in range(25):
        shuffled = records[:]
        rng.shuffle(shuffled)
        assert index(*shuffled).resolve(IP1, at(2.5)) == expected


def test_every_permutation_of_conflicting_evidence_is_equally_unknown() -> None:
    a = dhcp(IP1, MAC_A, at(0), at(3))
    b = dhcp(IP1, MAC_B, at(1), at(4))
    for order in itertools.permutations([a, b]):
        attribution = index(*order).resolve(IP1, at(2)).attribution
        assert attribution.basis is Basis.UNKNOWN


def test_too_much_evidence_is_refused_not_truncated() -> None:
    records = [
        dhcp(IP1, MAC_A, at(0), at(1), native_id=f"lease-{n}") for n in range(MAX_RECORDS + 1)
    ]
    with pytest.raises(ValueError, match="too many"):
        CorrelationIndex(records, CorrelationPolicy())


def test_the_basis_and_confidence_invariants_hold_for_every_link_produced() -> None:
    idx = index(
        *chain_records(),
        agent(PC1, IP1, at(0), at(4), mac=MAC_A),
        assignment(BOB, PC1),
        signin(BOB_ACC, IP1, at(2)),
    )
    result = idx.resolve(IP1, at(2))
    for link in (*result.endpoint, *result.attribution.links):
        if link.basis is Basis.OBSERVED:
            assert link.target is not None and link.confidence is not None and link.evidence
            assert link.reason is None and not link.ambiguous
        elif link.basis is Basis.INFERRED:
            assert link.target is not None and link.reason is not None and link.evidence
            assert link.confidence is not None and link.confidence <= 0.7
        else:
            assert link.target is None and link.confidence is None and link.reason is not None


# --- records validate themselves -----------------------------------------------------------------


def _bad(**changes: object) -> EvidenceRecord:
    base: dict[str, object] = {
        "source": "dhcp",
        "native_id": "x",
        "kind": EvidenceKind.DHCP_LEASE,
        "observed_at": at(0),
        "valid_from": at(0),
        "valid_to": at(1),
        "confidence": 0.9,
        "assertions": (Assertion(IP1, Relation.IP_MAC, MAC_A),),
    }
    base.update(changes)
    return EvidenceRecord(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "changes",
    [
        {"confidence": 1.1},
        {"confidence": -0.1},
        {"confidence": float("nan")},
        {"valid_to": at(0)},
        {"valid_to": at(-1)},
        {"observed_at": T0.replace(tzinfo=None)},
        {"valid_from": T0.replace(tzinfo=None)},
        {"assertions": ()},
        {"source": ""},
        {"native_id": " "},
        {"source": "x" * 33},
    ],
)
def test_a_malformed_evidence_record_is_refused(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        _bad(**changes)


def test_an_assertion_must_match_the_types_of_its_relation() -> None:
    with pytest.raises(ValueError, match="do not match"):
        Assertion(MAC_A, Relation.IP_MAC, IP1)  # endpoints swapped
    with pytest.raises(ValueError, match="derived"):
        Assertion(IP1, Relation.IDENTITY, ALICE)


def test_a_kind_may_only_assert_its_own_relations() -> None:
    with pytest.raises(ValueError, match="cannot assert"):
        _bad(assertions=(Assertion(ALICE, Relation.PERSON_DEVICE, PC1),))  # a lease is not an owner


@pytest.mark.parametrize(
    ("kind", "bad_id"),
    [
        (EntityType.IP, "not-an-ip"),
        (EntityType.MAC, "aa-bb"),
        (EntityType.PERSON, "alice@example.com"),
        (EntityType.PERSON, "person-alice@example.com"),
        (EntityType.ACCOUNT, "alice"),
        (EntityType.DEVICE, "device-123"),
        (EntityType.VLAN, "vlan-5000"),
        (EntityType.VLAN, "vlan-0"),
        (EntityType.HOSTNAME, "Has Space"),
        (EntityType.PORT, ""),
    ],
)
def test_an_entity_reference_must_carry_a_canonical_id_for_its_type(
    kind: EntityType, bad_id: str
) -> None:
    with pytest.raises(ValueError):
        EntityRef(kind, bad_id)


def test_a_label_is_bounded_display_text_and_not_part_of_identity() -> None:
    with pytest.raises(ValueError):
        EntityRef(EntityType.IP, "10.0.0.1", "x" * 129)
    assert EntityRef(EntityType.IP, "10.0.0.1", "a") == EntityRef(EntityType.IP, "10.0.0.1", "b")


def test_the_ip_key_is_normalised() -> None:
    assert ip_ref("10.0.0.010".replace(".010", ".10")) == IP1
    assert ip_ref("2001:DB8:0:0:0:0:0:1").id == "2001:db8::1"
    with pytest.raises(ValueError):
        ip_ref("999.1.1.1")


# --- a contested address is contested from both sides ----------------------------------------------------


def contested_leases() -> list[EvidenceRecord]:
    return [
        dhcp(IP1, MAC_A, at(0), at(3)),
        dhcp(IP1, MAC_B, at(2), at(4)),
        radius(ALICE_ACC, MAC_A, at(0), at(3)),
        directory(ALICE, ALICE_ACC),
    ]


def test_from_the_mac_side_a_contested_address_is_inferred_never_observed() -> None:
    result = index(*contested_leases()).resolve(MAC_A, at(2.5))
    (link,) = [x for x in result.endpoint if x.relation is Relation.IP_MAC and x.target == IP1]
    assert link.basis is Basis.INFERRED and link.reason is Reason.CONFLICTING
    assert link.confidence is not None and link.confidence <= 0.7
    # ...and the dispute itself is listed from the address's side with both candidates.
    (dispute,) = [x for x in result.endpoint if x.ambiguous]
    assert {c.entity for c in dispute.candidates} == {MAC_A, MAC_B}


def test_a_person_reached_through_a_contested_address_is_never_observed() -> None:
    idx = index(
        dhcp(IP1, MAC_A, at(0), at(3)),
        dhcp(IP1, MAC_B, at(2), at(4)),
        signin(ALICE_ACC, IP1, at(2.2)),
        directory(ALICE, ALICE_ACC),
    )
    attribution = idx.resolve(MAC_A, at(2.5)).attribution
    assert attribution.basis is not Basis.OBSERVED


def test_a_session_keeps_a_contested_address_as_inferred_and_weakens_itself() -> None:
    idx = index(*contested_leases())
    (session,) = idx.person_view(ALICE.id, at(2.5)).sessions  # type: ignore[union-attr]
    ip_link = next(x for x in session.links if x.relation is Relation.IP_MAC)
    assert ip_link.basis is Basis.INFERRED and session.basis is Basis.INFERRED
    assert session.confidence <= 0.7


def test_a_disputed_account_is_listed_from_the_accounts_side_and_has_no_session() -> None:
    idx = index(
        directory(ALICE, ALICE_ACC),
        directory(BOB, ALICE_ACC),
        radius(ALICE_ACC, MAC_A, at(1), at(3)),
    )
    view = idx.person_view(ALICE.id, at(2))
    assert view is not None and view.sessions == ()
    (account,) = view.accounts
    assert account.ambiguous and {c.entity for c in account.candidates} == {ALICE, BOB}


def test_two_accounts_on_one_mac_leave_neither_with_a_confirmed_session() -> None:
    idx = index(
        directory(ALICE, ALICE_ACC),
        directory(BOB, BOB_ACC),
        radius(ALICE_ACC, MAC_A, at(1), at(5)),
        radius(BOB_ACC, MAC_A, at(2), at(6)),
    )
    for person in (ALICE, BOB):
        view = idx.person_view(person.id, at(3))
        assert view is not None and view.sessions == ()
