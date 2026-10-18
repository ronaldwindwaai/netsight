"""A name is corroboration, never clearance (Step 8 review fix, security H1; code M1/M2/M3).

Anyone on the network can call themselves ``core-sw-1``. So a hostname that matches a NetBox device
never clears an endpoint on its own: clearance needs an address NetBox assigned, a MAC NetBox
records or the operator's keyed Wazuh join. A name that matches while the MAC does not is the
spoofing pattern and is recorded, at a lower severity, as ``name-matches-mac-does-not``.
"""

from __future__ import annotations

import pytest
from test_unknown_device_detect import (
    ALL_RELATIONS,
    MAC,
    NO_RESULT,
    NOW,
    POLICY,
    facts,
    fdb,
    lease,
    obs,
    only,
    run,
)

from netsight_api.identity.engine import CorrelationIndex
from netsight_api.identity.model import CorrelationPolicy, Relation
from netsight_api.unknown_devices import detect as d

KNOWN = facts(device_names=frozenset({"core-sw-1"}))


def test_a_spoofed_name_with_a_mac_netbox_does_not_know_is_a_finding_not_a_clearance() -> None:
    result = run([obs(ip="10.0.5.50", mac=MAC, hostname="core-sw-1")], netbox=KNOWN)
    finding = only(result)
    assert finding.comparison.reason == "name-matches-mac-does-not"
    assert [(c.field, c.result) for c in finding.comparison.checks] == [
        ("ip", "no-match"),
        ("mac", "no-match"),
        ("hostname", "match"),
    ]


def test_the_mac_is_always_looked_up_even_when_the_name_matches() -> None:
    correlation = CorrelationPolicy()
    index = CorrelationIndex([], correlation)
    candidates, _ = d.collect_candidates(
        [obs(ip="10.0.5.50", mac=MAC, hostname="core-sw-1")], [], index, correlation, NOW
    )
    assert d.macs_to_check(candidates, KNOWN) == [MAC]


def test_an_address_netbox_assigned_or_a_keyed_agent_still_clears_without_a_mac_lookup() -> None:
    correlation = CorrelationPolicy()
    index = CorrelationIndex([], correlation)
    known = facts(primary_ips={"10.0.5.9": "core"}, keyed_agents={"001": "pc-1"})
    candidates, _ = d.collect_candidates(
        [
            obs(native="1", ip="10.0.5.9", mac=MAC),
            obs("wazuh", "001", ip="10.0.5.60", hostname="pc-1"),
            obs(native="2", ip="10.0.5.70", mac="aa:bb:cc:00:11:99"),
        ],
        [],
        index,
        correlation,
        NOW,
    )
    assert d.macs_to_check(candidates, known) == ["aa:bb:cc:00:11:99"]


def test_a_matching_name_with_a_mac_netbox_does_record_is_cleared_by_the_mac() -> None:
    result = run(
        [obs(ip="10.0.5.50", mac=MAC, hostname="core-sw-1")],
        netbox=KNOWN,
        macs={MAC: d.MacCheck("match", "NetBox has an interface with this MAC")},
    )
    assert result.detections == () and result.unverified == 0


def test_a_matching_name_with_a_mac_netbox_could_not_be_asked_about_is_unverified() -> None:
    result = run(
        [obs(ip="10.0.5.50", mac=MAC, hostname="core-sw-1")],
        netbox=KNOWN,
        macs={MAC: d.MacCheck("not-checked", "NetBox could not be asked", incomplete=True)},
    )
    assert result.detections == () and result.unverified == 1


@pytest.mark.parametrize(
    "fields",
    [{"hostname": "core-sw-1"}, {"ip": "10.0.5.50", "hostname": "core-sw-1"}],
)
def test_a_name_alone_cannot_clear_an_endpoint_that_has_no_mac_to_verify(
    fields: dict[str, str],
) -> None:
    # nothing can verify the claim, so it is neither cleared nor accused: visible as unverified
    result = run([obs(**fields)], netbox=KNOWN)
    assert result.detections == () and result.unverified == 1


def test_the_spoofed_name_finding_is_one_step_lower_than_the_policy_says() -> None:
    plain = only(run([obs(ip="10.20.4.5", mac=MAC, hostname="other")], policy=POLICY))
    spoof = only(
        run([obs(ip="10.20.4.5", mac=MAC, hostname="core-sw-1")], netbox=KNOWN, policy=POLICY)
    )
    assert (plain.severity, plain.comparison.reason) == ("high", "no-match")
    assert (spoof.severity, spoof.severity_basis) == ("medium", "policy-rule")
    assert spoof.proposed_action is None  # medium is below the operator's quarantine threshold


def test_without_a_policy_the_spoofed_name_stays_unknown_severity() -> None:
    spoof = only(run([obs(ip="10.0.5.50", mac=MAC, hostname="core-sw-1")], netbox=KNOWN))
    assert (spoof.severity, spoof.severity_basis) == ("unknown", "no-policy")


def test_every_name_matching_detection_is_a_valid_finding() -> None:
    spoof = only(run([obs(ip="10.0.5.50", mac=MAC, hostname="core-sw-1")], netbox=KNOWN))
    assert spoof.as_finding("unknown-device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc", NOW)


# --- hostile hostnames ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        "bad\x00name",
        "tab\tname",
        "new\nline",
        "esc\x1b[31m",
        "rlo\u202ename",
        "iso\u2066x\u2069",
        "zw\u200bsp",
    ],
)
def test_control_nul_and_bidirectional_characters_never_reach_a_finding(hostile: str) -> None:
    finding = only(run([obs(ip="10.0.5.9", hostname=hostile)]))
    name = finding.endpoint.hostname
    assert name is not None
    assert all(
        ord(ch) >= 0x20
        and ch not in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200b\x7f"
        for ch in name
    )


def test_a_name_made_only_of_such_characters_is_no_name() -> None:
    finding = only(run([obs(ip="10.0.5.9", hostname="\x00\u202e\x1b")]))
    assert finding.endpoint.hostname is None


def test_a_hostname_cannot_borrow_a_netbox_name_with_hidden_characters() -> None:
    result = run([obs(ip="10.0.5.50", mac=MAC, hostname="core-\u200bsw-1")], netbox=KNOWN)
    assert only(result).endpoint.hostname == "core-sw-1"  # stripped, and still only corroboration


# --- one bad detection never aborts the scan -----------------------------------------------------------------------


def test_a_mac_only_candidate_with_no_ip_mac_link_is_unverified_not_a_crash() -> None:
    # the MAC is known only from a record that says nothing a chain can show: the slot would be empty
    result = run([], records=[fdb()], capabilities=ALL_RELATIONS)
    detections = result.detections
    # the switch table is evidence about the MAC, so the MAC slot falls back to that evidence
    assert len(detections) == 1 and detections[0].chain[1].value == MAC
    assert detections[0].chain[1].evidence


def test_a_mac_with_no_evidence_to_show_at_all_is_counted_unverified() -> None:
    correlation = CorrelationPolicy()
    index = CorrelationIndex([], correlation)
    bare = d.Candidate(ip=None, mac=MAC, hostname=None, observations=())
    result = d.detect(
        [bare],
        facts=facts(),
        mac_results={MAC: NO_RESULT},
        index=index,
        policy=POLICY,
        capabilities=frozenset(),
        now=NOW,
    )
    assert result.detections == () and result.unverified == 1


def test_one_candidate_that_cannot_be_built_is_unverified_and_the_others_survive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = d.build_chain

    def flaky(candidate, links, capabilities):  # type: ignore[no-untyped-def]
        if candidate.ip == "10.0.5.10":
            raise ValueError("boom")
        return real(candidate, links, capabilities)

    monkeypatch.setattr(d, "build_chain", flaky)
    result = run([obs(native="1", ip="10.0.5.9", mac=MAC), obs(native="2", ip="10.0.5.10")])
    assert [f.endpoint.ip for f in result.detections] == ["10.0.5.9"]
    assert result.unverified == 1


# --- inferred VLANs never decide ------------------------------------------------------------------------------------


def test_an_inferred_vlan_never_drives_the_severity() -> None:
    inferred = d._vlan_number
    from netsight_api.schemas_unknown_devices import UnknownDeviceEvidenceRef, UnknownDeviceLinkSlot

    ref = UnknownDeviceEvidenceRef(id="x:1", source="x", kind="k", observed_at=NOW, confidence=0.5)
    slot = UnknownDeviceLinkSlot(
        slot="vlan",
        basis="inferred",
        value="vlan-30",
        label=None,
        attachment_kind=None,
        confidence=0.5,
        reason="indirect-evidence",
        evidence=[ref],
    )
    assert inferred(slot) is None
    assert inferred(slot.model_copy(update={"basis": "observed", "reason": None})) == 30


# --- NetBox data that arrived incomplete -------------------------------------------------------------------------------


def test_incomplete_netbox_data_never_makes_a_finding_but_a_positive_match_still_clears() -> None:
    incomplete = d.NetboxFacts(primary_ips={"10.0.5.9": "core"}, incomplete=True)
    result = run(
        [
            obs(native="1", ip="10.0.5.9", mac=MAC),
            obs(native="2", ip="10.0.5.70", mac="aa:bb:cc:00:11:99"),
        ],
        netbox=incomplete,
    )
    assert result.detections == () and result.unverified == 1


# --- the order of MAC lookups ----------------------------------------------------------------------------------------


def test_lookups_go_to_endpoints_not_seen_before_then_the_most_recent() -> None:
    from datetime import timedelta

    correlation = CorrelationPolicy()
    index = CorrelationIndex([], correlation)
    macs = [f"aa:bb:cc:00:00:0{i}" for i in range(1, 5)]
    seen = [
        d.Observed("librenms", "device-poll", str(i), NOW - timedelta(minutes=age), mac=mac)
        for i, (mac, age) in enumerate(zip(macs, (50, 10, 30, 20), strict=True))
    ]
    candidates, _ = d.collect_candidates(seen, [], index, correlation, NOW)
    # mac 01 and 02 were seen before (an earlier finding); 03 and 04 are new to us
    order = d.macs_to_check(
        candidates, None, known_subjects=frozenset({f"mac:{macs[0]}", f"mac:{macs[1]}"})
    )
    assert order == [macs[3], macs[2], macs[1], macs[0]]


def test_lookup_ranking_is_not_an_ascending_sort_of_the_mac() -> None:
    correlation = CorrelationPolicy()
    index = CorrelationIndex([], correlation)
    from datetime import timedelta

    low = d.Observed(
        "librenms", "device-poll", "1", NOW - timedelta(hours=5), mac="00:00:00:00:00:01"
    )
    high = d.Observed(
        "librenms", "device-poll", "2", NOW - timedelta(minutes=1), mac="ff:ff:ff:00:00:01"
    )
    candidates, _ = d.collect_candidates([low, high], [], index, correlation, NOW)
    assert d.macs_to_check(candidates) == ["ff:ff:ff:00:00:01", "00:00:00:00:00:01"]


def test_relations_helper_is_imported_so_the_suite_fails_loudly_if_the_module_moves() -> None:
    assert Relation.MAC_SWITCH in ALL_RELATIONS
    assert lease("10.0.5.9")
