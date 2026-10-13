"""Which endpoints are unknown to NetBox, and what is known about them (Step 8c, pure).

An endpoint is known as soon as any observed field matches NetBox. It is a finding only when every
field that could be asked about did not match; if NetBox could not be asked about an observed MAC
the endpoint is unverified, never "unknown". The chain holds only links the evidence asserts.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from netsight_api.contracts import validate
from netsight_api.identity.engine import CorrelationIndex
from netsight_api.identity.model import (
    Assertion,
    CorrelationPolicy,
    EvidenceKind,
    EvidenceRecord,
    Relation,
    ap_ref,
    ip_ref,
    mac_ref,
    port_ref,
    switch_ref,
    vlan_ref,
)
from netsight_api.unknown_devices import detect as d
from netsight_api.unknown_devices.policy import POLICY_ENV, load_policy

NOW = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)
EARLIER = NOW - timedelta(minutes=2)
MAC = "aa:bb:cc:00:11:22"
NO_POLICY = load_policy({})
POLICY = load_policy(
    {
        POLICY_ENV: json.dumps(
            {
                "version": 1,
                "default_severity": "medium",
                "rules": [
                    {"cidrs": ["10.20.0.0/16"], "severity": "high"},
                    {"vlans": [30], "severity": "critical"},
                ],
                "quarantine_recommended_at": "high",
            }
        )
    }
)
NO_RESULT = d.MacCheck("no-match")
ALL_RELATIONS = frozenset(Relation)


def obs(source: str = "librenms", native: str = "9", **fields: str | None) -> d.Observed:
    kind = "device-poll" if source == "librenms" else "agent-status"
    return d.Observed(source, kind, native, EARLIER, **fields)  # type: ignore[arg-type]


def facts(**kwargs: object) -> d.NetboxFacts:
    return d.NetboxFacts(**kwargs)  # type: ignore[arg-type]


def run(
    observations: list[d.Observed],
    *,
    records: list[EvidenceRecord] | None = None,
    netbox: d.NetboxFacts | None = None,
    macs: dict[str, d.MacCheck] | None = None,
    policy=NO_POLICY,  # type: ignore[no-untyped-def]
    capabilities=frozenset(),  # type: ignore[no-untyped-def]
) -> d.DetectResult:
    correlation = CorrelationPolicy()
    index = CorrelationIndex(records or [], correlation)
    candidates, _ = d.collect_candidates(observations, records or [], index, correlation, NOW)
    results = {m: NO_RESULT for m in d.macs_to_check(candidates)}
    results.update(macs or {})
    return d.detect(
        candidates,
        facts=netbox or facts(),
        mac_results=results,
        index=index,
        policy=policy,
        capabilities=capabilities,
        now=NOW,
    )


def record(
    kind: EvidenceKind,
    native: str,
    *assertions: Assertion,
    source: str = "snmp",
    confidence: float = 0.9,
    valid_from: datetime | None = None,
    observed_at: datetime = EARLIER,
) -> EvidenceRecord:
    return EvidenceRecord(
        source=source,
        native_id=native,
        kind=kind,
        observed_at=observed_at,
        valid_from=valid_from or NOW - timedelta(minutes=10),
        valid_to=None,
        confidence=confidence,
        assertions=assertions,
    )


def fdb(
    mac: str = MAC,
    *,
    native: str = "fdb-1",
    switch: str = "sw-3",
    port: str = "Gi1/0/7",
    vlan: int = 20,
) -> EvidenceRecord:
    sw = switch_ref("netbox", switch, "access-sw-3")
    pt = port_ref(sw.id, port)
    return record(
        EvidenceKind.SWITCH_MAC_TABLE,
        native,
        Assertion(mac_ref(mac), Relation.MAC_SWITCH, sw),
        Assertion(mac_ref(mac), Relation.MAC_PORT, pt),
        Assertion(mac_ref(mac), Relation.MAC_VLAN, vlan_ref(vlan)),
    )


def lease(ip: str, mac: str = MAC, native: str = "lease-1") -> EvidenceRecord:
    return record(
        EvidenceKind.DHCP_LEASE,
        native,
        Assertion(ip_ref(ip), Relation.IP_MAC, mac_ref(mac)),
        source="dhcp",
        confidence=0.95,
    )


def only(result: d.DetectResult):  # type: ignore[no-untyped-def]
    assert len(result.detections) == 1, result
    return result.detections[0]


# --- known versus unknown ---------------------------------------------------------------------------------


def test_an_endpoint_nothing_in_netbox_matches_is_a_finding_with_the_comparison_shown() -> None:
    finding = only(run([obs(ip="10.0.5.9", mac=MAC, hostname="printer-x")]))
    assert (finding.endpoint.ip, finding.endpoint.mac, finding.endpoint.hostname) == (
        "10.0.5.9",
        MAC,
        "printer-x",
    )
    assert [(c.field, c.result) for c in finding.comparison.checks] == [
        ("ip", "no-match"),
        ("mac", "no-match"),
        ("hostname", "no-match"),
    ]
    assert finding.subject_key == f"mac:{MAC}"


def test_a_primary_or_assigned_address_makes_the_endpoint_known() -> None:
    known = facts(primary_ips={"10.0.5.9": "core"}, assigned_ips={"10.0.5.10": "pc"})
    assert run([obs(ip="10.0.5.9")], netbox=known).detections == ()
    assert run([obs(ip="10.0.5.10")], netbox=known).detections == ()
    assert len(run([obs(ip="10.0.5.11")], netbox=known).detections) == 1


def test_a_device_name_is_matched_whatever_the_case_but_never_clears_on_its_own() -> None:
    # (the full rule is in test_unknown_device_name_corroboration.py): a name nothing can verify is
    # neither a finding nor cleared, it is counted as unverified
    known = facts(device_names=frozenset({"core-sw-1"}))
    for name in ("CORE-SW-1", "core-sw-1."):
        result = run([obs(hostname=name)], netbox=known)
        assert (result.detections, result.unverified) == ((), 1), name
    assert len(run([obs(hostname="core-sw-1.example.com")], netbox=known).detections) == 1


def test_a_mac_netbox_records_makes_the_endpoint_known() -> None:
    result = run(
        [obs(ip="10.0.5.9", mac=MAC)],
        macs={MAC: d.MacCheck("match", "NetBox has an interface with this MAC")},
    )
    assert result.detections == () and result.unverified == 0


def test_a_wazuh_agent_joined_by_the_operators_key_is_known() -> None:
    known = facts(keyed_agents={"001": "pc-1"})
    assert (
        run([obs("wazuh", "001", ip="10.0.5.9", hostname="whatever")], netbox=known).detections
        == ()
    )
    assert (
        len(run([obs("wazuh", "002", ip="10.0.5.9", hostname="whatever")], netbox=known).detections)
        == 1
    )


def test_an_endpoint_seen_only_by_name_is_checked_by_name_alone() -> None:
    finding = only(run([obs(hostname="printer-x")]))
    assert [(c.field, c.result) for c in finding.comparison.checks] == [
        ("ip", "not-checked"),
        ("mac", "not-checked"),
        ("hostname", "no-match"),
    ]
    assert finding.subject_key == "host:printer-x"


def test_a_mac_netbox_could_not_be_asked_about_is_unverified_never_unknown() -> None:
    result = run(
        [obs(ip="10.0.5.9", mac=MAC)],
        macs={MAC: d.MacCheck("not-checked", "NetBox could not be asked", incomplete=True)},
    )
    assert result.detections == () and result.unverified == 1


def test_an_endpoint_whose_every_check_was_skipped_is_unverified_not_a_finding() -> None:
    # NetBox answered, but not with a verdict: nothing was compared, so nothing can be "unknown".
    result = run([obs(mac=MAC)], macs={MAC: d.MacCheck("not-checked", "no verdict")})
    assert result.detections == () and result.unverified == 1


def test_a_mac_nobody_looked_up_is_unverified_too() -> None:
    correlation = CorrelationPolicy()
    index = CorrelationIndex([], correlation)
    candidates, _ = d.collect_candidates([obs(ip="10.0.5.9", mac=MAC)], [], index, correlation, NOW)
    result = d.detect(
        candidates,
        facts=facts(),
        mac_results={},
        index=index,
        policy=NO_POLICY,
        capabilities=frozenset(),
        now=NOW,
    )
    assert result.detections == () and result.unverified == 1


def test_nothing_that_could_be_checked_proves_nothing() -> None:
    # an address and nothing else, but the address is public: no candidate at all
    assert run([obs(ip="8.8.8.8")]).detections == ()


def test_public_loopback_and_garbage_addresses_are_never_candidates() -> None:
    for bad in ("8.8.8.8", "127.0.0.1", "0.0.0.0", "224.0.0.1", "not-an-ip", "10.0.0.1/24", ""):
        assert run([obs(ip=bad)]).detections == (), bad


def test_a_public_address_with_a_mac_keeps_the_mac_and_drops_the_address() -> None:
    finding = only(run([obs(ip="8.8.8.8", mac=MAC)]))
    assert finding.endpoint.ip is None and finding.endpoint.mac == MAC


def test_garbage_macs_are_ignored() -> None:
    finding = only(run([obs(ip="10.0.5.9", mac="not-a-mac")]))
    assert finding.endpoint.mac is None and finding.subject_key == "ip:10.0.5.9"


# --- merging reports --------------------------------------------------------------------------------------------


def test_two_sources_reporting_one_endpoint_make_one_candidate_with_both_as_evidence() -> None:
    finding = only(
        run(
            [
                obs("librenms", "9", ip="10.0.5.9", mac=MAC, hostname="printer-x"),
                obs("wazuh", "007", ip="10.0.5.9", hostname="PRINTER-X"),
            ]
        )
    )
    assert finding.endpoint.hostname == "printer-x"  # LibreNMS sorts first: deterministic
    assert {e.source for e in finding.chain[0].evidence} == {"librenms", "wazuh"}
    assert [e.source for e in finding.chain[1].evidence] == ["librenms"]


def test_an_address_only_report_joins_the_endpoint_that_has_that_address() -> None:
    result = run([obs("wazuh", "007", ip="10.0.5.9"), obs("librenms", "9", ip="10.0.5.9", mac=MAC)])
    assert len(result.detections) == 1 and result.detections[0].endpoint.mac == MAC


def test_different_macs_are_different_endpoints() -> None:
    result = run(
        [
            obs(native="1", ip="10.0.5.9", mac=MAC),
            obs(native="2", ip="10.0.5.10", mac="aa:bb:cc:00:11:33"),
        ]
    )
    assert len(result.detections) == 2


def test_detections_come_out_in_a_stable_order_whatever_the_input_order() -> None:
    a = obs(native="1", ip="10.0.5.9", mac=MAC)
    b = obs(native="2", ip="10.0.5.10", mac="aa:bb:cc:00:11:33")
    c = obs("wazuh", "3", ip="10.0.5.11")
    assert [x.subject_key for x in run([a, b, c]).detections] == [
        x.subject_key for x in run([c, b, a]).detections
    ]


def test_at_most_the_candidate_cap_is_examined_and_truncation_is_reported() -> None:
    many = [
        obs(native=str(i), ip=f"10.{i // 250}.{i % 250}.1") for i in range(d.MAX_CANDIDATES + 20)
    ]
    correlation = CorrelationPolicy()
    candidates, truncated = d.collect_candidates(
        many, [], CorrelationIndex([], correlation), correlation, NOW
    )
    assert len(candidates) == d.MAX_CANDIDATES and truncated is True


# --- the chain ----------------------------------------------------------------------------------------------------


def test_without_a_source_for_attachment_port_and_vlan_those_hops_are_unavailable_not_filled_in() -> (
    None
):
    finding = only(run([obs(ip="10.0.5.9", mac=MAC)]))
    ip, mac, attachment, port, vlan = finding.chain
    assert (ip.basis, mac.basis) == ("observed", "observed")
    for slot in (attachment, port, vlan):
        assert (slot.basis, slot.value, slot.reason, slot.evidence) == (
            "unknown",
            None,
            "source-unavailable",
            [],
        )


def test_a_connected_source_that_says_nothing_about_a_mac_leaves_no_evidence() -> None:
    finding = only(run([obs(ip="10.0.5.9", mac=MAC)], capabilities=ALL_RELATIONS))
    assert {s.reason for s in finding.chain[2:]} == {"no-evidence"}


def test_a_switch_mac_table_fills_the_attachment_port_and_vlan() -> None:
    finding = only(run([obs(ip="10.0.5.9", mac=MAC)], records=[fdb()], capabilities=ALL_RELATIONS))
    _ip, _mac, attachment, port, vlan = finding.chain
    assert attachment.basis == "observed" and attachment.attachment_kind == "switch"
    assert attachment.label == "access-sw-3" and attachment.evidence[0].kind == "switch-mac-table"
    assert port.basis == "observed" and port.label == "Gi1/0/7"
    assert (vlan.basis, vlan.value) == ("observed", "vlan-20")
    assert attachment.confidence == 0.9


def test_an_access_point_association_is_an_ap_attachment() -> None:
    wifi = record(
        EvidenceKind.WIFI_ASSOCIATION,
        "wifi-1",
        Assertion(mac_ref(MAC), Relation.MAC_AP, ap_ref("netbox", "ap-1", "ap-lobby")),
        Assertion(mac_ref(MAC), Relation.MAC_VLAN, vlan_ref(40)),
        source="wlc",
    )
    finding = only(run([obs(ip="10.0.5.9", mac=MAC)], records=[wifi], capabilities=ALL_RELATIONS))
    assert finding.chain[2].attachment_kind == "ap" and finding.chain[2].label == "ap-lobby"
    assert finding.chain[3].reason == "no-evidence" and finding.chain[4].value == "vlan-40"


def test_an_address_only_observation_gets_its_mac_from_a_dhcp_lease_and_says_how() -> None:
    finding = only(
        run([obs(ip="10.0.5.9")], records=[lease("10.0.5.9"), fdb()], capabilities=ALL_RELATIONS)
    )
    assert finding.endpoint.mac == MAC and finding.subject_key == f"mac:{MAC}"
    mac = finding.chain[1]
    assert mac.basis == "observed" and mac.evidence[0].kind == "dhcp-lease"
    assert finding.chain[2].basis == "observed"


def test_an_endpoint_only_the_records_know_is_found_from_them() -> None:
    result = run([], records=[lease("10.0.5.9"), fdb()], capabilities=ALL_RELATIONS)
    finding = only(result)
    assert finding.endpoint.mac == MAC and finding.endpoint.ip == "10.0.5.9"
    assert finding.chain[0].evidence[0].source == "dhcp"


def test_conflicting_switch_records_leave_the_attachment_unknown_with_the_reason() -> None:
    finding = only(
        run(
            [obs(ip="10.0.5.9", mac=MAC)],
            records=[fdb(native="a", switch="sw-3"), fdb(native="b", switch="sw-4")],
            capabilities=ALL_RELATIONS,
        )
    )
    assert finding.chain[2].basis == "unknown" and finding.chain[2].reason == "conflicting-evidence"


def test_expired_evidence_is_not_a_link() -> None:
    old = record(
        EvidenceKind.SWITCH_MAC_TABLE,
        "old",
        Assertion(mac_ref(MAC), Relation.MAC_SWITCH, switch_ref("netbox", "sw-3", "access-sw-3")),
        valid_from=NOW - timedelta(hours=3),
        observed_at=NOW - timedelta(hours=3),
    )
    finding = only(run([obs(ip="10.0.5.9", mac=MAC)], records=[old], capabilities=ALL_RELATIONS))
    assert finding.chain[2].basis == "unknown"


def test_hostile_labels_and_hostnames_are_carried_as_data() -> None:
    hostile = "<script>alert(1)</script> ' OR 1=1 --"
    finding = only(run([obs(ip="10.0.5.9", hostname=hostile)]))
    assert finding.endpoint.hostname == hostile
    validate(
        "unknown_device_finding",
        json.loads(
            finding.as_finding(
                "unknown-device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc", NOW
            ).model_dump_json()
        ),
    )


def test_an_unnormalisable_name_is_tracked_by_a_hash_of_it() -> None:
    finding = only(run([obs(hostname="Prïnter X (lobby)")]))
    assert finding.subject_key.startswith("hash:")


# --- severity and the proposal ------------------------------------------------------------------------------------


def test_the_severity_comes_from_the_operators_policy() -> None:
    finding = only(run([obs(ip="10.20.4.5", mac=MAC)], policy=POLICY))
    assert (finding.severity, finding.severity_basis) == ("high", "policy-rule")
    default = only(run([obs(ip="172.16.0.5", mac=MAC)], policy=POLICY))
    assert (default.severity, default.severity_basis) == ("medium", "policy-default")


def test_without_a_policy_the_severity_is_unknown_and_nothing_is_proposed() -> None:
    finding = only(run([obs(ip="10.20.4.5", mac=MAC)]))
    assert (finding.severity, finding.severity_basis, finding.proposed_action) == (
        "unknown",
        "no-policy",
        None,
    )


def test_a_vlan_rule_uses_the_vlan_the_evidence_observed() -> None:
    switch = fdb(vlan=30)
    finding = only(
        run(
            [obs(ip="172.16.0.5", mac=MAC)],
            records=[switch],
            policy=POLICY,
            capabilities=ALL_RELATIONS,
        )
    )
    assert (finding.severity, finding.severity_basis) == ("critical", "policy-rule")


def test_a_quarantine_is_proposed_only_at_the_operators_threshold_and_never_executable() -> None:
    high = only(run([obs(ip="10.20.4.5", mac=MAC)], policy=POLICY))
    assert high.proposed_action is not None
    assert high.proposed_action.executable is False and high.proposed_action.state == "proposed"
    assert high.proposed_action.action_type == "endpoint.isolate"
    medium = only(run([obs(ip="172.16.0.5", mac=MAC)], policy=POLICY))
    assert medium.proposed_action is None


def test_every_detection_is_a_valid_finding() -> None:
    result = run(
        [
            obs(ip="10.20.4.5", mac=MAC, hostname="printer-x"),
            obs("wazuh", "007", ip="10.20.4.6"),
            obs(hostname="only-a-name"),
        ],
        records=[fdb()],
        policy=POLICY,
        capabilities=ALL_RELATIONS,
    )
    assert len(result.detections) == 3
    for detection in result.detections:
        finding = detection.as_finding("unknown-device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc", NOW)
        validate("unknown_device_finding", json.loads(finding.model_dump_json()))


@pytest.mark.parametrize("count", [0, 1])
def test_no_observations_no_findings(count: int) -> None:
    result = run([] if count == 0 else [obs()])
    assert result.detections == () and result.unverified == 0
