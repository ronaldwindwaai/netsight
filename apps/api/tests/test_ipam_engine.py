"""IPAM arithmetic (Step 8b): the prefix tree, utilisation with its basis, and active versus stale.

Pure: no I/O, no clock. NetBox says what is intended; telemetry only ever says "seen within the
window". Anything that cannot be known (telemetry unreadable, addresses unreadable, a huge IPv6
prefix) is stated as unknown, never guessed.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime

from inventory_support import address, prefix, reserved, vlan

from netsight_api.contracts import validate
from netsight_api.ipam.engine import Seen, build_ipam

SEEN_AT = datetime(2026, 10, 11, 11, 55, tzinfo=UTC)


def seen(*ips: str, by: str = "librenms") -> dict[str, Seen]:
    return {ip: Seen(frozenset({by}), SEEN_AT) for ip in ips}  # type: ignore[arg-type]


def by_prefix(build) -> dict:  # type: ignore[no-untyped-def]
    return {p.prefix: p for p in build.prefixes}


def addresses_of(count: int, base: str = "10.0.0.") -> list:  # type: ignore[type-arg]
    return [address(str(i), f"{base}{i}") for i in range(1, count + 1)]


def run(
    prefixes=None,
    vlans=None,
    addresses=None,
    ranges=None,
    telemetry=None,  # type: ignore[no-untyped-def]
):
    return build_ipam(
        prefixes=prefixes if prefixes is not None else [],
        vlans=vlans if vlans is not None else [],
        addresses=addresses if addresses is not None else [],
        ranges=ranges if ranges is not None else [],
        seen=telemetry,
    )


# --- the prefix tree ------------------------------------------------------------------------------------


def test_prefixes_form_a_tree_by_containment_in_pre_order() -> None:
    build = run(
        prefixes=[
            prefix("1", "10.1.5.0/24"),
            prefix("2", "192.168.0.0/24"),
            prefix("3", "10.0.0.0/8"),
            prefix("4", "10.2.0.0/16"),
            prefix("5", "10.1.0.0/16"),
        ]
    )
    assert [p.prefix for p in build.prefixes] == [
        "10.0.0.0/8",
        "10.1.0.0/16",
        "10.1.5.0/24",
        "10.2.0.0/16",
        "192.168.0.0/24",
    ]
    tree = by_prefix(build)
    assert tree["10.0.0.0/8"].parent_id is None and tree["10.0.0.0/8"].depth == 0
    assert tree["10.1.0.0/16"].parent_id == tree["10.0.0.0/8"].id and tree["10.1.0.0/16"].depth == 1
    assert (
        tree["10.1.5.0/24"].parent_id == tree["10.1.0.0/16"].id and tree["10.1.5.0/24"].depth == 2
    )
    assert tree["10.2.0.0/16"].parent_id == tree["10.0.0.0/8"].id
    assert tree["192.168.0.0/24"].parent_id is None
    assert tree["10.0.0.0/8"].children == 2 and tree["10.1.0.0/16"].children == 1


def test_a_prefix_never_nests_across_vrfs_or_families() -> None:
    build = run(
        prefixes=[
            prefix("1", "10.0.0.0/8"),
            prefix("2", "10.1.0.0/16", vrf_id="9"),
            prefix("3", "::/0"),
            prefix("4", "2001:db8::/32"),
        ]
    )
    tree = by_prefix(build)
    assert tree["10.1.0.0/16"].parent_id is None
    assert tree["2001:db8::/32"].parent_id == tree["::/0"].id
    assert tree["10.0.0.0/8"].children == 0


def test_the_same_prefix_twice_nests_deterministically() -> None:
    first = run(prefixes=[prefix("2", "10.0.0.0/24"), prefix("1", "10.0.0.0/24")])
    second = run(prefixes=[prefix("1", "10.0.0.0/24"), prefix("2", "10.0.0.0/24")])
    assert [p.id for p in first.prefixes] == [p.id for p in second.prefixes]
    assert [p.depth for p in first.prefixes] == [0, 1]


def test_the_vlan_a_prefix_names_is_carried_with_its_number() -> None:
    build = run(prefixes=[prefix("1", "10.0.0.0/24", vlan_id="11", vlan_vid=20, vlan_name="staff")])
    assert build.prefixes[0].vlan is not None
    assert (build.prefixes[0].vlan.vid, build.prefixes[0].vlan.name) == (20, "staff")


# --- capacity and utilisation -----------------------------------------------------------------------------


def test_a_24_has_254_usable_hosts_and_utilisation_follows_the_addresses() -> None:
    build = run(prefixes=[prefix("1", "10.0.0.0/24")], addresses=addresses_of(100))
    u = build.prefixes[0].utilisation
    assert (u.state, u.basis, u.capacity) == ("ok", "netbox-addresses", 254)
    assert (u.netbox_addresses, u.discovered_only, u.used) == (100, 0, 100)
    assert (u.reserved, u.free, u.percent) == (0, 154, 39.4)


def test_small_prefixes_and_pools_have_their_own_capacity() -> None:
    build = run(
        prefixes=[
            prefix("1", "10.0.1.0/31"),
            prefix("2", "10.0.2.5/32"),
            prefix("3", "10.0.3.0/30"),
            prefix("4", "10.0.4.0/24", is_pool=True),
        ]
    )
    capacity = {p.prefix: p.utilisation.capacity for p in build.prefixes}
    assert capacity == {"10.0.1.0/31": 2, "10.0.2.5/32": 1, "10.0.3.0/30": 2, "10.0.4.0/24": 256}


def test_ipv6_capacity_is_meaningful_only_for_small_prefixes() -> None:
    build = run(prefixes=[prefix("1", "2001:db8::/64"), prefix("2", "2001:db8:1::/120")])
    wide, narrow = by_prefix(build)["2001:db8::/64"], by_prefix(build)["2001:db8:1::/120"]
    assert (
        wide.utilisation.state == "unknown" and wide.utilisation.basis == "capacity-not-meaningful"
    )
    assert wide.utilisation.capacity is None and wide.utilisation.percent is None
    assert narrow.utilisation.capacity == 256 and narrow.utilisation.state == "ok"


def test_addresses_that_could_not_be_read_make_utilisation_unknown_not_empty() -> None:
    build = build_ipam(
        prefixes=[prefix("1", "10.0.0.0/24")], vlans=[], addresses=None, ranges=[], seen=None
    )
    u = build.prefixes[0].utilisation
    assert (u.state, u.basis, u.percent, u.used) == ("unknown", "addresses-unavailable", None, None)


def test_a_prefix_netbox_marks_utilized_is_full_by_the_operators_declaration() -> None:
    build = run(
        prefixes=[prefix("1", "10.0.0.0/24", mark_utilized=True)], addresses=addresses_of(3)
    )
    u = build.prefixes[0].utilisation
    assert (u.basis, u.percent, u.state) == ("marked-utilized", 100, "ok")
    assert u.netbox_addresses == 3


def test_every_netbox_address_status_counts_and_other_vrfs_do_not() -> None:
    addrs = [
        address("1", "10.0.0.1", status="active"),
        address("2", "10.0.0.2", status="reserved"),
        address("3", "10.0.0.3", status="deprecated"),
        address("4", "10.0.0.4", status="dhcp"),
        address("5", "10.0.0.5", vrf_id="9"),
        address("6", "10.0.1.1"),
    ]
    build = run(prefixes=[prefix("1", "10.0.0.0/24")], addresses=addrs)
    assert build.prefixes[0].utilisation.netbox_addresses == 4


def test_a_container_counts_the_addresses_of_its_children() -> None:
    build = run(
        prefixes=[prefix("1", "10.0.0.0/16"), prefix("2", "10.0.5.0/24")],
        addresses=addresses_of(10, "10.0.5."),
    )
    tree = by_prefix(build)
    assert tree["10.0.0.0/16"].utilisation.netbox_addresses == 10
    assert tree["10.0.5.0/24"].utilisation.netbox_addresses == 10


def test_discovered_addresses_netbox_lacks_are_counted_with_their_basis() -> None:
    build = run(
        prefixes=[prefix("1", "10.0.0.0/24")],
        addresses=[address("1", "10.0.0.1")],
        telemetry=seen("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.9.9.9"),
    )
    u = build.prefixes[0].utilisation
    assert (u.basis, u.netbox_addresses, u.discovered_only, u.used) == (
        "netbox-and-discovered",
        1,
        2,
        3,
    )


def test_telemetry_that_was_readable_but_saw_nothing_still_has_that_basis() -> None:
    build = run(
        prefixes=[prefix("1", "10.0.0.0/24")], addresses=[address("1", "10.0.0.1")], telemetry={}
    )
    assert build.prefixes[0].utilisation.basis == "netbox-and-discovered"
    assert build.prefixes[0].utilisation.discovered_only == 0


def test_a_prefix_in_a_vrf_cannot_borrow_vrf_less_telemetry() -> None:
    build = run(
        prefixes=[prefix("1", "10.0.0.0/24", vrf_id="9")],
        addresses=[address("1", "10.0.0.1", vrf_id="9")],
        telemetry=seen("10.0.0.1", "10.0.0.2"),
    )
    u = build.prefixes[0].utilisation
    assert (u.basis, u.netbox_addresses, u.discovered_only) == ("netbox-addresses", 1, 0)


def test_reserved_ranges_are_counted_once_and_not_on_top_of_used_addresses() -> None:
    addrs = [address(str(i), f"10.0.0.{i}") for i in (1, 2, 105, 110, 111)]
    build = run(
        prefixes=[prefix("1", "10.0.0.0/24")],
        addresses=addrs,
        ranges=[
            reserved("9", "10.0.0.100", "10.0.0.119"),
            reserved("10", "10.0.0.110", "10.0.0.124"),
        ],
    )
    p = build.prefixes[0]
    # the union is .100-.124 = 25 addresses, of which .105 .110 .111 are already used
    assert p.utilisation.used == 5
    assert (p.utilisation.reserved, p.utilisation.free) == (22, 254 - 5 - 22)
    assert p.reserved_ranges_total == 2
    assert {(r.start, r.end, r.size) for r in p.reserved_ranges} == {
        ("10.0.0.100", "10.0.0.119", 20),
        ("10.0.0.110", "10.0.0.124", 15),
    }


def test_unreadable_reserved_ranges_leave_reserved_and_free_unreported() -> None:
    build = build_ipam(
        prefixes=[prefix("1", "10.0.0.0/24")],
        vlans=[],
        addresses=addresses_of(2),
        ranges=None,
        seen=None,
    )
    u = build.prefixes[0].utilisation
    assert u.state == "ok" and (u.reserved, u.free) == (None, None)
    assert build.prefixes[0].reserved_ranges == []


def test_a_reserved_range_is_listed_on_the_smallest_prefix_that_contains_all_of_it() -> None:
    build = run(
        prefixes=[prefix("1", "10.0.0.0/16"), prefix("2", "10.0.5.0/24")],
        ranges=[reserved("9", "10.0.5.10", "10.0.5.20")],
    )
    tree = by_prefix(build)
    assert tree["10.0.5.0/24"].reserved_ranges_total == 1
    assert tree["10.0.0.0/16"].reserved_ranges_total == 0
    assert (
        tree["10.0.0.0/16"].utilisation.reserved == 11
    )  # still reserved space inside the container


def test_only_sixteen_ranges_are_listed_but_all_are_counted() -> None:
    ranges = [reserved(str(i), f"10.0.0.{i * 10}", f"10.0.0.{i * 10 + 1}") for i in range(1, 21)]
    build = run(prefixes=[prefix("1", "10.0.0.0/24")], ranges=ranges)
    assert len(build.prefixes[0].reserved_ranges) == 16
    assert build.prefixes[0].reserved_ranges_total == 20


def test_used_above_capacity_caps_the_percentage_at_100() -> None:
    addrs = [address(str(i), f"10.0.0.{i}") for i in range(4)]
    build = run(prefixes=[prefix("1", "10.0.0.0/30")], addresses=addrs)
    u = build.prefixes[0].utilisation
    assert (u.capacity, u.used, u.percent, u.free) == (2, 4, 100, 0)


# --- addresses: active versus stale -----------------------------------------------------------------------


def test_a_seen_netbox_address_is_active_with_its_witness() -> None:
    build = run(
        prefixes=[prefix("1", "10.0.0.0/24")],
        addresses=[address("1", "10.0.0.15")],
        telemetry=seen("10.0.0.15"),
    )
    (a,) = build.addresses
    assert (a.source, a.activity, a.seen_by, a.last_seen) == (
        "both",
        "active",
        ["librenms"],
        SEEN_AT,
    )
    assert a.prefix_id == build.prefixes[0].id


def test_an_unseen_netbox_address_is_stale_only_when_telemetry_was_readable() -> None:
    readable = run(addresses=[address("1", "10.0.0.15")], telemetry={})
    unreadable = run(addresses=[address("1", "10.0.0.15")], telemetry=None)
    assert readable.addresses[0].activity == "stale"
    assert unreadable.addresses[0].activity == "unknown"
    assert unreadable.addresses[0].seen_by == [] and unreadable.addresses[0].last_seen is None


def test_a_reserved_address_nobody_saw_is_reserved_not_stale() -> None:
    build = run(addresses=[address("1", "10.0.0.15", status="reserved")], telemetry={})
    assert build.addresses[0].activity == "reserved"
    again = run(addresses=[address("1", "10.0.0.15", status="reserved")], telemetry=None)
    assert again.addresses[0].activity == "reserved"


def test_a_reserved_address_that_was_seen_is_active() -> None:
    build = run(
        addresses=[address("1", "10.0.0.15", status="reserved")], telemetry=seen("10.0.0.15")
    )
    assert build.addresses[0].activity == "active"


def test_an_address_only_telemetry_saw_is_listed_as_discovered_and_active() -> None:
    build = run(prefixes=[prefix("1", "10.0.0.0/24")], telemetry=seen("10.0.0.77", by="wazuh"))
    (a,) = build.addresses
    assert (a.source, a.activity, a.status, a.dns_name, a.seen_by) == (
        "discovered",
        "active",
        None,
        None,
        ["wazuh"],
    )
    assert a.prefix_id == build.prefixes[0].id


def test_telemetry_never_vouches_for_an_address_in_a_vrf() -> None:
    build = run(addresses=[address("1", "10.0.0.15", vrf_id="9")], telemetry=seen("10.0.0.15"))
    rows = {a.source: a for a in build.addresses}
    # The VRF address is unwitnessed; the seen address is a different (VRF-less) entity.
    assert rows["netbox"].activity == "stale" and rows["netbox"].vrf == "9"
    assert rows["discovered"].activity == "active" and rows["discovered"].vrf is None


def test_two_witnesses_are_both_named_with_the_latest_time() -> None:
    later = datetime(2026, 10, 11, 11, 59, tzinfo=UTC)
    telemetry = {"10.0.0.15": Seen(frozenset({"librenms", "wazuh"}), later)}
    build = run(addresses=[address("1", "10.0.0.15")], telemetry=telemetry)  # type: ignore[arg-type]
    assert build.addresses[0].seen_by == ["librenms", "wazuh"]
    assert build.addresses[0].last_seen == later


def test_an_address_in_no_prefix_has_no_prefix_id_and_counts_nowhere() -> None:
    build = run(
        prefixes=[prefix("1", "10.0.0.0/24")], addresses=[address("1", "172.16.0.1")], telemetry={}
    )
    assert build.addresses[0].prefix_id is None
    assert build.prefixes[0].utilisation.netbox_addresses == 0


def test_addresses_are_ordered_numerically_not_as_text() -> None:
    build = run(
        addresses=[
            address(str(i), ip)
            for i, ip in enumerate(["10.0.0.100", "10.0.0.9", "10.0.0.20", "2001:db8::1"])
        ]
    )
    assert [a.address for a in build.addresses] == [
        "10.0.0.9",
        "10.0.0.20",
        "10.0.0.100",
        "2001:db8::1",
    ]


def test_the_same_address_twice_in_netbox_is_two_rows_with_distinct_ids() -> None:
    build = run(
        addresses=[address("1", "10.0.0.15"), address("2", "10.0.0.15")],
        telemetry=seen("10.0.0.15"),
    )
    assert len({a.id for a in build.addresses}) == 2
    assert {a.activity for a in build.addresses} == {"active"}


# --- vlans, counts ---------------------------------------------------------------------------------------


def test_vlans_are_ordered_by_number_and_count_the_prefixes_that_name_them() -> None:
    build = run(
        prefixes=[
            prefix("1", "10.0.0.0/24", vlan_id="11", vlan_vid=20, vlan_name="staff"),
            prefix("2", "10.0.1.0/24", vlan_id="11", vlan_vid=20, vlan_name="staff"),
            prefix("3", "10.0.2.0/24", vlan_id="12", vlan_vid=30, vlan_name="staff"),
        ],
        vlans=[vlan("12", 30, "guest"), vlan("11", 20, "staff"), vlan("13", 20, "other-site")],
    )
    assert [(v.vid, v.name, v.prefix_count) for v in build.vlans] == [
        (20, "other-site", 0),
        (20, "staff", 2),
        (30, "guest", 1),
    ]


def test_vlan_prefix_counts_are_null_when_prefixes_could_not_be_read() -> None:
    build = build_ipam(
        prefixes=None, vlans=[vlan("11", 20, "staff")], addresses=[], ranges=[], seen=None
    )
    assert build.vlans is not None and build.vlans[0].prefix_count is None
    assert build.prefixes is None


def test_counts_report_null_for_what_could_not_be_read_never_zero() -> None:
    build = build_ipam(prefixes=None, vlans=[], addresses=None, ranges=None, seen=None)
    c = build.counts
    assert (c.prefixes, c.addresses, c.reserved_ranges, c.active_addresses, c.stale_addresses) == (
        None,
        None,
        None,
        None,
        None,
    )
    assert c.vlans == 0


def test_counts_and_activity_counts_add_up() -> None:
    build = run(
        prefixes=[prefix("1", "10.0.0.0/24")],
        addresses=[
            address("1", "10.0.0.1"),
            address("2", "10.0.0.2"),
            address("3", "10.0.0.3", status="reserved"),
        ],
        telemetry=seen("10.0.0.1", "10.0.0.50"),
        ranges=[reserved("9", "10.0.0.200", "10.0.0.210")],
    )
    c = build.counts
    assert (c.prefixes, c.addresses, c.reserved_ranges) == (1, 3, 1)
    assert (c.active_addresses, c.stale_addresses, c.unknown_activity_addresses) == (2, 1, 0)
    assert c.discovered_only_addresses == 1
    counts = build.activity_counts
    assert counts is not None
    assert (counts.active, counts.stale, counts.unknown, counts.reserved) == (2, 1, 0, 1)


def test_without_telemetry_counts_of_activity_are_unknown_not_zero() -> None:
    build = run(addresses=[address("1", "10.0.0.1"), address("2", "10.0.0.2")], telemetry=None)
    c = build.counts
    assert (c.active_addresses, c.stale_addresses) == (None, None)
    assert c.unknown_activity_addresses == 2 and c.discovered_only_addresses is None


def test_everything_built_satisfies_the_canonical_contracts() -> None:
    build = run(
        prefixes=[
            prefix("1", "10.0.0.0/8"),
            prefix("2", "10.0.0.0/24", vlan_id="11", vlan_vid=20, vlan_name="staff"),
            prefix("3", "2001:db8::/64"),
        ],
        vlans=[vlan("11", 20, "staff")],
        addresses=addresses_of(5),
        ranges=[reserved("9", "10.0.0.100", "10.0.0.110")],
        telemetry=seen("10.0.0.1", "10.0.0.99"),
    )
    for item in build.prefixes:
        validate("ipam_prefix", json.loads(item.model_dump_json()))
    for vl in build.vlans:
        validate("ipam_vlan", json.loads(vl.model_dump_json()))
    for ad in build.addresses:
        validate("ipam_address", json.loads(ad.model_dump_json()))
    validate("ipam_counts", json.loads(build.counts.model_dump_json()))


def test_five_thousand_addresses_and_two_thousand_prefixes_are_handled_quickly() -> None:
    prefixes = [prefix(str(i), f"10.{i // 250}.{i % 250}.0/24") for i in range(2000)]
    prefixes.append(prefix("big", "10.0.0.0/8"))
    addrs = [address(str(i), f"10.{(i // 250) % 8}.{i % 250}.{(i % 200) + 1}") for i in range(5000)]
    started = time.monotonic()
    build = run(
        prefixes=prefixes, addresses=addrs, telemetry=seen(*[a.address for a in addrs[:100]])
    )
    assert time.monotonic() - started < 10
    assert len(build.prefixes) == 2001 and len(build.addresses) == 5000
