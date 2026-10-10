"""Path visualisation model (S7 Step 4d): explicit NetBox cables only, nothing fabricated.

Pure unit tests over plain topology data. The path is User -> access point -> access switch ->
core -> firewall -> server, grown outward from the resolved target one explicit cable at a time.
A tier nothing explicit establishes stays unknown, and a hop after an unknown one is unknown too
because there is no link to follow.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid5

from netsight_api.contracts import validate
from netsight_api.diagnostic_path import (
    TopologyDevice,
    TopologyLink,
    TopologyRead,
    build_path,
)

OBSERVED = datetime(2026, 10, 10, 8, 0, 4, tzinfo=UTC)


def device_id(name: str) -> str:
    return f"device-{uuid5(NAMESPACE_URL, name)}"


def device(
    name: str,
    role: str | None,
    *,
    hostname: str | None = None,
    addresses: tuple[str, ...] = (),
) -> TopologyDevice:
    return TopologyDevice(
        device_id=device_id(name), name=name, role=role, hostname=hostname, addresses=addresses
    )


def link(a: str, b: str) -> TopologyLink:
    return TopologyLink(device_id(a), device_id(b))


def read(devices: list[TopologyDevice], links: list[TopologyLink]) -> TopologyRead:
    return TopologyRead(
        state="ok", devices=tuple(devices), links=tuple(links), observed_at=OBSERVED
    )


FULL_DEVICES = [
    device("SERVER01", "server", hostname="server01.example.test", addresses=("10.0.5.20/24",)),
    device("fw-01", "Firewall"),
    device("core-01", "core_switch"),
    device("sw-access-01", "Access Switch"),
    device("ap-01", "access-point"),
]
FULL_LINKS = [
    link("SERVER01", "fw-01"),
    link("fw-01", "core-01"),
    link("core-01", "sw-access-01"),
    link("sw-access-01", "ap-01"),
]


def tiers(path):  # type: ignore[no-untyped-def]
    return {hop.tier: hop for hop in path.hops}


def test_no_topology_source_is_not_connected_with_nothing_drawn() -> None:
    path = build_path(TopologyRead("not-connected", (), (), None), "SERVER01", None)
    assert (path.state, path.hops, path.links, path.observed_at) == ("not-connected", [], [], None)


def test_an_unreadable_topology_is_unknown_with_nothing_drawn() -> None:
    path = build_path(TopologyRead("unknown", (), (), None), "SERVER01", None)
    assert (path.state, path.hops, path.links) == ("unknown", [], [])


def test_a_target_that_is_not_in_the_topology_is_unknown() -> None:
    path = build_path(read(FULL_DEVICES, FULL_LINKS), "other-host", None)
    assert (path.state, path.hops, path.links) == ("unknown", [], [])


def test_a_target_that_matches_two_devices_is_not_guessed() -> None:
    twins = [device("DUP", "server"), TopologyDevice(device_id("DUP2"), "dup", "server", None, ())]
    path = build_path(read(twins, []), "dup", None)
    assert path.state == "unknown"


def test_the_full_explicit_chain_is_drawn_in_display_order() -> None:
    path = build_path(read(FULL_DEVICES, FULL_LINKS), "SERVER01", None)
    assert path.state == "ok" and path.observed_at == OBSERVED
    assert [hop.tier for hop in path.hops] == [
        "user",
        "access-point",
        "access-switch",
        "core",
        "firewall",
        "server",
    ]
    by_tier = tiers(path)
    assert by_tier["user"].state == "unknown"
    for name, tier in [
        ("ap-01", "access-point"),
        ("sw-access-01", "access-switch"),
        ("core-01", "core"),
        ("fw-01", "firewall"),
        ("SERVER01", "server"),
    ]:
        assert by_tier[tier].state == "known"
        assert by_tier[tier].device_id == device_id(name)
        assert by_tier[tier].name == name
    assert [(link.from_tier, link.state) for link in path.links] == [
        ("user", "unknown"),
        ("access-point", "known"),
        ("access-switch", "known"),
        ("core", "known"),
        ("firewall", "known"),
    ]
    validate("diagnostic_path", json.loads(path.model_dump_json(by_alias=True)))


def test_the_target_is_found_by_hostname_or_address_ignoring_case_and_prefix() -> None:
    for needle in ("server01.EXAMPLE.test", "10.0.5.20", " server01 "):
        path = build_path(read(FULL_DEVICES, FULL_LINKS), needle, None)
        assert path.state == "ok", needle
        assert tiers(path)["server"].name == "SERVER01"


def test_a_missing_cable_leaves_the_tier_and_everything_beyond_it_unknown() -> None:
    links = [
        link("SERVER01", "fw-01"),
        link("core-01", "sw-access-01"),
        link("sw-access-01", "ap-01"),
    ]
    path = build_path(read(FULL_DEVICES, links), "SERVER01", None)
    by_tier = tiers(path)
    assert by_tier["firewall"].state == "known"
    # core-01 exists with the right role but no explicit cable joins it to the firewall:
    for tier in ("core", "access-switch", "access-point"):
        assert by_tier[tier].state == "unknown", tier
        assert by_tier[tier].device_id is None and by_tier[tier].name is None
    assert [link.state for link in path.links] == ["unknown"] * 4 + ["known"]


def test_a_role_that_is_not_recognised_is_never_guessed_into_a_tier() -> None:
    devices = [device("SERVER01", "server"), device("edge-1", "Catalyst 9300"), device("n-1", None)]
    links = [link("SERVER01", "edge-1"), link("SERVER01", "n-1")]
    path = build_path(read(devices, links), "SERVER01", None)
    assert tiers(path)["firewall"].state == "unknown"


def test_two_candidates_for_one_tier_are_not_chosen_between() -> None:
    devices = [*FULL_DEVICES, device("fw-02", "firewall")]
    links = [*FULL_LINKS, link("SERVER01", "fw-02")]
    path = build_path(read(devices, links), "SERVER01", None)
    by_tier = tiers(path)
    assert by_tier["firewall"].state == "unknown"
    assert by_tier["core"].state == "unknown"


def test_self_links_and_links_to_unlisted_devices_are_ignored() -> None:
    links = [
        link("SERVER01", "SERVER01"),
        TopologyLink(device_id("SERVER01"), device_id("not-in-the-inventory")),
        *FULL_LINKS,
    ]
    path = build_path(read(FULL_DEVICES, links), "SERVER01", None)
    assert tiers(path)["firewall"].state == "known"


def test_the_suspected_hop_follows_the_probable_domain() -> None:
    expectations = {
        "firewall": "firewall",
        "core": "core",
        "access-device": "access-switch",
        "service": "server",
        "target": "server",
        "host": "server",
        "interface": "server",
    }
    for domain, tier in expectations.items():
        path = build_path(read(FULL_DEVICES, FULL_LINKS), "SERVER01", domain)  # type: ignore[arg-type]
        assert [hop.tier for hop in path.hops if hop.highlight] == [tier], domain
    for domain in ("wan-dns-external", None):
        path = build_path(read(FULL_DEVICES, FULL_LINKS), "SERVER01", domain)
        assert all(hop.highlight is None for hop in path.hops), domain


def test_a_suspected_tier_that_is_unknown_is_still_marked_but_stays_unknown() -> None:
    path = build_path(read(FULL_DEVICES[:1], []), "SERVER01", "firewall")
    firewall = tiers(path)["firewall"]
    assert firewall.state == "unknown" and firewall.highlight == "suspected"
    validate("diagnostic_path", json.loads(path.model_dump_json(by_alias=True)))


def test_a_hostile_device_name_is_carried_as_bounded_inert_text() -> None:
    hostile = "<img src=x onerror=alert(1)>\x1b[2J" + "n" * 400
    devices = [device("SERVER01", "server"), device(hostile, "firewall")]
    path = build_path(read(devices, [link("SERVER01", hostile)]), "SERVER01", None)
    name = tiers(path)["firewall"].name
    assert name is not None and len(name) <= 255 and "\x1b" not in name
    assert name.startswith("<img src=x onerror=alert(1)>")


def test_a_large_topology_is_handled_in_linear_time() -> None:
    devices = [device("SERVER01", "server")] + [device(f"leaf-{n}", "server") for n in range(5000)]
    links = [link("SERVER01", f"leaf-{n}") for n in range(5000)]
    path = build_path(read(devices, links), "SERVER01", None)
    assert path.state == "ok"
