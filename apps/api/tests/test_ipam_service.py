"""The IPAM service: reading NetBox IPAM and the telemetry that decides active versus stale (Step 8b).

Hermetic: every source is a fake that returns a value or raises. NetBox datasets fail independently
(a missing ip-ranges endpoint must not hide the prefixes); telemetry is optional, and when it cannot
be read nothing is judged stale.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any

import pytest
from inventory_support import (
    NOW,
    FakeLibrenms,
    FakeNetbox,
    FakeWazuh,
    address,
    agent,
    device,
    prefix,
    reserved,
    vlan,
)

from netsight_api.inventory.cache import TtlCache
from netsight_api.ipam import service as svc
from netsight_api.ipam.service import IpamService, stale_window_from_env

DAY = timedelta(hours=24)


def make(
    netbox: Any = "default",
    librenms: Any = "default",
    wazuh: Any = "default",
    *,
    window: timedelta | None = DAY,
    cache: TtlCache[Any] | None = None,
) -> IpamService:
    if netbox == "default":
        netbox = FakeNetbox(
            prefixes=[prefix("1", "10.0.0.0/24")],
            vlans=[vlan("11", 20, "staff")],
            addresses=[
                address("1", "10.0.0.2"),
                address("2", "10.0.0.3"),
                address("3", "10.0.0.4"),
            ],
            ranges=[reserved("9", "10.0.0.100", "10.0.0.110")],
        )
    if librenms == "default":
        librenms = FakeLibrenms(
            [
                device("librenms", "7", "sw", ip="10.0.0.2"),
                device("librenms", "8", "down-host", ip="10.0.0.3", status="offline"),
            ]
        )
    if wazuh == "default":
        wazuh = FakeWazuh([agent("001", "pc", "10.0.0.50")])
    return IpamService(
        netbox=netbox,
        librenms=librenms,
        wazuh=wazuh,
        stale_window=window,
        clock=lambda: NOW,
        cache=cache or TtlCache(0.0),
    )


def activity(snapshot: svc.IpamSnapshot) -> dict[str, str]:
    assert snapshot.build is not None and snapshot.build.addresses is not None
    return {a.address: a.activity for a in snapshot.build.addresses}


@pytest.mark.asyncio
async def test_everything_ok_judges_activity_from_both_telemetry_sources() -> None:
    snapshot = await make().snapshot()
    assert snapshot.state == "ok"
    assert {s.source: s.state for s in snapshot.sources} == {
        "netbox": "ok",
        "librenms": "ok",
        "wazuh": "ok",
    }
    assert snapshot.telemetry.state == "ok" and snapshot.telemetry.sources == ["librenms", "wazuh"]
    assert snapshot.telemetry.window_seconds == 86400
    assert activity(snapshot) == {
        "10.0.0.2": "active",  # LibreNMS says the device is up
        "10.0.0.3": "stale",  # LibreNMS lists it but it is down: not seen
        "10.0.0.4": "stale",
        "10.0.0.50": "active",  # only Wazuh saw it
    }


@pytest.mark.asyncio
async def test_a_wazuh_agent_seen_within_the_window_counts_even_when_disconnected_now() -> None:
    recent = agent(
        "002", "laptop", "10.0.0.60", status="disconnected", seen=NOW - timedelta(hours=3)
    )
    old = agent("003", "gone", "10.0.0.61", status="disconnected", seen=NOW - timedelta(hours=30))
    never = agent("004", "new", "10.0.0.62", status="never_connected")
    snapshot = await make(wazuh=FakeWazuh([recent, old, never])).snapshot()
    ips = activity(snapshot)
    assert ips["10.0.0.60"] == "active"
    assert "10.0.0.61" not in ips and "10.0.0.62" not in ips


@pytest.mark.asyncio
async def test_the_agent_window_and_bound_are_the_configured_ones() -> None:
    wazuh = FakeWazuh([])
    await make(wazuh=wazuh, window=timedelta(hours=6)).snapshot()
    ((start, end, limit),) = wazuh.calls
    assert (end - start, end, limit) == (timedelta(hours=6), NOW, svc.AGENT_LIMIT)


@pytest.mark.asyncio
async def test_without_any_telemetry_nothing_is_judged_stale() -> None:
    snapshot = await make(librenms=None, wazuh=None).snapshot()
    assert snapshot.telemetry.state == "not-connected" and snapshot.telemetry.sources == []
    assert set(activity(snapshot).values()) == {"unknown"}


@pytest.mark.asyncio
async def test_telemetry_that_fails_is_unknown_and_judges_nothing() -> None:
    snapshot = await make(
        librenms=FakeLibrenms(RuntimeError("x")), wazuh=FakeWazuh(RuntimeError("y"))
    ).snapshot()
    assert snapshot.telemetry.state == "unknown"
    assert set(activity(snapshot).values()) == {"unknown"}
    assert {s.source: s.state for s in snapshot.sources}["librenms"] == "unknown"


@pytest.mark.asyncio
async def test_one_failing_telemetry_source_still_judges_with_the_other() -> None:
    snapshot = await make(wazuh=FakeWazuh(RuntimeError("y"))).snapshot()
    assert snapshot.telemetry.state == "ok" and snapshot.telemetry.sources == ["librenms"]
    assert activity(snapshot)["10.0.0.2"] == "active"


@pytest.mark.asyncio
async def test_a_truncated_agent_list_is_not_used() -> None:
    snapshot = await make(
        librenms=None, wazuh=FakeWazuh([agent("1", "a", "10.0.0.9")], truncated=True)
    ).snapshot()
    assert snapshot.telemetry.state == "unknown"
    assert {s.source: s.state for s in snapshot.sources}["wazuh"] == "unknown"


@pytest.mark.asyncio
async def test_an_unusable_stale_window_means_telemetry_cannot_judge() -> None:
    snapshot = await make(window=None).snapshot()
    assert snapshot.telemetry.state == "unknown"
    assert set(activity(snapshot).values()) == {"unknown"}


@pytest.mark.asyncio
async def test_without_netbox_there_is_no_ipam() -> None:
    snapshot = await make(netbox=None).snapshot()
    assert snapshot.state == "not-connected" and snapshot.build is None
    assert {s.source: s.state for s in snapshot.sources}["netbox"] == "not-connected"


@pytest.mark.asyncio
async def test_netbox_failing_entirely_is_unknown() -> None:
    boom = RuntimeError("boom")
    netbox = FakeNetbox(prefixes=boom, vlans=boom, addresses=boom, ranges=boom)
    snapshot = await make(netbox=netbox).snapshot()
    assert snapshot.state == "unknown" and snapshot.build is None


@pytest.mark.asyncio
async def test_netbox_datasets_fail_independently() -> None:
    netbox = FakeNetbox(
        prefixes=[prefix("1", "10.0.0.0/24")],
        vlans=RuntimeError("down"),
        addresses=[address("1", "10.0.0.2")],
        ranges=RuntimeError("no ip-ranges endpoint on this NetBox"),
    )
    snapshot = await make(netbox=netbox).snapshot()
    assert snapshot.state == "ok" and snapshot.build is not None
    assert snapshot.build.vlans is None and snapshot.build.prefixes is not None
    assert snapshot.build.counts.vlans is None and snapshot.build.counts.reserved_ranges is None
    assert snapshot.build.prefixes[0].utilisation.reserved is None


@pytest.mark.asyncio
async def test_a_snapshot_is_cached_and_concurrent_callers_share_one_read() -> None:
    netbox = FakeNetbox(prefixes=[prefix("1", "10.0.0.0/24")])
    service = make(netbox=netbox, librenms=None, wazuh=None, cache=TtlCache(60.0))
    snapshots = await asyncio.gather(*(service.snapshot() for _ in range(4)))
    assert len({id(s) for s in snapshots}) == 1
    assert netbox.calls.count("prefixes") == 1


@pytest.mark.asyncio
async def test_a_hanging_source_is_unknown_after_its_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(svc, "SOURCE_BUDGET_SECONDS", 0.05)

    class Hanging(FakeLibrenms):
        async def devices(self) -> Any:
            await asyncio.sleep(5)

    snapshot = await make(librenms=Hanging([])).snapshot()
    assert {s.source: s.state for s in snapshot.sources}["librenms"] == "unknown"
    assert snapshot.telemetry.sources == ["wazuh"]


@pytest.mark.asyncio
async def test_a_device_with_an_unusable_address_is_skipped_not_fatal() -> None:
    odd = device("librenms", "9", "weird", ip="not-an-ip")
    ok = device("librenms", "7", "sw", ip="10.0.0.2")
    snapshot = await make(librenms=FakeLibrenms([odd, ok]), wazuh=None).snapshot()
    assert activity(snapshot)["10.0.0.2"] == "active"


def test_the_stale_window_comes_from_hours_in_the_environment() -> None:
    assert stale_window_from_env({}) == DAY
    assert stale_window_from_env({"NETSIGHT_IPAM_STALE_WINDOW_HOURS": "6"}) == timedelta(hours=6)
    assert stale_window_from_env({"NETSIGHT_IPAM_STALE_WINDOW_HOURS": "168"}) == timedelta(
        hours=168
    )
    for bad in ("0", "169", "-1", "x", "1.5", " "):
        window = stale_window_from_env({"NETSIGHT_IPAM_STALE_WINDOW_HOURS": bad})
        assert window is None or bad.strip() == ""
