"""The inventory service: reading the sources, honest states, filters, counts and paging (Step 8a).

Hermetic: every source is a fake that returns a value or raises. NetBox is the authority, so
without it there are no rows; any other source failing only degrades what is compared.
"""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from typing import Any

import pytest
from inventory_support import (
    NOW,
    FakeLibrenms,
    FakeNetbox,
    FakeWazuh,
    agent,
    asset,
    device,
)

from netsight_api.adapters.netbox import AdapterError, AdapterStatus
from netsight_api.contracts import validate
from netsight_api.inventory import service as svc
from netsight_api.inventory.cache import TtlCache
from netsight_api.inventory.classmap import CLASS_MAP_ENV, load_class_map
from netsight_api.inventory.service import InventoryFilters, InventoryService

CLASS_MAP = load_class_map(
    {
        CLASS_MAP_ENV: json.dumps(
            {
                "version": 1,
                "roles": {"core-switch": "network-device", "web-server": "server"},
                "device_types": {"u6": "access-point"},
            }
        )
    }
)
FIELD = "wazuh_agent"


def make(
    netbox: Any = "default",
    librenms: Any = "default",
    wazuh: Any = "default",
    *,
    field: str | None = FIELD,
    cache: TtlCache[Any] | None = None,
) -> InventoryService:
    if netbox == "default":
        netbox = FakeNetbox(
            [
                asset("1", "core-sw-1", ip="10.0.0.2", role="core-switch"),
                asset("2", "web-1", ip="10.0.0.20", role="web-server", site="DC"),
                asset("3", "ap-1", role="odd-role", device_type="u6"),
            ],
            agent_keys={"2": "001"},
        )
    if librenms == "default":
        librenms = FakeLibrenms(
            [
                device("librenms", "7", "core-sw-1", ip="10.0.0.2", mac="aa:bb:cc:00:11:22"),
                device("librenms", "9", "printer-x", ip="10.0.5.9", status="offline"),
            ]
        )
    if wazuh == "default":
        wazuh = FakeWazuh([agent("001", "web-1", "10.0.0.20"), agent("002", "stray", "10.0.0.77")])
    return InventoryService(
        netbox=netbox,
        librenms=librenms,
        wazuh=wazuh,
        agent_field=field,
        class_map=CLASS_MAP,
        clock=lambda: NOW,
        cache=cache or TtlCache(0.0),
    )


def states(snapshot: svc.InventorySnapshot) -> dict[str, str]:
    return {s.source: s.state for s in snapshot.sources}


@pytest.mark.asyncio
async def test_all_sources_ok_merges_everything_and_is_contract_valid() -> None:
    snapshot = await make().snapshot()
    assert snapshot.state == "ok"
    assert states(snapshot) == {"netbox": "ok", "librenms": "ok", "wazuh": "ok"}
    names = {i.name.value for i in snapshot.items}
    assert names == {"core-sw-1", "web-1", "ap-1", "printer-x", "stray"}
    assert snapshot.summary is not None and snapshot.summary.total == 5
    assert snapshot.summary.known == 3 and snapshot.summary.unknown == 2
    for item in snapshot.items:
        validate("inventory_item", json.loads(item.model_dump_json(by_alias=True)))


@pytest.mark.asyncio
async def test_each_source_carries_the_time_of_its_own_read() -> None:
    snapshot = await make().snapshot()
    assert all(s.observed_at == NOW for s in snapshot.sources)


@pytest.mark.asyncio
async def test_without_netbox_there_are_no_rows_and_no_claims() -> None:
    snapshot = await make(netbox=None).snapshot()
    assert snapshot.state == "not-connected"
    assert snapshot.items == () and snapshot.summary is None
    assert states(snapshot)["netbox"] == "not-connected"
    assert states(snapshot)["librenms"] == "ok"


@pytest.mark.asyncio
async def test_a_failing_netbox_is_unknown_not_an_empty_inventory() -> None:
    failing = FakeNetbox(AdapterError(AdapterStatus.UNAVAILABLE, "boom"))
    snapshot = await make(netbox=failing).snapshot()
    assert snapshot.state == "unknown"
    assert snapshot.items == () and snapshot.summary is None
    assert states(snapshot)["netbox"] == "unknown"


@pytest.mark.asyncio
async def test_a_failing_librenms_only_degrades_the_comparison() -> None:
    snapshot = await make(librenms=FakeLibrenms(RuntimeError("down"))).snapshot()
    assert snapshot.state == "ok"
    assert states(snapshot)["librenms"] == "unknown"
    by_name = {i.name.value: i for i in snapshot.items}
    assert by_name["core-sw-1"].reconcile.status == "not-checked"
    assert by_name["web-1"].reconcile.status == "reconciled"  # joined to its Wazuh agent
    assert "printer-x" not in by_name


@pytest.mark.asyncio
async def test_an_unconfigured_source_is_not_connected() -> None:
    snapshot = await make(librenms=None, wazuh=None).snapshot()
    assert states(snapshot) == {
        "netbox": "ok",
        "librenms": "not-connected",
        "wazuh": "not-connected",
    }
    assert {i.source for i in snapshot.items} == {"netbox"}
    assert {i.reconcile.status for i in snapshot.items} == {"not-checked"}


@pytest.mark.asyncio
async def test_wazuh_without_the_join_field_is_not_connected_and_never_read() -> None:
    wazuh = FakeWazuh([agent("002", "stray", "10.0.0.77")])
    snapshot = await make(wazuh=wazuh, field=None).snapshot()
    assert states(snapshot)["wazuh"] == "not-connected"
    assert wazuh.calls == []
    assert "stray" not in {i.name.value for i in snapshot.items}


@pytest.mark.asyncio
async def test_a_truncated_agent_list_is_unknown_not_a_partial_answer() -> None:
    wazuh = FakeWazuh([agent("002", "stray", "10.0.0.77")], truncated=True)
    snapshot = await make(wazuh=wazuh).snapshot()
    assert states(snapshot)["wazuh"] == "unknown"
    assert "stray" not in {i.name.value for i in snapshot.items}


@pytest.mark.asyncio
async def test_a_failing_agent_key_read_makes_wazuh_unknown_and_joins_nothing() -> None:
    netbox = FakeNetbox([asset("2", "web-1")], agent_keys=RuntimeError("boom"))
    snapshot = await make(netbox=netbox).snapshot()
    assert snapshot.state == "ok"
    assert states(snapshot)["wazuh"] == "unknown"
    assert {i.source for i in snapshot.items} <= {"netbox", "discovered"}
    assert "stray" not in {i.name.value for i in snapshot.items}


@pytest.mark.asyncio
async def test_agents_are_asked_for_the_last_day_with_a_bound() -> None:
    wazuh = FakeWazuh([])
    await make(wazuh=wazuh).snapshot()
    ((start, end, limit),) = wazuh.calls
    assert end == NOW and start == NOW - timedelta(hours=24)
    assert limit == svc.AGENT_LIMIT


@pytest.mark.asyncio
async def test_a_source_that_hangs_is_unknown_after_its_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(svc, "SOURCE_BUDGET_SECONDS", 0.05)

    class Hanging(FakeLibrenms):
        async def devices(self) -> Any:
            await asyncio.sleep(5)

    snapshot = await make(librenms=Hanging([])).snapshot()
    assert states(snapshot)["librenms"] == "unknown"
    assert snapshot.state == "ok"


@pytest.mark.asyncio
async def test_a_snapshot_is_cached_for_its_ttl_and_then_read_again() -> None:
    netbox = FakeNetbox([asset("1", "a")])
    service = make(netbox=netbox, librenms=None, wazuh=None, cache=TtlCache(60.0))
    first = await service.snapshot()
    second = await service.snapshot()
    assert first is second
    assert netbox.calls.count("inventory_assets") == 1


@pytest.mark.asyncio
async def test_concurrent_requests_share_one_read() -> None:
    netbox = FakeNetbox([asset("1", "a")])
    service = make(netbox=netbox, librenms=None, wazuh=None, cache=TtlCache(60.0))
    await asyncio.gather(*(service.snapshot() for _ in range(5)))
    assert netbox.calls.count("inventory_assets") == 1


@pytest.mark.asyncio
async def test_the_error_of_a_source_is_not_leaked_into_the_snapshot() -> None:
    secret = "token=SECRET-VALUE"
    snapshot = await make(librenms=FakeLibrenms(RuntimeError(secret))).snapshot()
    assert secret not in repr(snapshot)
    assert all(secret not in item.model_dump_json() for item in snapshot.items)


# --- filters, paging, detail ------------------------------------------------------------------------------


async def items() -> list[Any]:
    return list((await make().snapshot()).items)


@pytest.mark.asyncio
async def test_filter_by_class() -> None:
    result = svc.filter_items(await items(), InventoryFilters(asset_class="server"))
    assert [i.name.value for i in result] == ["web-1"]


@pytest.mark.asyncio
async def test_filter_unknown_assets_by_class_and_known_flag() -> None:
    all_items = await items()
    unknown = svc.filter_items(all_items, InventoryFilters(known=False))
    assert {i.name.value for i in unknown} == {"printer-x", "stray"}
    assert {
        i.name.value
        for i in svc.filter_items(all_items, InventoryFilters(asset_class="unknown-asset"))
    } == {
        "printer-x",
        "stray",
    }
    assert {i.name.value for i in svc.filter_items(all_items, InventoryFilters(known=True))} == {
        "core-sw-1",
        "web-1",
        "ap-1",
    }


@pytest.mark.asyncio
async def test_filter_by_site_source_and_observed_status() -> None:
    all_items = await items()
    assert [i.name.value for i in svc.filter_items(all_items, InventoryFilters(site="DC"))] == [
        "web-1"
    ]
    assert {
        i.name.value for i in svc.filter_items(all_items, InventoryFilters(source="netbox"))
    } == {"ap-1"}
    assert {i.name.value for i in svc.filter_items(all_items, InventoryFilters(source="both"))} == {
        "core-sw-1",
        "web-1",
    }
    assert [
        i.name.value for i in svc.filter_items(all_items, InventoryFilters(status="offline"))
    ] == ["printer-x"]


@pytest.mark.asyncio
async def test_filter_by_text_matches_name_address_and_mac_case_insensitively() -> None:
    all_items = await items()
    by_name = svc.filter_items(all_items, InventoryFilters(q="CORE"))
    by_ip = svc.filter_items(all_items, InventoryFilters(q="10.0.5."))
    by_mac = svc.filter_items(all_items, InventoryFilters(q="AA:BB:CC"))
    assert [i.name.value for i in by_name] == ["core-sw-1"]
    assert [i.name.value for i in by_ip] == ["printer-x"]
    assert [i.name.value for i in by_mac] == ["core-sw-1"]


@pytest.mark.asyncio
async def test_filters_combine_and_can_match_nothing() -> None:
    all_items = await items()
    assert (
        svc.filter_items(all_items, InventoryFilters(known=True, asset_class="server", site="HQ"))
        == []
    )
    assert svc.filter_items(all_items, InventoryFilters(q="no-such-thing")) == []


@pytest.mark.asyncio
async def test_a_hostile_search_string_is_just_text() -> None:
    assert svc.filter_items(await items(), InventoryFilters(q="' OR 1=1 --<script>")) == []


@pytest.mark.asyncio
async def test_items_are_sorted_by_name_then_id_and_paged() -> None:
    all_items = await items()
    ordered = svc.sort_items(all_items)
    assert [i.name.value for i in ordered] == sorted(
        (i.name.value or "" for i in ordered), key=str.casefold
    )
    page = svc.page_items(ordered, page=2, page_size=2)
    assert [i.id for i in page] == [i.id for i in ordered[2:4]]
    assert svc.page_items(ordered, page=99, page_size=2) == []


@pytest.mark.asyncio
async def test_summary_counts_add_up() -> None:
    summary = svc.summarise(await items())
    assert summary.total == summary.known + summary.unknown
    assert sum(r.count for r in summary.by_class) == summary.total
    assert {r.source: r.count for r in summary.by_source} == {
        "both": 2,
        "netbox": 1,
        "discovered": 2,
    }


@pytest.mark.asyncio
async def test_find_returns_the_item_or_none() -> None:
    all_items = await items()
    assert svc.find_item(all_items, all_items[0].id) == all_items[0]
    assert svc.find_item(all_items, "device-00000000-0000-0000-0000-000000000000") is None


def test_the_ttl_cache_expires_and_never_serves_across_event_loops() -> None:
    clock = [0.0]
    cache: TtlCache[int] = TtlCache(10.0, clock=lambda: clock[0])
    loads = []

    async def load() -> int:
        loads.append(1)
        return len(loads)

    async def use() -> list[int]:
        a = await cache.get(load)
        clock[0] = 5.0
        b = await cache.get(load)
        clock[0] = 11.0
        c = await cache.get(load)
        return [a, b, c]

    assert asyncio.run(use()) == [1, 1, 2]
    assert asyncio.run(cache.get(load)) in (2, 3)  # a new event loop must not fail on a stale lock
