"""NetBox read-only reads behind inventory, IPAM and unknown-device comparison (Step 8a/8b/8c).

Hermetic: a mock transport only. The response shapes follow NetBox 3.x/4.x REST and are not verified
against a live NetBox in this build (stated in docs/12-implementation/INVENTORY-IPAM.md). Every read is
a GET, bounded (500 rows a page, at most 10 pages), same-origin when it paginates, and a failure is
typed: never an empty success.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest

from netsight_api.adapters.netbox import (
    AdapterError,
    AdapterStatus,
    NetboxClient,
    canonical_device_id,
)

Handler = Callable[[httpx.Request], httpx.Response]
HOSTILE = "<script>alert(1)</script>" + "x" * 400


def client_for(handler: Handler) -> NetboxClient:
    return NetboxClient(
        base_url="https://netbox.test",
        token="test-token",
        _transport=httpx.MockTransport(handler),
    )


def page(rows: list[dict[str, Any]], next_url: str | None = None) -> httpx.Response:
    return httpx.Response(200, json={"count": len(rows), "next": next_url, "results": rows})


def asset_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": 42,
        "name": "core-sw-1",
        "display": "core-sw-1",
        "role": {"id": 3, "name": "Core switch", "slug": "core-switch"},
        "device_type": {"id": 9, "model": "C9300-48P", "slug": "c9300-48p", "display": "C9300"},
        "site": {"id": 1, "name": "HQ", "slug": "hq"},
        "status": {"value": "active", "label": "Active"},
        "primary_ip4": {"address": "10.0.0.2/24"},
        "last_updated": "2026-10-01T10:00:00Z",
    }
    row.update(overrides)
    return row


# --- devices as inventory assets --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_assets_keep_the_role_and_type_the_class_map_needs() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return page([asset_row()])

    collection = await client_for(handler).inventory_assets()
    (asset,) = collection.items
    assert seen[0].method == "GET"
    assert seen[0].url.path == "/api/dcim/devices/"
    assert seen[0].url.params["limit"] == "500"
    assert seen[0].headers["Authorization"] == "Token test-token"
    assert asset.device.id == canonical_device_id("42")
    assert asset.device.name == "core-sw-1"
    assert asset.device.site_id == "HQ"
    assert asset.device.ip_addresses == ["10.0.0.2"]
    assert (asset.role_slug, asset.role_name) == ("core-switch", "Core switch")
    assert (asset.type_slug, asset.type_model) == ("c9300-48p", "C9300-48P")
    assert asset.status == "active"
    assert collection.skipped == 0


@pytest.mark.asyncio
async def test_the_netbox_3_device_role_key_is_read_when_role_is_absent() -> None:
    row = asset_row()
    row.pop("role")
    row["device_role"] = {"name": "Access point", "slug": "access-point"}
    collection = await client_for(lambda r: page([row])).inventory_assets()
    assert collection.items[0].role_slug == "access-point"


@pytest.mark.asyncio
async def test_a_device_without_role_or_type_is_still_listed_with_nothing_invented() -> None:
    row = asset_row(role=None, device_type=None, status=None)
    collection = await client_for(lambda r: page([row])).inventory_assets()
    asset = collection.items[0]
    assert (asset.role_slug, asset.role_name, asset.type_slug, asset.type_model) == (None,) * 4
    assert asset.status is None


@pytest.mark.asyncio
async def test_hostile_names_are_bounded_text() -> None:
    row = asset_row(
        name=HOSTILE[:100],
        role={"name": HOSTILE[:100], "slug": "core-switch"},
        device_type={"model": HOSTILE, "slug": "x"},
        site={"name": HOSTILE[:100]},
    )
    asset = (await client_for(lambda r: page([row])).inventory_assets()).items[0]
    assert asset.role_name == HOSTILE[:100]
    assert asset.type_model is not None and len(asset.type_model) == 128


@pytest.mark.asyncio
async def test_pagination_follows_same_origin_next_links_only() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.params.get("offset") == "500":
            return page([asset_row(id=2, name="b")])
        return page(
            [asset_row(id=1, name="a")],
            "https://netbox.test/api/dcim/devices/?limit=500&offset=500",
        )

    collection = await client_for(handler).inventory_assets()
    assert [a.device.name for a in collection.items] == ["a", "b"]
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_a_foreign_next_link_is_refused() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return page([asset_row()], "https://evil.test/api/dcim/devices/?offset=500")

    with pytest.raises(AdapterError) as excinfo:
        await client_for(handler).inventory_assets()
    assert excinfo.value.status is AdapterStatus.UNAVAILABLE


@pytest.mark.asyncio
async def test_runaway_pagination_is_a_failure_not_a_partial_list() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return page([asset_row()], "https://netbox.test/api/dcim/devices/?limit=500&offset=500")

    with pytest.raises(AdapterError) as excinfo:
        await client_for(handler).inventory_assets()
    assert excinfo.value.status is AdapterStatus.UNAVAILABLE


@pytest.mark.asyncio
async def test_one_malformed_device_is_skipped_and_counted() -> None:
    rows = [asset_row(id=1), {"id": 2, "name": ""}, asset_row(id=3, name="c")]
    collection = await client_for(lambda r: page(rows)).inventory_assets()
    assert [a.device.name for a in collection.items] == ["core-sw-1", "c"]
    assert collection.skipped == 1


@pytest.mark.asyncio
async def test_mostly_malformed_devices_fail_the_read() -> None:
    rows = [{"id": 1}, {"id": 2}, asset_row(id=3)]
    with pytest.raises(AdapterError) as excinfo:
        await client_for(lambda r: page(rows)).inventory_assets()
    assert excinfo.value.status is AdapterStatus.INVALID_SOURCE_DATA


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "status"),
    [
        (httpx.Response(401), AdapterStatus.FORBIDDEN),
        (httpx.Response(503), AdapterStatus.UNAVAILABLE),
        (httpx.Response(200, content=b"<html>"), AdapterStatus.INVALID_SOURCE_DATA),
        (httpx.Response(200, json={"results": "no"}), AdapterStatus.INVALID_SOURCE_DATA),
    ],
)
@pytest.mark.parametrize(
    "method", ["inventory_assets", "prefixes", "vlans", "ip_addresses", "reserved_ranges"]
)
async def test_failures_are_typed_and_never_an_empty_success(
    method: str, response: httpx.Response, status: AdapterStatus
) -> None:
    with pytest.raises(AdapterError) as excinfo:
        await getattr(client_for(lambda r: response), method)()
    assert excinfo.value.status is status


# --- IPAM -----------------------------------------------------------------------------------------------


def prefix_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": 7,
        "prefix": "10.0.0.0/24",
        "status": {"value": "active", "label": "Active"},
        "site": {"name": "HQ"},
        "vrf": None,
        "role": {"name": "Staff"},
        "vlan": {"id": 11, "vid": 20, "name": "staff"},
        "description": "Staff LAN",
        "is_pool": False,
        "mark_utilized": False,
    }
    row.update(overrides)
    return row


@pytest.mark.asyncio
async def test_prefixes_are_mapped_with_their_vlan_site_and_vrf() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return page(
            [
                prefix_row(),
                prefix_row(id=8, prefix="2001:db8::/64", vrf={"id": 4, "name": "red"}, vlan=None),
            ]
        )

    collection = await client_for(handler).prefixes()
    assert seen[0].url.path == "/api/ipam/prefixes/"
    first, second = collection.items
    assert (first.prefix, first.version, first.vrf_id) == ("10.0.0.0/24", 4, None)
    assert (first.site, first.role, first.status) == ("HQ", "Staff", "active")
    assert (first.vlan_native_id, first.vlan_vid, first.vlan_name) == ("11", 20, "staff")
    assert (second.prefix, second.version, second.vrf_id, second.vrf_name) == (
        "2001:db8::/64",
        6,
        "4",
        "red",
    )
    assert second.vlan_vid is None
    assert first.is_pool is False and first.mark_utilized is False


@pytest.mark.asyncio
async def test_a_prefix_is_stored_in_canonical_network_form() -> None:
    collection = await client_for(lambda r: page([prefix_row(prefix="10.0.0.5/24")])).prefixes()
    assert collection.items[0].prefix == "10.0.0.0/24"


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["", "not-a-prefix", "10.0.0.0/33", None, 5, "10.0.0.0"])
async def test_a_bad_prefix_is_skipped_and_counted(bad: Any) -> None:
    rows = [prefix_row(), prefix_row(id=9, prefix=bad), prefix_row(id=10, prefix="10.1.0.0/16")]
    collection = await client_for(lambda r: page(rows)).prefixes()
    assert [p.prefix for p in collection.items] == ["10.0.0.0/24", "10.1.0.0/16"]
    assert collection.skipped == 1


def vlan_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": 11,
        "vid": 20,
        "name": "staff",
        "status": {"value": "active"},
        "site": {"name": "HQ"},
        "group": {"name": "Campus"},
        "description": "Staff",
    }
    row.update(overrides)
    return row


@pytest.mark.asyncio
async def test_vlans_are_mapped_and_only_vids_1_to_4094_count() -> None:
    rows = [
        vlan_row(),
        vlan_row(id=12, vid=0),
        vlan_row(id=13, vid=4095),
        vlan_row(id=14, vid="x"),
        vlan_row(id=15, vid=4094, name="last"),
        vlan_row(id=16, vid=1, name="first"),
        vlan_row(id=17, vid=30, name="guest"),
    ]
    collection = await client_for(lambda r: page(rows)).vlans()
    assert [v.vid for v in collection.items] == [20, 4094, 1, 30]
    assert collection.skipped == 3
    first = collection.items[0]
    assert (first.name, first.status, first.site, first.group) == (
        "staff",
        "active",
        "HQ",
        "Campus",
    )


def address_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": 100,
        "address": "10.0.0.15/24",
        "status": {"value": "active"},
        "vrf": None,
        "dns_name": "pc-15.example",
        "description": "Front desk",
        "assigned_object_type": "dcim.interface",
        "assigned_object": {"device": {"id": 5, "name": "pc-15"}},
    }
    row.update(overrides)
    return row


@pytest.mark.asyncio
async def test_addresses_keep_every_status_and_the_assignment_flag() -> None:
    rows = [
        address_row(),
        address_row(
            id=101,
            address="10.0.0.16/24",
            status={"value": "reserved"},
            assigned_object_type=None,
            assigned_object=None,
        ),
        address_row(id=102, address="2001:db8::5/64", status={"value": "dhcp"}),
    ]
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return page(rows)

    collection = await client_for(handler).ip_addresses()
    assert seen[0].url.path == "/api/ipam/ip-addresses/"
    a, b, c = collection.items
    assert (a.address, a.version, a.status, a.assigned) == ("10.0.0.15", 4, "active", True)
    assert (b.address, b.status, b.assigned) == ("10.0.0.16", "reserved", False)
    assert (c.address, c.version, c.status) == ("2001:db8::5", 6, "dhcp")
    assert a.dns_name == "pc-15.example"


@pytest.mark.asyncio
async def test_a_bad_address_row_is_skipped_and_counted() -> None:
    rows = [
        address_row(),
        address_row(id=2, address="nope"),
        address_row(id=3, address="10.0.0.17/24"),
    ]
    collection = await client_for(lambda r: page(rows)).ip_addresses()
    assert len(collection.items) == 2 and collection.skipped == 1


def range_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": 21,
        "start_address": "10.0.0.100/24",
        "end_address": "10.0.0.150/24",
        "status": {"value": "reserved"},
        "vrf": None,
        "size": 51,
        "description": "Printers",
    }
    row.update(overrides)
    return row


@pytest.mark.asyncio
async def test_reserved_ranges_ask_netbox_for_reserved_and_keep_only_reserved() -> None:
    rows = [range_row(), range_row(id=22, status={"value": "active"})]
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return page(rows)

    collection = await client_for(handler).reserved_ranges()
    assert seen[0].url.path == "/api/ipam/ip-ranges/"
    assert seen[0].url.params["status"] == "reserved"
    (only,) = collection.items
    assert (only.start, only.end, only.size, only.version) == ("10.0.0.100", "10.0.0.150", 51, 4)


@pytest.mark.asyncio
async def test_a_range_whose_size_is_missing_is_computed_and_a_reversed_range_is_skipped() -> None:
    rows = [
        range_row(size=None),
        range_row(id=23, start_address="10.0.0.9/24", end_address="10.0.0.1/24"),
        range_row(id=24, start_address="10.0.0.1/24", end_address="2001:db8::1/64"),
        range_row(id=25, size=51),
        range_row(id=26, start_address="10.0.1.1/24", end_address="10.0.1.1/24", size=None),
    ]
    collection = await client_for(lambda r: page(rows)).reserved_ranges()
    assert [r.size for r in collection.items] == [51, 51, 1]
    assert collection.skipped == 2


# --- MAC comparison ------------------------------------------------------------------------------------


def interface_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": 900,
        "name": "eth0",
        "mac_address": "AA:BB:CC:00:11:22",
        "device": {"id": 5, "name": "pc-15"},
    }
    row.update(overrides)
    return row


@pytest.mark.asyncio
async def test_a_mac_lookup_is_one_bounded_get_with_the_canonical_address() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return page([interface_row()])

    lookup = await client_for(handler).interfaces_by_mac("aa:bb:cc:00:11:22")
    assert len(seen) == 1 and seen[0].method == "GET"
    assert seen[0].url.path == "/api/dcim/interfaces/"
    assert seen[0].url.params["mac_address"] == "aa:bb:cc:00:11:22"
    assert int(seen[0].url.params["limit"]) <= 50
    (match,) = lookup.matches
    assert (match.device_native_id, match.device_name, match.interface_name) == (
        "5",
        "pc-15",
        "eth0",
    )


@pytest.mark.asyncio
async def test_no_interface_with_that_mac_is_an_empty_success_not_a_failure() -> None:
    lookup = await client_for(lambda r: page([])).interfaces_by_mac("aa:bb:cc:00:11:22")
    assert lookup.matches == ()


@pytest.mark.asyncio
async def test_a_netbox_that_ignores_the_filter_cannot_widen_what_is_trusted() -> None:
    rows = [interface_row(mac_address="de:ad:be:ef:00:01", id=1), interface_row(id=2)]
    lookup = await client_for(lambda r: page(rows)).interfaces_by_mac("aa:bb:cc:00:11:22")
    assert [m.device_native_id for m in lookup.matches] == ["5"]


@pytest.mark.asyncio
async def test_the_netbox_4_primary_mac_object_and_the_mac_list_are_read() -> None:
    primary = interface_row(
        mac_address=None, primary_mac_address={"mac_address": "aa:bb:cc:00:11:22"}
    )
    listed = interface_row(
        id=2,
        mac_address=None,
        mac_addresses=[{"mac_address": "AA-BB-CC-00-11-22"}],
        device={"id": 6, "name": "pc-16"},
    )
    lookup = await client_for(lambda r: page([primary, listed])).interfaces_by_mac(
        "aa:bb:cc:00:11:22"
    )
    assert [m.device_native_id for m in lookup.matches] == ["5", "6"]


@pytest.mark.asyncio
async def test_an_interface_of_no_device_is_not_a_match() -> None:
    lookup = await client_for(lambda r: page([interface_row(device=None)])).interfaces_by_mac(
        "aa:bb:cc:00:11:22"
    )
    assert lookup.matches == ()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad",
    [
        "",
        "aa:bb:cc",
        "aa:bb:cc:00:11:2z",
        "aa:bb:cc:00:11:22&limit=100000",
        "../etc",
        "AA:BB:CC:00:11:22",
        "aabbcc001122",
    ],
)
async def test_a_non_canonical_mac_never_reaches_the_url(bad: str) -> None:
    called: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        called.append(request)
        return page([])

    with pytest.raises(ValueError):
        await client_for(handler).interfaces_by_mac(bad)
    assert called == []


@pytest.mark.asyncio
async def test_a_mac_lookup_failure_is_typed() -> None:
    with pytest.raises(AdapterError) as excinfo:
        await client_for(lambda r: httpx.Response(500)).interfaces_by_mac("aa:bb:cc:00:11:22")
    assert excinfo.value.status is AdapterStatus.UNAVAILABLE
