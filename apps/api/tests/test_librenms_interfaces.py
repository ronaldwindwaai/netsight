"""Contract tests for the LibreNMS interface adapter (NS-022)."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from netsight_api.adapters.librenms import (
    AdapterError,
    AdapterStatus,
    DeviceNotFoundError,
    LibrenmsClient,
    canonical_device_id,
    canonical_interface_id,
)

PORTS_PAYLOAD: dict[str, Any] = {
    "status": "ok",
    "count": 5,
    "ports": [
        {
            "port_id": 1,
            "device_id": 7,
            "ifIndex": 1,
            "ifName": "lo",
            "ifDescr": "loopback",
            "ifAlias": "",
            "ifAdminStatus": "up",
            "ifOperStatus": "up",
            "ifType": "softwareLoopback",
            "ifSpeed": 0,
            "ifHighSpeed": 0,
        },
        {
            "port_id": 2,
            "device_id": 7,
            "ifIndex": 24,
            "ifName": "GigabitEthernet0/1",
            "ifDescr": "Uplink to core",
            "ifAlias": "uplink-core",
            "ifAdminStatus": "up",
            "ifOperStatus": "up",
            "ifType": "ethernetCsmacd",
            "ifSpeed": 1000000000,
        },
        {
            "port_id": 3,
            "device_id": 7,
            "ifIndex": 25,
            "ifName": "Gi0/2",
            "ifDescr": "Spare",
            "ifAlias": "",
            "ifAdminStatus": "down",
            "ifOperStatus": "down",
            "ifType": "ethernetCsmacd",
            "ifHighSpeed": 1000,
        },
        {
            "port_id": 4,
            "device_id": 7,
            "ifIndex": 26,
            "ifName": "Gi0/3",
            "ifDescr": "",
            "ifAlias": "",
            "ifAdminStatus": "up",
            "ifOperStatus": "lowerLayerDown",
            "ifType": "ethernetCsmacd",
        },
        {
            "port_id": 5,
            "device_id": 7,
            "ifIndex": 27,
            "ifName": "Gi0/4",
            "ifDescr": "Monitoring",
            "ifAlias": "",
            "ifAdminStatus": "up",
            "ifOperStatus": "weirdVendorState",
            "ifType": "ethernetCsmacd",
        },
    ],
}


def _client(handler: Any) -> LibrenmsClient:
    return LibrenmsClient(
        base_url="https://librenms.test",
        token="adapter-secret",
        _transport=httpx.MockTransport(handler),
    )


def _ports(payload: dict[str, Any]) -> LibrenmsClient:
    return _client(lambda request: httpx.Response(200, json=payload))


def _run(coro: Any) -> Any:
    import anyio

    return anyio.run(lambda: coro)


def test_interface_ids_are_stable_and_device_scoped() -> None:
    first = canonical_interface_id("7", "24")
    assert first == canonical_interface_id("7", "24")
    # The same port number on another device must not collide.
    assert first != canonical_interface_id("8", "24")
    assert first.startswith("interface-")
    assert len(first) == len("interface-") + 36


def test_interfaces_are_mapped_to_canonical_contract() -> None:
    collection = _run(_ports(PORTS_PAYLOAD).interfaces("7"))

    assert collection.observed_at is not None
    assert len(collection.items) == 5

    loopback = collection.items[0]
    assert loopback.device_id == canonical_device_id("7")
    assert loopback.name == "lo"
    assert loopback.admin_status == "up"
    assert loopback.oper_status == "up"
    assert loopback.status == "healthy"
    assert loopback.source_aliases[0].source == "librenms"
    assert loopback.freshness.source == "librenms"


def test_speed_prefers_bits_per_second_over_megabits() -> None:
    collection = _run(_ports(PORTS_PAYLOAD).interfaces("7"))

    # ifSpeed is bits/s and wins over the absent ifHighSpeed.
    assert collection.items[1].speed_bps == 1_000_000_000
    # ifHighSpeed is Mb/s and is scaled.
    assert collection.items[2].speed_bps == 1_000_000_000


def test_zero_speed_is_unknown_not_zero() -> None:
    collection = _run(_ports(PORTS_PAYLOAD).interfaces("7"))
    assert collection.items[0].speed_bps is None


def test_admin_down_is_maintenance_not_offline() -> None:
    """An operator-disabled interface is not an incident."""
    collection = _run(_ports(PORTS_PAYLOAD).interfaces("7"))
    spare = collection.items[2]
    assert spare.admin_status == "down"
    assert spare.status == "maintenance"


def test_oper_states_map_to_health() -> None:
    collection = _run(_ports(PORTS_PAYLOAD).interfaces("7"))

    degraded = collection.items[3]
    assert degraded.oper_status == "lowerLayerDown"
    assert degraded.status == "degraded"

    # An unrecognised source state becomes unknown, never healthy.
    unknown = collection.items[4]
    assert unknown.oper_status == "unknown"
    assert unknown.status == "unknown"


def test_missing_interface_name_is_invalid_source_data() -> None:
    payload = {"status": "ok", "ports": [{"port_id": 1, "device_id": 7}]}
    with pytest.raises(AdapterError) as exc:
        _run(_ports(payload).interfaces("7"))
    assert exc.value.status is AdapterStatus.INVALID_SOURCE_DATA


def test_missing_port_id_is_invalid_source_data() -> None:
    payload = {"status": "ok", "ports": [{"ifName": "Gi0/1", "device_id": 7}]}
    with pytest.raises(AdapterError) as exc:
        _run(_ports(payload).interfaces("7"))
    assert exc.value.status is AdapterStatus.INVALID_SOURCE_DATA


def test_non_list_ports_is_rejected() -> None:
    with pytest.raises(AdapterError) as exc:
        _run(_ports({"status": "ok", "ports": "nope"}).interfaces("7"))
    assert exc.value.status is AdapterStatus.INVALID_SOURCE_DATA


def test_non_row_port_is_rejected() -> None:
    with pytest.raises(AdapterError) as exc:
        _run(_ports({"status": "ok", "ports": ["nope"]}).interfaces("7"))
    assert exc.value.status is AdapterStatus.INVALID_SOURCE_DATA


def test_bad_source_status_is_rejected() -> None:
    with pytest.raises(AdapterError) as exc:
        _run(_ports({"status": "error", "ports": []}).interfaces("7"))
    assert exc.value.status is AdapterStatus.INVALID_SOURCE_DATA


def test_empty_inventory_is_valid() -> None:
    collection = _run(_ports({"status": "ok", "ports": []}).interfaces("7"))
    assert collection.items == ()


def test_device_native_id_cannot_escape_the_ports_path() -> None:
    """A hostile native identifier must never steer the request elsewhere."""
    for hostile in (
        "../admin",
        "../../devices",
        "7/../../alerts",
        "7\\admin",
        "..",
        ".",
        ".hidden",
    ):
        with pytest.raises(AdapterError) as exc:
            _run(
                _client(
                    lambda request: httpx.Response(200, json={"status": "ok", "ports": []})
                ).interfaces(hostile)
            )
        assert exc.value.status is AdapterStatus.INVALID_SOURCE_DATA, hostile


def test_interface_native_ids_are_distinct_within_a_device() -> None:
    """Regression: port_id must key interfaces, not the parent device_id."""
    collection = _run(_ports(PORTS_PAYLOAD).interfaces("7"))

    native_ids = [item.source_aliases[0].native_id for item in collection.items]
    assert native_ids == ["1", "2", "3", "4", "5"]

    canonical_ids = [item.id for item in collection.items]
    assert len(set(canonical_ids)) == len(canonical_ids)


def test_device_native_id_is_url_encoded() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.raw_path.decode("ascii"))
        return httpx.Response(200, json={"status": "ok", "ports": []})

    _run(_client(handler).interfaces("device 7"))
    assert seen == ["/api/v0/devices/device%207/ports"]


def test_source_failure_maps_to_typed_status() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={})

    with pytest.raises(AdapterError) as exc:
        _run(_client(handler).interfaces("7"))
    # A 404 on the ports endpoint is an unexpected source response, not a
    # silent empty result.
    assert exc.value.status is AdapterStatus.INVALID_SOURCE_DATA


def test_device_not_found_still_raised_for_unknown_device() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "ok", "devices": []})

    with pytest.raises(DeviceNotFoundError):
        _run(_client(handler).device(canonical_device_id("999")))
