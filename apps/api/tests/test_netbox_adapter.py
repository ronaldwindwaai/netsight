from collections.abc import Callable
from typing import Any

import httpx
import pytest

from netsight_api.adapters.netbox import (
    AdapterError,
    AdapterStatus,
    DeviceNotFoundError,
    NetboxClient,
    canonical_device_id,
)
from netsight_api.contracts import validate

Handler = Callable[[httpx.Request], httpx.Response]

DEVICES_PAYLOAD: dict[str, Any] = {
    "count": 2,
    "next": None,
    "previous": None,
    "results": [
        {
            "id": 1,
            "name": "core-sw-01",
            "display": "core-sw-01",
            "device_type": {"display": "Juniper EX4300"},
            "role": {"display": "network switch"},
            "site": {"name": "dc1"},
            "status": {"value": "active", "label": "Active"},
            "primary_ip4": {"address": "10.0.0.1/32"},
        },
        {
            "id": "2",
            "name": "edge-rt-02",
            "display": "edge-rt-02",
            "device_type": {"display": "Cisco ISR"},
            "role": {"display": "router"},
            "site": {"name": "dc2"},
            "status": {"value": "offline", "label": "Offline"},
            "primary_ip4": {"address": "10.0.0.2/32"},
        },
    ],
}


def _transport(handler: Handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def _client_for(handler: Handler, *, token: str = "test-token") -> NetboxClient:
    return NetboxClient(
        base_url="https://netbox.test",
        token=token,
        _transport=_transport(handler),
    )


@pytest.mark.asyncio
async def test_devices_use_token_auth_and_map_to_canonical_contract() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Token test-token"
        assert request.url.path == "/api/dcim/devices/"
        return httpx.Response(200, json=DEVICES_PAYLOAD)

    client = _client_for(handler)
    collection = await client.devices()
    assert len(collection.items) == 2
    for device in collection.items:
        validate("device", device.model_dump(mode="json"))
    first = collection.items[0]
    assert first.id.startswith("device-")
    assert first.source_aliases[0].source == "netbox"
    assert first.status == "healthy"
    assert first.ip_addresses == ["10.0.0.1"]
    assert collection.items[1].status == "offline"


@pytest.mark.asyncio
async def test_health_maps_denied_to_forbidden() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"detail": "denied"})

    client = _client_for(handler)
    health = await client.health()
    assert health.status is AdapterStatus.FORBIDDEN
    assert health.detail == "forbidden"
    assert health.reachable is False


@pytest.mark.asyncio
async def test_health_maps_non_json_to_invalid_source_data() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not json")

    client = _client_for(handler)
    health = await client.health()
    assert health.status is AdapterStatus.INVALID_SOURCE_DATA
    assert health.detail == "invalid-source-data"


@pytest.mark.asyncio
async def test_device_not_found() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "not found"})

    client = _client_for(handler)
    with pytest.raises(DeviceNotFoundError):
        await client.get_device("999")


@pytest.mark.asyncio
async def test_device_by_canonical_id() -> None:
    native_id = "1"
    canonical = canonical_device_id(native_id)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/dcim/devices/":
            return httpx.Response(200, json=DEVICES_PAYLOAD)
        if request.url.path == "/api/dcim/devices/1/":
            return httpx.Response(200, json=DEVICES_PAYLOAD["results"][0])
        return httpx.Response(404)

    client = _client_for(handler)
    device = await client.device(canonical)
    assert device.id == canonical


@pytest.mark.asyncio
async def test_timeout_maps_to_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("slow", request=request)

    client = _client_for(handler)
    with pytest.raises(AdapterError) as exc_info:
        await client.devices()
    assert exc_info.value.status is AdapterStatus.UNAVAILABLE
