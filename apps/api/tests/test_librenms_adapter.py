import json

import httpx
import pytest
from fastapi.testclient import TestClient

from netsight_api.adapters.librenms import LibrenmsClient
from netsight_api.contracts import validate
from netsight_api.main import app, get_client

DEVICES_PAYLOAD = {
    "devices": [
        {
            "device_id": 1,
            "hostname": "core-sw-01",
            "sysName": "core-sw-01",
            "status": 1,
            "ip": "10.0.0.1",
        },
        {
            "device_id": 2,
            "hostname": "edge-rt-02",
            "sysName": "edge-rt-02",
            "status": 0,
            "ip": "10.0.0.2",
        },
    ]
}

ALERTS_PAYLOAD = {
    "alerts": [
        {
            "id": 7,
            "device_id": 1,
            "severity": "critical",
            "state": 0,
            "name": "Link down on port 12",
            "timestamp": "2026-10-02T10:00:00Z",
        }
    ]
}


def _transport(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def _client_for(handler) -> LibrenmsClient:
    return LibrenmsClient(
        base_url="http://librenms.test", token="test", _transport=_transport(handler)
    )


@pytest.mark.asyncio
async def test_devices_map_to_canonical() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-Auth-Token"] == "test"
        return httpx.Response(200, json=DEVICES_PAYLOAD)

    rows = await _client_for(handler).devices()
    assert len(rows) == 2
    assert rows[1]["status"] == "offline"
    for row in rows:
        validate("device", row)


@pytest.mark.asyncio
async def test_alerts_map_to_canonical() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=ALERTS_PAYLOAD)

    rows = await _client_for(handler).alerts()
    assert rows[0]["severity"] == "critical"
    assert rows[0]["device_id"] == "librenms:1"
    validate("alert", rows[0])


@pytest.mark.asyncio
async def test_unavailable_source_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    with pytest.raises(Exception):
        await _client_for(handler).devices()


@pytest.mark.asyncio
async def test_health_ok_and_down() -> None:
    def ok(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "ok"})

    health = await _client_for(ok).health()
    assert health.reachable is True

    def down(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    health = await _client_for(down).health()
    assert health.reachable is False


def test_devices_endpoint_requires_authorisation() -> None:
    client = TestClient(app)
    response = client.get("/api/devices")
    assert response.status_code == 403


def test_devices_endpoint_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_DEV_MODE", "true")

    def handler(request: httpx.Request) -> httpx.Response:
        if "devices" in request.url.path:
            return httpx.Response(200, json=DEVICES_PAYLOAD)
        return httpx.Response(200, json={})

    app.dependency_overrides[get_client] = lambda: LibrenmsClient(
        base_url="http://librenms.test", token="t", _transport=_transport(handler)
    )
    try:
        response = TestClient(app).get("/api/devices")
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    body = response.json()
    assert len(body["items"]) == 2
    for row in body["items"]:
        validate("device", row)
