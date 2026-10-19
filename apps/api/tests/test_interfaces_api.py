"""Endpoint tests for /api/v1/devices/{device_id}/interfaces (NS-022)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from netsight_api.adapters.librenms import LibrenmsClient, canonical_device_id
from netsight_api.main import app, get_client, get_current_identity
from netsight_api.rbac import Identity

# Canonical identifiers are uuid5-derived, so the fixture must use the real one.
DEVICE_ID = canonical_device_id("1")

DEVICES: dict[str, Any] = {
    "status": "ok",
    "count": 1,
    "devices": [
        {"device_id": 1, "hostname": "core-sw-01.example.test", "status": 1, "type": "network"}
    ],
}

PORTS: dict[str, Any] = {
    "status": "ok",
    "count": 2,
    "ports": [
        {
            "port_id": 1,
            "ifIndex": 1,
            "ifName": "Gi0/1",
            "ifDescr": "Uplink",
            "ifAdminStatus": "up",
            "ifOperStatus": "up",
            "ifType": "ethernetCsmacd",
            "ifHighSpeed": 1000,
        },
        {
            "port_id": 2,
            "ifIndex": 2,
            "ifName": "Gi0/2",
            "ifDescr": "Spare",
            "ifAlias": "spare-port",
            "ifAdminStatus": "down",
            "ifOperStatus": "down",
        },
    ],
}


DEVICE_DETAIL: dict[str, Any] = {
    "status": "ok",
    "count": 1,
    "devices": [
        {"device_id": 1, "hostname": "core-sw-01.example.test", "status": 1, "type": "network"}
    ],
}

# The adapter resolves a device by listing the inventory, fetching the detail
# row, and only then reading its ports.
PATHS: dict[str, Any] = {
    "/api/v0/devices": DEVICES,
    "/api/v0/devices/1": DEVICE_DETAIL,
    "/api/v0/devices/1/ports": PORTS,
}


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in (
        "NETSIGHT_ENV",
        "NETSIGHT_ENABLE_DEV_IDENTITY",
        "LIBRENMS_BASE_URL",
        "LIBRENMS_TOKEN",
        "LIBRENMS_TIMEZONE",
    ):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def _enable_dev_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_ENV", "development")
    monkeypatch.setenv("NETSIGHT_ENABLE_DEV_IDENTITY", "true")


def _override(handler: Any) -> None:
    app.dependency_overrides[get_client] = lambda: LibrenmsClient(
        base_url="https://librenms.test",
        token="adapter-secret",
        _transport=httpx.MockTransport(handler),
    )


def _router(paths: dict[str, Any]) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = paths.get(request.url.path)
        if payload is None:
            return httpx.Response(404, json={})
        return httpx.Response(200, json=payload)

    return handler


def test_interfaces_fail_closed_without_session() -> None:
    response = TestClient(app).get(f"/api/v1/devices/{DEVICE_ID}/interfaces")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"


def test_interfaces_forbidden_without_device_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "limited", frozenset({"not_a_role"})
    )
    response = TestClient(app).get(f"/api/v1/devices/{DEVICE_ID}/interfaces")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_interfaces_require_a_configured_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "engineer", frozenset({"network_engineer"})
    )
    response = TestClient(app).get(f"/api/v1/devices/{DEVICE_ID}/interfaces")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "SOURCE_UNAVAILABLE"


def test_interfaces_return_canonical_records(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_dev_identity(monkeypatch)
    _override(_router(PATHS))

    response = TestClient(app).get(f"/api/v1/devices/{DEVICE_ID}/interfaces")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert body["freshness"]["source"] == "librenms"

    uplink = body["items"][0]
    assert uplink["name"] == "Gi0/1"
    assert uplink["device_id"] == DEVICE_ID
    assert uplink["admin_status"] == "up"
    assert uplink["oper_status"] == "up"
    assert uplink["status"] == "healthy"
    assert uplink["speed_bps"] == 1_000_000_000
    assert uplink["id"].startswith("interface-")

    spare = body["items"][1]
    assert spare["admin_status"] == "down"
    assert spare["status"] == "maintenance"
    assert spare["alias"] == "spare-port"

    # Identifiers must be unique across the device.
    assert len({item["id"] for item in body["items"]}) == 2


def test_interfaces_for_unknown_device_is_404(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_dev_identity(monkeypatch)
    _override(_router({"/api/v0/devices": {"status": "ok", "devices": []}}))

    response = TestClient(app).get(f"/api/v1/devices/{DEVICE_ID}/interfaces")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "DEVICE_NOT_FOUND"


def test_interfaces_source_outage_is_503(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_dev_identity(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v0/devices":
            return httpx.Response(200, json=DEVICES)
        if request.url.path == "/api/v0/devices/1":
            return httpx.Response(200, json=DEVICE_DETAIL)
        return httpx.Response(503, json={})

    _override(handler)
    response = TestClient(app).get(f"/api/v1/devices/{DEVICE_ID}/interfaces")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "SOURCE_UNAVAILABLE"


def test_interfaces_invalid_source_data_is_502(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_dev_identity(monkeypatch)
    _override(
        _router(
            {
                **PATHS,
                "/api/v0/devices/1/ports": {"status": "ok", "ports": [{"port_id": 1}]},
            }
        )
    )
    response = TestClient(app).get(f"/api/v1/devices/{DEVICE_ID}/interfaces")
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "SOURCE_INVALID_DATA"


def test_interfaces_empty_inventory_is_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_dev_identity(monkeypatch)
    _override(_router({**PATHS, "/api/v0/devices/1/ports": {"status": "ok", "ports": []}}))
    response = TestClient(app).get(f"/api/v1/devices/{DEVICE_ID}/interfaces")
    assert response.status_code == 200
    assert response.json() == {
        "items": [],
        "total": 0,
        "freshness": {
            "state": "fresh",
            "observed_at": response.json()["freshness"]["observed_at"],
            "source": "librenms",
        },
    }


def test_interfaces_never_disclose_the_source_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_dev_identity(monkeypatch)
    _override(_router({"/api/v0/devices": DEVICES, "/api/v0/devices/1": DEVICE_DETAIL}))
    response = TestClient(app).get(f"/api/v1/devices/{DEVICE_ID}/interfaces")
    assert "adapter-secret" not in response.text
    assert "librenms.test" not in response.text


def test_interfaces_respects_correlation_id(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_dev_identity(monkeypatch)
    _override(_router({**PATHS, "/api/v0/devices/1/ports": {"status": "ok", "ports": []}}))
    response = TestClient(app).get(
        f"/api/v1/devices/{DEVICE_ID}/interfaces",
        headers={"X-Correlation-ID": "interfaces-test-1"},
    )
    assert response.headers["X-Correlation-ID"] == "interfaces-test-1"
