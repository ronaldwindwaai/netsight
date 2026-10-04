"""Tests for the /api/v1/overview aggregate endpoint."""

from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from netsight_api.adapters.librenms import LibrenmsClient
from netsight_api.main import app, get_client, get_current_identity
from netsight_api.rbac import Identity

Handler = Callable[[httpx.Request], httpx.Response]

DEVICES_PAYLOAD: dict[str, Any] = {
    "status": "ok",
    "count": 4,
    "devices": [
        {"device_id": 1, "hostname": "core-1.example.test", "sysName": "core-1", "status": 1},
        {"device_id": 2, "hostname": "core-2.example.test", "sysName": "core-2", "status": 1},
        {"device_id": 3, "hostname": "edge-1.example.test", "sysName": "edge-1", "status": 0},
        {
            "device_id": 4,
            "hostname": "unk-1.example.test",
            "sysName": "unk-1",
            "status": 2,
        },
    ],
}


@pytest.fixture(autouse=True)
def _clean_app_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
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


def _override_source(handler: Handler) -> None:
    app.dependency_overrides[get_client] = lambda: LibrenmsClient(
        base_url="https://librenms.test",
        token="adapter-secret",
        _transport=httpx.MockTransport(handler),
    )


def _devices_ok(request: httpx.Request) -> httpx.Response:
    assert request.url.path == "/api/v0/devices"
    return httpx.Response(200, json=DEVICES_PAYLOAD)


def test_overview_fails_closed_without_session() -> None:
    response = TestClient(app).get("/api/v1/overview")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"


def test_overview_forbidden_without_device_read_permission() -> None:
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "limited-user", frozenset({"unknown-role"})
    )

    response = TestClient(app).get("/api/v1/overview")

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_overview_reports_source_unavailable_when_not_configured() -> None:
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "network-engineer", frozenset({"network_engineer"})
    )

    response = TestClient(app).get("/api/v1/overview")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "SOURCE_UNAVAILABLE"


def test_overview_aggregates_health_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_dev_identity(monkeypatch)
    _override_source(_devices_ok)

    response = TestClient(app).get("/api/v1/overview")

    assert response.status_code == 200
    body = response.json()
    assert body["devices"]["total"] == 4
    counts = {entry["status"]: entry["count"] for entry in body["devices"]["by_status"]}
    assert counts["healthy"] == 2
    assert counts["offline"] == 1
    assert counts["unknown"] == 1
    assert body["devices"]["freshness"]["source"] == "librenms"
    assert body["sources"]["librenms"]["configured"] is True
    assert body["sources"]["librenms"]["status"] == "success"


def test_overview_reports_empty_inventory_as_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_dev_identity(monkeypatch)
    _override_source(lambda request: httpx.Response(200, json={"status": "ok", "devices": []}))

    response = TestClient(app).get("/api/v1/overview")

    assert response.status_code == 200
    assert response.json()["devices"]["total"] == 0


def test_overview_rejects_invalid_source_data(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_dev_identity(monkeypatch)
    _override_source(lambda request: httpx.Response(200, json={"status": "ok", "devices": [{}]}))

    response = TestClient(app).get("/api/v1/overview")

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "SOURCE_INVALID_DATA"


def test_overview_maps_source_outage_to_503(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_dev_identity(monkeypatch)
    _override_source(lambda request: httpx.Response(503, json={"status": "error"}))

    response = TestClient(app).get("/api/v1/overview")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "SOURCE_UNAVAILABLE"