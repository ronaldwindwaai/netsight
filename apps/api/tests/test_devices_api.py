from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from netsight_api.adapters.librenms import LibrenmsClient, canonical_device_id
from netsight_api.errors import ApiError
from netsight_api.main import app, get_client, get_current_identity
from netsight_api.rbac import Identity

Handler = Callable[[httpx.Request], httpx.Response]

DEVICES_PAYLOAD: dict[str, Any] = {
    "status": "ok",
    "count": 3,
    "devices": [
        {
            "device_id": index,
            "hostname": f"device-{index}.example.test",
            "sysName": f"device-{index}",
            "status": 1 if index != 2 else 0,
            "ip": f"10.0.0.{index}",
            "type": "network",
        }
        for index in range(1, 4)
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


def _transport(handler: Handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def _client_for(handler: Handler, *, token: str = "adapter-secret") -> LibrenmsClient:
    return LibrenmsClient(
        base_url="https://librenms.test", token=token, _transport=_transport(handler)
    )


def _enable_dev_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_ENV", "development")
    monkeypatch.setenv("NETSIGHT_ENABLE_DEV_IDENTITY", "true")


def _override_source(handler: Handler, *, token: str = "adapter-secret") -> None:
    app.dependency_overrides[get_client] = lambda: _client_for(handler, token=token)


@pytest.mark.parametrize(
    "environment",
    [
        {},
        {"NETSIGHT_ENV": "development"},
        {"NETSIGHT_ENABLE_DEV_IDENTITY": "true"},
        {"NETSIGHT_ENV": "production", "NETSIGHT_ENABLE_DEV_IDENTITY": "true"},
    ],
)
def test_devices_fail_closed_without_both_development_controls(
    monkeypatch: pytest.MonkeyPatch, environment: dict[str, str]
) -> None:
    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    response = TestClient(app).get(
        "/api/v1/devices", headers={"X-Correlation-ID": "test-auth-negative"}
    )

    assert response.status_code == 401
    assert response.json() == {
        "error": {
            "code": "AUTHENTICATION_REQUIRED",
            "message": "Authentication is required",
            "correlation_id": "test-auth-negative",
        }
    }
    assert response.headers["X-Correlation-ID"] == "test-auth-negative"


def test_authenticated_identity_without_permission_is_forbidden() -> None:
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "limited-user", frozenset({"unknown-role"})
    )

    response = TestClient(app).get("/api/v1/devices")

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_source_health_is_protected() -> None:
    response = TestClient(app).get("/api/v1/sources/librenms/health")
    assert response.status_code == 401


def test_source_health_reports_adapter_state(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_dev_identity(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v0/system"
        return httpx.Response(200, json={"status": "ok"})

    _override_source(handler)
    response = TestClient(app).get("/api/v1/sources/librenms/health")

    assert response.status_code == 200
    assert response.json()["source"] == "librenms"
    assert response.json()["reachable"] is True
    assert response.json()["status"] == "success"


def test_device_list_uses_bounded_platform_pagination(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_dev_identity(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=DEVICES_PAYLOAD)

    _override_source(handler)
    response = TestClient(app).get("/api/v1/devices?page=2&page_size=1")

    assert response.status_code == 200
    body = response.json()
    assert body["page"] == 2
    assert body["page_size"] == 1
    assert body["total"] == 3
    assert [item["name"] for item in body["items"]] == ["device-2"]
    assert body["freshness"]["state"] == "fresh"
    assert body["freshness"]["source"] == "librenms"
    assert body["items"][0]["source_aliases"] == [
        {"source": "librenms", "native_id": "2"}
    ]


@pytest.mark.parametrize("query", ["page=0", "page_size=0", "page_size=101"])
def test_device_pagination_validation_uses_error_envelope(
    monkeypatch: pytest.MonkeyPatch, query: str
) -> None:
    _enable_dev_identity(monkeypatch)

    def must_not_call_source(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"source called for invalid query: {request.url}")

    _override_source(must_not_call_source)
    response = TestClient(app).get(
        f"/api/v1/devices?{query}", headers={"X-Correlation-ID": "pagination-error"}
    )

    assert response.status_code == 422
    assert response.json()["error"] == {
        "code": "VALIDATION_ERROR",
        "message": "Request validation failed",
        "correlation_id": "pagination-error",
    }


def test_device_detail_uses_get_device_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_dev_identity(monkeypatch)
    expected_id = canonical_device_id("1")
    requested_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        if request.url.path == "/api/v0/devices":
            return httpx.Response(200, json=DEVICES_PAYLOAD)
        if request.url.path == "/api/v0/devices/1":
            return httpx.Response(
                200,
                json={"status": "ok", "count": 1, "devices": [DEVICES_PAYLOAD["devices"][0]]},
            )
        return httpx.Response(404)

    _override_source(handler)
    response = TestClient(app).get(f"/api/v1/devices/{expected_id}")

    assert response.status_code == 200
    assert response.json()["item"]["id"] == expected_id
    assert requested_paths == ["/api/v0/devices", "/api/v0/devices/1"]


def test_device_detail_missing_canonical_id_is_404(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_dev_identity(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=DEVICES_PAYLOAD)

    _override_source(handler)
    response = TestClient(app).get(
        f"/api/v1/devices/{canonical_device_id('999')}",
        headers={"X-Correlation-ID": "missing-device"},
    )

    assert response.status_code == 404
    assert response.json()["error"] == {
        "code": "DEVICE_NOT_FOUND",
        "message": "Device was not found",
        "correlation_id": "missing-device",
    }


@pytest.mark.parametrize(
    ("upstream_response", "expected_status", "expected_code"),
    [
        (httpx.Response(503), 503, "SOURCE_UNAVAILABLE"),
        (
            httpx.Response(200, json={"status": "ok", "devices": "invalid"}),
            502,
            "SOURCE_INVALID_DATA",
        ),
    ],
)
def test_device_list_maps_source_errors_without_exposing_secret(
    monkeypatch: pytest.MonkeyPatch,
    upstream_response: httpx.Response,
    expected_status: int,
    expected_code: str,
) -> None:
    _enable_dev_identity(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return upstream_response

    _override_source(handler, token="never-return-this-secret")
    response = TestClient(app).get("/api/v1/devices")
    body = response.json()

    assert response.status_code == expected_status
    assert body["error"]["code"] == expected_code
    assert body["error"]["correlation_id"] == response.headers["X-Correlation-ID"]
    assert "never-return-this-secret" not in response.text


def test_unconfigured_source_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_dev_identity(monkeypatch)
    response = TestClient(app).get("/api/v1/devices")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "SOURCE_UNAVAILABLE"


def test_source_url_with_embedded_credentials_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_dev_identity(monkeypatch)
    monkeypatch.setenv("LIBRENMS_BASE_URL", "https://user:password@librenms.test")
    monkeypatch.setenv("LIBRENMS_TOKEN", "never-return-this-secret")

    response = TestClient(app).get("/api/v1/devices")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "SOURCE_UNAVAILABLE"
    assert "password" not in response.text
    assert "never-return-this-secret" not in response.text


def test_librenms_timezone_is_passed_to_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LIBRENMS_BASE_URL", "https://librenms.test")
    monkeypatch.setenv("LIBRENMS_TOKEN", "adapter-secret")
    monkeypatch.setenv("LIBRENMS_TIMEZONE", "Africa/Windhoek")

    client = get_client()

    assert client.source_timezone is not None
    assert client.source_timezone.key == "Africa/Windhoek"


def test_missing_librenms_timezone_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LIBRENMS_BASE_URL", "https://librenms.test")
    monkeypatch.setenv("LIBRENMS_TOKEN", "never-return-this-secret")

    with pytest.raises(ApiError) as exc_info:
        get_client()

    assert exc_info.value.code == "SOURCE_UNAVAILABLE"
    assert "never-return-this-secret" not in str(exc_info.value)


@pytest.mark.parametrize("timezone_name", ["Not/A-Timezone", "../UTC"])
def test_invalid_librenms_timezone_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    timezone_name: str,
) -> None:
    monkeypatch.setenv("LIBRENMS_BASE_URL", "https://librenms.test")
    monkeypatch.setenv("LIBRENMS_TOKEN", "never-return-this-secret")
    monkeypatch.setenv("LIBRENMS_TIMEZONE", timezone_name)

    with pytest.raises(ApiError) as exc_info:
        get_client()

    assert exc_info.value.code == "SOURCE_UNAVAILABLE"
    assert "never-return-this-secret" not in str(exc_info.value)
    assert timezone_name not in str(exc_info.value)


def test_invalid_correlation_id_is_not_reflected() -> None:
    response = TestClient(app).get(
        "/api/v1/devices", headers={"X-Correlation-ID": "bad id with spaces"}
    )
    correlation_id = response.headers["X-Correlation-ID"]
    assert correlation_id != "bad id with spaces"
    assert response.json()["error"]["correlation_id"] == correlation_id


def test_openapi_exposes_versioned_typed_device_routes() -> None:
    schema = app.openapi()
    assert "/api/v1/devices" in schema["paths"]
    assert "/api/v1/devices/{device_id}" in schema["paths"]
    assert "/api/v1/sources/librenms/health" in schema["paths"]
    list_operation = schema["paths"]["/api/v1/devices"]["get"]
    response_schema = list_operation["responses"]["200"]["content"]["application/json"][
        "schema"
    ]
    assert response_schema["$ref"].endswith("/DeviceListResponse")
