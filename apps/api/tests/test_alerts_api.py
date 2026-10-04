from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from netsight_api.adapters.librenms import LibrenmsClient, canonical_device_id
from netsight_api.auth.deps import get_current_identity
from netsight_api.main import app, get_client
from netsight_api.rbac import Identity

Handler = Callable[[httpx.Request], httpx.Response]


@pytest.fixture(autouse=True)
def _clean_app_state() -> Iterator[None]:
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def _authorise_alert_reader() -> None:
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "operator",
        frozenset({"network_engineer"}),
    )


def _override_source(handler: Handler, *, token: str = "adapter-secret") -> None:
    app.dependency_overrides[get_client] = lambda: LibrenmsClient(
        base_url="https://librenms.test",
        token=token,
        _transport=httpx.MockTransport(handler),
    )


def _alert(index: int) -> dict[str, Any]:
    return {
        "id": index,
        "device_id": index,
        "severity": "critical" if index == 1 else "warning",
        "state": 0,
        "name": f"Alert {index}",
        "timestamp": f"2026-10-04T10:0{index}:00Z",
    }


def test_alerts_require_authentication_without_calling_source() -> None:
    def must_not_call_source(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"source called without authentication: {request.url}")

    _override_source(must_not_call_source)

    response = TestClient(app).get("/api/v1/alerts")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"


def test_alerts_deny_identity_without_permission() -> None:
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "limited-user",
        frozenset({"unknown-role"}),
    )

    response = TestClient(app).get("/api/v1/alerts")

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_alerts_return_typed_bounded_page_with_freshness() -> None:
    _authorise_alert_reader()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v0/alerts"
        return httpx.Response(200, json={"alerts": [_alert(index) for index in range(1, 4)]})

    _override_source(handler)

    response = TestClient(app).get("/api/v1/alerts?page=2&page_size=1")

    assert response.status_code == 200
    body = response.json()
    assert body["page"] == 2
    assert body["page_size"] == 1
    assert body["total"] == 3
    assert body["items"] == [
        {
            "id": "librenms:2",
            "severity": "high",
            "state": "open",
            "title": "Alert 2",
            "observed_at": "2026-10-04T10:02:00Z",
            "device_id": canonical_device_id("2"),
            "incident_id": None,
        }
    ]
    assert body["freshness"]["state"] == "fresh"
    assert body["freshness"]["source"] == "librenms"
    assert body["freshness"]["observed_at"] is not None


@pytest.mark.parametrize("query", ["page=0", "page_size=0", "page_size=101"])
def test_alert_pagination_validation_uses_error_envelope(query: str) -> None:
    _authorise_alert_reader()

    def must_not_call_source(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"source called for invalid query: {request.url}")

    _override_source(must_not_call_source)

    response = TestClient(app).get(
        f"/api/v1/alerts?{query}",
        headers={"X-Correlation-ID": "alert-pagination-error"},
    )

    assert response.status_code == 422
    assert response.json()["error"] == {
        "code": "VALIDATION_ERROR",
        "message": "Request validation failed",
        "correlation_id": "alert-pagination-error",
    }


def test_alert_source_failure_does_not_expose_service_token() -> None:
    _authorise_alert_reader()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    _override_source(handler, token="never-return-this-secret")

    response = TestClient(app).get("/api/v1/alerts")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "SOURCE_UNAVAILABLE"
    assert "never-return-this-secret" not in response.text


def test_openapi_exposes_typed_alert_collection() -> None:
    operation = app.openapi()["paths"]["/api/v1/alerts"]["get"]
    response_schema = operation["responses"]["200"]["content"]["application/json"][
        "schema"
    ]

    assert response_schema["$ref"].endswith("/AlertListResponse")
    assert {parameter["name"] for parameter in operation["parameters"]} == {
        "page",
        "page_size",
    }
