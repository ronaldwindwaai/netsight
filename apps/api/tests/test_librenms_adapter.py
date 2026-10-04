from collections.abc import Callable
from typing import Any
from zoneinfo import ZoneInfo

import httpx
import pytest

from netsight_api.adapters.librenms import (
    AdapterError,
    AdapterStatus,
    DeviceNotFoundError,
    LibrenmsClient,
    canonical_device_id,
)
from netsight_api.contracts import validate

Handler = Callable[[httpx.Request], httpx.Response]

DEVICES_PAYLOAD: dict[str, Any] = {
    "status": "ok",
    "count": 2,
    "devices": [
        {
            "device_id": 1,
            "hostname": "core-sw-01.example.test",
            "sysName": "core-sw-01",
            "status": 1,
            "ip": "10.0.0.1",
            "type": "network",
        },
        {
            "device_id": "2",
            "hostname": "edge-rt-02.example.test",
            "sysName": "edge-rt-02",
            "status": "0",
            "ip": "10.0.0.2",
            "type": "network",
        },
    ],
}

ALERTS_PAYLOAD: dict[str, Any] = {
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

_MISSING = object()


def _transport(handler: Handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def _client_for(
    handler: Handler,
    *,
    token: str = "test-token",
    source_timezone: ZoneInfo | None = None,
) -> LibrenmsClient:
    return LibrenmsClient(
        base_url="https://librenms.test",
        token=token,
        source_timezone=source_timezone,
        _transport=_transport(handler),
    )


@pytest.mark.asyncio
async def test_devices_use_bearer_auth_and_map_to_canonical_contract() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer test-token"
        assert "X-Auth-Token" not in request.headers
        return httpx.Response(200, json=DEVICES_PAYLOAD)

    result = await _client_for(handler).devices()

    assert len(result.items) == 2
    assert result.items[1].status == "offline"
    assert result.items[0].id == canonical_device_id("1")
    assert result.items[0].source_aliases[0].native_id == "1"
    for device in result.items:
        validate("device", device.model_dump(mode="json"))


@pytest.mark.asyncio
async def test_get_device_maps_librenms_detail_response() -> None:
    requested_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        return httpx.Response(
            200,
            json={
                "status": "ok",
                "count": 1,
                "devices": [DEVICES_PAYLOAD["devices"][0]],
            },
        )

    device = await _client_for(handler).get_device("1")

    assert requested_paths == ["/api/v0/devices/1"]
    assert device.id == canonical_device_id("1")
    assert device.hostname == "core-sw-01.example.test"


@pytest.mark.asyncio
async def test_get_device_empty_response_is_not_found() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "ok", "count": 0, "devices": []})

    with pytest.raises(DeviceNotFoundError):
        await _client_for(handler).get_device("404")


@pytest.mark.asyncio
async def test_alerts_map_device_reference_to_canonical_id() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=ALERTS_PAYLOAD)

    rows = await _client_for(handler).alerts()
    assert rows[0]["severity"] == "critical"
    assert rows[0]["device_id"] == canonical_device_id("1")
    assert rows[0]["observed_at"] == "2026-10-02T10:00:00Z"
    validate("alert", rows[0])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        (
            "2026-10-02T12:30:45+02:30",
            "2026-10-02T10:00:45Z",
        ),
        (
            "2026-10-02T12:00:00.123456+02:00",
            "2026-10-02T10:00:00.123456Z",
        ),
        (
            "2026-10-02t10:00:00z",
            "2026-10-02T10:00:00Z",
        ),
    ],
    ids=["offset", "fraction", "lowercase-z"],
)
async def test_alerts_normalize_rfc3339_timestamp_to_utc(
    timestamp: str,
    expected: str,
) -> None:
    alert = {**ALERTS_PAYLOAD["alerts"][0], "timestamp": timestamp}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"alerts": [alert]})

    rows = await _client_for(handler).alerts()

    assert rows[0]["observed_at"] == expected
    validate("alert", rows[0])


@pytest.mark.asyncio
async def test_alerts_normalize_native_timestamp_using_explicit_source_timezone() -> None:
    alert = {
        **ALERTS_PAYLOAD["alerts"][0],
        "timestamp": "2026-10-02 12:00:00",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"alerts": [alert]})

    rows = await _client_for(
        handler,
        source_timezone=ZoneInfo("Africa/Windhoek"),
    ).alerts()

    assert rows[0]["observed_at"] == "2026-10-02T10:00:00Z"
    validate("alert", rows[0])


@pytest.mark.asyncio
async def test_alerts_reject_native_timestamp_without_source_timezone() -> None:
    alert = {
        **ALERTS_PAYLOAD["alerts"][0],
        "timestamp": "2026-10-02 12:00:00",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"alerts": [alert]})

    with pytest.raises(AdapterError) as exc_info:
        await _client_for(handler).alerts()

    assert exc_info.value.status is AdapterStatus.INVALID_SOURCE_DATA
    assert exc_info.value.detail == "invalid alert timestamp"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "timestamp",
    [
        pytest.param("2026-11-01 01:30:00", id="ambiguous-dst-fold"),
        pytest.param("2026-03-08 02:30:00", id="nonexistent-dst-gap"),
        pytest.param("2026-10-02 25:00:00", id="invalid-native-time"),
    ],
)
async def test_alerts_reject_unresolvable_native_timestamp(timestamp: str) -> None:
    alert = {**ALERTS_PAYLOAD["alerts"][0], "timestamp": timestamp}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"alerts": [alert]})

    with pytest.raises(AdapterError) as exc_info:
        await _client_for(
            handler,
            source_timezone=ZoneInfo("America/New_York"),
        ).alerts()

    assert exc_info.value.status is AdapterStatus.INVALID_SOURCE_DATA
    assert exc_info.value.detail == "invalid alert timestamp"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "timestamp",
    [
        pytest.param(_MISSING, id="missing"),
        pytest.param(None, id="null"),
        pytest.param("", id="empty"),
        pytest.param("   ", id="blank"),
        pytest.param("not-a-date", id="malformed"),
        pytest.param("2026-02-30T10:00:00Z", id="invalid-calendar-date"),
        pytest.param("2026-10-02T10:00:00", id="missing-timezone"),
        pytest.param(1_759_398_400, id="wrong-type"),
    ],
)
async def test_alerts_reject_missing_or_invalid_observed_at(timestamp: object) -> None:
    alert = dict(ALERTS_PAYLOAD["alerts"][0])
    if timestamp is _MISSING:
        alert.pop("timestamp")
    else:
        alert["timestamp"] = timestamp

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"alerts": [alert]})

    with pytest.raises(AdapterError) as exc_info:
        await _client_for(handler).alerts()

    assert exc_info.value.status is AdapterStatus.INVALID_SOURCE_DATA
    assert exc_info.value.detail == "invalid alert timestamp"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "expected_status"),
    [
        (httpx.Response(503), AdapterStatus.UNAVAILABLE),
        (httpx.Response(401), AdapterStatus.FORBIDDEN),
        (httpx.Response(200, text="not-json"), AdapterStatus.INVALID_SOURCE_DATA),
        (httpx.Response(200, json={"devices": "wrong"}), AdapterStatus.INVALID_SOURCE_DATA),
        (
            httpx.Response(200, json={"status": "error", "count": 0, "devices": []}),
            AdapterStatus.INVALID_SOURCE_DATA,
        ),
    ],
)
async def test_source_failures_are_typed(
    response: httpx.Response, expected_status: AdapterStatus
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return response

    with pytest.raises(AdapterError) as exc_info:
        await _client_for(handler).devices()
    assert exc_info.value.status is expected_status


@pytest.mark.asyncio
async def test_health_reports_ok_and_down_without_raw_errors() -> None:
    def ok(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "ok"})

    health = await _client_for(ok).health()
    assert health.reachable is True
    assert health.status is AdapterStatus.SUCCESS
    assert health.detail == "ok"

    def down(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="database password leaked")

    health = await _client_for(down).health()
    assert health.reachable is False
    assert health.status is AdapterStatus.UNAVAILABLE
    assert "password" not in health.detail


def test_client_repr_does_not_expose_token() -> None:
    client = _client_for(lambda request: httpx.Response(200), token="super-secret")
    assert "super-secret" not in repr(client)
