"""ObservationSource contract and the LibreNMS-backed source (S6 step 2).

Truthfulness is the point: an unconfigured source is ``not-connected``, a failing one is
``unknown``, and a value the source cannot state is ``None`` -- never a made-up reading.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from netsight_api.adapters.librenms import LibrenmsClient, canonical_device_id
from netsight_api.alerting.engine import Observation
from netsight_api.evaluation.librenms_source import (
    MAX_OBSERVATIONS,
    SUPPORTED_METRICS,
    LibrenmsObservationSource,
)
from netsight_api.evaluation.source import (
    ObservationBatch,
    ObservationSource,
    is_availability_metric,
)

NOW = datetime(2026, 10, 10, 9, 0, tzinfo=UTC)
Handler = Callable[[httpx.Request], httpx.Response]

DEVICES: dict[str, Any] = {
    "status": "ok",
    "count": 4,
    "devices": [
        {"device_id": 1, "hostname": "a.example.test", "sysName": "a", "status": 1},
        {"device_id": 2, "hostname": "b.example.test", "sysName": "b", "status": 0},
        {"device_id": 3, "hostname": "c.example.test", "sysName": "c", "status": None},
        {
            "device_id": 4,
            "hostname": "d.example.test",
            "sysName": "<script>alert(1)</script>",
            "status": 1,
            "disabled": 1,
        },
    ],
}
ALERTS: dict[str, Any] = {
    "alerts": [
        {"id": 10, "device_id": 2, "severity": "critical", "state": 0, "name": "x",
         "timestamp": "2026-10-10T08:59:00Z"},
        {"id": 11, "device_id": 2, "severity": "warning", "state": 0, "name": "y",
         "timestamp": "2026-10-10T08:59:00Z"},
        {"id": 12, "device_id": 2, "severity": "warning", "state": 1, "name": "acked",
         "timestamp": "2026-10-10T08:59:00Z"},
        {"id": 13, "device_id": 1, "severity": "notice", "state": 0, "name": "z",
         "timestamp": "2026-10-10T08:59:00Z"},
    ]
}


def client_for(handler: Handler) -> LibrenmsClient:
    return LibrenmsClient(
        base_url="https://librenms.test",
        token="test-token",
        _transport=httpx.MockTransport(handler),
    )


def routing_handler(
    devices: dict[str, Any] | int = DEVICES, alerts: dict[str, Any] | int = ALERTS
) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"  # the source is strictly read-only
        body = devices if request.url.path == "/api/v0/devices" else alerts
        if isinstance(body, int):
            return httpx.Response(body, json={})
        return httpx.Response(200, json=body)

    return handler


def source_for(handler: Handler | None) -> LibrenmsObservationSource:
    client = None if handler is None else client_for(handler)
    return LibrenmsObservationSource(lambda: client)


def by_entity(batch: ObservationBatch) -> dict[str, Observation]:
    return {o.entity: o for o in batch.observations}


# --- the contract -----------------------------------------------------------------------------------


def test_batches_other_than_ok_cannot_carry_observations() -> None:
    observation = Observation(at=NOW, entity="e", scopes=frozenset())
    assert ObservationBatch("ok", (observation,)).observations == (observation,)
    for state in ("not-connected", "unknown"):
        with pytest.raises(ValueError, match="observations"):
            ObservationBatch(state, (observation,))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="state"):
        ObservationBatch("fine")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("metric", "expected"),
    [
        ("device.status", True),
        ("interface.oper_status", True),
        ("availability.ping", True),
        ("device.alert_count", False),
        ("traffic.upload_bytes", False),
        ("security.event_count", False),
        ("availability", False),
        ("device.statuses", False),
        ("", False),
    ],
)
def test_availability_metrics_are_a_closed_namespace(metric: str, expected: bool) -> None:
    assert is_availability_metric(metric) is expected


def test_the_librenms_source_satisfies_the_protocol() -> None:
    source: ObservationSource = source_for(None)
    assert source.supports("device.status") and source.supports("device.alert_count")
    assert not source.supports("traffic.upload_bytes")
    assert set(SUPPORTED_METRICS) == {"device.status", "device.alert_count"}


# --- truthful states ---------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unconfigured_source_is_not_connected_with_no_rows() -> None:
    batch = await source_for(None).observe("device.status", now=NOW)
    assert (batch.state, batch.observations) == ("not-connected", ())


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
async def test_source_failure_is_unknown_never_empty_ok(status: int) -> None:
    batch = await source_for(routing_handler(devices=status)).observe("device.status", now=NOW)
    assert (batch.state, batch.observations) == ("unknown", ())


@pytest.mark.asyncio
async def test_timeouts_and_garbage_are_unknown() -> None:
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("boom")

    def garbage(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>not json</html>")

    for handler in (slow, garbage):
        batch = await source_for(handler).observe("device.status", now=NOW)
        assert (batch.state, batch.observations) == ("unknown", ())


@pytest.mark.asyncio
async def test_alert_count_is_unknown_when_only_the_alert_read_fails() -> None:
    batch = await source_for(routing_handler(alerts=500)).observe("device.alert_count", now=NOW)
    assert batch.state == "unknown" and batch.observations == ()


@pytest.mark.asyncio
async def test_an_unsupported_metric_is_refused_not_guessed() -> None:
    with pytest.raises(ValueError, match="metric"):
        await source_for(routing_handler()).observe("traffic.upload_bytes", now=NOW)


@pytest.mark.asyncio
async def test_a_collection_beyond_the_cap_is_unknown_not_truncated() -> None:
    many = {
        "status": "ok",
        "devices": [
            {"device_id": i, "hostname": f"h{i}.test", "sysName": f"h{i}", "status": 1}
            for i in range(1, MAX_OBSERVATIONS + 2)
        ],
        "count": MAX_OBSERVATIONS + 1,
    }
    batch = await source_for(routing_handler(devices=many)).observe("device.status", now=NOW)
    assert (batch.state, batch.observations, batch.detail) == (
        "unknown",
        (),
        "TOO_MANY_OBSERVATIONS",
    )


# --- device.status ----------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_device_status_reports_up_down_and_no_data_per_canonical_device() -> None:
    batch = await source_for(routing_handler()).observe("device.status", now=NOW)
    assert batch.state == "ok"
    seen = by_entity(batch)
    assert set(seen) == {canonical_device_id(str(n)) for n in (1, 2, 3, 4)}
    assert seen[canonical_device_id("1")].value == 1.0
    assert seen[canonical_device_id("2")].value == 0.0
    assert seen[canonical_device_id("3")].value is None  # unknown status: no data, not "down"
    assert seen[canonical_device_id("4")].value is None  # LibreNMS-side maintenance/disabled
    assert all(o.at == NOW for o in batch.observations)


@pytest.mark.asyncio
async def test_observations_are_scoped_to_the_device_and_the_organisation_only() -> None:
    batch = await source_for(routing_handler()).observe("device.status", now=NOW)
    device = canonical_device_id("1")
    assert by_entity(batch)[device].scopes == frozenset(
        {("device", device), ("organisation", "default")}
    )


@pytest.mark.asyncio
async def test_hostile_device_names_never_enter_an_observation() -> None:
    batch = await source_for(routing_handler()).observe("device.status", now=NOW)
    rendered = repr(batch.observations)
    assert "<script>" not in rendered
    assert all(o.text is None for o in batch.observations)


# --- device.alert_count -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alert_count_counts_open_source_alerts_and_reports_zero_for_quiet_devices() -> None:
    batch = await source_for(routing_handler()).observe("device.alert_count", now=NOW)
    assert batch.state == "ok"
    seen = by_entity(batch)
    assert seen[canonical_device_id("2")].value == 2.0  # the acknowledged alert is not counted
    assert seen[canonical_device_id("1")].value == 1.0
    assert seen[canonical_device_id("3")].value == 0.0
    assert seen[canonical_device_id("4")].value == 0.0


def test_the_source_repr_exposes_no_credentials() -> None:
    assert "test-token" not in repr(source_for(routing_handler()))
