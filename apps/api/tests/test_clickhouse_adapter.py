"""Unit tests for the read-only ClickHouse flow adapter (S4-2).

The adapter's SQL grammar and HTTP behaviour were verified against a live
ClickHouse server (26.10 HTTP interface) while building S4-2; these tests
pin the client-side contract with a mock transport so they run offline.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from netsight_api.adapters.clickhouse import (
    AdapterError,
    AdapterStatus,
    ClickhouseClient,
    _parse_protocol,
)

Handler = Callable[[httpx.Request], httpx.Response]

_START = datetime(2026, 10, 5, 0, 0, tzinfo=UTC)
_END = datetime(2026, 10, 6, 0, 0, tzinfo=UTC)
_OBSERVED_EPOCH = int(datetime(2026, 10, 5, 23, 30, tzinfo=UTC).timestamp())

_TOP_COLUMNS = ["TimeReceived", "SrcAddr", "DstAddr", "Proto", "Bytes", "Packets"]
_FLOW_COLUMNS = [*_TOP_COLUMNS, "DstPort", "DstHostname", "Application", "User"]


def _discovery(names: list[str]) -> httpx.Response:
    return httpx.Response(
        200, json={"data": [{"name": name} for name in names], "rows": len(names)}
    )


def _client(
    handler: Handler,
    *,
    dsn: str = "http://clickhouse.test:8123",
    flows_table: str = "flows",
) -> ClickhouseClient:
    return ClickhouseClient(
        dsn=dsn,
        flows_table=flows_table,
        _transport=httpx.MockTransport(handler),
    )


def _is_discovery(request: httpx.Request) -> bool:
    return "system.columns" in request.content.decode()


@pytest.mark.asyncio
async def test_top_returns_ranked_items_with_share_and_normalised_labels() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if _is_discovery(request):
            return _discovery(_TOP_COLUMNS)
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "label": "::ffff:10.1.2.3",
                        "agg_bytes": "6000",
                        "agg_packets": "12",
                        "agg_seen": _OBSERVED_EPOCH,
                    },
                    {
                        "label": "2001:db8::1",
                        "agg_bytes": 4000,
                        "agg_packets": 8,
                        "agg_seen": _OBSERVED_EPOCH - 60,
                    },
                ],
                "totals": {
                    "label": "",
                    "agg_bytes": "10000",
                    "agg_packets": "20",
                    "agg_seen": 0,
                },
                "rows": 2,
            },
        )

    items, observed_at = await _client(handler).top(
        dimension="talkers", start=_START, end=_END, limit=5
    )

    assert observed_at == datetime(2026, 10, 5, 23, 30, tzinfo=UTC)
    assert [item.label for item in items] == ["10.1.2.3", "2001:db8::1"]
    assert items[0].rank == 1
    assert items[0].bytes == 6000
    assert items[0].packets == 12
    assert items[0].share == 0.6
    assert items[0].subject_kind == "ip"
    assert items[0].subject_id is None
    assert items[1].share == 0.4

    discovery, data = calls
    assert discovery.url.params["param_db"] == "default"
    assert discovery.url.params["param_table"] == "flows"
    body = data.content.decode()
    assert "`SrcAddr`" in body
    assert "WITH TOTALS" in body
    assert "FROM `default`.`flows`" in body
    assert "LIMIT 5" in body
    assert data.url.params["param_start"] == str(int(_START.timestamp()))
    assert data.url.params["param_end"] == str(int(_END.timestamp()))
    assert data.url.params["max_execution_time"] == "10"


@pytest.mark.asyncio
async def test_top_destinations_queries_destination_column_and_missing_totals() -> None:
    bodies: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(request.content.decode())
        if _is_discovery(request):
            return _discovery(_TOP_COLUMNS)
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "label": "10.9.9.9",
                        "agg_bytes": "50",
                        "agg_packets": "1",
                        "agg_seen": _OBSERVED_EPOCH,
                    }
                ],
                "rows": 1,
            },
        )

    items, observed_at = await _client(handler).top(
        dimension="destinations", start=_START, end=_END, limit=5
    )

    assert observed_at == datetime(2026, 10, 5, 23, 30, tzinfo=UTC)
    assert len(items) == 1
    assert items[0].share is None  # no totals -> no share denominator
    assert "`DstAddr`" in bodies[1]
    assert "`SrcAddr`" not in bodies[1]


@pytest.mark.asyncio
async def test_missing_required_column_fails_closed() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if _is_discovery(request):
            return _discovery(["TimeReceived", "Bytes"])  # no address column
        return httpx.Response(500, text="the data query must never be issued")

    with pytest.raises(AdapterError) as excinfo:
        await _client(handler).top(dimension="talkers", start=_START, end=_END, limit=5)

    assert excinfo.value.status is AdapterStatus.INVALID_SOURCE_DATA
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_unknown_table_raises_invalid_source_data() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [], "rows": 0})

    with pytest.raises(AdapterError) as excinfo:
        await _client(handler).top(dimension="talkers", start=_START, end=_END, limit=5)

    assert excinfo.value.status is AdapterStatus.INVALID_SOURCE_DATA


@pytest.mark.asyncio
async def test_flows_missing_core_column_fails_closed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if _is_discovery(request):
            return _discovery(["TimeReceived", "SrcAddr", "DstAddr", "Bytes"])  # no Proto
        return httpx.Response(500, text="unexpected")

    with pytest.raises(AdapterError) as excinfo:
        await _client(handler).flows(start=_START, end=_END, limit=50)

    assert excinfo.value.status is AdapterStatus.INVALID_SOURCE_DATA


@pytest.mark.asyncio
async def test_invalid_table_identifier_never_reaches_network() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return _discovery(_TOP_COLUMNS)

    with pytest.raises(AdapterError) as excinfo:
        await _client(handler, flows_table="flows; DROP TABLE x").top(
            dimension="talkers", start=_START, end=_END, limit=5
        )

    assert excinfo.value.status is AdapterStatus.UNAVAILABLE
    assert calls == []


@pytest.mark.parametrize(
    "dsn",
    [
        "ftp://clickhouse.test:8123",
        "clickhouse.test:8123",
        "http://clickhouse.test:8123/path",
        "http://clickhouse.test:8123/?query=1",
        "http://clickhouse.test:8123/#frag",
    ],
)
@pytest.mark.asyncio
async def test_invalid_dsn_raises_unavailable_without_network(dsn: str) -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return _discovery(_TOP_COLUMNS)

    with pytest.raises(AdapterError) as excinfo:
        await _client(handler, dsn=dsn).top(
            dimension="talkers", start=_START, end=_END, limit=5
        )

    assert excinfo.value.status is AdapterStatus.UNAVAILABLE
    assert calls == []


@pytest.mark.asyncio
async def test_forbidden_status_raises_forbidden() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")

    with pytest.raises(AdapterError) as excinfo:
        await _client(handler).top(dimension="talkers", start=_START, end=_END, limit=5)

    assert excinfo.value.status is AdapterStatus.FORBIDDEN


@pytest.mark.asyncio
async def test_timeout_raises_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("too slow")

    with pytest.raises(AdapterError) as excinfo:
        await _client(handler).top(dimension="talkers", start=_START, end=_END, limit=5)

    assert excinfo.value.status is AdapterStatus.UNAVAILABLE


@pytest.mark.asyncio
async def test_invalid_json_raises_invalid_source_data() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>not json</html>")

    with pytest.raises(AdapterError) as excinfo:
        await _client(handler).top(dimension="talkers", start=_START, end=_END, limit=5)

    assert excinfo.value.status is AdapterStatus.INVALID_SOURCE_DATA


@pytest.mark.asyncio
async def test_readonly_settings_error_retries_without_setting() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(
                500,
                text=(
                    "Code: 164. DB::Exception: Cannot modify 'max_execution_time' "
                    "setting in readonly mode. (READONLY)"
                ),
            )
        if _is_discovery(request):
            return _discovery(_TOP_COLUMNS)
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "label": "10.0.0.1",
                        "agg_bytes": "100",
                        "agg_packets": "1",
                        "agg_seen": _OBSERVED_EPOCH,
                    }
                ],
                "totals": {"agg_bytes": "100"},
                "rows": 1,
            },
        )

    items, _ = await _client(handler).top(
        dimension="talkers", start=_START, end=_END, limit=5
    )

    assert len(items) == 1
    assert len(calls) == 3  # failed attempt, settings-free retry, one data query
    assert "max_execution_time" in calls[0].url.params
    assert "max_execution_time" not in calls[1].url.params
    assert "max_execution_time" not in calls[2].url.params


@pytest.mark.asyncio
async def test_flows_maps_optional_columns_and_protocols() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if _is_discovery(request):
            return _discovery(_FLOW_COLUMNS)
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "seen_at": _OBSERVED_EPOCH,
                        "source_ip": "::ffff:10.1.2.3",
                        "destination_ip": "2001:db8::9",
                        "n_bytes": "900",
                        "proto_num": 6,
                        "n_packets": "7",
                        "dest_port": 443,
                        "dest_host": "cdn.example.net",
                        "app_name": "https",
                        "user_name": "alice",
                    },
                    {
                        "seen_at": _OBSERVED_EPOCH - 10,
                        "source_ip": "10.1.2.4",
                        "destination_ip": "10.1.2.5",
                        "n_bytes": 100,
                        "proto_num": 47,
                        "n_packets": None,
                        "dest_port": None,
                        "dest_host": "",
                        "app_name": "<img src=x onerror=alert(1)>",
                        "user_name": None,
                    },
                ],
                "rows": 2,
            },
        )

    flows, observed_at = await _client(handler).flows(start=_START, end=_END, limit=50)

    assert observed_at == datetime(2026, 10, 5, 23, 30, tzinfo=UTC)
    first, second = flows
    assert first.source_ip == "10.1.2.3"
    assert first.protocol == "tcp"
    assert first.destination_port == 443
    assert first.packets == 7
    assert first.direction == "unknown"
    assert first.source_device_id is None
    assert first.application == "https"
    assert first.user == "alice"
    assert second.protocol == "other"
    assert second.destination_port is None
    assert second.packets is None
    assert second.destination_host is None
    assert second.application == "<img src=x onerror=alert(1)>"
    assert second.user is None


@pytest.mark.parametrize(
    ("number", "expected"),
    [(1, "icmp"), (6, "tcp"), (17, "udp"), (58, "icmp"), (47, "other"), (132, "other")],
)
def test_protocol_number_mapping(number: int, expected: str) -> None:
    assert _parse_protocol(number) == expected


@pytest.mark.parametrize("value", ["tcp", "TCP", None, True, -1, "999999"])
def test_protocol_invalid_values_fail_closed(value: Any) -> None:
    with pytest.raises(AdapterError):
        _parse_protocol(value)


@pytest.mark.asyncio
async def test_empty_window_returns_no_observed_at() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if _is_discovery(request):
            return _discovery(_FLOW_COLUMNS)
        return httpx.Response(200, json={"data": [], "rows": 0})

    flows, observed_at = await _client(handler).flows(start=_START, end=_END, limit=50)

    assert flows == []
    assert observed_at is None


@pytest.mark.asyncio
async def test_naive_window_is_rejected_before_any_network_call() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return _discovery(_TOP_COLUMNS)

    with pytest.raises(ValueError):
        await _client(handler).top(
            dimension="talkers",
            start=datetime(2026, 10, 5),  # noqa: DTZ001 — naive window is the point
            end=datetime(2026, 10, 6),  # noqa: DTZ001
            limit=5,
        )

    assert calls == []


@pytest.mark.asyncio
async def test_dsn_userinfo_supplies_basic_auth() -> None:
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("authorization"))
        if _is_discovery(request):
            return _discovery(_TOP_COLUMNS)
        return httpx.Response(200, json={"data": [], "totals": {}, "rows": 0})

    await _client(handler, dsn="http://alice:s3cret@clickhouse.test:8123").top(
        dimension="talkers", start=_START, end=_END, limit=5
    )

    expected = "Basic " + base64.b64encode(b"alice:s3cret").decode()
    assert seen[0] == expected


def test_repr_masks_dsn_and_password() -> None:
    client = ClickhouseClient(
        dsn="http://alice:s3cret@clickhouse.test:8123",
        user="alice",
        password="hunter2",
    )
    text = repr(client)
    assert "hunter2" not in text
    assert "s3cret" not in text


@pytest.mark.asyncio
@pytest.mark.skipif(
    not os.environ.get("CLICKHOUSE_TEST_DSN"),
    reason="set CLICKHOUSE_TEST_DSN to run the live ClickHouse integration test",
)
async def test_live_clickhouse_read_is_bounded_and_typed() -> None:
    """Opt-in smoke test against a real ClickHouse server (never fabricated).

    The live table may be empty or absent, so the only contract asserted is
    that a bounded read completes with either a parsed result or a typed
    ``AdapterError`` — never an unhandled exception and never invented rows.
    """
    client = ClickhouseClient(
        dsn=os.environ["CLICKHOUSE_TEST_DSN"],
        user=os.environ.get("CLICKHOUSE_TEST_USER", ""),
        password=os.environ.get("CLICKHOUSE_TEST_PASSWORD", ""),
        flows_table=os.environ.get("CLICKHOUSE_TEST_TABLE", "flows"),
    )
    end = datetime.now(UTC)
    start = end - timedelta(hours=1)
    try:
        items, observed_at = await client.top(
            dimension="talkers", start=start, end=end, limit=10
        )
    except AdapterError as exc:
        assert exc.status in {
            AdapterStatus.UNAVAILABLE,
            AdapterStatus.INVALID_SOURCE_DATA,
            AdapterStatus.FORBIDDEN,
        }
        return
    assert isinstance(items, list)
    assert observed_at is None or observed_at.tzinfo is not None