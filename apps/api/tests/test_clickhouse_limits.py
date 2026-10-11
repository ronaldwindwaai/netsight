"""Server-side resource limits on every ClickHouse read (Step 7 security review, HIGH-1).

A mock transport stands in for ClickHouse. The adapter must ask the server to bound each query
(time, memory, rows and bytes read, result size) whenever the identity may set settings, remember the
answer for the life of the process so a readonly identity does not pay a failed round trip on every
request, and say once, loudly, that the limits are then the user profile's job.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from netsight_api.adapters import clickhouse_limits
from netsight_api.adapters.clickhouse import AdapterError, ClickhouseClient
from netsight_api.adapters.clickhouse_explorer import ExplorerClickhouse

START = datetime(2026, 10, 5, 0, 0, tzinfo=UTC)
END = datetime(2026, 10, 6, 0, 0, tzinfo=UTC)
COLUMNS = ["TimeReceived", "SrcAddr", "DstAddr", "Proto", "Bytes", "Packets"]
SEEN = int(datetime(2026, 10, 5, 23, 30, tzinfo=UTC).timestamp())
FORBIDDEN_BODY = (
    "Code: 164. DB::Exception: Cannot modify 'max_execution_time' setting in readonly mode. "
    "(READONLY)"
)
EXPECTED_SETTINGS = {
    "readonly",
    "max_execution_time",
    "max_memory_usage",
    "max_rows_to_read",
    "max_bytes_to_read",
    "max_result_rows",
    "max_result_bytes",
    "cancel_http_readonly_queries_on_client_close",
    "read_overflow_mode",
    "result_overflow_mode",
    "timeout_overflow_mode",
}


def _discovery() -> httpx.Response:
    return httpx.Response(200, json={"data": [{"name": name} for name in COLUMNS]})


def _answer(request: httpx.Request) -> httpx.Response:
    if "system.columns" in request.content.decode():
        return _discovery()
    return httpx.Response(
        200,
        json={
            "data": [
                {"label": "10.0.0.1", "agg_bytes": "100", "agg_packets": "1", "agg_seen": SEEN}
            ],
            "totals": {"agg_bytes": "100"},
        },
    )


def _client(handler: Callable[[httpx.Request], httpx.Response], **kwargs: Any) -> ClickhouseClient:
    return ClickhouseClient(
        dsn="http://clickhouse.test:8123", _transport=httpx.MockTransport(handler), **kwargs
    )


async def _read(client: ClickhouseClient) -> None:
    await client.top(dimension="talkers", start=START, end=END, limit=5)


def _settings_in(request: httpx.Request) -> dict[str, str]:
    return {k: v for k, v in request.url.params.items() if not k.startswith("param_")}


@pytest.mark.asyncio
async def test_every_query_carries_the_full_set_of_server_side_limits() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return _answer(request)

    await _read(_client(handler))

    assert len(calls) == 2  # discovery, data
    for request in calls:
        sent = _settings_in(request)
        assert set(sent) == EXPECTED_SETTINGS
        assert sent["readonly"] == "2"  # settings may change, but never writes
        assert sent["max_execution_time"] == "10"
        assert sent["cancel_http_readonly_queries_on_client_close"] == "1"
        for name in ("read_overflow_mode", "result_overflow_mode", "timeout_overflow_mode"):
            assert sent[name] == "throw"  # an exceeded limit fails the read, never truncates it
        for name in (
            "max_memory_usage",
            "max_rows_to_read",
            "max_bytes_to_read",
            "max_result_rows",
            "max_result_bytes",
        ):
            assert int(sent[name]) > 0


@pytest.mark.asyncio
async def test_the_execution_time_follows_the_client_timeout() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return _answer(request)

    await _read(_client(handler, timeout_seconds=4.0))
    assert {r.url.params["max_execution_time"] for r in calls} == {"4"}


@pytest.mark.asyncio
async def test_forbidden_settings_are_learned_once_and_cached_across_clients() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if _settings_in(request):
            return httpx.Response(500, text=FORBIDDEN_BODY)
        return _answer(request)

    await _read(_client(handler))
    first = len(calls)
    assert first == 3  # refused attempt, settings-free retry, data query
    assert _settings_in(calls[0]) and not _settings_in(calls[1]) and not _settings_in(calls[2])

    # A later request builds a brand new client (the route does): no failed round trip this time.
    await _read(_client(handler))
    later = calls[first:]
    assert len(later) == 2  # discovery + data, neither carries settings, none is refused
    assert all(not _settings_in(request) for request in later)


@pytest.mark.asyncio
async def test_permitted_settings_are_cached_too_so_a_later_refusal_is_not_retried_silently() -> (
    None
):
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return _answer(request)

    await _read(_client(handler))
    await _read(_client(handler))
    assert clickhouse_limits.capability_for(("http://clickhouse.test:8123", "")) == "enforced"
    assert all(set(_settings_in(r)) == EXPECTED_SETTINGS for r in calls)


@pytest.mark.asyncio
async def test_capability_is_per_endpoint_and_identity() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        if _settings_in(request):
            return httpx.Response(500, text=FORBIDDEN_BODY)
        return _answer(request)

    seen: list[httpx.Request] = []

    def allow(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _answer(request)

    await _read(_client(refuse, user="reader"))
    await _read(_client(allow, user="admin"))  # a different identity still sends its limits
    assert seen and all(set(_settings_in(r)) == EXPECTED_SETTINGS for r in seen)


@pytest.mark.asyncio
async def test_unverifiable_limits_are_logged_once_with_the_profile_requirement(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if _settings_in(request):
            return httpx.Response(500, text=FORBIDDEN_BODY)
        return _answer(request)

    with caplog.at_level(logging.WARNING, logger="netsight_api"):
        await _read(_client(handler))
        await _read(_client(handler))
        await _read(_client(handler))

    notes = [r for r in caplog.records if "profile" in r.getMessage()]
    assert len(notes) == 1
    assert "limits" in notes[0].getMessage()
    assert clickhouse_limits.capability_for(("http://clickhouse.test:8123", "")) == "profile-only"
    rendered = "".join(r.getMessage() for r in caplog.records)
    assert "clickhouse.test" not in rendered and "password" not in rendered


@pytest.mark.asyncio
async def test_a_refusal_unrelated_to_settings_is_not_taken_for_a_readonly_profile() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            500, text="Code: 60. DB::Exception: Table default.flows does not exist"
        )

    with pytest.raises(AdapterError):
        await _read(_client(handler))
    assert clickhouse_limits.capability_for(("http://clickhouse.test:8123", "")) == "unverified"


@pytest.mark.asyncio
async def test_a_pinned_setting_constraint_is_treated_as_a_profile_enforced_limit() -> None:
    body = (
        "Code: 452. DB::Exception: Setting max_execution_time should not be changed. "
        "(SETTING_CONSTRAINT_VIOLATION)"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if _settings_in(request):
            return httpx.Response(500, text=body)
        return _answer(request)

    await _read(_client(handler))
    assert clickhouse_limits.capability_for(("http://clickhouse.test:8123", "")) == "profile-only"


@pytest.mark.asyncio
async def test_the_explorer_queries_carry_the_limits_too() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        sql = request.content.decode()
        if "system.columns" in sql:
            return httpx.Response(
                200, json={"data": [{"name": n} for n in (*COLUMNS, "Application")]}
            )
        return httpx.Response(
            200, json={"data": [{"app_name": "https", "cur_bytes": "10", "agg_seen": SEEN}]}
        )

    client = ExplorerClickhouse(
        dsn="http://clickhouse.test:8123", _transport=httpx.MockTransport(handler)
    )
    with contextlib.suppress(
        Exception
    ):  # the canned payload is incomplete; the request is the point
        await client.applications(start=START, end=END, limit=5)
    assert calls and all(set(_settings_in(r)) == EXPECTED_SETTINGS for r in calls)
