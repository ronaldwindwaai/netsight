"""Unit tests for the daily-totals read behind the capacity forecast (Step 13).

A mock transport stands in for ClickHouse: these pin what the adapter *sends* (typed parameters, a
window and a LIMIT, nothing a caller typed inside the SQL) and how it treats what comes back (source
reported or an error, a day with no flows absent rather than zero).
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime
from typing import Any

import httpx
import pytest

from netsight_api.adapters.clickhouse import AdapterError
from netsight_api.adapters.clickhouse_explorer import ExplorerClickhouse
from netsight_api.forecast.source import DailyTotals

FIRST = date(2026, 9, 1)
END = date(2026, 9, 4)


def midnight(day: date) -> int:
    return int(datetime(day.year, day.month, day.day, tzinfo=UTC).timestamp())


class Script:
    def __init__(self, columns: list[str], answers: dict[str, Any]) -> None:
        self.columns, self.answers = columns, answers
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        sql = request.content.decode()
        if "system.columns" in sql:
            return httpx.Response(200, json={"data": [{"name": n} for n in self.columns]})
        for marker, payload in self.answers.items():
            if marker in sql:
                if isinstance(payload, httpx.Response):
                    return payload
                return httpx.Response(200, json=payload)
        raise AssertionError(f"unscripted query: {sql}")

    @property
    def data_requests(self) -> list[httpx.Request]:
        return [r for r in self.requests if "system.columns" not in r.content.decode()]


CORE = ["TimeReceived", "SrcAddr", "DstAddr", "Proto", "Bytes"]


def answers(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "AS total_day": {
            "data": [
                {"total_day": midnight(date(2026, 9, 1)), "agg_bytes": "100"},
                {"total_day": midnight(date(2026, 9, 3)), "agg_bytes": "300"},
            ]
        },
        "AS first_seen": {
            "data": [
                {
                    "first_seen": midnight(date(2026, 9, 1)) + 5,
                    "last_seen": midnight(date(2026, 9, 3)) + 80_000,
                    "agg_rows": "9000",
                }
            ]
        },
    }
    base.update(overrides)
    return base


def client(script: Script) -> ExplorerClickhouse:
    return ExplorerClickhouse(
        dsn="http://clickhouse.test:8123", _transport=httpx.MockTransport(script)
    )


async def read(script: Script) -> DailyTotals:
    return await client(script).daily_totals(first_day=FIRST, end_day=END)


@pytest.mark.asyncio
async def test_days_are_keyed_by_utc_date_and_a_day_without_flows_is_absent() -> None:
    result = await read(Script(CORE, answers()))
    assert result.daily == {date(2026, 9, 1): 100, date(2026, 9, 3): 300}  # 9-02 is absent, not 0
    assert result.first_flow_at == datetime.fromtimestamp(midnight(FIRST) + 5, tz=UTC)
    assert result.last_flow_at == datetime.fromtimestamp(
        midnight(date(2026, 9, 3)) + 80_000, tz=UTC
    )


@pytest.mark.asyncio
async def test_an_empty_store_is_an_empty_read_not_zeros() -> None:
    script = Script(
        CORE,
        answers(
            **{
                "AS total_day": {"data": []},
                "AS first_seen": {"data": [{"first_seen": 0, "last_seen": 0, "agg_rows": "0"}]},
            }
        ),
    )
    result = await read(script)
    assert result == DailyTotals({}, None, None)


@pytest.mark.asyncio
async def test_every_query_is_bounded_typed_and_read_only() -> None:
    script = Script(CORE, answers())
    await read(script)
    assert len(script.data_requests) == 2
    for request in script.data_requests:
        sql = request.content.decode()
        assert "FORMAT JSON" in sql and "LIMIT" in sql and "SELECT *" not in sql
        assert "TimeReceived` >=" in sql and "param_range_from" in str(request.url)
        assert not re.search(r"INSERT|ALTER|DROP|CREATE|SYSTEM", sql, re.IGNORECASE)
    params = {k: v for k, v in httpx.QueryParams(script.data_requests[0].url.query).items()}
    assert params["param_range_from"] == str(midnight(FIRST))
    assert params["param_range_to"] == str(midnight(END))


@pytest.mark.asyncio
async def test_a_bucket_that_is_not_a_whole_day_is_invalid_source_data() -> None:
    rows = [{"total_day": midnight(FIRST) + 3600, "agg_bytes": "1"}]
    with pytest.raises(AdapterError):
        await read(Script(CORE, answers(**{"AS total_day": {"data": rows}})))


@pytest.mark.asyncio
async def test_a_day_outside_the_requested_window_is_invalid_source_data() -> None:
    rows = [{"total_day": midnight(date(2026, 8, 1)), "agg_bytes": "1"}]
    with pytest.raises(AdapterError):
        await read(Script(CORE, answers(**{"AS total_day": {"data": rows}})))


@pytest.mark.asyncio
async def test_negative_or_fractional_bytes_fail_the_read_instead_of_being_clamped() -> None:
    for bad in ("-5", "1.5", True, None):
        rows = [{"total_day": midnight(FIRST), "agg_bytes": bad}]
        with pytest.raises(AdapterError):
            await read(Script(CORE, answers(**{"AS total_day": {"data": rows}})))


@pytest.mark.asyncio
async def test_a_result_that_hit_its_row_cap_fails_instead_of_being_truncated() -> None:
    start = date(2026, 6, 1)
    rows = [{"total_day": midnight(start) + 86_400 * i, "agg_bytes": "1"} for i in range(121)]
    wide = ExplorerClickhouse(
        dsn="http://clickhouse.test:8123",
        _transport=httpx.MockTransport(Script(CORE, answers(**{"AS total_day": {"data": rows}}))),
    )
    with pytest.raises(AdapterError):
        await wide.daily_totals(first_day=date(2026, 6, 1), end_day=date(2026, 9, 29))


@pytest.mark.asyncio
async def test_a_table_without_the_needed_columns_fails_closed() -> None:
    with pytest.raises(AdapterError):
        await read(Script(["TimeReceived", "SrcAddr"], answers()))


@pytest.mark.asyncio
async def test_a_failing_store_raises_and_never_returns_an_empty_success() -> None:
    failing = answers(**{"AS total_day": httpx.Response(500, text="boom")})
    with pytest.raises(AdapterError):
        await read(Script(CORE, failing))


@pytest.mark.asyncio
async def test_the_window_must_be_ordered_and_at_most_120_days() -> None:
    script = Script(CORE, answers())
    for first, end in (
        (END, FIRST),
        (FIRST, FIRST),
        (date(2026, 1, 1), date(2026, 6, 1)),
    ):
        with pytest.raises(ValueError):
            await client(script).daily_totals(first_day=first, end_day=end)
    assert script.requests == []
