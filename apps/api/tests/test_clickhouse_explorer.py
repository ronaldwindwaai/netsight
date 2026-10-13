"""Unit tests for the read-only Flow Explorer, Applications, Destinations and baseline queries.

A mock transport stands in for ClickHouse, so these pin what the adapter *sends* (every value bound
as a typed parameter, every query bounded by a window and a LIMIT, nothing a caller typed inside the
SQL text) and how it treats what comes back (source-reported or ``None``, never estimated).
"""

from __future__ import annotations

import asyncio
import os
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from netsight_api.adapters.clickhouse import AdapterError, AdapterStatus
from netsight_api.adapters.clickhouse_explorer import ExplorerClickhouse, bucket_seconds
from netsight_api.traffic.filters import FlowFilterSet

START = datetime(2026, 10, 5, 0, 0, tzinfo=UTC)
END = datetime(2026, 10, 6, 0, 0, tzinfo=UTC)
SEEN = int(datetime(2026, 10, 5, 23, 30, tzinfo=UTC).timestamp())

CORE = ["TimeReceived", "SrcAddr", "DstAddr", "Proto", "Bytes"]
FULL = [
    *CORE,
    "Packets",
    "DstPort",
    "SrcPort",
    "DstHostname",
    "Application",
    "ApplicationCategory",
    "ExporterName",
    "SrcVlan",
    "DstVlan",
    "SrcCountry",
    "DstCountry",
    "SrcAS",
    "DstAS",
    "InIfBoundary",
    "OutIfBoundary",
]

ROW_MARK, TIMELINE_MARK, VOLUME_MARK = "AS source_ip", "AS bucket", "AS agg_sources"
MIX_MARK, DEST_MARK = "AS app_name", "AS address"


class Script:
    """A scripted ClickHouse: answers discovery, then each query by a marker in its SQL."""

    def __init__(
        self,
        columns: list[str],
        answers: dict[str, Any] | None = None,
        types: dict[str, str] | None = None,
    ) -> None:
        self.columns = columns
        self.types = types
        self.answers = answers or {}
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        sql = request.content.decode()
        if "system.columns" in sql:
            if self.types is None:
                return httpx.Response(200, json={"data": [{"name": n} for n in self.columns]})
            rows = [{"name": n, "type": self.types.get(n, "String")} for n in self.columns]
            return httpx.Response(200, json={"data": rows})
        for marker, payload in self.answers.items():
            if marker in sql:
                if isinstance(payload, httpx.Response):
                    return payload
                return httpx.Response(200, json=payload)
        raise AssertionError(f"unscripted query: {sql}")

    @property
    def data_requests(self) -> list[httpx.Request]:
        return [r for r in self.requests if "system.columns" not in r.content.decode()]

    def sql(self, marker: str) -> str:
        (found,) = [r.content.decode() for r in self.data_requests if marker in r.content.decode()]
        return found

    def params(self, marker: str) -> dict[str, str]:
        (found,) = [r for r in self.data_requests if marker in r.content.decode()]
        return {k: v[0] for k, v in parse_qs(str(found.url.query, "ascii")).items()}


def client(script: Script, **kwargs: Any) -> ExplorerClickhouse:
    return ExplorerClickhouse(
        dsn="http://clickhouse.test:8123", _transport=httpx.MockTransport(script), **kwargs
    )


def flow_row(**overrides: Any) -> dict[str, Any]:
    row = {
        "seen_at": SEEN,
        "source_ip": "::ffff:10.1.2.3",
        "destination_ip": "203.0.113.9",
        "n_bytes": "900",
        "proto_num": 6,
        "n_packets": "9",
        "dest_port": 443,
        "dest_host": "cdn.example.net",
        "app_name": "https",
        "in_boundary": "internal",
        "out_boundary": "external",
    }
    row.update(overrides)
    return row


def answers(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        ROW_MARK: {"data": [flow_row()]},
        TIMELINE_MARK: {
            "data": [
                {"bucket": SEEN - 1800, "agg_bytes": "400", "agg_packets": "4", "agg_flows": "2"},
                {
                    "bucket": SEEN + 1800 - 3600 + 900,
                    "agg_bytes": "500",
                    "agg_packets": "5",
                    "agg_flows": "3",
                },
            ]
        },
        VOLUME_MARK: {
            "data": [
                {
                    "agg_bytes": "900",
                    "agg_packets": "9",
                    "agg_flows": "5",
                    "agg_sources": "2",
                    "agg_destinations": "3",
                }
            ]
        },
        MIX_MARK: {
            "data": [
                {"app_name": "https", "agg_bytes": "600"},
                {"app_name": "", "agg_bytes": "200"},
            ],
            "totals": {"app_name": "", "agg_bytes": "900"},
        },
        DEST_MARK: {
            "data": [
                {
                    "address": "::ffff:203.0.113.9",
                    "dest_host": "cdn.example.net",
                    "agg_bytes": "700",
                },
                {"address": "198.51.100.7", "dest_host": "", "agg_bytes": "200"},
            ],
            "totals": {"address": "", "agg_bytes": "900"},
        },
    }
    base.update(overrides)
    return base


async def explore(script: Script, filters: FlowFilterSet | None = None, limit: int = 50, **kw: Any):
    return await client(script, **kw).explore(
        start=START, end=END, limit=limit, filters=filters or FlowFilterSet()
    )


# --- explore: rows and aggregations ------------------------------------------------------------


@pytest.mark.asyncio
async def test_explore_returns_source_reported_rows_and_aggregations() -> None:
    result = await explore(Script(FULL, answers()))

    assert result.unsupported == ()
    (flow,) = result.flows
    assert flow.source_ip == "10.1.2.3"  # IPv4-mapped renders plain
    assert flow.destination_host == "cdn.example.net"
    assert flow.application == "https" and flow.destination_port == 443
    assert flow.protocol == "tcp" and flow.packets == 9
    assert flow.direction == "outbound"
    assert flow.attribution is None  # attribution is the identity service's, never the adapter's
    assert result.observed_at == datetime(2026, 10, 5, 23, 30, tzinfo=UTC)

    aggs = result.aggregations
    assert aggs is not None
    assert aggs.volume.bytes == 900 and aggs.volume.flows == 5 and aggs.volume.packets == 9
    assert (aggs.volume.source_addresses, aggs.volume.destination_addresses) == (2, 3)
    assert [b.bytes for b in aggs.timeline] == [400, 500]
    assert aggs.bucket_seconds == bucket_seconds(int((END - START).total_seconds()))
    assert aggs.application_mix is not None
    mix = aggs.application_mix
    assert [(i.application, i.bytes) for i in mix.items] == [("https", 600), (None, 200)]
    assert mix.other_bytes == 100 and mix.total_bytes == 900
    assert mix.items[0].share == pytest.approx(600 / 900)
    assert [(d.address, d.host, d.bytes) for d in aggs.destinations] == [
        ("203.0.113.9", "cdn.example.net", 700),
        ("198.51.100.7", None, 200),
    ]
    assert aggs.destinations[0].share == pytest.approx(700 / 900)


@pytest.mark.asyncio
async def test_every_query_is_bounded_read_only_and_parameterised() -> None:
    script = Script(FULL, answers())
    await explore(script, limit=25)

    assert len(script.data_requests) == 5  # rows, timeline, volume, mix, destinations
    for request in script.data_requests:
        sql = request.content.decode()
        assert sql.lstrip().upper().startswith("SELECT")
        assert "FORMAT JSON" in sql and "LIMIT" in sql
        assert "TimeReceived` >= toDateTime({start:UInt32})" in sql
        assert "TimeReceived` < toDateTime({end:UInt32})" in sql
        assert "SELECT *" not in sql and ";" not in sql
        params = {k: v[0] for k, v in parse_qs(str(request.url.query, "ascii")).items()}
        assert params["param_start"] == str(int(START.timestamp()))
        assert params["param_end"] == str(int(END.timestamp()))
        assert params["max_execution_time"] == "10"
    assert "LIMIT 25 " in script.sql(ROW_MARK) + " "


@pytest.mark.asyncio
async def test_filters_are_bound_as_typed_parameters_never_in_the_sql_text() -> None:
    hostile = "x' OR 1=1; DROP TABLE flows; --"
    filters = FlowFilterSet(
        source_ip="10.1.2.3",
        destination_ip="2001:db8::1",
        device=hostile,
        vlan=20,
        application=hostile,
        protocol="udp",
        port=53,
        country="ZA",
        asn=64500,
        direction="inbound",
    )
    script = Script(FULL, answers())
    await explore(script, filters)

    for request in script.data_requests:
        sql = request.content.decode()
        assert hostile not in sql and "DROP" not in sql and "10.1.2.3" not in sql
        assert "64500" not in sql and "'ZA'" not in sql
        params = {k: v[0] for k, v in parse_qs(str(request.url.query, "ascii")).items()}
        assert params["param_f_device"] == hostile
        assert params["param_f_application"] == hostile
        assert params["param_f_vlan"] == "20" and params["param_f_port"] == "53"
        assert params["param_f_asn"] == "64500" and params["param_f_country"] == "ZA"
        assert params["param_f_src_0"] == "10.1.2.3"
        assert params["param_f_src_1"] == "::ffff:10.1.2.3"  # both stored spellings
        assert params["param_f_dst_0"] == "2001:db8::1"
        assert "param_f_dst_1" not in params
    sql = script.sql(ROW_MARK)
    assert "{f_device:String}" in sql and "{f_vlan:UInt16}" in sql and "{f_asn:UInt32}" in sql
    assert "IN ({f_src_0:String}, {f_src_1:String})" in sql


@pytest.mark.asyncio
async def test_protocol_and_direction_filters_use_fixed_constants() -> None:
    script = Script(FULL, answers())
    await explore(script, FlowFilterSet(protocol="icmp", direction="inbound"))
    sql = script.sql(ROW_MARK)
    assert "`Proto` IN (1, 58)" in sql
    assert "`InIfBoundary` = 'external'" in sql and "`OutIfBoundary` = 'internal'" in sql
    assert (
        "toString(`InIfBoundary`)" not in sql.split(" WHERE ")[1]
    )  # a typed comparison, not a per-row string

    script = Script(FULL, answers())
    await explore(script, FlowFilterSet(protocol="other"))
    assert "`Proto` NOT IN (1, 6, 17, 58)" in script.sql(ROW_MARK)


@pytest.mark.asyncio
async def test_a_filter_the_source_cannot_honour_is_reported_not_dropped() -> None:
    script = Script(CORE, answers())  # no ExporterName, VLAN, Application, country, AS or boundary
    result = await explore(
        script,
        FlowFilterSet(
            device="edge", vlan=1, application="x", country="ZA", asn=1, direction="inbound"
        ),
    )
    assert result.unsupported == ("device", "vlan", "application", "country", "asn", "direction")
    assert result.flows == () and result.aggregations is None
    assert script.data_requests == []  # nothing was run unfiltered


@pytest.mark.asyncio
async def test_port_matches_both_sides_only_when_the_source_reports_the_source_port() -> None:
    script = Script(FULL, answers())
    await explore(script, FlowFilterSet(port=443))
    assert "`DstPort` = {f_port:UInt16} OR `SrcPort` = {f_port:UInt16}" in script.sql(ROW_MARK)
    without = [c for c in FULL if c != "SrcPort"]
    script = Script(without, answers())
    await explore(script, FlowFilterSet(port=443))
    sql = script.sql(ROW_MARK)
    assert "`DstPort` = {f_port:UInt16}" in sql and "SrcPort" not in sql
    script = Script([c for c in FULL if c not in ("SrcPort", "DstPort")], answers())
    result = await explore(script, FlowFilterSet(port=443))
    assert result.unsupported == ("port",)


@pytest.mark.asyncio
async def test_direction_comes_only_from_the_sources_interface_boundaries() -> None:
    cases = [
        ("external", "internal", "inbound"),
        ("internal", "external", "outbound"),
        ("internal", "internal", "internal"),
        ("external", "external", "unknown"),
        ("undefined", "internal", "unknown"),
        ("", "", "unknown"),
    ]
    for inbound, outbound, expected in cases:
        row = flow_row(in_boundary=inbound, out_boundary=outbound)
        result = await explore(Script(FULL, answers(**{ROW_MARK: {"data": [row]}})))
        assert result.flows[0].direction == expected, (inbound, outbound)
    no_boundary = [c for c in FULL if c not in ("InIfBoundary", "OutIfBoundary")]
    result = await explore(Script(no_boundary, answers(**{ROW_MARK: {"data": [flow_row()]}})))
    assert result.flows[0].direction == "unknown"


@pytest.mark.asyncio
async def test_columns_the_source_lacks_become_null_never_guesses() -> None:
    row = {
        "seen_at": SEEN,
        "source_ip": "10.1.2.3",
        "destination_ip": "10.9.9.9",
        "n_bytes": "5",
        "proto_num": 99,
    }
    script = Script(
        CORE,
        answers(
            **{
                ROW_MARK: {"data": [row]},
                VOLUME_MARK: {
                    "data": [
                        {
                            "agg_bytes": "5",
                            "agg_flows": "1",
                            "agg_sources": "1",
                            "agg_destinations": "1",
                        }
                    ]
                },
            }
        ),
    )
    result = await explore(script)
    flow = result.flows[0]
    assert (flow.packets, flow.destination_port, flow.destination_host, flow.application) == (
        None,
        None,
        None,
        None,
    )
    assert flow.protocol == "other" and flow.direction == "unknown"
    aggs = result.aggregations
    assert aggs is not None and aggs.volume.packets is None
    assert (
        aggs.application_mix is None
    )  # no Application column: not reported, not "all unattributed"
    assert all(b.packets is None for b in aggs.timeline)
    assert MIX_MARK not in "".join(r.content.decode() for r in script.data_requests)


@pytest.mark.asyncio
async def test_an_empty_window_is_a_valid_empty_result() -> None:
    empty = {
        ROW_MARK: {"data": []},
        TIMELINE_MARK: {"data": []},
        VOLUME_MARK: {
            "data": [
                {
                    "agg_bytes": "0",
                    "agg_packets": "0",
                    "agg_flows": "0",
                    "agg_sources": "0",
                    "agg_destinations": "0",
                }
            ]
        },
        MIX_MARK: {"data": [], "totals": {"app_name": "", "agg_bytes": "0"}},
        DEST_MARK: {"data": [], "totals": {"address": "", "agg_bytes": "0"}},
    }
    result = await explore(Script(FULL, empty))
    assert result.flows == () and result.observed_at is None
    aggs = result.aggregations
    assert aggs is not None and aggs.volume.bytes == 0 and aggs.timeline == []
    assert aggs.application_mix is not None and aggs.application_mix.total_bytes == 0
    assert aggs.destinations == []


@pytest.mark.asyncio
async def test_limit_is_clamped_to_the_contract_bounds() -> None:
    script = Script(FULL, answers())
    await explore(script, limit=10_000)
    assert "LIMIT 500 " in script.sql(ROW_MARK) + " "
    script = Script(FULL, answers())
    await explore(script, limit=0)
    assert "LIMIT 1 " in script.sql(ROW_MARK) + " "


@pytest.mark.asyncio
async def test_bucket_width_keeps_the_timeline_within_the_bound() -> None:
    for seconds in (3600, 6 * 3600, 86400, 7 * 86400, 31 * 86400):
        width = bucket_seconds(seconds)
        assert 60 <= width <= 86400
        assert seconds // width + 2 <= 200, seconds
    assert bucket_seconds(3600) == 60
    assert bucket_seconds(86400) == 900
    assert bucket_seconds(7 * 86400) == 3600
    script = Script(FULL, answers())
    await explore(script)
    assert script.params(TIMELINE_MARK)["param_bucket"] == str(bucket_seconds(86400))


@pytest.mark.asyncio
async def test_a_timeline_over_the_bound_is_refused_not_truncated() -> None:
    too_many = [{"bucket": SEEN + 900 * n, "agg_bytes": "1", "agg_flows": "1"} for n in range(201)]
    script = Script(FULL, answers(**{TIMELINE_MARK: {"data": too_many}}))
    with pytest.raises(AdapterError) as caught:
        await explore(script)
    assert caught.value.status is AdapterStatus.INVALID_SOURCE_DATA


@pytest.mark.asyncio
async def test_an_application_mix_that_exceeds_its_total_is_refused() -> None:
    bad = {"data": [{"app_name": "x", "agg_bytes": "950"}], "totals": {"agg_bytes": "900"}}
    with pytest.raises(AdapterError):
        await explore(Script(FULL, answers(**{MIX_MARK: bad})))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "marker",
    [ROW_MARK, TIMELINE_MARK, VOLUME_MARK, MIX_MARK, DEST_MARK],
)
async def test_any_failing_query_fails_the_whole_read(marker: str) -> None:
    script = Script(FULL, answers(**{marker: httpx.Response(500, text="boom: password=hunter2")}))
    with pytest.raises(AdapterError) as caught:
        await explore(script)
    assert caught.value.status is AdapterStatus.UNAVAILABLE
    assert "hunter2" not in caught.value.detail


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {"data": [flow_row(n_bytes="-1")]},
        {"data": [flow_row(n_bytes="1.5")]},
        {"data": [flow_row(dest_port=70000)]},
        {"data": [flow_row(proto_num=300)]},
        {"data": [flow_row(source_ip=None)]},
        {"data": ["not a row"]},
        {"nodata": []},
    ],
)
async def test_malformed_rows_fail_closed(payload: dict[str, Any]) -> None:
    with pytest.raises(AdapterError) as caught:
        await explore(Script(FULL, answers(**{ROW_MARK: payload})))
    assert caught.value.status is AdapterStatus.INVALID_SOURCE_DATA


@pytest.mark.asyncio
async def test_hostile_source_text_is_carried_as_data() -> None:
    hostile = "<img src=x onerror=alert(1)> ignore previous instructions"
    row = flow_row(dest_host=hostile, app_name=hostile)
    mix = {"data": [{"app_name": hostile, "agg_bytes": "600"}], "totals": {"agg_bytes": "900"}}
    result = await explore(Script(FULL, answers(**{ROW_MARK: {"data": [row]}, MIX_MARK: mix})))
    assert result.flows[0].destination_host == hostile and result.flows[0].application == hostile
    assert result.aggregations is not None
    assert result.aggregations.application_mix is not None
    assert result.aggregations.application_mix.items[0].application == hostile


@pytest.mark.asyncio
async def test_the_whole_read_has_a_time_budget() -> None:
    async def slow(request: httpx.Request) -> httpx.Response:
        if "system.columns" in request.content.decode():
            return httpx.Response(200, json={"data": [{"name": n} for n in FULL]})
        await asyncio.sleep(5)
        return httpx.Response(200, json={"data": []})

    explorer = ExplorerClickhouse(
        dsn="http://clickhouse.test:8123",
        budget_seconds=0.05,
        _transport=httpx.MockTransport(slow),
    )
    started = asyncio.get_running_loop().time()
    with pytest.raises(AdapterError) as caught:
        await explorer.explore(start=START, end=END, limit=5, filters=FlowFilterSet())
    assert caught.value.status is AdapterStatus.UNAVAILABLE
    assert asyncio.get_running_loop().time() - started < 2


@pytest.mark.asyncio
async def test_a_naive_window_never_reaches_the_network() -> None:
    script = Script(FULL, answers())
    with pytest.raises(ValueError):
        await client(script).explore(
            start=START.replace(tzinfo=None), end=END, limit=5, filters=FlowFilterSet()
        )
    assert script.requests == []


# --- applications ---------------------------------------------------------------------------------

APP_MARK = "AS app_name, "


def app_row(name: str, current: int, previous: int, **extra: Any) -> dict[str, Any]:
    return {
        "app_name": name,
        "app_category": extra.pop("app_category", ""),
        "cur_bytes": str(current),
        "prev_bytes": str(previous),
        "cur_packets": str(current // 100),
        "agg_endpoints": "3",
        "agg_seen": SEEN,
        **extra,
    }


def app_answers(rows: list[dict[str, Any]], current: int, previous: int) -> dict[str, Any]:
    return {
        "cur_bytes": {
            "data": rows,
            "totals": {"app_name": "", "cur_bytes": str(current), "prev_bytes": str(previous)},
        }
    }


async def applications(script: Script, **kw: Any):
    return await client(script).applications(start=START, end=END, limit=kw.pop("limit", 25))


@pytest.mark.asyncio
async def test_applications_rank_by_bytes_with_trend_against_the_previous_window() -> None:
    rows = [
        app_row("Microsoft 365", 600, 400, app_category="Productivity"),
        app_row("Zoom", 200, 500),
        app_row("Dropbox", 100, 100),
        app_row("NewApp", 100, 0),
    ]
    script = Script(FULL, app_answers(rows, 1000, 1000))
    result = await applications(script)

    assert result.unsupported == ()
    assert result.total_bytes == 1000
    assert result.previous_range == (START - (END - START), START)
    by_name = {r.application: r for r in result.rows}
    assert [r.rank for r in result.rows] == [1, 2, 3, 4]
    assert by_name["Microsoft 365"].category == "Productivity"
    assert by_name["Microsoft 365"].trend.state == "up"
    assert by_name["Microsoft 365"].trend.change_ratio == pytest.approx(0.5)
    assert by_name["Zoom"].trend.state == "down"
    assert by_name["Dropbox"].trend.state == "flat"
    assert by_name["NewApp"].trend.state == "new"
    assert by_name["NewApp"].trend.previous_bytes == 0
    assert by_name["Zoom"].category is None
    assert by_name["Microsoft 365"].share == pytest.approx(0.6)
    assert by_name["Microsoft 365"].endpoints == 3
    assert by_name["Microsoft 365"].users is None  # needs per-flow identity attribution: not done
    assert all(r.risk == "unknown" and r.approval == "unknown" for r in result.rows)  # policy's job
    assert result.observed_at == datetime(2026, 10, 5, 23, 30, tzinfo=UTC)


@pytest.mark.asyncio
async def test_applications_query_is_one_bounded_parameterised_read_over_two_windows() -> None:
    script = Script(FULL, app_answers([], 0, 0))
    await applications(script, limit=7)
    (request,) = script.data_requests
    sql = request.content.decode()
    params = {k: v[0] for k, v in parse_qs(str(request.url.query, "ascii")).items()}
    assert params["param_pstart"] == str(int((START - (END - START)).timestamp()))
    assert params["param_start"] == str(int(START.timestamp()))
    # one extra group: the source's "no application" group is dropped, so the limit still fills
    assert "LIMIT 8 " in sql + " " and "WITH TOTALS" in sql and "FORMAT JSON" in sql
    assert "GROUP BY app_name" in sql


@pytest.mark.asyncio
async def test_no_traffic_before_the_window_means_the_trend_is_unknown_not_new() -> None:
    # An empty previous window is a source with no history, not evidence that everything is new.
    script = Script(FULL, app_answers([app_row("Zoom", 500, 0)], 500, 0))
    result = await applications(script)
    assert result.rows[0].trend.state == "unknown"
    assert result.rows[0].trend.previous_bytes is None


@pytest.mark.asyncio
async def test_a_long_window_has_no_previous_window() -> None:
    script = Script(FULL, app_answers([app_row("Zoom", 500, 0)], 500, 0))
    result = await client(script).applications(start=END - timedelta(days=20), end=END, limit=5)
    assert result.previous_range is None
    assert result.rows[0].trend.state == "unknown"
    assert "pstart" not in script.data_requests[0].content.decode()


@pytest.mark.asyncio
async def test_a_source_without_applications_is_unsupported_not_empty() -> None:
    script = Script(CORE, {})
    result = await applications(script)
    assert result.unsupported == ("application",)
    assert result.rows == () and result.total_bytes is None
    assert script.data_requests == []


@pytest.mark.asyncio
async def test_application_text_and_counts_are_validated() -> None:
    hostile = "<script>alert(1)</script>"
    ok = await applications(Script(FULL, app_answers([app_row(hostile, 10, 10)], 10, 10)))
    assert ok.rows[0].application == hostile
    with pytest.raises(AdapterError):
        await applications(Script(FULL, app_answers([app_row("x", -5, 0)], 10, 10)))


# --- destinations -------------------------------------------------------------------------------------

DEST_COLS = "AS dest_bytes"


def dest_row(address: str, bytes_: int, **extra: Any) -> dict[str, Any]:
    return {
        "address": address,
        "dest_host": "",
        "dest_asn": 0,
        "dest_country": "",
        "dest_bytes": str(bytes_),
        "dest_packets": str(bytes_ // 100),
        "dest_endpoints": "4",
        "last_seen": SEEN,
        **extra,
    }


def dest_answers(
    rows: list[dict[str, Any]], total: int, first: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        DEST_COLS: {"data": rows, "totals": {"address": "", "dest_bytes": str(total)}},
        "AS first_seen": {"data": first},
    }


@pytest.mark.asyncio
async def test_destinations_carry_only_what_the_source_reports() -> None:
    rows = [
        dest_row(
            "::ffff:203.0.113.9",
            700,
            dest_host="cdn.example.net",
            dest_asn=64500,
            dest_country="ZA",
        ),
        dest_row("198.51.100.7", 200),
    ]
    first = [{"address": "203.0.113.9", "first_seen": SEEN - 86400}]
    script = Script(FULL, dest_answers(rows, 900, first))
    result = await client(script).destinations(start=START, end=END, limit=10)

    assert result.total_bytes == 900
    assert result.first_seen_since == END - timedelta(days=31)
    a, b = result.rows
    assert (a.rank, a.address, a.domain, a.asn, a.country) == (
        1,
        "203.0.113.9",
        "cdn.example.net",
        64500,
        "ZA",
    )
    assert a.first_seen == datetime.fromtimestamp(SEEN - 86400, tz=UTC)
    assert a.last_seen == datetime.fromtimestamp(SEEN, tz=UTC)
    assert a.share == pytest.approx(700 / 900) and a.endpoints == 4 and a.users is None
    assert (b.domain, b.asn, b.country, b.first_seen) == (None, None, None, None)
    assert a.reputation == b.reputation == "unknown"  # classification is the policy's job


@pytest.mark.asyncio
async def test_destinations_without_optional_columns_report_nulls() -> None:
    script = Script(
        CORE,
        {
            DEST_COLS: {
                "data": [
                    {
                        "address": "198.51.100.7",
                        "dest_bytes": "5",
                        "dest_endpoints": "1",
                        "last_seen": SEEN,
                    }
                ],
                "totals": {"dest_bytes": "5"},
            },
            "AS first_seen": {"data": []},
        },
    )
    result = await client(script).destinations(start=START, end=END, limit=10)
    row = result.rows[0]
    assert (row.domain, row.asn, row.country, row.packets) == (None, None, None, None)
    sql = script.sql(DEST_COLS)
    assert "DstHostname" not in sql and "DstAS" not in sql and "DstCountry" not in sql


@pytest.mark.asyncio
async def test_first_seen_is_a_bounded_lookback_query_not_an_unbounded_scan() -> None:
    script = Script(FULL, dest_answers([dest_row("198.51.100.7", 5)], 5, []))
    await client(script).destinations(start=START, end=END, limit=10)
    sql = script.sql("AS first_seen")
    params = script.params("AS first_seen")
    assert params["param_lookback"] == str(int((END - timedelta(days=31)).timestamp()))
    assert "IN (SELECT" in sql and "LIMIT 10" in sql and "FORMAT JSON" in sql
    assert "{lookback:UInt32}" in sql


@pytest.mark.asyncio
async def test_a_first_seen_after_last_seen_is_dropped_not_reported() -> None:
    first = [{"address": "198.51.100.7", "first_seen": SEEN + 5000}]
    script = Script(FULL, dest_answers([dest_row("198.51.100.7", 5)], 5, first))
    result = await client(script).destinations(start=START, end=END, limit=10)
    assert result.rows[0].first_seen is None


@pytest.mark.asyncio
async def test_destination_asn_and_country_must_be_valid() -> None:
    for bad in (
        dest_row("198.51.100.7", 5, dest_asn=-1),
        dest_row("198.51.100.7", 5, dest_country="zz1"),
    ):
        with pytest.raises(AdapterError):
            await client(Script(FULL, dest_answers([bad], 5, []))).destinations(
                start=START, end=END, limit=10
            )


# --- baseline inputs -------------------------------------------------------------------------------------

FIRST_ASN = "AS first_asn"
FIRST_DEST = "AS first_address"
OLDEST = "AS oldest"
FIRST_HOUR = datetime(2026, 10, 5, 0, tzinfo=UTC)
LAST_HOUR = datetime(2026, 10, 6, 0, tzinfo=UTC)


def hour(n: int) -> int:
    return int(FIRST_HOUR.timestamp()) + n * 3600


def baseline_answers(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "AS total_hour": {
            "data": [
                {"total_hour": hour(-24 * 7), "agg_bytes": "100"},
                {"total_hour": hour(0), "agg_bytes": "500"},
            ]
        },
        "AS app_hour": {
            "data": [
                {"app_hour": hour(0), "app_name": "Zoom", "agg_bytes": "300"},
                {"app_hour": hour(1), "app_name": "Zoom", "agg_bytes": "50"},
                {"app_hour": hour(1), "app_name": "Teams", "agg_bytes": "90"},
            ]
        },
        OLDEST: {"data": [{"oldest": hour(-24 * 20), "agg_rows": "9000"}]},
        "AS total_sources": {"data": [{"total_sources": "40"}]},
        "AS app_sources": {
            "data": [
                {"app_name": "Zoom", "app_sources": "30"},
                {"app_name": "Teams", "app_sources": "2"},
            ]
        },
        FIRST_ASN: {"data": [{"first_asn": "64501", "agg_bytes": "800", "first_seen": hour(3)}]},
        FIRST_DEST: {
            "data": [
                {
                    "first_address": "198.51.100.7",
                    "dest_host": "files.example.net",
                    "agg_bytes": "700",
                    "first_seen": hour(4),
                }
            ]
        },
    }
    base.update(overrides)
    return base


async def inputs(script: Script):
    return await client(script).anomaly_inputs(first_hour=FIRST_HOUR, last_hour=LAST_HOUR)


@pytest.mark.asyncio
async def test_baseline_inputs_cover_the_lookback_and_the_window() -> None:
    script = Script(FULL, baseline_answers())
    result = await inputs(script)

    assert result.hourly_total == {hour(-24 * 7): 100, hour(0): 500}
    assert list(result.hourly_apps) == ["Zoom", "Teams"]  # ranked by volume inside the window
    assert result.hourly_apps["Zoom"] == {hour(0): 300, hour(1): 50}
    assert result.applications_reported is True
    assert result.oldest == datetime.fromtimestamp(hour(-24 * 20), tz=UTC)
    assert [(f.kind, f.asn, f.address, f.domain, f.bytes) for f in result.first_seen] == [
        ("first-seen-asn", 64501, None, None, 800),
        ("first-seen-destination", None, "198.51.100.7", "files.example.net", 700),
    ]
    lookback = int((FIRST_HOUR - timedelta(weeks=4)).timestamp())
    assert script.params("AS total_hour")["param_range_from"] == str(lookback)
    assert script.params("AS total_hour")["param_range_to"] == str(int(LAST_HOUR.timestamp()))


@pytest.mark.asyncio
async def test_every_baseline_query_is_bounded() -> None:
    script = Script(FULL, baseline_answers())
    await inputs(script)
    assert 4 <= len(script.data_requests) <= 8
    for request in script.data_requests:
        sql = request.content.decode()
        assert "FORMAT JSON" in sql and "LIMIT" in sql and "SELECT *" not in sql
        assert "TimeReceived` >=" in sql
        assert not re.search(r"INSERT|ALTER|DROP|CREATE|SYSTEM", sql, re.IGNORECASE)


@pytest.mark.asyncio
async def test_without_applications_only_the_total_series_is_read() -> None:
    columns = [c for c in FULL if c != "Application"]
    answers_ = baseline_answers()
    del answers_["AS app_hour"], answers_["AS app_sources"]
    script = Script(columns, answers_)
    result = await inputs(script)
    assert result.applications_reported is False and result.hourly_apps == {}
    assert "app_hour" not in "".join(r.content.decode() for r in script.data_requests)


@pytest.mark.asyncio
async def test_without_an_asn_column_no_asn_flags_are_read() -> None:
    columns = [c for c in FULL if c != "DstAS"]
    answers_ = baseline_answers()
    del answers_[FIRST_ASN]
    result = await inputs(Script(columns, answers_))
    assert {f.kind for f in result.first_seen} == {"first-seen-destination"}


@pytest.mark.asyncio
async def test_an_empty_source_has_no_history() -> None:
    empty = baseline_answers(
        **{
            "AS total_hour": {"data": []},
            "AS app_hour": {"data": []},
            OLDEST: {"data": [{"oldest": 0, "agg_rows": "0"}]},
            FIRST_ASN: {"data": []},
            FIRST_DEST: {"data": []},
        }
    )
    result = await inputs(Script(FULL, empty))
    assert result.hourly_total == {} and result.oldest is None and result.first_seen == ()


@pytest.mark.asyncio
async def test_a_result_set_at_its_row_cap_is_refused_not_truncated() -> None:
    rows = [{"total_hour": hour(n), "agg_bytes": "1"} for n in range(1001)]
    with pytest.raises(AdapterError) as caught:
        await inputs(Script(FULL, baseline_answers(**{"AS total_hour": {"data": rows}})))
    assert caught.value.status is AdapterStatus.INVALID_SOURCE_DATA


@pytest.mark.asyncio
async def test_baseline_rows_must_land_on_the_hour() -> None:
    rows = [{"total_hour": hour(0) + 7, "agg_bytes": "1"}]
    with pytest.raises(AdapterError):
        await inputs(Script(FULL, baseline_answers(**{"AS total_hour": {"data": rows}})))


@pytest.mark.asyncio
async def test_baseline_window_must_be_whole_hours_and_ordered() -> None:
    script = Script(FULL, baseline_answers())
    with pytest.raises(ValueError):
        await client(script).anomaly_inputs(
            first_hour=FIRST_HOUR + timedelta(minutes=5), last_hour=LAST_HOUR
        )
    with pytest.raises(ValueError):
        await client(script).anomaly_inputs(first_hour=LAST_HOUR, last_hour=FIRST_HOUR)
    assert script.requests == []


# --- live (opt-in) -----------------------------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.skipif(
    not os.environ.get("CLICKHOUSE_TEST_DSN"),
    reason="set CLICKHOUSE_TEST_DSN to run the live ClickHouse integration test",
)
async def test_live_step7_reads_are_bounded_and_typed() -> None:
    """Opt-in smoke test of the Step 7 reads against a real ClickHouse (never fabricated).

    The live table may be empty, lack optional columns or be absent, so the only contract asserted is
    that each bounded read completes with a parsed result or a typed ``AdapterError``: never an
    unhandled exception, never invented rows.
    """
    live = ExplorerClickhouse(
        dsn=os.environ["CLICKHOUSE_TEST_DSN"],
        user=os.environ.get("CLICKHOUSE_TEST_USER", ""),
        password=os.environ.get("CLICKHOUSE_TEST_PASSWORD", ""),
        flows_table=os.environ.get("CLICKHOUSE_TEST_TABLE", "flows"),
    )
    end = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(hours=6)
    reads = (
        live.explore(start=start, end=end, limit=10, filters=FlowFilterSet(protocol="tcp")),
        live.applications(start=start, end=end, limit=10),
        live.destinations(start=start, end=end, limit=10),
        live.anomaly_inputs(first_hour=end - timedelta(hours=2), last_hour=end),
    )
    for read in reads:
        try:
            result = await read
        except AdapterError as exc:
            assert exc.status in {
                AdapterStatus.UNAVAILABLE,
                AdapterStatus.INVALID_SOURCE_DATA,
                AdapterStatus.FORBIDDEN,
            }
            continue
        assert result is not None


# --- bounded cost: approximate distinct counts and typed comparisons (security review HIGH-1) ---------------


@pytest.mark.asyncio
async def test_distinct_counts_use_uniq_on_the_typed_column() -> None:
    script = Script(FULL, answers())
    await explore(script)
    volume = script.sql(VOLUME_MARK)
    assert "uniq(`SrcAddr`)" in volume and "uniq(`DstAddr`)" in volume
    assert "uniqExact" not in volume and "uniq(toString" not in volume


@pytest.mark.asyncio
async def test_application_and_destination_endpoint_counts_use_uniq_too() -> None:
    script = Script(
        FULL,
        {
            "AS app_name": {"data": [], "totals": {"cur_bytes": "0", "prev_bytes": "0"}},
        },
    )
    await client(script).applications(start=START, end=END, limit=5)
    sql = script.sql("AS app_name")
    assert "uniqIf(" in sql and "uniqExact" not in sql

    script = Script(
        FULL,
        {
            "AS dest_endpoints": {"data": [], "totals": {"dest_bytes": "0"}},
            "AS first_seen": {"data": []},
        },
    )
    await client(script).destinations(start=START, end=END, limit=5)
    sql = script.sql("AS dest_endpoints")
    assert "uniqIf(" in sql and "uniqExact" not in sql


@pytest.mark.asyncio
async def test_text_filters_compare_the_column_without_converting_every_row() -> None:
    filters = FlowFilterSet(device="edge", application="x", country="ZA", direction="outbound")
    script = Script(FULL, answers())
    await explore(script, filters)
    sql = script.sql(ROW_MARK)
    for converted in ("Application", "ExporterName", "SrcCountry", "DstCountry", "InIfBoundary"):
        assert f"toString(`{converted}`) =" not in sql and f"toString(`{converted}`) IN" not in sql
    assert "`ExporterName` = {f_device:String}" in sql
    assert "`Application` = {f_application:String}" in sql
    assert "`SrcCountry` = {f_country:String}" in sql


@pytest.mark.asyncio
async def test_address_filters_use_a_typed_ipv6_comparison_when_the_column_is_ipv6() -> None:
    script = Script(FULL, answers(), types={"SrcAddr": "IPv6", "DstAddr": "IPv6"})
    filters = FlowFilterSet(source_ip="10.1.2.3", destination_ip="2001:db8::1")
    await explore(script, filters)
    sql = script.sql(ROW_MARK)
    assert "`SrcAddr` IN ({f_src_0:IPv6})" in sql
    assert "`DstAddr` IN ({f_dst_0:IPv6})" in sql
    assert "toString(`SrcAddr`) IN" not in sql and "toString(`DstAddr`) IN" not in sql
    params = script.params(ROW_MARK)
    assert params["param_f_src_0"] == "::ffff:10.1.2.3"  # an IPv4 address is stored mapped
    assert "param_f_src_1" not in params
    assert params["param_f_dst_0"] == "2001:db8::1"


@pytest.mark.asyncio
async def test_address_filters_fall_back_to_text_when_the_column_type_is_unknown() -> None:
    script = Script(FULL, answers())
    await explore(script, FlowFilterSet(source_ip="10.1.2.3"))
    assert "toString(`SrcAddr`) IN ({f_src_0:String}, {f_src_1:String})" in script.sql(ROW_MARK)


# --- scope and cohort inputs (security review HIGH-2) -----------------------------------------------------


@pytest.mark.asyncio
async def test_destination_shares_say_whether_the_address_is_inside_the_organisation() -> None:
    script = Script(
        FULL,
        answers(
            **{
                DEST_MARK: {
                    "data": [
                        {"address": "203.0.113.9", "agg_bytes": "500"},
                        {"address": "::ffff:192.168.1.20", "agg_bytes": "300"},
                        {"address": "fd00::5", "agg_bytes": "100"},
                    ],
                    "totals": {"agg_bytes": "900"},
                }
            }
        ),
    )
    result = await explore(script)
    assert result.aggregations is not None
    assert [(d.address, d.scope) for d in result.aggregations.destinations] == [
        ("203.0.113.9", "external"),
        ("192.168.1.20", "internal"),
        ("fd00::5", "internal"),
    ]


@pytest.mark.asyncio
async def test_destination_rows_say_whether_the_address_is_inside_the_organisation() -> None:
    rows = [dest_row("10.1.1.5", 600), dest_row("198.51.100.7", 300)]
    script = Script(FULL, dest_answers(rows, 900, []))
    result = await client(script).destinations(start=START, end=END, limit=10)
    assert [(r.address, r.scope) for r in result.rows] == [
        ("10.1.1.5", "internal"),
        ("198.51.100.7", "external"),
    ]


@pytest.mark.asyncio
async def test_first_seen_rows_carry_how_many_sources_reached_them() -> None:
    answers_ = baseline_answers(
        **{
            FIRST_ASN: {
                "data": [
                    {
                        "first_asn": "64501",
                        "agg_bytes": "800",
                        "agg_endpoints": "2",
                        "first_seen": hour(3),
                    }
                ]
            },
            FIRST_DEST: {
                "data": [
                    {
                        "first_address": "198.51.100.7",
                        "agg_bytes": "700",
                        "agg_endpoints": "9",
                        "first_seen": hour(4),
                    }
                ]
            },
        }
    )
    script = Script(FULL, answers_)
    result = await inputs(script)
    assert [(f.kind, f.endpoints) for f in result.first_seen] == [
        ("first-seen-asn", 2),
        ("first-seen-destination", 9),
    ]
    for marker in (FIRST_ASN, FIRST_DEST):  # sources inside the window only, approximate counts
        sql = script.sql(marker)
        assert "AND `TimeReceived` >= toDateTime({obs_from:UInt32}))" in sql
        assert "isIPAddressInRange" in sql and "uniqExact" not in sql


@pytest.mark.asyncio
async def test_a_first_seen_row_without_a_count_reports_none() -> None:
    result = await inputs(Script(FULL, baseline_answers()))
    assert all(f.endpoints is None for f in result.first_seen)


# --- the cohort denominator is internal endpoints (second re-review, HIGH 3) -------------------------------

BOUNDARY_SIDE = (
    "if(`InIfBoundary` = 'external' AND `OutIfBoundary` = 'internal', `DstAddr`, `SrcAddr`)"
)
IN_ORGANISATION = "isIPAddressInRange(replaceRegexpOne(toString("
PLAIN = [c for c in FULL if c not in {"InIfBoundary", "OutIfBoundary"}]


def prefixes_of(params: dict[str, str]) -> list[str]:
    raw = params["param_internal"]
    assert raw.startswith("[") and raw.endswith("]")
    return [item.strip("'") for item in raw[1:-1].split(",")]


@pytest.mark.asyncio
async def test_the_cohort_counts_the_internal_side_of_each_flow_by_direction() -> None:
    script = Script(FULL, answers())
    await explore(script)
    volume = script.sql(VOLUME_MARK)
    assert f"uniqIf({BOUNDARY_SIDE}," in volume  # inbound flows count the destination
    assert IN_ORGANISATION in volume
    assert "AS agg_internal" in volume
    # The all-addresses figures are still reported, but they are not the cohort count.
    assert "uniq(`SrcAddr`)" in volume and "AS agg_sources" in volume


@pytest.mark.asyncio
async def test_without_interface_boundaries_the_source_address_is_the_internal_side() -> None:
    script = Script(PLAIN, answers())
    await explore(script)
    volume = script.sql(VOLUME_MARK)
    assert "uniqIf(`SrcAddr`," in volume and "InIfBoundary" not in volume


@pytest.mark.asyncio
async def test_the_internal_prefixes_are_one_bound_parameter_never_sql_text() -> None:
    script = Script(FULL, answers())
    await explore(script)
    volume = script.sql(VOLUME_MARK)
    assert "{internal:Array(String)}" in volume
    assert "10.0.0.0/8" not in volume and "fc00::/7" not in volume
    prefixes = prefixes_of(script.params(VOLUME_MARK))
    for expected in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
        "fc00::/7", "fe80::/10", "198.18.0.0/15", "192.0.0.0/24", "240.0.0.0/4", "0.0.0.0/8",
    ):  # fmt: skip
        assert expected in prefixes


@pytest.mark.asyncio
async def test_configured_internal_prefixes_reach_the_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NETSIGHT_INTERNAL_PREFIXES", "203.0.113.0/24")
    script = Script(FULL, answers())
    await explore(script)
    assert "203.0.113.0/24" in prefixes_of(script.params(VOLUME_MARK))


@pytest.mark.asyncio
async def test_mix_shares_and_the_summary_lists_all_count_the_internal_side() -> None:
    script = Script(FULL, answers())
    await explore(script)
    for marker in ("GROUP BY app_name", DEST_MARK):
        sql = script.sql(marker)
        assert f"uniqIf({BOUNDARY_SIDE}," in sql and "AS agg_endpoints" in sql
        assert "param_internal" in script.params(marker)

    empty_apps = {"AS app_name": {"data": [], "totals": {"cur_bytes": "0", "prev_bytes": "0"}}}
    script = Script(FULL, empty_apps)
    await client(script).applications(start=START, end=END, limit=5)
    assert f"uniqIf({BOUNDARY_SIDE}," in script.sql("AS app_name")
    assert "param_internal" in script.params("AS app_name")

    empty_dests = {
        "AS dest_endpoints": {"data": [], "totals": {"dest_bytes": "0"}},
        "AS first_seen": {"data": []},
    }
    script = Script(FULL, empty_dests)
    await client(script).destinations(start=START, end=END, limit=5)
    assert f"uniqIf({BOUNDARY_SIDE}," in script.sql("AS dest_endpoints")
    assert "param_internal" in script.params("AS dest_endpoints")


@pytest.mark.asyncio
async def test_first_seen_counts_internal_endpoints_in_the_window_only() -> None:
    script = Script(FULL, baseline_answers())
    await inputs(script)
    for marker in (FIRST_ASN, FIRST_DEST):
        sql = script.sql(marker)
        assert f"uniqIf({BOUNDARY_SIDE}," in sql and "param_internal" in script.params(marker)


@pytest.mark.asyncio
async def test_the_volume_reports_the_internal_endpoint_count() -> None:
    payload = answers()
    payload[VOLUME_MARK] = {
        "data": [
            {
                "agg_bytes": "900", "agg_packets": "9", "agg_flows": "5", "agg_sources": "20",
                "agg_destinations": "1", "agg_internal": "1",
            }
        ]
    }  # fmt: skip
    result = await explore(Script(FULL, payload))
    assert result.aggregations is not None
    volume = result.aggregations.volume
    assert (volume.source_addresses, volume.internal_endpoints) == (20, 1)


@pytest.mark.asyncio
async def test_an_unreported_internal_endpoint_count_is_none_not_a_guess() -> None:
    result = await explore(Script(FULL, answers()))  # the default payload carries no agg_internal
    assert result.aggregations is not None
    assert result.aggregations.volume.internal_endpoints is None


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["-1", "1.5", "many", True])
async def test_a_malformed_internal_endpoint_count_fails_the_read(bad: Any) -> None:
    payload = answers()
    payload[VOLUME_MARK]["data"][0]["agg_internal"] = bad
    with pytest.raises(AdapterError):
        await explore(Script(FULL, payload))


@pytest.mark.asyncio
async def test_mix_items_and_shares_carry_their_internal_endpoint_counts() -> None:
    payload = answers()
    payload[MIX_MARK]["data"][0]["agg_endpoints"] = "7"
    payload[DEST_MARK]["data"][0]["agg_endpoints"] = "3"
    result = await explore(Script(FULL, payload))
    assert result.aggregations is not None
    mix = result.aggregations.application_mix
    assert mix is not None
    assert [(i.visibility, i.endpoints) for i in mix.items] == [("shown", 7), ("shown", None)]
    assert [(d.visibility, d.endpoints) for d in result.aggregations.destinations] == [
        ("shown", 3),
        ("shown", None),
    ]


@pytest.mark.asyncio
async def test_application_and_destination_rows_carry_internal_endpoint_counts() -> None:
    rows = [app_row("Zoom", 700, 100, agg_endpoints="6")]
    result = await applications(Script(FULL, app_answers(rows, 700, 100)))
    assert result.rows[0].endpoints == 6 and result.rows[0].visibility == "shown"
    destination = dest_row("198.51.100.7", 300, dest_endpoints="8")
    found = await client(Script(FULL, dest_answers([destination], 300, []))).destinations(
        start=START, end=END, limit=10
    )
    assert found.rows[0].endpoints == 8 and found.rows[0].visibility == "shown"


# --- source-level freshness (second re-review, HIGH 4) --------------------------------------------------------


@pytest.mark.asyncio
async def test_the_aggregate_explorer_reads_the_source_level_newest_flow_without_rows() -> None:
    payload = answers(**{"AS source_seen": {"data": [{"source_seen": SEEN + 600}]}})
    del payload[ROW_MARK]
    script = Script(FULL, payload)
    result = await client(script).explore(
        start=START, end=END, limit=10, filters=FlowFilterSet(application="x"), include_rows=False
    )
    assert result.source_observed_at == datetime.fromtimestamp(SEEN + 600, tz=UTC)
    sql = script.sql("AS source_seen")
    assert "WHERE `TimeReceived` >=" in sql and "ExporterName" not in sql and "{f_" not in sql
    assert "LIMIT" in sql and "FORMAT JSON" in sql


@pytest.mark.asyncio
async def test_the_detail_explorer_does_not_pay_for_the_source_level_read() -> None:
    script = Script(FULL, answers())
    result = await explore(script)
    assert result.source_observed_at is None
    assert not [r for r in script.data_requests if "AS source_seen" in r.content.decode()]


@pytest.mark.asyncio
async def test_an_empty_window_has_no_source_level_time() -> None:
    payload = answers(**{"AS source_seen": {"data": [{"source_seen": 0}]}})
    del payload[ROW_MARK]
    result = await client(Script(FULL, payload)).explore(
        start=START, end=END, limit=10, filters=FlowFilterSet(), include_rows=False
    )
    assert result.source_observed_at is None


@pytest.mark.asyncio
async def test_applications_and_destinations_take_the_source_level_time_from_the_totals() -> None:
    rows = [app_row("Zoom", 700, 100, agg_seen=SEEN - 3000)]
    payload = app_answers(rows, 700, 100)
    payload["cur_bytes"]["totals"]["agg_seen"] = SEEN
    result = await applications(Script(FULL, payload))
    assert result.observed_at == datetime.fromtimestamp(SEEN - 3000, tz=UTC)
    assert result.source_observed_at == datetime.fromtimestamp(SEEN, tz=UTC)

    answers_ = dest_answers([dest_row("198.51.100.7", 300, last_seen=SEEN - 3000)], 300, [])
    answers_[DEST_COLS]["totals"]["last_seen"] = SEEN
    found = await client(Script(FULL, answers_)).destinations(start=START, end=END, limit=10)
    assert found.observed_at == datetime.fromtimestamp(SEEN - 3000, tz=UTC)
    assert found.source_observed_at == datetime.fromtimestamp(SEEN, tz=UTC)


@pytest.mark.asyncio
async def test_without_totals_the_source_level_time_is_none() -> None:
    result = await applications(Script(FULL, app_answers([app_row("Zoom", 700, 100)], 700, 100)))
    assert result.source_observed_at is None


# --- the hourly series' cohort inputs (second re-review, HIGH 5) -------------------------------------------------


def with_sources(**overrides: Any) -> dict[str, Any]:
    payload = baseline_answers()
    payload.update(overrides)
    return payload


@pytest.mark.asyncio
async def test_the_baseline_carries_internal_endpoint_counts_per_series() -> None:
    script = Script(FULL, with_sources())
    result = await inputs(script)
    assert result.sources_total == 40
    assert dict(result.sources_by_application) == {"Zoom": 30, "Teams": 2}
    for marker in ("AS total_sources", "AS app_sources"):
        sql = script.sql(marker)
        assert f"uniqIf({BOUNDARY_SIDE}," in sql and "param_internal" in script.params(marker)
        assert "LIMIT" in sql and "FORMAT JSON" in sql and "obs_from" in sql


@pytest.mark.asyncio
async def test_without_applications_only_the_total_count_is_read() -> None:
    columns = [c for c in FULL if c != "Application"]
    payload = with_sources()
    del payload["AS app_hour"], payload["AS app_sources"]
    result = await inputs(Script(columns, payload))
    assert result.sources_total == 40 and dict(result.sources_by_application) == {}


@pytest.mark.asyncio
async def test_a_source_that_does_not_count_endpoints_yields_none() -> None:
    payload = with_sources()
    payload["AS total_sources"] = {"data": [{"total_sources": None}]}
    result = await inputs(Script(FULL, payload))
    assert result.sources_total is None


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["-3", "x", 1.5])
async def test_malformed_series_counts_fail_the_read(bad: Any) -> None:
    payload = with_sources()
    payload["AS app_sources"] = {"data": [{"app_name": "Zoom", "app_sources": bad}]}
    with pytest.raises(AdapterError):
        await inputs(Script(FULL, payload))
