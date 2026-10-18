"""Flow Explorer, Applications, Destinations and baseline reads over the ClickHouse flow store.

Extends the S4-2 client (same connection, discovery, readonly-retry and error vocabulary) with the
bounded, parameterised reads of Step 7. Contract for every method:

* the caller's window and filters arrive as typed values and leave as ``param_*`` placeholders; no
  caller text is ever part of the SQL (``clickhouse_queries`` builds the text from constants);
* every read has a window, a ``LIMIT`` and a time budget (``budget_seconds`` for the whole method,
  with the independent queries of one request running concurrently and cancelled together);
* a value is source-reported or ``None``. A column the source lacks yields ``None`` (or an
  ``unsupported`` filter), never a default; a count that is negative, fractional or oversize fails
  the read instead of being clamped; a result that hit its row cap fails instead of being truncated;
* a failure raises ``AdapterError``; this layer never turns one into an empty success;
* every ``endpoints`` figure counts endpoints *inside the organisation* (see ``clickhouse_queries``),
  the denominator of the small-cohort rule; a count the source does not give is ``None``, which the
  rule treats as too few;
* ``source_observed_at`` is the newest flow the source holds in the window whatever the filter (the
  one freshness the aggregate tier is told); it is read without caller filters.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

from pydantic import ValidationError

from netsight_api.adapters import clickhouse_queries as q
from netsight_api.adapters.clickhouse import (
    AdapterError,
    AdapterStatus,
    ClickhouseClient,
    _data_rows,
    _optional_total,
    _parse_address,
    _parse_counter,
    _parse_epoch,
    _parse_optional_counter,
    _parse_optional_text,
    _parse_port,
    _parse_protocol,
    _window_params,
)
from netsight_api.adapters.clickhouse_queries import Params, bucket_seconds
from netsight_api.forecast.source import DailyTotals
from netsight_api.schemas_traffic import (
    TREND_FLAT_BAND,
    ApplicationMix,
    ApplicationMixItem,
    ApplicationRow,
    AppTrend,
    DestinationRow,
    DestinationScope,
    DestinationShare,
    FlowAggregations,
    FlowDirection,
    TimelineBucket,
    TrafficFlow,
    Volume,
)
from netsight_api.traffic import anomaly
from netsight_api.traffic.addresses import is_internal_address
from netsight_api.traffic.filters import FlowFilterSet
from netsight_api.traffic.source import (
    AnomalyInputs,
    ApplicationsRead,
    DestinationsRead,
    Exploration,
    FirstSeenRow,
)

__all__ = ["ExplorerClickhouse", "bucket_seconds"]

MAX_FLOW_ROWS = 500
MAX_LIST_ROWS = 100
MAX_DESTINATION_SHARES = 10
PREVIOUS_WINDOW_MAX = timedelta(days=7)
FIRST_SEEN_LOOKBACK = timedelta(days=31)
MAX_BASELINE_WINDOW = timedelta(days=7)
_BASELINE_LOOKBACK = timedelta(weeks=anomaly.WEEKS)
_ASN_MAX = 4294967295


def _invalid(detail: str) -> AdapterError:
    return AdapterError(AdapterStatus.INVALID_SOURCE_DATA, detail)


def _clamp(limit: int, ceiling: int) -> int:
    return max(1, min(int(limit), ceiling))


def _share(part: int, total: int) -> float | None:
    return (part / total) if total > 0 else None


def _boundary_direction(inbound: Any, outbound: Any) -> FlowDirection:
    """Direction from the source's own interface boundary classification; unknown otherwise."""
    pair = (inbound, outbound)
    if pair == ("external", "internal"):
        return "inbound"
    if pair == ("internal", "external"):
        return "outbound"
    if pair == ("internal", "internal"):
        return "internal"
    return "unknown"


def _scope(address: str) -> DestinationScope:
    """Inside the organisation (private, loopback, link-local, shared, multicast) or outside it."""
    return "internal" if is_internal_address(address) else "external"


def _optional_asn(value: Any) -> int | None:
    number = _parse_optional_counter(value, "asn")
    if number is None or number == 0:
        return None
    if number > _ASN_MAX:
        raise _invalid("asn out of range")
    return number


def _optional_country(value: Any) -> str | None:
    text = _parse_optional_text(value, "country")
    if text is None:
        return None
    if len(text) != 2 or not text.isascii() or not text.isupper() or not text.isalpha():
        raise _invalid("invalid country code")
    return text


def _trend(current: int, previous: int | None, history_exists: bool) -> AppTrend:
    """Change against the preceding window; unknown when that window carried no traffic at all."""
    if previous is None or not history_exists:
        return AppTrend(state="unknown", previous_bytes=None, change_ratio=None)
    if previous == 0:
        return AppTrend(state="new", previous_bytes=0, change_ratio=None)
    ratio = (current - previous) / previous
    state = "flat"
    if ratio > TREND_FLAT_BAND:
        state = "up"
    elif ratio < -TREND_FLAT_BAND:
        state = "down"
    return AppTrend(state=state, previous_bytes=previous, change_ratio=ratio)  # type: ignore[arg-type]


def _midnight(day: date) -> int:
    return int(datetime(day.year, day.month, day.day, tzinfo=UTC).timestamp())


def _epoch(value: Any) -> datetime:
    return _parse_epoch(value)


@dataclass
class ExplorerClickhouse(ClickhouseClient):
    """The S4-2 client plus the Step 7 reads; ``budget_seconds`` bounds each whole read."""

    budget_seconds: float = 25.0

    # --- plumbing ------------------------------------------------------------------------------

    async def _bounded[T](self, work: Awaitable[T]) -> T:
        try:
            async with asyncio.timeout(self.budget_seconds):
                return await work
        except TimeoutError as exc:
            raise AdapterError(
                AdapterStatus.UNAVAILABLE, "clickhouse read exceeded its time budget"
            ) from exc

    async def _run(self, *queries: tuple[str, Params]) -> list[dict[str, Any]]:
        """Run independent queries concurrently; the first failure cancels the rest."""
        table = self._qualified_table()
        try:
            async with asyncio.TaskGroup() as group:
                tasks = [
                    group.create_task(self._query(sql.replace("{table}", table), params=params))
                    for sql, params in queries
                ]
        except* AdapterError as failures:
            raise failures.exceptions[0] from None
        return [task.result() for task in tasks]

    # --- Flow Explorer ---------------------------------------------------------------------------

    async def explore(
        self,
        *,
        start: datetime,
        end: datetime,
        limit: int,
        filters: FlowFilterSet,
        include_rows: bool = True,
    ) -> Exploration:
        """Rows (unless ``include_rows`` is false) and aggregations for the filtered window.

        ``include_rows=False`` never reads an endpoint row from the store: the aggregate rung of
        the Explorer (Management) is served from the aggregation queries alone.
        """
        window = _window_params(start, end)
        return await self._bounded(self._explore(window, start, end, limit, filters, include_rows))

    async def _explore(
        self,
        window: Mapping[str, str | int],
        start: datetime,
        end: datetime,
        limit: int,
        filters: FlowFilterSet,
        include_rows: bool,
    ) -> Exploration:
        columns = await self._ensure_columns()
        self._require(columns, *q.CORE_COLUMNS)
        where, bound, unsupported = q.build_where(filters, columns, self._types)
        if unsupported:
            return Exploration((), None, unsupported, None)
        base: Params = {**window, **bound}
        counted: Params = {**base, **q.internal_params()}
        bucket = bucket_seconds(int((end - start).total_seconds()))
        plan: dict[str, tuple[str, Params]] = {}
        if include_rows:
            plan["rows"] = (q.flow_rows(where, columns, _clamp(limit, MAX_FLOW_ROWS)), base)
        plan["timeline"] = (q.timeline(where, columns), {**base, "bucket": bucket})
        plan["volume"] = (q.volume(where, columns), counted)
        if "Application" in columns:
            plan["mix"] = (q.application_mix(where, columns), counted)
        plan["destinations"] = (
            q.destination_share(where, columns, MAX_DESTINATION_SHARES),
            counted,
        )
        if (
            not include_rows
        ):  # the aggregate tier is told the source's freshness, never this answer's
            plan["source_seen"] = (q.source_seen(), dict(window))
        payloads = dict(zip(plan, await self._run(*plan.values()), strict=True))
        flows, observed_at = self._flows(payloads["rows"], columns) if include_rows else ([], None)
        volume_seen = self._newest(payloads["volume"])
        if volume_seen is not None and (observed_at is None or volume_seen > observed_at):
            observed_at = volume_seen
        try:
            aggregations = FlowAggregations(
                bucket_seconds=bucket,
                timeline=self._timeline(payloads["timeline"], columns),
                volume=self._volume(payloads["volume"], columns),
                application_mix=self._mix(payloads["mix"]) if "mix" in payloads else None,
                destinations=self._shares(payloads["destinations"]),
            )
        except ValidationError as exc:
            raise _invalid("invalid traffic aggregate") from exc
        source_seen = (
            self._newest(payloads["source_seen"], "source_seen") if not include_rows else None
        )
        return Exploration(tuple(flows), aggregations, (), observed_at, source_seen)

    @staticmethod
    def _newest(payload: dict[str, Any], key: str = "agg_seen") -> datetime | None:
        rows = _data_rows(payload)
        seen = _parse_optional_counter(rows[0].get(key), "timestamp") if rows else None
        return _epoch(seen) if seen else None

    @staticmethod
    def _flows(
        payload: dict[str, Any], columns: frozenset[str]
    ) -> tuple[list[TrafficFlow], datetime | None]:
        flows: list[TrafficFlow] = []
        observed_at: datetime | None = None
        has_boundaries = "InIfBoundary" in columns and "OutIfBoundary" in columns
        for row in _data_rows(payload):
            seen = _epoch(row.get("seen_at"))
            observed_at = seen if observed_at is None or seen > observed_at else observed_at
            try:
                flows.append(
                    TrafficFlow(
                        observed_at=seen,
                        source_ip=_parse_address(row.get("source_ip"), "source_ip"),
                        source_device_id=None,
                        destination_ip=_parse_address(row.get("destination_ip"), "destination_ip"),
                        destination_host=_parse_optional_text(
                            row.get("dest_host"), "destination_host"
                        ),
                        protocol=_parse_protocol(row.get("proto_num")),
                        destination_port=_parse_port(row.get("dest_port")),
                        bytes=_parse_counter(row.get("n_bytes"), "bytes"),
                        packets=(
                            _parse_optional_counter(row.get("n_packets"), "packets")
                            if "Packets" in columns
                            else None
                        ),
                        direction=(
                            _boundary_direction(row.get("in_boundary"), row.get("out_boundary"))
                            if has_boundaries
                            else "unknown"
                        ),
                        application=_parse_optional_text(row.get("app_name"), "application"),
                        attribution=None,
                    )
                )
            except ValidationError as exc:
                raise _invalid("invalid flow row") from exc
        return flows, observed_at

    @staticmethod
    def _timeline(payload: dict[str, Any], columns: frozenset[str]) -> list[TimelineBucket]:
        rows = _data_rows(payload)
        if len(rows) > q.MAX_TIMELINE_BUCKETS:
            raise _invalid("timeline exceeds its bucket bound")
        buckets = [
            TimelineBucket(
                start=_epoch(row.get("bucket")),
                bytes=_parse_counter(row.get("agg_bytes"), "bytes"),
                packets=(
                    _parse_optional_counter(row.get("agg_packets"), "packets")
                    if "Packets" in columns
                    else None
                ),
                flows=_parse_counter(row.get("agg_flows"), "flows"),
            )
            for row in rows
        ]
        return sorted(buckets, key=lambda bucket: bucket.start)

    @staticmethod
    def _volume(payload: dict[str, Any], columns: frozenset[str]) -> Volume:
        rows = _data_rows(payload)
        if len(rows) != 1:
            raise _invalid("volume read returned no totals row")
        row = rows[0]
        return Volume(
            bytes=_parse_counter(row.get("agg_bytes"), "bytes"),
            packets=(
                _parse_optional_counter(row.get("agg_packets"), "packets")
                if "Packets" in columns
                else None
            ),
            flows=_parse_counter(row.get("agg_flows"), "flows"),
            source_addresses=_parse_counter(row.get("agg_sources"), "sources"),
            destination_addresses=_parse_counter(row.get("agg_destinations"), "destinations"),
            internal_endpoints=_parse_optional_counter(
                row.get("agg_internal"), "internal endpoints"
            ),
        )

    @staticmethod
    def _total(payload: dict[str, Any], key: str, rows: int) -> int:
        total = _optional_total(payload, key)
        if total is None:
            if rows:
                raise _invalid("clickhouse response is missing totals")
            return 0
        return total

    def _mix(self, payload: dict[str, Any]) -> ApplicationMix:
        rows = _data_rows(payload)
        total = self._total(payload, "agg_bytes", len(rows))
        items = [
            ApplicationMixItem(
                application=_parse_optional_text(row.get("app_name"), "application"),
                visibility="shown",
                bytes=(count := _parse_counter(row.get("agg_bytes"), "bytes")),
                share=_share(count, total),
                endpoints=_parse_optional_counter(row.get("agg_endpoints"), "endpoints"),
            )
            for row in rows
        ]
        listed = sum(item.bytes or 0 for item in items)
        if listed > total:
            raise _invalid("application mix exceeds its total")
        return ApplicationMix(items=items, other_bytes=total - listed, total_bytes=total)

    def _shares(self, payload: dict[str, Any]) -> list[DestinationShare]:
        rows = _data_rows(payload)
        total = self._total(payload, "agg_bytes", len(rows))
        return [
            DestinationShare(
                address=(address := _parse_address(row.get("address"), "address")),
                host=_parse_optional_text(row.get("dest_host"), "host"),
                scope=_scope(address),
                visibility="shown",
                bytes=(count := _parse_counter(row.get("agg_bytes"), "bytes")),
                share=_share(count, total),
                endpoints=_parse_optional_counter(row.get("agg_endpoints"), "endpoints"),
            )
            for row in rows
        ]

    # --- Applications -------------------------------------------------------------------------------

    async def applications(self, *, start: datetime, end: datetime, limit: int) -> ApplicationsRead:
        window = _window_params(start, end)
        return await self._bounded(self._applications(window, start, end, limit))

    async def _applications(
        self, window: Mapping[str, str | int], start: datetime, end: datetime, limit: int
    ) -> ApplicationsRead:
        columns = await self._ensure_columns()
        self._require(columns, "TimeReceived", "SrcAddr", "Bytes")
        if "Application" not in columns:
            return ApplicationsRead((), None, None, ("application",), None)
        length = end - start
        previous = length <= PREVIOUS_WINDOW_MAX
        params: Params = {**window, **q.internal_params()}
        previous_range: tuple[datetime, datetime] | None = None
        if previous:
            previous_start = start - length
            params["pstart"] = int(previous_start.timestamp())
            previous_range = (previous_start, start)
        bounded = _clamp(limit, MAX_LIST_ROWS)
        (payload,) = await self._run((q.applications(columns, bounded, previous=previous), params))
        return self._application_rows(payload, bounded, previous, previous_range)

    def _application_rows(
        self,
        payload: dict[str, Any],
        bounded: int,
        previous: bool,
        previous_range: tuple[datetime, datetime] | None,
    ) -> ApplicationsRead:
        data = _data_rows(payload)
        named = [row for row in data if _parse_optional_text(row.get("app_name"), "application")]
        total = self._total(payload, "cur_bytes", len(data))
        history = bool(_optional_total(payload, "prev_bytes")) if previous else False
        ranked = sorted(
            ((_parse_counter(row.get("cur_bytes"), "bytes"), row) for row in named),
            key=lambda pair: (-pair[0], str(pair[1].get("app_name"))),
        )[:bounded]
        try:
            rows = [
                self._application_row(rank, count, row, total, previous, history)
                for rank, (count, row) in enumerate(ranked, start=1)
            ]
        except ValidationError as exc:
            raise _invalid("invalid application row") from exc
        seen = [_parse_optional_counter(row.get("agg_seen"), "timestamp") for _, row in ranked]
        newest = max((_epoch(moment) for moment in seen if moment), default=None)
        return ApplicationsRead(
            tuple(rows), total, previous_range, (), newest, self._totals_seen(payload, "agg_seen")
        )

    @staticmethod
    def _totals_seen(payload: dict[str, Any], key: str) -> datetime | None:
        """The newest flow across every group (the ``WITH TOTALS`` row): source-level, not per row."""
        totals = payload.get("totals")
        if not isinstance(totals, dict):
            return None
        seen = _parse_optional_counter(totals.get(key), "timestamp")
        return _epoch(seen) if seen else None

    @staticmethod
    def _application_row(
        rank: int, count: int, row: dict[str, Any], total: int, previous: bool, history: bool
    ) -> ApplicationRow:
        earlier = _parse_optional_counter(row.get("prev_bytes"), "bytes") if previous else None
        return ApplicationRow(
            rank=rank,
            application=str(_parse_optional_text(row.get("app_name"), "application")),
            category=_parse_optional_text(row.get("app_category"), "category"),
            visibility="shown",
            bytes=count,
            packets=_parse_optional_counter(row.get("cur_packets"), "packets"),
            share=_share(count, total),
            endpoints=_parse_optional_counter(row.get("agg_endpoints"), "endpoints"),
            users=None,
            trend=_trend(count, earlier, history),
            risk="unknown",
            approval="unknown",
        )

    # --- Destinations -------------------------------------------------------------------------------

    async def destinations(self, *, start: datetime, end: datetime, limit: int) -> DestinationsRead:
        window = _window_params(start, end)
        return await self._bounded(self._destinations(window, end, limit))

    async def _destinations(
        self, window: Mapping[str, str | int], end: datetime, limit: int
    ) -> DestinationsRead:
        columns = await self._ensure_columns()
        self._require(columns, *q.CORE_COLUMNS)
        bounded = _clamp(limit, MAX_LIST_ROWS)
        lookback = end - FIRST_SEEN_LOOKBACK
        main, first = await self._run(
            (q.destinations(columns, bounded), {**window, **q.internal_params()}),
            (q.destinations_first_seen(bounded), {**window, "lookback": int(lookback.timestamp())}),
        )
        rows = _data_rows(main)
        total = self._total(main, "dest_bytes", len(rows))
        first_seen = {
            _parse_address(row.get("address"), "address"): _epoch(row.get("first_seen"))
            for row in _data_rows(first)
        }
        result: list[DestinationRow] = []
        newest: datetime | None = None
        try:
            for rank, row in enumerate(rows, start=1):
                address = _parse_address(row.get("address"), "address")
                count = _parse_counter(row.get("dest_bytes"), "bytes")
                last_seen = _epoch(row.get("last_seen"))
                newest = last_seen if newest is None or last_seen > newest else newest
                earliest = first_seen.get(address)
                result.append(
                    DestinationRow(
                        rank=rank,
                        address=address,
                        scope=_scope(address),
                        visibility="shown",
                        domain=_parse_optional_text(row.get("dest_host"), "domain"),
                        asn=_optional_asn(row.get("dest_asn")),
                        country=_optional_country(row.get("dest_country")),
                        first_seen=earliest
                        if earliest is not None and earliest <= last_seen
                        else None,
                        last_seen=last_seen,
                        bytes=count,
                        packets=_parse_optional_counter(row.get("dest_packets"), "packets"),
                        share=_share(count, total),
                        endpoints=_parse_optional_counter(row.get("dest_endpoints"), "endpoints"),
                        users=None,
                        reputation="unknown",
                    )
                )
        except ValidationError as exc:
            raise _invalid("invalid destination row") from exc
        return DestinationsRead(
            tuple(result), total, lookback, newest, self._totals_seen(main, "last_seen")
        )

    # --- baseline inputs -----------------------------------------------------------------------------

    async def anomaly_inputs(self, *, first_hour: datetime, last_hour: datetime) -> AnomalyInputs:
        if first_hour.tzinfo is None or last_hour.tzinfo is None:
            raise ValueError("the baseline window must be timezone-aware")
        for moment in (first_hour, last_hour):
            if moment.minute or moment.second or moment.microsecond:
                raise ValueError("the baseline window runs on whole hours")
        if not first_hour < last_hour or last_hour - first_hour > MAX_BASELINE_WINDOW:
            raise ValueError("the baseline window is ordered and at most a week")
        return await self._bounded(self._anomaly_inputs(first_hour, last_hour))

    async def _anomaly_inputs(self, first_hour: datetime, last_hour: datetime) -> AnomalyInputs:
        columns = await self._ensure_columns()
        self._require(columns, "TimeReceived", "SrcAddr", "DstAddr", "Bytes")
        params: Params = {
            "range_from": int((first_hour - _BASELINE_LOOKBACK).timestamp()),
            "range_to": int(last_hour.timestamp()),
            "obs_from": int(first_hour.timestamp()),
        }
        has_apps = "Application" in columns
        has_asn = "DstAS" in columns
        counted: Params = {**params, **q.internal_params()}
        plan: list[tuple[str, str, Params]] = [("total", q.baseline_total_hours(), params)]
        if has_apps:
            plan.append(("apps", q.baseline_application_hours(), params))
        plan.append(("oldest", q.baseline_oldest(), params))
        plan.append(("total_sources", q.baseline_sources_total(columns), counted))
        if has_apps:
            plan.append(("app_sources", q.baseline_sources_by_application(columns), counted))
        if has_asn:
            plan.append(("asn", q.first_seen_asns(columns), counted))
        plan.append(("dest", q.first_seen_destinations(columns), counted))
        payloads = dict(
            zip(
                (name for name, _, _ in plan),
                await self._run(*[(s, p) for _, s, p in plan]),
                strict=True,
            )
        )

        hourly_total = self._hourly_totals(payloads["total"])
        hourly_apps = self._hourly_apps(payloads["apps"], first_hour, last_hour) if has_apps else {}
        first_seen = [
            *(self._first_seen_asns(payloads["asn"]) if has_asn else []),
            *self._first_seen_destinations(payloads["dest"]),
        ]
        newest = max(hourly_total, default=None)
        return AnomalyInputs(
            hourly_total=hourly_total,
            hourly_apps=hourly_apps,
            applications_reported=has_apps,
            oldest=self._oldest(payloads["oldest"]),
            first_seen=tuple(first_seen),
            observed_at=datetime.fromtimestamp(newest, tz=UTC) if newest is not None else None,
            sources_total=self._sources_total(payloads["total_sources"]),
            sources_by_application=(
                self._sources_by_application(payloads["app_sources"]) if has_apps else {}
            ),
        )

    # --- capacity forecast inputs ---------------------------------------------------------------

    async def daily_totals(self, *, first_day: date, end_day: date) -> DailyTotals:
        """Bytes per whole UTC day for ``first_day <= day < end_day`` (at most 120 days)."""
        if not first_day < end_day or (end_day - first_day).days > q.MAX_DAILY_ROWS:
            raise ValueError("the daily window is ordered and at most 120 days")
        return await self._bounded(self._daily_totals(first_day, end_day))

    async def _daily_totals(self, first_day: date, end_day: date) -> DailyTotals:
        columns = await self._ensure_columns()
        self._require(columns, "TimeReceived", "Bytes")
        params: Params = {"range_from": _midnight(first_day), "range_to": _midnight(end_day)}
        days, edges = await self._run((q.daily_totals(), params), (q.daily_edges(), params))
        rows = _data_rows(days)
        if len(rows) > q.MAX_DAILY_ROWS:
            raise _invalid("daily totals hit their row cap")
        daily: dict[date, int] = {}
        for row in rows:
            day = self._day(row.get("total_day"))
            if not first_day <= day < end_day:
                raise _invalid("daily bucket is outside the requested window")
            daily[day] = _parse_counter(row.get("agg_bytes"), "bytes")
        return self._with_edges(daily, edges)

    @staticmethod
    def _day(value: Any) -> date:
        seconds = _parse_counter(value, "day")
        if seconds % 86_400:
            raise _invalid("daily bucket is not on a UTC midnight")
        return datetime.fromtimestamp(seconds, tz=UTC).date()

    @staticmethod
    def _with_edges(daily: dict[date, int], edges: dict[str, Any]) -> DailyTotals:
        rows = _data_rows(edges)
        if len(rows) != 1:
            raise _invalid("daily edge read returned no row")
        if _parse_counter(rows[0].get("agg_rows"), "rows") == 0:
            return DailyTotals(daily, None, None)
        return DailyTotals(
            daily, _epoch(rows[0].get("first_seen")), _epoch(rows[0].get("last_seen"))
        )

    @staticmethod
    def _sources_total(payload: dict[str, Any]) -> int | None:
        rows = _data_rows(payload)
        if len(rows) != 1:
            raise _invalid("endpoint count returned no row")
        return _parse_optional_counter(rows[0].get("total_sources"), "endpoints")

    @staticmethod
    def _sources_by_application(payload: dict[str, Any]) -> dict[str, int]:
        found: dict[str, int] = {}
        for row in _data_rows(payload):
            name = _parse_optional_text(row.get("app_name"), "application")
            count = _parse_optional_counter(row.get("app_sources"), "endpoints")
            if name is not None and count is not None:
                found[name] = count
        return found

    @staticmethod
    def _hour(value: Any) -> int:
        hour = _parse_counter(value, "hour")
        if hour % anomaly.HOUR_SECONDS:
            raise _invalid("hourly bucket is not on the hour")
        return hour

    def _hourly_totals(self, payload: dict[str, Any]) -> dict[int, int]:
        rows = _data_rows(payload)
        if len(rows) > q.MAX_BASELINE_TOTAL_ROWS:
            raise _invalid("hourly totals hit their row cap")
        return {
            self._hour(row.get("total_hour")): _parse_counter(row.get("agg_bytes"), "bytes")
            for row in rows
        }

    def _hourly_apps(
        self, payload: dict[str, Any], first_hour: datetime, last_hour: datetime
    ) -> dict[str, dict[int, int]]:
        rows = _data_rows(payload)
        if len(rows) > q.MAX_BASELINE_APP_ROWS:
            raise _invalid("hourly application series hit their row cap")
        series: dict[str, dict[int, int]] = {}
        for row in rows:
            name = _parse_optional_text(row.get("app_name"), "application")
            if name is None:
                continue
            series.setdefault(name, {})[self._hour(row.get("app_hour"))] = _parse_counter(
                row.get("agg_bytes"), "bytes"
            )
        low, high = int(first_hour.timestamp()), int(last_hour.timestamp())
        volume = {
            name: sum(count for hour, count in hours.items() if low <= hour < high)
            for name, hours in series.items()
        }
        ranked = sorted(series, key=lambda name: (-volume[name], name))
        return {name: series[name] for name in ranked[: q.MAX_BASELINE_APPLICATIONS]}

    @staticmethod
    def _oldest(payload: dict[str, Any]) -> datetime | None:
        rows = _data_rows(payload)
        if len(rows) != 1:
            raise _invalid("history read returned no row")
        count = _parse_counter(rows[0].get("agg_rows"), "rows")
        return _epoch(rows[0].get("oldest")) if count > 0 else None

    @staticmethod
    def _first_seen_asns(payload: dict[str, Any]) -> list[FirstSeenRow]:
        found: list[FirstSeenRow] = []
        for row in _data_rows(payload):
            number = _optional_asn(row.get("first_asn"))
            if number is None:
                continue
            found.append(
                FirstSeenRow(
                    "first-seen-asn",
                    number,
                    None,
                    None,
                    _epoch(row.get("first_seen")),
                    _parse_counter(row.get("agg_bytes"), "bytes"),
                    _parse_optional_counter(row.get("agg_endpoints"), "endpoints"),
                )
            )
        return found

    @staticmethod
    def _first_seen_destinations(payload: dict[str, Any]) -> list[FirstSeenRow]:
        return [
            FirstSeenRow(
                "first-seen-destination",
                None,
                _parse_address(row.get("first_address"), "address"),
                _parse_optional_text(row.get("dest_host"), "domain"),
                _epoch(row.get("first_seen")),
                _parse_counter(row.get("agg_bytes"), "bytes"),
                _parse_optional_counter(row.get("agg_endpoints"), "endpoints"),
            )
            for row in _data_rows(payload)
        ]
