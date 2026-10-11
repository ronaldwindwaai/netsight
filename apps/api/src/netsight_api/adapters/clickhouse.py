"""Read-only ClickHouse (Akvorado) flow adapter for bounded traffic reads.

This module owns the DSN handling, identifier validation, parameterised SQL
and source-data validation for the flow store. Values are bound through
ClickHouse ``param_*`` placeholders (server-side typed substitution); table,
database and column identifiers only ever come from validated configuration
or this module's own constants — never from source output.

Source failures raise typed errors; this layer never converts a failed read
into an empty successful result. The API degrades failures to the explicit
``unknown`` traffic state.

Verified against the ClickHouse HTTP interface (26.10): ``param_*`` URL
binding, backtick-qualified identifiers, ``GROUP BY .. WITH TOTALS ..
FORMAT JSON`` (``totals`` is present even for zero rows), ``system.columns``
discovery under a readonly identity, and readonly identities rejecting URL
settings. Server-side limits are sent when the identity may set them and the refusal is
remembered for the process (``clickhouse_limits``).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from urllib.parse import unquote, urlsplit

import httpx
from pydantic import ValidationError

from netsight_api.adapters import clickhouse_limits as limits
from netsight_api.schemas import TrafficDimension, TrafficItem

ADAPTER_VERSION = "clickhouse/1"
SOURCE_NAME = "clickhouse"

FlowProtocol = Literal["tcp", "udp", "icmp", "other"]

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}(?:\.[A-Za-z_][A-Za-z0-9_]{0,127})?$")
_IPV4_MAPPED = re.compile(r"^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$", re.IGNORECASE)

# IANA protocol numbers that map to a contract protocol value. Any other
# number is contractually "other"; non-numbers are invalid source data.
_PROTOCOL_NUMBERS: dict[int, FlowProtocol] = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmp"}

# Client-side row bound (the API layer already enforces it per endpoint). The Flow Explorer, the
# Applications and Destinations roll-ups and the baseline reads live in ``clickhouse_explorer``.
_MAX_TOP_LIMIT = 100


class AdapterStatus(StrEnum):
    """Typed source outcomes (same vocabulary as the other adapters)."""

    UNAVAILABLE = "unavailable"
    FORBIDDEN = "forbidden"
    INVALID_SOURCE_DATA = "invalid-source-data"


class AdapterError(Exception):
    """Source failure with a stable status; detail never contains secrets."""

    def __init__(self, status: AdapterStatus, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


class _SettingsForbidden(Exception):
    """Internal signal: the identity may not modify settings (readonly)."""


def _parse_counter(value: Any, field_name: str) -> int:
    """Parse a source counter (integer or decimal string) into a bounded int."""
    if isinstance(value, bool):
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, f"invalid {field_name} counter")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and value.isdecimal():
        parsed = int(value)
    else:
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, f"invalid {field_name} counter")
    if parsed < 0:
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, f"negative {field_name} counter")
    return parsed


def _parse_optional_counter(value: Any, field_name: str) -> int | None:
    """Counter that is None when the source reports no value for the column."""
    if value is None:
        return None
    return _parse_counter(value, field_name)


def _parse_epoch(value: Any) -> datetime:
    """Convert a source unix timestamp (seconds, UTC) into an aware datetime."""
    seconds = _parse_counter(value, "timestamp")
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "timestamp out of range") from exc


def _parse_optional_text(value: Any, field_name: str) -> str | None:
    """Source text field: absent or empty means no value, never a guess."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, f"invalid {field_name}")
    return value or None


def _parse_address(value: Any, field_name: str) -> str:
    """Source-reported address text; IPv4-mapped IPv6 renders as plain IPv4."""
    text = _parse_optional_text(value, field_name)
    if text is None:
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, f"missing {field_name}")
    match = _IPV4_MAPPED.match(text)
    return match.group(1) if match else text


def _parse_port(value: Any) -> int | None:
    """Destination port: None when unknown, otherwise 0..65535."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid destination port")
    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and value.isdecimal():
        port = int(value)
    else:
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid destination port")
    if not 0 <= port <= 65535:
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "destination port out of range")
    return port


def _parse_protocol(value: Any) -> FlowProtocol:
    """Map an IANA protocol number onto the contract protocol enum."""
    if isinstance(value, bool):
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid protocol number")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.isdecimal():
        number = int(value)
    else:
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid protocol number")
    if not 0 <= number <= 255:
        # Outside the IP-protocol byte range the column is not a protocol.
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "protocol number out of range")
    return _PROTOCOL_NUMBERS.get(number, "other")


def _data_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract and validate the ``data`` array of a FORMAT JSON response."""
    rows = payload.get("data")
    if not isinstance(rows, list):
        raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "clickhouse response is missing rows")
    result: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise AdapterError(
                AdapterStatus.INVALID_SOURCE_DATA, "clickhouse returned a malformed row"
            )
        result.append(row)
    return result


def _optional_total(payload: dict[str, Any], key: str) -> int | None:
    """Grand total from ``WITH TOTALS`` when present (share denominator)."""
    totals = payload.get("totals")
    if not isinstance(totals, dict) or key not in totals:
        return None
    return _parse_counter(totals[key], "total")


def _window_params(start: datetime, end: datetime) -> dict[str, int]:
    """Bound the query to an aware, ordered window as unix seconds (UTC)."""
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("traffic window must be timezone-aware")
    if start >= end:
        raise ValueError("traffic window must be ordered")
    return {"start": int(start.timestamp()), "end": int(end.timestamp())}


def _raise_for_status(response: httpx.Response, *, with_limits: bool) -> None:
    """Typed errors for a refused or failed query; a refused *setting* is told apart."""
    if 300 <= response.status_code < 400:
        raise AdapterError(AdapterStatus.UNAVAILABLE, "clickhouse returned an unexpected redirect")
    if response.status_code in (401, 403):
        raise AdapterError(
            AdapterStatus.FORBIDDEN, "clickhouse rejected the configured credentials"
        )
    if response.status_code >= 400:
        if with_limits and limits.settings_refused(response.text):
            raise _SettingsForbidden()
        raise AdapterError(AdapterStatus.UNAVAILABLE, "clickhouse query failed")


@dataclass
class ClickhouseClient:
    """Read-only flow-query client for one configured ClickHouse endpoint.

    ``dsn``, ``user`` and ``password`` are excluded from ``repr`` so
    credentials and the service-account name can never leak through logging
    or test output.
    """

    dsn: str = field(repr=False)
    user: str = field(default="", repr=False)
    password: str = field(default="", repr=False)
    flows_table: str = "flows"
    timeout_seconds: float = 10.0
    _transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)
    _columns: frozenset[str] | None = field(default=None, init=False, repr=False)
    _types: dict[str, str] = field(default_factory=dict, init=False, repr=False)

    async def top(
        self,
        *,
        dimension: TrafficDimension,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> tuple[list[TrafficItem], datetime | None]:
        """Ranked source/destination aggregates for a bounded window.

        Returns the rows and the newest flow timestamp among them, or None
        when the window carried no rows at all.
        """
        params = _window_params(start, end)
        address_column = "SrcAddr" if dimension == "talkers" else "DstAddr"
        columns = await self._ensure_columns()
        self._require(columns, "TimeReceived", "Bytes", address_column)
        bounded = max(1, min(int(limit), _MAX_TOP_LIMIT))
        include_packets = "Packets" in columns
        select = [
            f"toString(`{address_column}`) AS label",
            "toString(sum(`Bytes`)) AS agg_bytes",
            *(["toString(sum(`Packets`)) AS agg_packets"] if include_packets else []),
            "toUnixTimestamp(max(`TimeReceived`)) AS agg_seen",
        ]
        sql = (
            f"SELECT {', '.join(select)} FROM {self._qualified_table()} "
            "WHERE `TimeReceived` >= toDateTime({start:UInt32}) "
            "AND `TimeReceived` < toDateTime({end:UInt32}) "
            "GROUP BY label WITH TOTALS ORDER BY sum(`Bytes`) DESC "
            f"LIMIT {bounded} FORMAT JSON"
        )
        payload = await self._query(sql, params=params)
        total_bytes = _optional_total(payload, "agg_bytes")

        items: list[TrafficItem] = []
        observed_at: datetime | None = None
        for rank, row in enumerate(_data_rows(payload), start=1):
            byte_count = _parse_counter(row.get("agg_bytes"), "bytes")
            packets = (
                _parse_optional_counter(row.get("agg_packets"), "packets")
                if include_packets
                else None
            )
            seen = _parse_epoch(row.get("agg_seen"))
            observed_at = seen if observed_at is None or seen > observed_at else observed_at
            share = (byte_count / total_bytes) if total_bytes else None
            try:
                items.append(
                    TrafficItem(
                        rank=rank,
                        subject_kind="ip",
                        subject_id=None,
                        label=_parse_address(row.get("label"), "label"),
                        bytes=byte_count,
                        packets=packets,
                        share=share,
                    )
                )
            except ValidationError as exc:
                raise AdapterError(
                    AdapterStatus.INVALID_SOURCE_DATA, "invalid traffic aggregate row"
                ) from exc
        return items, observed_at

    async def _ensure_columns(self) -> frozenset[str]:
        """Discover the flows table's columns once per client instance."""
        if self._columns is None:
            database, table = self._split_table()
            payload = await self._query(
                "SELECT name, type FROM system.columns "
                "WHERE database = {db:String} AND table = {table:String} FORMAT JSON",
                params={"db": database, "table": table},
            )
            names: set[str] = set()
            for row in _data_rows(payload):
                name = row.get("name")
                if not isinstance(name, str) or not name:
                    raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "invalid column listing")
                names.add(name)
                column_type = row.get("type")
                if isinstance(column_type, str):
                    self._types[name] = column_type
            if not names:
                raise AdapterError(AdapterStatus.INVALID_SOURCE_DATA, "flows table not found")
            self._columns = frozenset(names)
        return self._columns

    @staticmethod
    def _require(columns: frozenset[str], *required: str) -> None:
        """Fail closed when the table lacks a column a query depends on."""
        missing = [name for name in required if name not in columns]
        if missing:
            raise AdapterError(
                AdapterStatus.INVALID_SOURCE_DATA,
                f"flows table is missing required column(s): {', '.join(missing)}",
            )

    def _split_table(self) -> tuple[str, str]:
        """Split the configured table into validated database/table parts."""
        table = self.flows_table
        if not _IDENTIFIER.fullmatch(table):
            raise AdapterError(
                AdapterStatus.UNAVAILABLE, "flows table name is not a valid identifier"
            )
        if "." in table:
            database, _, name = table.partition(".")
            return database, name
        return "default", table

    def _qualified_table(self) -> str:
        """Backtick-quoted, identifier-validated table reference."""
        database, table = self._split_table()
        return f"`{database}`.`{table}`"

    def _connection(self) -> tuple[str, tuple[str, str] | None]:
        """Derive (base_url, auth) from the DSN without exposing the secret."""
        try:
            parsed = urlsplit(self.dsn)
            port = parsed.port
        except ValueError as exc:
            raise AdapterError(AdapterStatus.UNAVAILABLE, "clickhouse DSN is invalid") from exc
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise AdapterError(AdapterStatus.UNAVAILABLE, "clickhouse DSN is invalid")
        if parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            raise AdapterError(AdapterStatus.UNAVAILABLE, "clickhouse DSN is invalid")
        host = parsed.hostname
        if ":" in host:
            host = f"[{host}]"
        base_url = f"{parsed.scheme}://{host}{f':{port}' if port else ''}"
        user, password = self.user, self.password
        if not user and parsed.username is not None:
            user = unquote(parsed.username)
            password = unquote(parsed.password or "")
        return base_url, (user, password) if user else None

    async def _query(self, sql: str, *, params: Mapping[str, str | int]) -> dict[str, Any]:
        """Run one read with the server-side limits, or without them for a readonly identity.

        The first refusal marks the (endpoint, user) as profile-limited for the life of the process,
        so later reads (on new client instances) do not repeat the failed attempt.
        """
        key = self._capability_key()
        if not limits.may_send_settings(key):
            return await self._post(sql, params, with_limits=False)
        try:
            payload = await self._post(sql, params, with_limits=True)
        except _SettingsForbidden:
            limits.mark_profile_only(key)
            return await self._post(sql, params, with_limits=False)
        limits.mark_enforced(key)
        return payload

    def _capability_key(self) -> limits.CapabilityKey:
        base_url, auth = self._connection()
        return base_url, auth[0] if auth else ""

    async def _post(
        self, sql: str, params: Mapping[str, str | int], *, with_limits: bool
    ) -> dict[str, Any]:
        """POST one parameterised query; errors raise typed AdapterErrors."""
        base_url, auth = self._connection()
        url_params: dict[str, str | int] = {
            f"param_{name}": value for name, value in params.items()
        }
        if with_limits:
            url_params.update(limits.limit_settings(self.timeout_seconds))
        timeout = httpx.Timeout(self.timeout_seconds, connect=5.0)
        try:
            async with httpx.AsyncClient(
                base_url=base_url,
                timeout=timeout,
                auth=auth,
                transport=self._transport,
                # Never follow a redirect from the flow store: a 3xx could
                # silently resend the Authorization header to another host.
                follow_redirects=False,
            ) as client:
                response = await client.post("/", params=url_params, content=sql)
        except httpx.TimeoutException as exc:
            raise AdapterError(AdapterStatus.UNAVAILABLE, "clickhouse request timed out") from exc
        except httpx.HTTPError as exc:
            raise AdapterError(AdapterStatus.UNAVAILABLE, "clickhouse request failed") from exc

        _raise_for_status(response, with_limits=with_limits)
        try:
            payload = json.loads(response.text)
        except json.JSONDecodeError as exc:
            raise AdapterError(
                AdapterStatus.INVALID_SOURCE_DATA, "clickhouse returned invalid JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise AdapterError(
                AdapterStatus.INVALID_SOURCE_DATA, "clickhouse returned an unexpected response"
            )
        return payload
