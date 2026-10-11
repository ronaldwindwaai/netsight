"""SQL text for the Step 7 flow reads: pure functions, no I/O, no caller text.

Every function returns SQL plus the typed ``param_*`` values to bind. A caller's filter value is only
ever a *parameter* (``{f_name:Type}``); identifiers are this module's constants, and the only table
reference is the validated one passed in. Every query has a time window and a ``LIMIT``, ends in
``FORMAT JSON`` and is a plain ``SELECT``. Column availability comes from schema discovery: a filter
whose column is absent is reported as unsupported instead of being dropped.

Distinct counts use ``uniq`` (adaptive sampling over a 64-bit hash; exact in practice for the small
cardinalities the cohort rule cares about, a close estimate above that), not ``uniqExact``, which holds
every key in memory. Filters compare the typed column; they do not render a string per row.

``Bytes`` is summed as stored. Akvorado's own UI scales by ``SamplingRate``; this surface does not,
because an extrapolation is an estimate (docs/04-integrations/AKVORADO-CLICKHOUSE.md).
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from typing import Final

from netsight_api.schemas_traffic import FilterName
from netsight_api.traffic.filters import FlowFilterSet, ip_candidates

Params = dict[str, str | int]

WINDOW: Final = (
    "`TimeReceived` >= toDateTime({start:UInt32}) AND `TimeReceived` < toDateTime({end:UInt32})"
)
CORE_COLUMNS: Final = ("TimeReceived", "SrcAddr", "DstAddr", "Proto", "Bytes")
HOUR_SECONDS: Final = 3600
BUCKET_STEPS: Final = (60, 300, 900, 3600, 4 * 3600, 86400)
MAX_TIMELINE_BUCKETS: Final = 200
MAX_MIX_GROUPS: Final = 11
MAX_BASELINE_TOTAL_ROWS: Final = 1000
MAX_BASELINE_APPLICATIONS: Final = 10
MAX_BASELINE_APP_ROWS: Final = 8400
FIRST_SEEN_DESTINATION_POOL: Final = 1000
FIRST_SEEN_ASN_LIMIT: Final = 50
FIRST_SEEN_DESTINATION_LIMIT: Final = 100

_PROTOCOL_CLAUSES: Final = {
    "tcp": "`Proto` = 6",
    "udp": "`Proto` = 17",
    "icmp": "`Proto` IN (1, 58)",
    "other": "`Proto` NOT IN (1, 6, 17, 58)",
}
# Typed comparisons: the boundary column is an Enum (or text) and the literal converts once, so the
# store compares the stored value instead of rendering a string for every row.
_DIRECTION_CLAUSES: Final = {
    "inbound": "(`InIfBoundary` = 'external' AND `OutIfBoundary` = 'internal')",
    "outbound": "(`InIfBoundary` = 'internal' AND `OutIfBoundary` = 'external')",
    "internal": "(`InIfBoundary` = 'internal' AND `OutIfBoundary` = 'internal')",
}


def bucket_seconds(window_seconds: int) -> int:
    """The narrowest bucket that keeps the timeline (plus one partial bucket) within its bound."""
    for step in BUCKET_STEPS:
        if -(-window_seconds // step) + 1 <= MAX_TIMELINE_BUCKETS:
            return step
    return BUCKET_STEPS[-1]


def _either(columns: Collection[str], candidates: tuple[str, ...], expression: str) -> str | None:
    """``(A = x OR B = x)`` over whichever of the candidate columns exist; None when neither does."""
    present = [column for column in candidates if column in columns]
    if not present:
        return None
    return "(" + " OR ".join(expression.format(column=column) for column in present) + ")"


def _address_clause(
    column: str, label: str, address: str, column_type: str | None
) -> tuple[str, Params]:
    """``column IN (...)``: typed against an IPv6 column (IPv4 is stored mapped), text otherwise.

    The text form is the fallback when discovery did not report the column type: it matches both the
    plain and the IPv4-mapped spelling but renders every row's address, so it is the slower path.
    """
    bound: Params = {}
    names = []
    typed = column_type is not None and column_type.startswith("IPv6")
    spellings = ip_candidates(address)
    if typed:
        spellings = spellings[-1:]  # the mapped spelling for IPv4, the address itself for IPv6
    for index, spelling in enumerate(spellings):
        name = f"f_{label}_{index}"
        bound[name] = spelling
        names.append(f"{{{name}:{'IPv6' if typed else 'String'}}}")
    subject = f"`{column}`" if typed else f"toString(`{column}`)"
    return f"{subject} IN ({', '.join(names)})", bound


Clause = tuple[FilterName, str | None, Params]  # (filter, SQL or None when unsupported, bound)


def _endpoint_clauses(
    filters: FlowFilterSet, columns: Collection[str], types: Mapping[str, str]
) -> list[Clause]:
    """Clauses for the filters that narrow a read to a place: addresses, device and VLAN."""
    found: list[Clause] = []
    if filters.source_ip is not None:
        found.append(
            (
                "source_ip",
                *_address_clause("SrcAddr", "src", filters.source_ip, types.get("SrcAddr")),
            )
        )
    if filters.destination_ip is not None:
        address = _address_clause("DstAddr", "dst", filters.destination_ip, types.get("DstAddr"))
        found.append(("destination_ip", *address))
    if filters.device is not None:
        clause = "`ExporterName` = {f_device:String}" if "ExporterName" in columns else None
        found.append(("device", clause, {"f_device": filters.device}))
    if filters.vlan is not None:
        clause = _either(columns, ("SrcVlan", "DstVlan"), "`{column}` = {{f_vlan:UInt16}}")
        found.append(("vlan", clause, {"f_vlan": filters.vlan}))
    return found


def _traffic_clauses(filters: FlowFilterSet, columns: Collection[str]) -> list[Clause]:
    """Clauses for the filters that describe the traffic itself."""
    found: list[Clause] = []
    if filters.application is not None:
        clause = "`Application` = {f_application:String}" if "Application" in columns else None
        found.append(("application", clause, {"f_application": filters.application}))
    if filters.protocol is not None:
        found.append(("protocol", _PROTOCOL_CLAUSES[filters.protocol], {}))
    if filters.port is not None:
        clause = (
            _either(columns, ("DstPort", "SrcPort"), "`{column}` = {{f_port:UInt16}}")
            if "DstPort" in columns
            else None
        )
        found.append(("port", clause, {"f_port": filters.port}))
    if filters.country is not None:
        clause = _either(columns, ("SrcCountry", "DstCountry"), "`{column}` = {{f_country:String}}")
        found.append(("country", clause, {"f_country": filters.country}))
    if filters.asn is not None:
        clause = _either(columns, ("SrcAS", "DstAS"), "`{column}` = {{f_asn:UInt32}}")
        found.append(("asn", clause, {"f_asn": filters.asn}))
    if filters.direction is not None:
        both = "InIfBoundary" in columns and "OutIfBoundary" in columns
        found.append(("direction", _DIRECTION_CLAUSES[filters.direction] if both else None, {}))
    return found


def build_where(
    filters: FlowFilterSet, columns: Collection[str], types: Mapping[str, str] | None = None
) -> tuple[str, Params, tuple[FilterName, ...]]:
    """The WHERE clause for the filters, its parameters, and the filters the source can not honour.

    ``types`` maps a column to its discovered ClickHouse type, when known (address filters use it).
    """
    clauses = [WINDOW]
    params: Params = {}
    unsupported: list[FilterName] = []
    found = [*_endpoint_clauses(filters, columns, types or {}), *_traffic_clauses(filters, columns)]
    for name, clause, bound in found:
        if clause is None:
            unsupported.append(name)
            continue
        clauses.append(clause)
        params.update(bound)
    return " AND ".join(clauses), params, tuple(unsupported)


def flow_rows(where: str, columns: Collection[str], limit: int) -> str:
    select = [
        "toUnixTimestamp(`TimeReceived`) AS seen_at",
        "toString(`SrcAddr`) AS source_ip",
        "toString(`DstAddr`) AS destination_ip",
        "toString(`Bytes`) AS n_bytes",
        "`Proto` AS proto_num",
    ]
    optional = (
        ("Packets", "toString(`Packets`) AS n_packets"),
        ("DstPort", "`DstPort` AS dest_port"),
        ("DstHostname", "toString(`DstHostname`) AS dest_host"),
        ("Application", "toString(`Application`) AS app_name"),
    )
    select.extend(expression for column, expression in optional if column in columns)
    if "InIfBoundary" in columns and "OutIfBoundary" in columns:
        select.append("toString(`InIfBoundary`) AS in_boundary")
        select.append("toString(`OutIfBoundary`) AS out_boundary")
    return (
        f"SELECT {', '.join(select)} FROM {{table}} WHERE {where} "
        f"ORDER BY `Bytes` DESC LIMIT {limit} FORMAT JSON"
    )


def timeline(where: str, columns: Collection[str]) -> str:
    packets = ", toString(sum(`Packets`)) AS agg_packets" if "Packets" in columns else ""
    return (
        "SELECT intDiv(toUnixTimestamp(`TimeReceived`), {bucket:UInt32}) * {bucket:UInt32} AS bucket, "
        f"toString(sum(`Bytes`)) AS agg_bytes{packets}, toString(count()) AS agg_flows "
        f"FROM {{table}} WHERE {where} GROUP BY bucket ORDER BY bucket "
        f"LIMIT {MAX_TIMELINE_BUCKETS + 1} FORMAT JSON"
    )


def volume(where: str, columns: Collection[str]) -> str:
    packets = ", toString(sum(`Packets`)) AS agg_packets" if "Packets" in columns else ""
    return (
        f"SELECT toString(sum(`Bytes`)) AS agg_bytes{packets}, toString(count()) AS agg_flows, "
        "toString(uniq(`SrcAddr`)) AS agg_sources, "
        "toString(uniq(`DstAddr`)) AS agg_destinations, "
        "toUnixTimestamp(max(`TimeReceived`)) AS agg_seen "
        f"FROM {{table}} WHERE {where} LIMIT 1 FORMAT JSON"
    )


def application_mix(where: str) -> str:
    return (
        "SELECT toString(`Application`) AS app_name, toString(sum(`Bytes`)) AS agg_bytes "
        f"FROM {{table}} WHERE {where} GROUP BY app_name WITH TOTALS "
        f"ORDER BY sum(`Bytes`) DESC LIMIT {MAX_MIX_GROUPS} FORMAT JSON"
    )


def _hostname(columns: Collection[str]) -> str:
    if "DstHostname" not in columns:
        return ""
    return (
        ", toString(argMaxIf(toString(`DstHostname`), `TimeReceived`, "
        "`DstHostname` != '')) AS dest_host"
    )


def destination_share(where: str, columns: Collection[str], limit: int) -> str:
    return (
        f"SELECT toString(`DstAddr`) AS address{_hostname(columns)}, "
        "toString(sum(`Bytes`)) AS agg_bytes "
        f"FROM {{table}} WHERE {where} GROUP BY address WITH TOTALS "
        f"ORDER BY sum(`Bytes`) DESC LIMIT {limit} FORMAT JSON"
    )


def applications(columns: Collection[str], limit: int, *, previous: bool) -> str:
    current = "`TimeReceived` >= toDateTime({start:UInt32})"
    select = ["toString(`Application`) AS app_name"]
    if "ApplicationCategory" in columns:
        select.append(
            "toString(argMaxIf(toString(`ApplicationCategory`), `TimeReceived`, "
            "`ApplicationCategory` != '')) AS app_category"
        )
    select.append(f"toString(sumIf(`Bytes`, {current})) AS cur_bytes")
    if "Packets" in columns:
        select.append(f"toString(sumIf(`Packets`, {current})) AS cur_packets")
    if previous:
        select.append(
            "toString(sumIf(`Bytes`, `TimeReceived` < toDateTime({start:UInt32}))) AS prev_bytes"
        )
    select.append(f"toString(uniqIf(`SrcAddr`, {current})) AS agg_endpoints")
    select.append(f"toUnixTimestamp(maxIf(`TimeReceived`, {current})) AS agg_seen")
    lower = "{pstart:UInt32}" if previous else "{start:UInt32}"
    return (
        f"SELECT {', '.join(select)} FROM {{table}} "
        f"WHERE `TimeReceived` >= toDateTime({lower}) AND `TimeReceived` < toDateTime({{end:UInt32}}) "
        f"GROUP BY app_name WITH TOTALS HAVING sumIf(`Bytes`, {current}) > 0 "
        f"ORDER BY sumIf(`Bytes`, {current}) DESC LIMIT {limit + 1} FORMAT JSON"
    )


def destinations(columns: Collection[str], limit: int) -> str:
    select = ["toString(`DstAddr`) AS address"]
    if "DstHostname" in columns:
        select.append(_hostname(columns)[2:])
    if "DstAS" in columns:
        select.append("toString(anyLast(`DstAS`)) AS dest_asn")
    if "DstCountry" in columns:
        select.append("anyLast(toString(`DstCountry`)) AS dest_country")
    select.append("toString(sum(`Bytes`)) AS dest_bytes")
    if "Packets" in columns:
        select.append("toString(sum(`Packets`)) AS dest_packets")
    select.append("toString(uniq(`SrcAddr`)) AS dest_endpoints")
    select.append("toUnixTimestamp(max(`TimeReceived`)) AS last_seen")
    return (
        f"SELECT {', '.join(select)} FROM {{table}} WHERE {WINDOW} GROUP BY address WITH TOTALS "
        f"ORDER BY sum(`Bytes`) DESC LIMIT {limit} FORMAT JSON"
    )


def destinations_first_seen(limit: int) -> str:
    return (
        "SELECT toString(`DstAddr`) AS address, toUnixTimestamp(min(`TimeReceived`)) AS first_seen "
        "FROM {table} WHERE `TimeReceived` >= toDateTime({lookback:UInt32}) "
        "AND `TimeReceived` < toDateTime({end:UInt32}) AND `DstAddr` IN "
        f"(SELECT `DstAddr` FROM {{table}} WHERE {WINDOW} GROUP BY `DstAddr` "
        f"ORDER BY sum(`Bytes`) DESC LIMIT {limit}) GROUP BY address LIMIT {limit} FORMAT JSON"
    )


_RANGE = "`TimeReceived` >= toDateTime({range_from:UInt32}) AND `TimeReceived` < toDateTime({range_to:UInt32})"
_OBSERVED = "`TimeReceived` >= toDateTime({obs_from:UInt32}) AND `TimeReceived` < toDateTime({range_to:UInt32})"
_HOUR = "intDiv(toUnixTimestamp(`TimeReceived`), 3600) * 3600"


def baseline_total_hours() -> str:
    return (
        f"SELECT {_HOUR} AS total_hour, toString(sum(`Bytes`)) AS agg_bytes FROM {{table}} "
        f"WHERE {_RANGE} GROUP BY total_hour ORDER BY total_hour "
        f"LIMIT {MAX_BASELINE_TOTAL_ROWS + 1} FORMAT JSON"
    )


def baseline_application_hours() -> str:
    return (
        f"SELECT {_HOUR} AS app_hour, toString(`Application`) AS app_name, "
        f"toString(sum(`Bytes`)) AS agg_bytes FROM {{table}} WHERE {_RANGE} AND "
        "`Application` IN (SELECT `Application` FROM {table} "
        f"WHERE {_OBSERVED} AND `Application` != '' GROUP BY `Application` "
        f"ORDER BY sum(`Bytes`) DESC LIMIT {MAX_BASELINE_APPLICATIONS}) "
        f"GROUP BY app_hour, app_name ORDER BY app_hour LIMIT {MAX_BASELINE_APP_ROWS + 1} FORMAT JSON"
    )


def baseline_oldest() -> str:
    return (
        "SELECT toUnixTimestamp(min(`TimeReceived`)) AS oldest, toString(count()) AS agg_rows "
        f"FROM {{table}} WHERE {_RANGE} LIMIT 1 FORMAT JSON"
    )


def first_seen_asns() -> str:
    return (
        "SELECT toString(`DstAS`) AS first_asn, toString(sum(`Bytes`)) AS agg_bytes, "
        "toString(uniqIf(`SrcAddr`, `TimeReceived` >= toDateTime({obs_from:UInt32}))) "
        "AS agg_endpoints, toUnixTimestamp(min(`TimeReceived`)) AS first_seen "
        f"FROM {{table}} WHERE {_RANGE} AND `DstAS` != 0 GROUP BY first_asn "
        "HAVING min(`TimeReceived`) >= toDateTime({obs_from:UInt32}) "
        f"ORDER BY sum(`Bytes`) DESC LIMIT {FIRST_SEEN_ASN_LIMIT} FORMAT JSON"
    )


def first_seen_destinations(columns: Collection[str]) -> str:
    return (
        f"SELECT toString(`DstAddr`) AS first_address{_hostname(columns)}, "
        "toString(sum(`Bytes`)) AS agg_bytes, "
        "toString(uniqIf(`SrcAddr`, `TimeReceived` >= toDateTime({obs_from:UInt32}))) "
        "AS agg_endpoints, toUnixTimestamp(min(`TimeReceived`)) AS first_seen "
        f"FROM {{table}} WHERE {_RANGE} AND `DstAddr` IN (SELECT `DstAddr` FROM {{table}} "
        f"WHERE {_OBSERVED} GROUP BY `DstAddr` ORDER BY sum(`Bytes`) DESC "
        f"LIMIT {FIRST_SEEN_DESTINATION_POOL}) GROUP BY first_address "
        "HAVING min(`TimeReceived`) >= toDateTime({obs_from:UInt32}) "
        f"ORDER BY sum(`Bytes`) DESC LIMIT {FIRST_SEEN_DESTINATION_LIMIT} FORMAT JSON"
    )
