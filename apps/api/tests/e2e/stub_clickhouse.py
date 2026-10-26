"""Loopback ClickHouse HTTP stub for the local demo stack (read-only, synthetic flows only).

Recognises each query shape the traffic adapters send (`adapters/clickhouse*.py`, matched by the
output aliases the queries select) and answers from 29 days of synthetic hourly flow records, so the
Traffic, Applications, Destinations and Anomalies screens can be reviewed with data. It is not a SQL
engine: ``WHERE`` filters other than the time window are ignored, so Flow Explorer filters have no
effect here. Includes a destination that first appears in the last two days and an off-hours spike
from one host, so first-seen and anomaly states have something to show. Addresses are documentation
or well-known public ones; nothing is real traffic.

    python apps/api/tests/e2e/stub_clickhouse.py --port 8085
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar
from urllib.parse import parse_qs, urlsplit

HOUR = 3600
DAYS = 29
COLUMNS = [
    ("TimeReceived", "DateTime"),
    ("SrcAddr", "IPv6"),
    ("DstAddr", "IPv6"),
    ("Proto", "UInt32"),
    ("Bytes", "UInt64"),
    ("Packets", "UInt64"),
    ("DstPort", "UInt16"),
    ("DstHostname", "String"),
    ("Application", "String"),
    ("ApplicationCategory", "String"),
    ("DstAS", "UInt32"),
    ("DstCountry", "FixedString(2)"),
    ("InIfBoundary", "String"),
    ("OutIfBoundary", "String"),
]


@dataclass(frozen=True)
class Flow:
    ts: int
    src: str
    dst: str
    proto: int
    port: int
    bytes: int
    packets: int
    host: str
    app: str
    category: str
    asn: int
    country: str
    inbound: bool

    @property
    def inside(self) -> str:
        return self.dst if self.inbound else self.src


# (src, dst, app, category, port, proto, MB per busy hour, host, asn, country, first day offset)
_PAIRS: list[tuple[str, str, str, str, int, int, float, str, int, str, int]] = [
    ("10.0.1.21", "142.250.74.46", "HTTPS", "Web", 443, 6, 180, "www.google.com", 15169, "US", 0),
    (
        "10.0.1.34",
        "52.96.0.1",
        "Microsoft 365",
        "Productivity",
        443,
        6,
        260,
        "outlook.office365.com",
        8075,
        "IE",
        0,
    ),
    (
        "10.0.1.34",
        "185.199.108.153",
        "GitHub",
        "Development",
        443,
        6,
        90,
        "github.com",
        54113,
        "US",
        0,
    ),
    ("10.0.1.57", "31.13.71.36", "Facebook", "Social", 443, 6, 140, "facebook.com", 32934, "IE", 0),
    ("10.0.1.57", "104.18.2.1", "HTTPS", "Web", 443, 6, 70, "cdn.example.net", 13335, "US", 0),
    (
        "10.0.0.12",
        "54.239.28.85",
        "Amazon S3",
        "Cloud storage",
        443,
        6,
        520,
        "s3.amazonaws.com",
        16509,
        "US",
        0,
    ),
    ("10.0.0.12", "8.8.8.8", "DNS", "Network", 53, 17, 4, "dns.google", 15169, "US", 0),
    ("10.0.1.21", "203.0.113.9", "Unclassified", "Unknown", 8443, 6, 35, "", 64496, "NL", DAYS - 2),
]
_INBOUND = ("198.51.100.8", "10.0.0.12", "SSH", "Remote access", 22, 6, 6, "", 64497, "DE")
_SPIKE = ("10.0.1.57", "198.51.100.77", "BitTorrent", "P2P", 6881, 6, 900, "", 64498, "RU")


def _weight(moment: datetime) -> float:
    weekend = moment.weekday() >= 5
    busy = 8 <= moment.hour < 18
    return (0.3 if weekend else 1.0) * (1.0 if busy else 0.12)


def build_flows(now: datetime) -> list[Flow]:
    flows: ClassVar[list[Flow]] = []
    first_hour = int(now.timestamp()) // HOUR * HOUR - DAYS * 24 * HOUR
    for step in range(DAYS * 24 + 1):
        hour_start = first_hour + step * HOUR
        ts = hour_start + 300
        if ts > now.timestamp():
            break
        moment = datetime.fromtimestamp(hour_start, UTC)
        weight = _weight(moment)
        for src, dst, app, cat, port, proto, mb, host, asn, cc, first in _PAIRS:
            if step < first * 24:
                continue
            jitter = 0.8 + 0.4 * ((step * 7 + len(dst)) % 10) / 10
            size = int(mb * weight * jitter * 1_000_000)
            flows.append(
                Flow(ts, src, dst, proto, port, size, size // 900, host, app, cat, asn, cc, False)
            )
        src, dst, app, cat, port, proto, mb, host, asn, cc = _INBOUND
        size = int(mb * weight * 1_000_000)
        flows.append(
            Flow(ts, src, dst, proto, port, size, size // 900, host, app, cat, asn, cc, True)
        )
        recent = now - moment < timedelta(hours=30)
        if recent and moment.hour in (22, 23) and moment.date() < now.date():
            s, d, a, c, p, pr, m, h, an, co = _SPIKE
            size = m * 1_000_000
            flows.append(Flow(ts, s, d, pr, p, size, size // 1200, h, a, c, an, co, False))
    return flows


@cache
def _internal(address: str) -> bool:
    return ipaddress.ip_address(address).is_private


def _uniq_internal(flows: list[Flow]) -> int:
    return len({f.inside for f in flows if _internal(f.inside)})


def _window(flows: list[Flow], params: dict[str, int], low: str, high: str) -> list[Flow]:
    return [f for f in flows if params[low] <= f.ts < params[high]]


def _strs(**values: Any) -> dict[str, str]:
    return {k: ("" if v is None else str(v)) for k, v in values.items()}


def _group(flows: list[Flow], key: Callable[[Flow], Any]) -> list[tuple[Any, list[Flow]]]:
    groups: dict[Any, list[Flow]] = defaultdict(list)
    for flow in flows:
        groups[key(flow)].append(flow)
    return sorted(groups.items(), key=lambda kv: -sum(f.bytes for f in kv[1]))


def _limit(sql: str, rows: list[Any]) -> list[Any]:
    match = re.search(r"LIMIT (\d+) FORMAT JSON", sql)
    return rows[: int(match.group(1))] if match else rows


def _sum(flows: list[Flow]) -> int:
    return sum(f.bytes for f in flows)


def answer(sql: str, params: dict[str, int], flows: list[Flow]) -> dict[str, Any]:
    if "system.columns" in sql:
        return {"data": [{"name": n, "type": t} for n, t in COLUMNS]}
    win = _window(flows, params, "start", "end") if "start" in params and "end" in params else []
    rng = _window(flows, params, "range_from", "range_to") if "range_from" in params else []
    seen = max((f.ts for f in win), default=0)

    if "AS source_seen" in sql:
        return {"data": [{"source_seen": seen}]}
    if "AS agg_flows" in sql and "AS bucket" in sql:
        step = params["bucket"]
        rows = [
            _strs(
                bucket=b,
                agg_bytes=_sum(g),
                agg_packets=sum(f.packets for f in g),
                agg_flows=len(g),
            )
            for b, g in sorted(_group(win, lambda f: f.ts // step * step))
        ]
        return {"data": rows}
    if "AS agg_flows" in sql:
        row = _strs(
            agg_bytes=_sum(win),
            agg_packets=sum(f.packets for f in win),
            agg_flows=len(win),
            agg_sources=len({f.src for f in win}),
            agg_destinations=len({f.dst for f in win}),
            agg_internal=_uniq_internal(win),
        )
        row["agg_seen"] = seen
        return {"data": [row]}
    if "AS seen_at" in sql:
        rows = [
            {
                "seen_at": f.ts,
                "source_ip": f.src,
                "destination_ip": f.dst,
                "n_bytes": str(f.bytes),
                "proto_num": f.proto,
                "n_packets": str(f.packets),
                "dest_port": f.port,
                "dest_host": f.host,
                "app_name": f.app,
                "in_boundary": "external" if f.inbound else "internal",
                "out_boundary": "internal" if f.inbound else "external",
            }
            for f in sorted(win, key=lambda f: -f.bytes)
        ]
        return {"data": _limit(sql, rows)}
    if "AS label" in sql:
        column = "src" if "`SrcAddr`) AS label" in sql else "dst"
        rows = [
            {
                **_strs(label=k, agg_bytes=_sum(g), agg_packets=sum(f.packets for f in g)),
                "agg_seen": max(f.ts for f in g),
            }
            for k, g in _group(win, lambda f: getattr(f, column))
        ]
        totals = _strs(agg_bytes=_sum(win), agg_packets=sum(f.packets for f in win))
        return {"data": _limit(sql, rows), "totals": {**totals, "agg_seen": seen}}
    if "AS cur_bytes" in sql:
        return _applications(sql, params, flows)
    if "AS dest_bytes" in sql:
        rows = [
            {
                **_strs(
                    address=k,
                    dest_host=g[0].host,
                    dest_asn=g[0].asn,
                    dest_country=g[0].country,
                    dest_bytes=_sum(g),
                    dest_packets=sum(f.packets for f in g),
                    dest_endpoints=_uniq_internal(g),
                ),
                "last_seen": max(f.ts for f in g),
            }
            for k, g in _group(win, lambda f: f.dst)
        ]
        totals = {**_strs(dest_bytes=_sum(win)), "last_seen": seen}
        return {"data": _limit(sql, rows), "totals": totals}
    if "AS first_seen" in sql and "AS address" in sql and "AS first_address" not in sql:
        lookback = [f for f in flows if params["lookback"] <= f.ts < params["end"]]
        rows = [
            {"address": k, "first_seen": min(f.ts for f in g)}
            for k, g in _group(lookback, lambda f: f.dst)
        ]
        return {"data": _limit(sql, rows)}
    if "AS app_name" in sql and "agg_endpoints" in sql:
        rows = [
            _strs(app_name=k, agg_bytes=_sum(g), agg_endpoints=_uniq_internal(g))
            for k, g in _group(win, lambda f: f.app)
        ]
        totals = _strs(agg_bytes=_sum(win), agg_endpoints=_uniq_internal(win))
        return {"data": _limit(sql, rows), "totals": totals}
    if "AS address" in sql and "agg_endpoints" in sql:
        rows = [
            _strs(
                address=k,
                dest_host=g[0].host,
                agg_bytes=_sum(g),
                agg_endpoints=_uniq_internal(g),
            )
            for k, g in _group(win, lambda f: f.dst)
        ]
        totals = _strs(agg_bytes=_sum(win), agg_endpoints=_uniq_internal(win))
        return {"data": _limit(sql, rows), "totals": totals}
    return _baseline(sql, params, rng)


def _applications(sql: str, params: dict[str, int], flows: list[Flow]) -> dict[str, Any]:
    low = params.get("pstart", params["start"])
    scope = [f for f in flows if low <= f.ts < params["end"]]
    rows = []
    for app, group in _group(scope, lambda f: f.app):
        cur = [f for f in group if f.ts >= params["start"]]
        if not cur:
            continue
        row = _strs(
            app_name=app,
            app_category=group[0].category,
            cur_bytes=_sum(cur),
            cur_packets=sum(f.packets for f in cur),
            agg_endpoints=_uniq_internal(cur),
        )
        row["agg_seen"] = max(f.ts for f in cur)
        if "AS prev_bytes" in sql:
            row["prev_bytes"] = str(_sum([f for f in group if f.ts < params["start"]]))
        rows.append(row)
    rows.sort(key=lambda r: -int(r["cur_bytes"]))
    current = [f for f in scope if f.ts >= params["start"]]
    totals = _strs(
        cur_bytes=_sum(current),
        prev_bytes=sum(int(r.get("prev_bytes", 0)) for r in rows),
        agg_endpoints=_uniq_internal(current),
    )
    totals["agg_seen"] = max((int(r["agg_seen"]) for r in rows), default=0)
    return {"data": _limit(sql, rows), "totals": totals}


def _baseline(sql: str, params: dict[str, int], rng: list[Flow]) -> dict[str, Any]:
    obs = [f for f in rng if f.ts >= params.get("obs_from", 0)]
    if "AS total_hour" in sql:
        rows = [
            _strs(total_hour=h, agg_bytes=_sum(g))
            for h, g in sorted(_group(rng, lambda f: f.ts // HOUR * HOUR))
        ]
        return {"data": rows}
    if "AS app_hour" in sql:
        top = [a for a, _ in _group([f for f in obs if f.app], lambda f: f.app)][:10]
        scoped = [f for f in rng if f.app in top]
        rows = [
            _strs(app_hour=h, app_name=a, agg_bytes=_sum(g))
            for (h, a), g in sorted(_group(scoped, lambda f: (f.ts // HOUR * HOUR, f.app)))
        ]
        return {"data": rows}
    if "AS oldest" in sql:
        return {"data": [_strs(oldest=min((f.ts for f in rng), default=0), agg_rows=len(rng))]}
    if "AS total_day" in sql:
        rows = [
            _strs(total_day=d, agg_bytes=_sum(g), hours_seen=len({f.ts // HOUR for f in g}))
            for d, g in sorted(_group(rng, lambda f: f.ts // 86400 * 86400))
        ]
        return {"data": rows}
    if "AS agg_rows" in sql and "AS first_seen" in sql:
        return {
            "data": [
                _strs(
                    first_seen=min((f.ts for f in rng), default=0),
                    last_seen=max((f.ts for f in rng), default=0),
                    agg_rows=len(rng),
                )
            ]
        }
    if "AS first_asn" in sql or "AS first_address" in sql:
        by_asn = "AS first_asn" in sql

        def key_of(flow: Flow) -> Any:
            return flow.asn if by_asn else flow.dst

        known_before = {key_of(f) for f in rng if f.ts < params["obs_from"]}
        rows = []
        for key, group in _group(obs, key_of):
            if key in known_before:
                continue
            base = (
                {"first_asn": key} if by_asn else {"first_address": key, "dest_host": group[0].host}
            )
            rows.append(
                {
                    **_strs(**base, agg_bytes=_sum(group), agg_endpoints=_uniq_internal(group)),
                    "first_seen": min(f.ts for f in group),
                }
            )
        return {"data": rows}
    if "AS total_sources" in sql:
        return {"data": [_strs(total_sources=_uniq_internal(obs))]}
    if "AS app_sources" in sql:
        rows = [
            _strs(app_name=a, app_sources=_uniq_internal(g))
            for a, g in _group([f for f in obs if f.app], lambda f: f.app)
        ]
        return {"data": rows}
    return {"data": []}


class _Handler(BaseHTTPRequestHandler):
    server_version = "NetsightDemoClickHouse/1.0"
    protocol_version = "HTTP/1.1"
    flows: ClassVar[list[Flow]] = []

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        self._send(200, b"Ok.\n", "text/plain")

    def do_POST(self) -> None:
        sql = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
        query = parse_qs(urlsplit(self.path).query)
        params = {
            k[6:]: int(v[0])
            for k, v in query.items()
            if k.startswith("param_") and v[0].lstrip("-").isdigit()
        }
        try:
            payload = answer(sql, params, self.flows)
        except (KeyError, ValueError) as error:
            self._send(400, f"stub cannot answer this query: {error}".encode(), "text/plain")
            return
        self._send(200, json.dumps(payload).encode(), "application/json")

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8085)
    args = parser.parse_args()
    _Handler.flows = build_flows(datetime.now(UTC))
    server = ThreadingHTTPServer(("127.0.0.1", args.port), _Handler)
    print(f"ClickHouse demo stub on http://127.0.0.1:{args.port} ({len(_Handler.flows)} flows)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("stopped")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
