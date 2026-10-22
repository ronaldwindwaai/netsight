"""Loopback Oxidized stub for the local demo stack (read-only metadata, fixture data only).

Serves the two routes the Oxidized adapter reads (`adapters/oxidized.py`): `/nodes.json` and
`/node/version.json`. It exists so the Configuration screens can be reviewed with realistic data
(fresh, stale, failed and never-backed-up nodes, a long name, several versions). Timestamps are
relative to "now" so the freshness badges stay meaningful whenever the demo is started.

    python apps/api/tests/e2e/stub_oxidized.py --port 8082
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

# (full name, model, status, hours since last attempt, number of stored versions)
_NODES: list[tuple[str, str, str, float | None, int]] = [
    ("core-sw-01.example.test", "ios", "success", 2, 6),
    ("edge-rt-02.example.test", "junos", "success", 30, 3),
    ("branch/london-fw-01.example.test", "fortios", "failed", 5, 2),
    ("branch/leeds-sw-03.example.test", "ios", "never", None, 0),
    (
        "branch/manchester-ap-controller-with-an-unusually-long-hostname-for-wrapping.example.test",
        "aruba",
        "success",
        1,
        12,
    ),
    ("dc/spine-01.example.test", "eos", "no_connection", 49, 4),
]


def _iso(moment: datetime) -> str:
    return moment.isoformat()


def _node_rows(now: datetime) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for full, model, status, hours, _ in _NODES:
        group, _, name = full.rpartition("/")
        last: dict[str, Any] = {"status": status}
        if hours is not None:
            last["end"] = _iso(now - timedelta(hours=hours))
        rows.append(
            {
                "name": name,
                "full_name": full,
                "group": group or "default",
                "model": model,
                "last": last,
            }
        )
    return rows


def _version_rows(full: str, now: datetime) -> list[dict[str, Any]]:
    count = next((n for f, _m, _s, _h, n in _NODES if f == full), 0)
    return [
        {
            "oid": hashlib.sha1(f"{full}:{index}".encode()).hexdigest(),
            "time": _iso(now - timedelta(days=index, hours=3)),
        }
        for index in range(count)
    ]


class _Handler(BaseHTTPRequestHandler):
    server_version = "NetsightDemoOxidized/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(self, code: int, payload: Any) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        now = datetime.now(UTC)
        if parsed.path == "/nodes.json":
            self._send(200, _node_rows(now))
        elif parsed.path == "/node/version.json":
            node = parse_qs(parsed.query).get("node_full", [""])[0]
            self._send(200, _version_rows(node, now))
        else:
            self._send(404, {"error": "not found"})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8082)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), _Handler)
    print(f"Oxidized demo stub listening on http://127.0.0.1:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("stopped")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
