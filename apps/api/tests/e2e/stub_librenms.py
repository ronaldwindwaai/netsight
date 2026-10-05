"""Loopback LibreNMS stub for the Netsight end-to-end harness.

The platform API refuses to invent telemetry, so every E2E scenario that shows
real device data needs a source that actually answers. This module serves the
smallest surface the adapter reads (`adapters/librenms.py`), with canonical
payloads taken from the adapter's own contract tests.

It is a test fixture, not a mock of the adapter: requests arrive over real HTTP
so the adapter's URL construction, bearer handling, status mapping and
contract validation all run for real.

Run it directly for manual UI work:

    python apps/api/tests/e2e/stub_librenms.py --port 8080
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

# `count` must equal len(devices)/len(ports): the adapter treats a mismatch as
# invalid source data and the API answers 502 (adapters/librenms.py:429-436).
_DEVICES: list[dict[str, Any]] = [
    {
        "device_id": 1,
        "hostname": "core-sw-01.example.test",
        "display": "CORE-SW-01",
        "status": 1,
        "type": "network",
        "vendor": "Acme",
        "model": "Netsight 24P",
        "os": "nms-4.2",
    },
    {
        "device_id": 2,
        "hostname": "edge-rt-02.example.test",
        "display": "EDGE-RT-02",
        "status": 0,
        "type": "network",
        "vendor": "Acme",
        "model": "Netsight R4",
        "os": "nms-4.2",
    },
]

_PORTS: list[dict[str, Any]] = [
    {
        "port_id": 1,
        "ifIndex": 1,
        "ifName": "Gi0/1",
        "ifDescr": "Uplink to core",
        "ifAlias": "uplink-core",
        "ifAdminStatus": "up",
        "ifOperStatus": "up",
        "ifType": "ethernetCsmacd",
        "ifHighSpeed": 1000,
    },
    {
        "port_id": 2,
        "ifIndex": 2,
        "ifName": "Gi0/2",
        "ifDescr": "Spare",
        "ifAlias": "spare-port",
        "ifAdminStatus": "down",
        "ifOperStatus": "down",
        "ifType": "ethernetCsmacd",
        "ifHighSpeed": 1000,
    },
]

_ALERTS: list[dict[str, Any]] = [
    {
        "id": 7,
        "device_id": 1,
        "severity": "critical",
        "state": 0,
        "name": "Link down on port 12",
        "timestamp": "2026-10-02T10:00:00Z",
    },
    {
        "id": 8,
        "device_id": 2,
        "severity": "warning",
        "state": 0,
        "name": "Interface Gi0/2 administratively down",
        "timestamp": "2026-10-02T11:30:00Z",
    },
]


def _envelope(*, status: str = "ok", **extra: Any) -> dict[str, Any]:
    return {"status": status, **extra}


class _Handler(BaseHTTPRequestHandler):
    """Serves only the routes the LibreNMS adapter calls."""

    server_version = "NetsightE2EStub/1.0"
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
        path = self.path.split("?", 1)[0].rstrip("/") or "/"

        if path == "/api/v0/system":
            self._send(200, _envelope())
            return

        if path == "/api/v0/devices":
            self._send(200, _envelope(count=len(_DEVICES), devices=_DEVICES))
            return

        if path == "/api/v0/alerts":
            self._send(200, _envelope(alerts=_ALERTS))
            return

        parts = [p for p in path.split("/") if p]
        # /api/v0/devices/{id}[/ports]
        if len(parts) >= 4 and parts[:3] == ["api", "v0", "devices"]:
            native_id = parts[3]
            match = next(
                (d for d in _DEVICES if str(d["device_id"]) == native_id), None
            )
            if match is None:
                self._send(404, _envelope(status="error"))
                return
            if len(parts) == 4:
                self._send(200, _envelope(count=1, devices=[match]))
                return
            if len(parts) == 5 and parts[4] == "ports":
                self._send(200, _envelope(count=len(_PORTS), ports=_PORTS))
                return

        self._send(404, _envelope(status="error"))


def serve(port: int) -> ThreadingHTTPServer:
    """Start the stub on `port` and return the server (already serving)."""

    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    return server


def _serve_forever(server: ThreadingHTTPServer) -> Iterator[None]:
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    server = serve(args.port)
    print(f"LibreNMS stub listening on http://127.0.0.1:{args.port}")
    try:
        _serve_forever(server)
    except KeyboardInterrupt:
        print("stopped")


if __name__ == "__main__":
    main()