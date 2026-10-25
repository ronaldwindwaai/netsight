"""Loopback NetBox stub for the local demo stack (read-only, fixture data only).

Serves the routes the NetBox adapter reads (`adapters/netbox.py`, `adapters/netbox_ipam.py`) so the
Network map, Inventory and IPAM screens can be reviewed with a connected topology. Device names match
the LibreNMS stub (`stub_librenms.py`) so reconciliation finds both sides; `access-sw-03` exists only
here, so the "missing in discovery" finding is visible too. Every listener binds to 127.0.0.1.

    python apps/api/tests/e2e/stub_netbox.py --port 8083
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

_ACTIVE = {"value": "active", "label": "Active"}

# (id, name, role slug, role name, device type model, site, primary ipv4)
_DEVICES: list[tuple[int, str, str, str, str, str, str]] = [
    (11, "core-sw-01.example.test", "core", "Core switch", "Netsight 24P", "HQ", "10.0.0.1/24"),
    (12, "edge-rt-02.example.test", "router", "Edge router", "Netsight R4", "HQ", "10.0.0.2/24"),
    (
        13,
        "access-sw-03.example.test",
        "access",
        "Access switch",
        "Netsight 48P",
        "HQ",
        "10.0.1.3/24",
    ),
]
# Active cables between device ids; the last one is planned, so it must NOT become an edge.
_CABLES: list[tuple[int, int, int, str]] = [
    (1, 11, 12, "active"),
    (2, 11, 13, "active"),
    (3, 12, 13, "planned"),
]
_PREFIXES = [
    (1, "10.0.0.0/24", "active", "Management", 10),
    (2, "10.0.1.0/24", "active", "Access", 20),
    (3, "10.0.2.0/24", "reserved", "Guest", 30),
]
_VLANS = [(10, "mgmt"), (20, "access"), (30, "guest")]


def _device_row(row: tuple[int, str, str, str, str, str, str]) -> dict[str, Any]:
    ident, name, slug, role, model, site, ip = row
    return {
        "id": ident,
        "name": name,
        "display": name,
        "status": _ACTIVE,
        "role": {"slug": slug, "name": role},
        "device_type": {"slug": model.lower().replace(" ", "-"), "model": model},
        "site": {"name": site},
        "primary_ip4": {"address": ip},
        "custom_fields": {},
    }


def _cable_row(ident: int, a: int, b: int, status: str) -> dict[str, Any]:
    def end(device: int) -> dict[str, Any]:
        return {"object": {"device": {"id": device}}}

    stamp = (datetime.now(UTC) - timedelta(days=40)).isoformat()
    return {
        "id": ident,
        "status": {"value": status, "label": status.title()},
        "termination_a": end(a),
        "termination_b": end(b),
        "last_updated": stamp,
    }


def _routes() -> dict[str, list[dict[str, Any]]]:
    return {
        "/api/dcim/devices/": [_device_row(r) for r in _DEVICES],
        "/api/dcim/cables/": [_cable_row(*c) for c in _CABLES],
        "/api/ipam/prefixes/": [
            {
                "id": i,
                "prefix": p,
                "status": {"value": s},
                "role": {"name": role},
                "site": {"name": "HQ"},
                "vlan": {"id": vid, "vid": vid},
            }
            for i, p, s, role, vid in _PREFIXES
        ],
        "/api/ipam/vlans/": [
            {"id": vid, "vid": vid, "name": name, "status": _ACTIVE, "site": {"name": "HQ"}}
            for vid, name in _VLANS
        ],
        "/api/ipam/ip-addresses/": [
            {
                "id": r[0],
                "address": r[6],
                "status": _ACTIVE,
                "dns_name": r[1],
                "assigned_object_type": "dcim.interface",
                "assigned_object": {"device": {"id": r[0], "name": r[1]}},
            }
            for r in _DEVICES
        ],
        "/api/ipam/ip-ranges/": [],
        "/api/tenancy/contact-assignments/": [],
        "/api/dcim/interfaces/": [],
    }


class _Handler(BaseHTTPRequestHandler):
    server_version = "NetsightDemoNetbox/1.0"
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
        path = urlsplit(self.path).path
        if path == "/api/status/":
            self._send(200, {"netbox-version": "demo"})
        elif path in (routes := _routes()):
            rows = routes[path]
            self._send(200, {"count": len(rows), "next": None, "previous": None, "results": rows})
        else:
            self._send(404, {"detail": "Not found."})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8083)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), _Handler)
    print(f"NetBox demo stub listening on http://127.0.0.1:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("stopped")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
