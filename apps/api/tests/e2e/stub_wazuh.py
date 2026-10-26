"""Loopback Wazuh indexer stub for the local demo stack (read-only, fixture data only).

Answers the bounded ``POST /<index>/_search`` the Wazuh adapter issues (`adapters/wazuh.py`) so the
Security screen can be reviewed with realistic events: Wazuh rule alerts across every severity band
and Suricata EVE alerts. Timestamps are relative to "now" so the time-range picker stays meaningful.
Hostile-looking text is included on purpose: the UI must render it as plain data. The agent
monitoring index returns no hits.

    python apps/api/tests/e2e/stub_wazuh.py --port 8084
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

# (minutes ago, rule level, description, src, dst) - Wazuh rule alerts
_WAZUH: list[tuple[int, int, str, str, str]] = [
    (4, 14, "Multiple authentication failures followed by a success", "203.0.113.50", "10.0.0.1"),
    (12, 12, "Rootkit behavior detected on host", "", "10.0.1.3"),
    (35, 10, "sshd: brute force attempt", "198.51.100.23", "10.0.0.2"),
    (70, 8, "Firewall rule changed outside a maintenance window", "10.0.0.2", ""),
    (130, 5, "New user added to the system", "", "10.0.1.3"),
    (300, 3, "<img src=x onerror=alert(1)> unusual login time", "192.0.2.77", "10.0.0.1"),
]
# (minutes ago, signature, severity 1-3, category, src, dst) - Suricata EVE alerts
_SURICATA: list[tuple[int, str, int, str, str, str]] = [
    (
        7,
        "ET MALWARE Possible C2 beacon",
        1,
        "A Network Trojan was detected",
        "10.0.1.3",
        "203.0.113.9",
    ),
    (
        25,
        "ET SCAN Nmap Scripting Engine User-Agent",
        2,
        "Attempted Information Leak",
        "198.51.100.8",
        "10.0.0.1",
    ),
    (
        90,
        "ET POLICY Outbound TLS to rare TLD",
        3,
        "Potential Corporate Privacy Violation",
        "10.0.1.3",
        "192.0.2.200",
    ),
]


def _stamp(minutes: int, now: datetime) -> str:
    return (now - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")


def _hits(now: datetime) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for index, (mins, level, text, src, dst) in enumerate(_WAZUH):
        data = {k: v for k, v in (("srcip", src), ("dstip", dst)) if v}
        hits.append(
            {
                "_id": f"wz-{index}",
                "_source": {
                    "timestamp": _stamp(mins, now),
                    "rule": {"description": text, "level": level, "groups": ["authentication"]},
                    "data": data,
                },
            }
        )
    for index, (mins, sig, sev, cat, src, dst) in enumerate(_SURICATA):
        hits.append(
            {
                "_id": f"su-{index}",
                "_source": {
                    "timestamp": _stamp(mins, now),
                    "rule": {"groups": ["suricata"], "level": 6},
                    "data": {
                        "event_type": "alert",
                        "src_ip": src,
                        "dest_ip": dst,
                        "alert": {"signature": sig, "severity": sev, "category": cat},
                    },
                },
            }
        )
    return sorted(hits, key=lambda h: h["_source"]["timestamp"], reverse=True)


class _Handler(BaseHTTPRequestHandler):
    server_version = "NetsightDemoWazuh/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        is_alerts = self.path.startswith("/wazuh-alerts-") and self.path.endswith("/_search")
        hits = _hits(datetime.now(UTC)) if is_alerts else []
        body = json.dumps({"hits": {"hits": hits}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8084)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), _Handler)
    print(f"Wazuh demo stub listening on http://127.0.0.1:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("stopped")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
