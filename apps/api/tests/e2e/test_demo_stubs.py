"""The demo-only fixtures must satisfy the real adapters and contracts."""

from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime
from http.server import ThreadingHTTPServer

from stub_oxidized import _Handler

from netsight_api.adapters.oxidized import OxidizedClient


def _serve() -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_oxidized_stub_is_accepted_by_the_adapter() -> None:
    server = _serve()
    try:
        client = OxidizedClient(f"http://127.0.0.1:{server.server_address[1]}")
        nodes = asyncio.run(client.nodes())
        assert nodes.state == "ok" and nodes.skipped == 0
        assert {n.backup_status for n in nodes.items} >= {"success", "failed", "never"}
        assert {n.backup_freshness for n in nodes.items} >= {"fresh", "stale"}
        busiest = max(nodes.items, key=lambda n: len(n.name))
        versions = asyncio.run(client.versions(busiest.id))
        assert versions.state == "ok" and len(versions.items) == 12
        assert all(v.saved_at <= datetime.now(UTC) for v in versions.items)
    finally:
        server.shutdown()
        server.server_close()


def test_seeded_incident_fixture_is_valid_and_covers_the_lifecycle() -> None:
    from datetime import UTC, datetime

    from demo_app import _Clock, seed

    from netsight_api.storage.memory import InMemoryIncidentRepository

    clock = _Clock()
    repo = InMemoryIncidentRepository(clock=clock)
    seed(repo, clock, datetime.now(UTC))
    incidents = repo.list_incidents(limit=100)
    assert {i.state for i in incidents} >= {"open", "investigating", "mitigated", "closed"}
    assert {i.severity for i in incidents} >= {"low", "medium", "high", "critical"}
    assert sum(1 for i in incidents if repo.list_timeline(i.id)) >= 3
