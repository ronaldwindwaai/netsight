"""The demo-only fixtures must satisfy the real adapters and contracts."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from http.server import ThreadingHTTPServer

import pytest
from fastapi import FastAPI
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


@pytest.fixture
def demo_app_installed(monkeypatch: pytest.MonkeyPatch) -> Iterator[FastAPI]:
    import demo_app

    from netsight_api.main import app

    monkeypatch.setenv("NETSIGHT_DEMO", "1")
    before = dict(app.dependency_overrides)
    demo_app.install(app)
    try:
        yield app
    finally:
        demo_app.uninstall(app)
        assert app.dependency_overrides == before


def test_demo_override_is_not_installed_by_import_and_is_removed_after_use() -> None:
    import demo_app  # noqa: F401

    from netsight_api.incident_deps import get_optional_incident_store
    from netsight_api.main import app

    assert get_optional_incident_store not in app.dependency_overrides


def test_demo_app_installs_seeded_store(demo_app_installed: FastAPI) -> None:
    from netsight_api.incident_deps import get_optional_incident_store

    store = demo_app_installed.dependency_overrides[get_optional_incident_store]()
    assert len(store.list_incidents(limit=100)) >= 5


def test_demo_app_refuses_without_the_demo_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    import demo_app

    monkeypatch.delenv("NETSIGHT_DEMO", raising=False)
    with pytest.raises(RuntimeError, match="NETSIGHT_DEMO=1"):
        demo_app.build_app()
