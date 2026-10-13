"""One ClickHouse client per process (Step 7 re-review, MEDIUM): schema discovery is not per request.

Building a client for every request threw its discovered columns away, so each Explorer request paid
a ``system.columns`` round trip. The client is now shared for as long as the configuration is
unchanged, and the discovered schema expires after a TTL so a column added later is noticed.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from netsight_api import main
from netsight_api.adapters import clickhouse, clickhouse_shared
from netsight_api.adapters.clickhouse import ClickhouseClient
from netsight_api.adapters.clickhouse_explorer import ExplorerClickhouse

START = datetime(2026, 10, 5, 0, 0, tzinfo=UTC)
END = datetime(2026, 10, 6, 0, 0, tzinfo=UTC)
COLUMNS = ["TimeReceived", "SrcAddr", "DstAddr", "Proto", "Bytes", "Packets"]
SEEN = int(datetime(2026, 10, 5, 23, 30, tzinfo=UTC).timestamp())


@pytest.fixture(autouse=True)
def _environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "CLICKHOUSE_DSN",
        "CLICKHOUSE_USER",
        "CLICKHOUSE_PASSWORD",
        "CLICKHOUSE_FLOWS_TABLE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CLICKHOUSE_DSN", "http://clickhouse.test:8123")
    clickhouse_shared.reset_for_tests()


def test_the_same_configuration_yields_the_same_client() -> None:
    first = main.get_optional_traffic_source()
    assert first is not None
    assert main.get_optional_traffic_source() is first


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("CLICKHOUSE_DSN", "http://other.test:8123"),
        ("CLICKHOUSE_USER", "reader"),
        ("CLICKHOUSE_PASSWORD", "changed"),
        ("CLICKHOUSE_FLOWS_TABLE", "flows_5m"),
    ],
)
def test_a_changed_setting_builds_a_new_client(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    first = main.get_optional_traffic_source()
    monkeypatch.setenv(name, value)
    second = main.get_optional_traffic_source()
    assert second is not None and second is not first


def test_without_a_dsn_there_is_no_client_and_none_is_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    first = main.get_optional_traffic_source()
    monkeypatch.delenv("CLICKHOUSE_DSN")
    assert main.get_optional_traffic_source() is None
    monkeypatch.setenv("CLICKHOUSE_DSN", "http://clickhouse.test:8123")
    assert main.get_optional_traffic_source() is not first  # nothing stale comes back


def test_the_shared_client_does_not_expose_its_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLICKHOUSE_PASSWORD", "s3cret-value")
    client = main.get_optional_traffic_source()
    assert "s3cret-value" not in repr(client)


def _counting_client(discoveries: list[int]) -> ExplorerClickhouse:
    def handler(request: httpx.Request) -> httpx.Response:
        if "system.columns" in request.content.decode():
            discoveries.append(1)
            return httpx.Response(200, json={"data": [{"name": name} for name in COLUMNS]})
        return httpx.Response(
            200,
            json={
                "data": [
                    {"label": "10.0.0.1", "agg_bytes": "1", "agg_packets": "1", "agg_seen": SEEN}
                ],
                "totals": {"agg_bytes": "1"},
            },
        )

    return ExplorerClickhouse(
        dsn="http://clickhouse.test:8123", _transport=httpx.MockTransport(handler)
    )


async def _read(client: ClickhouseClient) -> None:
    await client.top(dimension="talkers", start=START, end=END, limit=5)


@pytest.mark.asyncio
async def test_the_schema_is_discovered_once_within_its_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [1000.0]
    monkeypatch.setattr(clickhouse.time, "monotonic", lambda: now[0])
    discoveries: list[int] = []
    client = _counting_client(discoveries)
    await _read(client)
    now[0] += clickhouse.SCHEMA_TTL_SECONDS - 1
    await _read(client)
    assert len(discoveries) == 1


@pytest.mark.asyncio
async def test_the_schema_is_discovered_again_after_its_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [1000.0]
    monkeypatch.setattr(clickhouse.time, "monotonic", lambda: now[0])
    discoveries: list[int] = []
    client = _counting_client(discoveries)
    await _read(client)
    now[0] += clickhouse.SCHEMA_TTL_SECONDS + 1
    await _read(client)
    assert len(discoveries) == 2
