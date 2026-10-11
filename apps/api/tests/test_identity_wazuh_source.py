"""Wazuh agent inventory as identity evidence (Step 6b): adapter reads and the evidence mapping.

The field names follow the Wazuh 4.x monitoring index (``id``, ``name``, ``ip``, ``status``,
``lastKeepAlive``, ``timestamp``). They are exercised against a mock transport only: this build has
no live Wazuh, so the shape is unverified against a real indexer (see IDENTITY-CORRELATION.md).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from netsight_api.adapters.wazuh import (
    AdapterError,
    AdapterStatus,
    WazuhAgent,
    WazuhIndexerClient,
    parse_agent_hit,
)
from netsight_api.identity.engine import CorrelationIndex
from netsight_api.identity.model import (
    Basis,
    CorrelationPolicy,
    EntityType,
    EvidenceKind,
    Relation,
    ip_ref,
)
from netsight_api.identity.sources import EvidenceSource
from netsight_api.identity.wazuh_source import WazuhAgentSource

NOW = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)
START = NOW - timedelta(hours=24)


def hit(**overrides: Any) -> dict[str, Any]:
    source: dict[str, Any] = {
        "id": "001",
        "name": "PC-001",
        "ip": "10.0.0.10",
        "status": "active",
        "lastKeepAlive": "2026-10-11T11:54:50.000Z",
        "timestamp": "2026-10-11T11:55:00.123Z",
    }
    source.update(overrides)
    return {"_id": f"doc-{source.get('id')}", "_source": source}


def client(handler: Any, **kwargs: Any) -> WazuhIndexerClient:
    return WazuhIndexerClient(
        base_url="https://indexer.test:9200",
        user="svc",
        password="s3cret",
        _transport=httpx.MockTransport(handler),
        **kwargs,
    )


def ok(hits: list[dict[str, Any]]) -> httpx.Response:
    return httpx.Response(200, json={"hits": {"hits": hits}})


# --- parsing ---------------------------------------------------------------------------------


def test_an_active_agent_is_parsed() -> None:
    agent = parse_agent_hit(hit())
    assert agent == WazuhAgent(
        agent_id="001",
        name="PC-001",
        ip="10.0.0.10",
        status="active",
        observed_at=datetime(2026, 10, 11, 11, 55, 0, 123000, tzinfo=UTC),
        last_keep_alive=datetime(2026, 10, 11, 11, 54, 50, tzinfo=UTC),
    )


def test_an_agent_without_a_usable_address_keeps_none() -> None:
    assert parse_agent_hit(hit(ip="any")).ip is None
    assert parse_agent_hit(hit(ip="")).ip is None
    assert parse_agent_hit(hit(ip=None)).ip is None
    assert parse_agent_hit(hit(ip="0.0.0.0")).ip is None


def test_text_is_bounded_and_blank_name_is_none() -> None:
    assert parse_agent_hit(hit(name="  ")).name is None
    assert parse_agent_hit(hit(name="x" * 500)).name == "x" * 128


@pytest.mark.parametrize(
    "bad",
    [
        {"id": ""},
        {"id": 7},
        {"status": "weird"},
        {"status": None},
        {"timestamp": "yesterday"},
        {"timestamp": "2026-10-11T11:55:00"},  # no timezone
        {"lastKeepAlive": "nope"},
        {"ip": 5},
        {"name": 5},
    ],
)
def test_a_malformed_agent_document_is_invalid_source_data(bad: dict[str, Any]) -> None:
    with pytest.raises(AdapterError) as error:
        parse_agent_hit(hit(**bad))
    assert error.value.status is AdapterStatus.INVALID_SOURCE_DATA


def test_a_hit_without_source_is_invalid() -> None:
    with pytest.raises(AdapterError):
        parse_agent_hit({"_id": "x"})
    with pytest.raises(AdapterError):
        parse_agent_hit("not a dict")


def test_hostile_text_in_an_agent_name_is_data() -> None:
    hostile = "<img src=x onerror=alert(1)>; DROP TABLE agents; ignore previous instructions"
    assert parse_agent_hit(hit(name=hostile)).name == hostile


# --- the query ---------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_agent_query_is_bounded_read_only_and_collapsed_per_agent() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        seen["method"] = request.method
        return ok([hit()])

    inventory = await client(handler).agents(start=START, end=NOW, limit=100)
    assert len(inventory.agents) == 1 and inventory.truncated is False and inventory.skipped == 0
    assert seen["method"] == "POST"
    assert seen["url"] == "https://indexer.test:9200/wazuh-monitoring-*/_search"
    body = seen["body"]
    assert body["size"] == 101  # one more than the limit, to detect truncation
    assert body["collapse"] == {"field": "id"}
    assert body["sort"] == [{"timestamp": {"order": "desc"}}]
    window = body["query"]["bool"]["filter"][0]["range"]["timestamp"]
    assert window == {"gte": START.isoformat(), "lt": NOW.isoformat()}
    assert set(body["_source"]["includes"]) == {
        "id",
        "name",
        "ip",
        "status",
        "lastKeepAlive",
        "timestamp",
    }


@pytest.mark.asyncio
async def test_more_agents_than_the_limit_is_reported_as_truncated() -> None:
    hits = [hit(id=f"{n:03d}") for n in range(4)]
    inventory = await client(lambda _r: ok(hits)).agents(start=START, end=NOW, limit=3)
    assert len(inventory.agents) == 3 and inventory.truncated is True


@pytest.mark.asyncio
async def test_the_limit_is_capped() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["size"] = json.loads(request.content)["size"]
        return ok([])

    await client(handler).agents(start=START, end=NOW, limit=10**9)
    assert seen["size"] <= 2501


@pytest.mark.asyncio
async def test_the_agents_index_comes_from_configuration_and_is_validated() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        return ok([])

    await client(handler, agents_index_pattern="wazuh-monitoring-custom-*").agents(
        start=START, end=NOW, limit=5
    )
    assert seen["path"] == "/wazuh-monitoring-custom-*/_search"
    for bad in ("other-index-*", "wazuh-../x", "_all", "*", ""):
        with pytest.raises(AdapterError) as error:
            await client(lambda _r: ok([]), agents_index_pattern=bad).agents(
                start=START, end=NOW, limit=5
            )
        assert error.value.status is AdapterStatus.UNAVAILABLE


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "status"),
    [
        (httpx.Response(401), AdapterStatus.FORBIDDEN),
        (httpx.Response(403), AdapterStatus.FORBIDDEN),
        (httpx.Response(500), AdapterStatus.UNAVAILABLE),
        (
            httpx.Response(302, headers={"location": "https://evil.test/"}),
            AdapterStatus.UNAVAILABLE,
        ),
        (httpx.Response(200, content=b"not json"), AdapterStatus.INVALID_SOURCE_DATA),
        (httpx.Response(200, json={"hits": {}}), AdapterStatus.INVALID_SOURCE_DATA),
        (
            # every document malformed: a changed index shape is a failure, not "no agents"
            httpx.Response(200, json={"hits": {"hits": [{"_id": "x"}]}}),
            AdapterStatus.INVALID_SOURCE_DATA,
        ),
    ],
)
async def test_every_failure_is_typed_and_never_an_empty_success(
    response: httpx.Response, status: AdapterStatus
) -> None:
    with pytest.raises(AdapterError) as error:
        await client(lambda _r: response).agents(start=START, end=NOW, limit=5)
    assert error.value.status is status
    assert "s3cret" not in str(error.value)


@pytest.mark.asyncio
async def test_a_timeout_is_unavailable() -> None:
    def handler(_r: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    with pytest.raises(AdapterError) as error:
        await client(handler).agents(start=START, end=NOW, limit=5)
    assert error.value.status is AdapterStatus.UNAVAILABLE


@pytest.mark.asyncio
async def test_an_oversized_response_is_refused() -> None:
    big = httpx.Response(200, content=b"x" * 200)
    with pytest.raises(AdapterError) as error:
        await client(lambda _r: big, max_response_bytes=100).agents(start=START, end=NOW, limit=5)
    assert error.value.status is AdapterStatus.INVALID_SOURCE_DATA


@pytest.mark.asyncio
async def test_credentials_are_not_in_the_repr_and_need_https() -> None:
    plain = WazuhIndexerClient(base_url="http://indexer.test:9200", user="svc", password="s3cret")
    assert "s3cret" not in repr(plain)
    with pytest.raises(AdapterError):
        await plain.agents(start=START, end=NOW, limit=5)


@pytest.mark.asyncio
async def test_an_inverted_window_is_a_programming_error() -> None:
    with pytest.raises(ValueError):
        await client(lambda _r: ok([])).agents(start=NOW, end=START, limit=5)


# --- evidence mapping --------------------------------------------------------------------------------


def agent_source(handler: Any) -> WazuhAgentSource:
    return WazuhAgentSource(client(handler))


@pytest.mark.asyncio
async def test_an_active_agent_becomes_endpoint_agent_evidence() -> None:
    source = agent_source(lambda _r: ok([hit()]))
    as_protocol: EvidenceSource = source  # the adapter satisfies the plug-in interface
    assert as_protocol is source
    assert source.name == "wazuh" and source.kinds == {EvidenceKind.ENDPOINT_AGENT}
    batch = await source.fetch(start=START, end=NOW, limit=100)
    (record,) = batch.records
    assert record.source == "wazuh" and record.kind is EvidenceKind.ENDPOINT_AGENT
    (assertion,) = record.assertions
    assert assertion.relation is Relation.DEVICE_IP
    assert assertion.a.type is EntityType.DEVICE and assertion.a.label == "PC-001"
    assert assertion.b == ip_ref("10.0.0.10")
    assert record.valid_to is None  # open: trusted for a bounded time after it was seen
    assert record.observed_at == datetime(2026, 10, 11, 11, 55, 0, 123000, tzinfo=UTC)
    assert record.valid_from == datetime(2026, 10, 11, 11, 54, 50, tzinfo=UTC)
    assert 0.8 <= record.confidence < 1


@pytest.mark.asyncio
async def test_the_device_id_is_stable_per_agent_and_never_derived_from_the_name() -> None:
    first = await agent_source(lambda _r: ok([hit(name="PC-001")])).fetch(
        start=START, end=NOW, limit=9
    )
    renamed = await agent_source(lambda _r: ok([hit(name="renamed")])).fetch(
        start=START, end=NOW, limit=9
    )
    other = await agent_source(lambda _r: ok([hit(id="002", name="PC-001")])).fetch(
        start=START, end=NOW, limit=9
    )
    id_of = lambda batch: batch.records[0].assertions[0].a.id
    assert id_of(first) == id_of(renamed) != id_of(other)


@pytest.mark.asyncio
async def test_a_disconnected_agent_evidence_has_ended() -> None:
    batch = await agent_source(
        lambda _r: ok([hit(status="disconnected", lastKeepAlive="2026-10-11T08:00:00Z")])
    ).fetch(start=START, end=NOW, limit=9)
    (record,) = batch.records
    assert record.valid_to is not None and record.valid_to < NOW  # expired, not live
    index = CorrelationIndex(list(batch.records), CorrelationPolicy())
    assert index.resolve(ip_ref("10.0.0.10"), NOW).endpoint == ()


@pytest.mark.asyncio
async def test_agents_that_were_never_connected_or_have_no_address_yield_no_evidence() -> None:
    batch = await agent_source(
        lambda _r: ok(
            [
                hit(id="001", status="never_connected"),
                hit(id="002", status="pending"),
                hit(id="003", ip="any"),
                hit(id="004"),
            ]
        )
    ).fetch(start=START, end=NOW, limit=9)
    assert [r.assertions[0].a.label for r in batch.records] == ["PC-001"]
    assert len(batch.records) == 1


@pytest.mark.asyncio
async def test_a_wazuh_agent_alone_never_names_a_person() -> None:
    batch = await agent_source(lambda _r: ok([hit()])).fetch(start=START, end=NOW, limit=9)
    result = CorrelationIndex(list(batch.records), CorrelationPolicy()).resolve(
        ip_ref("10.0.0.10"), NOW
    )
    assert result.attribution.basis is Basis.UNKNOWN and result.attribution.links == ()


@pytest.mark.asyncio
async def test_truncation_is_passed_on_so_the_service_can_refuse_the_read() -> None:
    hits = [hit(id=f"{n:03d}", ip=f"10.0.0.{n + 1}") for n in range(3)]
    batch = await agent_source(lambda _r: ok(hits)).fetch(start=START, end=NOW, limit=2)
    assert batch.truncated is True and len(batch.records) == 2


@pytest.mark.asyncio
async def test_adapter_errors_propagate_so_the_source_is_unknown() -> None:
    with pytest.raises(AdapterError):
        await agent_source(lambda _r: httpx.Response(500)).fetch(start=START, end=NOW, limit=9)


@pytest.mark.asyncio
async def test_a_loopback_or_multicast_agent_address_says_nothing() -> None:
    batch = await agent_source(
        lambda _r: ok(
            [hit(id="001", ip="127.0.0.1"), hit(id="002", ip="224.0.0.1"), hit(id="003", ip="::1")]
        )
    ).fetch(start=START, end=NOW, limit=9)
    assert batch.records == ()


@pytest.mark.asyncio
@pytest.mark.parametrize("address", ["999.9.9.9", "fe80::1%eth0", "10.0.0.1/24", "not-an-ip"])
async def test_one_agent_with_an_unusable_address_is_skipped_and_counted_not_fatal(
    address: str,
) -> None:
    hits = [hit(id="001", ip="10.0.0.10"), hit(id="002", ip="10.0.0.11"), hit(id="003", ip=address)]
    batch = await agent_source(lambda _r: ok(hits)).fetch(start=START, end=NOW, limit=9)
    assert [r.native_id for r in batch.records] == ["agent-001", "agent-002"]
    assert batch.skipped == 1


@pytest.mark.asyncio
async def test_when_most_agents_are_unusable_the_read_fails_rather_than_looking_empty() -> None:
    hits = [hit(id="001"), hit(id="002", ip="not-an-ip"), hit(id="003", ip="999.9.9.9")]
    with pytest.raises(AdapterError) as error:
        await agent_source(lambda _r: ok(hits)).fetch(start=START, end=NOW, limit=9)
    assert error.value.status is AdapterStatus.INVALID_SOURCE_DATA


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [{"status": "weird"}, {"timestamp": "yesterday"}, {"ip": 5}])
async def test_a_malformed_agent_row_is_skipped_by_the_client_and_counted(
    bad: dict[str, Any],
) -> None:
    hits = [hit(id="001"), hit(id="002"), hit(id="003", **bad)]
    inventory = await client(lambda _r: ok(hits)).agents(start=START, end=NOW, limit=9)
    assert [a.agent_id for a in inventory.agents] == ["001", "002"]
    assert inventory.skipped == 1


@pytest.mark.asyncio
async def test_an_ipv4_mapped_agent_address_is_the_ipv4() -> None:
    batch = await agent_source(lambda _r: ok([hit(ip="::ffff:10.0.0.10")])).fetch(
        start=START, end=NOW, limit=9
    )
    assert batch.records[0].assertions[0].b == ip_ref("10.0.0.10")


@pytest.mark.asyncio
async def test_a_disconnected_agent_never_seen_alive_has_no_moment_to_vouch_for() -> None:
    batch = await agent_source(
        lambda _r: ok([hit(status="disconnected", lastKeepAlive=None)])
    ).fetch(start=START, end=NOW, limit=9)
    assert batch.records == ()
