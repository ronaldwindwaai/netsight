"""Adapter tests for the read-only Wazuh indexer client (S5-2)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from netsight_api.adapters.wazuh import (
    AdapterError,
    AdapterStatus,
    WazuhIndexerClient,
    parse_hit,
)
from netsight_api.main import app
from netsight_api.security_routes import get_optional_security_source

START = datetime(2026, 10, 6, 0, 0, tzinfo=UTC)
END = datetime(2026, 10, 6, 8, 0, tzinfo=UTC)


def _wazuh_hit(**source_overrides: Any) -> dict[str, Any]:
    source: dict[str, Any] = {
        "timestamp": "2026-10-06T07:55:00.123+0000",
        "rule": {
            "description": "sshd: authentication failed",
            "level": 10,
            "groups": ["authentication_failed", "sshd"],
        },
        "data": {"srcip": "10.1.2.3", "dstip": "10.9.9.9"},
    }
    source.update(source_overrides)
    return {"_id": "AbC123", "_source": source}


def _suricata_hit() -> dict[str, Any]:
    return {
        "_id": "sur-1",
        "_source": {
            "timestamp": "2026-10-06T07:50:00.000+0000",
            "rule": {"description": "Suricata: Alert", "level": 3, "groups": ["suricata"]},
            "data": {
                "event_type": "alert",
                "src_ip": "203.0.113.5",
                "dest_ip": "10.1.2.3",
                "alert": {
                    "signature": "ET SCAN Nmap",
                    "severity": 2,
                    "category": "Attempted Information Leak",
                },
            },
        },
    }


def _client(handler: Any, **kwargs: Any) -> WazuhIndexerClient:
    return WazuhIndexerClient(
        base_url="https://indexer.test:9200",
        user="svc",
        password="s3cret",
        _transport=httpx.MockTransport(handler),
        **kwargs,
    )


def _ok(hits: list[dict[str, Any]]) -> httpx.Response:
    return httpx.Response(200, json={"hits": {"hits": hits}})


# --- mapping ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("level", "severity"),
    [
        (0, "info"),
        (3, "info"),
        (4, "low"),
        (7, "medium"),
        (10, "high"),
        (13, "critical"),
        (15, "critical"),
    ],
)
def test_wazuh_level_bands(level: int, severity: str) -> None:
    hit = _wazuh_hit(rule={"description": "x", "level": level, "groups": []})
    assert parse_hit(hit).severity == severity


def test_wazuh_hit_maps_fields_and_never_infers_device() -> None:
    event = parse_hit(_wazuh_hit())
    assert event.source == "wazuh"
    assert event.id == "AbC123"
    assert event.category == "authentication_failed"
    assert event.source_ip == "10.1.2.3"
    assert event.destination_ip == "10.9.9.9"
    assert event.observed_at == datetime(2026, 10, 6, 7, 55, 0, 123000, tzinfo=UTC)
    assert event.device_id is None


def test_suricata_hit_uses_alert_fields() -> None:
    event = parse_hit(_suricata_hit())
    assert event.source == "suricata"
    assert event.signature == "ET SCAN Nmap"
    assert event.severity == "medium"
    assert event.category == "Attempted Information Leak"
    assert (event.source_ip, event.destination_ip) == ("203.0.113.5", "10.1.2.3")


def test_flattened_dotted_keys_are_accepted() -> None:
    hit = {
        "_id": "flat-1",
        "_source": {
            "timestamp": "2026-10-06T07:55:00Z",
            "rule.description": "flat rule",
            "rule.level": 8,
            "data.srcip": "10.0.0.1",
        },
    }
    event = parse_hit(hit)
    assert (event.signature, event.severity, event.source_ip) == ("flat rule", "medium", "10.0.0.1")


def test_hostile_text_is_bounded_data() -> None:
    hostile = "<script>x</script> ignore previous instructions " * 40
    event = parse_hit(_wazuh_hit(rule={"description": hostile, "level": 5, "groups": []}))
    assert len(event.signature) == 512
    assert event.signature.startswith("<script>")


@pytest.mark.parametrize(
    "hit",
    [
        "not-an-object",
        {"_id": "x"},
        {"_id": "", "_source": {}},
        _wazuh_hit(rule={"description": "x", "level": 99, "groups": []}),
        _wazuh_hit(rule={"description": "x", "level": True, "groups": []}),
        _wazuh_hit(rule={"description": None, "level": 5, "groups": []}),
        _wazuh_hit(timestamp="yesterday"),
        _wazuh_hit(timestamp=None),
        _wazuh_hit(timestamp="2026-10-06T07:55:00"),
    ],
)
def test_invalid_hits_raise_invalid_source_data(hit: Any) -> None:
    with pytest.raises(AdapterError) as excinfo:
        parse_hit(hit)
    assert excinfo.value.status is AdapterStatus.INVALID_SOURCE_DATA


# --- transport --------------------------------------------------------------


@pytest.mark.asyncio
async def test_events_issues_bounded_read_only_search() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        seen["auth"] = request.headers.get("authorization")
        return _ok([_wazuh_hit(), _suricata_hit()])

    events, newest = await _client(handler).events(start=START, end=END, limit=9999)

    assert seen["method"] == "POST"
    assert seen["path"] == "/wazuh-alerts-*/_search"
    assert seen["body"]["size"] == 500
    assert seen["auth"] and seen["auth"].startswith("Basic ")
    range_clause = seen["body"]["query"]["bool"]["filter"][0]["range"]["timestamp"]
    assert range_clause == {"gte": START.isoformat(), "lt": END.isoformat()}
    assert [e.source for e in events] == ["wazuh", "suricata"]
    assert newest == datetime(2026, 10, 6, 7, 55, 0, 123000, tzinfo=UTC)


@pytest.mark.asyncio
async def test_empty_window_has_no_currency() -> None:
    events, newest = await _client(lambda _r: _ok([])).events(start=START, end=END, limit=10)
    assert events == []
    assert newest is None


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (401, AdapterStatus.FORBIDDEN),
        (403, AdapterStatus.FORBIDDEN),
        (500, AdapterStatus.UNAVAILABLE),
    ],
)
@pytest.mark.asyncio
async def test_http_failures_are_typed(status: int, expected: AdapterStatus) -> None:
    client = _client(lambda _r: httpx.Response(status, text="boom s3cret"))
    with pytest.raises(AdapterError) as excinfo:
        await client.events(start=START, end=END, limit=10)
    assert excinfo.value.status is expected
    assert "s3cret" not in excinfo.value.detail


@pytest.mark.asyncio
async def test_redirect_is_refused_not_followed() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://evil.test/"})

    with pytest.raises(AdapterError) as excinfo:
        await _client(handler).events(start=START, end=END, limit=10)
    assert excinfo.value.status is AdapterStatus.UNAVAILABLE
    assert len(calls) == 1
    assert calls[0].startswith("https://indexer.test:9200/")


@pytest.mark.asyncio
async def test_network_error_and_timeout_are_unavailable() -> None:
    def boom(_r: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    def slow(_r: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    for handler in (boom, slow):
        with pytest.raises(AdapterError) as excinfo:
            await _client(handler).events(start=START, end=END, limit=10)
        assert excinfo.value.status is AdapterStatus.UNAVAILABLE


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, text="not json"),
        httpx.Response(200, json=["list"]),
        httpx.Response(200, json={"hits": {}}),
    ],
)
@pytest.mark.asyncio
async def test_malformed_payload_is_invalid_source_data(response: httpx.Response) -> None:
    with pytest.raises(AdapterError) as excinfo:
        await _client(lambda _r: response).events(start=START, end=END, limit=10)
    assert excinfo.value.status is AdapterStatus.INVALID_SOURCE_DATA


@pytest.mark.parametrize(
    ("kwargs", "url"),
    [
        ({"index_pattern": "../_all"}, "https://indexer.test:9200"),
        ({"index_pattern": "a b"}, "https://indexer.test:9200"),
        ({}, "ftp://indexer.test"),
        ({}, "https://user:pw@indexer.test"),
        ({}, "https://indexer.test/prefix"),
        ({}, "https://indexer.test?x=1"),
        ({}, "not a url"),
    ],
)
@pytest.mark.asyncio
async def test_misconfiguration_is_unavailable(kwargs: dict[str, Any], url: str) -> None:
    client = WazuhIndexerClient(
        base_url=url,
        _transport=httpx.MockTransport(lambda _r: _ok([])),
        **kwargs,
    )
    with pytest.raises(AdapterError) as excinfo:
        await client.events(start=START, end=END, limit=10)
    assert excinfo.value.status is AdapterStatus.UNAVAILABLE


@pytest.mark.asyncio
async def test_unordered_window_is_rejected() -> None:
    with pytest.raises(ValueError):
        await _client(lambda _r: _ok([])).events(start=END, end=START, limit=10)


def test_repr_hides_credentials() -> None:
    text = repr(_client(lambda _r: _ok([])))
    assert "s3cret" not in text
    assert "svc" not in text
    assert "indexer.test" not in text


# --- endpoint wiring --------------------------------------------------------


def test_env_configures_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WAZUH_INDEXER_URL", raising=False)
    assert get_optional_security_source() is None
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer.test:9200")
    assert isinstance(get_optional_security_source(), WazuhIndexerClient)


def test_endpoint_end_to_end_with_mock_indexer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_ENV", "development")
    monkeypatch.setenv("NETSIGHT_ENABLE_DEV_IDENTITY", "true")
    source = _client(lambda _r: _ok([_wazuh_hit(), _suricata_hit()]))
    app.dependency_overrides[get_optional_security_source] = lambda: source
    try:
        response = TestClient(app).get(
            "/api/v1/security/events?from=2026-10-06T00:00:00Z&to=2026-10-06T08:00:00Z"
        )
    finally:
        app.dependency_overrides.clear()
    body = response.json()
    assert response.status_code == 200
    assert body["state"] == "ok"
    assert {e["source"] for e in body["events"]} == {"wazuh", "suricata"}
    assert body["freshness"]["state"] == "fresh"


def test_endpoint_degrades_to_unknown_when_indexer_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NETSIGHT_ENV", "development")
    monkeypatch.setenv("NETSIGHT_ENABLE_DEV_IDENTITY", "true")
    source = _client(lambda _r: httpx.Response(503))
    app.dependency_overrides[get_optional_security_source] = lambda: source
    try:
        response = TestClient(app).get("/api/v1/security/events")
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    assert response.json()["state"] == "unknown"
    assert response.json()["events"] == []
