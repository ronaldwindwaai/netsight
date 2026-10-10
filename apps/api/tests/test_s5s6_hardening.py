"""Hardening carry-overs from the S5/S6 reviews (M1-M4, L1-L5, body cap, read limits)."""

from __future__ import annotations

import json
import logging
import ssl
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import certifi
import httpx
import pytest
import yaml  # type: ignore[import-untyped]
from fastapi.testclient import TestClient

from netsight_api import read_limit, security_routes
from netsight_api.adapters.wazuh import (
    AdapterError,
    AdapterStatus,
    WazuhIndexerClient,
    parse_hit,
)
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.contracts import SCHEMA_DIR
from netsight_api.main import app
from netsight_api.security_routes import get_optional_security_source

REPO_ROOT = SCHEMA_DIR.parents[1]
START = datetime(2026, 10, 6, 0, 0, tzinfo=UTC)
END = datetime(2026, 10, 6, 8, 0, tzinfo=UTC)
INCIDENT_COMMENTS = "/api/v1/incidents/incident-00000000-0000-0000-0000-000000000000/comment"


def _ok(hits: list[dict[str, Any]] | None = None) -> httpx.Response:
    return httpx.Response(200, json={"hits": {"hits": hits or []}})


def _client(url: str = "https://indexer.test:9200", **kwargs: Any) -> WazuhIndexerClient:
    kwargs.setdefault("user", "svc")
    kwargs.setdefault("password", "s3cret")
    kwargs.setdefault("_transport", httpx.MockTransport(lambda _r: _ok()))
    return WazuhIndexerClient(base_url=url, **kwargs)


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in (
        "NETSIGHT_ENV",
        "NETSIGHT_ENABLE_DEV_IDENTITY",
        "WAZUH_INDEXER_URL",
        "WAZUH_INDEXER_USER",
        "WAZUH_INDEXER_ALLOW_HTTP",
        "DATABASE_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def _dev(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_ENV", "development")
    monkeypatch.setenv("NETSIGHT_ENABLE_DEV_IDENTITY", "true")


# --- M1: credentials never travel over plain http ------------------------------------------


@pytest.mark.asyncio
async def test_credentials_over_plain_http_are_refused() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _ok()

    client = _client("http://indexer.test:9200", _transport=httpx.MockTransport(handler))
    with pytest.raises(AdapterError) as excinfo:
        await client.events(start=START, end=END, limit=10)
    assert excinfo.value.status is AdapterStatus.UNAVAILABLE
    assert "s3cret" not in excinfo.value.detail
    assert seen == []


@pytest.mark.asyncio
async def test_plain_http_without_credentials_is_allowed() -> None:
    client = _client("http://indexer.test:9200", user="", password="")
    events, _ = await client.events(start=START, end=END, limit=10)
    assert events == []


@pytest.mark.asyncio
async def test_plain_http_with_credentials_needs_explicit_dev_flag() -> None:
    client = _client("http://indexer.test:9200", allow_insecure_http=True)
    events, _ = await client.events(start=START, end=END, limit=10)
    assert events == []


def test_env_dev_flag_requires_development_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_INDEXER_URL", "http://indexer.test:9200")
    monkeypatch.setenv("WAZUH_INDEXER_ALLOW_HTTP", "true")
    source = get_optional_security_source()
    assert isinstance(source, WazuhIndexerClient)
    assert source.allow_insecure_http is False
    monkeypatch.setenv("NETSIGHT_ENV", "development")
    source = get_optional_security_source()
    assert isinstance(source, WazuhIndexerClient)
    assert source.allow_insecure_http is True


# --- M3: OpenAPI expresses non-ok => no rows, and equals the JSON schema ----------------------


def _normalise(node: Any, ref_map: dict[str, str], in_properties: bool = False) -> Any:
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for key, value in node.items():
            if not in_properties and key in {"$schema", "title", "description", "$defs"}:
                continue
            if not in_properties and key == "$ref" and isinstance(value, str):
                out[key] = ref_map.get(value, value.rsplit("/", 1)[-1])
                continue
            out[key] = _normalise(value, ref_map, key == "properties" and not in_properties)
        return out
    if isinstance(node, list):
        return [_normalise(item, ref_map) for item in node]
    return node


def test_openapi_security_response_matches_json_schema() -> None:
    openapi = yaml.safe_load(
        (REPO_ROOT / "contracts" / "openapi" / "netsight-api.yaml").read_text("utf-8")
    )
    schema = json.loads((SCHEMA_DIR / "security.schema.json").read_text("utf-8"))
    ref_map = {
        "#/$defs/event": "SecurityEvent",
        "traffic.schema.json#/$defs/timeRange": "TrafficTimeRange",
        "common.schema.json#/$defs/freshness": "Freshness",
    }
    components = openapi["components"]["schemas"]
    assert _normalise(components["SecurityEventsResponse"], ref_map) == _normalise(schema, ref_map)
    assert _normalise(components["SecurityEvent"], ref_map) == _normalise(
        schema["$defs"]["event"], ref_map
    )


# --- M4: whitespace-only optional text is absent, not an error ------------------------------


def test_whitespace_only_optional_fields_are_treated_as_absent() -> None:
    hit = {
        "_id": "ws-1",
        "_source": {
            "timestamp": "2026-10-06T07:55:00Z",
            "rule": {"description": "  padded rule  ", "level": 5, "groups": ["grp"]},
            "data": {"srcip": "   ", "dstip": "\t\n"},
        },
    }
    event = parse_hit(hit)
    assert event.source_ip is None
    assert event.destination_ip is None
    assert event.signature == "padded rule"


def test_whitespace_only_signature_is_invalid_not_blank() -> None:
    hit = {
        "_id": "ws-2",
        "_source": {
            "timestamp": "2026-10-06T07:55:00Z",
            "rule": {"description": "   ", "level": 5},
        },
    }
    with pytest.raises(AdapterError) as excinfo:
        parse_hit(hit)
    assert excinfo.value.status is AdapterStatus.INVALID_SOURCE_DATA


# --- L1: adapter failure status is logged --------------------------------------------------


def test_adapter_failure_status_is_logged(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _dev(monkeypatch)
    source = _client(_transport=httpx.MockTransport(lambda _r: httpx.Response(403)))
    app.dependency_overrides[get_optional_security_source] = lambda: source
    with caplog.at_level(logging.WARNING, logger="netsight_api"):
        response = TestClient(app).get("/api/v1/security/events")
    assert response.json()["state"] == "unknown"
    records = [r for r in caplog.records if r.getMessage() == "security source read failed"]
    assert records
    assert getattr(records[0], "adapter_status", None) == "forbidden"
    assert "s3cret" not in caplog.text


# --- L2: CA bundle becomes an SSLContext ---------------------------------------------------


def test_ca_bundle_path_becomes_ssl_context() -> None:
    verify = _client(verify=certifi.where())._tls_verify()
    assert isinstance(verify, ssl.SSLContext)
    assert verify.verify_mode is ssl.CERT_REQUIRED


def test_default_verify_stays_on() -> None:
    assert _client()._tls_verify() is True


@pytest.mark.asyncio
async def test_unreadable_ca_bundle_is_unavailable(tmp_path: Path) -> None:
    client = _client(verify=str(tmp_path / "missing.pem"))
    with pytest.raises(AdapterError) as excinfo:
        await client.events(start=START, end=END, limit=10)
    assert excinfo.value.status is AdapterStatus.UNAVAILABLE
    assert str(tmp_path) not in excinfo.value.detail


# --- L3: response-size cap -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_oversized_response_is_rejected() -> None:
    big = httpx.Response(200, content=b"x" * 4096)
    client = _client(_transport=httpx.MockTransport(lambda _r: big), max_response_bytes=1024)
    with pytest.raises(AdapterError) as excinfo:
        await client.events(start=START, end=END, limit=10)
    assert excinfo.value.status is AdapterStatus.INVALID_SOURCE_DATA


@pytest.mark.asyncio
async def test_response_within_cap_is_parsed() -> None:
    client = _client(max_response_bytes=1024)
    events, _ = await client.events(start=START, end=END, limit=10)
    assert events == []


# --- L4: only wazuh- indices ---------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    ["_all", "*", "other-alerts-*", "wazuh", ".security", "Wazuh-x", "wazuh-alerts-*\n"],
)
@pytest.mark.asyncio
async def test_non_wazuh_index_is_misconfiguration(pattern: str) -> None:
    with pytest.raises(AdapterError) as excinfo:
        await _client(index_pattern=pattern).events(start=START, end=END, limit=10)
    assert excinfo.value.status is AdapterStatus.UNAVAILABLE


@pytest.mark.asyncio
async def test_requests_ask_for_identity_encoding() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _ok()

    await _client(_transport=httpx.MockTransport(handler)).events(start=START, end=END, limit=10)
    assert seen[0].headers["accept-encoding"] == "identity"


@pytest.mark.asyncio
async def test_wazuh_prefixed_index_is_accepted() -> None:
    events, _ = await _client(index_pattern="wazuh-alerts-4.x-*").events(
        start=START, end=END, limit=10
    )
    assert events == []


# --- L5: docstring ------------------------------------------------------------------------


def test_security_routes_docstring_is_not_stale() -> None:
    assert "arrive in S5-2" not in (security_routes.__doc__ or "")


# --- request body size cap -----------------------------------------------------------------


def test_oversized_content_length_is_rejected_with_413(monkeypatch: pytest.MonkeyPatch) -> None:
    _dev(monkeypatch)
    body = b'{"x":"' + b"a" * (2 * 1024 * 1024) + b'"}'
    response = TestClient(app).post(
        INCIDENT_COMMENTS,
        content=body,
        headers={"content-type": "application/json", "x-correlation-id": "abc-1"},
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"
    assert response.headers["x-correlation-id"] == "abc-1"


def test_oversized_chunked_body_is_rejected_with_413(monkeypatch: pytest.MonkeyPatch) -> None:
    _dev(monkeypatch)

    def chunks() -> Iterator[bytes]:
        for _ in range(40):
            yield b"a" * (64 * 1024)

    response = TestClient(app).post(
        INCIDENT_COMMENTS,
        content=chunks(),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_normal_body_is_not_blocked_by_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    _dev(monkeypatch)
    response = TestClient(app).post(INCIDENT_COMMENTS, json={"body": "hello"})
    assert response.status_code != 413


def test_get_requests_are_not_subject_to_body_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    _dev(monkeypatch)
    response = TestClient(app).get("/api/v1/security/events")
    assert response.status_code == 200


# --- read rate limiting --------------------------------------------------------------------

_READ_PATHS = [
    "/api/v1/security/events",
    "/api/v1/traffic/top-talkers",
    "/api/v1/traffic/top-destinations",
    "/api/v1/traffic/flows",
    "/api/v1/incidents",
    "/api/v1/devices",
    "/api/v1/alerts",
    "/api/v1/alert-rules",
    "/api/v1/maintenance-windows",
]


@pytest.mark.parametrize("path", _READ_PATHS)
def test_reads_are_rate_limited_per_identity(monkeypatch: pytest.MonkeyPatch, path: str) -> None:
    _dev(monkeypatch)
    monkeypatch.setattr(read_limit, "_read_limiter", RateLimiter())
    monkeypatch.setattr(read_limit, "READ_LIMIT_PER_MINUTE", 2)
    client = TestClient(app)
    # Unconfigured upstream sources may answer 503; only the limiter's 429 matters here.
    assert client.get(path).status_code != 429
    assert client.get(path).status_code != 429
    limited = client.get(path)
    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "RATE_LIMITED"
    assert limited.headers["retry-after"]


def test_read_limit_does_not_mask_authorisation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(read_limit, "_read_limiter", RateLimiter())
    monkeypatch.setattr(read_limit, "READ_LIMIT_PER_MINUTE", 1)
    client = TestClient(app)
    for _ in range(3):
        assert client.get("/api/v1/security/events").status_code == 401


def test_read_limit_is_independent_per_family(monkeypatch: pytest.MonkeyPatch) -> None:
    _dev(monkeypatch)
    monkeypatch.setattr(read_limit, "_read_limiter", RateLimiter())
    monkeypatch.setattr(read_limit, "READ_LIMIT_PER_MINUTE", 1)
    client = TestClient(app)
    assert client.get("/api/v1/security/events").status_code == 200
    assert client.get("/api/v1/security/events").status_code == 429
    assert client.get("/api/v1/traffic/flows").status_code == 200
