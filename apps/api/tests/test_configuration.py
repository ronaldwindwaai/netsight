"""Oxidized boundary, metadata privacy, role policy and explicit read-state contracts."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from alerting_support import Caller, audit_records
from fastapi.testclient import TestClient

from netsight_api import configuration_routes as routes
from netsight_api.adapters.oxidized import (
    ConfigurationNodeNotFound,
    OxidizedClient,
    OxidizedUnavailable,
    canonical_node_id,
)
from netsight_api.contracts import validate
from netsight_api.main import app
from netsight_api.schemas_configuration import ConfigurationNodes, ConfigurationVersions

SECRET = "source-only-private-value"
NOW = datetime.now(UTC)


def node(**changes: Any) -> dict[str, Any]:
    return {
        "name": "core-switch",
        "group": "hq",
        "model": "ios",
        "last": {"status": "success", "end": NOW.isoformat()},
        "password": SECRET,
        "vars": {"community": SECRET},
        **changes,
    }


def source(payload: object, status: int = 200) -> OxidizedClient:
    return OxidizedClient(
        "https://oxidized.example/prefix",
        SECRET,
        _transport=httpx.MockTransport(lambda request: httpx.Response(status, json=payload)),
    )


@pytest.mark.asyncio
async def test_nodes_only_select_safe_metadata() -> None:
    result = await source([node()]).nodes()
    validate("configuration_nodes", result.model_dump(mode="json"))
    assert result.state == "ok" and result.items[0].backup_freshness == "fresh"
    assert result.items[0].id == canonical_node_id("hq/core-switch")
    assert SECRET not in result.model_dump_json()


@pytest.mark.asyncio
async def test_versions_use_documented_query_and_never_forward_client_paths() -> None:
    requests = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/prefix/nodes.json":
            return httpx.Response(200, json=[node()])
        assert request.url.path == "/prefix/node/version.json"
        assert request.url.params["node_full"] == "hq/core-switch"
        return httpx.Response(
            200,
            json=[
                {
                    "oid": "a" * 40,
                    "time": NOW.isoformat(),
                    "author": {"email": SECRET},
                    "message": SECRET,
                }
            ],
        )

    adapter = OxidizedClient(
        "https://oxidized.example/prefix", SECRET, _transport=httpx.MockTransport(respond)
    )
    result = await adapter.versions(canonical_node_id("hq/core-switch"))
    validate("configuration_versions", result.model_dump(mode="json"))
    assert result.items[0].id == "a" * 40
    assert SECRET not in result.model_dump_json()
    assert all(request.method == "GET" for request in requests)
    assert all(request.headers["Authorization"] == f"Bearer {SECRET}" for request in requests)


@pytest.mark.asyncio
async def test_partial_and_stale_source_data_are_explicit() -> None:
    result = await source(
        [node(last={"status": "success", "end": (NOW - timedelta(days=2)).isoformat()}), None]
    ).nodes()
    assert result.state == "partial" and result.skipped == 1
    assert result.items[0].backup_freshness == "stale"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload,status", [([], 403), ([], 500), ([], 302), ({}, 200), ([None], 200)]
)
async def test_unreadable_source_does_not_look_empty(payload: object, status: int) -> None:
    with pytest.raises(OxidizedUnavailable):
        await source(payload, status).nodes()


@pytest.mark.asyncio
async def test_empty_and_missing_node_are_distinct() -> None:
    assert (await source([]).nodes()).state == "ok"
    with pytest.raises(ConfigurationNodeNotFound):
        await source([]).versions(canonical_node_id("missing"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "http://internal.example",
        "https://user:password@oxidized.example",
        "https://oxidized.example?x=1",
        "file:///etc/passwd",
        "https://oxidized.example/../private",
        "https://oxidized.example:bad",
    ],
)
async def test_invalid_source_settings_do_not_make_network_requests(url: str) -> None:
    called = []
    adapter = OxidizedClient(url, _transport=httpx.MockTransport(lambda r: called.append(r)))
    with pytest.raises(OxidizedUnavailable):
        await adapter.nodes()
    assert not called


@pytest.mark.asyncio
async def test_redirect_cannot_send_source_token_elsewhere() -> None:
    called = []

    def redirect(request: httpx.Request) -> httpx.Response:
        called.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://attacker.example/private"})

    with pytest.raises(OxidizedUnavailable):
        await OxidizedClient(
            "https://oxidized.example", SECRET, _transport=httpx.MockTransport(redirect)
        ).nodes()
    assert called == ["https://oxidized.example/nodes.json"]


@pytest.mark.asyncio
async def test_duplicate_ids_and_unsafe_source_names_are_accounted_for() -> None:
    result = await source([node(), node(), node(name="../private")]).nodes()
    assert result.state == "partial" and result.skipped == 2 and len(result.items) == 1


@pytest.mark.asyncio
async def test_timeout_and_oversize_are_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    from netsight_api.adapters import oxidized

    monkeypatch.setattr(oxidized, "MAX_BYTES", 10)
    with pytest.raises(OxidizedUnavailable):
        await source([node()]).nodes()

    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout(SECRET)

    with pytest.raises(OxidizedUnavailable):
        await OxidizedClient(
            "https://oxidized.example", _transport=httpx.MockTransport(timeout)
        ).nodes()


@pytest.fixture(autouse=True)
def wiring(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.delenv("OXIDIZED_BASE_URL", raising=False)
    monkeypatch.delenv("NETSIGHT_ENABLE_DEV_IDENTITY", raising=False)
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


@pytest.mark.parametrize(
    "role,expected",
    [
        ("administrator", 200),
        ("network_engineer", 200),
        ("security_analyst", 200),
        ("technician", 200),
        ("auditor", 200),
        ("management", 403),
        ("unknown", 403),
    ],
)
def test_role_policy_is_enforced_before_source_access(role: str, expected: int) -> None:
    response = Caller(role).get("/api/v1/config/nodes")
    assert response.status_code == expected
    assert response.headers["cache-control"] == "no-store"
    if expected == 200:
        assert response.json()["state"] == "not-connected"


def test_anonymous_and_unknown_parameters_are_refused() -> None:
    assert TestClient(app).get("/api/v1/config/nodes").status_code == 401
    assert Caller("administrator").get("/api/v1/config/nodes", token=SECRET).status_code == 422


def test_source_error_is_unknown_and_audited_without_secrets(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app.dependency_overrides[routes.get_configuration_source] = lambda: source([], 403)
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        response = Caller("administrator").get("/api/v1/config/nodes")
    assert response.status_code == 200 and response.json()["state"] == "unknown"
    assert SECRET not in response.text and SECRET not in caplog.text
    assert audit_records(caplog)[-1]["outcome"] == "failure"


@pytest.mark.parametrize(
    "model,schema",
    [
        (ConfigurationNodes, "configuration_nodes"),
        (ConfigurationVersions, "configuration_versions"),
    ],
)
def test_canonical_schema_and_model_reject_incoherent_states(model: Any, schema: str) -> None:
    for state in ["ok", "partial", "not-connected", "unknown"]:
        data = {
            "source": "oxidized",
            "state": state,
            "observed_at": None,
            "items": [],
            "skipped": 0,
            "truncated": False,
        }
        if state in {"ok", "partial"}:
            data["observed_at"] = NOW.isoformat()
        if state == "partial":
            data["skipped"] = 1
        assert model.model_validate(data)
        validate(schema, json.loads(json.dumps(data)))


def test_api_pagination_has_bounded_pages_and_no_false_total_for_unavailable_source() -> None:
    app.dependency_overrides[routes.get_configuration_source] = lambda: source(
        [node(name=f"switch-{i:03d}") for i in range(105)]
    )
    caller = Caller("administrator")
    first = caller.get("/api/v1/config/nodes", page=1, page_size=100).json()
    second = caller.get("/api/v1/config/nodes", page=2, page_size=100).json()
    assert len(first["items"]) == 100 and first["has_more"]
    assert len(second["items"]) == 5 and not second["has_more"]
    assert first["total"] == second["total"] == 105
    assert {n["id"] for n in first["items"]}.isdisjoint(n["id"] for n in second["items"])
    assert caller.get("/api/v1/config/nodes", page_size=101).status_code == 422
    assert caller.http.get("/api/v1/config/nodes?page=1&page=2").status_code == 422


def test_versions_are_authorized_and_unknown_source_cannot_be_a_false_404() -> None:
    caller = Caller("administrator")
    node_id = canonical_node_id("hq/core-switch")
    path = f"/api/v1/config/nodes/{node_id}/versions"
    assert Caller("management").get(path).status_code == 403
    app.dependency_overrides[routes.get_configuration_source] = lambda: source([])
    assert caller.get(path).status_code == 404
    app.dependency_overrides[routes.get_configuration_source] = lambda: source([None])
    result = caller.get(path)
    assert result.status_code == 200 and result.json()["state"] == "unknown"


@pytest.mark.asyncio
async def test_transient_source_failure_is_retried_once() -> None:
    calls = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, text=SECRET) if calls == 1 else httpx.Response(200, json=[])

    result = await OxidizedClient(
        "https://oxidized.example", _transport=httpx.MockTransport(respond)
    ).nodes()
    assert result.state == "ok" and calls == 2


@pytest.mark.parametrize(
    "case",
    json.loads(
        (
            Path(__file__).resolve().parents[3]
            / "contracts/test-vectors/configuration.vectors.json"
        ).read_text()
    ),
    ids=lambda case: case["name"],
)
def test_shared_configuration_vectors(case: dict[str, Any]) -> None:
    from pydantic import ValidationError

    from netsight_api.contracts import ContractViolation

    model = ConfigurationNodes if case["target"] == "nodes" else ConfigurationVersions
    schema = "configuration_" + case["target"]
    for validation in [
        lambda: model.model_validate(case["data"]),
        lambda: validate(schema, case["data"]),
    ]:
        if case["valid"]:
            validation()
        else:
            with pytest.raises((ValidationError, ContractViolation)):
                validation()


@pytest.mark.asyncio
async def test_upstream_full_name_disambiguates_ungrouped_nodes() -> None:
    queries = []

    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("nodes.json"):
            return httpx.Response(200, json=[node(group="default", full_name="core-switch")])
        queries.append(request.url.params["node_full"])
        return httpx.Response(200, json=[])

    adapter = OxidizedClient("https://oxidized.example", _transport=httpx.MockTransport(respond))
    snapshot = await adapter.nodes()
    assert snapshot.items[0].group is None
    await adapter.versions(snapshot.items[0].id)
    assert queries == ["core-switch"]
