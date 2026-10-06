"""Contract tests for the topology surface (S3, build plan step 1)."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from netsight_api.contracts import ContractViolation, validate
from netsight_api.main import app

DEVICE_A = "device-a7f3d9e1-1c2b-4a8e-9f0d-5b6c7d8e9f01"
DEVICE_B = "device-b1c2d3e4-5f6a-4b7c-8d9e-0a1b2c3d4e56"


def _dev_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_ENV", "development")
    monkeypatch.setenv("NETSIGHT_ENABLE_DEV_IDENTITY", "true")


@pytest.fixture(autouse=True)
def _clean_app_state(monkeypatch: pytest.MonkeyPatch):
    for name in ("NETSIGHT_ENV", "NETSIGHT_ENABLE_DEV_IDENTITY"):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def test_topology_requires_authentication() -> None:
    response = TestClient(app).get("/api/v1/topology")
    assert response.status_code == 401


def test_topology_default_state_is_not_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    _dev_identity(monkeypatch)
    response = TestClient(app).get("/api/v1/topology")

    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    assert body["state"] == "not-connected"
    assert body["nodes"] == []
    assert body["edges"] == []
    assert body["freshness"]["state"] == "unknown"
    validate("topology", body)


def test_topology_openapi_route_versioned() -> None:
    schema = app.openapi()
    assert "/api/v1/topology" in schema["paths"]


def test_valid_graph_contract() -> None:
    instance = {
        "state": "ok",
        "nodes": [{"device_id": DEVICE_A}, {"device_id": DEVICE_B}],
        "edges": [
            {
                "source_device_id": DEVICE_A,
                "target_device_id": DEVICE_B,
                "source": "lldp",
                "observed_at": "2026-10-06T08:00:00Z",
            }
        ],
        "freshness": {"state": "fresh", "observed_at": "2026-10-06T08:00:00Z", "source": "netbox"},
    }
    validate("topology", instance)


@pytest.mark.parametrize(
    "instance",
    [
        # ok state must not be empty — never fabricate a graph
        {
            "state": "ok",
            "nodes": [],
            "edges": [],
            "freshness": {"state": "unknown", "observed_at": None, "source": None},
        },
        # not-connected must not carry data
        {
            "state": "not-connected",
            "nodes": [{"device_id": DEVICE_A}],
            "edges": [],
            "freshness": {"state": "unknown", "observed_at": None, "source": None},
        },
        # non-canonical device id
        {
            "state": "ok",
            "nodes": [{"device_id": "librenms:1"}],
            "edges": [],
            "freshness": {"state": "fresh", "observed_at": None, "source": "lldp"},
        },
        # unknown edge source
        {
            "state": "ok",
            "nodes": [{"device_id": DEVICE_A}],
            "edges": [
                {
                    "source_device_id": DEVICE_A,
                    "target_device_id": DEVICE_A,
                    "source": "guess",
                }
            ],
            "freshness": {"state": "fresh", "observed_at": None, "source": "lldp"},
        },
    ],
)
def test_invalid_topology_contract_violations(instance: dict[str, Any]) -> None:
    with pytest.raises(ContractViolation):
        validate("topology", instance)
