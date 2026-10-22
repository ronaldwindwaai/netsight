"""Contract tests for the topology surface (S3, build plan step 1)."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from netsight_api.auth.deps import get_current_identity
from netsight_api.contracts import ContractViolation, validate
from netsight_api.main import app
from netsight_api.rbac import Identity

DEVICE_A = "device-a7f3d9e1-1c2b-4a8e-9f0d-5b6c7d8e9f01"
DEVICE_B = "device-b1c2d3e4-5f6a-4b7c-8d9e-0a1b2c3d4e56"


def _dev_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_ENV", "development")
    monkeypatch.setenv("NETSIGHT_ENABLE_DEV_IDENTITY", "true")


@pytest.fixture(autouse=True)
def _clean_app_state(monkeypatch: pytest.MonkeyPatch):
    for name in (
        "NETSIGHT_ENV",
        "NETSIGHT_ENABLE_DEV_IDENTITY",
        "NETBOX_BASE_URL",
        "NETBOX_TOKEN",
        "LIBRENMS_BASE_URL",
        "LIBRENMS_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def test_topology_requires_authentication() -> None:
    response = TestClient(app).get("/api/v1/topology")
    assert response.status_code == 401


def test_topology_forbidden_without_devices_read() -> None:
    """An authenticated identity lacking DEVICES_READ must be denied."""
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "limited-user", frozenset({"unknown-role"})
    )

    response = TestClient(app).get("/api/v1/topology")

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


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
        "nodes": [
            {
                "device_id": DEVICE_A,
                "name": "core-sw-01",
                "reconciled": True,
                "finding": None,
            },
            {
                "device_id": DEVICE_B,
                "name": "edge-sw-02",
                "reconciled": True,
                "finding": {
                    "kind": "missing-discovered",
                    "detail": "Intended device not seen by LibreNMS discovery",
                },
            },
        ],
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


def test_connected_source_may_report_an_explicitly_empty_graph() -> None:
    """A configured source with zero cables is ok + empty, not fabrication."""
    instance = {
        "state": "ok",
        "nodes": [],
        "edges": [],
        "freshness": {"state": "fresh", "observed_at": "2026-10-06T08:00:00Z", "source": "netbox"},
    }
    validate("topology", instance)


@pytest.mark.parametrize(
    "instance",
    [
        # not-connected must not carry data
        {
            "state": "not-connected",
            "nodes": [
                {
                    "device_id": DEVICE_A,
                    "name": None,
                    "reconciled": False,
                    "finding": None,
                }
            ],
            "edges": [],
            "freshness": {"state": "unknown", "observed_at": None, "source": None},
        },
        # unknown must not carry data — nothing is drawn from a failed source
        {
            "state": "unknown",
            "nodes": [
                {
                    "device_id": DEVICE_A,
                    "name": None,
                    "reconciled": False,
                    "finding": None,
                }
            ],
            "edges": [],
            "freshness": {"state": "unknown", "observed_at": None, "source": "netbox"},
        },
        # non-canonical device id
        {
            "state": "ok",
            "nodes": [
                {
                    "device_id": "librenms:1",
                    "name": None,
                    "reconciled": False,
                    "finding": None,
                }
            ],
            "edges": [],
            "freshness": {"state": "fresh", "observed_at": None, "source": "lldp"},
        },
        # node without a name key is not canonical
        {
            "state": "ok",
            "nodes": [{"device_id": DEVICE_A, "reconciled": False, "finding": None}],
            "edges": [],
            "freshness": {"state": "fresh", "observed_at": None, "source": "lldp"},
        },
        # a finding must never appear when reconciliation did not run
        {
            "state": "ok",
            "nodes": [
                {
                    "device_id": DEVICE_A,
                    "name": None,
                    "reconciled": False,
                    "finding": {
                        "kind": "status-mismatch",
                        "detail": "NetBox status=offline; discovered status=healthy",
                    },
                }
            ],
            "edges": [],
            "freshness": {"state": "fresh", "observed_at": None, "source": "lldp"},
        },
        # finding kinds outside the reconciliation vocabulary
        {
            "state": "ok",
            "nodes": [
                {
                    "device_id": DEVICE_A,
                    "name": None,
                    "reconciled": True,
                    "finding": {"kind": "unknown-discovered", "detail": "rogue"},
                }
            ],
            "edges": [],
            "freshness": {"state": "fresh", "observed_at": None, "source": "lldp"},
        },
        # unknown edge source
        {
            "state": "ok",
            "nodes": [
                {
                    "device_id": DEVICE_A,
                    "name": None,
                    "reconciled": False,
                    "finding": None,
                }
            ],
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


# --- End-to-end: NetBox wired as the explicit edge source -------------------


def _cable(
    cable_id: int,
    *,
    status: str = "active",
    device_a: Any = 1,
    device_b: Any = 2,
    termination_b: dict[str, Any] | None = None,
) -> dict[str, Any]:
    termination_a: dict[str, Any] = {
        "id": cable_id * 10,
        "object_type": "dcim.interface",
        "object": {"name": "Ethernet1", "device": {"id": device_a, "name": "sw-a"}},
    }
    if termination_b is None:
        termination_b = {
            "id": cable_id * 10 + 1,
            "object_type": "dcim.interface",
            "object": {"name": "Ethernet1", "device": {"id": device_b, "name": "sw-b"}},
        }
    return {
        "id": cable_id,
        "status": {"value": status, "label": status.title()},
        "termination_a": termination_a,
        "termination_b": termination_b,
        "last_updated": "2026-10-05T10:00:00Z",
    }


def _wire_netbox(
    cables: list[dict[str, Any]],
    devices: list[dict[str, Any]] | None = None,
) -> None:
    import httpx

    from netsight_api.adapters.netbox import NetboxClient
    from netsight_api.main import get_optional_netbox_client

    device_rows = (
        devices
        if devices is not None
        else [
            {"id": 1, "name": "core-sw-01", "display": "core-sw-01"},
            {"id": 2, "name": "edge-sw-02", "display": "edge-sw-02"},
            {"id": 3, "name": "dist-sw-03", "display": "dist-sw-03"},
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/dcim/cables/":
            return httpx.Response(200, json={"count": len(cables), "results": cables})
        if request.url.path == "/api/dcim/devices/":
            return httpx.Response(200, json={"count": len(device_rows), "results": device_rows})
        raise AssertionError(f"unexpected source path: {request.url.path}")

    client = NetboxClient(
        base_url="http://netbox.test",
        token="test-token",
        _transport=httpx.MockTransport(handler),
    )
    app.dependency_overrides[get_optional_netbox_client] = lambda: client


def test_topology_builds_explicit_graph_from_active_cables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _dev_identity(monkeypatch)
    _wire_netbox([_cable(1, device_a=1, device_b=2), _cable(2, device_a=2, device_b=3)])

    response = TestClient(app).get("/api/v1/topology")

    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    assert body["state"] == "ok"
    assert len(body["nodes"]) == 3
    assert len(body["edges"]) == 2
    from netsight_api.adapters.netbox import canonical_device_id as netbox_id

    assert {node["device_id"]: node["name"] for node in body["nodes"]} == {
        netbox_id("1"): "core-sw-01",
        netbox_id("2"): "edge-sw-02",
        netbox_id("3"): "dist-sw-03",
    }
    assert {edge["source"] for edge in body["edges"]} == {"netbox"}
    assert {edge["observed_at"] for edge in body["edges"]} == {"2026-10-05T10:00:00Z"}
    # Discovery source not configured: reconciliation is explicitly NOT checked.
    assert all(node["reconciled"] is False and node["finding"] is None for node in body["nodes"])
    assert body["freshness"] == {
        "state": "fresh",
        "observed_at": body["freshness"]["observed_at"],
        "source": "netbox",
    }
    validate("topology", body)


def test_topology_skips_non_evidenced_cables(monkeypatch: pytest.MonkeyPatch) -> None:
    """Planned cables and device-less terminations never become edges."""
    _dev_identity(monkeypatch)
    _wire_netbox(
        [
            _cable(1, status="planned"),
            _cable(2, termination_b={"id": 21, "object_type": "frontport"}),
            _cable(3, device_a=5, device_b=5),
        ]
    )

    response = TestClient(app).get("/api/v1/topology")

    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    assert body["state"] == "ok"
    assert body["nodes"] == []
    assert body["edges"] == []
    validate("topology", body)


def test_topology_source_failure_reports_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A configured source that cannot be read yields unknown + empty graph."""
    _dev_identity(monkeypatch)

    import httpx

    from netsight_api.adapters.netbox import NetboxClient
    from netsight_api.main import get_optional_netbox_client

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"detail": "boom"})

    client = NetboxClient(
        base_url="http://netbox.test",
        token="test-token",
        _transport=httpx.MockTransport(handler),
    )
    app.dependency_overrides[get_optional_netbox_client] = lambda: client

    response = TestClient(app).get("/api/v1/topology")

    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    assert body["state"] == "unknown"
    assert body["nodes"] == []
    assert body["edges"] == []
    assert body["freshness"] == {
        "state": "unknown",
        "observed_at": None,
        "source": "netbox",
    }
    validate("topology", body)


def test_topology_keeps_graph_when_name_lookup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Names are cosmetic: a failed device lookup must not drop the graph."""
    _dev_identity(monkeypatch)

    import httpx

    from netsight_api.adapters.netbox import NetboxClient
    from netsight_api.main import get_optional_netbox_client

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/dcim/cables/":
            return httpx.Response(200, json={"count": 1, "results": [_cable(1)]})
        return httpx.Response(500, json={"detail": "boom"})

    client = NetboxClient(
        base_url="http://netbox.test",
        token="test-token",
        _transport=httpx.MockTransport(handler),
    )
    app.dependency_overrides[get_optional_netbox_client] = lambda: client

    response = TestClient(app).get("/api/v1/topology")

    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    assert body["state"] == "ok"
    assert len(body["nodes"]) == 2
    assert all(node["name"] is None for node in body["nodes"])
    assert all(node["reconciled"] is False for node in body["nodes"])
    assert len(body["edges"]) == 1
    validate("topology", body)


def _wire_librenms(rows: list[dict[str, Any]] | None, *, fail: bool = False) -> None:
    """Wire the optional discovery source; rows=None means not configured."""
    from netsight_api.main import get_optional_librenms_client

    if rows is None:
        app.dependency_overrides[get_optional_librenms_client] = lambda: None
        return

    import httpx

    from netsight_api.adapters.librenms import LibrenmsClient

    def handler(_request: httpx.Request) -> httpx.Response:
        if fail:
            return httpx.Response(500, json={"message": "boom"})
        return httpx.Response(200, json={"status": "ok", "devices": rows})

    client = LibrenmsClient(
        base_url="http://librenms.test",
        token="test-token",
        _transport=httpx.MockTransport(handler),
    )
    app.dependency_overrides[get_optional_librenms_client] = lambda: client


def test_topology_attaches_reconciliation_findings_in_edge_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Intent-vs-discovery drift is surfaced on the node it belongs to.

    Findings annotate the graph; they never replace source data, and
    `unknown-discovered` findings have no NetBox node to attach to.
    """
    _dev_identity(monkeypatch)
    _wire_netbox(
        [_cable(1, device_a=1, device_b=2), _cable(2, device_a=2, device_b=3)],
        devices=[
            {"id": 1, "name": "core-sw-01", "display": "core-sw-01"},
            {
                "id": 2,
                "name": "edge-sw-02",
                "display": "edge-sw-02",
                "status": {"value": "offline", "label": "Offline"},
            },
            {"id": 3, "name": "dist-sw-03", "display": "dist-sw-03"},
        ],
    )
    _wire_librenms(
        [
            {"device_id": 10, "hostname": "core-sw-01", "status": 1},
            {"device_id": 11, "hostname": "edge-sw-02", "status": 1},
            {"device_id": 12, "hostname": "rogue-sw", "status": 1},
        ]
    )

    response = TestClient(app).get("/api/v1/topology")

    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    assert body["state"] == "ok"
    from netsight_api.adapters.netbox import canonical_device_id as netbox_id

    findings = {node["device_id"]: node["finding"] for node in body["nodes"]}
    assert all(node["reconciled"] is True for node in body["nodes"])
    assert findings[netbox_id("1")] is None
    assert findings[netbox_id("2")] is not None
    assert findings[netbox_id("2")]["kind"] == "status-mismatch"
    assert findings[netbox_id("3")] is not None
    assert findings[netbox_id("3")]["kind"] == "missing-discovered"
    validate("topology", body)


def test_topology_discovery_failure_leaves_reconciliation_not_checked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed discovery read must not be presented as 'in sync'."""
    _dev_identity(monkeypatch)
    _wire_netbox([_cable(1)])
    _wire_librenms([], fail=True)

    response = TestClient(app).get("/api/v1/topology")

    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    assert body["state"] == "ok"
    assert len(body["nodes"]) == 2
    assert all(node["reconciled"] is False and node["finding"] is None for node in body["nodes"])
    validate("topology", body)
