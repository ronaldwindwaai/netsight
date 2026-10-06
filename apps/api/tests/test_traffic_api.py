"""Contract tests for the traffic intelligence surface (S4, build plan step 1)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from netsight_api.auth.deps import get_current_identity
from netsight_api.contracts import ContractViolation, validate
from netsight_api.main import app, get_optional_traffic_source
from netsight_api.rbac import Identity
from netsight_api.schemas import TrafficFlow, TrafficItem

DEVICE_A = "device-a7f3d9e1-1c2b-4a8e-9f0d-5b6c7d8e9f01"

_OBSERVED_AT = datetime(2026, 10, 6, 8, 0, tzinfo=UTC)


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


# --- contract instances -----------------------------------------------------


def _time_range() -> dict[str, Any]:
    return {"from": "2026-10-06T00:00:00Z", "to": "2026-10-06T08:00:00Z", "preset": "24h"}


def _freshness() -> dict[str, Any]:
    return {
        "state": "fresh",
        "observed_at": "2026-10-06T08:00:00Z",
        "source": "clickhouse",
    }


def _item(**overrides: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "rank": 1,
        "subject_kind": "ip",
        "subject_id": None,
        "label": "10.1.2.3",
        "bytes": 104_857_600,
        "packets": 820_000,
        "share": 0.42,
    }
    item.update(overrides)
    return item


def _flow(**overrides: Any) -> dict[str, Any]:
    flow: dict[str, Any] = {
        "observed_at": "2026-10-06T07:59:00Z",
        "source_ip": "10.1.2.3",
        "source_device_id": DEVICE_A,
        "destination_ip": "203.0.113.9",
        "destination_host": "cdn.example.net",
        "protocol": "tcp",
        "destination_port": 443,
        "bytes": 987_654_321,
        "packets": 700_000,
        "direction": "outbound",
        "application": "https",
        "user": "alice",
    }
    flow.update(overrides)
    return flow


def test_valid_top_contract() -> None:
    instance = {
        "state": "ok",
        "dimension": "talkers",
        "time_range": _time_range(),
        "items": [
            _item(),
            _item(rank=2, subject_kind="user", label="alice", share=None),
            _item(rank=3, subject_kind="domain", label="cdn.example.net", packets=None),
        ],
        "freshness": _freshness(),
    }
    validate("traffic_top", instance)


def test_valid_flows_contract() -> None:
    instance = {
        "state": "ok",
        "time_range": _time_range(),
        "flows": [
            _flow(),
            _flow(
                source_device_id=None,
                destination_host=None,
                protocol="udp",
                destination_port=None,
                packets=None,
                direction="unknown",
                application=None,
                user=None,
            ),
        ],
        "freshness": _freshness(),
    }
    validate("traffic_flows", instance)


@pytest.mark.parametrize(
    "instance",
    [
        # not-connected must not carry items
        {
            "state": "not-connected",
            "dimension": "talkers",
            "time_range": _time_range(),
            "items": [_item()],
            "freshness": {"state": "unknown", "observed_at": None, "source": None},
        },
        # unknown must not carry items — nothing is drawn from a failed source
        {
            "state": "unknown",
            "dimension": "destinations",
            "time_range": _time_range(),
            "items": [_item()],
            "freshness": {"state": "unknown", "observed_at": None, "source": "clickhouse"},
        },
        # unknown dimension
        {
            "state": "ok",
            "dimension": "apps",
            "time_range": _time_range(),
            "items": [],
            "freshness": _freshness(),
        },
        # unknown preset
        {
            "state": "ok",
            "dimension": "talkers",
            "time_range": {"from": "2026-10-06T00:00:00Z", "to": "2026-10-06T08:00:00Z", "preset": "12h"},
            "items": [],
            "freshness": _freshness(),
        },
        # share outside [0, 1]
        {
            "state": "ok",
            "dimension": "talkers",
            "time_range": _time_range(),
            "items": [_item(share=1.5)],
            "freshness": _freshness(),
        },
        # rank below 1
        {
            "state": "ok",
            "dimension": "talkers",
            "time_range": _time_range(),
            "items": [_item(rank=0)],
            "freshness": _freshness(),
        },
        # empty label never renders as a blank row
        {
            "state": "ok",
            "dimension": "talkers",
            "time_range": _time_range(),
            "items": [_item(label="")],
            "freshness": _freshness(),
        },
        # unknown subject kind
        {
            "state": "ok",
            "dimension": "talkers",
            "time_range": _time_range(),
            "items": [_item(subject_kind="process")],
            "freshness": _freshness(),
        },
        # missing required key
        {
            "state": "ok",
            "dimension": "talkers",
            "time_range": _time_range(),
            "items": [{k: v for k, v in _item().items() if k != "label"}],
            "freshness": _freshness(),
        },
        # negative byte counts are never fabricated or wrapped
        {
            "state": "ok",
            "dimension": "talkers",
            "time_range": _time_range(),
            "items": [_item(bytes=-1)],
            "freshness": _freshness(),
        },
    ],
)
def test_invalid_top_contract(instance: dict[str, Any]) -> None:
    with pytest.raises(ContractViolation):
        validate("traffic_top", instance)


@pytest.mark.parametrize(
    "instance",
    [
        # unknown must not carry flows
        {
            "state": "unknown",
            "time_range": _time_range(),
            "flows": [_flow()],
            "freshness": {"state": "unknown", "observed_at": None, "source": "clickhouse"},
        },
        # port outside range
        {
            "state": "ok",
            "time_range": _time_range(),
            "flows": [_flow(destination_port=70000)],
            "freshness": _freshness(),
        },
        # unknown direction vocabulary
        {
            "state": "ok",
            "time_range": _time_range(),
            "flows": [_flow(direction="sideways")],
            "freshness": _freshness(),
        },
        # non-canonical source device id
        {
            "state": "ok",
            "time_range": _time_range(),
            "flows": [_flow(source_device_id="ip-10.1.2.3")],
            "freshness": _freshness(),
        },
        # missing required key
        {
            "state": "ok",
            "time_range": _time_range(),
            "flows": [{k: v for k, v in _flow().items() if k != "user"}],
            "freshness": _freshness(),
        },
    ],
)
def test_invalid_flows_contract(instance: dict[str, Any]) -> None:
    with pytest.raises(ContractViolation):
        validate("traffic_flows", instance)


# --- source test double -----------------------------------------------------


class _FakeTrafficSource:
    """Stands in for the S4-2 ClickHouse adapter."""

    def __init__(
        self,
        *,
        items: list[TrafficItem] | None = None,
        flows: list[TrafficFlow] | None = None,
        error: Exception | None = None,
    ) -> None:
        self._items = items
        self._flows = flows
        self._error = error
        self.calls: list[dict[str, Any]] = []

    async def top(
        self, *, dimension: str, start: datetime, end: datetime, limit: int
    ) -> tuple[list[TrafficItem], datetime]:
        self.calls.append(
            {"method": "top", "dimension": dimension, "start": start, "end": end, "limit": limit}
        )
        if self._error is not None:
            raise self._error
        return list(self._items or []), _OBSERVED_AT

    async def flows(
        self, *, start: datetime, end: datetime, limit: int
    ) -> tuple[list[TrafficFlow], datetime]:
        self.calls.append({"method": "flows", "start": start, "end": end, "limit": limit})
        if self._error is not None:
            raise self._error
        return list(self._flows or []), _OBSERVED_AT


def _override_source(source: _FakeTrafficSource) -> None:
    app.dependency_overrides[get_optional_traffic_source] = lambda: source


# --- endpoint states --------------------------------------------------------


def test_traffic_requires_authentication() -> None:
    response = TestClient(app).get("/api/v1/traffic/top-talkers")
    assert response.status_code == 401


def test_traffic_forbidden_without_traffic_read() -> None:
    """An authenticated identity lacking TRAFFIC_READ must be denied."""
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "limited-user", frozenset({"unknown-role"})
    )

    response = TestClient(app).get("/api/v1/traffic/top-talkers")

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_traffic_forbidden_for_technician_role() -> None:
    """RBAC matrix: technicians hold no traffic:read permission."""
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "tech-1", frozenset({"technician"})
    )

    response = TestClient(app).get("/api/v1/traffic/flows")

    assert response.status_code == 403


def test_top_talkers_default_state_is_not_connected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _dev_identity(monkeypatch)
    response = TestClient(app).get("/api/v1/traffic/top-talkers")

    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    assert body["state"] == "not-connected"
    assert body["dimension"] == "talkers"
    assert body["items"] == []
    assert body["time_range"]["preset"] == "24h"
    assert body["freshness"] == {"state": "unknown", "observed_at": None, "source": None}
    validate("traffic_top", body)


def test_top_destinations_dimension_is_echoed(monkeypatch: pytest.MonkeyPatch) -> None:
    _dev_identity(monkeypatch)
    response = TestClient(app).get("/api/v1/traffic/top-destinations")

    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    assert body["state"] == "not-connected"
    assert body["dimension"] == "destinations"
    validate("traffic_top", body)


def test_flows_default_state_is_not_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    _dev_identity(monkeypatch)
    response = TestClient(app).get("/api/v1/traffic/flows")

    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    assert body["state"] == "not-connected"
    assert body["flows"] == []
    validate("traffic_flows", body)


def test_top_talkers_returns_source_reported_items(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ok only with source data; labels pass through as untrusted data."""
    _dev_identity(monkeypatch)
    source = _FakeTrafficSource(
        items=[
            TrafficItem(
                rank=1,
                subject_kind="ip",
                subject_id=None,
                label="<script>alert('xss')</script>",
                bytes=1000,
                packets=10,
                share=0.5,
            )
        ]
    )
    _override_source(source)

    response = TestClient(app).get("/api/v1/traffic/top-talkers?limit=5")

    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    assert body["state"] == "ok"
    # XSS probe survives as data; markup interpretation is the renderer's job.
    assert body["items"][0]["label"] == "<script>alert('xss')</script>"
    assert body["freshness"] == {
        "state": "fresh",
        "observed_at": "2026-10-06T08:00:00Z",
        "source": "clickhouse",
    }
    validate("traffic_top", body)

    call = source.calls[0]
    assert call["dimension"] == "talkers"
    assert call["limit"] == 5
    assert call["end"] - call["start"] == timedelta(hours=24)


def test_explicit_window_is_echoed_without_preset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _dev_identity(monkeypatch)
    _override_source(_FakeTrafficSource(items=[]))

    response = TestClient(app).get(
        "/api/v1/traffic/top-talkers"
        "?from=2026-10-05T00:00:00Z&to=2026-10-06T00:00:00Z"
    )

    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    assert body["time_range"] == {
        "from": "2026-10-05T00:00:00Z",
        "to": "2026-10-06T00:00:00Z",
        "preset": None,
    }
    assert body["state"] == "ok"
    validate("traffic_top", body)


def test_flows_returns_source_reported_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    _dev_identity(monkeypatch)
    source = _FakeTrafficSource(
        flows=[
            TrafficFlow(
                observed_at=_OBSERVED_AT,
                source_ip="10.1.2.3",
                source_device_id=DEVICE_A,
                destination_ip="203.0.113.9",
                destination_host="cdn.example.net",
                protocol="tcp",
                destination_port=443,
                bytes=987_654_321,
                packets=700_000,
                direction="outbound",
                application="https",
                user="alice",
            )
        ]
    )
    _override_source(source)

    response = TestClient(app).get("/api/v1/traffic/flows?preset=1h")

    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    assert body["state"] == "ok"
    assert len(body["flows"]) == 1
    assert body["flows"][0]["source_device_id"] == DEVICE_A
    validate("traffic_flows", body)

    call = source.calls[0]
    assert call["method"] == "flows"
    assert call["end"] - call["start"] == timedelta(hours=1)


def test_top_source_failure_degrades_to_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed source read must not be presented as in-sync or empty-ok."""
    _dev_identity(monkeypatch)
    _override_source(_FakeTrafficSource(error=RuntimeError("boom")))

    response = TestClient(app).get("/api/v1/traffic/top-talkers")

    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    assert body["state"] == "unknown"
    assert body["items"] == []
    assert body["freshness"] == {
        "state": "unknown",
        "observed_at": None,
        "source": "clickhouse",
    }
    validate("traffic_top", body)


def test_flows_source_failure_degrades_to_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _dev_identity(monkeypatch)
    _override_source(_FakeTrafficSource(error=RuntimeError("boom")))

    response = TestClient(app).get("/api/v1/traffic/flows")

    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    assert body["state"] == "unknown"
    assert body["flows"] == []
    validate("traffic_flows", body)


# --- bounded window / query budget ------------------------------------------


@pytest.mark.parametrize(
    "query",
    [
        "from=2026-10-05T00:00:00Z",
        "to=2026-10-06T00:00:00Z",
        "from=2026-10-06T00:00:00Z&to=2026-10-05T00:00:00Z",
        "from=2026-01-01T00:00:00Z&to=2026-03-01T00:00:00Z",
        "from=2026-10-05T00:00:00&to=2026-10-06T00:00:00",
        "preset=12h",
        "limit=0",
        "limit=101",
    ],
)
def test_top_talkers_rejects_unbounded_or_invalid_requests(
    monkeypatch: pytest.MonkeyPatch, query: str
) -> None:
    _dev_identity(monkeypatch)
    response = TestClient(app).get(f"/api/v1/traffic/top-talkers?{query}")
    assert response.status_code == 422


@pytest.mark.parametrize("query", ["limit=0", "limit=501", "preset=forever"])
def test_flows_rejects_unbounded_or_invalid_requests(
    monkeypatch: pytest.MonkeyPatch, query: str
) -> None:
    _dev_identity(monkeypatch)
    response = TestClient(app).get(f"/api/v1/traffic/flows?{query}")
    assert response.status_code == 422
