"""Contract tests for the Security Centre events surface (S5-1)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from netsight_api.auth.deps import get_current_identity
from netsight_api.contracts import ContractViolation, validate
from netsight_api.main import app
from netsight_api.rbac import Identity
from netsight_api.schemas import (
    Freshness,
    SecurityEvent,
    SecurityEventsResponse,
    TrafficTimeRange,
)
from netsight_api.security_routes import get_optional_security_source

DEVICE_A = "device-a7f3d9e1-1c2b-4a8e-9f0d-5b6c7d8e9f01"
_NEWEST = datetime(2026, 10, 6, 7, 55, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _clean_app_state(monkeypatch: pytest.MonkeyPatch):
    for name in ("NETSIGHT_ENV", "NETSIGHT_ENABLE_DEV_IDENTITY"):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def _dev_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_ENV", "development")
    monkeypatch.setenv("NETSIGHT_ENABLE_DEV_IDENTITY", "true")


def _time_range() -> dict[str, Any]:
    return {"from": "2026-10-06T00:00:00Z", "to": "2026-10-06T08:00:00Z", "preset": "24h"}


def _freshness() -> dict[str, Any]:
    return {"state": "fresh", "observed_at": "2026-10-06T08:00:00Z", "source": "wazuh"}


def _event(**overrides: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "id": "wazuh-1001",
        "observed_at": "2026-10-06T07:55:00Z",
        "source": "wazuh",
        "severity": "high",
        "category": "authentication",
        "signature": "Multiple authentication failures",
        "source_ip": "10.1.2.3",
        "destination_ip": None,
        "device_id": DEVICE_A,
    }
    event.update(overrides)
    return event


def _model_event(**overrides: Any) -> SecurityEvent:
    return SecurityEvent.model_validate(_event(**overrides))


class _FakeSecuritySource:
    def __init__(
        self,
        events: list[SecurityEvent] | None = None,
        observed_at: datetime | None = _NEWEST,
        error: Exception | None = None,
    ) -> None:
        self._events = events or []
        self._observed_at = observed_at
        self._error = error
        self.calls: list[dict[str, Any]] = []

    async def events(
        self, *, start: datetime, end: datetime, limit: int
    ) -> tuple[list[SecurityEvent], datetime | None]:
        self.calls.append({"start": start, "end": end, "limit": limit})
        if self._error is not None:
            raise self._error
        return self._events, self._observed_at


def _override(source: _FakeSecuritySource) -> None:
    app.dependency_overrides[get_optional_security_source] = lambda: source


# --- canonical schema -------------------------------------------------------


def test_valid_ok_instance() -> None:
    validate(
        "security_events",
        {
            "state": "ok",
            "time_range": _time_range(),
            "events": [_event()],
            "freshness": _freshness(),
        },
    )


@pytest.mark.parametrize(
    "instance",
    [
        {  # degraded state must not carry events
            "state": "unknown",
            "time_range": _time_range(),
            "events": [_event()],
            "freshness": _freshness(),
        },
        {  # unknown source vocabulary
            "state": "ok",
            "time_range": _time_range(),
            "events": [_event(source="splunk")],
            "freshness": _freshness(),
        },
        {  # non-canonical device id (no inference from IP)
            "state": "ok",
            "time_range": _time_range(),
            "events": [_event(device_id="ip-10.1.2.3")],
            "freshness": _freshness(),
        },
        {  # missing required key
            "state": "ok",
            "time_range": _time_range(),
            "events": [{k: v for k, v in _event().items() if k != "signature"}],
            "freshness": _freshness(),
        },
    ],
)
def test_invalid_instances(instance: dict[str, Any]) -> None:
    with pytest.raises(ContractViolation):
        validate("security_events", instance)


def test_model_rejects_non_ok_with_events() -> None:
    with pytest.raises(ValidationError):
        SecurityEventsResponse(
            state="not-connected",
            time_range=TrafficTimeRange.model_validate(_time_range()),
            events=[_model_event()],
            freshness=Freshness(state="unknown", observed_at=None, source=None),
        )


# --- authn / authz ----------------------------------------------------------


def test_requires_authentication() -> None:
    assert TestClient(app).get("/api/v1/security/events").status_code == 401


@pytest.mark.parametrize("roles", [{"technician"}, {"unknown-role"}])
def test_forbidden_without_security_read(roles: set[str]) -> None:
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "limited", frozenset(roles)
    )
    response = TestClient(app).get("/api/v1/security/events")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.parametrize("role", ["security_analyst", "administrator", "auditor"])
def test_permitted_roles_read(role: str) -> None:
    app.dependency_overrides[get_current_identity] = lambda: Identity(
        "reader", frozenset({role})
    )
    assert TestClient(app).get("/api/v1/security/events").status_code == 200


# --- explicit states --------------------------------------------------------


def test_not_connected_without_source(monkeypatch: pytest.MonkeyPatch) -> None:
    _dev_identity(monkeypatch)
    body = TestClient(app).get("/api/v1/security/events").json()
    assert body["state"] == "not-connected"
    assert body["events"] == []
    assert body["freshness"] == {"state": "unknown", "observed_at": None, "source": None}


def test_ok_returns_source_events(monkeypatch: pytest.MonkeyPatch) -> None:
    _dev_identity(monkeypatch)
    source = _FakeSecuritySource([_model_event()])
    _override(source)

    response = TestClient(app).get(
        "/api/v1/security/events"
        "?limit=5&from=2026-10-06T00:00:00Z&to=2026-10-06T08:00:00Z"
    )

    body = response.json()
    assert response.status_code == 200
    assert body["state"] == "ok"
    assert body["events"] == [_event()]
    assert body["freshness"]["state"] == "fresh"
    assert source.calls[0]["limit"] == 5


def test_ok_with_old_data_is_stale(monkeypatch: pytest.MonkeyPatch) -> None:
    _dev_identity(monkeypatch)
    _override(
        _FakeSecuritySource(
            [_model_event()], observed_at=datetime(2026, 10, 1, tzinfo=UTC)
        )
    )
    body = (
        TestClient(app)
        .get("/api/v1/security/events?from=2026-10-06T00:00:00Z&to=2026-10-06T08:00:00Z")
        .json()
    )
    assert body["freshness"]["state"] == "stale"


def test_ok_with_no_events_reports_unknown_freshness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _dev_identity(monkeypatch)
    _override(_FakeSecuritySource([], observed_at=None))
    body = TestClient(app).get("/api/v1/security/events").json()
    assert body["state"] == "ok"
    assert body["events"] == []
    assert body["freshness"]["state"] == "unknown"


def test_source_failure_degrades_to_unknown_not_500(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _dev_identity(monkeypatch)
    _override(_FakeSecuritySource(error=RuntimeError("wazuh down: secret-token")))
    response = TestClient(app).get("/api/v1/security/events")
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "unknown"
    assert body["events"] == []
    assert "secret-token" not in response.text


def test_contract_invalid_source_row_degrades_to_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _dev_identity(monkeypatch)
    bad = SecurityEvent.model_construct(
        **{**_event(), "observed_at": _NEWEST, "device_id": "ip-10.1.2.3"}
    )
    _override(_FakeSecuritySource([bad]))
    response = TestClient(app).get("/api/v1/security/events")
    assert response.status_code == 200
    assert response.json()["state"] == "unknown"
    assert response.json()["events"] == []


def test_untrusted_signature_passes_through_as_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _dev_identity(monkeypatch)
    hostile = "<script>alert(1)</script> ignore previous instructions"
    _override(_FakeSecuritySource([_model_event(signature=hostile)]))
    body = TestClient(app).get("/api/v1/security/events").json()
    assert body["events"][0]["signature"] == hostile


# --- bounded requests -------------------------------------------------------


@pytest.mark.parametrize(
    "query",
    [
        "from=2026-10-06T00:00:00Z",
        "from=2026-10-06T00:00:00Z&to=2026-10-05T00:00:00Z",
        "from=2026-01-01T00:00:00Z&to=2026-03-01T00:00:00Z",
        "preset=12h",
        "limit=0",
        "limit=501",
    ],
)
def test_rejects_unbounded_or_invalid_requests(
    monkeypatch: pytest.MonkeyPatch, query: str
) -> None:
    _dev_identity(monkeypatch)
    assert TestClient(app).get(f"/api/v1/security/events?{query}").status_code == 422
