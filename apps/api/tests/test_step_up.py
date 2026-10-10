"""Step-up authentication (recent MFA) for incident resolve and reopen.

Human decision recorded 2026-10-10: resolve and reopen require MFA performed within
``NETSIGHT_STEP_UP_MAX_AGE_SECONDS`` (default 900). An unknown MFA time fails closed and
the refusal is a distinct, audited ``STEP_UP_REQUIRED``.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from test_incidents_api import TickingClock, resolve_body, seed

from netsight_api import incident_routes
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.session import Session, session_manager
from netsight_api.auth.settings import auth_settings, session_policy
from netsight_api.incident_routes import get_optional_incident_store
from netsight_api.main import app
from netsight_api.storage import InMemoryIncidentRepository

API = "/api/v1/incidents"


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in (
        "NETSIGHT_ENV",
        "NETSIGHT_ENABLE_DEV_IDENTITY",
        "DATABASE_URL",
        "NETSIGHT_STEP_UP_MAX_AGE_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    monkeypatch.setattr(incident_routes, "_write_limiter", RateLimiter())
    yield
    app.dependency_overrides.clear()
    session_policy.cache_clear()


@pytest.fixture
def store() -> InMemoryIncidentRepository:
    repository = InMemoryIncidentRepository(clock=TickingClock())
    app.dependency_overrides[get_optional_incident_store] = lambda: repository
    return repository


class Browser:
    def __init__(self, role: str = "administrator", *, mfa_age: float | None = 0.0) -> None:
        manager = session_manager()
        self.session: Session = manager.create_session("sub-su", "microsoft", [role])
        if mfa_age is not None:
            self.session.mfa_verified_at = manager.store.now() - mfa_age
        self.http = TestClient(app, raise_server_exceptions=False)
        self.http.cookies.set(manager.policy.cookie_name, manager.cookie_value(self.session))

    def post(self, path: str, body: Any = None) -> Any:
        return self.http.post(path, json=body, headers={"X-CSRF-Token": self.session.csrf_token})


def _audit(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == "netsight_api.audit"]


def test_the_default_window_is_fifteen_minutes() -> None:
    assert auth_settings().step_up_max_age_seconds == 900


@pytest.mark.parametrize("age", [None, 901.0, 86_400.0])
def test_resolve_without_recent_mfa_is_refused_and_changes_nothing(
    store: InMemoryIncidentRepository, age: float | None
) -> None:
    incident_id = seed(store, state="mitigated")
    response = Browser(mfa_age=age).post(f"{API}/{incident_id}/resolve", resolve_body())
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "STEP_UP_REQUIRED"
    assert store.get_incident(incident_id).state == "mitigated"  # type: ignore[union-attr]


@pytest.mark.parametrize("age", [None, 901.0])
def test_reopen_without_recent_mfa_is_refused_and_changes_nothing(
    store: InMemoryIncidentRepository, age: float | None
) -> None:
    incident_id = seed(store, state="resolved")
    response = Browser(mfa_age=age).post(f"{API}/{incident_id}/reopen", {"reason": "Recurred"})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "STEP_UP_REQUIRED"
    assert store.get_incident(incident_id).state == "resolved"  # type: ignore[union-attr]


def test_resolve_and_reopen_succeed_with_recent_mfa(store: InMemoryIncidentRepository) -> None:
    incident_id = seed(store, state="mitigated")
    browser = Browser(mfa_age=899.0)
    assert browser.post(f"{API}/{incident_id}/resolve", resolve_body()).status_code == 200
    assert browser.post(f"{API}/{incident_id}/reopen", {"reason": "Recurred"}).status_code == 200


def test_the_window_is_configurable(
    store: InMemoryIncidentRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NETSIGHT_STEP_UP_MAX_AGE_SECONDS", "60")
    incident_id = seed(store, state="mitigated")
    stale = Browser(mfa_age=120.0).post(f"{API}/{incident_id}/resolve", resolve_body())
    assert stale.json()["error"]["code"] == "STEP_UP_REQUIRED"
    monkeypatch.setenv("NETSIGHT_STEP_UP_MAX_AGE_SECONDS", "3600")
    ok = Browser(mfa_age=120.0).post(f"{API}/{incident_id}/resolve", resolve_body())
    assert ok.status_code == 200


@pytest.mark.parametrize("value", ["0", "-5", "86401", "soon"])
def test_an_unusable_window_setting_never_disables_the_check(
    store: InMemoryIncidentRepository, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("NETSIGHT_STEP_UP_MAX_AGE_SECONDS", value)
    incident_id = seed(store, state="mitigated")
    response = Browser(mfa_age=None).post(f"{API}/{incident_id}/resolve", resolve_body())
    assert response.status_code != 200
    assert store.get_incident(incident_id).state == "mitigated"  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("suffix", "body"),
    [
        ("/acknowledge", None),
        ("/comment", {"message": "Looking now"}),
        ("/assign", {"assignee_id": "microsoft:sub-9"}),
        ("/evidence", {"evidence_id": "ev-1"}),
    ],
)
def test_other_writes_do_not_need_step_up(
    store: InMemoryIncidentRepository, suffix: str, body: Any
) -> None:
    incident_id = seed(store)
    response = Browser(mfa_age=None).post(f"{API}/{incident_id}{suffix}", body)
    assert response.status_code in (200, 201), response.text


def test_authorisation_is_decided_before_step_up(store: InMemoryIncidentRepository) -> None:
    """A role without the permission learns nothing about MFA recency."""
    incident_id = seed(store, state="mitigated")
    response = Browser("technician", mfa_age=None).post(
        f"{API}/{incident_id}/resolve", resolve_body()
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_csrf_is_checked_before_step_up(store: InMemoryIncidentRepository) -> None:
    incident_id = seed(store, state="mitigated")
    browser = Browser(mfa_age=None)
    response = browser.http.post(f"{API}/{incident_id}/resolve", json=resolve_body())
    assert response.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"


def test_the_refusal_is_audited_with_a_reason_code_only(
    store: InMemoryIncidentRepository, caplog: pytest.LogCaptureFixture
) -> None:
    incident_id = seed(store, state="mitigated")
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        Browser(mfa_age=None).post(f"{API}/{incident_id}/resolve", resolve_body())
    records = [r for r in _audit(caplog) if r["action"] == "incident.resolve"]
    assert len(records) == 1
    assert records[0]["outcome"] == "denied"
    assert records[0]["reason"] == "step-up"
    assert records[0]["target"] == incident_id


def test_a_refused_step_up_does_not_consume_the_write_rate_limit(
    store: InMemoryIncidentRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(incident_routes, "WRITE_LIMIT_PER_MINUTE", 1)
    incident_id = seed(store, state="mitigated")
    browser = Browser(mfa_age=None)
    for _ in range(3):
        assert browser.post(f"{API}/{incident_id}/resolve", resolve_body()).status_code == 403
    browser.session.mfa_verified_at = session_manager().store.now()
    assert browser.post(f"{API}/{incident_id}/resolve", resolve_body()).status_code == 200


def test_the_development_bridge_is_exempt(
    store: InMemoryIncidentRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NETSIGHT_ENV", "development")
    monkeypatch.setenv("NETSIGHT_ENABLE_DEV_IDENTITY", "true")
    incident_id = seed(store, state="mitigated")
    response = TestClient(app).post(
        f"{API}/{incident_id}/resolve", json=resolve_body(), headers={"X-CSRF-Token": "dev"}
    )
    assert response.status_code == 200, response.text
