"""Shared fixtures and helpers for the alert-rule / maintenance-window API tests (S6-3).

Authentication goes through real server-side sessions (cookie plus CSRF token), so the
session, CSRF and origin stack is exercised rather than bypassed. The store is the in-memory
repository (same domain rules as PostgreSQL, proven by the storage conformance suite).
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from netsight_api import alerting_route_support
from netsight_api.alerting_route_support import get_now, get_optional_alert_rule_store
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.session import Session, session_manager
from netsight_api.auth.settings import session_policy
from netsight_api.main import app
from netsight_api.schemas import AlertRuleDefinition, MaintenanceWindowDefinition
from netsight_api.storage import InMemoryAlertRuleRepository

RULES = "/api/v1/alert-rules"
WINDOWS = "/api/v1/maintenance-windows"
NOW = datetime(2026, 10, 8, 10, 0, tzinfo=UTC)
XSS = "<script>alert('xss')</script> \" ' ; DROP TABLE alert_rules; -- \u202e \U0001f525 {{7*7}}"
MISSING_RULE_ID = "alert-rule-00000000-0000-4000-8000-000000000000"
MISSING_WINDOW_ID = "maintenance-00000000-0000-4000-8000-000000000000"
SEED_ACTOR = "seed:operator"
ALL_ROLES = [
    "administrator",
    "network_engineer",
    "security_analyst",
    "technician",
    "management",
    "auditor",
]
READ_ROLES = ["administrator", "network_engineer", "security_analyst", "auditor"]
AUTHOR_ROLES = ["administrator", "network_engineer", "security_analyst"]
APPROVER_ROLES = ["administrator"]
ENV_NAMES = (
    "NETSIGHT_ENV",
    "NETSIGHT_ENABLE_DEV_IDENTITY",
    "NETSIGHT_ALLOWED_ORIGINS",
    "NETSIGHT_PUBLIC_BASE_URL",
    "DATABASE_URL",
    "DATABASE_MIGRATION_URL",
)


class TickingClock:
    """Strictly increasing clock anchored at NOW (1 s per call): deterministic ordering."""

    def __init__(self) -> None:
        self._current = NOW

    def __call__(self) -> datetime:
        self._current += timedelta(seconds=1)
        return self._current


def clean_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Generator body of each module's autouse fixture (``yield from``)."""
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    monkeypatch.setattr(alerting_route_support, "_write_limiter", RateLimiter())
    monkeypatch.setattr(alerting_route_support, "_evaluate_limiter", RateLimiter())
    app.dependency_overrides[get_now] = lambda: NOW
    yield
    app.dependency_overrides.clear()
    session_policy.cache_clear()


def new_store() -> InMemoryAlertRuleRepository:
    repository = InMemoryAlertRuleRepository(clock=TickingClock())
    app.dependency_overrides[get_optional_alert_rule_store] = lambda: repository
    return repository


class Caller:
    """A signed-in browser: session cookie plus the CSRF token the UI would send."""

    def __init__(self, role: str, subject: str = "sub-1") -> None:
        manager = session_manager()
        self.session: Session = manager.create_session(subject, "microsoft", [role])
        self.identity_id = self.session.identity_id
        self.http = TestClient(app, raise_server_exceptions=False)
        self.http.cookies.set(manager.policy.cookie_name, manager.cookie_value(self.session))

    def _headers(self, csrf: str | None, extra: dict[str, str] | None) -> dict[str, str]:
        headers = dict(extra or {})
        if csrf == "valid":
            headers["X-CSRF-Token"] = self.session.csrf_token
        elif csrf is not None:
            headers["X-CSRF-Token"] = csrf
        return headers

    def get(self, path: str, **params: Any) -> Any:
        return self.http.get(path, params=params)

    def post(
        self,
        path: str,
        body: Any = None,
        *,
        csrf: str | None = "valid",
        headers: dict[str, str] | None = None,
    ) -> Any:
        return self.http.post(path, json=body, headers=self._headers(csrf, headers))

    def put(
        self,
        path: str,
        body: Any = None,
        *,
        csrf: str | None = "valid",
        headers: dict[str, str] | None = None,
    ) -> Any:
        return self.http.put(path, json=body, headers=self._headers(csrf, headers))


def iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def rule_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "After-hours large upload",
        "scope": {"kind": "device_group", "ref": "staff-workstations"},
        "condition": {
            "metric": "traffic.upload_bytes",
            "operator": "gt",
            "threshold": 1000000000,
            "pattern": None,
        },
        "baseline_mode": "none",
        "window_seconds": 900,
        "for_seconds": 0,
        "cooldown_seconds": 3600,
        "schedule": {
            "timezone": "Africa/Windhoek",
            "active": [
                {"weekdays": ["mon", "tue", "wed", "thu", "fri"], "from": "20:00", "to": "06:00"}
            ],
        },
        "exceptions": {"destinations": ["approved-backup"], "device_groups": ["backup-servers"]},
        "severity": "high",
        "labels": {"team": "network"},
        "actions": ["create_alert", "email"],
        "incident_policy": "group",
    }
    body.update(overrides)
    return copy.deepcopy(body)


def window_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "Core switch firmware upgrade",
        "scope": {"kind": "site", "ref": "windhoek-hq"},
        "starts_at": iso(NOW + timedelta(hours=1)),
        "ends_at": iso(NOW + timedelta(hours=5)),
        "evaluation": "retain",
        "reason": "Planned firmware upgrade",
    }
    body.update(overrides)
    return copy.deepcopy(body)


def seed_rule(
    store: InMemoryAlertRuleRepository, status: str = "draft", **overrides: Any
) -> tuple[str, int]:
    """Create a rule directly in the store; returns (id, version)."""
    rule = store.create_rule(
        AlertRuleDefinition.model_validate_json(json.dumps(rule_body(**overrides))),
        actor_id=SEED_ACTOR,
    )
    if status in ("active", "disabled"):
        rule = store.approve_rule(rule.id, approver_id=SEED_ACTOR, expected_version=rule.version)
    if status == "disabled":
        rule = store.disable_rule(rule.id, actor_id=SEED_ACTOR)
    return rule.id, rule.version


def seed_window(
    store: InMemoryAlertRuleRepository, cancelled: bool = False, **overrides: Any
) -> str:
    definition = MaintenanceWindowDefinition.model_validate_json(
        json.dumps(window_body(**overrides))
    )
    # Seeding is a privileged test path: it may create organisation-scope or
    # ``disable`` windows that ordinary callers are refused (deny by default).
    window = store.create_window(definition, actor_id=SEED_ACTOR, organisation_allowed=True)
    if cancelled:
        window = store.cancel_window(window.id, actor_id=SEED_ACTOR, organisation_allowed=True)
    return window.id


def audit_records(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == "netsight_api.audit"]


def observation(offset_s: int = 0, **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "at": iso(datetime(2026, 10, 8, 18, 30, tzinfo=UTC) + timedelta(seconds=offset_s)),
        "entity": "device-1",
        "scopes": [{"kind": "device_group", "ref": "staff-workstations"}],
        "value": 5000000000,
        "text": None,
        "anomaly": None,
        "destination": "evil.example",
        "device_groups": ["laptops"],
    }
    body.update(overrides)
    return body


def evaluate_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "definition": rule_body(),
        "observations": [observation()],
        "windows": [],
    }
    body.update(overrides)
    return body


class SpyStore(InMemoryAlertRuleRepository):
    """Counts every call so a test can prove a route never touched the store."""

    def __init__(self) -> None:
        super().__init__(clock=TickingClock())
        self.calls: list[str] = []

    def __getattribute__(self, name: str) -> Any:
        attribute = super().__getattribute__(name)
        if callable(attribute) and not name.startswith("_") and name != "calls":
            calls = super().__getattribute__("calls")

            def recorded(*args: Any, **kwargs: Any) -> Any:
                calls.append(name)
                return attribute(*args, **kwargs)

            return recorded
        return attribute


class FailingStore(InMemoryAlertRuleRepository):
    """Every method raises ``error`` (a driver-style message carrying a would-be secret)."""

    def __init__(self, error: Exception) -> None:
        super().__init__(clock=TickingClock())
        self.error = error

    def __getattribute__(self, name: str) -> Any:
        if name in {
            "create_rule",
            "get_rule",
            "list_rules",
            "update_rule",
            "approve_rule",
            "disable_rule",
            "create_window",
            "get_window",
            "list_windows",
            "cancel_window",
        }:
            error = super().__getattribute__("error")

            def fail(*_args: Any, **_kwargs: Any) -> Any:
                raise error

            return fail
        return super().__getattribute__(name)


ParamFactory = Callable[[], Any]
