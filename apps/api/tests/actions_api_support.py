"""Shared fixtures for the controlled-action API tests (Step 12): sessions, a clock, a runtime."""

from __future__ import annotations

import itertools
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest
from actions_support import FINDING, NOW
from alerting_support import Caller

from netsight_api import actions_route_support as support
from netsight_api import read_limit
from netsight_api.actions.wiring import ActionRuntime, build_runtime
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.auth.session import session_manager
from netsight_api.auth.settings import session_policy
from netsight_api.main import app

BASE = "/api/v1/actions"
ENV_ON = {"NETSIGHT_ACTIONS_ENABLED": "true"}
_keys = itertools.count(1)


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> Any:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += timedelta(**kwargs)


class Person(Caller):
    """A signed-in browser with a chosen age of its last second factor (None: never proven)."""

    def __init__(self, role: str, subject: str | None = None, mfa_age: float | None = 0.0) -> None:
        super().__init__(role, subject or f"sub-{role}")
        manager = session_manager()
        self.session.mfa_verified_at = None if mfa_age is None else manager.store.now() - mfa_age

    def create(self, body: dict[str, Any] | None = None, key: str | None = None, **kw: Any) -> Any:
        headers = {"Idempotency-Key": key or unique_key()}
        return self.post(BASE, body if body is not None else isolate_body(), headers=headers, **kw)

    def decide(self, request: dict[str, Any], verb: str, **extra: Any) -> Any:
        body = {
            "expected_digest": request["digest"],
            "expected_version": request["version"],
            **extra,
        }
        return self.post(f"{BASE}/{request['id']}/{verb}", body)

    def approve(self, request: dict[str, Any]) -> Any:
        return self.decide(request, "approve")

    def execute(self, request: dict[str, Any], key: str | None = None, **kw: Any) -> Any:
        body = {"expected_digest": request["digest"], "expected_version": request["version"]}
        return self.post(
            f"{BASE}/{request['id']}/execute",
            body,
            headers={"Idempotency-Key": key or unique_key()},
            **kw,
        )

    def show(self, action_id: str) -> Any:
        return self.get(f"{BASE}/{action_id}")


def unique_key() -> str:
    return f"test-key-{next(_keys):012d}"


def isolate_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "action_type": "endpoint.isolate",
        "target_id": f"endpoint:laptop-{next(_keys)}",
        "params": {"duration_minutes": 60},
        "reason": "Unknown device on the finance VLAN",
    }
    body.update(overrides)
    return body


def port_body(action_type: str = "switch.port.disable", **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "action_type": action_type,
        "target_id": f"interface:sw1-gi0-{next(_keys)}",
        "params": {},
        "reason": "Loop detected on this port",
    }
    body.update(overrides)
    return body


class FindingStub:
    def __init__(self, finding: Any) -> None:
        self.finding = finding
        self.reads = 0

    def get_finding(self, finding_id: str) -> Any:
        self.reads += 1
        return self.finding if self.finding is not None and self.finding.id == finding_id else None


ENV_NAMES = (
    "NETSIGHT_ENV",
    "NETSIGHT_ENABLE_DEV_IDENTITY",
    "NETSIGHT_ALLOWED_ORIGINS",
    "NETSIGHT_PUBLIC_BASE_URL",
    "DATABASE_URL",
    "NETSIGHT_STEP_UP_MAX_AGE_SECONDS",
    "NETSIGHT_ACTIONS_ENABLED",
    "NETSIGHT_ACTIONS_KILL_SWITCH",
    "NETSIGHT_ACTIONS_LIVE_EXECUTION",
)


def clean_wiring(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Generator body of each module's autouse fixture (``yield from``)."""
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    monkeypatch.setattr(read_limit, "_read_limiter", RateLimiter())
    support.reset_for_tests()
    yield
    app.dependency_overrides.clear()
    session_policy.cache_clear()


def install_clock() -> Clock:
    instance = Clock()
    app.dependency_overrides[support.get_clock] = lambda: instance
    return instance


def install_findings() -> FindingStub:
    from actions_support import make_finding

    stub = FindingStub(make_finding())
    app.dependency_overrides[support.get_finding_reader] = lambda: stub
    return stub


def install_runtime(clock: Clock, findings: FindingStub) -> ActionRuntime:
    built = build_runtime(ENV_ON, clock=clock, findings=lambda: findings)
    assert built is not None
    app.dependency_overrides[support.get_runtime] = lambda: built
    return built


def disabled() -> None:
    app.dependency_overrides[support.get_runtime] = lambda: None


__all__ = [
    "BASE",
    "FINDING",
    "Clock",
    "FindingStub",
    "Person",
    "disabled",
    "isolate_body",
    "port_body",
]
