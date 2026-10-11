"""Step 3 security-review hardening: redirects, replay tolerance, dev bridge, summary, globs."""

from __future__ import annotations

import inspect
import time
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from netsight_api.alerting.matching import glob_matches
from netsight_api.auth.identity import STEP_UP_REPLAY_TOLERANCE_SECONDS, mfa_age
from netsight_api.auth.redirects import DEFAULT_REDIRECT, safe_ui_redirect
from netsight_api.auth.settings import session_policy
from netsight_api.main import app

# --- redirect target ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "/devices",
        "/devices/abc-123",
        "/incidents/incident-1?after_seq=3",
        "/alerts?rules_offset=50",
        "/network/map",
        "/overview",
        "/diagnostics",
        "/security",
        "/traffic",
        "/inventory?known=false",
        "/ipam",
        "/unknown-devices/unknown-device-6f1c2a9e-0b1d-5c3e-8f4a-123456789abc",
    ],
)
def test_ui_paths_are_kept(target: str) -> None:
    assert safe_ui_redirect(target) == target


@pytest.mark.parametrize(
    "target",
    [
        None,
        "",
        "overview",
        "//evil.example",
        "/\\evil.example",
        "/\t/evil.example",
        "/\n/evil.example",
        "/\r/evil.example",
        "/\x00/overview",
        "/\x7f/overview",
        "/" + chr(0x202E) + "overview",
        "/" + chr(0x200B) + "overview",
        "\\\\evil.example",
        "/%2F/evil.example",
        "/%2f%2fevil.example",
        "/%5Cevil.example",
        "/%5cevil.example",
        "/%09/evil.example",
        "/%0d%0aSet-Cookie:x=1",
        "/%2",
        "https://evil.example/",
        "javascript:alert(1)",
        "/api/v1/incidents",
        "/api",
        "/auth/logout",
        "/unknown-area",
        "/overviewx",
        "/" + "a" * 600,
        42,
    ],
)
def test_unsafe_or_non_ui_targets_fall_back_to_the_default(target: Any) -> None:
    assert safe_ui_redirect(target) == DEFAULT_REDIRECT == "/overview"


def test_the_login_route_stores_only_a_vetted_destination(monkeypatch: pytest.MonkeyPatch) -> None:
    import netsight_api.auth.pending as pending_module
    import netsight_api.auth.rate_limit as rate_limit_module

    monkeypatch.setenv("NETSIGHT_OIDC_MICROSOFT_ENABLED", "true")
    monkeypatch.setenv("NETSIGHT_OIDC_MICROSOFT_CLIENT_ID", "netsight-client")
    monkeypatch.setenv("NETSIGHT_OIDC_MICROSOFT_CLIENT_SECRET", "s")
    monkeypatch.setenv(
        "NETSIGHT_OIDC_MICROSOFT_AUTHORITY", "https://login.microsoftonline.com/contoso.com/v2.0"
    )
    monkeypatch.setenv("NETSIGHT_PUBLIC_BASE_URL", "https://netsight.test")
    store = pending_module.PendingAuthStore()
    monkeypatch.setattr(pending_module, "_pending_store", store)
    monkeypatch.setattr(rate_limit_module, "_limiter", rate_limit_module.RateLimiter())
    captured: dict[str, str] = {}

    async def fake_authorization_url(*args: Any, **_kwargs: Any) -> str:
        captured["state"] = args[3]
        return "https://provider.example/authorize"

    monkeypatch.setattr("netsight_api.auth.routes.authorization_url", fake_authorization_url)
    client = TestClient(app, follow_redirects=False)
    client.get("/api/v1/auth/login/microsoft", params={"redirect_to": "/\t/evil.example"})
    pending = store.take(captured["state"])
    assert pending is not None
    assert pending.redirect_to == "/overview"


# --- step-up replay tolerance --------------------------------------------------------------------


def _claims(auth_time: float) -> dict[str, Any]:
    return {"amr": ["mfa"], "auth_time": auth_time}


def test_the_replay_tolerance_is_five_seconds() -> None:
    assert STEP_UP_REPLAY_TOLERANCE_SECONDS == 5.0


def test_an_auth_time_just_before_the_step_up_request_is_tolerated() -> None:
    requested = 1_000_000.0
    age, reason = mfa_age(
        _claims(requested - 4.0), now=requested + 20, max_age=900, step_up_requested_at=requested
    )
    assert reason is None
    assert age == pytest.approx(24.0)


def test_an_auth_time_beyond_the_tolerance_is_a_replay() -> None:
    requested = 1_000_000.0
    age, reason = mfa_age(
        _claims(requested - 6.0), now=requested + 20, max_age=900, step_up_requested_at=requested
    )
    assert (age, reason) == (None, "step-up-replay")


def test_a_valid_token_that_predates_the_request_by_minutes_is_a_replay() -> None:
    requested = 1_000_000.0
    # Within max_age (so otherwise perfectly valid) but minted well before the step-up began.
    age, reason = mfa_age(
        _claims(requested - 120.0), now=requested + 10, max_age=900, step_up_requested_at=requested
    )
    assert (age, reason) == (None, "step-up-replay")


def test_without_a_step_up_request_the_tolerance_does_not_apply() -> None:
    now = 1_000_000.0
    age, reason = mfa_age(_claims(now - 60.0), now=now, max_age=900)
    assert reason is None
    assert age == pytest.approx(60.0)


# --- the development identity bridge ---------------------------------------------------------------


@pytest.fixture
def _fresh_settings() -> Iterator[None]:
    app.dependency_overrides.clear()
    session_policy.cache_clear()
    yield
    session_policy.cache_clear()


@pytest.mark.parametrize(
    "environment", ["production", "staging", "test", "ci", "Development ", "dev", "", "DEVELOPMENT"]
)
def test_the_dev_bridge_is_never_on_outside_development(
    monkeypatch: pytest.MonkeyPatch, environment: str, _fresh_settings: None
) -> None:
    from netsight_api.auth.deps import dev_identity_bridge_enabled

    monkeypatch.setenv("NETSIGHT_ENV", environment)
    monkeypatch.setenv("NETSIGHT_ENABLE_DEV_IDENTITY", "true")
    assert dev_identity_bridge_enabled() is False
    response = TestClient(app).get("/api/v1/incidents")
    assert response.status_code == 401


def test_the_dev_bridge_needs_both_flags(
    monkeypatch: pytest.MonkeyPatch, _fresh_settings: None
) -> None:
    from netsight_api.auth.deps import dev_identity_bridge_enabled

    monkeypatch.setenv("NETSIGHT_ENV", "development")
    monkeypatch.delenv("NETSIGHT_ENABLE_DEV_IDENTITY", raising=False)
    assert dev_identity_bridge_enabled() is False
    monkeypatch.setenv("NETSIGHT_ENABLE_DEV_IDENTITY", "true")
    assert dev_identity_bridge_enabled() is True


def test_the_dev_bridge_defaults_to_off(
    monkeypatch: pytest.MonkeyPatch, _fresh_settings: None
) -> None:
    from netsight_api.auth.deps import dev_identity_bridge_enabled

    monkeypatch.delenv("NETSIGHT_ENV", raising=False)
    monkeypatch.delenv("NETSIGHT_ENABLE_DEV_IDENTITY", raising=False)
    assert dev_identity_bridge_enabled() is False


# --- management summary response schema --------------------------------------------------------------


def _summary_payload() -> dict[str, Any]:
    return {
        "id": "incident-" + "0" * 8 + "-0000-0000-0000-" + "0" * 12,
        "title": "Link down",
        "severity": "critical",
        "state": "open",
        "created_at": "2026-10-10T10:00:00+00:00",
        "updated_at": "2026-10-10T10:00:00+00:00",
        "assigned": False,
        "resolved_at": None,
    }


@pytest.mark.parametrize(
    "extra", ["assignee_id", "evidence_ids", "resolution", "timeline", "anything_else"]
)
def test_the_summary_schema_forbids_extra_fields(extra: str) -> None:
    from netsight_api.schemas_incidents import IncidentSummary

    ok = {**_summary_payload()}
    IncidentSummary.model_validate_json(__import__("json").dumps(ok))
    with pytest.raises(ValidationError):
        IncidentSummary.model_validate_json(__import__("json").dumps({**ok, extra: "leak"}))


def test_the_summary_list_schema_forbids_extra_fields() -> None:
    from netsight_api.schemas_incidents import IncidentSummaryListResponse

    body = {"state": "ok", "incidents": [], "limit": 25, "offset": 0, "next_offset": None}
    IncidentSummaryListResponse.model_validate(body)
    with pytest.raises(ValidationError):
        IncidentSummaryListResponse.model_validate({**body, "total_with_assignees": 3})


# --- the `matches` operator is linear time ----------------------------------------------------------


def test_matches_uses_the_glob_matcher_and_no_regular_expression_engine() -> None:
    from netsight_api.alerting import engine, matching

    assert "glob_matches" in inspect.getsource(engine)
    for module in (engine, matching):
        source = inspect.getsource(module)
        assert "import re\n" not in source
        assert "re.compile" not in source
        assert "fnmatch" not in source


def test_a_catastrophic_pattern_finishes_quickly() -> None:
    # (a*)*b-style: exponential for a backtracking engine, linear here.
    pattern = "*a" * 100 + "b"
    text = "a" * 4000
    started = time.perf_counter()
    assert glob_matches(pattern, text) is False
    assert glob_matches("*" + "a*" * 100, text + "b") is True
    assert time.perf_counter() - started < 2.0


def test_cost_grows_roughly_linearly_with_the_text() -> None:
    pattern = "a*" * 120 + "b"

    def cost(length: int) -> float:
        started = time.perf_counter()
        glob_matches(pattern, "a" * length)
        return time.perf_counter() - started

    cost(500)  # warm up
    small = min(cost(1000) for _ in range(3))
    large = min(cost(4000) for _ in range(3))
    assert large < max(small * 4 * 3, 0.5)  # 4x the text with a generous constant: not quadratic


def test_over_long_text_never_matches() -> None:
    assert glob_matches("*", "a" * 5000) is False
