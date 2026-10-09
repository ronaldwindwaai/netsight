"""POST /api/v1/alert-rules/evaluate: the read-only dry-run. No store, no network, no effects."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest
from alerting_support import (
    NOW,
    RULES,
    XSS,
    Caller,
    SpyStore,
    audit_records,
    clean_environment,
    evaluate_body,
    iso,
    new_store,
    observation,
    rule_body,
)
from net_guard import no_network  # noqa: F401  (pytest fixture)

from netsight_api.alerting_route_support import get_optional_alert_rule_store
from netsight_api.contracts import validate
from netsight_api.main import app
from netsight_api.storage import InMemoryAlertRuleRepository


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    yield from clean_environment(monkeypatch)


@pytest.fixture
def store() -> InMemoryAlertRuleRepository:
    return new_store()


EVALUATE = f"{RULES}/evaluate"
pytestmark = pytest.mark.usefixtures("no_network")


def run(body: dict[str, Any], role: str = "administrator") -> Any:
    return Caller(role).post(EVALUATE, body)


def test_a_valid_definition_yields_one_decision_per_observation() -> None:
    body = evaluate_body(observations=[observation(0), observation(60, value=1), observation(120)])
    response = run(body)
    assert response.status_code == 200
    out = response.json()
    validate("alert_rule_evaluate_response", out)
    assert out["valid"] is True and out["problems"] == []
    assert [r["outcome"] for r in out["results"]] == ["firing", "not-met", "firing"]
    assert [r["transition"] for r in out["results"]] == ["fired", "resolved", "fired"]
    # cooldown 3600: the first firing notifies, the quick re-fire is blocked.
    assert [(r["notify"], r["blocked_by"]) for r in out["results"]] == [
        (True, None),
        (False, None),
        (False, "cooldown"),
    ]
    assert out["results"][0]["at"] == body["observations"][0]["at"]


def test_the_schedule_is_applied_in_its_timezone() -> None:
    # 10:00 UTC is noon in Windhoek: outside the 20:00-06:00 window.
    noon = observation(0, at=iso(NOW))
    response = run(evaluate_body(observations=[noon])).json()
    assert response["results"][0]["outcome"] == "outside-schedule"


def test_for_seconds_debounce_is_replayed() -> None:
    definition = rule_body(for_seconds=120, cooldown_seconds=0)
    series = [observation(offset) for offset in (0, 60, 119, 120, 180)]
    out = run(evaluate_body(definition=definition, observations=series)).json()
    assert [r["outcome"] for r in out["results"]] == [
        "pending",
        "pending",
        "pending",
        "firing",
        "firing",
    ]
    assert [r["notify"] for r in out["results"]] == [False, False, False, True, False]


def test_supplied_maintenance_windows_suppress_and_are_reported_by_index() -> None:
    start = observation(0)["at"]
    window = {
        "scope": {"kind": "device_group", "ref": "staff-workstations"},
        "starts_at": iso(NOW),
        "ends_at": iso(NOW + timedelta(days=1)),
        "evaluation": "retain",
        "status": "scheduled",
    }
    cancelled = {**window, "status": "cancelled", "evaluation": "disable"}
    out = run(evaluate_body(windows=[cancelled, window])).json()
    (result,) = out["results"]
    assert (result["outcome"], result["notify"], result["blocked_by"]) == (
        "firing",
        False,
        "maintenance",
    )
    assert result["maintenance_windows"] == [1]
    assert start  # the observation time is inside the window


def test_a_disable_window_stops_evaluation() -> None:
    window = {
        "scope": {"kind": "device_group", "ref": "staff-workstations"},
        "starts_at": iso(NOW),
        "ends_at": iso(NOW + timedelta(days=1)),
        "evaluation": "disable",
        "status": "scheduled",
    }
    (result,) = run(evaluate_body(windows=[window])).json()["results"]
    assert result["outcome"] == "maintenance-disabled" and result["notify"] is False


def test_an_unevaluable_definition_is_valid_false_with_problems_and_no_results() -> None:
    bad = rule_body(
        schedule={
            "timezone": "Mars/Olympus",
            "active": [{"weekdays": ["mon"], "from": "01:00", "to": "02:00"}],
        },
        actions=["email"],
        incident_policy="create",
    )
    response = run(evaluate_body(definition=bad))
    assert response.status_code == 200
    out = response.json()
    validate("alert_rule_evaluate_response", out)
    assert out["valid"] is False and out["results"] == []
    assert {p["code"] for p in out["problems"]} == {
        "SCHEDULE_TIMEZONE_UNKNOWN",
        "INCIDENT_POLICY_REQUIRES_CREATE_ALERT",
    }
    assert {p["field"] for p in out["problems"]} == {"schedule.timezone", "incident_policy"}


def test_scope_and_baseline_anomaly_inputs_are_honoured() -> None:
    definition = rule_body(schedule=None, baseline_mode="above-baseline")
    hit = observation(0, anomaly="above")
    miss = observation(60, anomaly="below")
    nothing = observation(90, anomaly=None)
    outside = observation(120, anomaly="above", scopes=[{"kind": "site", "ref": "other"}])
    out = run(evaluate_body(definition=definition, observations=[hit, miss, nothing, outside]))
    assert [r["outcome"] for r in out.json()["results"]] == [
        "firing",
        "not-met",
        "no-data",
        "out-of-scope",
    ]


def test_text_patterns_use_the_linear_time_matcher() -> None:
    definition = rule_body(
        condition={
            "metric": "security.signature",
            "operator": "matches",
            "threshold": None,
            "pattern": "a*" * 100 + "b",  # catastrophic for a backtracking engine
        },
        schedule=None,
    )
    series = [observation(0, value=None, text="a" * 3000)]
    response = run(evaluate_body(definition=definition, observations=series))
    assert response.status_code == 200
    assert response.json()["results"][0]["outcome"] == "not-met"


def test_worst_case_input_stays_cheap() -> None:
    """64 observations of maximum-size text against a maximum-size pattern."""
    import time

    definition = rule_body(
        condition={
            "metric": "security.signature",
            "operator": "matches",
            "threshold": None,
            "pattern": "a*" * 127 + "b",
        },
        schedule=None,
        cooldown_seconds=0,
    )
    # 64 full-size texts is the combined-text cap (test_alert_evaluate_limits.py).
    series = [observation(i, value=None, text="a" * 4096) for i in range(64)]
    started = time.perf_counter()
    response = run(evaluate_body(definition=definition, observations=series))
    assert response.status_code == 200
    assert all(r["outcome"] == "not-met" for r in response.json()["results"])
    assert time.perf_counter() - started < 10.0


def test_untrusted_observation_text_is_data_only() -> None:
    definition = rule_body(
        condition={
            "metric": "security.signature",
            "operator": "matches",
            "threshold": None,
            "pattern": "*",
        },
        schedule=None,
    )
    out = run(
        evaluate_body(definition=definition, observations=[observation(0, value=None, text=XSS)])
    )
    assert out.status_code == 200
    assert out.json()["results"][0]["outcome"] == "firing"
    assert "script" not in out.text  # nothing from the input is reflected


@pytest.mark.parametrize(
    "mutation",
    [
        {"observations": []},
        {"observations": [observation(0)] * 201},
        {"observations": [observation(60), observation(0)]},
        {"observations": [observation(0), observation(0)]},
        {"observations": [observation(0, scopes=[])]},
        {"observations": [observation(0, entity="")]},
        {"observations": [observation(0, value="5")]},
        {"observations": [observation(0, text="x" * 4097)]},
        {"observations": [observation(0, anomaly="sideways")]},
        {"observations": [observation(0, at="2026-10-08T18:30:00")]},
        {"windows": [{"scope": {"kind": "site", "ref": "x"}}] * 1},
        {"definition": rule_body(severity="urgent")},
        {"persist": True},
    ],
)
def test_request_bounds_are_422(mutation: dict[str, Any]) -> None:
    assert run(evaluate_body(**mutation)).status_code == 422


def test_the_dry_run_has_no_external_effect(caplog: pytest.LogCaptureFixture) -> None:
    spy = SpyStore()
    app.dependency_overrides[get_optional_alert_rule_store] = lambda: spy
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    response = run(evaluate_body())
    assert response.status_code == 200
    assert spy.calls == []  # the store is never read or written
    assert spy.list_rules() == [] and spy.list_windows() == []
    assert not [r for r in audit_records(caplog) if r["outcome"] == "success"]


def test_the_dry_run_works_without_any_store() -> None:
    app.dependency_overrides[get_optional_alert_rule_store] = lambda: None
    assert run(evaluate_body()).status_code == 200


def test_the_dry_run_is_deterministic() -> None:
    body = evaluate_body(
        observations=[observation(i * 30, value=5e9 if i % 2 else 1) for i in range(40)]
    )
    first, second = run(body).json(), run(body).json()
    assert first == second


def test_the_dry_run_is_rate_limited_per_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    from netsight_api import alerting_route_support

    monkeypatch.setattr(alerting_route_support, "EVALUATE_LIMIT_PER_MINUTE", 3)
    caller = Caller("administrator")
    statuses = [caller.post(EVALUATE, evaluate_body()).status_code for _ in range(5)]
    assert statuses == [200, 200, 200, 429, 429]
    assert Caller("auditor", "sub-other").post(EVALUATE, evaluate_body()).status_code == 200


def test_the_dry_run_still_demands_a_csrf_token_and_a_trusted_origin(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    caller = Caller("administrator")
    assert caller.post(EVALUATE, evaluate_body(), csrf=None).status_code == 403
    assert caller.post(EVALUATE, evaluate_body(), csrf="forged").status_code == 403
    monkeypatch.setenv("NETSIGHT_PUBLIC_BASE_URL", "https://netsight.example.com")
    foreign = caller.post(EVALUATE, evaluate_body(), headers={"Origin": "https://evil.example"})
    assert foreign.status_code == 403 and foreign.json()["error"]["code"] == "ORIGIN_NOT_ALLOWED"
    assert [r["reason"] for r in audit_records(caplog)] == ["csrf", "csrf", "origin"]
