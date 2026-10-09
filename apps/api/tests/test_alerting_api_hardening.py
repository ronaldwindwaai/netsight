"""CSRF, origin, dev-bridge and rate-limit behaviour of every alert-rule / maintenance write.

The writer dependency order is authorise (403) -> CSRF + origin (403) -> rate limit (429); a
refusal at any step changes nothing and is audited.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from alerting_support import (
    MISSING_RULE_ID,
    NOW,
    RULES,
    WINDOWS,
    Caller,
    audit_records,
    clean_environment,
    evaluate_body,
    new_store,
    rule_body,
    seed_rule,
    seed_window,
    window_body,
)
from fastapi.testclient import TestClient

from netsight_api import alerting_route_support
from netsight_api.auth.rate_limit import RateLimiter
from netsight_api.main import app
from netsight_api.storage import InMemoryAlertRuleRepository


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    yield from clean_environment(monkeypatch)


@pytest.fixture
def store() -> InMemoryAlertRuleRepository:
    return new_store()


GOOD_ORIGIN = "https://netsight.example.com"


def writes(store: InMemoryAlertRuleRepository) -> list[tuple[str, Callable[[Caller, Any], Any]]]:
    """Every state-changing route, each against a fresh record so a success is observable."""

    def draft() -> str:
        return seed_rule(store)[0]

    return [
        ("create-rule", lambda c, kw: c.post(RULES, rule_body(), **kw)),
        (
            "update-rule",
            lambda c, kw: c.put(
                f"{RULES}/{draft()}", {"expected_version": 1, "definition": rule_body()}, **kw
            ),
        ),
        (
            "approve-rule",
            lambda c, kw: c.post(f"{RULES}/{draft()}/approve", {"expected_version": 1}, **kw),
        ),
        (
            "disable-rule",
            lambda c, kw: c.post(f"{RULES}/{seed_rule(store, 'active')[0]}/disable", **kw),
        ),
        ("evaluate", lambda c, kw: c.post(f"{RULES}/evaluate", evaluate_body(), **kw)),
        ("create-window", lambda c, kw: c.post(WINDOWS, window_body(), **kw)),
        (
            "cancel-window",
            lambda c, kw: c.post(f"{WINDOWS}/{seed_window(store)}/cancel", **kw),
        ),
    ]


def assert_only_the_seeds_exist(store: InMemoryAlertRuleRepository) -> None:
    """``writes`` seeds three rules (draft, draft, active) and one window; refused calls add or
    change nothing beyond them (no created rule or window, no approval, no cancellation)."""
    assert sorted(r.status for r in store.list_rules(limit=100)) == ["active", "draft", "draft"]
    assert all(r.version == 1 or r.status == "active" for r in store.list_rules(limit=100))
    windows = store.list_windows(include_cancelled=True, limit=100)
    assert [w.status for w in windows] == ["scheduled"]


def test_every_write_works_with_a_valid_token(store: InMemoryAlertRuleRepository) -> None:
    caller = Caller("administrator")
    for name, call in writes(store):
        assert call(caller, {}).status_code in (200, 201), name


@pytest.mark.parametrize("token", [None, "", "forged", "valid-prefix-" + "x" * 500])
def test_a_missing_or_wrong_csrf_token_is_refused_audited_and_changes_nothing(
    store: InMemoryAlertRuleRepository, token: str | None, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    caller = Caller("administrator")
    for name, call in writes(store):
        response = call(caller, {"csrf": token})
        assert response.status_code == 403, name
        assert response.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"
        if token:
            assert token not in response.text
    denied = [r for r in audit_records(caplog) if r["outcome"] == "denied"]
    assert len(denied) == len(writes(store)) and {r["reason"] for r in denied} == {"csrf"}
    assert {r["actor_id"] for r in denied} == {caller.identity_id}
    assert_only_the_seeds_exist(store)


def test_a_csrf_refusal_does_not_mutate_the_targeted_record(
    store: InMemoryAlertRuleRepository,
) -> None:
    rule_id, version = seed_rule(store)
    window_id = seed_window(store)
    caller = Caller("administrator")
    assert (
        caller.post(
            f"{RULES}/{rule_id}/approve", {"expected_version": version}, csrf=None
        ).status_code
        == 403
    )
    assert (
        caller.put(
            f"{RULES}/{rule_id}",
            {"expected_version": version, "definition": rule_body(name="hijacked")},
            csrf="forged",
        ).status_code
        == 403
    )
    assert caller.post(f"{WINDOWS}/{window_id}/cancel", csrf=None).status_code == 403
    rule = store.get_rule(rule_id)
    assert rule is not None and rule.status == "draft" and rule.name != "hijacked"
    assert rule.version == version
    assert store.get_window(window_id).status == "scheduled"  # type: ignore[union-attr]


def test_a_token_from_another_session_is_refused(store: InMemoryAlertRuleRepository) -> None:
    victim, attacker = Caller("administrator", "sub-victim"), Caller("administrator", "sub-evil")
    response = victim.post(RULES, rule_body(), csrf=attacker.session.csrf_token)
    assert response.status_code == 403
    assert store.list_rules() == []


def test_authorisation_comes_before_csrf(
    store: InMemoryAlertRuleRepository, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    technician = Caller("technician")
    response = technician.post(RULES, rule_body(), csrf=None)
    assert response.json()["error"]["code"] == "FORBIDDEN"  # not CSRF: no oracle for the token
    assert [r["reason"] for r in audit_records(caplog)] == ["permission"]


def test_csrf_comes_before_the_rate_limit(
    store: InMemoryAlertRuleRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(alerting_route_support, "WRITE_LIMIT_PER_MINUTE", 1)
    caller = Caller("administrator")
    for _ in range(5):  # forged requests must not consume the victim's budget
        assert caller.post(RULES, rule_body(), csrf="forged").status_code == 403
    assert caller.post(RULES, rule_body()).status_code == 201


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example",
        "null",
        "http://netsight.example.com",
        "https://netsight.example.com.evil.example",
    ],
)
def test_cookie_writes_from_a_foreign_origin_are_refused_even_with_a_valid_token(
    store: InMemoryAlertRuleRepository,
    monkeypatch: pytest.MonkeyPatch,
    origin: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setenv("NETSIGHT_PUBLIC_BASE_URL", GOOD_ORIGIN)
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    caller = Caller("administrator")
    for name, call in writes(store):
        response = call(caller, {"headers": {"Origin": origin}})
        assert response.status_code == 403, name
        assert response.json()["error"]["code"] == "ORIGIN_NOT_ALLOWED"
    assert {r["reason"] for r in audit_records(caplog)} == {"origin"}
    assert_only_the_seeds_exist(store)


def test_cookie_writes_from_the_allowed_origin_or_referer_succeed(
    store: InMemoryAlertRuleRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NETSIGHT_PUBLIC_BASE_URL", GOOD_ORIGIN)
    caller = Caller("administrator")
    assert caller.post(RULES, rule_body(), headers={"Origin": GOOD_ORIGIN}).status_code == 201
    assert (
        caller.post(
            RULES, rule_body(), headers={"Referer": f"{GOOD_ORIGIN}/alert-rules"}
        ).status_code
        == 201
    )
    assert (
        caller.post(
            RULES, rule_body(), headers={"Referer": "https://evil.example/alert-rules"}
        ).status_code
        == 403
    )


def test_reads_do_not_need_a_token_or_an_origin(
    store: InMemoryAlertRuleRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NETSIGHT_PUBLIC_BASE_URL", GOOD_ORIGIN)
    caller = Caller("auditor")
    assert caller.http.get(RULES, headers={"Origin": "https://evil.example"}).status_code == 200
    assert caller.http.get(WINDOWS).status_code == 200


# --- development identity bridge -------------------------------------------------------------------------


@pytest.fixture
def dev_bridge(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSIGHT_ENV", "development")
    monkeypatch.setenv("NETSIGHT_ENABLE_DEV_IDENTITY", "true")


def test_dev_bridge_writes_need_the_custom_header_and_an_allowed_origin(
    store: InMemoryAlertRuleRepository, dev_bridge: None, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    client = TestClient(app)
    assert client.get(RULES).status_code == 200
    assert client.post(RULES, json=rule_body()).status_code == 403
    foreign = client.post(
        RULES, json=rule_body(), headers={"X-CSRF-Token": "dev", "Origin": "https://evil.example"}
    )
    assert foreign.status_code == 403
    assert store.list_rules() == []
    assert [r["reason"] for r in audit_records(caplog)] == ["csrf", "origin"]
    ok = client.post(RULES, json=rule_body(), headers={"X-CSRF-Token": "dev"})
    assert ok.status_code == 201


# --- write rate limit -----------------------------------------------------------------------------------------


def test_writes_are_rate_limited_per_identity_and_audited(
    store: InMemoryAlertRuleRepository,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(alerting_route_support, "WRITE_LIMIT_PER_MINUTE", 3)
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    caller = Caller("administrator")
    statuses = [caller.post(RULES, rule_body()).status_code for _ in range(5)]
    assert statuses == [201, 201, 201, 429, 429]
    assert len(store.list_rules()) == 3
    limited = [r for r in audit_records(caplog) if r.get("reason") == "rate-limit"]
    assert len(limited) == 2
    # Another identity has its own budget, and maintenance writes share the same budget.
    assert Caller("network_engineer", "sub-other").post(RULES, rule_body()).status_code == 201
    assert caller.post(WINDOWS, window_body()).status_code == 429


def test_rate_limit_response_names_no_internal_detail(
    store: InMemoryAlertRuleRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(alerting_route_support, "WRITE_LIMIT_PER_MINUTE", 1)
    monkeypatch.setattr(alerting_route_support, "_write_limiter", RateLimiter())
    caller = Caller("administrator")
    caller.post(RULES, rule_body())
    response = caller.post(RULES, rule_body())
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "RATE_LIMITED"
    assert MISSING_RULE_ID not in response.text and str(NOW.year) not in response.text
