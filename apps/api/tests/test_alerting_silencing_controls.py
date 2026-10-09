"""Silencing controls (S6-3 security review H1): who may silence alerting, how much, and the trail.

* A maintenance window whose evaluation is ``disable`` stops rules from evaluating at all, so
  it needs ``maintenance:write-organisation`` whatever its scope kind.
* Cancelling an organisation-scope window needs the same permission, judged on the locked row
  inside the audited store call (a scope change between a read and the write cannot race it).
* Live windows per scope reference, live windows in total and rules in total are capped; the
  limits are constants in ``storage.lifecycle`` and are enforced inside the store call.
* Rule-disable and window create/cancel audit events are distinguishable (``silencing``) and
  carry scope kind, evaluation mode and a duration bucket, so an alert on them is possible.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest
from alerting_support import (
    NOW,
    RULES,
    WINDOWS,
    Caller,
    audit_records,
    clean_environment,
    iso,
    new_store,
    rule_body,
    seed_rule,
    seed_window,
    window_body,
)

from netsight_api.schemas import AlertScope
from netsight_api.storage import (
    InMemoryAlertRuleRepository,
    LimitExceededError,
    ScopeViolationError,
    lifecycle,
)

ORGANISATION = {"kind": "organisation", "ref": "default"}
LIMIT_MESSAGE = "A configuration limit was reached; remove unused entries and retry"


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    yield from clean_environment(monkeypatch)


@pytest.fixture
def store() -> InMemoryAlertRuleRepository:
    return new_store()


# --- disable-mode windows are administrator-only -----------------------------------------------


@pytest.mark.parametrize("role", ["network_engineer", "security_analyst"])
@pytest.mark.parametrize("kind", ["site", "device", "device_group", "vlan", "user", "service"])
def test_a_disable_window_needs_the_organisation_permission_whatever_the_scope(
    store: InMemoryAlertRuleRepository,
    role: str,
    kind: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    response = Caller(role).post(
        WINDOWS, window_body(scope={"kind": kind, "ref": "x"}, evaluation="disable")
    )
    assert response.status_code == 403
    assert store.list_windows() == []
    assert [(r["outcome"], r["reason"]) for r in audit_records(caplog)] == [
        ("denied", "disable-evaluation")
    ]


def test_an_administrator_may_schedule_a_disable_window(
    store: InMemoryAlertRuleRepository,
) -> None:
    response = Caller("administrator").post(WINDOWS, window_body(evaluation="disable"))
    assert response.status_code == 201
    assert response.json()["evaluation"] == "disable"


def test_a_retain_window_below_organisation_scope_stays_open_to_the_scoped_roles(
    store: InMemoryAlertRuleRepository,
) -> None:
    assert Caller("network_engineer").post(WINDOWS, window_body()).status_code == 201


# --- cancelling an organisation-scope window ------------------------------------------------------


def test_cancelling_an_organisation_window_needs_the_organisation_permission(
    store: InMemoryAlertRuleRepository, caplog: pytest.LogCaptureFixture
) -> None:
    window_id = seed_window(store, scope=ORGANISATION)
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    refused = Caller("network_engineer").post(f"{WINDOWS}/{window_id}/cancel")
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "FORBIDDEN"
    assert store.get_window(window_id).status == "scheduled"  # type: ignore[union-attr]
    assert [(r["outcome"], r["reason"], r["target"]) for r in audit_records(caplog)] == [
        ("denied", "organisation-scope", window_id)
    ]
    assert Caller("administrator").post(f"{WINDOWS}/{window_id}/cancel").status_code == 200


def test_cancelling_a_site_window_stays_open_to_the_scoped_roles(
    store: InMemoryAlertRuleRepository,
) -> None:
    window_id = seed_window(store)
    assert Caller("security_analyst").post(f"{WINDOWS}/{window_id}/cancel").status_code == 200


def test_the_store_judges_the_scope_on_the_row_it_cancels(
    store: InMemoryAlertRuleRepository,
) -> None:
    organisation_id = seed_window(store, scope=ORGANISATION)
    site_id = seed_window(store)
    with pytest.raises(ScopeViolationError):
        store.cancel_window(organisation_id, actor_id="u", organisation_allowed=False)
    assert store.get_window(organisation_id).status == "scheduled"  # type: ignore[union-attr]
    assert store.cancel_window(site_id, actor_id="u", organisation_allowed=False).status == (
        "cancelled"
    )
    assert store.cancel_window(organisation_id, actor_id="u", organisation_allowed=True).status == (
        "cancelled"
    )


def test_the_store_denies_organisation_cancellation_by_default(
    store: InMemoryAlertRuleRepository,
) -> None:
    organisation_id = seed_window(store, scope=ORGANISATION)
    with pytest.raises(ScopeViolationError):
        store.cancel_window(organisation_id, actor_id="u")


# --- capacity caps ---------------------------------------------------------------------------------------


def test_the_limits_are_defined_in_one_place() -> None:
    assert lifecycle.MAX_LIVE_WINDOWS_PER_SCOPE == 20
    assert lifecycle.MAX_LIVE_WINDOWS == 500
    assert lifecycle.MAX_RULES == 2000


def test_the_per_scope_window_cap_is_a_409_with_a_fixed_message(
    store: InMemoryAlertRuleRepository, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    caller = Caller("network_engineer")
    for _ in range(lifecycle.MAX_LIVE_WINDOWS_PER_SCOPE):
        assert caller.post(WINDOWS, window_body()).status_code == 201
    refused = caller.post(WINDOWS, window_body())
    assert refused.status_code == 409
    error = refused.json()["error"]
    assert (error["code"], error["message"]) == ("LIMIT_REACHED", LIMIT_MESSAGE)
    assert len(store.list_windows(limit=100)) == lifecycle.MAX_LIVE_WINDOWS_PER_SCOPE
    last = audit_records(caplog)[-1]
    assert (last["outcome"], last["reason"]) == ("failure", "LIMIT_REACHED")
    # Another scope reference is unaffected.
    other = caller.post(WINDOWS, window_body(scope={"kind": "site", "ref": "other-site"}))
    assert other.status_code == 201


def test_cancelled_and_expired_windows_do_not_count_towards_the_cap(
    store: InMemoryAlertRuleRepository,
) -> None:
    for _ in range(lifecycle.MAX_LIVE_WINDOWS_PER_SCOPE - 2):
        seed_window(store)
    cancelled = seed_window(store)
    store.cancel_window(cancelled, actor_id="u")
    # Ended before the store clock (NOW + a few seconds): expired, not live.
    seed_window(
        store,
        starts_at=iso(NOW - timedelta(hours=3)),
        ends_at=iso(NOW - timedelta(hours=2)),
    )
    caller = Caller("network_engineer")
    assert caller.post(WINDOWS, window_body()).status_code == 201
    assert caller.post(WINDOWS, window_body()).status_code == 201
    assert caller.post(WINDOWS, window_body()).status_code == 409


def test_the_scope_cap_does_not_confuse_kind_with_reference(
    store: InMemoryAlertRuleRepository,
) -> None:
    for _ in range(lifecycle.MAX_LIVE_WINDOWS_PER_SCOPE):
        seed_window(store, scope={"kind": "site", "ref": "same"})
    caller = Caller("network_engineer")
    other_kind = caller.post(WINDOWS, window_body(scope={"kind": "device", "ref": "same"}))
    assert other_kind.status_code == 201


def test_the_total_window_cap(
    store: InMemoryAlertRuleRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lifecycle, "MAX_LIVE_WINDOWS", 3)
    for index in range(3):
        seed_window(store, scope={"kind": "site", "ref": f"s{index}"})
    refused = Caller("network_engineer").post(
        WINDOWS, window_body(scope={"kind": "site", "ref": "s9"})
    )
    assert refused.status_code == 409
    assert refused.json()["error"]["message"] == LIMIT_MESSAGE


def test_the_total_rule_cap(
    store: InMemoryAlertRuleRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lifecycle, "MAX_RULES", 3)
    caller = Caller("network_engineer")
    for _ in range(3):
        assert caller.post(RULES, rule_body()).status_code == 201
    refused = caller.post(RULES, rule_body())
    assert refused.status_code == 409
    error = refused.json()["error"]
    assert (error["code"], error["message"]) == ("LIMIT_REACHED", LIMIT_MESSAGE)
    assert len(store.list_rules(limit=100)) == 3


def test_editing_an_existing_rule_is_not_blocked_by_the_rule_cap(
    store: InMemoryAlertRuleRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    rule_id, version = seed_rule(store)
    monkeypatch.setattr(lifecycle, "MAX_RULES", 1)
    response = Caller("network_engineer").put(
        f"{RULES}/{rule_id}", {"expected_version": version, "definition": rule_body(name="n")}
    )
    assert response.status_code == 200


def test_the_store_raises_a_limit_error_not_a_generic_failure(
    store: InMemoryAlertRuleRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lifecycle, "MAX_LIVE_WINDOWS_PER_SCOPE", 1)
    seed_window(store)
    with pytest.raises(LimitExceededError):
        seed_window(store)
    assert AlertScope(kind="site", ref="windhoek-hq")  # the scope is a plain value object


# --- audit distinguishability ---------------------------------------------------------------------------


def _by_action(caplog: pytest.LogCaptureFixture) -> dict[str, dict[str, Any]]:
    return {r["action"]: r for r in audit_records(caplog) if r["outcome"] == "success"}


@pytest.mark.parametrize(
    ("hours", "bucket"),
    [(1, "lte_1h"), (4, "lte_24h"), (24, "lte_24h"), (25, "lte_7d"), (24 * 7, "lte_7d"),
     (24 * 7 + 1, "gt_7d"), (24 * 30, "gt_7d")],
)  # fmt: skip
def test_window_create_and_cancel_carry_scope_mode_and_duration_bucket(
    store: InMemoryAlertRuleRepository,
    caplog: pytest.LogCaptureFixture,
    hours: int,
    bucket: str,
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    caller = Caller("administrator")
    created = caller.post(
        WINDOWS,
        window_body(
            ends_at=iso(NOW + timedelta(hours=1 + hours)),
            evaluation="disable",
            scope=ORGANISATION,
        ),
    ).json()
    assert caller.post(f"{WINDOWS}/{created['id']}/cancel").status_code == 200
    records = _by_action(caplog)
    for action, silencing in (
        ("maintenance.create", "window-create"),
        ("maintenance.cancel", "window-cancel"),
    ):
        record = records[action]
        assert record["silencing"] == silencing
        assert record["scope_kind"] == "organisation"
        assert record["evaluation"] == "disable"
        assert record["duration_bucket"] == bucket


def test_rule_disable_is_distinguishable_and_names_the_scope_kind(
    store: InMemoryAlertRuleRepository, caplog: pytest.LogCaptureFixture
) -> None:
    rule_id, _ = seed_rule(store, status="active", scope={"kind": "site", "ref": "windhoek-hq"})
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    assert Caller("network_engineer").post(f"{RULES}/{rule_id}/disable").status_code == 200
    record = _by_action(caplog)["alert_rule.disable"]
    assert record["silencing"] == "rule-disable"
    assert record["scope_kind"] == "site"
    assert record["evaluation"] == "disable"
    assert record["duration_bucket"] == "indefinite"


def test_non_silencing_events_do_not_carry_the_marker(
    store: InMemoryAlertRuleRepository, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="netsight_api.audit")
    Caller("network_engineer").post(RULES, rule_body())
    assert all("silencing" not in r for r in audit_records(caplog))
