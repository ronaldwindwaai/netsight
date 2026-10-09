"""Deterministic alert evaluation: conditions, schedules, for/cooldown, exceptions, scope,
maintenance, grouping, fail-closed configuration. Every test uses fixed, injected clocks."""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from typing import Any

import pytest

from netsight_api.alerting.engine import (
    Decision,
    Observation,
    RuleState,
    alert_fingerprint,
    evaluate_definition,
    evaluate_rule,
)
from netsight_api.alerting.grouping import group_key, plan_incident
from netsight_api.alerting.validation import check_definition
from netsight_api.schemas import AlertRule, AlertRuleDefinition, AlertScope, MaintenanceWindow

T0 = datetime(2026, 10, 8, 10, 0, tzinfo=UTC)  # Thursday
RULE_ID = "alert-rule-5a6b7c8d-1e2f-4a3b-9c4d-5e6f7a8b9c0d"
SCOPES = frozenset({("device_group", "staff-workstations"), ("site", "hq")})


def definition(**overrides: Any) -> AlertRuleDefinition:
    body: dict[str, Any] = {
        "name": "Large upload",
        "scope": {"kind": "device_group", "ref": "staff-workstations"},
        "condition": {
            "metric": "traffic.upload_bytes",
            "operator": "gt",
            "threshold": 1000.0,
            "pattern": None,
        },
        "baseline_mode": "none",
        "window_seconds": 900,
        "for_seconds": 0,
        "cooldown_seconds": 0,
        "schedule": None,
        "exceptions": {"destinations": [], "device_groups": []},
        "severity": "high",
        "labels": {"team": "network"},
        "actions": ["create_alert", "email"],
        "incident_policy": "group",
    }
    body.update(overrides)
    return AlertRuleDefinition.model_validate(body)


def obs(offset_s: float = 0, value: float | None = 5000.0, **overrides: Any) -> Observation:
    fields: dict[str, Any] = {
        "at": T0 + timedelta(seconds=offset_s),
        "entity": "device-1",
        "value": value,
        "scopes": SCOPES,
    }
    fields.update(overrides)
    return Observation(**fields)


def clock_at(offset_s: float = 0) -> Callable[[], datetime]:
    moment = T0 + timedelta(seconds=offset_s)
    return lambda: moment


def step(
    d: AlertRuleDefinition,
    o: Observation,
    state: RuleState | None = None,
    windows: list[Any] | None = None,
    *,
    now: float | None = None,
) -> tuple[Decision, RuleState]:
    """Evaluate one observation with the clock at the observation unless told otherwise."""
    offset = (o.at - T0).total_seconds() if now is None else now
    return evaluate_definition(
        d,
        rule_id=RULE_ID,
        observation=o,
        state=state or RuleState(),
        windows=windows or [],
        clock=clock_at(offset),
    )


def replay(d: AlertRuleDefinition, series: list[Observation]) -> list[Decision]:
    state = RuleState()
    out = []
    for o in series:
        decision, state = step(d, o, state)
        out.append(decision)
    return out


class Window:
    def __init__(
        self,
        start_s: float,
        end_s: float,
        *,
        kind: str = "site",
        ref: str = "hq",
        evaluation: str = "retain",
        status: str = "scheduled",
    ) -> None:
        self.scope = AlertScope(kind=kind, ref=ref)  # type: ignore[arg-type]
        self.starts_at = T0 + timedelta(seconds=start_s)
        self.ends_at = T0 + timedelta(seconds=end_s)
        self.evaluation = evaluation
        self.status = status


# --- conditions -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("operator", "threshold", "value", "holds"),
    [
        ("gt", 10.0, 10.0, False),
        ("gt", 10.0, 10.5, True),
        ("gte", 10.0, 10.0, True),
        ("gte", 10.0, 9.99, False),
        ("lt", 10.0, 10.0, False),
        ("lt", 10.0, 9.0, True),
        ("lte", 10.0, 10.0, True),
        ("lte", 10.0, 10.1, False),
        ("eq", 10.0, 10.0, True),
        ("eq", 10.0, 10.1, False),
        ("ne", 10.0, 10.0, False),
        ("ne", 10.0, 11.0, True),
        ("gt", -5.0, -4.0, True),
        ("gt", 0.0, 0.0, False),
    ],
)
def test_numeric_operators_at_their_boundaries(
    operator: str, threshold: float, value: float, holds: bool
) -> None:
    d = definition(
        condition={
            "metric": "traffic.upload_bytes",
            "operator": operator,
            "threshold": threshold,
            "pattern": None,
        }
    )
    decision, _ = step(d, obs(value=value))
    assert decision.outcome == ("firing" if holds else "not-met")


def test_matches_uses_the_glob_matcher_on_text() -> None:
    d = definition(
        condition={
            "metric": "security.signature",
            "operator": "matches",
            "threshold": None,
            "pattern": "*ssh*brute*",
        }
    )
    hit, _ = step(d, obs(value=None, text="SSH brute-force attempt"))
    assert hit.outcome == "not-met"  # case-sensitive: 'SSH' != 'ssh'
    hit, _ = step(d, obs(value=None, text="ssh brute-force attempt"))
    assert hit.outcome == "firing"
    miss, _ = step(d, obs(value=None, text="dns lookup"))
    assert miss.outcome == "not-met"


def test_matches_without_text_is_no_data() -> None:
    d = definition(
        condition={
            "metric": "security.signature",
            "operator": "matches",
            "threshold": None,
            "pattern": "*",
        }
    )
    decision, _ = step(d, obs(value=None, text=None))
    assert decision.outcome == "no-data"
    assert decision.notify is False


@pytest.mark.parametrize("bad", [None, math.nan, math.inf, -math.inf])
def test_missing_or_non_finite_values_never_fire(bad: float | None) -> None:
    decision, state = step(definition(), obs(value=bad))
    assert decision.outcome == "no-data"
    assert state.phase == "inactive"
    assert decision.notify is False


def test_first_firing_notifies_once_and_continuing_does_not_renotify() -> None:
    d = definition()
    first, state = step(d, obs(0))
    assert (first.outcome, first.transition, first.phase, first.notify) == (
        "firing",
        "fired",
        "firing",
        True,
    )
    second, state = step(d, obs(60), state)
    assert (second.outcome, second.transition, second.phase, second.notify) == (
        "firing",
        None,
        "firing",
        False,
    )
    assert second.blocked_by is None
    assert state.notified is True


def test_recovery_resolves_and_resets_the_notified_flag() -> None:
    d = definition()
    _, state = step(d, obs(0))
    decision, state = step(d, obs(60, value=1.0), state)
    assert (decision.outcome, decision.transition, decision.phase) == (
        "not-met",
        "resolved",
        "inactive",
    )
    assert state.notified is False
    assert state.phase == "inactive"


# --- for / debounce -------------------------------------------------------------------------------


def test_for_seconds_delays_firing_until_the_condition_has_held_long_enough() -> None:
    d = definition(for_seconds=120)
    decisions = replay(d, [obs(0), obs(60), obs(119), obs(120), obs(180)])
    assert [x.outcome for x in decisions] == ["pending", "pending", "pending", "firing", "firing"]
    assert [x.notify for x in decisions] == [False, False, False, True, False]
    assert [x.transition for x in decisions] == [None, None, None, "fired", None]


def test_not_met_resets_the_for_timer() -> None:
    d = definition(for_seconds=120)
    decisions = replay(d, [obs(0), obs(60), obs(90, value=1.0), obs(120), obs(200), obs(240)])
    assert [x.outcome for x in decisions] == [
        "pending",
        "pending",
        "not-met",
        "pending",
        "pending",
        "firing",
    ]


def test_flapping_condition_under_for_never_fires() -> None:
    d = definition(for_seconds=120)
    series = [obs(30 * i, value=5000.0 if i % 2 == 0 else 1.0) for i in range(40)]
    decisions = replay(d, series)
    assert all(x.phase != "firing" for x in decisions)
    assert not any(x.notify for x in decisions)


def test_a_data_gap_resets_pending_but_not_a_firing_alert() -> None:
    d = definition(for_seconds=120)
    pending_gap = replay(d, [obs(0), obs(60), obs(90, value=None), obs(120), obs(240)])
    assert [x.outcome for x in pending_gap] == [
        "pending",
        "pending",
        "no-data",
        "pending",
        "firing",
    ]
    firing_gap = replay(definition(), [obs(0), obs(60, value=None), obs(120)])
    assert [x.phase for x in firing_gap] == ["firing", "firing", "firing"]
    assert firing_gap[1].transition is None  # a gap is not a recovery


# --- cooldown ---------------------------------------------------------------------------------------


def test_cooldown_suppresses_the_notification_of_a_quick_refire() -> None:
    d = definition(cooldown_seconds=300)
    series = [obs(0), obs(60, value=1.0), obs(120), obs(180)]
    first, cleared, refire, continuing = replay(d, series)
    assert first.notify is True
    assert cleared.transition == "resolved"
    assert refire.transition == "fired"
    assert (refire.notify, refire.blocked_by) == (False, "cooldown")
    assert (continuing.notify, continuing.blocked_by) == (False, "cooldown")


def test_cooldown_expiry_releases_the_pending_notification_while_still_firing() -> None:
    d = definition(cooldown_seconds=300)
    state = RuleState()
    outcomes = []
    for o in [obs(0), obs(60, value=1.0), obs(120), obs(299), obs(300), obs(360)]:
        decision, state = step(d, o, state)
        outcomes.append((decision.notify, decision.blocked_by))
    assert outcomes == [
        (True, None),
        (False, None),
        (False, "cooldown"),
        (False, "cooldown"),
        (True, None),  # 300s after the first notification
        (False, None),
    ]


def test_flapping_with_cooldown_notifies_at_most_once_per_cooldown() -> None:
    d = definition(cooldown_seconds=600)
    series = [obs(30 * i, value=5000.0 if i % 2 == 0 else 1.0) for i in range(41)]
    decisions = replay(d, series)
    notified_at = [(x.at - T0).total_seconds() for x in decisions if x.notify]
    assert notified_at[0] == 0
    assert all(b - a >= 600 for a, b in pairwise(notified_at))
    assert 1 < len(notified_at) <= 3


# --- schedules ---------------------------------------------------------------------------------------


def after_hours() -> AlertRuleDefinition:
    return definition(
        schedule={
            "timezone": "Africa/Windhoek",
            "active": [
                {"weekdays": ["mon", "tue", "wed", "thu", "fri"], "from": "20:00", "to": "06:00"}
            ],
        }
    )


def test_rule_only_fires_inside_its_schedule_in_the_schedule_timezone() -> None:
    d = after_hours()
    # 10:00 UTC is 12:00 in Windhoek: outside the 20:00-06:00 window.
    noon, _ = step(d, obs(0))
    assert noon.outcome == "outside-schedule"
    assert noon.notify is False
    night = Observation(
        at=datetime(2026, 10, 8, 18, 30, tzinfo=UTC), entity="device-1", value=5000.0, scopes=SCOPES
    )
    decision, _ = evaluate_definition(
        d,
        rule_id=RULE_ID,
        observation=night,
        state=RuleState(),
        windows=[],
        clock=lambda: night.at,
    )
    assert decision.outcome == "firing"


def test_leaving_the_schedule_resolves_a_firing_alert() -> None:
    d = after_hours()
    inside = datetime(2026, 10, 9, 3, 59, tzinfo=UTC)  # 05:59 local
    outside = datetime(2026, 10, 9, 4, 0, tzinfo=UTC)  # 06:00 local
    state = RuleState()
    decision = None
    for moment in (inside, outside):
        o = Observation(at=moment, entity="device-1", value=5000.0, scopes=SCOPES)
        decision, state = evaluate_definition(
            d, rule_id=RULE_ID, observation=o, state=state, windows=[], clock=lambda m=moment: m
        )
    assert decision is not None
    assert (decision.outcome, decision.transition) == ("outside-schedule", "resolved")


# --- exceptions ---------------------------------------------------------------------------------------


def test_exception_destination_suppresses_the_alert() -> None:
    d = definition(exceptions={"destinations": ["approved-backup"], "device_groups": []})
    excepted, state = step(d, obs(destination="approved-backup"))
    assert excepted.outcome == "excepted"
    assert state.phase == "inactive"
    other, _ = step(d, obs(destination="evil.example"))
    assert other.outcome == "firing"
    # Exact, case-sensitive: a look-alike is not excepted.
    lookalike, _ = step(d, obs(destination="Approved-Backup"))
    assert lookalike.outcome == "firing"


def test_exception_device_group_suppresses_the_alert() -> None:
    d = definition(exceptions={"destinations": [], "device_groups": ["backup-servers"]})
    excepted, _ = step(d, obs(device_groups=frozenset({"cctv", "backup-servers"})))
    assert excepted.outcome == "excepted"
    other, _ = step(d, obs(device_groups=frozenset({"cctv"})))
    assert other.outcome == "firing"


def test_an_exception_arriving_mid_alert_resolves_it() -> None:
    d = definition(exceptions={"destinations": ["approved-backup"], "device_groups": []})
    _, state = step(d, obs(0))
    decision, state = step(d, obs(60, destination="approved-backup"), state)
    assert (decision.outcome, decision.transition) == ("excepted", "resolved")


# --- scope -----------------------------------------------------------------------------------------------


def test_observations_outside_the_rule_scope_are_ignored_and_change_nothing() -> None:
    d = definition()
    _, state = step(d, obs(0))
    other = obs(60, scopes=frozenset({("device_group", "servers")}))
    decision, after = step(d, other, state)
    assert decision.outcome == "out-of-scope"
    assert after == state
    assert decision.notify is False


# --- maintenance --------------------------------------------------------------------------------------


def test_retain_window_keeps_evaluating_but_suppresses_the_notification() -> None:
    d = definition()
    decision, state = step(d, obs(0), windows=[Window(-60, 600)])
    assert (decision.outcome, decision.transition, decision.phase) == ("firing", "fired", "firing")
    assert (decision.notify, decision.blocked_by) == (False, "maintenance")
    assert decision.maintenance_windows == (0,)
    assert state.notified is False


def test_notification_is_released_when_the_window_ends_while_still_firing() -> None:
    d = definition()
    windows = [Window(-60, 600)]
    _, state = step(d, obs(0), windows=windows)
    during, state = step(d, obs(300), state, windows)
    assert (during.notify, during.blocked_by) == (False, "maintenance")
    after, state = step(d, obs(600), state, windows)  # end is exclusive
    assert (after.notify, after.blocked_by) == (True, None)
    assert state.notified is True


def test_alert_that_resolved_inside_the_window_never_notifies() -> None:
    d = definition()
    windows = [Window(-60, 600)]
    _, state = step(d, obs(0), windows=windows)
    cleared, state = step(d, obs(60, value=1.0), state, windows)
    assert cleared.transition == "resolved"
    later, _ = step(d, obs(900, value=1.0), state, windows)
    assert later.notify is False


def test_disable_window_stops_evaluation_entirely() -> None:
    d = definition()
    _, state = step(d, obs(0))
    decision, after = step(d, obs(60), state, [Window(0, 600, evaluation="disable")])
    assert decision.outcome == "maintenance-disabled"
    assert decision.maintenance_windows == (0,)
    assert after == state  # no evidence recorded, no state change
    assert decision.notify is False


def test_overlapping_windows_disable_wins_and_expired_or_cancelled_are_ignored() -> None:
    d = definition()
    windows = [
        Window(-600, -1),  # expired
        Window(0, 600, status="cancelled", evaluation="disable"),
        Window(0, 600),  # active retain
        Window(0, 600, kind="device_group", ref="staff-workstations", evaluation="disable"),
    ]
    decision, _ = step(d, obs(10), windows=windows)
    assert decision.outcome == "maintenance-disabled"
    assert decision.maintenance_windows == (2, 3)


def test_window_for_another_scope_does_not_apply() -> None:
    decision, _ = step(definition(), obs(0), windows=[Window(-60, 600, ref="branch")])
    assert (decision.notify, decision.blocked_by) == (True, None)
    assert decision.maintenance_windows == ()


# --- baseline ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "anomaly", "expected"),
    [
        ("above-baseline", "above", "firing"),
        ("above-baseline", "below", "not-met"),
        ("above-baseline", "normal", "not-met"),
        ("below-baseline", "below", "firing"),
        ("below-baseline", "above", "not-met"),
        ("outside-baseline", "above", "firing"),
        ("outside-baseline", "below", "firing"),
        ("outside-baseline", "normal", "not-met"),
        ("above-baseline", None, "no-data"),
    ],
)
def test_baseline_modes_need_the_detector_direction_and_the_threshold(
    mode: str, anomaly: str | None, expected: str
) -> None:
    decision, _ = step(definition(baseline_mode=mode), obs(anomaly=anomaly))
    assert decision.outcome == expected


def test_baseline_mode_still_requires_the_threshold_to_hold() -> None:
    decision, _ = step(definition(baseline_mode="above-baseline"), obs(value=1.0, anomaly="above"))
    assert decision.outcome == "not-met"


# --- freshness, duplicates, ordering -------------------------------------------------------------------


def test_stale_observations_are_ignored() -> None:
    d = definition(window_seconds=900)
    decision, state = step(d, obs(0), now=901)
    assert decision.outcome == "stale"
    assert state == RuleState()
    ok, _ = step(d, obs(0), now=900)
    assert ok.outcome == "firing"


def test_future_observations_beyond_the_skew_allowance_are_ignored() -> None:
    d = definition()
    ok, _ = step(d, obs(60), now=0)
    assert ok.outcome == "firing"
    future, state = step(d, obs(61), now=0)
    assert future.outcome == "future"
    assert state == RuleState()


def test_duplicate_and_out_of_order_observations_do_not_change_state() -> None:
    d = definition(for_seconds=120)
    _, state = step(d, obs(60))
    duplicate, same = step(d, obs(60), state)
    older, again = step(d, obs(30), state)
    assert duplicate.outcome == older.outcome == "stale"
    assert same == again == state


def test_naive_observation_time_is_refused() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        Observation(
            at=datetime(2026, 10, 8, 10),  # noqa: DTZ001 (deliberately naive)
            entity="e",
            value=1.0,
            scopes=SCOPES,
        )


@pytest.mark.parametrize("entity", ["", "x" * 256])
def test_observation_entity_is_bounded(entity: str) -> None:
    with pytest.raises(ValueError, match="entity"):
        Observation(at=T0, entity=entity, value=1.0, scopes=SCOPES)


# --- fail-closed configuration ------------------------------------------------------------------------


def test_unknown_timezone_never_fires_even_when_the_condition_holds() -> None:
    d = definition(
        schedule={
            "timezone": "Mars/Olympus",
            "active": [{"weekdays": ["thu"], "from": "00:00", "to": "00:00"}],
        }
    )
    decision, state = step(d, obs(0))
    assert decision.outcome == "invalid-config"
    assert decision.notify is False
    assert state == RuleState()


def test_check_definition_reports_every_problem_with_a_code_and_field() -> None:
    assert check_definition(definition()) == ()
    bad_tz = definition(
        schedule={
            "timezone": "Mars/Olympus",
            "active": [{"weekdays": ["thu"], "from": "01:00", "to": "02:00"}],
        }
    )
    assert [(p.code, p.field) for p in check_definition(bad_tz)] == [
        ("SCHEDULE_TIMEZONE_UNKNOWN", "schedule.timezone")
    ]
    baseline_text = definition(
        baseline_mode="above-baseline",
        condition={"metric": "m", "operator": "matches", "threshold": None, "pattern": "*"},
    )
    assert [p.code for p in check_definition(baseline_text)] == [
        "BASELINE_REQUIRES_NUMERIC_OPERATOR"
    ]
    orphan_incident = definition(actions=["email"], incident_policy="create")
    assert [p.code for p in check_definition(orphan_incident)] == [
        "INCIDENT_POLICY_REQUIRES_CREATE_ALERT"
    ]
    both = definition(
        actions=["email"],
        incident_policy="group",
        schedule={
            "timezone": "Mars/Olympus",
            "active": [{"weekdays": ["thu"], "from": "01:00", "to": "02:00"}],
        },
    )
    assert len(check_definition(both)) == 2


def rule_from(d: AlertRuleDefinition, status: str) -> AlertRule:
    approved = status != "draft"
    return AlertRule(
        **d.model_dump(),
        id=RULE_ID,
        status=status,  # type: ignore[arg-type]
        created_by="identity-ronald",
        created_at=T0,
        updated_at=T0,
        approved_by="identity-admin" if approved else None,
        approved_at=T0 if approved else None,
        version=2,
    )


@pytest.mark.parametrize("status", ["draft", "disabled"])
def test_only_an_active_rule_evaluates(status: str) -> None:
    decision, state = evaluate_rule(
        rule_from(definition(), status),
        observation=obs(0),
        state=RuleState(),
        windows=[],
        clock=clock_at(0),
    )
    assert decision.outcome == "rule-not-active"
    assert decision.notify is False
    assert state == RuleState()


def test_an_active_rule_evaluates_and_uses_its_own_id_for_the_fingerprint() -> None:
    decision, _ = evaluate_rule(
        rule_from(definition(), "active"),
        observation=obs(0),
        state=RuleState(),
        windows=[],
        clock=clock_at(0),
    )
    assert decision.outcome == "firing"
    assert decision.fingerprint == alert_fingerprint(RULE_ID, "device-1")


# --- determinism, grouping, scale ------------------------------------------------------------------------


def test_evaluation_is_deterministic_and_does_not_read_the_wall_clock() -> None:
    d = definition(for_seconds=60, cooldown_seconds=120)
    series = [obs(20 * i, value=5000.0 if i % 3 else 1.0) for i in range(60)]
    assert replay(d, series) == replay(d, series)
    assert all(x.at.year == 2026 for x in replay(d, series))


def test_states_and_decisions_are_immutable() -> None:
    decision, state = step(definition(), obs(0))
    with pytest.raises(AttributeError):
        state.phase = "inactive"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        decision.notify = False  # type: ignore[misc]


def test_fingerprint_is_stable_and_distinguishes_rule_and_entity() -> None:
    a = alert_fingerprint(RULE_ID, "device-1")
    assert a == alert_fingerprint(RULE_ID, "device-1")
    assert a != alert_fingerprint(RULE_ID, "device-2")
    assert a != alert_fingerprint(RULE_ID.replace("5a6b", "5a6c"), "device-1")
    # The separator cannot be forged by shifting characters between the two parts.
    assert alert_fingerprint("a", "bc") != alert_fingerprint("ab", "c")
    assert len(a) == 32


def test_group_key_ignores_label_order_and_depends_on_scope_and_labels() -> None:
    one = definition(labels={"team": "network", "site": "hq"})
    two = definition(labels={"site": "hq", "team": "network"})
    assert group_key(one) == group_key(two)
    assert group_key(one) != group_key(definition(labels={"team": "security", "site": "hq"}))
    assert group_key(one) != group_key(
        definition(labels={"team": "network", "site": "hq"}, scope={"kind": "site", "ref": "hq"})
    )


def test_incident_plan_follows_the_policy_and_dedupes() -> None:
    key = group_key(definition())
    fingerprint = "f" * 32
    none = plan_incident(
        definition(incident_policy="none"),
        fingerprint=fingerprint,
        open_group_keys=frozenset(),
        open_fingerprints=frozenset(),
    )
    assert none.action == "none"
    create = plan_incident(
        definition(incident_policy="create"),
        fingerprint=fingerprint,
        open_group_keys=frozenset({key}),
        open_fingerprints=frozenset(),
    )
    assert create.action == "create"  # 'create' never merges into a group
    duplicate = plan_incident(
        definition(incident_policy="create"),
        fingerprint=fingerprint,
        open_group_keys=frozenset(),
        open_fingerprints=frozenset({fingerprint}),
    )
    assert duplicate.action == "none"
    first = plan_incident(
        definition(incident_policy="group"),
        fingerprint=fingerprint,
        open_group_keys=frozenset(),
        open_fingerprints=frozenset(),
    )
    assert (first.action, first.group_key) == ("create", key)
    joined = plan_incident(
        definition(incident_policy="group"),
        fingerprint="e" * 32,
        open_group_keys=frozenset({key}),
        open_fingerprints=frozenset({fingerprint}),
    )
    assert (joined.action, joined.group_key) == ("attach", key)


def test_ten_thousand_observations_evaluate_quickly() -> None:
    d = definition(for_seconds=60, cooldown_seconds=300)
    state = RuleState()
    started = time.perf_counter()
    for i in range(10_000):
        _, state = step(d, obs(i * 10, value=5000.0 if i % 7 else 1.0), state)
    assert time.perf_counter() - started < 5.0


def test_maintenance_window_model_satisfies_the_engine_protocol() -> None:
    window = MaintenanceWindow(
        id="maintenance-5a6b7c8d-1e2f-4a3b-9c4d-5e6f7a8b9c0d",
        name="m",
        scope=AlertScope(kind="site", ref="hq"),
        starts_at=T0 - timedelta(minutes=1),
        ends_at=T0 + timedelta(hours=1),
        evaluation="retain",
        status="scheduled",
        reason="planned",
        created_by="identity-ronald",
        created_at=T0,
        cancelled_by=None,
        cancelled_at=None,
    )
    decision, _ = step(definition(), obs(0), windows=[window])
    assert decision.blocked_by == "maintenance"


def test_engine_vocabulary_matches_the_api_contract_vocabulary() -> None:
    from typing import get_args

    from netsight_api import schemas_alerting as schemas
    from netsight_api.alerting import engine

    assert set(get_args(engine.Outcome)) == set(get_args(schemas.EvaluateOutcome))
    assert set(get_args(engine.Phase)) == set(get_args(schemas.EvaluatePhase))
    assert set(get_args(engine.Transition)) == set(get_args(schemas.EvaluateTransition))
    assert set(get_args(engine.BlockedBy)) == set(get_args(schemas.EvaluateBlockedBy))
    assert set(get_args(engine.Anomaly)) == set(get_args(schemas.ObservationAnomaly))
