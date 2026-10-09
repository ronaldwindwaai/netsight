"""Deterministic rule evaluation (ALERT-ENGINE.md): pure functions, injected clock, no I/O.

``evaluate_definition`` judges one observation of one entity against one rule and returns an
immutable :class:`Decision` plus the next immutable :class:`RuleState`. Nothing here reads the
wall clock, a database or the network: the same inputs always give the same outputs.

Order of judgement (each step can end the evaluation, and anything unclear ends it without
firing, i.e. the engine fails closed):

1. configuration (``validation.check_definition``): an invalid rule never fires;
2. rule status (``evaluate_rule`` only): drafts and disabled rules never fire;
3. freshness against the injected clock: an observation older than the rule's
   ``window_seconds`` or more than ``MAX_FUTURE_SKEW_SECONDS`` ahead is ignored, and so is a
   duplicate or out-of-order observation (at-least-once delivery is therefore harmless);
4. scope: observations for entities outside the rule's scope are ignored;
5. maintenance: an active window with ``evaluation: disable`` stops evaluation entirely (no
   state change); an active ``retain`` window keeps evaluating but blocks the notification;
6. the condition, after exceptions and the schedule: ``held`` is True, False or None (no data);
7. the debounce / cooldown state machine.

State machine (``for_seconds`` = debounce, ``cooldown_seconds`` = minimum spacing between
notifications for the same alert):

* inactive --held--> pending (or firing at once when ``for_seconds`` is 0);
* pending --held for ``for_seconds``--> firing; pending --not held / no data--> inactive;
* firing --not held--> inactive (``resolved``); firing --no data--> firing (a gap is not a
  recovery);
* the notification is released the first time the alert is firing, not yet notified, outside
  any maintenance window and outside the cooldown of the previous notification. A
  notification blocked by maintenance or cooldown is therefore deferred, not lost, while the
  alert keeps firing.

``for_seconds`` is measured between observation timestamps: with sparse sampling the alert
fires at the first held observation at or after the end of the debounce period.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Final, Literal

from netsight_api.alerting.grouping import alert_fingerprint, group_key
from netsight_api.alerting.maintenance import WindowLike, effect_of_windows
from netsight_api.alerting.matching import glob_matches
from netsight_api.alerting.schedule import ScheduleError, schedule_active
from netsight_api.alerting.validation import check_definition
from netsight_api.schemas import AlertRule, AlertRuleDefinition

__all__ = [
    "Decision",
    "Observation",
    "RuleState",
    "alert_fingerprint",
    "definition_of",
    "evaluate_definition",
    "evaluate_rule",
]

MAX_FUTURE_SKEW_SECONDS: Final = 60
MAX_ENTITY_LENGTH: Final = 255

Phase = Literal["inactive", "pending", "firing"]
Outcome = Literal[
    "firing",
    "pending",
    "not-met",
    "excepted",
    "outside-schedule",
    "no-data",
    "out-of-scope",
    "stale",
    "future",
    "maintenance-disabled",
    "invalid-config",
    "rule-not-active",
]
Transition = Literal["fired", "resolved"]
BlockedBy = Literal["maintenance", "cooldown"]
Anomaly = Literal["above", "below", "normal"]
Clock = Callable[[], datetime]


def _require_aware(value: datetime, what: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{what} must be timezone-aware")


@dataclass(frozen=True)
class Observation:
    """One reading of one monitored entity (already aggregated over the rule window).

    ``value`` feeds numeric operators, ``text`` the ``matches`` operator, ``anomaly`` is the
    baseline detector's direction (None: the detector produced no signal). ``scopes`` lists
    every ``(kind, ref)`` the entity belongs to; ``destination`` and ``device_groups`` feed the
    rule exceptions. Text fields are untrusted data and are only ever compared, never
    interpreted.
    """

    at: datetime
    entity: str
    scopes: frozenset[tuple[str, str]]
    value: float | None = None
    text: str | None = None
    anomaly: Anomaly | None = None
    destination: str | None = None
    device_groups: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        _require_aware(self.at, "the observation time")
        if not 1 <= len(self.entity) <= MAX_ENTITY_LENGTH:
            raise ValueError(f"entity must be 1 to {MAX_ENTITY_LENGTH} characters")


@dataclass(frozen=True)
class RuleState:
    """Per (rule, entity) evaluation state; replaced, never mutated."""

    phase: Phase = "inactive"
    since: datetime | None = None
    notified: bool = False
    last_notified_at: datetime | None = None
    last_seen_at: datetime | None = None


@dataclass(frozen=True)
class Decision:
    at: datetime
    outcome: Outcome
    phase: Phase
    notify: bool
    transition: Transition | None
    blocked_by: BlockedBy | None
    maintenance_windows: tuple[int, ...]
    fingerprint: str
    group_key: str


def _holds(definition: AlertRuleDefinition, observation: Observation) -> bool | None:
    """The configured condition on this observation; None when the data cannot say."""
    condition = definition.condition
    if condition.operator == "matches":
        if observation.text is None or condition.pattern is None:
            return None
        verdict = glob_matches(condition.pattern, observation.text)
    else:
        value, threshold = observation.value, condition.threshold
        if value is None or threshold is None or not math.isfinite(value):
            return None
        verdict = {
            "gt": value > threshold,
            "gte": value >= threshold,
            "lt": value < threshold,
            "lte": value <= threshold,
            "eq": value == threshold,
            "ne": value != threshold,
        }[condition.operator]
    mode = definition.baseline_mode
    if mode == "none":
        return verdict
    if observation.anomaly is None:
        return None
    directions = {
        "above-baseline": {"above"},
        "below-baseline": {"below"},
        "outside-baseline": {"above", "below"},
    }[mode]
    return verdict and observation.anomaly in directions


def _is_excepted(definition: AlertRuleDefinition, observation: Observation) -> bool:
    exceptions = definition.exceptions
    if observation.destination is not None and observation.destination in exceptions.destinations:
        return True
    return any(group in exceptions.device_groups for group in observation.device_groups)


def _decision(
    definition: AlertRuleDefinition,
    rule_id: str,
    observation: Observation,
    outcome: Outcome,
    state: RuleState,
    *,
    notify: bool = False,
    transition: Transition | None = None,
    blocked_by: BlockedBy | None = None,
    windows: tuple[int, ...] = (),
) -> Decision:
    return Decision(
        at=observation.at,
        outcome=outcome,
        phase=state.phase,
        notify=notify,
        transition=transition,
        blocked_by=blocked_by,
        maintenance_windows=windows,
        fingerprint=alert_fingerprint(rule_id, observation.entity),
        group_key=group_key(definition),
    )


def _screen(
    definition: AlertRuleDefinition,
    observation: Observation,
    state: RuleState,
    clock: Clock,
) -> Outcome | None:
    """Reasons to ignore the observation without touching the state."""
    if check_definition(definition):
        return "invalid-config"
    now = clock()
    _require_aware(now, "the clock")
    age = (now - observation.at).total_seconds()
    if age > definition.window_seconds:
        return "stale"
    if -age > MAX_FUTURE_SKEW_SECONDS:
        return "future"
    if state.last_seen_at is not None and observation.at <= state.last_seen_at:
        return "stale"
    scope = (definition.scope.kind, definition.scope.ref)
    if scope not in observation.scopes:
        return "out-of-scope"
    return None


def _judge(
    definition: AlertRuleDefinition, observation: Observation
) -> tuple[bool | None, Outcome]:
    """(held, reason-when-not-held); schedule and exceptions only ever narrow the rule."""
    if _is_excepted(definition, observation):
        return False, "excepted"
    try:
        in_schedule = schedule_active(definition.schedule, observation.at)
    except ScheduleError:
        return False, "invalid-config"
    if not in_schedule:
        return False, "outside-schedule"
    held = _holds(definition, observation)
    if held is None:
        return None, "no-data"
    return held, "not-met"


def _next_state(
    definition: AlertRuleDefinition, state: RuleState, held: bool | None, at: datetime
) -> tuple[RuleState, Transition | None]:
    seen = replace(state, last_seen_at=at)
    if held is None:  # a gap: debounce restarts, an existing alert is kept
        if state.phase == "pending":
            return replace(seen, phase="inactive", since=None), None
        return seen, None
    if not held:
        if state.phase == "firing":
            return replace(seen, phase="inactive", since=None, notified=False), "resolved"
        return replace(seen, phase="inactive", since=None), None
    if state.phase == "firing":
        return seen, None
    started = state.since if state.phase == "pending" and state.since is not None else at
    if at - started >= timedelta(seconds=definition.for_seconds):
        return replace(seen, phase="firing", since=at), "fired"
    return replace(seen, phase="pending", since=started), None


def _release_notification(
    definition: AlertRuleDefinition, state: RuleState, at: datetime, suppressed: bool
) -> tuple[RuleState, bool, BlockedBy | None]:
    if state.phase != "firing" or state.notified:
        return state, False, None
    if suppressed:
        return state, False, "maintenance"
    last = state.last_notified_at
    if last is not None and at - last < timedelta(seconds=definition.cooldown_seconds):
        return state, False, "cooldown"
    return replace(state, notified=True, last_notified_at=at), True, None


def evaluate_definition(
    definition: AlertRuleDefinition,
    *,
    rule_id: str,
    observation: Observation,
    state: RuleState,
    windows: Sequence[WindowLike],
    clock: Clock,
) -> tuple[Decision, RuleState]:
    """Judge one observation; ignores rule status (dry-runs evaluate drafts)."""
    ignored = _screen(definition, observation, state, clock)
    if ignored is not None:
        return _decision(definition, rule_id, observation, ignored, state), state
    effect = effect_of_windows(windows, observation.scopes, observation.at)
    if effect.kind == "disable":
        decision = _decision(
            definition, rule_id, observation, "maintenance-disabled", state, windows=effect.indexes
        )
        return decision, state
    held, reason = _judge(definition, observation)
    if reason == "invalid-config":
        return _decision(definition, rule_id, observation, reason, state), state
    after, transition = _next_state(definition, state, held, observation.at)
    notify, blocked_by = False, None
    if held:
        after, notify, blocked_by = _release_notification(
            definition, after, observation.at, effect.kind == "suppress"
        )
        outcome: Outcome = "firing" if after.phase == "firing" else "pending"
    else:
        outcome = reason
    decision = _decision(
        definition,
        rule_id,
        observation,
        outcome,
        after,
        notify=notify,
        transition=transition,
        blocked_by=blocked_by,
        windows=effect.indexes,
    )
    return decision, after


def evaluate_rule(
    rule: AlertRule,
    *,
    observation: Observation,
    state: RuleState,
    windows: Sequence[WindowLike],
    clock: Clock,
) -> tuple[Decision, RuleState]:
    """As ``evaluate_definition`` but only an active (approved) rule ever evaluates."""
    definition = definition_of(rule)
    if rule.status != "active":
        return _decision(definition, rule.id, observation, "rule-not-active", state), state
    return evaluate_definition(
        definition,
        rule_id=rule.id,
        observation=observation,
        state=state,
        windows=windows,
        clock=clock,
    )


_DEFINITION_FIELDS: Final = set(AlertRuleDefinition.model_fields)


def definition_of(rule: AlertRule) -> AlertRuleDefinition:
    """The operator-editable part of a stored rule, re-validated against the contract."""
    return AlertRuleDefinition.model_validate(rule.model_dump(include=_DEFINITION_FIELDS))
