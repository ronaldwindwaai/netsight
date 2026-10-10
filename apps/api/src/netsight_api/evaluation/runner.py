"""The evaluation runner: observations in, deduplicated incidents and notifications out.

One ``run_cycle`` is a bounded unit of work; scheduling it is somebody else's job
(``wiring.run_scheduler``), so nothing here loops. Per cycle:

1. load the *approved* (``active``) rules and the maintenance windows active now from the rule
   store (a store failure evaluates nothing and is reported, never guessed around);
2. read each distinct metric once through the :class:`ObservationSource`, with bounded
   concurrency and a per-read timeout; a failure or timeout is ``unknown``, an unconfigured
   source is ``not-connected``: both mean the rule is not evaluated and a data gap is recorded
   (a pending debounce restarts, a firing alert is kept), never a fabricated reading;
3. run the pure engine (``evaluate_rule``) on every observation, with the cycle's clock. Only
   availability metrics see maintenance windows (``is_availability_metric``): planned work
   explains a device being down, not a policy violation;
4. for each firing alert that is not held back by maintenance, ensure one deduplicated incident
   (``AlertIncidentService``); for each released notification, route and send it
   (``AlertNotifier``). Work beyond the per-cycle caps or the notification deadline is deferred
   (incidents are re-derived next cycle; notifications wait in a bounded backlog, most severe
   first); an overflow is counted and audited (``BACKLOG_FULL``), never dropped silently.

The evaluation budget (``max_evaluations``) is shared fairly between rules, and the entities of a
rule are visited round-robin across cycles, so a rule with more observations than its share is
still evaluated completely over a few cycles. Running out of budget is *not* a data gap: the
entities that were not reached keep their pending/firing state untouched.

CPU- and I/O-bound steps run in worker threads so the event loop is never blocked. The cycle
lock makes overlapping calls return immediately instead of queueing.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final

from netsight_api.alerting.engine import (
    Decision,
    Observation,
    definition_of,
    evaluate_definition,
)
from netsight_api.audit import record_audit
from netsight_api.evaluation.incidents import SERVICE_ACTOR_ID, AlertIncidentService
from netsight_api.evaluation.notify import AlertNotifier
from netsight_api.evaluation.rulestate import DEFAULT_MAX_ENTRIES, RuleStateStore, StateKey
from netsight_api.evaluation.source import (
    ObservationBatch,
    ObservationSource,
    is_availability_metric,
)
from netsight_api.schemas import AlertRule, AlertRuleDefinition, MaintenanceWindow
from netsight_api.storage import AlertRuleRepository

_LOGGER: Final = logging.getLogger("netsight_api.evaluation")
_PAGE: Final = 100
_MAX_WINDOW_PAGES: Final = 5  # MAX_LIVE_WINDOWS (500) / _PAGE
MAX_NOTIFICATION_BACKLOG: Final = 1000
_SEVERITY_RANK: Final = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
Clock = Callable[[], datetime]


@dataclass(frozen=True)
class RunnerLimits:
    max_concurrency: int = 4
    max_rules: int = 500
    max_evaluations: int = 200_000
    max_state_entries: int = DEFAULT_MAX_ENTRIES
    max_incident_actions: int = 100
    max_notifications: int = 50
    max_backlog: int = MAX_NOTIFICATION_BACKLOG
    notification_deadline_seconds: float = 60.0
    source_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        checks = (
            (1 <= self.max_concurrency <= 16, "max_concurrency must be between 1 and 16"),
            (1 <= self.max_rules <= 2000, "max_rules must be between 1 and 2000"),
            (1 <= self.max_evaluations <= 1_000_000, "max_evaluations must be 1 to 1000000"),
            (1 <= self.max_state_entries <= 1_000_000, "max_state_entries must be 1 to 1000000"),
            (1 <= self.max_incident_actions <= 1000, "max_incident_actions must be 1 to 1000"),
            (1 <= self.max_notifications <= 1000, "max_notifications must be 1 to 1000"),
            (1 <= self.max_backlog <= 10_000, "max_backlog must be between 1 and 10000"),
            (
                0 < self.notification_deadline_seconds <= 600,
                "notification_deadline_seconds must be up to 600",
            ),
            (0 < self.source_timeout_seconds <= 120, "source_timeout_seconds must be up to 120"),
        )
        for ok, message in checks:
            if not ok:
                raise ValueError(message)


@dataclass(frozen=True)
class CycleReport:
    """Counts only: no entity names, rule text or payloads (it is logged)."""

    at: datetime
    correlation_id: str
    rules_loaded: int = 0
    rules_evaluated: int = 0
    rules_not_connected: int = 0
    rules_unknown: int = 0
    rules_unsupported: int = 0
    rules_invalid: int = 0
    evaluations: int = 0
    evaluation_errors: int = 0
    fired: int = 0
    resolved: int = 0
    incidents_created: int = 0
    incidents_attached: int = 0
    incident_failures: int = 0
    notifications_sent: int = 0
    notifications_failed: int = 0
    notifications_skipped: int = 0
    notifications_backlog: int = 0
    state_entries: int = 0
    store_error: bool = False
    truncated: bool = False
    overlapped: bool = False
    lease_lost: bool = False


@dataclass
class _Tally:
    counts: dict[str, int] = field(default_factory=dict)
    truncated: bool = False

    def add(self, name: str, amount: int = 1) -> None:
        self.counts[name] = self.counts.get(name, 0) + amount


@dataclass(frozen=True)
class _Effect:
    key: StateKey
    rule: AlertRule
    decision: Decision
    entity: str
    wants_incident: bool
    recovered: bool = False


class EvaluationRunner:
    def __init__(
        self,
        *,
        rules: AlertRuleRepository,
        source: ObservationSource,
        incidents: AlertIncidentService | None,
        notifier: AlertNotifier | None,
        clock: Clock,
        limits: RunnerLimits | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        lease: Callable[[], bool] | None = None,
    ) -> None:
        self._rules = rules
        self._source = source
        self._incidents = incidents
        self._notifier = notifier
        self._clock = clock
        self._limits = limits or RunnerLimits()
        self._states = RuleStateStore(self._limits.max_state_entries)
        self._linked: dict[StateKey, str] = {}
        self._backlog: deque[_Effect] = deque()
        self._recoveries: dict[StateKey, _Effect] = {}
        self._cursor: dict[tuple[str, int], int] = {}
        self._monotonic = monotonic
        self._lease = lease
        self._lock = asyncio.Lock()

    def reset_state(self) -> None:
        """Forget everything held in memory (called when evaluation leadership is lost)."""
        self._states = RuleStateStore(self._limits.max_state_entries)
        self._linked = {}
        self._backlog.clear()
        self._recoveries = {}
        self._cursor = {}

    async def run_cycle(self) -> CycleReport:
        now = self._clock()
        correlation_id = f"eval-{uuid.uuid4().hex[:12]}"
        if self._lock.locked():
            return CycleReport(at=now, correlation_id=correlation_id, overlapped=True)
        async with self._lock:
            report = await self._run(now, correlation_id)
        _LOGGER.info(
            "evaluation cycle %s: %d rules, %d evaluations, %d fired, %d incidents created, "
            "%d notifications sent",
            report.correlation_id,
            report.rules_loaded,
            report.evaluations,
            report.fired,
            report.incidents_created,
            report.notifications_sent,
        )
        return report

    # -- the cycle ---------------------------------------------------------------------------

    async def _run(self, now: datetime, correlation_id: str) -> CycleReport:
        tally = _Tally()
        try:
            rules, windows = await asyncio.to_thread(self._load, now, tally)
        except Exception as error:  # noqa: BLE001 - nothing can be judged without the rules
            _LOGGER.warning("rule store unreadable", extra={"error_type": type(error).__name__})
            return CycleReport(at=now, correlation_id=correlation_id, store_error=True)
        self._states.retain_rules({(rule.id, rule.version) for rule in rules})
        live = self._live(rules)
        self._linked = {k: v for k, v in self._linked.items() if (k[0], k[1]) in live}
        self._cursor = {k: v for k, v in self._cursor.items() if k in live}
        self._recoveries = {k: v for k, v in self._recoveries.items() if (k[0], k[1]) in live}
        batches = await self._collect(rules, now)
        effects = await asyncio.to_thread(self._evaluate, rules, windows, batches, now, tally)
        if not await asyncio.to_thread(self._still_leader):
            self.reset_state()  # whoever leads now owns these alerts; stale state must not leak
            return CycleReport(
                at=now, correlation_id=correlation_id, rules_loaded=len(rules), lease_lost=True
            )
        await asyncio.to_thread(self._apply, effects, correlation_id, tally)
        counts: dict[str, Any] = {
            **tally.counts,
            "rules_loaded": len(rules),
            "state_entries": len(self._states),
            "truncated": tally.truncated,
            "notifications_backlog": len(self._backlog),
        }
        return CycleReport(at=now, correlation_id=correlation_id, **counts)

    def _still_leader(self) -> bool:
        if self._lease is None:
            return True
        try:
            return bool(self._lease())
        except Exception as error:  # noqa: BLE001 - an unverifiable lease is a lost lease
            _LOGGER.warning("lease check failed", extra={"error_type": type(error).__name__})
            return False

    @staticmethod
    def _live(rules: Sequence[AlertRule]) -> set[tuple[str, int]]:
        return {(rule.id, rule.version) for rule in rules}

    def _load(
        self, now: datetime, tally: _Tally
    ) -> tuple[list[AlertRule], list[MaintenanceWindow]]:
        rules: list[AlertRule] = []
        offset = 0
        while len(rules) < self._limits.max_rules:
            page = self._rules.list_rules(status="active", limit=_PAGE, offset=offset)
            rules.extend(page)
            if len(page) < _PAGE:
                break
            offset += _PAGE
        limit = self._limits.max_rules
        more = len(rules) == limit and bool(
            self._rules.list_rules(status="active", limit=1, offset=len(rules))
        )
        tally.truncated = tally.truncated or len(rules) > limit or more
        rules = rules[:limit]
        windows: list[MaintenanceWindow] = []
        for page_number in range(_MAX_WINDOW_PAGES):
            page_of_windows = self._rules.list_windows(
                active_at=now, limit=_PAGE, offset=page_number * _PAGE
            )
            windows.extend(page_of_windows)
            if len(page_of_windows) < _PAGE:
                break
        else:  # every page was full: is there a window beyond the pages read?
            more_windows = self._rules.list_windows(
                active_at=now, limit=1, offset=_MAX_WINDOW_PAGES * _PAGE
            )
            tally.truncated = tally.truncated or bool(more_windows)
        return rules, windows

    async def _collect(
        self, rules: Sequence[AlertRule], now: datetime
    ) -> dict[str, ObservationBatch | None]:
        """One bounded read per supported metric; ``None`` marks an unsupported metric."""
        metrics = sorted({rule.condition.metric for rule in rules})
        gate = asyncio.Semaphore(self._limits.max_concurrency)

        async def read(metric: str) -> ObservationBatch | None:
            if not self._source.supports(metric):
                return None
            async with gate:
                try:
                    return await asyncio.wait_for(
                        self._source.observe(metric, now=now),
                        timeout=self._limits.source_timeout_seconds,
                    )
                except Exception as error:  # noqa: BLE001 - any failure is "unknown"
                    _LOGGER.warning(
                        "observation read failed",
                        extra={"metric": metric, "error_type": type(error).__name__},
                    )
                    return ObservationBatch("unknown", detail="READ_FAILED")

        results = await asyncio.gather(*(read(metric) for metric in metrics))
        return dict(zip(metrics, results, strict=True))

    def _evaluate(
        self,
        rules: Sequence[AlertRule],
        windows: Sequence[MaintenanceWindow],
        batches: dict[str, ObservationBatch | None],
        now: datetime,
        tally: _Tally,
    ) -> list[_Effect]:
        effects: list[_Effect] = []
        plan = self._plan(rules, batches, tally)
        budget = self._limits.max_evaluations
        for position, (rule, definition, batch) in enumerate(plan):
            share = -(-budget // (len(plan) - position))  # ceiling: unused budget flows on
            visible = windows if is_availability_metric(rule.condition.metric) else ()
            budget -= self._evaluate_rule(
                rule, definition, batch, visible, now, share, effects, tally
            )
        return effects

    def _plan(
        self,
        rules: Sequence[AlertRule],
        batches: dict[str, ObservationBatch | None],
        tally: _Tally,
    ) -> list[tuple[AlertRule, AlertRuleDefinition, ObservationBatch]]:
        """The rules that can be evaluated now; the others are tallied (and gaps recorded)."""
        plan: list[tuple[AlertRule, AlertRuleDefinition, ObservationBatch]] = []
        for rule in rules:
            batch = batches.get(rule.condition.metric)
            if batch is None:
                tally.add("rules_unsupported")
            elif batch.state == "not-connected":
                tally.add("rules_not_connected")
                self._states.gap(rule.id, rule.version)
            elif batch.state == "unknown":
                tally.add("rules_unknown")
                self._states.gap(rule.id, rule.version)
            else:
                try:
                    definition = definition_of(rule)
                except ValueError:  # a corrupt stored rule never evaluates (fail closed)
                    tally.add("rules_invalid")
                    continue
                if rule.status != "active":  # the store only lists active rules; stay explicit
                    tally.add("rules_invalid")
                    continue
                plan.append((rule, definition, batch))
        return plan

    def _evaluate_rule(
        self,
        rule: AlertRule,
        definition: AlertRuleDefinition,
        batch: ObservationBatch,
        windows: Sequence[MaintenanceWindow],
        now: datetime,
        share: int,
        effects: list[_Effect],
        tally: _Tally,
    ) -> int:
        """Evaluate up to ``share`` observations, round-robin; returns how many were used."""
        tally.add("rules_evaluated")
        observations = batch.observations
        total = len(observations)
        cursor_key = (rule.id, rule.version)
        start = self._cursor.get(cursor_key, 0) % total if total else 0
        visit = (observations[start:] + observations[:start])[:share]
        for observation in visit:
            effect = self._evaluate_one(rule, definition, observation, windows, now, tally)
            if effect is not None:
                effects.append(effect)
        if len(visit) < total:
            tally.truncated = True
            self._cursor[cursor_key] = (start + len(visit)) % total
        else:
            self._cursor.pop(cursor_key, None)
        # Entities present in the data but not reached are not a gap: only the absent ones are.
        self._states.gap(rule.id, rule.version, seen={o.entity for o in observations})
        return len(visit)

    def _evaluate_one(
        self,
        rule: AlertRule,
        definition: AlertRuleDefinition,
        observation: Observation,
        windows: Sequence[MaintenanceWindow],
        now: datetime,
        tally: _Tally,
    ) -> _Effect | None:
        key: StateKey = (rule.id, rule.version, observation.entity)
        try:
            decision, state = evaluate_definition(
                definition,
                rule_id=rule.id,
                observation=observation,
                state=self._states.get(key),
                windows=windows,
                clock=lambda: now,
            )
        except Exception as error:  # noqa: BLE001 - one bad reading must not stop the cycle
            _LOGGER.warning("evaluation failed", extra={"error_type": type(error).__name__})
            tally.add("evaluation_errors")
            return None
        tally.add("evaluations")
        if not self._states.put(key, state):
            tally.truncated = True
        if decision.transition == "fired":
            tally.add("fired")
        elif decision.transition == "resolved":
            tally.add("resolved")
            self._linked.pop(key, None)
        firing = decision.outcome == "firing" and decision.blocked_by != "maintenance"
        wants_incident = firing and rule.incident_policy != "none" and key not in self._linked
        recovered = decision.transition == "resolved" and rule.incident_policy != "none"
        if wants_incident or decision.notify or recovered:
            return _Effect(key, rule, decision, observation.entity, wants_incident, recovered)
        return None

    # -- effects ------------------------------------------------------------------------------

    def _apply(self, effects: list[_Effect], correlation_id: str, tally: _Tally) -> None:
        for effect in effects:
            if effect.recovered:
                self._recoveries[effect.key] = effect
        self._record_recoveries(tally)
        due: list[_Effect] = list(self._backlog)  # deferred earlier, so first in line
        self._backlog.clear()
        incident_budget = self._limits.max_incident_actions
        for effect in _most_severe_first(effects):
            if effect.wants_incident and self._incidents is not None:
                if incident_budget <= 0:
                    tally.truncated = True
                else:
                    incident_budget -= 1
                    self._ensure_incident(effect, correlation_id, tally)
            if effect.decision.notify:
                due.append(effect)
        self._notify_all(_most_severe_first(due), correlation_id, tally)

    def _record_recoveries(self, tally: _Tally) -> None:
        """Make each recovery durable (a failed write is retried next cycle)."""
        if self._incidents is None:
            self._recoveries.clear()
            return
        for key, effect in list(self._recoveries.items()):
            try:
                self._incidents.note_recovery(rule=effect.rule, decision=effect.decision)
            except Exception as error:  # noqa: BLE001 - keep it pending and carry on
                _LOGGER.warning("recovery note failed", extra={"error_type": type(error).__name__})
                tally.add("incident_failures")
            else:
                del self._recoveries[key]

    def _ensure_incident(self, effect: _Effect, correlation_id: str, tally: _Tally) -> None:
        assert self._incidents is not None
        try:
            result = self._incidents.ensure(
                rule=effect.rule,
                decision=effect.decision,
                entity=effect.entity,
                correlation_id=correlation_id,
            )
        except Exception as error:  # noqa: BLE001 - audited by the service; keep going
            _LOGGER.warning("incident step failed", extra={"error_type": type(error).__name__})
            tally.add("incident_failures")
            return
        if result.incident_id is not None:
            self._linked[effect.key] = result.incident_id
        if result.action == "created":
            tally.add("incidents_created")
        elif result.action == "attached":
            tally.add("incidents_attached")

    def _notify_all(self, due: list[_Effect], correlation_id: str, tally: _Tally) -> None:
        if self._notifier is None:
            return
        started = self._monotonic()
        deadline = self._limits.notification_deadline_seconds
        for position, effect in enumerate(due):
            out_of_time = self._monotonic() - started >= deadline
            if position >= self._limits.max_notifications or out_of_time:
                self._defer(due[position:], correlation_id, tally)
                return
            try:
                result = self._notifier.notify(
                    rule=effect.rule,
                    decision=effect.decision,
                    entity=effect.entity,
                    incident_id=self._linked.get(effect.key),
                    correlation_id=correlation_id,
                )
            except Exception as error:  # noqa: BLE001 - contained; the cycle goes on
                _LOGGER.warning("notify step failed", extra={"error_type": type(error).__name__})
                tally.add("notifications_failed")
                continue
            tally.add("notifications_sent", result.sent)
            tally.add("notifications_failed", result.failed)
            if result.skipped is not None:
                tally.add("notifications_skipped")

    def _defer(self, remaining: list[_Effect], correlation_id: str, tally: _Tally) -> None:
        """Keep what the caps or the deadline held back, most severe first and bounded; the
        overflow (the least severe) is counted as failed and audited, never silent."""
        tally.truncated = True
        for effect in remaining:
            if len(self._backlog) < self._limits.max_backlog:
                self._backlog.append(effect)
                continue
            tally.add("notifications_failed")
            record_audit(
                "notification.send",
                outcome="failure",
                actor_id=SERVICE_ACTOR_ID,
                correlation_id=correlation_id,
                rule_id=effect.rule.id,
                alert=effect.decision.fingerprint,
                code="BACKLOG_FULL",
            )


def _most_severe_first(effects: Sequence[_Effect]) -> list[_Effect]:
    return sorted(effects, key=lambda e: -_SEVERITY_RANK.get(e.rule.severity, 0))
