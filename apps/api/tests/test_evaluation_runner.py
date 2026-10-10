"""The evaluation runner (S6 step 2): approved rules only, truthful sources, bounded work,
maintenance for availability only, deduplicated incidents, notifications through the dispatcher.

Everything runs against in-memory stores, a scripted source and an injected clock: no wall clock,
no network, no sleeping.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from evaluation_support import DEVICE_A, DEVICE_B, T0, ScriptedSource, Stack

from netsight_api.evaluation.incidents import SERVICE_ACTOR_ID, AlertIncidentService
from netsight_api.evaluation.notify import AlertNotifier
from netsight_api.evaluation.runner import CycleReport, EvaluationRunner, RunnerLimits
from netsight_api.evaluation.source import ObservationBatch
from netsight_api.notifications.dispatcher import (
    InMemoryDeliveryRecorder,
    NotificationDispatcher,
    RetryPolicy,
    RoutingRule,
)
from netsight_api.notifications.models import EmailDestination
from netsight_api.notifications.senders import FakeSender

BASE = "https://netsight.example.com"
EMAIL = EmailDestination("ops@example.com")


class Rig:
    def __init__(
        self,
        *,
        metrics: tuple[str, ...] = ("device.status",),
        limits: RunnerLimits | None = None,
        incidents: bool = True,
        notifier: bool = True,
        monotonic: Callable[[], float] | None = None,
        lease: Callable[[], bool] | None = None,
    ) -> None:
        self.stack = Stack.build()
        self.source = ScriptedSource(metrics)
        self.sender = FakeSender("email")
        self.recorder = InMemoryDeliveryRecorder()
        dispatcher = NotificationDispatcher(
            {"email": self.sender},
            self.recorder,
            clock=self.stack.clock,
            sleep=lambda seconds: None,
            policy=RetryPolicy(max_attempts=1),
            public_base_url=BASE,
        )
        self.runner = EvaluationRunner(
            rules=self.stack.rules,
            source=self.source,
            incidents=AlertIncidentService(self.stack.incidents, self.stack.links)
            if incidents
            else None,
            notifier=AlertNotifier(
                dispatcher, (RoutingRule("high", (EMAIL,)),), self.recorder, public_base_url=BASE
            )
            if notifier
            else None,
            clock=self.stack.clock,
            limits=limits or RunnerLimits(),
            **({"monotonic": monotonic} if monotonic is not None else {}),
            **({"lease": lease} if lease is not None else {}),
        )

    async def cycle(self, *, advance: float = 0) -> CycleReport:
        if advance:
            self.stack.clock.advance(seconds=advance)
        return await self.runner.run_cycle()

    @property
    def incidents(self) -> list[Any]:
        return self.stack.incidents.list_incidents(limit=100)


def down(rig: Rig, *entities: str) -> None:
    rig.source.set("device.status", *[(entity, 0.0) for entity in entities])


def up(rig: Rig, *entities: str) -> None:
    rig.source.set("device.status", *[(entity, 1.0) for entity in entities])


# --- which rules evaluate ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_only_approved_rules_evaluate() -> None:
    rig = Rig()
    rig.stack.draft_rule()
    disabled = rig.stack.active_rule(name="to disable")
    rig.stack.rules.disable_rule(disabled.id, actor_id="seed:admin")
    down(rig, DEVICE_A)
    report = await rig.cycle()
    assert report.rules_loaded == 0 and report.evaluations == 0
    assert rig.source.calls == [] and rig.incidents == [] and rig.sender.calls == []


@pytest.mark.asyncio
async def test_an_approved_rule_creates_an_incident_and_sends_one_notification() -> None:
    rig = Rig()
    rig.stack.active_rule()
    down(rig, DEVICE_A)
    report = await rig.cycle()
    assert (report.rules_evaluated, report.fired) == (1, 1)
    assert (report.incidents_created, report.notifications_sent) == (1, 1)
    (incident,) = rig.incidents
    assert incident.state == "open"
    (event,) = rig.stack.incidents.list_timeline(incident.id)
    assert (event.kind, event.actor_id) == ("alert-linked", SERVICE_ACTOR_ID)
    ((_, payload),) = rig.sender.calls
    assert payload.incident_id == incident.id and payload.link.endswith(incident.id)


@pytest.mark.asyncio
async def test_the_source_is_read_with_the_runner_clock_once_per_metric() -> None:
    rig = Rig(metrics=("device.status", "device.alert_count"))
    rig.stack.active_rule()
    rig.stack.active_rule(
        name="second",
        condition={"metric": "device.status", "operator": "eq", "threshold": 0, "pattern": None},
    )
    rig.stack.active_rule(
        name="alerts",
        condition={"metric": "device.alert_count", "operator": "gt", "threshold": 0, "pattern": None},
    )
    await rig.cycle()
    assert sorted(m for m, _ in rig.source.calls) == ["device.alert_count", "device.status"]
    assert {at for _, at in rig.source.calls} == {T0}


# --- truthfulness -----------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_source_that_is_not_connected_produces_no_alert_and_no_fabrication() -> None:
    rig = Rig()
    rig.stack.active_rule()
    report = await rig.cycle()  # the scripted source has no batch: not-connected
    assert (report.rules_not_connected, report.rules_unknown) == (1, 0)
    assert report.evaluations == 0 and rig.incidents == [] and rig.sender.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [RuntimeError("boom postgresql://u:p@h/x"), ObservationBatch("unknown", detail="SOURCE_FAILED")],
)
async def test_a_failing_source_is_unknown_and_never_an_alert_or_a_recovery(
    failure: Exception | ObservationBatch,
) -> None:
    rig = Rig()
    rig.stack.active_rule()
    down(rig, DEVICE_A)
    await rig.cycle()
    rig.source.batches["device.status"] = failure
    report = await rig.cycle(advance=60)
    assert (report.rules_unknown, report.evaluations, report.resolved) == (1, 0, 0)
    assert len(rig.incidents) == 1  # the open alert stays: a gap is not a recovery
    assert len(rig.sender.calls) == 1


@pytest.mark.asyncio
async def test_a_data_gap_restarts_the_debounce() -> None:
    rig = Rig()
    rig.stack.active_rule(for_seconds=120)
    down(rig, DEVICE_A)
    assert (await rig.cycle()).fired == 0  # pending since t0
    rig.source.batches["device.status"] = ObservationBatch("unknown")
    await rig.cycle(advance=60)  # gap: the pending alert is forgotten
    down(rig, DEVICE_A)
    assert (await rig.cycle(advance=60)).fired == 0  # pending again (not firing at t0+120)
    assert (await rig.cycle(advance=60)).fired == 0
    assert (await rig.cycle(advance=60)).fired == 1  # 120 s of unbroken evidence
    assert len(rig.incidents) == 1


@pytest.mark.asyncio
async def test_a_reading_the_source_cannot_state_is_no_data_not_down() -> None:
    rig = Rig()
    rig.stack.active_rule()
    rig.source.set("device.status", (DEVICE_A, None))
    report = await rig.cycle()
    assert report.fired == 0 and rig.incidents == []


@pytest.mark.asyncio
async def test_an_unsupported_metric_is_reported_and_never_read() -> None:
    rig = Rig()
    rig.stack.active_rule(
        condition={"metric": "traffic.upload_bytes", "operator": "gt", "threshold": 1, "pattern": None}
    )
    report = await rig.cycle()
    assert report.rules_unsupported == 1 and rig.source.calls == []


# --- debounce, dedup, recovery ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_for_seconds_is_measured_over_consecutive_cycles() -> None:
    rig = Rig()
    rig.stack.active_rule(for_seconds=120)
    down(rig, DEVICE_A)
    assert (await rig.cycle()).fired == 0
    assert (await rig.cycle(advance=60)).fired == 0
    assert rig.incidents == []
    assert (await rig.cycle(advance=60)).fired == 1
    assert len(rig.incidents) == 1


@pytest.mark.asyncio
async def test_many_cycles_of_a_firing_alert_keep_one_incident_and_one_notification() -> None:
    rig = Rig()
    rig.stack.active_rule()
    down(rig, DEVICE_A)
    for index in range(6):
        await rig.cycle(advance=60 if index else 0)
    assert len(rig.incidents) == 1 and len(rig.sender.calls) == 1
    assert len(rig.stack.incidents.list_timeline(rig.incidents[0].id)) == 1


@pytest.mark.asyncio
async def test_two_devices_get_two_incidents_under_policy_create_and_one_under_group() -> None:
    create = Rig()
    create.stack.active_rule()
    down(create, DEVICE_A, DEVICE_B)
    await create.cycle()
    assert len(create.incidents) == 2

    group = Rig()
    group.stack.active_rule(incident_policy="group")
    down(group, DEVICE_A, DEVICE_B)
    report = await group.cycle()
    assert (report.incidents_created, report.incidents_attached) == (1, 1)
    assert len(group.incidents) == 1


@pytest.mark.asyncio
async def test_a_restart_does_not_duplicate_the_incident() -> None:
    rig = Rig()
    rule = rig.stack.active_rule()
    down(rig, DEVICE_A)
    await rig.cycle()
    # a fresh runner has no state in memory, only the durable links
    fresh = Rig()
    fresh.stack = rig.stack
    fresh.runner = EvaluationRunner(
        rules=rig.stack.rules,
        source=rig.source,
        incidents=AlertIncidentService(rig.stack.incidents, rig.stack.links),
        notifier=None,
        clock=rig.stack.clock,
    )
    report = await fresh.cycle(advance=60)
    assert report.fired == 1 and report.incidents_created == 0
    assert len(rig.incidents) == 1 and rule.id


@pytest.mark.asyncio
async def test_recovery_keeps_the_incident_open_and_resets_the_alert() -> None:
    rig = Rig()
    rig.stack.active_rule()
    down(rig, DEVICE_A)
    await rig.cycle()
    up(rig, DEVICE_A)
    report = await rig.cycle(advance=60)
    assert report.resolved == 1
    (incident,) = rig.incidents
    assert incident.state == "open" and incident.resolution is None  # resolve is human-only
    down(rig, DEVICE_A)
    again = await rig.cycle(advance=60)
    assert again.fired == 1 and again.incidents_created == 0  # the open incident still carries it
    assert len(rig.incidents) == 1


# --- maintenance (availability only) ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_retain_window_defers_an_availability_alert_until_it_ends() -> None:
    rig = Rig()
    rig.stack.active_rule()
    rig.stack.window(evaluation="retain")  # active now, 2 hours long
    down(rig, DEVICE_A)
    report = await rig.cycle()
    assert report.fired == 1
    assert (report.incidents_created, report.notifications_sent) == (0, 0)
    assert rig.incidents == [] and rig.sender.calls == []
    after = await rig.cycle(advance=3 * 3600)  # the window is over, the device is still down
    assert (after.incidents_created, after.notifications_sent) == (1, 1)


@pytest.mark.asyncio
async def test_a_site_or_device_window_only_covers_what_it_names() -> None:
    rig = Rig()
    rig.stack.active_rule()
    rig.stack.window(scope=("device", DEVICE_A))
    down(rig, DEVICE_A, DEVICE_B)
    report = await rig.cycle()
    assert report.incidents_created == 1
    assert rig.incidents[0].title.endswith(DEVICE_B)


@pytest.mark.asyncio
async def test_a_disable_window_stops_availability_evaluation_without_touching_state() -> None:
    rig = Rig()
    rig.stack.active_rule()
    rig.stack.window(evaluation="disable")
    down(rig, DEVICE_A)
    report = await rig.cycle()
    assert report.fired == 0 and rig.incidents == [] and rig.sender.calls == []


@pytest.mark.asyncio
async def test_maintenance_never_silences_non_availability_alerts() -> None:
    rig = Rig(metrics=("device.status", "device.alert_count"))
    rig.stack.active_rule(
        name="Too many alerts",
        condition={"metric": "device.alert_count", "operator": "gt", "threshold": 0, "pattern": None},
    )
    rig.stack.window(evaluation="disable")
    rig.stack.window(evaluation="retain", name="also")
    rig.source.set("device.alert_count", (DEVICE_A, 3.0))
    report = await rig.cycle()
    assert (report.incidents_created, report.notifications_sent) == (1, 1)


@pytest.mark.asyncio
async def test_an_expired_or_cancelled_window_no_longer_suppresses() -> None:
    rig = Rig()
    rig.stack.active_rule()
    cancelled = rig.stack.window()
    rig.stack.rules.cancel_window(cancelled.id, actor_id="seed:admin", organisation_allowed=True)
    rig.stack.window(starts_at=T0 - timedelta(hours=5))  # ended three hours ago
    down(rig, DEVICE_A)
    assert (await rig.cycle()).incidents_created == 1


# --- degraded wiring --------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_without_an_incident_service_the_alert_still_notifies() -> None:
    rig = Rig(incidents=False)
    rig.stack.active_rule()
    down(rig, DEVICE_A)
    report = await rig.cycle()
    assert (report.incidents_created, report.notifications_sent) == (0, 1)


@pytest.mark.asyncio
async def test_an_incident_failure_is_counted_and_the_page_still_goes_out() -> None:
    rig = Rig()
    rig.stack.active_rule()

    class Broken(AlertIncidentService):
        def ensure(self, **_kw: Any) -> Any:
            raise RuntimeError("store down postgresql://u:p@h/x")

    rig.runner._incidents = Broken(rig.stack.incidents, rig.stack.links)
    down(rig, DEVICE_A, DEVICE_B)
    report = await rig.cycle()
    assert report.incident_failures == 2 and report.notifications_sent == 2
    assert rig.incidents == []


@pytest.mark.asyncio
async def test_a_store_failure_loading_rules_evaluates_nothing_and_does_not_raise() -> None:
    rig = Rig()
    rig.stack.active_rule()
    down(rig, DEVICE_A)

    def fail(**_kw: Any) -> Any:
        raise RuntimeError("db down")

    rig.stack.rules.list_rules = fail  # type: ignore[method-assign]
    report = await rig.cycle()
    assert report.store_error is True and report.evaluations == 0
    assert rig.source.calls == [] and rig.incidents == []


@pytest.mark.asyncio
async def test_one_failing_metric_does_not_stop_the_others() -> None:
    rig = Rig(metrics=("device.status", "device.alert_count"))
    rig.stack.active_rule()
    rig.stack.active_rule(
        name="alerts",
        condition={"metric": "device.alert_count", "operator": "gt", "threshold": 0, "pattern": None},
    )
    rig.source.batches["device.alert_count"] = RuntimeError("boom")
    down(rig, DEVICE_A)
    report = await rig.cycle()
    assert (report.rules_unknown, report.rules_evaluated, report.incidents_created) == (1, 1, 1)


# --- bounds -----------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_source_reads_run_with_bounded_concurrency() -> None:
    metrics = tuple(f"device.m{index}" for index in range(10))
    rig = Rig(metrics=metrics, limits=RunnerLimits(max_concurrency=3))
    for metric in metrics:
        rig.stack.active_rule(
            name=metric,
            condition={"metric": metric, "operator": "lt", "threshold": 1, "pattern": None},
        )
        rig.source.set(metric, (DEVICE_A, 1.0))
    await rig.cycle()
    assert len(rig.source.calls) == 10
    assert 1 < rig.source.peak_in_flight <= 3


@pytest.mark.asyncio
async def test_a_hanging_source_times_out_as_unknown() -> None:
    rig = Rig(limits=RunnerLimits(source_timeout_seconds=0.05))
    rig.stack.active_rule()

    async def hang(metric: str, *, now: Any) -> ObservationBatch:
        await asyncio.sleep(3600)
        return ObservationBatch("unknown")

    rig.source.observe = hang  # type: ignore[method-assign]
    report = await asyncio.wait_for(rig.cycle(), timeout=10)
    assert report.rules_unknown == 1 and report.evaluations == 0


@pytest.mark.asyncio
async def test_rule_and_evaluation_caps_truncate_and_say_so() -> None:
    rig = Rig(limits=RunnerLimits(max_rules=2, max_evaluations=3))
    for index in range(4):
        rig.stack.active_rule(name=f"rule {index}")
    down(rig, DEVICE_A, DEVICE_B)
    report = await rig.cycle()
    assert report.rules_loaded == 2 and report.truncated is True
    assert report.evaluations <= 3


@pytest.mark.asyncio
async def test_incident_and_notification_actions_per_cycle_are_capped() -> None:
    rig = Rig(limits=RunnerLimits(max_incident_actions=2, max_notifications=1))
    rig.stack.active_rule()
    entities = [f"device-00000000-0000-4000-8000-{index:012d}" for index in range(5)]
    down(rig, *entities)
    first = await rig.cycle()
    assert first.incidents_created == 2 and first.notifications_sent == 1 and first.truncated
    second = await rig.cycle(advance=60)  # deferred work is picked up, never lost
    assert second.incidents_created == 2 and second.notifications_sent == 1


@pytest.mark.asyncio
async def test_state_is_dropped_for_rules_that_are_no_longer_active_and_bounded() -> None:
    rig = Rig(limits=RunnerLimits(max_state_entries=2))
    rule = rig.stack.active_rule(for_seconds=3600)
    entities = [f"device-00000000-0000-4000-8000-{index:012d}" for index in range(5)]
    down(rig, *entities)
    report = await rig.cycle()
    assert report.state_entries <= 2 and report.truncated is True
    rig.stack.rules.disable_rule(rule.id, actor_id="seed:admin")
    assert (await rig.cycle(advance=60)).state_entries == 0


@pytest.mark.asyncio
async def test_overlapping_cycles_do_not_run_twice() -> None:
    rig = Rig()
    rig.stack.active_rule()
    down(rig, DEVICE_A)
    first, second = await asyncio.gather(rig.cycle(), rig.cycle())
    assert sorted([first.overlapped, second.overlapped]) == [False, True]
    assert len(rig.incidents) == 1


def test_runner_limits_are_validated() -> None:
    for bad in (
        {"max_concurrency": 0},
        {"max_concurrency": 17},
        {"max_rules": 0},
        {"max_rules": 2001},
        {"source_timeout_seconds": 0},
        {"source_timeout_seconds": 121},
        {"max_state_entries": 0},
        {"max_evaluations": 0},
    ):
        with pytest.raises(ValueError):
            RunnerLimits(**bad)


# --- containment ------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_crashing_notifier_is_contained_and_the_incident_stands() -> None:
    rig = Rig()
    rig.stack.active_rule()

    class Crashing:
        def notify(self, **_kw: Any) -> Any:
            raise RuntimeError("relay exploded")

    rig.runner._notifier = Crashing()  # type: ignore[assignment]
    down(rig, DEVICE_A)
    report = await rig.cycle()
    assert (report.incidents_created, report.notifications_failed) == (1, 1)


@pytest.mark.asyncio
async def test_an_engine_error_on_one_reading_does_not_stop_the_rest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from netsight_api.evaluation import runner as runner_module

    real = runner_module.evaluate_definition
    calls = {"n": 0}

    def flaky(*args: Any, **kwargs: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("bad reading")
        return real(*args, **kwargs)

    monkeypatch.setattr(runner_module, "evaluate_definition", flaky)
    rig = Rig()
    rig.stack.active_rule()
    down(rig, DEVICE_A, DEVICE_B)
    report = await rig.cycle()
    assert (report.evaluation_errors, report.evaluations, report.incidents_created) == (1, 1, 1)


@pytest.mark.asyncio
async def test_a_rule_that_is_not_active_is_never_evaluated_even_if_the_store_lists_it() -> None:
    rig = Rig()
    draft = rig.stack.draft_rule()
    rig.stack.rules.list_rules = lambda **_kw: [draft]  # type: ignore[method-assign]
    down(rig, DEVICE_A)
    report = await rig.cycle()
    assert (report.rules_invalid, report.evaluations) == (1, 0)
    assert rig.incidents == [] and rig.sender.calls == []


@pytest.mark.asyncio
async def test_a_corrupt_stored_rule_fails_closed() -> None:
    rig = Rig()
    good = rig.stack.active_rule()
    corrupt = good.model_copy(update={"window_seconds": 1})  # violates the contract bounds
    rig.stack.rules.list_rules = lambda **_kw: [corrupt]  # type: ignore[method-assign]
    down(rig, DEVICE_A)
    report = await rig.cycle()
    assert (report.rules_invalid, report.evaluations) == (1, 0)
    assert rig.incidents == []


@pytest.mark.asyncio
async def test_the_notification_backlog_is_bounded() -> None:
    from netsight_api.evaluation.runner import MAX_NOTIFICATION_BACKLOG

    rig = Rig(limits=RunnerLimits(max_notifications=1))
    rig.stack.active_rule(incident_policy="none")
    count = MAX_NOTIFICATION_BACKLOG + 20
    entities = [f"device-00000000-0000-4000-8000-{index:012d}" for index in range(count)]
    down(rig, *entities)
    report = await rig.cycle()
    assert report.notifications_backlog == MAX_NOTIFICATION_BACKLOG
    assert report.notifications_sent == 1
    assert report.notifications_failed == count - 1 - MAX_NOTIFICATION_BACKLOG
