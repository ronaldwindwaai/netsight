"""Step 2 review follow-ups (S6): budget fairness, single evaluator, notification deadlines,
resolved-incident behaviour across restarts, narrow incident dependency and the small fixes.

In-memory stores, scripted sources and injected clocks only: no network, no real sleeping.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import threading
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from evaluation_support import DEVICE_A, DEVICE_B, T0, Stack, decision_for
from test_evaluation_incidents import RacingLinks, human_resolve
from test_evaluation_runner import EMAIL, Rig, down, up

from netsight_api.evaluation.incidents import AlertIncidentService
from netsight_api.evaluation.leader import InMemoryLeaderLock, LeaseBoard
from netsight_api.evaluation.notify import AlertNotifier
from netsight_api.evaluation.runner import EvaluationRunner, RunnerLimits
from netsight_api.evaluation.wiring import run_scheduler, stop_evaluation
from netsight_api.notifications.dispatcher import (
    InMemoryDeliveryRecorder,
    NotificationDispatcher,
    RetryPolicy,
    RoutingRule,
)
from netsight_api.notifications.models import EmailDestination, sanitize_line
from netsight_api.notifications.senders import FakeSender
from netsight_api.notifications.smtp import SmtpEmailSender, SmtpSettings
from netsight_api.storage import InMemoryAlertIncidentLinkRepository

DEVICE_C = "device-00000000-0000-4000-8000-00000000000c"
ZERO_WIDTH_SPACE = chr(0x200B)


def audit_records(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == "netsight_api.audit"]


def pending_phase(rig: Rig, rule: Any, entity: str) -> str:
    return rig.runner._states.get((rule.id, rule.version, entity)).phase


# --- H1: budget exhaustion is not a data gap ---------------------------------------------------------


@pytest.mark.asyncio
async def test_budget_exhaustion_keeps_the_pending_state_of_unreached_entities() -> None:
    rig = Rig(limits=RunnerLimits(max_evaluations=2))
    rule = rig.stack.active_rule(for_seconds=120)
    down(rig, DEVICE_A, DEVICE_B, DEVICE_C)
    first = await rig.cycle()
    assert first.truncated and first.evaluations == 2
    second = await rig.cycle(advance=60)
    assert second.truncated
    # B was not reached in the second cycle, yet its debounce (since T0) must survive
    assert pending_phase(rig, rule, DEVICE_B) == "pending"
    third = await rig.cycle(advance=60)  # T0 + 120 s of unbroken evidence for B
    assert third.fired >= 1
    assert len(rig.incidents) >= 1


@pytest.mark.asyncio
async def test_a_small_budget_still_lets_every_entity_fire_eventually() -> None:
    rig = Rig(limits=RunnerLimits(max_evaluations=1))
    rig.stack.active_rule(for_seconds=0)
    down(rig, DEVICE_A, DEVICE_B, DEVICE_C)
    fired = 0
    for _ in range(3):
        fired += (await rig.cycle(advance=60)).fired
    assert fired == 3  # the cursor moves on instead of starving the tail
    assert len(rig.incidents) == 3


@pytest.mark.asyncio
async def test_each_rule_gets_a_fair_share_of_the_evaluation_budget() -> None:
    rig = Rig(limits=RunnerLimits(max_evaluations=4))
    first = rig.stack.active_rule(name="first")
    second = rig.stack.active_rule(name="second")
    down(rig, DEVICE_A, DEVICE_B, DEVICE_C, "device-00000000-0000-4000-8000-00000000000d")
    report = await rig.cycle()
    assert report.evaluations == 4 and report.truncated

    def started(rule: Any) -> int:
        entities = (
            DEVICE_A,
            DEVICE_B,
            DEVICE_C,
            "device-00000000-0000-4000-8000-00000000000d",
        )
        return sum(pending_phase(rig, rule, e) != "inactive" for e in entities)

    assert (started(first), started(second)) == (2, 2)


@pytest.mark.asyncio
async def test_entities_that_really_vanish_from_the_data_still_restart_their_debounce() -> None:
    rig = Rig()
    rule = rig.stack.active_rule(for_seconds=120)
    down(rig, DEVICE_A, DEVICE_B)
    await rig.cycle()
    down(rig, DEVICE_A)  # B is absent from the data now
    await rig.cycle(advance=60)
    assert pending_phase(rig, rule, DEVICE_B) == "inactive"
    assert pending_phase(rig, rule, DEVICE_A) == "pending"


# --- single evaluator: leader lock -------------------------------------------------------------------


class CountingRunner:
    def __init__(self) -> None:
        self.cycles = 0
        self.resets = 0

    async def run_cycle(self) -> None:
        self.cycles += 1

    def reset_state(self) -> None:
        self.resets += 1


async def until(condition: Callable[[], bool], seconds: float = 3.0) -> None:
    async def poll() -> None:
        while not condition():
            await asyncio.sleep(0.005)

    await asyncio.wait_for(poll(), timeout=seconds)


@pytest.mark.asyncio
async def test_only_the_lock_holder_evaluates_and_the_other_takes_over_when_it_stops() -> None:
    board = LeaseBoard()
    a, b = CountingRunner(), CountingRunner()
    stop_a, stop_b = asyncio.Event(), asyncio.Event()
    task_a = asyncio.create_task(run_scheduler(a, 0.01, stop_a, lock=InMemoryLeaderLock(board)))
    await until(lambda: a.cycles >= 1)
    task_b = asyncio.create_task(run_scheduler(b, 0.01, stop_b, lock=InMemoryLeaderLock(board)))
    await asyncio.sleep(0.1)
    assert b.cycles == 0  # the second evaluator idles and retries
    stop_a.set()
    await task_a
    await until(lambda: b.cycles >= 1)  # the lock was released on stop; b took over
    stop_b.set()
    await task_b
    assert board.owner is None  # released again at shutdown


@pytest.mark.asyncio
async def test_losing_the_lock_stops_evaluation_and_drops_in_memory_state() -> None:
    board = LeaseBoard()
    runner = CountingRunner()
    stop = asyncio.Event()
    task = asyncio.create_task(run_scheduler(runner, 0.01, stop, lock=InMemoryLeaderLock(board)))
    await until(lambda: runner.cycles >= 1)
    board.seize("another-evaluator")
    await until(lambda: runner.resets >= 1)
    frozen = runner.cycles
    await asyncio.sleep(0.1)
    assert runner.cycles in (frozen, frozen + 1)  # at most the cycle already under way
    settled = runner.cycles
    await asyncio.sleep(0.1)
    assert runner.cycles == settled
    board.seize(None)  # the other evaluator goes away; the retry succeeds
    await until(lambda: runner.cycles > settled)
    stop.set()
    await task


@pytest.mark.asyncio
async def test_a_lock_backend_failure_means_not_leader_and_never_crashes_the_scheduler() -> None:
    class Broken:
        def try_acquire(self) -> bool:
            raise OSError("database down")

        def still_held(self) -> bool:
            return False

        def release(self) -> None:
            raise OSError("database down")

    runner = CountingRunner()
    stop = asyncio.Event()
    task = asyncio.create_task(run_scheduler(runner, 0.01, stop, lock=Broken()))
    await asyncio.sleep(0.1)
    stop.set()
    await task
    assert runner.cycles == 0


@pytest.mark.asyncio
async def test_a_cycle_that_lost_its_lease_applies_no_effects() -> None:
    rig = Rig(lease=lambda: False)
    rig.stack.active_rule()
    down(rig, DEVICE_A)
    report = await rig.cycle()
    assert report.lease_lost is True
    assert rig.incidents == [] and rig.sender.calls == []
    assert len(rig.runner._states) == 0  # stale engine state is not kept


# --- notification phase deadline and single-send bound -----------------------------------------------


class FakeMonotonic:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


@pytest.mark.asyncio
async def test_the_notification_phase_stops_at_its_deadline_and_defers_the_rest() -> None:
    mono = FakeMonotonic()
    rig = Rig(
        limits=RunnerLimits(max_notifications=50, notification_deadline_seconds=5),
        monotonic=mono,
    )
    original = rig.sender.send

    def slow_send(destination: Any, payload: Any) -> Any:
        mono.now += 3.0  # each send takes three seconds
        return original(destination, payload)

    rig.sender.send = slow_send  # type: ignore[method-assign]
    rig.stack.active_rule()
    down(rig, DEVICE_A, DEVICE_B, DEVICE_C, "device-00000000-0000-4000-8000-00000000000d")
    first = await rig.cycle()
    assert first.notifications_sent == 2  # 0 s and 3 s start inside the budget, 6 s does not
    assert first.notifications_backlog == 2 and first.truncated
    mono.now = 0.0
    second = await rig.cycle(advance=60)
    assert second.notifications_sent == 2 and second.notifications_backlog == 0


def test_a_single_send_that_hangs_is_bounded_overall() -> None:
    release = threading.Event()

    class Hanging:
        channel = "email"

        def send(self, destination: Any, payload: Any) -> Any:
            release.wait(10)
            raise AssertionError("unreachable in the test")

    rig = Rig()
    recorder = InMemoryDeliveryRecorder()
    dispatcher = NotificationDispatcher(
        {"email": Hanging()},  # type: ignore[dict-item]
        recorder,
        clock=rig.stack.clock,
        sleep=lambda seconds: None,
        policy=RetryPolicy(max_attempts=3),
        public_base_url="https://netsight.example.com",
        send_timeout_seconds=0.05,
    )
    rule = rig.stack.active_rule()
    notifier = AlertNotifier(
        dispatcher,
        (RoutingRule("high", (EMAIL,)),),
        recorder,
        public_base_url="https://netsight.example.com",
    )
    try:
        result = notifier.notify(
            rule=rule,
            decision=decision_for(rule, DEVICE_A),
            entity=DEVICE_A,
            incident_id=None,
            correlation_id="c",
        )
    finally:
        release.set()
    assert (result.sent, result.failed) == (0, 1)
    (attempt,) = recorder.attempts  # a timeout is final: no retry piles up hung threads
    assert (attempt.status, attempt.code) == ("failed", "SEND_TIMEOUT")


# --- LOW: backlog ordering and BACKLOG_FULL ----------------------------------------------------------


@pytest.mark.asyncio
async def test_due_notifications_are_sent_most_severe_first() -> None:
    rig = Rig(limits=RunnerLimits(max_notifications=1))
    rig.stack.active_rule(name="minor", severity="high")
    rig.stack.active_rule(name="major", severity="critical")
    down(rig, DEVICE_A)
    first = await rig.cycle()
    assert first.notifications_sent == 1 and first.notifications_backlog == 1
    ((_, payload),) = rig.sender.calls
    assert payload.severity == "critical"
    await rig.cycle(advance=60)
    assert [p.severity for _, p in rig.sender.calls] == ["critical", "high"]


@pytest.mark.asyncio
async def test_a_full_backlog_drops_the_least_severe_and_audits_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    rig = Rig(limits=RunnerLimits(max_notifications=1, max_backlog=1))
    rig.stack.active_rule(name="a", severity="critical")
    rig.stack.active_rule(name="b", severity="critical")
    dropped_rule = rig.stack.active_rule(name="c", severity="high")
    down(rig, DEVICE_A)
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        report = await rig.cycle()
    assert report.notifications_sent == 1 and report.notifications_backlog == 1
    assert report.notifications_failed == 1
    (record,) = [r for r in audit_records(caplog) if r.get("code") == "BACKLOG_FULL"]
    assert record["action"] == "notification.send" and record["outcome"] == "failure"
    assert record["rule_id"] == dropped_rule.id
    assert record["alert"] == decision_for(dropped_rule, DEVICE_A).fingerprint


@pytest.mark.asyncio
async def test_a_notifier_that_raises_mid_drain_still_marks_delivered_items_as_sent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    rig = Rig()
    recorder = InMemoryDeliveryRecorder()
    calls = {"n": 0}

    class FlakyDrain(NotificationDispatcher):
        def drain(self, limit: int | None = None) -> Any:
            calls["n"] += 1
            outcomes = super().drain(limit)
            if calls["n"] == 2:
                raise RuntimeError("bookkeeping failed after delivery")
            return outcomes

    dispatcher = FlakyDrain(
        {"email": FakeSender("email")},
        recorder,
        clock=rig.stack.clock,
        sleep=lambda seconds: None,
        policy=RetryPolicy(max_attempts=1),
        public_base_url="https://netsight.example.com",
    )
    destinations = tuple(
        EmailDestination(a) for a in ("one@example.com", "two@example.com", "three@example.com")
    )
    notifier = AlertNotifier(
        dispatcher,
        (RoutingRule("high", destinations),),
        recorder,
        public_base_url="https://netsight.example.com",
    )
    rule = rig.stack.active_rule()
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        result = notifier.notify(
            rule=rule,
            decision=decision_for(rule, DEVICE_A),
            entity=DEVICE_A,
            incident_id=None,
            correlation_id="c",
        )
    assert (result.sent, result.failed) == (2, 1)
    codes = sorted(r["code"] for r in audit_records(caplog))
    assert codes == ["NOT_DELIVERED", "OK", "OK"]


# --- LOW: more than 500 maintenance windows ----------------------------------------------------------


class SyntheticWindows:
    """Rule store whose window listing is ``count`` long (the real store caps live windows)."""

    def __init__(self, inner: Any, window: Any, count: int) -> None:
        self._inner, self._window, self._count = inner, window, count

    def list_rules(self, **kwargs: Any) -> Any:
        return self._inner.list_rules(**kwargs)

    def list_windows(self, *, active_at: Any, limit: int, offset: int) -> list[Any]:
        return [self._window] * max(0, min(limit, self._count - offset))


@pytest.mark.asyncio
@pytest.mark.parametrize(("count", "truncated"), [(499, False), (500, False), (501, True)])
async def test_more_than_the_window_cap_marks_the_cycle_truncated(
    count: int, truncated: bool
) -> None:
    rig = Rig()
    window = rig.stack.window()
    rig.runner._rules = SyntheticWindows(rig.stack.rules, window, count)  # type: ignore[assignment]
    rig.stack.active_rule()
    down(rig, DEVICE_A)
    report = await rig.cycle()
    assert report.truncated is truncated


# --- LOW: orphan incident audit and claim results ----------------------------------------------------


def make_service(stack: Stack, links: Any) -> AlertIncidentService:
    return AlertIncidentService(stack.incidents, links)


def test_a_lost_claim_race_audits_the_orphan_incident(caplog: pytest.LogCaptureFixture) -> None:
    stack = Stack.build()
    rule = stack.active_rule()
    winner = stack.incidents.create_incident(title="rival", severity="high", actor_id="x:rival")
    service = make_service(stack, RacingLinks(stack, winner.id))
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        service.ensure(
            rule=rule, decision=decision_for(rule, DEVICE_A), entity=DEVICE_A, correlation_id="c"
        )
    failures = [r for r in audit_records(caplog) if r["outcome"] == "failure"]
    (record,) = failures
    assert record["action"] == "incident.auto_create" and record["reason"] == "CLAIM_LOST"
    orphan = next(i for i in stack.incidents.list_incidents(limit=10) if i.id != winner.id)
    assert record["target"] == orphan.id


class AlertKeyRace(InMemoryAlertIncidentLinkRepository):
    """A rival evaluator claims the *alert* key between our read and our claim."""

    def __init__(self, rival_incident_id: str) -> None:
        super().__init__(incident_exists=lambda _id: True)
        self._rival = rival_incident_id
        self._raced = False

    def claim(self, kind: Any, key: str, *, incident_id: str, replacing: str | None) -> bool:
        if kind == "alert" and not self._raced:
            self._raced = True
            super().claim("alert", key, incident_id=self._rival, replacing=None)
        return super().claim(kind, key, incident_id=incident_id, replacing=replacing)


def test_a_lost_alert_claim_while_attaching_is_audited_and_not_reported_as_attached(
    caplog: pytest.LogCaptureFixture,
) -> None:
    stack = Stack.build()
    rule = stack.active_rule(incident_policy="group")
    service = make_service(stack, stack.links)
    created = service.ensure(
        rule=rule, decision=decision_for(rule, DEVICE_A), entity=DEVICE_A, correlation_id="c"
    )
    rival = stack.incidents.create_incident(title="rival", severity="high", actor_id="x:rival")
    racing = AlertKeyRace(rival.id)
    racing.claim(
        "group",
        decision_for(rule, DEVICE_B).group_key,
        incident_id=created.incident_id,
        replacing=None,
    )  # type: ignore[arg-type]
    service = make_service(stack, racing)
    with caplog.at_level(logging.INFO, logger="netsight_api.audit"):
        effect = service.ensure(
            rule=rule, decision=decision_for(rule, DEVICE_B), entity=DEVICE_B, correlation_id="c"
        )
    assert effect.action == "none" and effect.incident_id == rival.id
    (record,) = [r for r in audit_records(caplog) if r["outcome"] == "failure"]
    assert record["reason"] == "CLAIM_LOST"
    assert len(stack.incidents.list_timeline(created.incident_id)) == 1  # no note for the loser


# --- resolved incident + restart ---------------------------------------------------------------------


def restarted(rig: Rig) -> Rig:
    fresh = Rig()
    fresh.stack = rig.stack
    fresh.source = rig.source
    fresh.runner = EvaluationRunner(
        rules=rig.stack.rules,
        source=rig.source,
        incidents=AlertIncidentService(rig.stack.incidents, rig.stack.links),
        notifier=None,
        clock=rig.stack.clock,
    )
    return fresh


@pytest.mark.asyncio
async def test_a_still_firing_alert_gets_no_new_incident_after_a_human_resolves_and_the_service_restarts() -> (
    None
):
    rig = Rig()
    rig.stack.active_rule()
    down(rig, DEVICE_A)
    await rig.cycle()
    (incident,) = rig.incidents
    human_resolve(rig.stack, incident.id)
    in_process = await rig.cycle(advance=60)  # the running evaluator: nothing new
    assert in_process.incidents_created == 0
    fresh = restarted(rig)
    after_restart = await fresh.cycle(advance=60)
    assert after_restart.fired == 1 and after_restart.incidents_created == 0
    assert len(rig.incidents) == 1


@pytest.mark.asyncio
async def test_after_recovery_the_next_outage_opens_a_new_incident_even_across_a_restart() -> None:
    rig = Rig()
    rig.stack.active_rule()
    down(rig, DEVICE_A)
    await rig.cycle()
    human_resolve(rig.stack, rig.incidents[0].id)
    fresh = restarted(rig)
    up(rig, DEVICE_A)
    assert (await fresh.cycle(advance=60)).resolved == 0  # fresh state: it never saw it fire
    down(rig, DEVICE_A)
    await fresh.cycle(advance=60)
    assert len(rig.incidents) == 1  # still the old outage as far as the durable record knows
    up(rig, DEVICE_A)
    assert (await fresh.cycle(advance=60)).resolved == 1  # recovery observed and recorded
    down(rig, DEVICE_A)
    report = await restarted(rig).cycle(advance=60)
    assert report.incidents_created == 1 and len(rig.incidents) == 2


@pytest.mark.asyncio
async def test_recovery_with_the_incident_still_open_re_arms_so_a_later_resolution_is_respected() -> (
    None
):
    rig = Rig()
    rig.stack.active_rule()
    down(rig, DEVICE_A)
    await rig.cycle()
    up(rig, DEVICE_A)
    await rig.cycle(advance=60)  # recovered, incident still open
    down(rig, DEVICE_A)
    await rig.cycle(advance=60)  # fires again: attaches to the open incident, re-arms the link
    human_resolve(rig.stack, rig.incidents[0].id)
    report = await restarted(rig).cycle(advance=60)
    assert report.incidents_created == 0 and len(rig.incidents) == 1


# --- narrow incident dependency ----------------------------------------------------------------------


def test_the_incident_service_needs_only_create_append_and_get() -> None:
    stack = Stack.build()
    real = stack.incidents

    class Narrow:
        create_incident = real.create_incident
        append_event = real.append_event
        get_incident = real.get_incident

    service = AlertIncidentService(Narrow(), stack.links)
    rule = stack.active_rule()
    effect = service.ensure(
        rule=rule, decision=decision_for(rule, DEVICE_A), entity=DEVICE_A, correlation_id="c"
    )
    assert effect.action == "created"


# --- lifespan helpers ---------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stopping_the_evaluator_never_swallows_a_real_cancellation() -> None:
    stop = asyncio.Event()

    async def stubborn() -> None:
        await asyncio.sleep(30)

    task = asyncio.create_task(stubborn())
    stopper = asyncio.create_task(stop_evaluation(task, stop, timeout=30))
    await asyncio.sleep(0.05)
    stopper.cancel()
    with pytest.raises(asyncio.CancelledError):
        await stopper
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_a_scheduler_that_ignores_the_stop_request_is_cancelled_after_the_timeout() -> None:
    stop = asyncio.Event()

    async def stubborn() -> None:
        await asyncio.sleep(30)

    task = asyncio.create_task(stubborn())
    await stop_evaluation(task, stop, timeout=0.05)
    assert stop.is_set() and task.cancelled()


@pytest.mark.asyncio
async def test_a_scheduler_that_ends_with_an_error_is_logged_not_raised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def failing() -> None:
        raise RuntimeError("boom")

    task = asyncio.create_task(failing())
    await asyncio.sleep(0)
    with caplog.at_level(logging.WARNING):
        await stop_evaluation(task, asyncio.Event(), timeout=1)
    assert "ended with an error" in caplog.text


def test_main_keeps_no_evaluation_lifecycle_helpers() -> None:
    from netsight_api import main

    assert not hasattr(main, "_stop_evaluation")


# --- LOW: text and TLS ---------------------------------------------------------------------------------


def test_format_characters_are_stripped_from_single_lines() -> None:
    hidden = f"pa{ZERO_WIDTH_SPACE}ge{chr(0xFEFF)}r{chr(0x2060)}{chr(0xE0041)}"
    assert sanitize_line(hidden, 50) == "pager"


def test_a_custom_ca_bundle_adds_to_the_system_roots_instead_of_replacing_them(
    tmp_path: Path,
) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-root")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(T0 - timedelta(days=1))
        .not_valid_after(T0 + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    bundle = tmp_path / "ca.pem"
    bundle.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    baseline = ssl.create_default_context().cert_store_stats()["x509"]
    settings = SmtpSettings.from_env(
        {
            "NETSIGHT_SMTP_HOST": "smtp.example.com",
            "NETSIGHT_SMTP_FROM": "netsight@example.com",
            "NETSIGHT_SMTP_CA_BUNDLE": str(bundle),
        }
    )
    assert settings is not None
    context = SmtpEmailSender(settings)._context()
    assert context.cert_store_stats()["x509"] == baseline + 1


def test_build_evaluation_service_is_a_short_function() -> None:
    import ast
    import inspect

    from netsight_api.evaluation import wiring

    tree = ast.parse(inspect.getsource(wiring.build_evaluation_service))
    function = tree.body[0]
    assert isinstance(function, ast.FunctionDef) and function.end_lineno is not None
    assert function.end_lineno - function.lineno + 1 < 50
