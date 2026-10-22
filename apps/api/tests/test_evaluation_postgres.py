"""The evaluation service against real PostgreSQL stores (skipped without NETSIGHT_TEST_PG_DSN).

Runs as the least-privilege application role: the same grants production uses must be enough for
incident creation, link claims and durable delivery recording, and not one privilege more.
"""

from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import pytest
from evaluation_support import DEVICE_A, DEVICE_B, T0, MutableClock, ScriptedSource, decision_for
from evaluation_support import definition as rule_definition
from pg_support import PG_DSN, app_role, isolated_schema, requires_pg

from netsight_api.evaluation.adapter import EvaluatorIncidentAdapter
from netsight_api.evaluation.incidents import SERVICE_ACTOR_ID, AlertIncidentService
from netsight_api.evaluation.notify import AlertNotifier
from netsight_api.evaluation.runner import EvaluationRunner
from netsight_api.notifications.dispatcher import (
    InMemoryDeliveryRecorder,
    NotificationDispatcher,
    RetryPolicy,
    RoutingRule,
)
from netsight_api.notifications.models import EmailDestination
from netsight_api.notifications.senders import FakeSender
from netsight_api.notifications.store import DurableDeliveryRecorder
from netsight_api.notifications.store_postgres import PostgresDeliveryAttemptRepository
from netsight_api.schemas import AlertRule
from netsight_api.storage import migrate
from netsight_api.storage.postgres import (
    PostgresAlertRuleRepository,
    PostgresIncidentRepository,
    PostgresSettings,
)
from netsight_api.storage.postgres_alert_incidents import PostgresAlertIncidentStore
from netsight_api.storage.postgres_links import PostgresAlertIncidentLinkRepository

pytestmark = requires_pg
BASE = "https://netsight.example.com"


@dataclass
class Live:
    app: PostgresSettings
    owner: PostgresSettings
    clock: MutableClock

    @property
    def rules(self) -> PostgresAlertRuleRepository:
        return PostgresAlertRuleRepository(self.app, clock=self.clock)

    @property
    def incidents(self) -> PostgresIncidentRepository:
        return PostgresIncidentRepository(self.app, clock=self.clock)

    @property
    def links(self) -> PostgresAlertIncidentLinkRepository:
        return PostgresAlertIncidentLinkRepository(self.app, clock=self.clock)

    @property
    def evaluator(self) -> EvaluatorIncidentAdapter:
        return EvaluatorIncidentAdapter(
            self.incidents, PostgresAlertIncidentStore(self.app, clock=self.clock)
        )

    @property
    def attempts(self) -> PostgresDeliveryAttemptRepository:
        return PostgresDeliveryAttemptRepository(self.app)

    def active_rule(self, **overrides: Any) -> AlertRule:
        repo = self.rules
        draft = repo.create_rule(rule_definition(**overrides), actor_id="seed:admin")
        return repo.approve_rule(draft.id, approver_id="seed:admin", expected_version=1)

    def runner(self, source: ScriptedSource, sender: FakeSender) -> EvaluationRunner:
        recorder = DurableDeliveryRecorder(InMemoryDeliveryRecorder(), self.attempts)
        dispatcher = NotificationDispatcher(
            {"email": sender},
            recorder,
            clock=self.clock,
            sleep=lambda seconds: None,
            policy=RetryPolicy(max_attempts=1),
            public_base_url=BASE,
        )
        return EvaluationRunner(
            rules=self.rules,
            source=source,
            incidents=AlertIncidentService(self.evaluator, self.links),
            notifier=AlertNotifier(
                dispatcher,
                (RoutingRule("high", (EmailDestination("ops@example.com"),)),),
                self.attempts,
                public_base_url=BASE,
            ),
            clock=self.clock,
        )


@pytest.fixture
def live() -> Iterator[Live]:
    assert PG_DSN
    with ExitStack() as stack:
        schema = stack.enter_context(isolated_schema())
        role, role_dsn = stack.enter_context(app_role())
        owner = PostgresSettings(dsn=PG_DSN, schema=schema)
        with owner.connect() as conn:
            migrate.apply_up(conn)
            migrate.apply_grants(conn, role)
        yield Live(PostgresSettings(dsn=role_dsn, schema=schema), owner, MutableClock())


@pytest.mark.asyncio
async def test_a_firing_rule_creates_one_incident_and_durable_delivery_records(live: Live) -> None:
    rule = live.active_rule()
    source, sender = ScriptedSource(), FakeSender("email")
    source.set("device.status", (DEVICE_A, 0.0), (DEVICE_B, 1.0))
    runner = live.runner(source, sender)

    first = await runner.run_cycle()
    assert (first.fired, first.incidents_created, first.notifications_sent) == (1, 1, 1)
    for _ in range(3):
        live.clock.advance(seconds=60)
        await runner.run_cycle()

    (incident,) = live.incidents.list_incidents(limit=50)
    assert incident.state == "open"
    events = live.incidents.list_timeline(incident.id)
    assert [(e.kind, e.actor_id) for e in events] == [("alert-linked", SERVICE_ACTOR_ID)]
    fingerprint = decision_for(rule, DEVICE_A).fingerprint
    assert live.links.get("alert", fingerprint) == incident.id
    (attempt,) = live.attempts.recent(10)
    assert (attempt.status, attempt.code, attempt.alert_ref) == ("sent", "OK", fingerprint)
    assert live.attempts.last_sent_at(fingerprint) == attempt.at
    assert len(sender.calls) == 1


@pytest.mark.asyncio
async def test_a_restarted_runner_neither_duplicates_the_incident_nor_loses_the_ledger(
    live: Live,
) -> None:
    live.active_rule(cooldown_seconds=3600)
    source, sender = ScriptedSource(), FakeSender("email")
    source.set("device.status", (DEVICE_A, 0.0))
    await live.runner(source, sender).run_cycle()
    live.clock.advance(seconds=60)
    restarted = await live.runner(source, sender).run_cycle()  # no in-memory state at all
    assert restarted.fired == 1 and restarted.incidents_created == 0
    assert len(live.incidents.list_incidents(limit=50)) == 1
    assert len(sender.calls) == 1  # the durable ledger held the repeat page back (cooldown)
    assert restarted.notifications_skipped == 1


@pytest.mark.asyncio
async def test_a_human_resolving_the_incident_lets_the_next_firing_open_a_new_one(
    live: Live,
) -> None:
    live.active_rule()
    source, sender = ScriptedSource(), FakeSender("email")
    source.set("device.status", (DEVICE_A, 0.0))
    runner = live.runner(source, sender)
    await runner.run_cycle()
    (first,) = live.incidents.list_incidents(limit=50)
    from test_evaluation_incidents import human_resolve

    class Shim:
        incidents = live.incidents

    human_resolve(Shim, first.id)  # type: ignore[arg-type]
    source.set("device.status", (DEVICE_A, 1.0))
    live.clock.advance(seconds=60)
    await runner.run_cycle()  # recovery
    source.set("device.status", (DEVICE_A, 0.0))
    live.clock.advance(seconds=60)
    report = await runner.run_cycle()
    assert report.incidents_created == 1
    assert len(live.incidents.list_incidents(limit=50)) == 2


def test_two_evaluators_racing_leave_exactly_one_incident_and_no_orphan(live: Live) -> None:
    rule = live.active_rule()
    decision = decision_for(rule, DEVICE_A, at=T0 + timedelta(seconds=1))

    def evaluator(_: int) -> Any:
        service = AlertIncidentService(live.evaluator, live.links)  # separate locks, one database
        return service.ensure(rule=rule, decision=decision, entity=DEVICE_A, correlation_id="c")

    with ThreadPoolExecutor(max_workers=6) as pool:
        effects = list(pool.map(evaluator, range(6)))
    linked = live.links.get("alert", decision.fingerprint)
    assert linked is not None
    assert {e.incident_id for e in effects if e.incident_id} == {linked}
    assert [i.id for i in live.incidents.list_incidents(limit=50)] == [linked]  # no orphans
    assert sum(1 for e in effects if e.action == "created") == 1


def test_the_application_role_needs_nothing_beyond_the_documented_grants(live: Live) -> None:
    import psycopg

    with live.app.connect() as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute("DELETE FROM alert_incident_links")  # type: ignore[arg-type]
    with live.app.connect() as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute("UPDATE notification_delivery_attempts SET code = 'X'")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_resolved_then_restart_opens_nothing_until_the_alert_has_recovered(
    live: Live,
) -> None:
    live.active_rule()
    source, sender = ScriptedSource(), FakeSender("email")
    source.set("device.status", (DEVICE_A, 0.0))
    await live.runner(source, sender).run_cycle()
    (first,) = live.incidents.list_incidents(limit=50)
    from test_evaluation_incidents import human_resolve

    class Shim:
        incidents = live.incidents

    human_resolve(Shim, first.id)  # type: ignore[arg-type]
    live.clock.advance(seconds=60)
    restarted = live.runner(source, sender)
    still_down = await restarted.run_cycle()  # same outage, no in-memory state
    assert still_down.fired == 1 and still_down.incidents_created == 0
    source.set("device.status", (DEVICE_A, 1.0))
    live.clock.advance(seconds=60)
    assert (await restarted.run_cycle()).resolved == 1  # recovery is written to the links
    source.set("device.status", (DEVICE_A, 0.0))
    live.clock.advance(seconds=60)
    after = await live.runner(source, sender).run_cycle()  # another restart
    assert after.incidents_created == 1
    assert len(live.incidents.list_incidents(limit=50)) == 2
