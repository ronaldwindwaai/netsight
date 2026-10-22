"""Conformance for the evaluation stores (S6 step 2): alert -> incident links and durable
notification delivery attempts.

The same tests run against the in-memory implementations and (with ``NETSIGHT_TEST_PG_DSN``)
PostgreSQL as the migrator/owner and as the least-privilege application role.
"""

from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from pg_support import app_role, isolated_schema, requires_pg

from netsight_api.notifications.dispatcher import DeliveryAttempt, InMemoryDeliveryRecorder
from netsight_api.notifications.store import DeliveryAttemptRepository
from netsight_api.storage import (
    AlertIncidentLinkRepository,
    AlertIncidentStore,
    IncidentRepository,
    InMemoryAlertIncidentLinkRepository,
    InMemoryAlertIncidentStore,
    InMemoryIncidentRepository,
    LinkClaim,
    NotFoundError,
)

T0 = datetime(2026, 10, 10, 8, 0, tzinfo=UTC)
KEY_A = "a" * 32
KEY_B = "b" * 32


@dataclass
class EvalStores:
    incidents: IncidentRepository
    links: AlertIncidentLinkRepository
    attempts: DeliveryAttemptRepository
    opener: AlertIncidentStore


@pytest.fixture(
    params=[
        "memory",
        pytest.param("postgres", marks=requires_pg),
        pytest.param("postgres-app-role", marks=requires_pg),
    ]
)
def stores(request: pytest.FixtureRequest) -> Iterator[EvalStores]:
    if request.param == "memory":
        incidents = InMemoryIncidentRepository()
        links = InMemoryAlertIncidentLinkRepository(
            incident_exists=lambda incident_id: incidents.get_incident(incident_id) is not None
        )
        yield EvalStores(
            incidents,
            links,
            InMemoryDeliveryRecorder(),
            InMemoryAlertIncidentStore(incidents, links),
        )
        return
    from pg_support import PG_DSN

    from netsight_api.notifications.store_postgres import PostgresDeliveryAttemptRepository
    from netsight_api.storage.migrate import apply_grants, apply_up
    from netsight_api.storage.postgres import PostgresIncidentRepository, PostgresSettings
    from netsight_api.storage.postgres_alert_incidents import PostgresAlertIncidentStore
    from netsight_api.storage.postgres_links import PostgresAlertIncidentLinkRepository

    assert PG_DSN
    with ExitStack() as stack:
        schema = stack.enter_context(isolated_schema())
        owner = PostgresSettings(dsn=PG_DSN, schema=schema)
        runtime = owner
        role_name = ""
        if request.param == "postgres-app-role":
            role_name, role_dsn = stack.enter_context(app_role())
            runtime = PostgresSettings(dsn=role_dsn, schema=schema)
        with owner.connect() as conn:
            apply_up(conn)
            if role_name:
                apply_grants(conn, role_name)
        yield EvalStores(
            PostgresIncidentRepository(runtime),
            PostgresAlertIncidentLinkRepository(runtime),
            PostgresDeliveryAttemptRepository(runtime),
            PostgresAlertIncidentStore(runtime),
        )


def make_incident(stores: EvalStores) -> str:
    return stores.incidents.create_incident(title="t", severity="high", actor_id="u-1").id


def attempt(**overrides: object) -> DeliveryAttempt:
    fields: dict[str, object] = {
        "notification_id": "n-1",
        "alert_ref": KEY_A,
        "channel": "email",
        "destination": "email:0123456789ab",
        "attempt": 1,
        "status": "sent",
        "code": "OK",
        "at": T0,
    }
    fields.update(overrides)
    return DeliveryAttempt(**fields)  # type: ignore[arg-type]


# --- one transaction: incident + link claim + timeline note --------------------------------------

SERVICE = "service:alert-evaluator"


def open_linked(stores: EvalStores, **overrides: object) -> object:
    fields: dict[str, object] = {
        "title": "Device down: core-1",
        "severity": "high",
        "actor_id": SERVICE,
        "primary": LinkClaim("alert", KEY_A),
        "note": "Alert rule 'Device down' (high) fired for core-1.",
        "note_subject": KEY_A,
    }
    fields.update(overrides)
    return stores.opener.open_linked(**fields)  # type: ignore[arg-type]


def test_open_linked_creates_the_incident_the_link_and_the_note_together(
    stores: EvalStores,
) -> None:
    opened = open_linked(stores)
    assert opened is not None
    incident = opened.incident  # type: ignore[attr-defined]
    assert (incident.state, incident.severity, incident.title) == (
        "open",
        "high",
        "Device down: core-1",
    )
    assert stores.incidents.get_incident(incident.id) == incident
    assert stores.links.get("alert", KEY_A) == incident.id
    (event,) = stores.incidents.list_timeline(incident.id)
    assert (event.kind, event.actor_id, event.subject_id) == ("alert-linked", SERVICE, KEY_A)
    assert event.message is not None and "core-1" in event.message


def test_open_linked_that_loses_the_claim_leaves_nothing_behind(stores: EvalStores) -> None:
    rival = make_incident(stores)
    assert stores.links.claim("alert", KEY_A, incident_id=rival, replacing=None)
    before = len(stores.incidents.list_incidents(limit=100))
    assert open_linked(stores) is None
    assert len(stores.incidents.list_incidents(limit=100)) == before  # no orphan incident
    assert stores.links.get("alert", KEY_A) == rival


def test_open_linked_replaces_a_resolved_incident_when_the_expectation_matches(
    stores: EvalStores,
) -> None:
    old = make_incident(stores)
    stores.links.claim("alert", KEY_A, incident_id=old, replacing=None)
    assert open_linked(stores, primary=LinkClaim("alert", KEY_A, replacing=old))
    assert stores.links.get("alert", KEY_A) != old
    assert open_linked(stores, primary=LinkClaim("alert", KEY_A, replacing=old)) is None


def test_open_linked_reports_a_lost_secondary_claim_without_rolling_back(
    stores: EvalStores,
) -> None:
    rival = make_incident(stores)
    stores.links.claim("alert", KEY_B, incident_id=rival, replacing=None)
    opened = open_linked(
        stores,
        primary=LinkClaim("group", KEY_A),
        secondary=LinkClaim("alert", KEY_B),
    )
    assert opened is not None
    assert opened.secondary_claimed is False  # type: ignore[attr-defined]
    assert stores.links.get("group", KEY_A) == opened.incident.id  # type: ignore[attr-defined]
    assert stores.links.get("alert", KEY_B) == rival


def test_open_linked_claims_both_keys_for_a_grouped_alert(stores: EvalStores) -> None:
    opened = open_linked(
        stores,
        primary=LinkClaim("group", KEY_A),
        secondary=LinkClaim("alert", KEY_B),
    )
    assert opened is not None and opened.secondary_claimed is True  # type: ignore[attr-defined]
    incident_id = opened.incident.id  # type: ignore[attr-defined]
    assert stores.links.get("group", KEY_A) == incident_id
    assert stores.links.get("alert", KEY_B) == incident_id


def test_open_linked_failing_after_the_claim_leaves_no_incident_and_no_link(
    stores: EvalStores,
) -> None:
    before = len(stores.incidents.list_incidents(limit=100))
    with pytest.raises(Exception):  # noqa: B017 - an oversized note fails contract validation
        open_linked(stores, note="x" * 5000)
    assert len(stores.incidents.list_incidents(limit=100)) == before
    assert stores.links.get("alert", KEY_A) is None


def test_open_linked_validates_its_arguments_before_writing(stores: EvalStores) -> None:
    before = len(stores.incidents.list_incidents(limit=100))
    with pytest.raises(ValueError, match="key"):
        open_linked(stores, primary=LinkClaim("alert", "not-a-key"))
    with pytest.raises(ValueError, match="incident"):
        open_linked(stores, primary=LinkClaim("alert", KEY_A, replacing="bogus"))
    assert len(stores.incidents.list_incidents(limit=100)) == before


def test_concurrent_open_linked_for_one_key_creates_exactly_one_incident(
    stores: EvalStores,
) -> None:
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _n: open_linked(stores), range(8)))
    assert sum(1 for r in results if r is not None) == 1
    assert len(stores.incidents.list_incidents(limit=100)) == 1


# --- alert -> incident links ---------------------------------------------------------------------


def test_unknown_link_is_none(stores: EvalStores) -> None:
    assert stores.links.get("alert", KEY_A) is None


def test_first_claim_wins_and_is_readable(stores: EvalStores) -> None:
    first, second = make_incident(stores), make_incident(stores)
    assert stores.links.claim("group", KEY_A, incident_id=first, replacing=None) is True
    assert stores.links.get("group", KEY_A) == first
    assert stores.links.claim("group", KEY_A, incident_id=second, replacing=None) is False
    assert stores.links.get("group", KEY_A) == first


def test_replacing_needs_the_current_incident(stores: EvalStores) -> None:
    old, new, other = (make_incident(stores) for _ in range(3))
    assert stores.links.claim("alert", KEY_A, incident_id=old, replacing=None)
    assert stores.links.claim("alert", KEY_A, incident_id=new, replacing=other) is False
    assert stores.links.get("alert", KEY_A) == old
    assert stores.links.claim("alert", KEY_A, incident_id=new, replacing=old) is True
    assert stores.links.get("alert", KEY_A) == new


def test_replacing_a_missing_link_fails(stores: EvalStores) -> None:
    some, other = make_incident(stores), make_incident(stores)
    assert stores.links.claim("alert", KEY_A, incident_id=some, replacing=other) is False
    assert stores.links.get("alert", KEY_A) is None


def test_kinds_and_keys_are_independent_namespaces(stores: EvalStores) -> None:
    one, two, three = (make_incident(stores) for _ in range(3))
    assert stores.links.claim("alert", KEY_A, incident_id=one, replacing=None)
    assert stores.links.claim("group", KEY_A, incident_id=two, replacing=None)
    assert stores.links.claim("alert", KEY_B, incident_id=three, replacing=None)
    assert [stores.links.get("alert", KEY_A), stores.links.get("group", KEY_A)] == [one, two]
    assert stores.links.get("alert", KEY_B) == three


def test_a_new_link_is_not_recovered_and_recovery_is_recorded_once(stores: EvalStores) -> None:
    incident = make_incident(stores)
    assert stores.links.is_recovered("alert", KEY_A) is False  # no link at all
    assert stores.links.mark_recovered("alert", KEY_A) is False
    stores.links.claim("alert", KEY_A, incident_id=incident, replacing=None)
    assert stores.links.is_recovered("alert", KEY_A) is False
    assert stores.links.mark_recovered("alert", KEY_A) is True
    assert stores.links.is_recovered("alert", KEY_A) is True
    assert stores.links.mark_recovered("alert", KEY_A) is False  # already recorded
    assert stores.links.get("alert", KEY_A) == incident


def test_claiming_again_re_arms_a_recovered_link(stores: EvalStores) -> None:
    old, new = make_incident(stores), make_incident(stores)
    stores.links.claim("alert", KEY_A, incident_id=old, replacing=None)
    stores.links.mark_recovered("alert", KEY_A)
    assert stores.links.claim("alert", KEY_A, incident_id=old, replacing=old) is True  # re-arm
    assert stores.links.is_recovered("alert", KEY_A) is False
    stores.links.mark_recovered("alert", KEY_A)
    assert stores.links.claim("alert", KEY_A, incident_id=new, replacing=old) is True
    assert stores.links.is_recovered("alert", KEY_A) is False


@pytest.mark.parametrize("key", ["", "A" * 32, "a" * 31, "a" * 33, "g" * 32, "a" * 31 + "\n"])
def test_keys_must_be_32_lowercase_hex(stores: EvalStores, key: str) -> None:
    incident = make_incident(stores)
    with pytest.raises(ValueError, match="key"):
        stores.links.get("alert", key)
    with pytest.raises(ValueError, match="key"):
        stores.links.claim("alert", key, incident_id=incident, replacing=None)


def test_kind_and_incident_ids_are_validated(stores: EvalStores) -> None:
    incident = make_incident(stores)
    with pytest.raises(ValueError, match="kind"):
        stores.links.get("other", KEY_A)  # type: ignore[arg-type]
    for bad in ("", "incident-1", "alert-rule-00000000-0000-4000-8000-000000000000"):
        with pytest.raises(ValueError, match="incident"):
            stores.links.claim("alert", KEY_A, incident_id=bad, replacing=None)
        with pytest.raises(ValueError, match="incident"):
            stores.links.claim("alert", KEY_A, incident_id=incident, replacing=bad)


def test_claim_for_a_missing_incident_is_not_found(stores: EvalStores) -> None:
    ghost = "incident-00000000-0000-4000-8000-000000000000"
    with pytest.raises(NotFoundError):
        stores.links.claim("alert", KEY_A, incident_id=ghost, replacing=None)
    assert stores.links.get("alert", KEY_A) is None


def test_concurrent_claims_have_exactly_one_winner(stores: EvalStores) -> None:
    incidents = [make_incident(stores) for _ in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(
                lambda incident: stores.links.claim(
                    "group", KEY_A, incident_id=incident, replacing=None
                ),
                incidents,
            )
        )
    assert results.count(True) == 1
    assert stores.links.get("group", KEY_A) == incidents[results.index(True)]


# --- delivery attempts -------------------------------------------------------------------------------


def test_attempts_round_trip_in_attempt_order(stores: EvalStores) -> None:
    first = attempt(attempt=1, status="retrying", code="TIMEOUT")
    second = attempt(attempt=2, at=T0 + timedelta(seconds=2))
    other = attempt(notification_id="n-2")
    for item in (first, second, other):
        stores.attempts.record(item)
    assert stores.attempts.for_notification("n-1") == (first, second)
    assert stores.attempts.for_notification("n-missing") == ()


def test_recent_is_newest_first_and_bounded(stores: EvalStores) -> None:
    for index in range(5):
        stores.attempts.record(
            attempt(notification_id=f"n-{index}", at=T0 + timedelta(seconds=index))
        )
    recent = stores.attempts.recent(3)
    assert [a.notification_id for a in recent] == ["n-4", "n-3", "n-2"]
    for bad in (0, -1, 501):
        with pytest.raises(ValueError, match="limit"):
            stores.attempts.recent(bad)


def test_last_sent_at_counts_only_successful_sends_of_that_alert(stores: EvalStores) -> None:
    assert stores.attempts.last_sent_at(KEY_A) is None
    stores.attempts.record(attempt(status="failed", code="HTTP_4XX"))
    stores.attempts.record(attempt(status="retrying", code="TIMEOUT"))
    stores.attempts.record(attempt(alert_ref=KEY_B, at=T0 + timedelta(hours=1)))
    assert stores.attempts.last_sent_at(KEY_A) is None
    stores.attempts.record(attempt(notification_id="n-2", at=T0 + timedelta(minutes=5)))
    stores.attempts.record(attempt(notification_id="n-3", at=T0 + timedelta(minutes=1)))
    assert stores.attempts.last_sent_at(KEY_A) == T0 + timedelta(minutes=5)


@pytest.mark.parametrize(
    "overrides",
    [
        {"notification_id": ""},
        {"notification_id": "n 1\n"},
        {"alert_ref": "x" * 65},
        {"channel": "sms"},
        {"status": "queued"},
        {"attempt": -1},
        {"attempt": 6},
        {"code": ""},
        {"code": "bad code\n"},
        {"destination": ""},
        {"destination": "d" * 301},
        {"destination": "line\nbreak"},
        {"destination": "nul\x00byte"},
        {"at": datetime(2026, 10, 10, 8, 0)},  # noqa: DTZ001 (deliberately naive)
    ],
)
def test_invalid_attempts_are_refused(stores: EvalStores, overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        stores.attempts.record(attempt(**overrides))
    assert stores.attempts.recent(10) == ()


class _SecondClaimFails(InMemoryAlertIncidentLinkRepository):
    """After ``armed``, the second claim raises (a connection lost mid-transaction)."""

    def __init__(self, incidents: InMemoryIncidentRepository) -> None:
        super().__init__(incident_exists=lambda i: incidents.get_incident(i) is not None)
        self.armed = False
        self._claims_since_armed = 0

    def claim(self, kind: object, key: str, *, incident_id: str, replacing: str | None) -> bool:
        if self.armed:
            self._claims_since_armed += 1
            if self._claims_since_armed == 2:
                raise RuntimeError("connection lost")
        return super().claim(kind, key, incident_id=incident_id, replacing=replacing)  # type: ignore[arg-type]


def test_in_memory_rollback_restores_what_the_claimed_keys_held_before() -> None:
    """A failure after the primary claim won puts every claimed key back as it was (including
    the recovered mark) and leaves keys that point elsewhere alone."""
    incidents = InMemoryIncidentRepository()
    links = _SecondClaimFails(incidents)
    store = InMemoryAlertIncidentStore(incidents, links)
    old = incidents.create_incident(title="old", severity="low", actor_id="u-1").id
    bystander = incidents.create_incident(title="by", severity="low", actor_id="u-1").id
    links.claim("group", KEY_A, incident_id=old, replacing=None)
    links.mark_recovered("group", KEY_A)
    links.claim("alert", KEY_B, incident_id=bystander, replacing=None)
    before = len(incidents.list_incidents(limit=100))
    links.armed = True
    with pytest.raises(RuntimeError):
        store.open_linked(
            title="t",
            severity="high",
            actor_id=SERVICE,
            primary=LinkClaim("group", KEY_A, replacing=old),
            secondary=LinkClaim("alert", KEY_B, replacing=bystander),
            note="n",
            note_subject=KEY_B,
        )
    assert len(incidents.list_incidents(limit=100)) == before
    assert links.get("group", KEY_A) == old and links.is_recovered("group", KEY_A) is True
    assert links.get("alert", KEY_B) == bystander


def test_hostile_text_is_stored_as_data(stores: EvalStores) -> None:
    hostile = attempt(destination="webhook:evil'; DROP TABLE x; --<script>" + chr(0x202E) + "🔥")
    stores.attempts.record(hostile)
    assert stores.attempts.for_notification("n-1") == (hostile,)
