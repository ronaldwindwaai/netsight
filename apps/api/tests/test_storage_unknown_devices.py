"""Behavioural conformance suite for the unknown-device finding store (Step 8c).

The same tests run against the in-memory fake and (when ``NETSIGHT_TEST_PG_DSN`` is set) PostgreSQL,
as the migrator/owner and as the least-privilege application role, so the fake cannot drift from
the real store. A finding is observed (created, refreshed or suppressed) by the scanner and then
moved through a fixed lifecycle by people; every change is an append-only timeline event.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from itertools import product
from typing import Any

import pytest
from pg_support import app_role, isolated_schema, requires_pg
from unknown_support import IP, MAC, comparison, detection, observed, unknown

from netsight_api.contracts import validate
from netsight_api.schemas_unknown_devices import (
    ALLOWED_TRANSITIONS,
    SYSTEM_ACTOR,
    UnknownDeviceEndpoint,
    UnknownDeviceFinding,
)
from netsight_api.storage import (
    IllegalTransitionError,
    InvalidOperationError,
    NotFoundError,
    StaleEvidenceError,
    StorageConflictError,
)
from netsight_api.storage.unknown_devices import (
    InMemoryUnknownDeviceRepository,
    UnknownDeviceRepository,
)
from netsight_api.unknown_devices.model import Detection, subject_key_for

START = datetime(2026, 10, 11, 8, 0, tzinfo=UTC)
STATES = ["new", "acknowledged", "investigating", "resolved", "false-positive"]
ACTOR = "oidc:analyst-1"
HOSTILE = "<script>alert('x')</script> \"; DROP TABLE unknown_device_findings; -- {{7*7}}"


class FakeClock:
    """Strictly increasing deterministic clock (1 s per call)."""

    def __init__(self) -> None:
        self.current = START

    def __call__(self) -> datetime:
        self.current += timedelta(seconds=1)
        return self.current


BACKENDS = [
    "memory",
    pytest.param("postgres", marks=requires_pg),
    pytest.param("postgres-app-role", marks=requires_pg),
]


def open_store(
    backend: str, clock: FakeClock, fp_ttl: timedelta | None = None
) -> Iterator[UnknownDeviceRepository]:
    options: dict[str, Any] = {} if fp_ttl is None else {"fp_ttl": fp_ttl}
    if backend == "memory":
        yield InMemoryUnknownDeviceRepository(clock=clock, **options)
        return
    from pg_support import PG_DSN

    from netsight_api.storage.connection import PostgresSettings
    from netsight_api.storage.migrate import apply_grants, apply_up
    from netsight_api.storage.postgres_unknown_devices import PostgresUnknownDeviceRepository

    with ExitStack() as stack:
        schema = stack.enter_context(isolated_schema())
        assert PG_DSN
        owner = PostgresSettings(dsn=PG_DSN, schema=schema)
        with owner.connect() as conn:
            apply_up(conn)
            if backend == "postgres-app-role":
                role, role_dsn = stack.enter_context(app_role())
                apply_grants(conn, role)
                yield PostgresUnknownDeviceRepository(
                    PostgresSettings(dsn=role_dsn, schema=schema), clock=clock, **options
                )
                return
        yield PostgresUnknownDeviceRepository(owner, clock=clock, **options)


@pytest.fixture(params=BACKENDS)
def store(request: pytest.FixtureRequest) -> Iterator[UnknownDeviceRepository]:
    yield from open_store(request.param, FakeClock())


@pytest.fixture(params=BACKENDS)
def timed(request: pytest.FixtureRequest) -> Iterator[tuple[UnknownDeviceRepository, FakeClock]]:
    """A store whose dismissals expire after ten days, and the clock to move past that."""
    clock = FakeClock()
    for repository in open_store(request.param, clock, fp_ttl=timedelta(days=10)):
        yield repository, clock


def created(store: UnknownDeviceRepository, **kwargs: Any) -> UnknownDeviceFinding:
    outcome = store.observe(detection(**kwargs))
    assert outcome.outcome == "created"
    finding = store.get_finding(outcome.finding_id)
    assert finding is not None
    return finding


def ver(store: UnknownDeviceRepository, finding_id: str) -> int:
    """The evidence version a person looking at the finding now would be quoting."""
    finding = store.get_finding(finding_id)
    assert finding is not None
    return finding.evidence_version


def kinds(store: UnknownDeviceRepository, finding_id: str) -> list[str]:
    return [e.kind for e in store.list_timeline(finding_id)]


# --- observing --------------------------------------------------------------------------------------------


def test_a_first_sighting_creates_a_new_finding_with_its_evidence_and_a_detected_event(
    store: UnknownDeviceRepository,
) -> None:
    finding = created(store)
    assert finding.state == "new" and finding.seen_count == 1
    assert finding.first_seen_at == finding.last_seen_at
    assert finding.endpoint.mac == MAC and finding.endpoint.ip == IP
    assert [s.slot for s in finding.chain] == ["ip", "mac", "attachment", "port", "vlan"]
    assert finding.assignee_id is None and finding.recurrence_of is None
    validate("unknown_device_finding", json.loads(finding.model_dump_json(by_alias=True)))
    (event,) = store.list_timeline(finding.id)
    assert (event.kind, event.seq, event.actor_id) == ("detected", 1, SYSTEM_ACTOR)
    assert event.finding_id == finding.id


def test_a_finding_with_a_proposed_quarantine_records_it_as_a_proposal_only(
    store: UnknownDeviceRepository,
) -> None:
    finding = created(store, severity="high", basis="policy-rule", with_action=True)
    assert finding.proposed_action is not None
    assert finding.proposed_action.executable is False
    assert kinds(store, finding.id) == ["detected", "action-proposed"]


def test_seeing_the_same_endpoint_again_only_moves_the_counter_and_the_time(
    store: UnknownDeviceRepository,
) -> None:
    first = created(store)
    outcome = store.observe(detection())
    assert (outcome.outcome, outcome.finding_id) == ("refreshed", first.id)
    again = store.get_finding(first.id)
    assert again is not None
    assert again.seen_count == 2 and again.first_seen_at == first.first_seen_at
    assert again.last_seen_at > first.last_seen_at
    assert again.chain == first.chain and again.comparison.checks == first.comparison.checks
    assert kinds(store, first.id) == ["detected"]


def test_new_evidence_about_the_same_endpoint_updates_it_and_leaves_a_history_event(
    store: UnknownDeviceRepository,
) -> None:
    first = created(store)
    outcome = store.observe(detection(port=True))
    assert outcome.outcome == "refreshed"
    updated = store.get_finding(first.id)
    assert updated is not None
    assert updated.chain[3].basis == "observed" and updated.chain[3].label == "Gi1/0/7"
    assert kinds(store, first.id) == ["detected", "evidence-updated"]


def test_a_changed_severity_is_a_recorded_change(store: UnknownDeviceRepository) -> None:
    first = created(store)
    store.observe(detection(severity="critical", basis="policy-rule", with_action=True))
    updated = store.get_finding(first.id)
    assert updated is not None
    assert (updated.severity, updated.severity_basis) == ("critical", "policy-rule")
    assert updated.proposed_action is not None
    assert kinds(store, first.id) == ["detected", "evidence-updated", "action-proposed"]


def test_a_known_endpoint_keeps_its_state_and_assignee_when_it_is_seen_again(
    store: UnknownDeviceRepository,
) -> None:
    first = created(store)
    store.transition_state(first.id, expected_evidence_version=ver(store, first.id), to_state="acknowledged", actor_id=ACTOR)
    store.set_assignee(first.id, expected_evidence_version=ver(store, first.id), assignee_id=ACTOR, actor_id=ACTOR)
    store.observe(detection(port=True))
    now = store.get_finding(first.id)
    assert now is not None and now.state == "acknowledged" and now.assignee_id == ACTOR


def test_the_same_mac_at_a_new_address_is_the_same_finding(store: UnknownDeviceRepository) -> None:
    first = created(store)
    outcome = store.observe(detection(ip="10.0.5.77"))
    assert outcome.outcome == "refreshed" and outcome.finding_id == first.id
    updated = store.get_finding(first.id)
    assert updated is not None and updated.endpoint.ip == "10.0.5.77"
    assert updated.chain[0].value == "10.0.5.77"
    assert "evidence-updated" in kinds(store, first.id)


def test_different_endpoints_are_different_findings(store: UnknownDeviceRepository) -> None:
    a = created(store)
    b = created(store, mac="aa:bb:cc:00:11:33", ip="10.0.5.10")
    c = created(store, mac=None, ip="10.0.5.11")
    assert len({a.id, b.id, c.id}) == 3
    rows, total = store.list_findings()
    assert total == 3 and len(rows) == 3


def test_a_false_positive_suppresses_the_endpoint_and_writes_nothing(
    store: UnknownDeviceRepository,
) -> None:
    first = created(store)
    store.transition_state(first.id, expected_evidence_version=ver(store, first.id), to_state="false-positive", actor_id=ACTOR, reason="Lab device")
    before = store.get_finding(first.id)
    outcome = store.observe(detection())
    assert outcome.outcome == "suppressed" and outcome.finding_id == first.id
    assert store.get_finding(first.id) == before
    assert len(store.list_findings()[0]) == 1
    assert kinds(store, first.id) == ["detected", "state-changed"]


def test_after_a_resolution_a_new_sighting_is_a_new_finding_that_remembers_the_old_one(
    store: UnknownDeviceRepository,
) -> None:
    first = created(store)
    store.transition_state(first.id, expected_evidence_version=ver(store, first.id), to_state="resolved", actor_id=ACTOR, reason="Added to NetBox")
    outcome = store.observe(detection())
    assert outcome.outcome == "created" and outcome.finding_id != first.id
    second = store.get_finding(outcome.finding_id)
    assert second is not None and second.recurrence_of == first.id and second.state == "new"
    old = store.get_finding(first.id)
    assert old is not None and old.state == "resolved"


def test_concurrent_first_sightings_make_exactly_one_finding(
    store: UnknownDeviceRepository,
) -> None:
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: store.observe(detection()), range(8)))
    assert sorted(o.outcome for o in outcomes).count("created") == 1
    assert len({o.finding_id for o in outcomes}) == 1
    rows, total = store.list_findings()
    assert total == 1
    assert rows[0].seen_count == 8


# --- transitions ------------------------------------------------------------------------------------------


@pytest.mark.parametrize(("start", "target"), list(product(STATES, STATES)))
def test_the_lifecycle_is_exactly_the_documented_table(
    store: UnknownDeviceRepository, start: str, target: str
) -> None:
    finding = created(store)
    path = {
        "new": [],
        "acknowledged": ["acknowledged"],
        "investigating": ["acknowledged", "investigating"],
        "resolved": ["resolved"],
        "false-positive": ["false-positive"],
    }[start]
    for step in path:
        store.transition_state(finding.id, expected_evidence_version=ver(store, finding.id), to_state=step, actor_id=ACTOR, reason="because")  # type: ignore[arg-type]
    allowed = target in ALLOWED_TRANSITIONS[start]  # type: ignore[index]
    if allowed:
        moved = store.transition_state(
            finding.id, expected_evidence_version=ver(store, finding.id), to_state=target, actor_id=ACTOR, reason="because"
        )  # type: ignore[arg-type]
        assert moved.state == target
    else:
        with pytest.raises(IllegalTransitionError):
            store.transition_state(finding.id, expected_evidence_version=ver(store, finding.id), to_state=target, actor_id=ACTOR, reason="because")  # type: ignore[arg-type]
        current = store.get_finding(finding.id)
        assert current is not None and current.state == start


def test_a_transition_leaves_an_event_with_both_states_and_the_actor(
    store: UnknownDeviceRepository,
) -> None:
    finding = created(store)
    store.transition_state(finding.id, expected_evidence_version=ver(store, finding.id), to_state="acknowledged", actor_id=ACTOR)
    events = store.list_timeline(finding.id)
    last = events[-1]
    assert (last.kind, last.state_from, last.state_to, last.actor_id) == (
        "state-changed",
        "new",
        "acknowledged",
        ACTOR,
    )
    assert [e.seq for e in events] == [1, 2]


@pytest.mark.parametrize("outcome", ["resolved", "false-positive"])
@pytest.mark.parametrize("reason", [None, "", "   ", "x" * 1001])
def test_a_resolution_or_dismissal_needs_a_real_reason(
    store: UnknownDeviceRepository, outcome: str, reason: str | None
) -> None:
    finding = created(store)
    with pytest.raises(InvalidOperationError):
        store.transition_state(finding.id, expected_evidence_version=ver(store, finding.id), to_state=outcome, actor_id=ACTOR, reason=reason)  # type: ignore[arg-type]
    current = store.get_finding(finding.id)
    assert current is not None and current.state == "new"


def test_the_reason_is_stored_verbatim_as_data(store: UnknownDeviceRepository) -> None:
    finding = created(store)
    store.transition_state(finding.id, expected_evidence_version=ver(store, finding.id), to_state="resolved", actor_id=ACTOR, reason=HOSTILE)
    assert store.list_timeline(finding.id)[-1].reason == HOSTILE


def test_unknown_and_malformed_ids_are_not_found(store: UnknownDeviceRepository) -> None:
    for bad in ("unknown-device-00000000-0000-4000-8000-000000000000", "x", "", "../etc"):
        assert store.get_finding(bad) is None
        with pytest.raises(NotFoundError):
            store.transition_state(
                bad, to_state="acknowledged", actor_id=ACTOR, expected_evidence_version=1
            )
        with pytest.raises(NotFoundError):
            store.set_assignee(bad, assignee_id=ACTOR, actor_id=ACTOR, expected_evidence_version=1)
        with pytest.raises(NotFoundError):
            store.add_comment(bad, actor_id=ACTOR, message="x")
        with pytest.raises(NotFoundError):
            store.list_timeline(bad)


def test_concurrent_acknowledgements_have_exactly_one_winner(
    store: UnknownDeviceRepository,
) -> None:
    finding = created(store)

    def attempt(_: int) -> str:
        try:
            store.transition_state(finding.id, expected_evidence_version=ver(store, finding.id), to_state="acknowledged", actor_id=ACTOR)
        except IllegalTransitionError:
            return "lost"
        return "won"

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))
    assert results.count("won") == 1 and results.count("lost") == 7
    assert kinds(store, finding.id).count("state-changed") == 1


# --- assignment and comments ------------------------------------------------------------------------------


def test_assigning_records_the_assignee_and_unassigning_clears_it(
    store: UnknownDeviceRepository,
) -> None:
    finding = created(store)
    assigned = store.set_assignee(finding.id, expected_evidence_version=ver(store, finding.id), assignee_id="oidc:tech-9", actor_id=ACTOR)
    assert assigned.assignee_id == "oidc:tech-9"
    last = store.list_timeline(finding.id)[-1]
    assert (last.kind, last.subject_id, last.actor_id) == ("assignee-changed", "oidc:tech-9", ACTOR)
    cleared = store.set_assignee(finding.id, expected_evidence_version=ver(store, finding.id), assignee_id=None, actor_id=ACTOR)
    assert cleared.assignee_id is None
    assert kinds(store, finding.id).count("assignee-changed") == 2


def test_assigning_the_same_person_again_changes_nothing(store: UnknownDeviceRepository) -> None:
    finding = created(store)
    store.set_assignee(finding.id, expected_evidence_version=ver(store, finding.id), assignee_id=ACTOR, actor_id=ACTOR)
    store.set_assignee(finding.id, expected_evidence_version=ver(store, finding.id), assignee_id=ACTOR, actor_id=ACTOR)
    assert kinds(store, finding.id).count("assignee-changed") == 1


@pytest.mark.parametrize("bad", ["", "   ", "x" * 256])
def test_an_unusable_assignee_is_refused(store: UnknownDeviceRepository, bad: str) -> None:
    finding = created(store)
    with pytest.raises((InvalidOperationError, ValueError)):
        store.set_assignee(finding.id, expected_evidence_version=ver(store, finding.id), assignee_id=bad, actor_id=ACTOR)


@pytest.mark.parametrize("outcome", ["resolved", "false-positive"])
def test_a_finished_finding_cannot_be_reassigned(
    store: UnknownDeviceRepository, outcome: str
) -> None:
    finding = created(store)
    store.transition_state(finding.id, expected_evidence_version=ver(store, finding.id), to_state=outcome, actor_id=ACTOR, reason="done")  # type: ignore[arg-type]
    with pytest.raises(IllegalTransitionError):
        store.set_assignee(finding.id, expected_evidence_version=ver(store, finding.id), assignee_id=ACTOR, actor_id=ACTOR)


def test_a_comment_is_stored_verbatim_and_allowed_even_after_the_finding_is_finished(
    store: UnknownDeviceRepository,
) -> None:
    finding = created(store)
    store.transition_state(finding.id, expected_evidence_version=ver(store, finding.id), to_state="resolved", actor_id=ACTOR, reason="done")
    event = store.add_comment(finding.id, actor_id=ACTOR, message=HOSTILE)
    assert (event.kind, event.message, event.actor_id) == ("comment", HOSTILE, ACTOR)
    assert store.list_timeline(finding.id)[-1] == event


@pytest.mark.parametrize("bad", ["", "   \n", "x" * 4001])
def test_an_unusable_comment_is_refused(store: UnknownDeviceRepository, bad: str) -> None:
    finding = created(store)
    with pytest.raises(InvalidOperationError):
        store.add_comment(finding.id, actor_id=ACTOR, message=bad)


# --- reads --------------------------------------------------------------------------------------------------


def test_the_timeline_is_ordered_and_pages_by_sequence(store: UnknownDeviceRepository) -> None:
    finding = created(store)
    for index in range(5):
        store.add_comment(finding.id, actor_id=ACTOR, message=f"note {index}")
    everything = store.list_timeline(finding.id)
    assert [e.seq for e in everything] == [1, 2, 3, 4, 5, 6]
    page = store.list_timeline(finding.id, after_seq=2, limit=3)
    assert [e.seq for e in page] == [3, 4, 5]
    assert store.list_timeline(finding.id, after_seq=6) == []


@pytest.mark.parametrize(("after", "limit"), [(-1, 10), (0, 0), (0, 201)])
def test_timeline_bounds_are_enforced(
    store: UnknownDeviceRepository, after: int, limit: int
) -> None:
    finding = created(store)
    with pytest.raises(ValueError):
        store.list_timeline(finding.id, after_seq=after, limit=limit)


def test_the_list_filters_orders_and_counts(store: UnknownDeviceRepository) -> None:
    a = created(store, severity="high", basis="policy-rule")
    b = created(store, mac="aa:bb:cc:00:11:33", ip="10.0.5.10", severity="low", basis="policy-rule")
    c = created(
        store, mac="aa:bb:cc:00:11:44", ip="10.0.5.11", severity="unknown", basis="no-policy"
    )
    store.transition_state(b.id, expected_evidence_version=ver(store, b.id), to_state="acknowledged", actor_id=ACTOR)
    store.set_assignee(b.id, expected_evidence_version=ver(store, b.id), assignee_id=ACTOR, actor_id=ACTOR)
    store.transition_state(c.id, expected_evidence_version=ver(store, c.id), to_state="false-positive", actor_id=ACTOR, reason="lab")

    rows, total = store.list_findings()
    assert total == 3
    assert [r.id for r in rows] == sorted(
        (r.id for r in rows),
        key=lambda i: (-next(x for x in rows if x.id == i).last_seen_at.timestamp(), i),
    )
    open_rows, open_total = store.list_findings(states=["new", "acknowledged", "investigating"])
    assert open_total == 2 and {r.id for r in open_rows} == {a.id, b.id}
    assert store.list_findings(states=["false-positive"])[1] == 1
    assert [r.id for r in store.list_findings(severity="high")[0]] == [a.id]
    assert [r.id for r in store.list_findings(assigned=True)[0]] == [b.id]
    assert {r.id for r in store.list_findings(assigned=False)[0]} == {a.id, c.id}


def test_list_paging_is_bounded(store: UnknownDeviceRepository) -> None:
    for index in range(5):
        created(store, mac=f"aa:bb:cc:00:11:{index:02x}", ip=f"10.0.6.{index}")
    page, total = store.list_findings(limit=2, offset=2)
    assert total == 5 and len(page) == 2
    for limit, offset in ((0, 0), (51, 0), (10, -1)):
        with pytest.raises(ValueError):
            store.list_findings(limit=limit, offset=offset)


def test_counts_cover_state_severity_and_open(store: UnknownDeviceRepository) -> None:
    a = created(store, severity="high", basis="policy-rule")
    created(store, mac="aa:bb:cc:00:11:33", ip="10.0.5.10", severity="high", basis="policy-rule")
    c = created(
        store, mac="aa:bb:cc:00:11:44", ip="10.0.5.11", severity="unknown", basis="no-policy"
    )
    store.transition_state(a.id, expected_evidence_version=ver(store, a.id), to_state="acknowledged", actor_id=ACTOR)
    store.transition_state(c.id, expected_evidence_version=ver(store, c.id), to_state="resolved", actor_id=ACTOR, reason="done")
    counts = store.counts()
    assert counts.open == 2
    assert {r.state: r.count for r in counts.by_state} == {
        "new": 1,
        "acknowledged": 1,
        "resolved": 1,
    }
    assert {r.severity: r.count for r in counts.by_severity} == {"high": 2, "unknown": 1}


def test_an_empty_store_has_empty_counts_and_lists(store: UnknownDeviceRepository) -> None:
    assert store.list_findings() == ([], 0)
    counts = store.counts()
    assert (counts.open, counts.by_state, counts.by_severity) == (0, [], [])


def test_returned_models_are_copies(store: UnknownDeviceRepository) -> None:
    finding = created(store)
    finding.endpoint.hostname = "mutated"  # type: ignore[misc]
    again = store.get_finding(finding.id)
    assert again is not None and again.endpoint.hostname == "printer-x"


def test_an_endpoint_with_only_a_name_is_still_tracked(store: UnknownDeviceRepository) -> None:
    finding = created(store, ip=None, mac=None, hostname="Printer-X.Example")
    assert finding.endpoint.hostname == "Printer-X.Example"
    again = store.observe(detection(ip=None, mac=None, hostname="Printer-X.Example"))
    assert again.outcome == "refreshed" and again.finding_id == finding.id


def test_unknown_hops_are_kept_unknown_and_never_filled_in(store: UnknownDeviceRepository) -> None:
    finding = created(store)
    assert [s.basis for s in finding.chain] == [
        "observed",
        "observed",
        "unknown",
        "unknown",
        "unknown",
    ]
    assert finding.chain[2].reason == "source-unavailable" and finding.chain[2].value is None


def test_an_observation_with_a_chain_the_contract_refuses_cannot_be_built() -> None:
    with pytest.raises(ValueError):
        # a MAC slot that disagrees with the endpoint it belongs to
        endpoint = UnknownDeviceEndpoint(ip=IP, mac=MAC, hostname=None)
        Detection(
            subject_key=subject_key_for(endpoint),
            endpoint=endpoint,
            chain=(
                observed("ip", IP),
                observed("mac", "aa:bb:cc:00:11:99"),
                unknown("attachment"),
                unknown("port"),
                unknown("vlan"),
            ),
            comparison=comparison(),
            severity="low",
            severity_basis="policy-default",
        )


# --- evidence versions (database review H2) -----------------------------------------------------------------------


def test_a_new_finding_starts_at_evidence_version_one(store: UnknownDeviceRepository) -> None:
    assert created(store).evidence_version == 1


def test_a_sighting_that_changes_nothing_does_not_move_the_evidence_version(
    store: UnknownDeviceRepository,
) -> None:
    first = created(store)
    for _ in range(3):
        store.observe(detection())
    assert ver(store, first.id) == 1


def test_changed_evidence_moves_the_evidence_version_by_one(store: UnknownDeviceRepository) -> None:
    first = created(store)
    store.observe(detection(port=True))
    assert ver(store, first.id) == 2


def test_assigning_acknowledging_and_commenting_do_not_move_the_evidence_version(
    store: UnknownDeviceRepository,
) -> None:
    first = created(store)
    store.set_assignee(first.id, assignee_id=ACTOR, actor_id=ACTOR, expected_evidence_version=1)
    store.transition_state(
        first.id, to_state="acknowledged", actor_id=ACTOR, expected_evidence_version=1
    )
    store.add_comment(first.id, actor_id=ACTOR, message="looking")
    assert ver(store, first.id) == 1


def test_a_decision_taken_on_stale_evidence_loses_with_stale_evidence(
    store: UnknownDeviceRepository,
) -> None:
    first = created(store)
    store.observe(detection(port=True))  # the evidence moved on while the person was reading
    with pytest.raises(StaleEvidenceError):
        store.transition_state(
            first.id,
            to_state="false-positive",
            actor_id=ACTOR,
            reason="lab",
            expected_evidence_version=1,
        )
    with pytest.raises(StaleEvidenceError):
        store.set_assignee(first.id, assignee_id=ACTOR, actor_id=ACTOR, expected_evidence_version=1)
    current = store.get_finding(first.id)
    assert current is not None and current.state == "new" and current.assignee_id is None
    assert kinds(store, first.id) == ["detected", "evidence-updated"]
    moved = store.transition_state(
        first.id,
        to_state="false-positive",
        actor_id=ACTOR,
        reason="lab",
        expected_evidence_version=2,
    )
    assert moved.state == "false-positive"


def test_stale_evidence_is_a_kind_of_conflict_the_routes_already_map_to_409() -> None:
    assert issubclass(StaleEvidenceError, StorageConflictError)


def test_a_future_version_is_not_accepted_either(store: UnknownDeviceRepository) -> None:
    first = created(store)
    with pytest.raises(StaleEvidenceError):
        store.transition_state(
            first.id, to_state="acknowledged", actor_id=ACTOR, expected_evidence_version=9
        )


# --- identity: the MAC is authoritative, every key of one endpoint counts (database review M1) -------------------------


def dismiss(store: UnknownDeviceRepository, finding_id: str) -> None:
    store.transition_state(
        finding_id,
        to_state="false-positive",
        actor_id=ACTOR,
        reason="lab",
        expected_evidence_version=ver(store, finding_id),
    )


def test_a_dismissal_on_a_mac_also_suppresses_the_same_endpoint_seen_by_address_only(
    store: UnknownDeviceRepository,
) -> None:
    first = created(store)
    dismiss(store, first.id)
    outcome = store.observe(detection(mac=None))  # same address, MAC not resolved this time
    assert (outcome.outcome, outcome.finding_id) == ("suppressed", first.id)
    assert store.list_findings()[1] == 1


def test_a_dismissal_on_an_address_also_suppresses_it_once_its_mac_is_known(
    store: UnknownDeviceRepository,
) -> None:
    first = created(store, mac=None)
    dismiss(store, first.id)
    outcome = store.observe(detection())
    assert (outcome.outcome, outcome.finding_id) == ("suppressed", first.id)


def test_an_open_finding_opened_by_address_is_found_again_when_the_mac_appears(
    store: UnknownDeviceRepository,
) -> None:
    first = created(store, mac=None)
    outcome = store.observe(detection())
    assert (outcome.outcome, outcome.finding_id) == ("refreshed", first.id)
    updated = store.get_finding(first.id)
    assert updated is not None and updated.endpoint.mac == MAC
    assert store.list_findings()[1] == 1


def test_a_different_mac_at_the_same_address_is_a_different_endpoint(
    store: UnknownDeviceRepository,
) -> None:
    first = created(store)
    other = store.observe(detection(mac="aa:bb:cc:00:11:99"))
    assert other.outcome == "created" and other.finding_id != first.id


def test_a_dismissed_mac_does_not_suppress_a_different_mac_that_took_its_address(
    store: UnknownDeviceRepository,
) -> None:
    first = created(store)
    dismiss(store, first.id)
    assert store.observe(detection(mac="aa:bb:cc:00:11:99")).outcome == "created"


def test_known_subject_keys_names_the_keys_that_have_a_finding(
    store: UnknownDeviceRepository,
) -> None:
    created(store)
    asked = [f"mac:{MAC}", "mac:aa:bb:cc:00:00:00", f"ip:{IP}"]
    assert store.known_subject_keys(asked) == {f"mac:{MAC}"}
    assert store.known_subject_keys([]) == set()


# --- dismissals expire and a changed dismissed endpoint is noticed (security M3) ---------------------------------------------


def test_a_dismissal_expires_and_the_next_sighting_is_a_new_finding_for_review(
    timed: tuple[UnknownDeviceRepository, FakeClock],
) -> None:
    store, clock = timed
    first = created(store)
    dismiss(store, first.id)
    assert store.observe(detection()).outcome == "suppressed"
    clock.current += timedelta(days=11)
    outcome = store.observe(detection())
    assert outcome.outcome == "created" and outcome.finding_id != first.id
    again = store.get_finding(outcome.finding_id)
    assert again is not None and again.recurrence_of == first.id and again.state == "new"


def test_a_dismissal_that_has_not_expired_keeps_suppressing(
    timed: tuple[UnknownDeviceRepository, FakeClock],
) -> None:
    store, clock = timed
    first = created(store)
    dismiss(store, first.id)
    clock.current += timedelta(days=9)
    assert store.observe(detection()).outcome == "suppressed"


def test_a_dismissed_endpoint_seen_with_different_evidence_leaves_a_suppressed_sighting(
    timed: tuple[UnknownDeviceRepository, FakeClock],
) -> None:
    store, clock = timed
    first = created(store)
    dismiss(store, first.id)
    assert store.observe(detection(port=True)).outcome == "suppressed"
    assert kinds(store, first.id) == ["detected", "state-changed", "suppressed-sighting"]
    # at most one a day, however often it is seen
    store.observe(detection(port=True))
    clock.current += timedelta(hours=3)
    store.observe(detection(port=True))
    assert kinds(store, first.id).count("suppressed-sighting") == 1
    clock.current += timedelta(hours=22)
    store.observe(detection(port=True))
    assert kinds(store, first.id).count("suppressed-sighting") == 2
    last = store.list_timeline(first.id)[-1]
    assert (last.kind, last.actor_id, last.state_from) == ("suppressed-sighting", SYSTEM_ACTOR, None)
    finding = store.get_finding(first.id)
    assert finding is not None and finding.state == "false-positive"  # the dismissal is untouched


def test_a_dismissed_endpoint_seen_unchanged_writes_nothing_at_all(
    store: UnknownDeviceRepository,
) -> None:
    first = created(store)
    dismiss(store, first.id)
    for _ in range(3):
        store.observe(detection())
    assert kinds(store, first.id) == ["detected", "state-changed"]


# --- evidence snapshots are rate limited (database review M5) ---------------------------------------------------------------


def test_a_second_evidence_change_within_the_hour_is_not_snapshotted_again(
    timed: tuple[UnknownDeviceRepository, FakeClock],
) -> None:
    store, clock = timed
    first = created(store)
    store.observe(detection(port=True))  # recorded: the first change
    assert (ver(store, first.id), kinds(store, first.id)) == (2, ["detected", "evidence-updated"])
    clock.current += timedelta(minutes=10)
    outcome = store.observe(detection(ip="10.0.5.77", port=True))  # churn: a new DHCP address
    assert outcome.outcome == "refreshed"
    held = store.get_finding(first.id)
    assert held is not None and held.endpoint.ip == IP  # not yet applied
    assert held.seen_count == 3 and ver(store, first.id) == 2
    assert kinds(store, first.id) == ["detected", "evidence-updated"]
    clock.current += timedelta(hours=1)
    store.observe(detection(ip="10.0.5.77", port=True))
    moved = store.get_finding(first.id)
    assert moved is not None and moved.endpoint.ip == "10.0.5.77" and ver(store, first.id) == 3
    assert kinds(store, first.id).count("evidence-updated") == 2


def test_a_severity_change_is_recorded_at_once_whatever_the_rate_limit(
    store: UnknownDeviceRepository,
) -> None:
    first = created(store)
    store.observe(detection(port=True))
    store.observe(detection(port=True, severity="critical", basis="policy-rule", with_action=True))
    updated = store.get_finding(first.id)
    assert updated is not None and updated.severity == "critical" and updated.evidence_version == 3
    assert kinds(store, first.id) == [
        "detected",
        "evidence-updated",
        "evidence-updated",
        "action-proposed",
    ]


def test_a_changed_netbox_verdict_is_recorded_at_once(store: UnknownDeviceRepository) -> None:
    first = created(store)
    store.observe(detection(port=True))
    store.observe(
        detection(
            port=True,
            reason="name-matches-mac-does-not",
            results={"hostname": "match"},
            severity="low",
        )
    )
    assert ver(store, first.id) == 3


# --- times only move forward (database review M2) -----------------------------------------------------------------------------


def test_a_clock_that_steps_back_never_rewinds_a_finding(
    timed: tuple[UnknownDeviceRepository, FakeClock],
) -> None:
    store, clock = timed
    first = created(store)
    before = store.get_finding(first.id)
    assert before is not None
    clock.current -= timedelta(hours=1)  # a worker with a slow clock sees the same endpoint
    store.observe(detection())
    after = store.get_finding(first.id)
    assert after is not None and after.seen_count == 2
    assert after.last_seen_at >= before.last_seen_at


# --- paging is bounded (database review M3) -----------------------------------------------------------------------------------


def test_a_page_beyond_the_offset_cap_is_refused(store: UnknownDeviceRepository) -> None:
    store.list_findings(limit=50, offset=10_000)
    with pytest.raises(ValueError):
        store.list_findings(limit=50, offset=10_001)


def test_a_state_filter_outside_the_closed_set_is_refused(store: UnknownDeviceRepository) -> None:
    with pytest.raises(ValueError):
        store.list_findings(states=["new' OR '1'='1"])  # type: ignore[list-item]
