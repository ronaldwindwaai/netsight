"""The action request lifecycle and its invariants (Step 12): approval rules, replay, TOCTOU, expiry,
idempotency, the target lock and the append-only hash-chained history.

One suite, every implementation: each test runs against the in-memory store and, with
``NETSIGHT_TEST_PG_DSN``, the PostgreSQL store as the schema owner and as the least-privilege application
role (a throwaway schema per test, migrated and granted by the runner). The two tests that reach into the
in-memory records say so with ``memory_only``; their PostgreSQL counterparts are in
``test_actions_store_postgres``.
"""

from __future__ import annotations

import itertools
import logging
import threading
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from datetime import timedelta
from typing import Any

import actions_support
import pytest
from actions_support import (
    ALICE,
    BOB,
    CAROL,
    NOW,
    ROBOT,
    new_action,
    new_store,
    two_person,
)
from pg_support import PG_DSN, app_role, isolated_schema, requires_pg

from netsight_api.actions import errors as e
from netsight_api.actions.history import ZERO_HASH, verify_chain
from netsight_api.actions.killswitch import KillSwitch
from netsight_api.actions.model import ExecutionFinish
from netsight_api.actions.store import EVICT_MIN_AGE_SECONDS, ActionStore
from netsight_api.schemas_actions import (
    ALLOWED_TRANSITIONS,
    ActionRequest,
    ActionRollback,
    ActionVerification,
)
from netsight_api.storage import migrate
from netsight_api.storage.connection import PostgresSettings

KEY = "idem-key-0000000001"
LATER = NOW + timedelta(seconds=EVICT_MIN_AGE_SECONDS + 1)
_keys = itertools.count(1)


@pytest.fixture(
    autouse=True,
    params=[
        "memory",
        pytest.param("postgres", marks=requires_pg),
        pytest.param("postgres-app-role", marks=requires_pg),
    ],
)
def backend(request: pytest.FixtureRequest) -> Iterator[str]:
    """memory; PostgreSQL as the schema owner; PostgreSQL as the least-privilege application role."""
    if request.param == "memory":
        actions_support.use_backend("memory")
        yield "memory"
        return
    assert PG_DSN
    with ExitStack() as stack:
        schema = stack.enter_context(isolated_schema())
        owner = PostgresSettings(dsn=PG_DSN, schema=schema)
        runtime = owner
        role = ""
        if request.param == "postgres-app-role":
            role, role_dsn = stack.enter_context(app_role())
            runtime = PostgresSettings(dsn=role_dsn, schema=schema)
        with owner.connect() as conn:
            migrate.apply_up(conn)
            if role:
                migrate.apply_grants(conn, role)
        actions_support.use_backend("postgres", runtime)
        try:
            yield request.param
        finally:
            actions_support.use_backend("memory")


def memory_only[F: Callable[..., Any]](test: F) -> F:
    """The test reaches into the in-memory store's records, which no other implementation has."""
    return pytest.mark.usefixtures("require_memory")(test)  # type: ignore[no-any-return]


@pytest.fixture
def require_memory(backend: str) -> None:
    if backend != "memory":
        pytest.skip(
            "pokes at the in-memory records; the PostgreSQL tamper tests are in test_actions_store_postgres"
        )


def next_key() -> str:
    return f"idem-key-{next(_keys):012d}"


def make(store: ActionStore, now: Any = NOW, **overrides: Any) -> ActionRequest:
    return store.create(new_action(**overrides), idempotency_key=next_key(), now=now).request


def approve(store: ActionStore, request: ActionRequest, who: Any = BOB, **kw: Any) -> ActionRequest:
    return store.approve(
        request.id,
        approver=who,
        expected_digest=kw.get("digest", request.digest),
        expected_version=kw.get("version", request.version),
        now=kw.get("now", NOW),
    )


def approved(store: ActionStore) -> ActionRequest:
    return approve(store, make(store))


def begin(
    store: ActionStore, request: ActionRequest, key: str = "exec-key-000000001", **kw: Any
) -> Any:
    return store.begin_execution(
        request.id,
        actor=kw.get("actor", BOB),
        expected_digest=request.digest,
        expected_version=kw.get("version", request.version),
        idempotency_key=key,
        executor_id="dry-run",
        mode="dry-run",
        steps=["Would do the thing"],
        now=kw.get("now", NOW),
    )


def finish(final: str = "succeeded", **kw: Any) -> ExecutionFinish:
    return ExecutionFinish(
        final_state=final,  # type: ignore[arg-type]
        effect="none",
        failure=kw.get("failure"),
        verification=ActionVerification(state="not-applicable", detail="dry-run"),
        rollback=kw.get("rollback"),
        events=kw.get("events", (("executed", "dry-run-recorded"),)),
        finished_at=kw.get("finished_at", NOW + timedelta(seconds=1)),
    )


# --- creation ---------------------------------------------------------------------------------------------


def test_a_new_request_is_pending_approval_with_a_three_event_chain() -> None:
    store = new_store()
    request = make(store)
    assert request.state == "pending-approval"
    assert request.version == 3
    assert request.approvals == [] and request.execution is None and request.execute_by is None
    events = store.history(request.id)
    assert [x.type for x in events] == ["proposed", "policy-checked", "submitted"]
    assert [x.seq for x in events] == [1, 2, 3]
    assert events[0].prev_hash == ZERO_HASH
    assert store.verify_chain(request.id) is True


def test_the_digest_binds_the_content_and_ignores_state() -> None:
    store = new_store()
    first = make(store)
    approved_request = approve(store, first)
    assert approved_request.digest == first.digest  # state changes, content does not
    other = make(store, reason="A different reason entirely")
    assert other.digest != first.digest


def test_the_same_idempotency_key_and_body_return_the_first_request() -> None:
    store = new_store()
    new = new_action()
    first = store.create(new, idempotency_key=KEY, now=NOW)
    again = store.create(
        new_action(**{**vars(new), "id": "action-ffffffff-0000-4000-8000-000000000000"}),
        idempotency_key=KEY,
        now=NOW,
    )
    assert first.replayed is False and again.replayed is True
    assert again.request.id == first.request.id
    assert store.list_requests(limit=50, offset=0, now=NOW)[1] == 1


def test_the_same_idempotency_key_with_a_different_body_is_a_conflict() -> None:
    store = new_store()
    store.create(new_action(), idempotency_key=KEY, now=NOW)
    with pytest.raises(e.IdempotencyConflict):
        store.create(new_action(reason="Changed my mind about why"), idempotency_key=KEY, now=NOW)


def test_idempotency_keys_are_scoped_to_the_requester() -> None:
    store = new_store()
    a = store.create(new_action(), idempotency_key=KEY, now=NOW)
    b = store.create(new_action(requester=BOB), idempotency_key=KEY, now=NOW)
    assert a.request.id != b.request.id and b.replayed is False


def test_only_one_open_request_per_action_and_target() -> None:
    store = new_store()
    store.create(new_action(target_id="endpoint:dup"), idempotency_key=next_key(), now=NOW)
    with pytest.raises(e.DuplicateOpenRequest):
        store.create(
            new_action(target_id="endpoint:dup", requester=BOB), idempotency_key=next_key(), now=NOW
        )


def test_a_requester_has_a_cap_on_open_requests_and_the_store_a_cap_in_total() -> None:
    store = new_store(max_open_per_requester=2, max_stored=3)
    store.create(new_action(), idempotency_key=KEY + "1", now=NOW)
    store.create(new_action(), idempotency_key=KEY + "2", now=NOW)
    with pytest.raises(e.TooManyOpenRequests):
        store.create(new_action(), idempotency_key=KEY + "3", now=NOW)
    store.create(new_action(requester=BOB), idempotency_key=KEY + "4", now=NOW)
    with pytest.raises(e.StoreFull):
        store.create(new_action(requester=CAROL), idempotency_key=KEY + "5", now=NOW)


def test_a_service_or_ai_requester_may_propose_and_is_recorded_as_such() -> None:
    store = new_store()
    request = make(store, requester=ROBOT)
    assert request.requester.kind == "ai"
    assert request.state == "pending-approval"


# --- approval ----------------------------------------------------------------------------------------------


def test_one_approval_approves_a_single_approver_request_and_sets_the_execution_deadline() -> None:
    store = new_store()
    request = make(store)
    result = approve(store, request)
    assert result.state == "approved"
    assert [a.approver_id for a in result.approvals] == ["bob"]
    assert result.execute_by == NOW + timedelta(seconds=3600)
    assert result.version == request.version + 1
    assert store.history(request.id)[-1].type == "approved"


def test_a_requester_can_never_approve_their_own_request() -> None:
    store = new_store()
    request = make(store)
    with pytest.raises(e.SelfApproval):
        approve(store, request, who=ALICE)
    assert store.get(request.id) == request  # nothing changed
    assert len(store.history(request.id)) == 3


def test_a_non_human_approver_is_refused_even_if_the_caller_forgot_to_check() -> None:
    store = new_store()
    request = make(store)
    with pytest.raises(e.ApproverNotHuman):
        approve(store, request, who=ROBOT)


def test_an_approval_quoting_a_stale_digest_or_version_is_refused() -> None:
    store = new_store()
    request = make(store)
    with pytest.raises(e.StaleRequest):
        approve(store, request, digest="sha256:" + "0" * 64)
    with pytest.raises(e.StaleRequest):
        approve(store, request, version=request.version - 1)
    with pytest.raises(e.StaleRequest):
        approve(store, request, version=request.version + 1)
    assert store.get(request.id).state == "pending-approval"  # type: ignore[union-attr]


def test_a_replayed_approval_is_refused_once_the_request_has_moved_on() -> None:
    store = new_store()
    request = make(store)
    approve(store, request)
    with pytest.raises(e.StaleRequest):
        approve(store, request, who=CAROL)  # the version they saw is gone
    with pytest.raises(e.IllegalTransition):
        approve(store, store.get(request.id), who=CAROL)  # type: ignore[arg-type]


def test_two_person_requests_need_two_distinct_approvers_neither_the_requester() -> None:
    store = new_store()
    request = make(store, **{k: v for k, v in vars(two_person()).items() if k != "id"})
    first = approve(store, request, BOB)
    assert first.state == "pending-approval" and len(first.approvals) == 1
    with pytest.raises(e.AlreadyApproved):
        approve(store, first, BOB)
    with pytest.raises(e.SelfApproval):
        approve(store, first, ALICE)
    with pytest.raises(e.StaleRequest):
        approve(store, request, CAROL)  # CAROL did not see BOB's approval
    second = approve(store, first, CAROL)
    assert second.state == "approved"
    assert {a.approver_id for a in second.approvals} == {"bob", "carol"}
    assert second.execute_by is not None


def test_concurrent_approvals_of_one_request_record_exactly_one() -> None:
    store = new_store()
    request = make(store)
    outcomes: list[str] = []
    barrier = threading.Barrier(8)

    def worker(index: int) -> None:
        barrier.wait()
        try:
            approve(store, request, who=BOB.model_copy(update={"id": f"approver-{index}"}))
            outcomes.append("ok")
        except e.ActionError as exc:
            outcomes.append(exc.code)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count("ok") == 1
    assert len(store.get(request.id).approvals) == 1  # type: ignore[union-attr]
    assert store.verify_chain(request.id)


def test_concurrent_double_approval_by_one_person_records_one() -> None:
    store = new_store()
    request = make(store, **{k: v for k, v in vars(two_person()).items() if k != "id"})
    outcomes: list[str] = []
    barrier = threading.Barrier(6)

    def worker() -> None:
        barrier.wait()
        try:
            approve(store, request, BOB)
            outcomes.append("ok")
        except e.ActionError as exc:
            outcomes.append(exc.code)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count("ok") == 1
    assert len(store.get(request.id).approvals) == 1  # type: ignore[union-attr]


# --- rejection, cancellation, expiry ----------------------------------------------------------------------


def test_reject_and_cancel_record_the_note_and_are_final() -> None:
    store = new_store()
    request = make(store)
    rejected = store.reject(
        request.id,
        actor=BOB,
        expected_digest=request.digest,
        expected_version=request.version,
        reason="Not justified",
        now=NOW,
    )
    assert rejected.state == "rejected"
    assert store.history(request.id)[-1].note == "Not justified"
    with pytest.raises(e.IllegalTransition):
        approve(store, rejected)
    other = make(store)
    cancelled = store.cancel(
        other.id,
        actor=ALICE,
        expected_digest=other.digest,
        expected_version=other.version,
        reason="Mistake",
        now=NOW,
    )
    assert cancelled.state == "cancelled"
    with pytest.raises(e.IllegalTransition):
        store.cancel(
            other.id,
            actor=ALICE,
            expected_digest=other.digest,
            expected_version=cancelled.version,
            reason="Again",
            now=NOW,
        )


def test_an_unapproved_request_expires_and_cannot_then_be_approved() -> None:
    store = new_store()
    request = make(store)
    late = request.approve_by + timedelta(seconds=1)
    with pytest.raises(e.ApprovalExpired):
        approve(store, request, now=late)
    assert store.get(request.id).state == "expired"  # type: ignore[union-attr]
    assert store.history(request.id)[-1].type == "expired"
    assert store.history(request.id)[-1].actor_id is None


def test_expire_due_sweeps_everything_open_and_past_its_deadline() -> None:
    store = new_store()
    a = make(store)
    b = approved(store)
    swept = store.expire_due(a.approve_by + timedelta(seconds=1))
    assert swept == 2
    assert store.get(a.id).state == "expired"  # type: ignore[union-attr]
    assert store.get(b.id).state == "expired"  # type: ignore[union-attr]
    assert store.expire_due(NOW + timedelta(days=30)) == 0


def test_listing_applies_expiry_and_filters_by_state() -> None:
    store = new_store()
    request = make(store)
    items, total = store.list_requests(state="pending-approval", limit=10, offset=0, now=NOW)
    assert [i.id for i in items] == [request.id] and total == 1
    items, total = store.list_requests(
        state="pending-approval", limit=10, offset=0, now=request.approve_by + timedelta(seconds=1)
    )
    assert items == [] and total == 0


# --- execution ---------------------------------------------------------------------------------------------


def test_execution_needs_an_approved_request_and_the_exact_digest_and_version() -> None:
    store = new_store()
    pending = make(store)
    with pytest.raises(e.IllegalTransition):
        begin(store, pending)
    ready = approve(store, pending)
    with pytest.raises(e.StaleRequest):
        begin(store, ready, version=ready.version - 1)
    started = begin(store, ready)
    assert started.replayed is False
    assert started.request.state == "executing"
    assert started.request.execution is not None and started.request.execution.mode == "dry-run"
    assert started.request.execution.finished_at is None


def test_the_same_execution_key_never_runs_twice() -> None:
    store = new_store()
    ready = approved(store)
    first = begin(store, ready, "exec-key-000000001")
    again = begin(store, first.request, "exec-key-000000001")
    assert again.replayed is True and again.request.id == first.request.id
    with pytest.raises(e.IllegalTransition):
        begin(store, first.request, "exec-key-000000002")  # another key cannot start a second run
    store.finish_execution(ready.id, finish(), now=NOW)
    after = begin(store, store.get(ready.id), "exec-key-000000001")  # type: ignore[arg-type]
    assert after.replayed is True and after.request.state == "succeeded"
    with pytest.raises(e.IllegalTransition):
        begin(store, store.get(ready.id), "exec-key-000000009")  # type: ignore[arg-type]


def test_concurrent_executions_of_one_request_start_exactly_one() -> None:
    store = new_store()
    ready = approved(store)
    outcomes: list[str] = []
    barrier = threading.Barrier(6)

    def worker(index: int) -> None:
        barrier.wait()
        try:
            begin(store, ready, f"exec-key-{index:010d}")
            outcomes.append("ok")
        except e.ActionError as exc:
            outcomes.append(exc.code)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count("ok") == 1


def test_a_target_already_being_executed_is_locked_across_action_types() -> None:
    store = new_store()
    disable = make(
        store,
        action_type="switch.port.disable",
        target_id="interface:sw1-gi0-9",
        params={},
        risk="D",
        approvals_required=1,
    )
    enable = make(
        store,
        action_type="switch.port.enable",
        target_id="interface:sw1-gi0-9",
        params={},
        risk="B",
        requester=CAROL,
    )
    disable, enable = approve(store, disable), approve(store, enable)
    begin(store, disable, "exec-key-aaaaaaaaaa")
    with pytest.raises(e.TargetLocked):
        begin(store, enable, "exec-key-bbbbbbbbbb")
    store.finish_execution(disable.id, finish(), now=NOW)
    assert begin(store, enable, "exec-key-bbbbbbbbbb").request.state == "executing"  # released


def test_an_approved_request_not_executed_in_time_expires() -> None:
    store = new_store()
    ready = approved(store)
    with pytest.raises(e.ApprovalExpired):
        begin(store, ready, now=ready.execute_by + timedelta(seconds=1))  # type: ignore[operator]
    assert store.get(ready.id).state == "expired"  # type: ignore[union-attr]


@pytest.mark.parametrize("final", ["succeeded", "failed", "rolled-back"])
def test_finishing_an_execution_records_the_outcome_and_closes_the_request(final: str) -> None:
    store = new_store()
    ready = approved(store)
    begin(store, ready)
    extra: dict[str, Any] = {}
    if final == "failed":
        extra = {"failure": "executor-error", "events": (("failed", "executor-error"),)}
    if final == "rolled-back":
        extra = {
            "rollback": ActionRollback(state="completed", detail="ok"),
            "events": (("verification-failed", "mismatch"), ("rolled-back", "rollback-done")),
        }
    done = store.finish_execution(ready.id, finish(final, **extra), now=NOW)
    assert done.state == final
    assert done.execution is not None and done.execution.finished_at is not None
    assert done.execution.effect == "none"
    assert store.verify_chain(ready.id)
    with pytest.raises(e.IllegalTransition):
        store.finish_execution(ready.id, finish(final), now=NOW)  # cannot finish twice


def test_a_dry_run_execution_cannot_be_recorded_as_having_changed_something() -> None:
    store = new_store()
    ready = approved(store)
    begin(store, ready)
    bad = ExecutionFinish(
        final_state="succeeded",
        effect="applied",
        failure=None,
        verification=ActionVerification(state="passed", detail="ok"),
        rollback=None,
        events=(("executed", "applied"),),
        finished_at=NOW,
    )
    with pytest.raises(e.InvalidOutcome):
        store.finish_execution(ready.id, bad, now=NOW)


def test_an_execution_that_never_finishes_is_failed_by_the_sweep() -> None:
    store = new_store()
    ready = approved(store)
    begin(store, ready)
    assert store.expire_due(NOW + timedelta(seconds=1)) == 0
    assert store.expire_due(NOW + timedelta(seconds=30 + 61)) == 1
    done = store.get(ready.id)
    assert done is not None and done.state == "failed"
    assert done.execution is not None and done.execution.failure == "executor-timeout"


def test_every_move_the_store_makes_is_in_the_transition_table() -> None:
    store = new_store()
    request = make(store)
    ready = approve(store, request)
    begin(store, ready)
    store.finish_execution(ready.id, finish(), now=NOW)
    states = [
        (x.from_state, x.to_state) for x in store.history(ready.id) if x.from_state != x.to_state
    ]
    for source, target in states:
        if source is not None:
            assert target in ALLOWED_TRANSITIONS[source]


# --- kill switch -------------------------------------------------------------------------------------------


def test_the_kill_switch_stops_new_proposals_approvals_and_executions_but_not_cancel_or_reads() -> (
    None
):
    kill = KillSwitch()
    store = new_store(kill_switch=kill)
    pending = make(store)
    ready = approved(store)
    kill.engage(NOW)
    with pytest.raises(e.KillSwitchEngaged):
        make(store)
    with pytest.raises(e.KillSwitchEngaged):
        approve(store, pending, CAROL)
    with pytest.raises(e.KillSwitchEngaged):
        begin(store, ready)
    assert store.get(pending.id) is not None
    cancelled = store.cancel(
        pending.id,
        actor=ALICE,
        expected_digest=pending.digest,
        expected_version=pending.version,
        reason="Stopping",
        now=NOW,
    )
    assert cancelled.state == "cancelled"
    kill.release()
    assert begin(store, ready).request.state == "executing"


def test_the_environment_kill_switch_cannot_be_released_at_runtime() -> None:
    kill = KillSwitch(env_engaged=True)
    assert kill.status().engaged and kill.status().source == "environment"
    with pytest.raises(e.KillSwitchLocked):
        kill.release()
    assert kill.engaged


def test_a_runtime_switch_reports_its_source_and_time() -> None:
    kill = KillSwitch()
    assert kill.status().engaged is False and kill.status().source == "none"
    kill.engage(NOW)
    status = kill.status()
    assert status.engaged and status.source == "runtime" and status.since == NOW
    kill.release()
    assert kill.status().engaged is False


# --- the history -------------------------------------------------------------------------------------------


def test_a_returned_request_is_a_copy_the_store_does_not_follow() -> None:
    store = new_store()
    request = make(store)
    request.params["duration_minutes"] = 1  # mutate the returned copy
    assert store.get(request.id).params == {"duration_minutes": 60}  # type: ignore[union-attr]
    history = store.history(request.id)
    history.clear()
    assert len(store.history(request.id)) == 3


def test_a_tampered_history_fails_verification() -> None:
    store = new_store()
    request = make(store)
    approve(store, request)
    events = store.history(request.id)
    digest = request.digest
    assert verify_chain(request.id, events, digest)
    edited = [events[0].model_copy(update={"actor_id": "mallory"}), *events[1:]]
    assert not verify_chain(request.id, edited, digest)
    assert not verify_chain(request.id, [events[0], *events[2:]], digest)  # a missing event
    assert not verify_chain(request.id, [events[1], events[0], *events[2:]], digest)  # reordered
    assert not verify_chain(request.id, events[1:], digest)  # a truncated start
    other = "action-ffffffff-0000-4000-8000-000000000000"
    assert not verify_chain(other, events, digest)  # moved to another request
    # The content an approver saw is in every hash: the same events under another digest do not verify.
    assert not verify_chain(request.id, events, "sha256:" + "0" * 64)


def test_the_approvers_on_the_request_are_the_approvers_its_history_records() -> None:
    from netsight_api.actions.history import history_matches

    store = new_store()
    request = approve(store, make(store))
    events = store.history(request.id)
    assert history_matches(request, events)
    swapped = request.model_copy(
        update={"approvals": [request.approvals[0].model_copy(update={"approver_id": "mallory"})]}
    )
    assert not history_matches(swapped, events)
    assert not history_matches(request.model_copy(update={"approvals": []}), events)
    late = request.approvals[0].model_copy(update={"approved_at": NOW + timedelta(days=1)})
    assert not history_matches(request.model_copy(update={"approvals": [late]}), events)


def test_unknown_requests_are_not_found() -> None:
    store = new_store()
    missing = "action-ffffffff-0000-4000-8000-000000000000"
    assert store.get(missing) is None
    with pytest.raises(e.ActionNotFound):
        store.approve(
            missing, approver=BOB, expected_digest="sha256:" + "0" * 64, expected_version=1, now=NOW
        )
    with pytest.raises(e.ActionNotFound):
        store.history(missing)


# --- review fixes: bounded memory, chain consistency, system audit, key binding, lazy expiry -------------------------


def test_terminal_records_are_evicted_oldest_first_so_the_store_cannot_be_exhausted() -> None:
    store = new_store(max_stored=4, max_open_per_requester=10)
    first = make(store)
    second = make(store)
    open_one = make(store)
    open_two = make(store)
    for request in (first, second):
        store.cancel(
            request.id,
            actor=ALICE,
            expected_digest=request.digest,
            expected_version=request.version,
            reason="Stand down",
            now=NOW,
        )
    fresh = make(store, now=LATER)  # the oldest finished record makes room
    assert store.get(first.id) is None
    assert store.get(second.id) is not None
    assert {open_one.id, open_two.id, fresh.id} <= {
        r.id for r in store.list_requests(limit=50, offset=0, now=NOW)[0]
    }


def test_a_propose_and_cancel_loop_never_fills_the_store() -> None:
    store = new_store(max_stored=5, max_open_per_requester=3)
    for hour in range(0, 120, 2):  # each round is old enough to make room for the next
        at = NOW + timedelta(hours=hour)
        request = make(store, now=at, created_at=at, approve_by=at + timedelta(hours=24))
        store.cancel(
            request.id,
            actor=ALICE,
            expected_digest=request.digest,
            expected_version=request.version,
            reason="Loop",
            now=at,
        )
    assert store.list_requests(limit=50, offset=0, now=at)[1] <= 5


def test_a_young_finished_request_is_not_evicted_so_a_loop_cannot_hide_other_records() -> None:
    store = new_store(max_stored=3, max_open_per_requester=10)
    kept = [make(store) for _ in range(2)]
    for request in kept:
        store.cancel(
            request.id,
            actor=ALICE,
            expected_digest=request.digest,
            expected_version=request.version,
            reason="Withdrawn",
            now=NOW,
        )
    make(store)  # the third slot
    with pytest.raises(e.StoreFull):  # the finished ones are younger than the minimum age
        make(store)
    assert all(store.get(r.id) is not None for r in kept)


def test_an_eviction_is_logged_with_the_request_id_only(caplog: pytest.LogCaptureFixture) -> None:
    store = new_store(max_stored=1, max_open_per_requester=10)
    first = make(store)
    store.cancel(
        first.id,
        actor=ALICE,
        expected_digest=first.digest,
        expected_version=first.version,
        reason="A private reason",
        now=NOW,
    )
    with caplog.at_level(logging.WARNING, logger="netsight_api"):
        make(store, now=LATER)
    messages = [r.getMessage() for r in caplog.records]
    assert any(first.id in m and "evicted" in m for m in messages)
    assert not any("A private reason" in m for m in messages)


def test_open_requests_are_never_evicted_and_a_store_full_of_them_is_full() -> None:
    store = new_store(max_stored=2, max_open_per_requester=5)
    a, b = make(store), make(store)
    with pytest.raises(e.StoreFull):
        make(store)
    assert store.get(a.id) is not None and store.get(b.id) is not None


def test_an_evicted_record_takes_its_idempotency_key_with_it() -> None:
    store = new_store(max_stored=2, max_open_per_requester=5)
    body = new_action()
    first = store.create(body, idempotency_key="evict-key-0000000001", now=NOW).request
    store.cancel(
        first.id,
        actor=ALICE,
        expected_digest=first.digest,
        expected_version=first.version,
        reason="Done",
        now=NOW,
    )
    make(store)
    third = make(store, now=LATER)  # the store is full: the finished first record is evicted
    assert store.get(first.id) is None
    store.cancel(
        third.id,
        actor=ALICE,
        expected_digest=third.digest,
        expected_version=third.version,
        reason="Done",
        now=NOW,
    )
    same_body = new_action(target_id=body.target_id)
    again = store.create(same_body, idempotency_key="evict-key-0000000001", now=LATER)
    assert again.replayed is False and again.request.id == same_body.id


@memory_only
def test_the_chain_verdict_also_checks_the_history_matches_the_request() -> None:
    store = new_store()
    request = make(store)
    approve(store, request)
    record = store._records[request.id]
    assert store.verify_chain(request.id)
    record.history.pop()  # the last event vanishes: every remaining link is still valid
    assert store.verify_chain(request.id) is False


@memory_only
def test_a_request_whose_state_disagrees_with_its_history_fails_the_chain_verdict() -> None:
    store = new_store()
    request = make(store)
    record = store._records[request.id]
    record.request = record.request.model_copy(update={"state": "rejected"})
    assert store.verify_chain(request.id) is False


def test_system_transitions_are_reported_so_they_can_be_audited() -> None:
    seen: list[tuple[str, str, str]] = []
    store = new_store(on_system_transition=lambda i, s, c: seen.append((i, s, c)))
    request = make(store)
    store.expire_due(request.approve_by + timedelta(seconds=1))
    assert seen == [(request.id, "expired", "approval-window-closed")]
    ready = approved(store)
    begin(store, ready)
    store.expire_due(NOW + timedelta(seconds=30 + 61))
    assert seen[-1] == (ready.id, "failed", "executor-timeout")


def test_an_execution_key_replays_only_for_the_person_who_started_the_run() -> None:
    store = new_store()
    ready = approved(store)
    begin(store, ready, "exec-key-000000000001")
    with pytest.raises(e.IdempotencyConflict):
        begin(store, ready, "exec-key-000000000001", actor=CAROL)
    assert begin(store, ready, "exec-key-000000000001").replayed is True


def test_expired_requests_stop_blocking_new_work_without_anyone_listing_first() -> None:
    store = new_store(max_open_per_requester=1)
    stale = make(store, target_id="endpoint:blocked")
    late = stale.approve_by + timedelta(seconds=1)
    fresh = store.create(
        new_action(
            target_id="endpoint:blocked", created_at=late, approve_by=late + timedelta(hours=1)
        ),
        idempotency_key=next_key(),
        now=late,
    )
    assert fresh.request.state == "pending-approval"
    assert store.get(stale.id).state == "expired"  # type: ignore[union-attr]


def test_a_timed_out_run_stops_locking_its_target_without_anyone_listing_first() -> None:
    store = new_store()
    first = make(
        store,
        action_type="switch.port.disable",
        target_id="interface:sw1-gi0-7",
        params={},
        risk="D",
        approvals_required=1,
    )
    second = make(
        store,
        action_type="switch.port.enable",
        target_id="interface:sw1-gi0-7",
        params={},
        risk="B",
        requester=CAROL,
    )
    first, second = approve(store, first), approve(store, second)
    begin(store, first, "exec-key-aaaaaaaaaa")
    later = NOW + timedelta(seconds=30 + 61)
    started = store.begin_execution(
        second.id,
        actor=BOB,
        expected_digest=second.digest,
        expected_version=second.version,
        idempotency_key="exec-key-bbbbbbbbbb",
        executor_id="dry-run",
        mode="dry-run",
        steps=["x"],
        now=later,
    )
    assert started.request.state == "executing"
    assert store.get(first.id).state == "failed"  # type: ignore[union-attr]
