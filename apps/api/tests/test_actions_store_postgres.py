"""The PostgreSQL action store beyond the shared contract suite (Step 12, D-53).

``test_actions_store`` runs every behaviour test against memory and PostgreSQL. This module holds what only
a database can show: state that outlives an instance, several workers racing one request, the triggers and
indexes that keep the store honest even if the application is wrong, the least-privilege role, and the
refusal to fall back to memory when the database is unreachable. The last group needs no database.
"""

from __future__ import annotations

import threading
from datetime import timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytest
from actions_pg_support import (
    DEAD_DSN,
    EXEC,
    KEY,
    approve,
    owner_conn_fixture,  # noqa: F401
    propose,
    seed,
    settings_fixture,  # noqa: F401
    store_for,
)
from actions_support import ALICE, BOB, CAROL, NOW, new_action
from pg_support import requires_pg

from netsight_api.actions import errors as e
from netsight_api.actions.history import ZERO_HASH
from netsight_api.actions.killswitch import KillSwitch
from netsight_api.actions.postgres_store import PostgresActionStore
from netsight_api.schemas_actions import ActionRequest
from netsight_api.storage import migrate
from netsight_api.storage.connection import PostgresSettings

# --- durability and several workers -----------------------------------------------------------------------------


@requires_pg
def test_requests_and_history_outlive_the_store_instance_and_the_role_can_run_the_lifecycle(
    settings: PostgresSettings,
) -> None:
    first = store_for(settings)
    request = approve(first, propose(first))
    second = store_for(settings)  # a restart, or another worker
    again = second.get(request.id)
    assert again == request
    assert [x.type for x in second.history(request.id)] == [
        "proposed",
        "policy-checked",
        "submitted",
        "approved",
    ]
    assert second.verify_chain(request.id) is True
    assert second.list_requests(limit=10, offset=0, now=NOW)[1] == 1


@requires_pg
def test_two_workers_racing_one_approval_record_exactly_one_decision(
    settings: PostgresSettings,
) -> None:
    request = propose(store_for(settings))
    stores = [store_for(settings) for _ in range(2)]
    outcomes: list[str] = []
    barrier = threading.Barrier(6)

    def worker(index: int) -> None:
        barrier.wait()
        try:
            approve(stores[index % 2], request, BOB.model_copy(update={"id": f"approver-{index}"}))
            outcomes.append("ok")
        except e.ActionError as exc:
            outcomes.append(exc.code)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count("ok") == 1
    assert sorted(outcomes) == ["STALE_REQUEST"] * 5 + [
        "ok"
    ]  # the losers quoted a version that moved
    current = stores[0].get(request.id)
    assert current is not None and len(current.approvals) == 1 and current.version == 4
    assert stores[1].verify_chain(request.id)


@requires_pg
def test_two_workers_racing_one_target_lock_start_exactly_one_run(
    settings: PostgresSettings,
) -> None:
    stores = [store_for(settings), store_for(settings)]
    kinds = ("switch.port.disable", "switch.port.enable")
    ready = []
    for index, kind in enumerate(kinds):
        request = (
            stores[0]
            .create(
                new_action(
                    action_type=kind,
                    target_id="interface:sw9-gi0-1",
                    params={},
                    risk="D" if index == 0 else "B",
                    requester=[ALICE, CAROL][index],
                ),
                idempotency_key=f"{KEY}{index}",
                now=NOW,
            )
            .request
        )
        ready.append(approve(stores[0], request, BOB))
    outcomes: list[str] = []
    barrier = threading.Barrier(2)

    def worker(index: int) -> None:
        barrier.wait()
        try:
            stores[index].begin_execution(
                ready[index].id,
                actor=BOB,
                expected_digest=ready[index].digest,
                expected_version=ready[index].version,
                idempotency_key=f"{EXEC}{index}",
                executor_id="dry-run",
                mode="dry-run",
                steps=["x"],
                now=NOW,
            )
            outcomes.append("ok")
        except e.ActionError as exc:
            outcomes.append(exc.code)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(outcomes) == ["TARGET_LOCKED", "ok"]


@requires_pg
def test_workers_sweeping_the_same_due_requests_move_each_once_and_report_each_once(
    settings: PostgresSettings,
) -> None:
    seen: list[tuple[str, str, str]] = []
    lock = threading.Lock()

    def report(request_id: str, state: str, code: str) -> None:
        with lock:
            seen.append((request_id, state, code))

    stores = [store_for(settings, on_system_transition=report) for _ in range(3)]
    ids = [
        stores[0].create(new_action(), idempotency_key=f"{KEY}{n}", now=NOW).request.id
        for n in range(4)
    ]
    late = NOW + timedelta(days=2)
    counts: list[int] = []
    barrier = threading.Barrier(3)

    def sweep(index: int) -> None:
        barrier.wait()
        counts.append(stores[index].expire_due(late))

    threads = [threading.Thread(target=sweep, args=(i,)) for i in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(counts) == 4
    assert sorted(i for i, _, _ in seen) == sorted(ids)
    assert all(store_state(stores[0], i) == "expired" for i in ids)


def store_state(store: PostgresActionStore, action_id: str) -> str:
    found = store.get(action_id)
    assert found is not None
    return found.state


@requires_pg
def test_a_listing_is_bounded_whatever_limit_is_asked_for(settings: PostgresSettings) -> None:
    store = store_for(settings, max_open_per_requester=100)
    for n in range(55):
        store.create(new_action(), idempotency_key=f"{KEY}{n:03d}", now=NOW)
    items, total = store.list_requests(limit=10_000, offset=0, now=NOW)
    assert total == 55 and len(items) == 50


def _race(workers: int, work: Any) -> list[Any]:
    """Run ``work(index)`` on ``workers`` threads released together; collect what each returned or raised."""
    barrier = threading.Barrier(workers)
    results: list[Any] = [None] * workers

    def run(index: int) -> None:
        barrier.wait()
        try:
            results[index] = work(index)
        except e.ActionError as exc:
            results[index] = exc.code

    threads = [threading.Thread(target=run, args=(i,)) for i in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


@requires_pg
def test_workers_creating_for_one_requester_never_exceed_the_open_cap(
    settings: PostgresSettings,
) -> None:
    stores = [store_for(settings, max_open_per_requester=3) for _ in range(3)]
    made = _race(
        9,
        lambda i: (
            stores[i % 3].create(new_action(), idempotency_key=f"{KEY}{i}", now=NOW).request.id
        ),
    )
    assert sum(1 for m in made if m != "TOO_MANY_OPEN") == 3
    assert stores[0].list_requests(limit=50, offset=0, now=NOW)[1] == 3


@requires_pg
def test_workers_proposing_the_same_action_on_one_target_open_exactly_one_request(
    settings: PostgresSettings,
) -> None:
    stores = [store_for(settings, max_open_per_requester=50) for _ in range(3)]
    made = _race(
        6,
        lambda i: (
            stores[i % 3]
            .create(
                new_action(target_id="endpoint:contested"), idempotency_key=f"{KEY}{i}", now=NOW
            )
            .request.id
        ),
    )
    assert [m for m in made if m == "ALREADY_OPEN"] == ["ALREADY_OPEN"] * 5
    assert stores[0].list_requests(limit=50, offset=0, now=NOW)[1] == 1


@requires_pg
def test_workers_retrying_one_creation_key_make_one_request_and_all_see_it(
    settings: PostgresSettings,
) -> None:
    stores = [store_for(settings) for _ in range(3)]
    body = new_action()
    results = _race(6, lambda i: stores[i % 3].create(body, idempotency_key=KEY, now=NOW))
    assert sorted(r.replayed for r in results) == [False] + [True] * 5
    assert {r.request.id for r in results} == {body.id}
    assert stores[0].history(body.id)[-1].seq == 3  # created once: three events, not eighteen


@requires_pg
@pytest.mark.parametrize("same_key", [True, False], ids=["one execution key", "a key each"])
def test_workers_executing_one_request_start_exactly_one_run(
    settings: PostgresSettings, same_key: bool
) -> None:
    stores = [store_for(settings), store_for(settings)]
    ready = approve(stores[0], propose(stores[0]), BOB)
    results = _race(
        6,
        lambda i: stores[i % 2].begin_execution(
            ready.id,
            actor=BOB,
            expected_digest=ready.digest,
            expected_version=ready.version,
            idempotency_key=EXEC if same_key else f"{EXEC}{i}",
            executor_id="dry-run",
            mode="dry-run",
            steps=["x"],
            now=NOW,
        ),
    )
    started = [r for r in results if not isinstance(r, str) and not r.replayed]
    assert len(started) == 1
    refused = [r for r in results if isinstance(r, str)]
    replayed = [r for r in results if not isinstance(r, str) and r.replayed]
    assert set(refused) <= {"STALE_REQUEST"} and len(refused) + len(replayed) == 5
    assert (len(replayed) == 5) if same_key else (len(refused) == 5)
    history = stores[1].history(ready.id)
    assert [x.type for x in history].count("execution-started") == 1
    assert stores[1].verify_chain(ready.id)


@requires_pg
def test_a_callback_that_fails_does_not_undo_the_move_it_reports(
    settings: PostgresSettings,
) -> None:
    def explode(*_: str) -> None:
        raise RuntimeError("audit sink down")

    store = store_for(settings, on_system_transition=explode)
    request = propose(store)
    assert store.expire_due(NOW + timedelta(days=2)) == 1
    found = store.get(request.id)
    assert found is not None and found.state == "expired"


@requires_pg
def test_a_decision_on_an_expired_request_is_refused_but_the_expiry_is_kept(
    settings: PostgresSettings,
) -> None:
    store = store_for(settings)
    request = propose(store)
    with pytest.raises(e.ApprovalExpired):
        store.approve(
            request.id,
            approver=BOB,
            expected_digest=request.digest,
            expected_version=request.version,
            now=NOW + timedelta(days=2),
        )
    found = store.get(request.id)
    assert (
        found is not None and found.state == "expired"
    )  # committed, not rolled back with the refusal
    assert store.verify_chain(request.id)


@requires_pg
def test_an_evicted_request_stays_in_the_tables_but_not_in_the_store(owner_conn: Any) -> None:
    store = store_for(owner_conn.settings, max_stored=1)
    first = propose(store)
    store.cancel(
        first.id,
        actor=ALICE,
        expected_digest=first.digest,
        expected_version=first.version,
        reason="Withdrawn",
        now=NOW,
    )
    second = store.create(
        new_action(), idempotency_key=f"{KEY}2", now=NOW + timedelta(hours=2)
    ).request
    assert store.get(first.id) is None
    with pytest.raises(e.ActionNotFound):
        store.history(first.id)
    assert [r.id for r in store.list_requests(limit=50, offset=0, now=NOW)[0]] == [second.id]
    kept = owner_conn.execute(
        "SELECT (SELECT count(*) FROM action_requests) AS requests, "
        "(SELECT count(*) FROM action_history WHERE action_id = %s) AS events",
        (first.id,),
    ).fetchone()
    assert kept["requests"] == 2 and kept["events"] == 4  # nothing was deleted


@requires_pg
def test_ids_that_are_not_action_ids_are_not_found_without_touching_the_database(
    settings: PostgresSettings,
) -> None:
    store = store_for(settings)
    for bad in ("", "x", "action-" + "g" * 36, "action-\x00", "'; SELECT 1; --"):
        assert store.get(bad) is None
        with pytest.raises(e.ActionNotFound):
            store.history(bad)


@requires_pg
def test_the_store_checks_itself_against_the_live_tables(settings: PostgresSettings) -> None:
    store_for(settings).check()


# --- the database refuses what the application would never do ---------------------------------------------------


def _first_history_row(conn: Any) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM action_history ORDER BY at, seq LIMIT 1").fetchone()
    assert row is not None
    return dict(row)


def _seed(conn: Any) -> ActionRequest:
    return seed(conn.settings)


@requires_pg
@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE action_history SET code = 'tampered'",
        "UPDATE action_history SET hash = repeat('a', 64)",
        "DELETE FROM action_history",
        "TRUNCATE action_history",
        "DELETE FROM action_requests",
        "TRUNCATE action_requests CASCADE",
    ],
)
def test_history_and_requests_cannot_be_edited_deleted_or_truncated_even_by_the_owner(
    owner_conn: Any, statement: str
) -> None:
    _seed(owner_conn)
    with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
        owner_conn.execute(statement)


@requires_pg
def test_identity_columns_and_the_digest_of_a_request_cannot_change(owner_conn: Any) -> None:
    request = _seed(owner_conn)
    for column, value in (
        ("target_id", "'endpoint:other'"),
        ("digest", "'sha256:' || repeat('0', 64)"),
        ("requester_id", "'mallory'"),
        ("reason", "'rewritten history'"),
        ("params", "'{}'::jsonb"),
        ("approve_by", "now() + interval '10 years'"),
    ):
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            owner_conn.execute(
                f"UPDATE action_requests SET {column} = {value} WHERE id = %s", (request.id,)
            )
        owner_conn.rollback()


@requires_pg
def test_a_history_event_that_does_not_continue_the_chain_is_refused(owner_conn: Any) -> None:
    request = _seed(owner_conn)
    last = owner_conn.execute(
        "SELECT * FROM action_history WHERE action_id = %s ORDER BY seq DESC LIMIT 1", (request.id,)
    ).fetchone()
    insert = (
        "INSERT INTO action_history (action_id, seq, at, type, actor_id, from_state, to_state, "
        "code, note, prev_hash, hash) VALUES (%s, %s, now(), 'cancelled', NULL, %s, 'cancelled', "
        "'cancelled', NULL, %s, repeat('b', 64))"
    )
    for seq, prev in (
        (last["seq"] + 2, last["hash"]),  # a gap
        (last["seq"] + 1, ZERO_HASH),  # not linked to the previous event
        (last["seq"], last["hash"]),  # a duplicate position
    ):
        with pytest.raises(psycopg.errors.Error):
            owner_conn.execute(insert, (request.id, seq, last["to_state"], prev))
        owner_conn.rollback()


@requires_pg
def test_a_request_cannot_commit_in_a_state_its_history_does_not_account_for(
    owner_conn: Any,
) -> None:
    request = _seed(owner_conn)
    with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
        owner_conn.execute(
            "UPDATE action_requests SET state = 'cancelled', version = version + 1 WHERE id = %s",
            (request.id,),
        )
        owner_conn.commit()
    owner_conn.rollback()


@requires_pg
def test_the_database_enforces_one_run_per_target_and_one_open_request_per_action_and_target(
    owner_conn: Any,
) -> None:
    indexes = {
        row["indexname"]: row["indexdef"]
        for row in owner_conn.execute(
            "SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema()"
        ).fetchall()
    }
    run = indexes["action_one_executing_per_target"]
    assert "UNIQUE" in run and "(target_id)" in run and "executing" in run
    open_one = indexes["action_one_open_per_target"]
    assert "UNIQUE" in open_one and "(action_type, target_id)" in open_one
    key = indexes["action_create_key_unique"]
    assert "UNIQUE" in key and "(requester_id, create_key)" in key


REQUEST_COLUMNS = {
    "id", "action_type", "target_id", "params", "risk", "state", "requester_id", "requester_kind",
    "reason", "source", "approvals_required", "approvals", "created_at", "approve_by", "execute_by",
    "execute_within_seconds", "timeout_seconds", "run_by", "version", "digest", "policy_checks",
    "pre_checks", "execution", "create_key", "create_fingerprint", "exec_key", "exec_actor_id",
    "evicted_at",
}  # fmt: skip
HISTORY_COLUMNS = {
    "action_id", "seq", "at", "type", "actor_id", "from_state", "to_state", "code", "note",
    "prev_hash", "hash",
}  # fmt: skip


@requires_pg
def test_the_tables_hold_exactly_these_columns_and_nothing_that_names_an_endpoint(
    owner_conn: Any,
) -> None:
    found: dict[str, set[str]] = {}
    for row in owner_conn.execute(
        "SELECT table_name, column_name FROM information_schema.columns "
        r"WHERE table_schema = current_schema() AND table_name LIKE 'action\_%'"
    ).fetchall():
        found.setdefault(row["table_name"], set()).add(row["column_name"])
    assert found == {"action_requests": REQUEST_COLUMNS, "action_history": HISTORY_COLUMNS}


@requires_pg
def test_the_application_role_cannot_delete_or_edit_the_record(settings: PostgresSettings) -> None:
    if "nsapp_" not in settings.dsn:
        pytest.skip("the owner is not the least-privilege role")
    request = propose(store_for(settings))
    with settings.connect() as conn:
        for statement in (
            "DELETE FROM action_requests",
            "DELETE FROM action_history",
            "UPDATE action_requests SET reason = 'edited'",
            "UPDATE action_history SET code = 'edited'",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(statement)
            conn.rollback()
    assert store_for(settings).get(request.id) == request


# --- migration -------------------------------------------------------------------------------------------------


UP = migrate.MIGRATIONS_DIR / "0007_action_requests.up.sql"
DOWN = migrate.MIGRATIONS_DIR / "0007_action_requests.down.sql"


def test_the_migration_has_a_rollback_with_notes_and_only_static_ddl() -> None:
    up, down = UP.read_text("utf-8"), DOWN.read_text("utf-8")
    assert "Rollback: 0007_action_requests.down.sql" in up
    assert "DESTRUCTIVE" in down and "backup" in down.lower()
    assert "DROP TABLE IF EXISTS action_history;" in down
    assert down.index("DROP TABLE IF EXISTS action_history;") < down.index(
        "DROP TABLE IF EXISTS action_requests;"
    )
    assert "netsight_reject_append_only_mutation" in up  # the 0003 function, not a copy
    assert "CREATE OR REPLACE FUNCTION netsight_reject_append_only_mutation" not in up
    assert "%s" not in up and "{" not in up


@requires_pg
def test_the_rollback_removes_the_tables_and_functions_and_up_can_run_again(
    owner_conn: Any,
) -> None:
    _seed(owner_conn)
    owner_conn.commit()
    with pytest.raises(migrate.DestructiveMigrationError):
        migrate.apply_down(owner_conn, allow_destructive=True, env={})
    assert migrate.apply_down(
        owner_conn, allow_destructive=True, env={migrate.DESTRUCTIVE_ENV: "1"}
    ) == ["0007"]
    remaining = owner_conn.execute(
        "SELECT count(*) AS n FROM information_schema.tables "
        "WHERE table_schema = current_schema() AND table_name LIKE 'action\\_%'"
    ).fetchone()
    assert remaining["n"] == 0
    assert migrate.apply_up(owner_conn) == ["0007"]


def test_the_grants_script_names_the_action_tables() -> None:
    grants = Path(migrate.GRANTS_PATH).read_text("utf-8")
    assert "action_requests" in grants and "action_history" in grants


# --- unreachable database: never memory (needs no database) ----------------------------------------------------


def dead_store() -> PostgresActionStore:
    return PostgresActionStore(PostgresSettings(dsn=DEAD_DSN), kill_switch=KillSwitch())


def test_an_unreachable_database_is_a_503_never_a_silent_empty_or_memory_answer() -> None:
    store = dead_store()
    request_id = "action-00000000-0000-4000-8000-000000000001"
    calls = (
        lambda: store.get(request_id),
        lambda: store.history(request_id),
        lambda: store.verify_chain(request_id),
        lambda: store.list_requests(limit=5, offset=0, now=NOW),
        lambda: store.create(new_action(), idempotency_key=KEY, now=NOW),
        lambda: store.expire_due(NOW),
        lambda: store.check(),
        lambda: store.approve(
            request_id,
            approver=BOB,
            expected_digest="sha256:" + "0" * 64,
            expected_version=1,
            now=NOW,
        ),
    )
    for call in calls:
        with pytest.raises(e.StoreUnavailable) as raised:
            call()
        assert raised.value.status == 503 and raised.value.code == "STORE_UNAVAILABLE"
        assert DEAD_DSN not in str(raised.value) and "nobody" not in str(raised.value)


def test_the_store_says_what_it_is() -> None:
    store = dead_store()
    assert (store.kind, store.durable) == ("postgres", True)
