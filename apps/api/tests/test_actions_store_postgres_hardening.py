"""Hardening of the PostgreSQL action store after review (Step 12 follow-up, D-53).

Shadowed tables, content binding, start-up probing, logged failures, bounded and corrupt-tolerant sweeps,
cheap refusals outside the creation lock, and the SQL/Python drift tests.
"""

from __future__ import annotations

import logging
import re
import typing
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import psycopg
import pytest
from actions_pg_support import (
    KEY,
    owner_conn_fixture,  # noqa: F401
    settings_fixture,  # noqa: F401
    store_for,
)
from actions_support import BOB, NOW, new_action
from pg_support import PG_DSN, app_role, isolated_schema, requires_pg

from netsight_api.actions import errors as e
from netsight_api.actions import lifecycle, wiring
from netsight_api.actions import postgres_rows as q
from netsight_api.actions.postgres_store import (
    CREATE_LOCK_KEY,
    LOCK_NAMESPACE_CREATE,
    PostgresActionStore,
)
from netsight_api.actions.wiring import build_runtime
from netsight_api.schemas_actions import (
    ALLOWED_TRANSITIONS,
    OPEN_STATES,
    TERMINAL_STATES,
    ActionType,
    EventType,
    RequestState,
)
from netsight_api.storage import migrate
from netsight_api.storage.connection import PostgresSettings

LATE = NOW + timedelta(days=2)
UP_SQL = migrate.MIGRATIONS_DIR / "0007_action_requests.up.sql"
FUNCTIONS = (
    "netsight_action_transition_ok",
    "netsight_action_state_is_final",
    "netsight_guard_action_request_insert",
    "netsight_guard_action_request_update",
    "netsight_guard_action_event_insert",
    "netsight_check_action_log",
    "netsight_action_request_logged",
    "netsight_action_event_logged",
)
ENV = {"NETSIGHT_ACTIONS_ENABLED": "true", "DATABASE_URL": "postgresql://nobody@127.0.0.1:1/none"}


def rewrite(conn: Any, *statements: str) -> None:
    conn.execute("ALTER TABLE action_history DISABLE TRIGGER USER")
    conn.execute("ALTER TABLE action_requests DISABLE TRIGGER USER")
    for statement in statements:
        conn.execute(statement)
    conn.commit()


def schema_of(conn: Any) -> str:
    return str(conn.settings.schema)


# --- search_path: a TEMP table cannot stand in for the real one --------------------------------------------------


@requires_pg
def test_a_temp_table_named_like_the_history_does_not_defeat_the_guards(
    settings: PostgresSettings,
) -> None:
    request = store_for(settings).create(new_action(), idempotency_key=KEY, now=NOW).request
    schema = settings.schema
    with settings.connect() as conn:
        conn.execute(f'CREATE TEMP TABLE action_history (LIKE "{schema}".action_history)')
        conn.execute(f'CREATE TEMP TABLE action_requests (LIKE "{schema}".action_requests)')
        # A fake past in which the request already stood at event 9, so a gap looks like continuity.
        conn.execute(
            "INSERT INTO pg_temp.action_history VALUES (%s, 9, now(), 'submitted', NULL, 'proposed', "
            "'pending-approval', 'awaiting-approval', NULL, repeat('a', 64), repeat('b', 64))",
            (request.id,),
        )
        conn.execute(
            f'INSERT INTO pg_temp.action_requests SELECT * FROM "{schema}".action_requests'
        )
        conn.execute("UPDATE pg_temp.action_requests SET version = 9")
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            conn.execute(
                f'INSERT INTO "{schema}".action_history (action_id, seq, at, type, actor_id, '
                "from_state, to_state, code, note, prev_hash, hash) VALUES (%s, 10, now(), "
                "'cancelled', NULL, 'pending-approval', 'cancelled', 'cancelled', NULL, "
                "repeat('b', 64), repeat('c', 64))",
                (request.id,),
            )
            conn.execute(
                f"UPDATE \"{schema}\".action_requests SET state = 'cancelled', version = 10 "
                "WHERE id = %s",
                (request.id,),
            )
            conn.commit()
    found = store_for(settings).get(request.id)
    assert found is not None and found.state == "pending-approval" and found.version == 3


@requires_pg
def test_every_function_of_the_migration_pins_its_search_path(owner_conn: Any) -> None:
    rows = owner_conn.execute(
        "SELECT proname, proconfig FROM pg_proc WHERE proname = ANY(%s) "
        "AND pronamespace = current_schema()::regnamespace",
        (list(FUNCTIONS),),
    ).fetchall()
    assert {r["proname"] for r in rows} == set(FUNCTIONS)
    schema = schema_of(owner_conn)
    for row in rows:
        pinned = [c for c in (row["proconfig"] or []) if c.startswith("search_path=")]
        assert pinned, row["proname"]
        path = [p.strip().strip('"') for p in pinned[0].split("=", 1)[1].split(",")]
        assert path[0] == "pg_catalog" and schema in path and path[-1] == "pg_temp", pinned


# --- the digest binds the content, the chain binds the digest -----------------------------------------------------


def test_the_digest_of_a_request_is_recomputable_from_its_stored_fields() -> None:
    for new in (
        new_action(),
        new_action(reason="  padded reason  "),
        new_action(created_at=NOW.astimezone(timezone(timedelta(hours=2)))),
        new_action(params={"duration_minutes": 5}),
    ):
        assert lifecycle.request_digest(lifecycle.new_request(new)) == new.digest


@requires_pg
@pytest.mark.parametrize(
    "tamper",
    [
        "UPDATE action_requests SET params = '{{\"duration_minutes\": 1}}'::jsonb WHERE id = '{a}'",
        "UPDATE action_requests SET target_id = 'endpoint:elsewhere' WHERE id = '{a}'",
        "UPDATE action_requests SET reason = 'A different reason' WHERE id = '{a}'",
        "UPDATE action_requests SET approve_by = approve_by + interval '1 day' WHERE id = '{a}'",
        "UPDATE action_requests SET risk = 'A' WHERE id = '{a}'",
    ],
    ids=["params", "target", "reason", "deadline", "risk"],
)
def test_content_edited_behind_the_digest_is_refused_on_read_and_before_a_run(
    owner_conn: Any, tamper: str
) -> None:
    store = store_for(owner_conn.settings)
    request = store.create(new_action(), idempotency_key=KEY, now=NOW).request
    ready = store.approve(
        request.id,
        approver=BOB,
        expected_digest=request.digest,
        expected_version=request.version,
        now=NOW,
    )
    rewrite(owner_conn, tamper.format(a=ready.id))
    with pytest.raises(q.StoredRecordError):
        store.get(ready.id)
    with pytest.raises(q.StoredRecordError):
        store.begin_execution(
            ready.id,
            actor=BOB,
            expected_digest=ready.digest,
            expected_version=ready.version,
            idempotency_key="exec-key-000000000001",
            executor_id="dry-run",
            mode="dry-run",
            steps=["x"],
            now=NOW,
        )


@requires_pg
def test_an_approver_swapped_in_the_request_is_detected_against_the_history(
    owner_conn: Any,
) -> None:
    store = store_for(owner_conn.settings)
    request = store.create(new_action(), idempotency_key=KEY, now=NOW).request
    ready = store.approve(
        request.id,
        approver=BOB,
        expected_digest=request.digest,
        expected_version=request.version,
        now=NOW,
    )
    assert store.verify_chain(ready.id) is True
    rewrite(
        owner_conn,
        "UPDATE action_requests SET approvals = jsonb_set(approvals, '{0,approver_id}', "
        f"'\"mallory\"') WHERE id = '{ready.id}'",
    )
    assert store.verify_chain(ready.id) is False


# --- start-up and the readiness probe ------------------------------------------------------------------------------


@requires_pg
def test_a_schema_without_the_migration_is_not_ready() -> None:
    with isolated_schema() as schema:
        store = PostgresActionStore(
            PostgresSettings(dsn=PG_DSN or "", schema=schema), kill_switch=_switch()
        )
        with pytest.raises(e.StoreMisconfigured) as raised:
            store.check()
        assert isinstance(raised.value, e.StoreUnavailable) and raised.value.status == 503


@requires_pg
def test_start_up_is_refused_for_a_missing_migration_and_says_what_to_apply(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    with isolated_schema() as schema:
        monkeypatch.setattr(
            wiring,
            "database_settings",
            lambda _env: PostgresSettings(dsn=PG_DSN or "", schema=schema),
        )
        with (
            caplog.at_level(logging.ERROR, logger="netsight_api"),
            pytest.raises(ValueError, match="0007"),
        ):
            build_runtime(ENV)
    assert any(r.levelno >= logging.ERROR for r in caplog.records)


def test_start_up_survives_an_unreachable_database_and_logs_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.ERROR, logger="netsight_api"):
        runtime = build_runtime(ENV)
    assert runtime is not None and runtime.store.kind == "postgres"
    errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert errors and not any("nobody" in m or "127.0.0.1" in m for m in errors)


@requires_pg
def test_the_probe_finds_missing_grants_and_disabled_triggers(owner_conn: Any) -> None:
    schema = schema_of(owner_conn)
    with app_role() as (role, dsn):
        runtime = PostgresSettings(dsn=dsn, schema=schema)
        store = PostgresActionStore(runtime, kill_switch=_switch())
        with pytest.raises(e.StoreMisconfigured):  # no grants at all
            store.check()
        migrate.apply_grants(owner_conn, role)
        owner_conn.commit()
        store.check()  # granted: ready
        owner_conn.execute(f'REVOKE INSERT ON "{schema}".action_history FROM "{role}"')
        owner_conn.commit()
        with pytest.raises(e.StoreMisconfigured):
            store.check()
        migrate.apply_grants(owner_conn, role)
        owner_conn.commit()
        store.check()
        owner_conn.execute("ALTER TABLE action_history DISABLE TRIGGER action_history_guard_insert")
        owner_conn.commit()
        with pytest.raises(e.StoreMisconfigured):
            store.check()


def _switch() -> Any:
    from netsight_api.actions.killswitch import KillSwitch

    return KillSwitch()


def test_require_durable_fails_start_up_without_a_database_and_is_off_by_default() -> None:
    on = {"NETSIGHT_ACTIONS_ENABLED": "true", "NETSIGHT_ACTIONS_REQUIRE_DURABLE": "true"}
    for refused in (lambda: build_runtime(on), lambda: wiring.validate_environment(on)):
        with pytest.raises(ValueError, match="DATABASE_URL"):
            refused()
    wiring.validate_environment({"NETSIGHT_ACTIONS_ENABLED": "true"})  # off by default
    assert build_runtime({"NETSIGHT_ACTIONS_ENABLED": "true"}) is not None
    with pytest.raises(ValueError, match="REQUIRE_DURABLE"):
        wiring.validate_environment({**on, "NETSIGHT_ACTIONS_REQUIRE_DURABLE": "maybe"})
    assert (
        build_runtime({"NETSIGHT_ACTIONS_REQUIRE_DURABLE": "true"}) is None
    )  # engine off: ignored


# --- failures are logged where the operator can see them, without content -----------------------------------------


@requires_pg
def test_a_missing_table_is_a_503_and_a_log_record_with_the_class_and_sqlstate(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with isolated_schema() as schema:
        store = PostgresActionStore(
            PostgresSettings(dsn=PG_DSN or "", schema=schema), kill_switch=_switch()
        )
        with (
            caplog.at_level(logging.WARNING, logger="netsight_api"),
            pytest.raises(e.StoreUnavailable) as raised,
        ):
            store.get("action-00000000-0000-4000-8000-000000000001")
    assert raised.value.status == 503
    text = " ".join(r.getMessage() for r in caplog.records)
    assert "UndefinedTable" in text and "42P01" in text
    assert "postgresql://" not in text and "action-00000000" not in text


def test_a_row_that_does_not_parse_is_logged_with_its_id_and_no_content(
    caplog: pytest.LogCaptureFixture,
) -> None:
    row = {"id": "action-00000000-0000-4000-8000-000000000009", "reason": "PRIVATE-REASON"}
    with (
        caplog.at_level(logging.WARNING, logger="netsight_api"),
        pytest.raises(q.StoredRecordError) as raised,
    ):
        q.request_from_row(row)
    assert raised.value.__cause__ is None and raised.value.__suppress_context__
    text = " ".join(r.getMessage() for r in caplog.records)
    assert row["id"] in text and "PRIVATE-REASON" not in text


# --- sweeps ---------------------------------------------------------------------------------------------------------


@requires_pg
def test_one_sweep_moves_a_bounded_batch_and_the_next_call_continues(
    settings: PostgresSettings,
) -> None:
    store = store_for(settings, max_open_per_requester=500)
    for n in range(205):
        store.create(new_action(), idempotency_key=f"{KEY}{n:04d}", now=NOW)
    assert store.expire_due(LATE) == 200
    assert store.expire_due(LATE) == 5
    assert store.expire_due(LATE) == 0


@requires_pg
def test_one_corrupt_overdue_row_blocks_neither_a_sweep_nor_create_nor_a_run(
    owner_conn: Any, caplog: pytest.LogCaptureFixture
) -> None:
    store = store_for(owner_conn.settings)
    bad = store.create(new_action(), idempotency_key=f"{KEY}a", now=NOW).request
    good = store.create(new_action(), idempotency_key=f"{KEY}b", now=NOW).request
    ready0 = store.create(
        new_action(execute_within_seconds=172800), idempotency_key=f"{KEY}c", now=NOW
    ).request
    ready = store.approve(
        ready0.id,
        approver=BOB,
        expected_digest=ready0.digest,
        expected_version=ready0.version,
        now=NOW,
    )
    rewrite(
        owner_conn, f"UPDATE action_requests SET reason = E'bad\\x01PRIVATE' WHERE id = '{bad.id}'"
    )
    after = NOW + timedelta(hours=25)  # past the 24 h approval window, inside the run window
    with caplog.at_level(logging.WARNING, logger="netsight_api"):
        started = store.begin_execution(
            ready.id,
            actor=BOB,
            expected_digest=ready.digest,
            expected_version=ready.version,
            idempotency_key="exec-key-000000000001",
            executor_id="dry-run",
            mode="dry-run",
            steps=["x"],
            now=after,
        )
        assert started.request.state == "executing"
        fresh = new_action(created_at=after, approve_by=after + timedelta(hours=24))
        assert store.create(fresh, idempotency_key=f"{KEY}d", now=after).replayed is False
    assert store.get(good.id).state == "expired"  # type: ignore[union-attr]
    text = " ".join(r.getMessage() for r in caplog.records)
    assert bad.id in text and "PRIVATE" not in text


@requires_pg
def test_cheap_refusals_do_not_wait_for_the_global_creation_lock(
    settings: PostgresSettings,
) -> None:
    store = store_for(settings, max_open_per_requester=1)
    body = new_action()
    made = store.create(body, idempotency_key=KEY, now=NOW).request
    with psycopg.connect(PG_DSN or "", autocommit=True) as holder:
        holder.execute("SELECT pg_advisory_lock(%s, %s)", (LOCK_NAMESPACE_CREATE, CREATE_LOCK_KEY))
        try:
            replay = store.create(body, idempotency_key=KEY, now=NOW)
            assert replay.replayed and replay.request.id == made.id
            with pytest.raises(e.DuplicateOpenRequest):
                store.create(
                    new_action(target_id=made.target_id), idempotency_key=f"{KEY}x", now=NOW
                )
            with pytest.raises(e.TooManyOpenRequests):
                store.create(new_action(), idempotency_key=f"{KEY}y", now=NOW)
        finally:
            holder.execute(
                "SELECT pg_advisory_unlock(%s, %s)", (LOCK_NAMESPACE_CREATE, CREATE_LOCK_KEY)
            )


@requires_pg
def test_a_listing_is_one_read_snapshot_after_its_own_sweep(
    settings: PostgresSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = store_for(settings)
    for n in range(3):
        store.create(new_action(), idempotency_key=f"{KEY}{n}", now=NOW)
    reads: list[str] = []
    original = store._read
    monkeypatch.setattr(store, "_read", lambda body: (reads.append("read"), original(body))[1])
    items, total = store.list_requests(limit=2, offset=0, now=LATE)
    assert reads == ["read"] and len(items) == 2 and total == 3
    assert {r.state for r in items} == {"expired"}  # the sweep ran first and committed


# --- drift between the database and the application ---------------------------------------------------------------


@requires_pg
def test_the_sql_lifecycle_functions_agree_with_the_python_tables_for_every_pair(
    owner_conn: Any,
) -> None:
    states = typing.get_args(RequestState)
    for source in states:
        final = owner_conn.execute("SELECT netsight_action_state_is_final(%s) AS v", (source,))
        assert final.fetchone()["v"] == (source in TERMINAL_STATES), source
        for target in states:
            row = owner_conn.execute(
                "SELECT netsight_action_transition_ok(%s, %s) AS v", (source, target)
            )
            assert row.fetchone()["v"] == (target in ALLOWED_TRANSITIONS[source]), (source, target)


def _sql_list(text: str, constraint: str) -> set[str]:
    block = text[text.index(f"CONSTRAINT {constraint}") :]
    block = block[: block.index("),")]
    return set(re.findall(r"'([a-z.-]+)'", block))


def test_the_state_strings_in_the_queries_are_the_python_sets() -> None:
    assert set(re.findall(r"'([a-z-]+)'", q.OPEN)) == OPEN_STATES
    assert set(re.findall(r"'([a-z-]+)'", q.FINISHED)) == TERMINAL_STATES


def test_the_check_lists_of_the_migration_are_the_python_literals() -> None:
    text = UP_SQL.read_text("utf-8")
    assert _sql_list(text, "action_type_valid") == set(typing.get_args(ActionType))
    assert _sql_list(text, "action_state_valid") == set(typing.get_args(RequestState))
    history = text[text.index("CONSTRAINT action_history_type_valid") :]
    history = history[: history.index("),")]
    assert set(re.findall(r"'([a-z-]+)'", history)) == set(typing.get_args(EventType))
    for statement in ("action_open_idx", "action_one_open_per_target"):
        index = text[text.index(f"INDEX {statement}") :]
        index = index[: index.index(";")]
        assert set(re.findall(r"'([a-z-]+)'", index)) == OPEN_STATES


# --- small things -----------------------------------------------------------------------------------------------------


def test_a_naive_datetime_is_refused_not_guessed() -> None:
    with pytest.raises(ValueError, match="time zone"):
        q.utc(datetime(2026, 10, 18, 12, 0, 0))  # noqa: DTZ001
    assert q.utc(NOW.astimezone(timezone(timedelta(hours=3)))).tzinfo is UTC


@requires_pg
@pytest.mark.parametrize("column", ["source", "policy_checks", "pre_checks"])
def test_a_stored_document_larger_than_a_mebibyte_is_refused(owner_conn: Any, column: str) -> None:
    store = store_for(owner_conn.settings)
    request = store.create(new_action(), idempotency_key=KEY, now=NOW).request
    owner_conn.execute(
        "ALTER TABLE action_requests DISABLE TRIGGER USER"
    )  # only the CHECK is under test
    document = (
        "jsonb_build_object('x', repeat('y', 1100000))"
        if column == "source"
        else "jsonb_build_array(jsonb_build_object('x', repeat('y', 1100000)))"
    )
    with pytest.raises(psycopg.errors.CheckViolation):
        owner_conn.execute(
            f"UPDATE action_requests SET {column} = {document} WHERE id = %s", (request.id,)
        )
    owner_conn.rollback()
    assert store.get(request.id) == request
