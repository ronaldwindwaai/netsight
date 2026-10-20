"""Tamper evidence and trigger-level integrity of the PostgreSQL action store (Step 12, D-53).

The triggers refuse an edit, a delete or a truncate for every role; but the table owner can disable them,
so these tests disable them on purpose and show that the store still *detects* every kind of rewrite of the
history (edit, gap, reorder, a cut-off tail or head, a transplant). They also show that a stored row which
no longer parses is an error and never a half-trusted answer, and that a request keeps its identity when the
session time zone is not UTC.
"""

from __future__ import annotations

from typing import Any

import psycopg
import pytest
from actions_pg_support import (
    KEY,
    approve,
    owner_conn_fixture,  # noqa: F401
    settings_fixture,  # noqa: F401
    store_for,
)
from actions_support import ALICE, BOB, NOW, new_action
from pg_support import requires_pg

from netsight_api.actions import errors as e
from netsight_api.actions.postgres_rows import StoredRecordError, request_from_row
from netsight_api.actions.postgres_store import PostgresActionStore
from netsight_api.schemas_actions import ActionRequest
from netsight_api.storage.connection import PostgresSettings
from netsight_api.storage.errors import StorageError


def two_approved(conn: Any) -> tuple[PostgresActionStore, ActionRequest, ActionRequest]:
    """Two requests at the same version and state, so only the hash can tell their histories apart."""
    store = store_for(conn.settings)
    made = [
        store.create(new_action(), idempotency_key=f"{KEY}{n}", now=NOW).request for n in range(2)
    ]
    first, second = (approve(store, request, BOB) for request in made)
    assert (first.version, first.state) == (second.version, second.state) == (4, "approved")
    return store, first, second


def disable_triggers(conn: Any) -> None:
    """What the owner can do and the application role cannot."""
    conn.execute("ALTER TABLE action_history DISABLE TRIGGER USER")
    conn.execute("ALTER TABLE action_requests DISABLE TRIGGER USER")


def rewrite(conn: Any, *statements: str) -> None:
    disable_triggers(conn)
    for statement in statements:
        conn.execute(statement)
    conn.commit()


# --- the chain verdict --------------------------------------------------------------------------------------------


@requires_pg
def test_an_untouched_history_verifies(owner_conn: Any) -> None:
    store, first, _ = two_approved(owner_conn)
    assert store.verify_chain(first.id) is True


@requires_pg
@pytest.mark.parametrize(
    "tamper",
    [
        "UPDATE action_history SET code = 'tampered' WHERE seq = 2 AND action_id = '{a}'",
        "UPDATE action_history SET actor_id = 'mallory' WHERE seq = 4 AND action_id = '{a}'",
        "DELETE FROM action_history WHERE seq = 2 AND action_id = '{a}'",
        "DELETE FROM action_history WHERE seq = 4 AND action_id = '{a}'",
        "DELETE FROM action_history WHERE seq = 1 AND action_id = '{a}'",
        "DELETE FROM action_history WHERE seq > 2 AND action_id = '{a}'",
        "UPDATE action_requests SET state = 'rejected' WHERE id = '{a}'",
        "UPDATE action_requests SET version = 5 WHERE id = '{a}'",
    ],
    ids=[
        "an edited event",
        "an edited actor",
        "a gap in the middle",
        "a cut-off tail",
        "a cut-off head",
        "several cut off",
        "a state its history does not say",
        "a version its history does not reach",
    ],
)
def test_every_kind_of_rewrite_of_the_history_is_detected(owner_conn: Any, tamper: str) -> None:
    store, first, second = two_approved(owner_conn)
    rewrite(owner_conn, tamper.format(a=first.id))
    assert store.verify_chain(first.id) is False
    assert store.verify_chain(second.id) is True  # only the tampered request fails


@requires_pg
def test_reordered_events_are_detected(owner_conn: Any) -> None:
    store, first, _ = two_approved(owner_conn)
    rewrite(
        owner_conn,
        f"UPDATE action_history SET seq = 100 WHERE seq = 2 AND action_id = '{first.id}'",
        f"UPDATE action_history SET seq = 2 WHERE seq = 3 AND action_id = '{first.id}'",
        f"UPDATE action_history SET seq = 3 WHERE seq = 100 AND action_id = '{first.id}'",
    )
    assert store.verify_chain(first.id) is False


@requires_pg
def test_a_history_moved_to_another_request_is_detected(owner_conn: Any) -> None:
    store, first, second = two_approved(owner_conn)
    rewrite(
        owner_conn,
        f"DELETE FROM action_history WHERE action_id = '{second.id}'",
        f"UPDATE action_history SET action_id = '{second.id}' WHERE action_id = '{first.id}'",
    )
    # Same length, same final state, every link valid: only the hash, which covers the request id, differs.
    assert store.verify_chain(second.id) is False


@requires_pg
def test_without_the_triggers_the_database_still_refuses_no_chain_but_the_store_never_serves_a_bad_one(
    owner_conn: Any,
) -> None:
    store, first, _ = two_approved(owner_conn)
    rewrite(
        owner_conn,
        f"UPDATE action_history SET hash = repeat('a', 64) WHERE action_id = '{first.id}'",
    )
    assert store.verify_chain(first.id) is False
    assert store.get(first.id) == first  # the request itself is intact; the verdict is the alarm


# --- a stored row that does not parse -----------------------------------------------------------------------------


@requires_pg
def test_a_corrupt_request_row_is_a_storage_error_not_an_answer_and_not_a_503(
    owner_conn: Any,
) -> None:
    store, first, _ = two_approved(owner_conn)
    # Long enough for the CHECK, but a control character the contract refuses.
    rewrite(
        owner_conn, f"UPDATE action_requests SET reason = E'bad\\x01text' WHERE id = '{first.id}'"
    )
    for call in (
        lambda: store.get(first.id),
        lambda: store.list_requests(limit=10, offset=0, now=NOW),
        lambda: store.verify_chain(first.id),
    ):
        with pytest.raises(StorageError) as raised:
            call()
        assert isinstance(raised.value, StoredRecordError)
        assert not isinstance(raised.value, e.ActionError)
        assert "bad" not in str(raised.value)


@requires_pg
def test_a_corrupt_event_row_is_a_storage_error(owner_conn: Any) -> None:
    store, first, _ = two_approved(owner_conn)
    rewrite(
        owner_conn,
        f"UPDATE action_history SET note = E'bad\\x01note' WHERE action_id = '{first.id}' AND seq = 4",
    )
    with pytest.raises(StoredRecordError):
        store.history(first.id)
    with pytest.raises(StoredRecordError):
        store.approve(  # the decision reads the end of the chain under its lock
            first.id,
            approver=BOB,
            expected_digest=first.digest,
            expected_version=first.version,
            now=NOW,
        )


def test_a_row_missing_a_column_or_holding_a_wrong_type_does_not_parse() -> None:
    for row in ({}, {"id": 5}):
        with pytest.raises(StoredRecordError):
            request_from_row(row)


# --- time zones and hostile text ----------------------------------------------------------------------------------


@requires_pg
def test_the_chain_verifies_whatever_time_zone_the_session_reads_in(
    owner_conn: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, first, _ = two_approved(owner_conn)
    monkeypatch.setenv("PGTZ", "JST-9")  # a POSIX zone: every server knows it, none is UTC
    reader = store_for(owner_conn.settings)
    assert reader.verify_chain(first.id) is True
    assert reader.get(first.id) == first
    assert [x.at for x in reader.history(first.id)] == [x.at for x in store.history(first.id)]


@requires_pg
def test_hostile_and_non_ascii_text_is_stored_as_data_and_round_trips(owner_conn: Any) -> None:
    store = store_for(owner_conn.settings)
    reason = "'; DROP TABLE action_requests; -- é中\U0001f600 <script>alert(1)</script> %s {0}"
    note = "Refused: über '; DELETE FROM action_history; --"
    request = store.create(new_action(reason=reason), idempotency_key=KEY, now=NOW).request
    assert store.get(request.id) == request and request.reason == reason
    rejected = store.reject(
        request.id,
        actor=BOB,
        expected_digest=request.digest,
        expected_version=request.version,
        reason=note,
        now=NOW,
    )
    assert store.verify_chain(rejected.id) is True
    assert store.history(rejected.id)[-1].note == note


# --- what the triggers refuse even to the owner -------------------------------------------------------------------


def _expect_refused(conn: Any, statement: str, *args: object) -> None:
    with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
        conn.execute(statement, args)
        conn.commit()
    conn.rollback()


@requires_pg
def test_a_finished_request_is_not_changed_and_has_no_further_events(owner_conn: Any) -> None:
    store = store_for(owner_conn.settings)
    request = store.create(new_action(), idempotency_key=KEY, now=NOW).request
    done = store.cancel(
        request.id,
        actor=ALICE,
        expected_digest=request.digest,
        expected_version=request.version,
        reason="No longer needed",
        now=NOW,
    )
    _expect_refused(
        owner_conn,
        "UPDATE action_requests SET state = 'approved', version = version + 1 WHERE id = %s",
        done.id,
    )
    _expect_refused(
        owner_conn, "UPDATE action_requests SET pre_checks = '[{}]'::jsonb WHERE id = %s", done.id
    )
    last = store.history(done.id)[-1]
    _expect_refused(
        owner_conn,
        "INSERT INTO action_history (action_id, seq, at, type, actor_id, from_state, to_state, code, "
        "note, prev_hash, hash) VALUES (%s, %s, now(), 'failed', NULL, 'cancelled', 'cancelled', "
        "'failed', NULL, %s, repeat('c', 64))",
        done.id,
        last.seq + 1,
        last.hash,
    )


@requires_pg
def test_the_requester_cannot_be_written_in_as_an_approver_and_an_approval_needs_its_event(
    owner_conn: Any,
) -> None:
    store = store_for(owner_conn.settings)
    request = store.create(new_action(), idempotency_key=KEY, now=NOW).request
    approvals = '\'[{"approver_id": "alice", "approved_at": "2026-10-18T12:00:00Z"}]\'::jsonb'
    _expect_refused(
        owner_conn,
        f"UPDATE action_requests SET approvals = {approvals}, version = version + 1 WHERE id = %s",
        request.id,
    )
    other = '\'[{"approver_id": "bob", "approved_at": "2026-10-18T12:00:00Z"}]\'::jsonb'
    _expect_refused(  # a well-formed approval, but no `approved` event accounts for it
        owner_conn, f"UPDATE action_requests SET approvals = {other} WHERE id = %s", request.id
    )


@requires_pg
def test_the_app_role_cannot_change_the_identity_of_a_request_or_truncate(
    settings: PostgresSettings,
) -> None:
    if "nsapp_" not in settings.dsn:
        pytest.skip("the owner is not the least-privilege role")
    request = store_for(settings).create(new_action(), idempotency_key=KEY, now=NOW).request
    with settings.connect() as conn:
        for statement in (
            "UPDATE action_requests SET target_id = 'endpoint:other'",
            "UPDATE action_requests SET digest = 'sha256:' || repeat('0', 64)",
            "UPDATE action_requests SET requester_id = 'mallory'",
            "UPDATE action_requests SET create_key = 'another-key-0000000001'",
            "TRUNCATE action_requests",
            "TRUNCATE action_history",
            "ALTER TABLE action_history DISABLE TRIGGER USER",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(statement)
            conn.rollback()
    assert store_for(settings).get(request.id) == request


@requires_pg
def test_the_app_role_holds_exactly_the_privileges_the_store_needs(
    settings: PostgresSettings,
) -> None:
    if "nsapp_" not in settings.dsn:
        pytest.skip("the owner is not the least-privilege role")
    with settings.connect() as conn:

        def holds(table: str, privilege: str) -> bool:
            row = conn.execute(
                "SELECT has_table_privilege(%s, %s) AS ok", (table, privilege)
            ).fetchone()
            assert row is not None
            return bool(row["ok"])

        def can_update(table: str, column: str) -> bool:
            row = conn.execute(
                "SELECT has_column_privilege(%s, %s, 'UPDATE') AS ok", (table, column)
            ).fetchone()
            assert row is not None
            return bool(row["ok"])

        for table in ("action_requests", "action_history"):
            assert holds(table, "SELECT") and holds(table, "INSERT")
            assert not any(
                holds(table, p) for p in ("UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
            )
        movable = ("state", "version", "approvals", "execute_by", "run_by", "pre_checks")
        movable += ("execution", "exec_key", "exec_actor_id", "evicted_at")
        assert all(can_update("action_requests", column) for column in movable)
        fixed = ("id", "action_type", "target_id", "params", "risk", "requester_id", "reason")
        fixed += ("source", "created_at", "approve_by", "digest", "create_key", "policy_checks")
        assert not any(can_update("action_requests", column) for column in fixed)
        assert not any(
            can_update("action_history", column)
            for column in ("seq", "at", "type", "code", "note", "prev_hash", "hash", "actor_id")
        )
