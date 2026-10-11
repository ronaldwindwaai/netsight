"""Migration 0006 and its defences (Step 8c): text checks everywhere, live checks with PostgreSQL.

The application already validates every document and every transition; the database repeats the
rules as CHECKs and triggers so that a bug, a hand-written statement or a least-privilege role still
cannot break the lifecycle, delete a finding, rewrite its timeline or store an executable quarantine.
Live tests run only with ``NETSIGHT_TEST_PG_DSN`` (the opt-in pattern of the other storage suites).
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from typing import Any

import psycopg
import pytest
from pg_support import PG_DSN, app_role, isolated_schema, requires_pg

from netsight_api.storage import migrate
from netsight_api.storage.connection import PostgresSettings

UP = migrate.MIGRATIONS_DIR / "0006_unknown_device_findings.up.sql"
DOWN = migrate.MIGRATIONS_DIR / "0006_unknown_device_findings.down.sql"
GRANTS = migrate.GRANTS_PATH


# --- text checks (no database) ---------------------------------------------------------------------------


def test_the_migration_has_a_rollback_and_is_the_newest() -> None:
    versions = [m.version for m in migrate.available_migrations()]
    assert versions[-1] == "0006" and versions == sorted(versions)
    assert UP.is_file() and DOWN.is_file()


def test_the_rollback_drops_the_timeline_before_the_findings_it_references() -> None:
    text = DOWN.read_text("utf-8")
    assert text.index("unknown_device_events") < text.index(
        "DROP TABLE IF EXISTS unknown_device_findings"
    )
    assert "netsight_guard_unknown_device_update" in text
    assert "netsight_reject_append_only_mutation" not in text.replace("-- ", "").split("DROP")[1]


def test_every_trigger_fires_even_when_a_session_disables_replication_triggers() -> None:
    text = UP.read_text("utf-8")
    triggers = re.findall(r"CREATE TRIGGER (\w+)", text)
    always = set(re.findall(r"ENABLE ALWAYS TRIGGER (\w+)", text))
    assert len(triggers) == 5 and set(triggers) == always


def test_the_migration_refuses_an_executable_quarantine_and_documents_the_missing_prune() -> None:
    text = UP.read_text("utf-8")
    assert "udf_proposal_only" in text and "'executable' = 'false'" in text
    assert "no prune path" in text.lower() or "no application delete and no prune" in text.lower()


def test_the_application_role_never_receives_delete_or_truncate() -> None:
    text = GRANTS.read_text("utf-8")
    grants = re.findall(r"GRANT ([A-Z, ()a-z_]+) ON TABLE %I\.(unknown_device_\w+)", text)
    assert {table for _, table in grants} == {"unknown_device_findings", "unknown_device_events"}
    for privileges, _ in grants:
        assert "DELETE" not in privileges and "TRUNCATE" not in privileges
    assert "unknown_device_findings" in text.split("pg_has_role")[0]  # part of the ownership check


# --- live checks -------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Db:
    owner: PostgresSettings
    app: PostgresSettings
    role: str


@pytest.fixture
def db() -> Iterator[Db]:
    assert PG_DSN
    with ExitStack() as stack:
        schema = stack.enter_context(isolated_schema())
        role, role_dsn = stack.enter_context(app_role())
        owner = PostgresSettings(dsn=PG_DSN, schema=schema)
        with owner.connect() as conn:
            migrate.apply_up(conn)
            migrate.apply_grants(conn, role)
        yield Db(owner, PostgresSettings(dsn=role_dsn, schema=schema), role)


ENDPOINT = {"ip": "10.0.5.9", "mac": "aa:bb:cc:00:11:22", "hostname": "printer-x"}
CHAIN = [{"slot": s} for s in ("ip", "mac", "attachment", "port", "vlan")]
COMPARISON = {"checks": [], "checked_at": "2026-10-11T12:00:00Z"}


def insert_finding(
    conn: psycopg.Connection[Any],
    *,
    subject: str = "mac:aa:bb:cc:00:11:22",
    state: str = "new",
    severity: str = "medium",
    basis: str = "policy-default",
    endpoint: dict[str, Any] | None = None,
    proposed_action: dict[str, Any] | None = None,
) -> uuid.UUID:
    key = uuid.uuid4()
    conn.execute(
        "INSERT INTO unknown_device_findings (id, subject_key, state, severity, severity_basis, "
        "first_seen_at, last_seen_at, seen_count, endpoint, chain, comparison, proposed_action, "
        "created_at, updated_at) VALUES (%s, %s, %s, %s, %s, now(), now(), 1, %s::jsonb, %s::jsonb, "
        "%s::jsonb, %s::jsonb, now(), now())",
        (
            key,
            subject,
            state,
            severity,
            basis,
            json.dumps(endpoint or ENDPOINT),
            json.dumps(CHAIN),
            json.dumps(COMPARISON),
            None if proposed_action is None else json.dumps(proposed_action),
        ),
    )
    return key


def insert_event(
    conn: psycopg.Connection[Any], finding: uuid.UUID, seq: int = 1, **fields: Any
) -> None:
    values = {
        "kind": "detected",
        "state_from": None,
        "state_to": None,
        "reason": None,
        "message": None,
        **fields,
    }
    conn.execute(
        "INSERT INTO unknown_device_events (id, finding_id, seq, occurred_at, actor_id, kind, state_from, "
        "state_to, reason, message) VALUES (%s, %s, %s, now(), 'system:test', %s, %s, %s, %s, %s)",
        (
            uuid.uuid4(),
            finding,
            seq,
            values["kind"],
            values["state_from"],
            values["state_to"],
            values["reason"],
            values["message"],
        ),
    )


@requires_pg
def test_the_timeline_cannot_be_rewritten_by_anyone_even_the_owner(db: Db) -> None:
    with db.owner.connect() as conn:
        finding = insert_finding(conn)
        insert_event(conn, finding)
        conn.commit()
        for statement in (
            "UPDATE unknown_device_events SET message = 'x'",
            "DELETE FROM unknown_device_events",
            "TRUNCATE unknown_device_events",
        ):
            with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
                conn.execute(statement)
            conn.rollback()
        conn.execute("SET session_replication_role = replica")
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            conn.execute("DELETE FROM unknown_device_events")


@requires_pg
def test_a_finding_can_never_be_deleted(db: Db) -> None:
    with db.owner.connect() as conn:
        insert_finding(conn)
        conn.commit()
        for statement in (
            "DELETE FROM unknown_device_findings",
            "TRUNCATE unknown_device_findings CASCADE",
        ):
            with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
                conn.execute(statement)
            conn.rollback()


@requires_pg
@pytest.mark.parametrize(
    "assignment",
    [
        "id = gen_random_uuid()",
        "subject_key = 'ip:10.9.9.9'",
        "first_seen_at = now() - interval '1 day'",
        "created_at = now() - interval '1 day'",
        "recurrence_of = id",
    ],
)
def test_the_identity_of_a_finding_is_immutable(db: Db, assignment: str) -> None:
    with db.owner.connect() as conn:
        insert_finding(conn)
        conn.commit()
        with pytest.raises(
            (psycopg.errors.IntegrityConstraintViolation, psycopg.errors.CheckViolation)
        ):
            conn.execute(f"UPDATE unknown_device_findings SET {assignment}")


@requires_pg
@pytest.mark.parametrize(
    ("start", "target", "allowed"),
    [
        ("new", "acknowledged", True),
        ("new", "investigating", False),
        ("new", "resolved", True),
        ("acknowledged", "investigating", True),
        ("acknowledged", "new", False),
        ("investigating", "acknowledged", False),
        ("investigating", "false-positive", True),
        ("resolved", "new", False),
        ("resolved", "acknowledged", False),
        ("false-positive", "new", False),
    ],
)
def test_the_database_enforces_the_lifecycle_table(
    db: Db, start: str, target: str, allowed: bool
) -> None:
    with db.owner.connect() as conn:
        key = insert_finding(conn, state=start)
        conn.commit()
        statement = "UPDATE unknown_device_findings SET state = %s WHERE id = %s"
        if allowed:
            conn.execute(statement, (target, key))
        else:
            with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
                conn.execute(statement, (target, key))


@requires_pg
def test_a_finished_finding_is_not_changed_at_all(db: Db) -> None:
    with db.owner.connect() as conn:
        key = insert_finding(conn, state="resolved")
        conn.commit()
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            conn.execute("UPDATE unknown_device_findings SET seen_count = 2 WHERE id = %s", (key,))


@requires_pg
def test_there_is_one_open_finding_per_endpoint_and_a_new_one_after_it_is_finished(db: Db) -> None:
    with db.owner.connect() as conn:
        first = insert_finding(conn)
        conn.commit()
        with pytest.raises(psycopg.errors.UniqueViolation):
            insert_finding(conn)
        conn.rollback()
        conn.execute(
            "UPDATE unknown_device_findings SET state = 'resolved' WHERE id = %s", (first,)
        )
        insert_finding(conn)  # allowed: the first is finished


@requires_pg
def test_an_executable_or_wrong_quarantine_is_refused_by_the_database(db: Db) -> None:
    good = {"action_type": "endpoint.isolate", "state": "proposed", "executable": False}
    with db.owner.connect() as conn:
        insert_finding(
            conn,
            proposed_action=good,
            subject="ip:10.0.5.20",
            endpoint={"ip": "10.0.5.20", "mac": None, "hostname": None},
        )
        for bad in (
            {**good, "executable": True},
            {**good, "state": "authorised"},
            {**good, "action_type": "switch.port.disable"},
        ):
            with pytest.raises(psycopg.errors.CheckViolation):
                insert_finding(
                    conn,
                    proposed_action=bad,
                    subject="ip:10.0.5.21",
                    endpoint={"ip": "10.0.5.21", "mac": None, "hostname": None},
                )
            conn.rollback()


@requires_pg
def test_the_subject_must_be_the_endpoint_and_severity_must_match_its_basis(db: Db) -> None:
    with db.owner.connect() as conn:
        for kwargs in (
            {"subject": "mac:aa:bb:cc:00:11:99"},  # not this endpoint's MAC
            {"subject": "ip:10.0.5.9"},  # the endpoint has a MAC: the MAC is the identity
            {"severity": "unknown", "basis": "policy-rule"},
            {"severity": "high", "basis": "no-policy"},
            {"subject": "not a key"},
        ):
            with pytest.raises(psycopg.errors.CheckViolation):
                insert_finding(conn, **kwargs)
            conn.rollback()


@requires_pg
def test_recorded_state_changes_must_be_legal_and_carry_their_reason(db: Db) -> None:
    with db.owner.connect() as conn:
        finding = insert_finding(conn)
        insert_event(conn, finding, 1)
        insert_event(
            conn, finding, 2, kind="state-changed", state_from="new", state_to="acknowledged"
        )
        conn.commit()
        for seq, fields in (
            (
                3,
                {
                    "kind": "state-changed",
                    "state_from": "resolved",
                    "state_to": "new",
                    "reason": "x",
                },
            ),
            (3, {"kind": "state-changed", "state_from": "acknowledged", "state_to": "resolved"}),
            (3, {"kind": "state-changed", "state_from": "acknowledged"}),
            (3, {"kind": "comment"}),
            (3, {"kind": "deleted"}),
        ):
            with pytest.raises(psycopg.errors.CheckViolation):
                insert_event(conn, finding, seq, **fields)
            conn.rollback()
        with pytest.raises(psycopg.errors.UniqueViolation):
            insert_event(conn, finding, 2, kind="comment", message="duplicate sequence number")


@requires_pg
def test_the_application_role_has_exactly_the_privileges_it_needs(db: Db) -> None:
    with db.owner.connect() as conn:
        insert_finding(conn)
        conn.commit()
    with db.app.connect() as conn:
        assert (
            conn.execute("SELECT count(*) AS n FROM unknown_device_findings").fetchone()["n"] == 1
        )  # type: ignore[index]
        conn.execute(
            "UPDATE unknown_device_findings SET seen_count = seen_count + 1, updated_at = now()"
        )
        conn.commit()
        forbidden = [
            "DELETE FROM unknown_device_findings",
            "TRUNCATE unknown_device_findings",
            "UPDATE unknown_device_findings SET subject_key = 'ip:1.2.3.4'",
            "UPDATE unknown_device_findings SET first_seen_at = now()",
            "UPDATE unknown_device_findings SET created_at = now()",
            "UPDATE unknown_device_findings SET recurrence_of = id",
            "UPDATE unknown_device_events SET message = 'x'",
            "DELETE FROM unknown_device_events",
            "TRUNCATE unknown_device_events",
            "DROP TABLE unknown_device_findings",
            "ALTER TABLE unknown_device_findings DISABLE TRIGGER ALL",
        ]
        for statement in forbidden:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(statement)
            conn.rollback()


@requires_pg
def test_the_application_role_does_not_own_the_tables(db: Db) -> None:
    with db.owner.connect() as conn:
        rows = conn.execute(
            "SELECT relname, pg_get_userbyid(relowner) AS owner FROM pg_class "
            "WHERE relname IN ('unknown_device_findings', 'unknown_device_events') "
            "AND relnamespace = current_schema()::regnamespace"
        ).fetchall()
    assert len(rows) == 2 and all(r["owner"] != db.role for r in rows)


@requires_pg
def test_the_rollback_is_guarded_and_reversible(db: Db) -> None:
    with db.owner.connect() as conn:
        insert_finding(conn)
        conn.commit()
        with pytest.raises(migrate.DestructiveMigrationError):
            migrate.apply_down(conn, allow_destructive=True, env={})
        assert "0006" in migrate.migration_status(conn).applied
        # reverse only 0006 (the newest), with consent
        assert migrate.apply_down(
            conn, allow_destructive=True, env={migrate.DESTRUCTIVE_ENV: "1"}
        ) == ["0006"]
        conn.commit()
        assert conn.execute(
            "SELECT to_regclass('unknown_device_findings') IS NULL AS gone"
        ).fetchone()["gone"]  # type: ignore[index]
        assert migrate.apply_up(conn) == ["0006"]
        conn.commit()
        assert conn.execute(
            "SELECT to_regclass('unknown_device_events') IS NOT NULL AS here"
        ).fetchone()["here"]  # type: ignore[index]
