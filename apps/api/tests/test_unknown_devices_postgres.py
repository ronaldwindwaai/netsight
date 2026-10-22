"""Migration 0006 and its defences (Step 8c): text checks everywhere, live checks with PostgreSQL.

The application already validates every document and every transition; the database repeats the
rules as CHECKs and triggers so that a bug, a hand-written statement or a least-privilege role still
cannot break the lifecycle, delete a finding, rewrite its timeline or store an executable quarantine.
The timeline is the record: the commit fails unless every change of a finding's state, assignee or
evidence has its event in the same transaction, and no event claims a change that did not happen.
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

LEGAL_PATHS = {
    "new": [],
    "acknowledged": ["acknowledged"],
    "investigating": ["acknowledged", "investigating"],
    "resolved": ["resolved"],
    "false-positive": ["false-positive"],
}


# --- text checks (no database) ---------------------------------------------------------------------------


def test_the_migration_has_a_rollback_and_is_the_newest() -> None:
    versions = [m.version for m in migrate.available_migrations()]
    assert "0006" in versions and versions == sorted(versions)  # later migrations may follow
    assert UP.is_file() and DOWN.is_file()


def test_the_rollback_drops_the_timeline_before_the_findings_it_references() -> None:
    text = DOWN.read_text("utf-8")
    assert text.index("unknown_device_events") < text.index(
        "DROP TABLE IF EXISTS unknown_device_findings"
    )
    assert "netsight_guard_unknown_device_update" in text
    assert "netsight_reject_append_only_mutation" not in text.replace("-- ", "").split("DROP")[1]


def test_the_rollback_drops_every_function_the_migration_created() -> None:
    created = set(re.findall(r"CREATE FUNCTION (\w+)", UP.read_text("utf-8")))
    dropped = set(re.findall(r"DROP FUNCTION IF EXISTS (\w+)", DOWN.read_text("utf-8")))
    assert created and created == dropped


def test_every_trigger_fires_even_when_a_session_disables_replication_triggers() -> None:
    text = UP.read_text("utf-8")
    triggers = re.findall(r"CREATE (?:CONSTRAINT )?TRIGGER (\w+)", text)
    always = set(re.findall(r"ENABLE ALWAYS TRIGGER (\w+)", text))
    assert len(triggers) == 8 and set(triggers) == always


def test_the_timeline_triggers_are_deferred_constraint_triggers() -> None:
    text = UP.read_text("utf-8")
    for name in ("unknown_device_findings_logged", "unknown_device_events_logged"):
        block = text.split(f"CREATE CONSTRAINT TRIGGER {name}")[1].split(";")[0]
        assert "DEFERRABLE INITIALLY DEFERRED" in block


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


def test_the_application_role_cannot_write_the_evidence_version() -> None:
    text = GRANTS.read_text("utf-8")
    update = text.split("GRANT UPDATE (state, severity")[1].split("ON TABLE")[0]
    assert "evidence_version" not in update


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
CHECKS = [
    {"field": "ip", "result": "no-match", "detail": None},
    {"field": "mac", "result": "no-match", "detail": None},
    {"field": "hostname", "result": "no-match", "detail": None},
]
COMPARISON = {"checks": CHECKS, "checked_at": "2026-10-11T12:00:00Z", "reason": "no-match"}
SUBJECT = "mac:aa:bb:cc:00:11:22"


def snapshot_of(
    *,
    endpoint: dict[str, Any] | None = None,
    chain: list[dict[str, Any]] | None = None,
    comparison: dict[str, Any] | None = None,
    severity: str = "medium",
    basis: str = "policy-default",
    proposed_action: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """What a ``detected`` or ``evidence-updated`` event keeps: the evidence of that moment."""
    return {
        "endpoint": endpoint or ENDPOINT,
        "chain": chain or CHAIN,
        "comparison": comparison or COMPARISON,
        "severity": severity,
        "severity_basis": basis,
        "proposed_action": proposed_action,
    }


def insert_finding(
    conn: psycopg.Connection[Any],
    *,
    subject: str = SUBJECT,
    severity: str = "medium",
    basis: str = "policy-default",
    endpoint: dict[str, Any] | None = None,
    proposed_action: dict[str, Any] | None = None,
    detected: bool = True,
    **columns: Any,
) -> uuid.UUID:
    """A finding with its ``detected`` event (the commit refuses one without)."""
    key = uuid.uuid4()
    values: dict[str, Any] = {"state": "new", "seen_count": 1, **columns}
    conn.execute(
        "INSERT INTO unknown_device_findings (id, subject_key, state, severity, severity_basis, "
        "first_seen_at, last_seen_at, seen_count, endpoint, chain, comparison, proposed_action, "
        "created_at, updated_at) VALUES (%s, %s, %s, %s, %s, now(), now(), %s, %s::jsonb, %s::jsonb, "
        "%s::jsonb, %s::jsonb, now(), now())",
        (
            key,
            subject,
            values["state"],
            severity,
            basis,
            values["seen_count"],
            json.dumps(endpoint or ENDPOINT),
            json.dumps(CHAIN),
            json.dumps(COMPARISON),
            None if proposed_action is None else json.dumps(proposed_action),
        ),
    )
    if detected:
        insert_event(
            conn,
            key,
            1,
            kind="detected",
            snapshot=snapshot_of(
                endpoint=endpoint,
                severity=severity,
                basis=basis,
                proposed_action=proposed_action,
            ),
        )
    return key


def insert_event(
    conn: psycopg.Connection[Any], finding: uuid.UUID, seq: int = 2, **fields: Any
) -> None:
    values = {
        "kind": "comment",
        "state_from": None,
        "state_to": None,
        "reason": None,
        "message": None,
        "subject_id": None,
        "snapshot": None,
        **fields,
    }
    if values["kind"] == "comment" and values["message"] is None:
        values["message"] = "note"
    snapshot = values["snapshot"]
    conn.execute(
        "INSERT INTO unknown_device_events (id, finding_id, seq, occurred_at, actor_id, kind, "
        "state_from, state_to, reason, message, subject_id, snapshot) "
        "VALUES (%s, %s, %s, now(), 'system:test', %s, %s, %s, %s, %s, %s, %s::jsonb)",
        (
            uuid.uuid4(),
            finding,
            seq,
            values["kind"],
            values["state_from"],
            values["state_to"],
            values["reason"],
            values["message"],
            values["subject_id"],
            None if snapshot is None else json.dumps(snapshot),
        ),
    )


def move(conn: psycopg.Connection[Any], key: uuid.UUID, start: str, target: str, seq: int) -> None:
    """One state change, with the event that records it."""
    conn.execute("UPDATE unknown_device_findings SET state = %s WHERE id = %s", (target, key))
    insert_event(
        conn,
        key,
        seq,
        kind="state-changed",
        state_from=start,
        state_to=target,
        reason="because" if target in ("resolved", "false-positive") else None,
    )


def finding_in(conn: psycopg.Connection[Any], state: str, **kwargs: Any) -> tuple[uuid.UUID, int]:
    """A finding brought to ``state`` by legal, recorded steps; the next free sequence number."""
    key = insert_finding(conn, **kwargs)
    seq, current = 2, "new"
    for step in LEGAL_PATHS[state]:
        move(conn, key, current, step, seq)
        seq, current = seq + 1, step
    return key, seq


@requires_pg
def test_the_timeline_cannot_be_rewritten_by_anyone_even_the_owner(db: Db) -> None:
    with db.owner.connect() as conn:
        finding = insert_finding(conn)
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
    assert finding


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
        key, seq = finding_in(conn, start)
        conn.commit()
        if allowed:
            move(conn, key, start, target, seq)
            conn.commit()
            row = conn.execute("SELECT state FROM unknown_device_findings WHERE id = %s", (key,))
            assert row.fetchone()["state"] == target  # type: ignore[index]
        else:
            with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
                conn.execute(
                    "UPDATE unknown_device_findings SET state = %s WHERE id = %s", (target, key)
                )


@requires_pg
def test_a_finished_finding_is_not_changed_at_all(db: Db) -> None:
    with db.owner.connect() as conn:
        key, _ = finding_in(conn, "resolved")
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
        move(conn, first, "new", "resolved", 2)
        insert_finding(conn)  # allowed: the first is finished
        conn.commit()


@requires_pg
def test_an_executable_or_wrong_quarantine_is_refused_by_the_database(db: Db) -> None:
    good = {"action_type": "endpoint.isolate", "state": "proposed", "executable": False}
    only_ip = {"ip": "10.0.5.20", "mac": None, "hostname": None}
    with db.owner.connect() as conn:
        insert_finding(conn, proposed_action=good, subject="ip:10.0.5.20", endpoint=only_ip)
        conn.commit()
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
@pytest.mark.parametrize(
    "subject",
    [
        "MAC:aa:bb:cc:00:11:22",  # upper-case prefix
        "mac:AA:BB:CC:00:11:22",  # upper-case digits
        "ip:010.0.5.9",  # a leading zero is not canonical
        "ip:10.0.5",  # not an address
        "ip:10.0.5.256",
        "ip:FE80::1",  # upper-case IPv6
        "host:Printer-X",
    ],
)
def test_a_subject_key_must_be_lower_case_and_canonical(db: Db, subject: str) -> None:
    endpoint = {"ip": subject.removeprefix("ip:"), "mac": None, "hostname": None}
    with db.owner.connect() as conn, pytest.raises(psycopg.errors.CheckViolation):
        insert_finding(conn, subject=subject, endpoint=endpoint)


@requires_pg
def test_canonical_address_keys_are_accepted(db: Db) -> None:
    with db.owner.connect() as conn:
        for ip in ("10.0.5.9", "0.0.0.0", "255.255.255.255", "fe80::1", "2001:db8::ff00:42:8329"):
            insert_finding(
                conn,
                subject=f"ip:{ip}",
                endpoint={"ip": ip, "mac": None, "hostname": None},
            )
        conn.commit()


@requires_pg
@pytest.mark.parametrize(
    "columns",
    [{"state": "acknowledged"}, {"state": "resolved"}, {"seen_count": 5}],
)
def test_a_finding_starts_new_and_seen_once(db: Db, columns: dict[str, Any]) -> None:
    with db.owner.connect() as conn, pytest.raises(psycopg.errors.CheckViolation):
        insert_finding(conn, **columns)


@requires_pg
def test_a_finding_starts_unassigned(db: Db) -> None:
    with db.owner.connect() as conn:
        key = insert_finding(conn, detected=False)
        conn.rollback()
        assert key
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO unknown_device_findings (id, subject_key, state, severity, "
                "severity_basis, assignee_id, first_seen_at, last_seen_at, seen_count, endpoint, "
                "chain, comparison, created_at, updated_at) VALUES (%s, %s, 'new', 'low', "
                "'policy-rule', 'someone', now(), now(), 1, %s::jsonb, %s::jsonb, %s::jsonb, now(), "
                "now())",
                (
                    uuid.uuid4(),
                    SUBJECT,
                    json.dumps(ENDPOINT),
                    json.dumps(CHAIN),
                    json.dumps(COMPARISON),
                ),
            )


@requires_pg
def test_recorded_state_changes_must_be_legal_and_carry_their_reason(db: Db) -> None:
    with db.owner.connect() as conn:
        finding, seq = finding_in(conn, "acknowledged")
        conn.commit()
        for fields in (
            {
                "kind": "state-changed",
                "state_from": "resolved",
                "state_to": "new",
                "reason": "x",
            },
            {"kind": "state-changed", "state_from": "acknowledged", "state_to": "resolved"},
            {"kind": "state-changed", "state_from": "acknowledged"},
            {"kind": "comment", "message": None, "state_from": "new", "state_to": "acknowledged"},
            {"kind": "deleted"},
        ):
            with pytest.raises(psycopg.errors.CheckViolation):
                conn.execute("SAVEPOINT s")
                insert_event(conn, finding, seq, **{"message": None, **fields})
            conn.execute("ROLLBACK TO SAVEPOINT s")
        with pytest.raises(psycopg.errors.UniqueViolation):
            insert_event(
                conn, finding, seq - 1, kind="comment", message="duplicate sequence number"
            )


@requires_pg
@pytest.mark.parametrize(
    "fields",
    [
        {"kind": "state-changed", "state_from": "new", "state_to": "acknowledged", "message": "x"},
        {"kind": "assignee-changed", "subject_id": "someone", "reason": "because"},
        {"kind": "comment", "subject_id": "someone"},
        {"kind": "comment", "snapshot": {"a": 1}},
        {"kind": "evidence-updated"},  # no snapshot
        {"kind": "suppressed-sighting"},  # no snapshot
        {"kind": "detected", "snapshot": {"a": 1}},  # only the first event is the detection
    ],
)
def test_events_carry_only_the_fields_of_their_kind(db: Db, fields: dict[str, Any]) -> None:
    with db.owner.connect() as conn:
        finding = insert_finding(conn)
        with pytest.raises(psycopg.errors.CheckViolation):
            insert_event(conn, finding, 2, **fields)


@requires_pg
def test_a_detected_event_must_carry_its_snapshot_and_be_first(db: Db) -> None:
    with db.owner.connect() as conn:
        key = insert_finding(conn, detected=False)
        with pytest.raises(psycopg.errors.CheckViolation):
            insert_event(conn, key, 1, kind="detected")  # no snapshot
        conn.rollback()
        key = insert_finding(conn, detected=False)
        with pytest.raises(psycopg.errors.CheckViolation):
            insert_event(conn, key, 2, kind="detected", snapshot=snapshot_of())  # not the first


# --- the timeline is the record (database review H1) ------------------------------------------------------------


@requires_pg
def test_a_finding_without_its_detected_event_cannot_be_committed(db: Db) -> None:
    with db.owner.connect() as conn:
        insert_finding(conn, detected=False)
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            conn.commit()


@requires_pg
@pytest.mark.parametrize(
    "change",
    [
        "state = 'acknowledged'",
        "assignee_id = 'someone'",
        "severity = 'high', severity_basis = 'policy-rule'",
        "endpoint = jsonb_set(endpoint, '{hostname}', '\"other\"')",
        "chain = jsonb_set(chain, '{0,basis}', '\"observed\"')",
        "comparison = jsonb_set(comparison, '{checks,0,result}', '\"not-checked\"')",
        "comparison = jsonb_set(comparison, '{reason}', '\"name-matches-mac-does-not\"')",
        (
            "proposed_action = "
            '\'{"action_type":"endpoint.isolate","state":"proposed","executable":false}\''
        ),
    ],
)
def test_a_change_of_state_assignee_or_evidence_without_its_event_cannot_be_committed(
    db: Db, change: str
) -> None:
    with db.owner.connect() as conn:
        key = insert_finding(conn)
        conn.commit()
        conn.execute(f"UPDATE unknown_device_findings SET {change} WHERE id = %s", (key,))
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            conn.commit()


@requires_pg
def test_the_same_changes_commit_when_their_events_are_in_the_same_transaction(db: Db) -> None:
    with db.owner.connect() as conn:
        key = insert_finding(conn)
        conn.commit()
        move(conn, key, "new", "acknowledged", 2)
        conn.execute(
            "UPDATE unknown_device_findings SET assignee_id = 'someone' WHERE id = %s", (key,)
        )
        insert_event(conn, key, 3, kind="assignee-changed", subject_id="someone")
        conn.execute(
            "UPDATE unknown_device_findings SET severity = 'high', severity_basis = 'policy-rule' "
            "WHERE id = %s",
            (key,),
        )
        insert_event(
            conn,
            key,
            4,
            kind="evidence-updated",
            snapshot=snapshot_of(severity="high", basis="policy-rule"),
        )
        conn.commit()


@requires_pg
def test_counters_and_times_move_without_any_event(db: Db) -> None:
    with db.owner.connect() as conn:
        key = insert_finding(conn)
        conn.commit()
        conn.execute(
            "UPDATE unknown_device_findings SET seen_count = seen_count + 1, "
            "last_seen_at = now() + interval '1 minute', updated_at = now() WHERE id = %s",
            (key,),
        )
        conn.commit()


@requires_pg
@pytest.mark.parametrize(
    "event",
    [
        {"kind": "state-changed", "state_from": "new", "state_to": "acknowledged"},  # no update
        {"kind": "assignee-changed", "subject_id": "someone"},  # no update
        {"kind": "evidence-updated", "snapshot": "same"},  # nothing changed
    ],
)
def test_an_event_that_claims_a_change_which_did_not_happen_cannot_be_committed(
    db: Db, event: dict[str, Any]
) -> None:
    with db.owner.connect() as conn:
        key = insert_finding(conn)
        conn.commit()
        fields = dict(event)
        if fields.get("snapshot") == "same":
            fields["snapshot"] = snapshot_of()
        insert_event(conn, key, 2, **fields)
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            conn.commit()


@requires_pg
def test_a_state_change_must_start_from_where_the_timeline_left_the_finding(db: Db) -> None:
    with db.owner.connect() as conn:
        key = insert_finding(conn)
        conn.commit()
        conn.execute(
            "UPDATE unknown_device_findings SET state = 'acknowledged' WHERE id = %s", (key,)
        )
        # the event says investigating -> resolved, which the finding never did
        insert_event(
            conn,
            key,
            2,
            kind="state-changed",
            state_from="investigating",
            state_to="resolved",
            reason="x",
        )
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            conn.commit()


@requires_pg
def test_an_assignment_that_changes_nothing_cannot_be_recorded(db: Db) -> None:
    with db.owner.connect() as conn:
        key = insert_finding(conn)
        conn.execute(
            "UPDATE unknown_device_findings SET assignee_id = 'someone' WHERE id = %s", (key,)
        )
        insert_event(conn, key, 2, kind="assignee-changed", subject_id="someone")
        conn.commit()
        insert_event(conn, key, 3, kind="assignee-changed", subject_id="someone")
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            conn.commit()


@requires_pg
def test_unassigning_is_recorded_as_a_change_to_nobody(db: Db) -> None:
    with db.owner.connect() as conn:
        key = insert_finding(conn)
        conn.execute(
            "UPDATE unknown_device_findings SET assignee_id = 'someone' WHERE id = %s", (key,)
        )
        insert_event(conn, key, 2, kind="assignee-changed", subject_id="someone")
        conn.commit()
        conn.execute("UPDATE unknown_device_findings SET assignee_id = NULL WHERE id = %s", (key,))
        insert_event(conn, key, 3, kind="assignee-changed")
        conn.commit()


@requires_pg
def test_a_suppressed_sighting_needs_no_change_of_the_finding(db: Db) -> None:
    with db.owner.connect() as conn:
        key, seq = finding_in(conn, "false-positive")
        conn.commit()
        insert_event(conn, key, seq, kind="suppressed-sighting", snapshot=snapshot_of())
        conn.commit()


@requires_pg
def test_the_triggers_hold_for_the_application_role_too(db: Db) -> None:
    with db.owner.connect() as conn:
        key = insert_finding(conn)
        conn.commit()
    with db.app.connect() as conn:
        conn.execute(
            "UPDATE unknown_device_findings SET state = 'acknowledged' WHERE id = %s", (key,)
        )
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            conn.commit()


# --- evidence version (database review H2) --------------------------------------------------------------------------------


def version(conn: psycopg.Connection[Any], key: uuid.UUID) -> int:
    row = conn.execute(
        "SELECT evidence_version AS v FROM unknown_device_findings WHERE id = %s", (key,)
    )
    found = row.fetchone()
    assert found is not None
    return int(found["v"])


@requires_pg
def test_the_evidence_version_moves_by_one_exactly_when_the_evidence_does(db: Db) -> None:
    with db.owner.connect() as conn:
        key = insert_finding(conn)
        conn.commit()
        assert version(conn, key) == 1
        conn.execute(
            "UPDATE unknown_device_findings SET seen_count = seen_count + 1, comparison = "
            "jsonb_set(comparison, '{checked_at}', '\"2030-01-01T00:00:00Z\"') WHERE id = %s",
            (key,),
        )
        assert version(conn, key) == 1  # a sighting is not a change of the evidence
        conn.execute(
            "UPDATE unknown_device_findings SET assignee_id = 'someone' WHERE id = %s", (key,)
        )
        assert version(conn, key) == 1  # nor is an assignment
        conn.execute(
            "UPDATE unknown_device_findings SET severity = 'high', severity_basis = 'policy-rule' "
            "WHERE id = %s",
            (key,),
        )
        assert version(conn, key) == 2
        conn.rollback()


@requires_pg
def test_nobody_can_set_the_evidence_version(db: Db) -> None:
    with db.owner.connect() as conn:
        key = insert_finding(conn)
        conn.commit()
        conn.execute(
            "UPDATE unknown_device_findings SET evidence_version = 99 WHERE id = %s", (key,)
        )
        assert version(conn, key) == 1  # the trigger decides, whatever the statement said
        conn.rollback()
    with db.app.connect() as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute(
            "UPDATE unknown_device_findings SET evidence_version = 99 WHERE id = %s", (key,)
        )


@requires_pg
def test_an_insert_cannot_choose_the_evidence_version(db: Db) -> None:
    with db.owner.connect() as conn:
        key = uuid.uuid4()
        conn.execute(
            "INSERT INTO unknown_device_findings (id, subject_key, state, severity, severity_basis, "
            "evidence_version, first_seen_at, last_seen_at, seen_count, endpoint, chain, comparison, "
            "created_at, updated_at) VALUES (%s, %s, 'new', 'low', 'policy-rule', 500, now(), now(), "
            "1, %s::jsonb, %s::jsonb, %s::jsonb, now(), now())",
            (key, SUBJECT, json.dumps(ENDPOINT), json.dumps(CHAIN), json.dumps(COMPARISON)),
        )
        assert version(conn, key) == 1
        conn.rollback()


@requires_pg
def test_a_finding_cannot_go_back_in_time_or_lose_sightings(db: Db) -> None:
    with db.owner.connect() as conn:
        key = insert_finding(conn, seen_count=1)
        conn.execute("UPDATE unknown_device_findings SET seen_count = 5 WHERE id = %s", (key,))
        conn.commit()
        for change in (
            "seen_count = 4",
            "last_seen_at = last_seen_at - interval '1 hour'",
        ):
            with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
                conn.execute(f"UPDATE unknown_device_findings SET {change} WHERE id = %s", (key,))
            conn.rollback()


@requires_pg
def test_the_indexes_serve_the_open_list_and_the_endpoint_lookups(db: Db) -> None:
    with db.owner.connect() as conn:
        names = {
            r["indexname"]
            for r in conn.execute(
                "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema() "
                "AND tablename IN ('unknown_device_findings', 'unknown_device_events')"
            ).fetchall()
        }
    assert {
        "udf_open_recent_idx",
        "udf_recent_idx",
        "udf_endpoint_mac_idx",
        "udf_endpoint_ip_idx",
        "ude_finding_kind_idx",
    } <= names
    assert "udf_state_recent_idx" not in names


# --- privileges ------------------------------------------------------------------------------------------------------------


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
            migrate.apply_down(conn, steps=2, allow_destructive=True, env={})
        assert "0006" in migrate.migration_status(conn).applied
        # reverse 0007 (empty) and 0006 (holds a finding), with consent
        assert migrate.apply_down(
            conn, steps=2, allow_destructive=True, env={migrate.DESTRUCTIVE_ENV: "1"}
        ) == ["0007", "0006"]
        conn.commit()
        assert conn.execute(
            "SELECT to_regclass('unknown_device_findings') IS NULL AS gone"
        ).fetchone()["gone"]  # type: ignore[index]
        assert (
            conn.execute(
                "SELECT count(*) AS n FROM pg_proc WHERE proname LIKE 'netsight_%unknown_device%' "
                "OR proname = 'netsight_udf_evidence'"
            ).fetchone()["n"]
            == 0
        )  # type: ignore[index]
        assert migrate.apply_up(conn) == ["0006", "0007"]
        conn.commit()
        assert conn.execute(
            "SELECT to_regclass('unknown_device_events') IS NOT NULL AS here"
        ).fetchone()["here"]  # type: ignore[index]


@requires_pg
def test_counters_saturate_at_the_cap_instead_of_failing(db: Db) -> None:
    from unknown_support import detection

    from netsight_api.storage.postgres_unknown_devices import PostgresUnknownDeviceRepository

    repository = PostgresUnknownDeviceRepository(db.app)
    first = repository.observe(detection())
    with db.owner.connect() as conn:
        conn.execute("UPDATE unknown_device_findings SET seen_count = 1000000")
        conn.commit()
    again = repository.observe(detection())
    assert again.outcome == "refreshed" and again.finding_id == first.finding_id
    found = repository.get_finding(first.finding_id)
    assert found is not None and found.seen_count == 1_000_000
