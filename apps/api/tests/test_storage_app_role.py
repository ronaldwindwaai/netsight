"""Live least-privilege tests: the runtime role is a non-owner with narrow grants.

Everything here connects as a throwaway login role that is neither superuser nor
owner of any table, after the migrator applied the migrations and the grants.
Needs ``NETSIGHT_TEST_PG_DSN`` to point at a role allowed to CREATE ROLE.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

import psycopg
import pytest
from pg_support import PG_DSN, app_role, isolated_schema, requires_pg
from test_storage_conformance import (
    FakeClock,
    new_incident,
    resolution_input,
    rule_definition,
    window_definition,
)

from netsight_api.storage import migrate
from netsight_api.storage.postgres import (
    PostgresAlertRuleRepository,
    PostgresIncidentRepository,
    PostgresSettings,
)

pytestmark = requires_pg


@dataclass(frozen=True)
class Env:
    owner: PostgresSettings
    app: PostgresSettings
    role: str


@pytest.fixture
def env() -> Iterator[Env]:
    assert PG_DSN
    with isolated_schema() as schema, app_role() as (role, role_dsn):
        owner = PostgresSettings(dsn=PG_DSN, schema=schema)
        with owner.connect() as conn:
            migrate.apply_up(conn)
            migrate.apply_grants(conn, role)
        yield Env(owner, PostgresSettings(dsn=role_dsn, schema=schema), role)


def _seed(env: Env) -> None:
    repo = PostgresIncidentRepository(env.app, clock=FakeClock())
    incident = new_incident(repo)
    repo.append_event(incident.id, kind="comment", actor_id="u", message="original")
    rules = PostgresAlertRuleRepository(env.app, clock=FakeClock())
    rules.create_rule(rule_definition(), actor_id="u")


FORBIDDEN_STATEMENTS = [
    # append-only timeline: no UPDATE / DELETE / TRUNCATE privilege at all
    "UPDATE incident_timeline_events SET message = 'edited'",
    "DELETE FROM incident_timeline_events",
    "TRUNCATE incident_timeline_events",
    # nobody deletes or truncates the other tables either
    "DELETE FROM incidents",
    "TRUNCATE incidents CASCADE",
    "DELETE FROM alert_rules",
    "DELETE FROM maintenance_windows",
    # column-level UPDATE: immutable columns stay immutable
    "UPDATE incidents SET title = 'renamed'",
    "UPDATE incidents SET created_at = now()",
    "UPDATE incidents SET severity = 'low'",
    "UPDATE alert_rules SET created_by = 'someone-else'",
    "UPDATE alert_rules SET created_at = now()",
    "UPDATE maintenance_windows SET name = 'renamed'",
    "UPDATE maintenance_windows SET created_by = 'someone-else'",
    # no DDL, no trigger tampering, no schema tracking access
    "CREATE TABLE evil (id int)",
    "DROP TABLE incident_timeline_events",
    "DROP TABLE incidents",
    "ALTER TABLE incident_timeline_events DISABLE TRIGGER ALL",
    "ALTER TABLE incident_timeline_events DISABLE TRIGGER incident_timeline_events_no_update_delete",
    "ALTER TABLE incident_timeline_events ADD COLUMN extra text",
    "DROP FUNCTION netsight_reject_timeline_mutation()",
    "SELECT * FROM netsight_schema_migrations",
    "INSERT INTO netsight_schema_migrations (version, name) VALUES ('9999', 'x')",
    "DELETE FROM netsight_schema_migrations",
    "SET session_replication_role = replica",
]


@pytest.mark.parametrize("statement", FORBIDDEN_STATEMENTS)
def test_app_role_is_denied_destructive_and_ddl_statements(env: Env, statement: str) -> None:
    _seed(env)
    with env.app.connect() as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute(statement)  # type: ignore[arg-type]


def test_denied_statements_changed_nothing(env: Env) -> None:
    _seed(env)
    for statement in FORBIDDEN_STATEMENTS:
        try:
            with env.app.connect() as conn:
                conn.execute(statement)  # type: ignore[arg-type]
        except psycopg.errors.InsufficientPrivilege:
            continue
    with env.owner.connect() as conn:
        row = conn.execute("SELECT message FROM incident_timeline_events").fetchone()
        titles = conn.execute("SELECT title FROM incidents").fetchall()
    assert row == {"message": "original"}
    assert titles == [{"title": "Perimeter outage"}]


def test_app_role_is_not_an_owner_superuser_or_member_of_privileged_roles(env: Env) -> None:
    with env.owner.connect() as conn:
        role = conn.execute(
            "SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls FROM pg_roles "
            "WHERE rolname = %s",
            (env.role,),
        ).fetchone()
        owned = conn.execute(
            "SELECT count(*) AS n FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner "
            "WHERE r.rolname = %s",
            (env.role,),
        ).fetchone()
    assert role == {
        "rolsuper": False,
        "rolcreaterole": False,
        "rolcreatedb": False,
        "rolbypassrls": False,
    }
    assert owned == {"n": 0}


def test_public_has_no_privileges_on_the_schema_or_tables(env: Env) -> None:
    # grantee 0 is PUBLIC in aclexplode()
    with env.owner.connect() as conn:
        on_schema = conn.execute(
            "SELECT count(*) AS n FROM pg_namespace n, aclexplode(n.nspacl) a "
            "WHERE n.nspname = %s AND a.grantee = 0",
            (env.owner.schema,),
        ).fetchone()
        on_tables = conn.execute(
            "SELECT count(*) AS n FROM pg_class c, aclexplode(c.relacl) a "
            "WHERE c.relnamespace = %s::regnamespace AND a.grantee = 0",
            (env.owner.schema,),
        ).fetchone()
    assert on_schema == {"n": 0}
    assert on_tables == {"n": 0}


def test_grants_are_idempotent_and_do_not_widen_on_rerun(env: Env) -> None:
    with env.owner.connect() as conn:
        migrate.apply_grants(conn, env.role)
        migrate.apply_grants(conn, env.role)
    with env.app.connect() as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute("DELETE FROM incident_timeline_events")


def test_repository_operations_still_work_as_the_app_role(env: Env) -> None:
    clock = FakeClock()
    incidents = PostgresIncidentRepository(env.app, clock=clock)
    rules = PostgresAlertRuleRepository(env.app, clock=clock)

    incident = new_incident(incidents, evidence_ids=["ev-1"])
    incidents.add_evidence(incident.id, evidence_id="ev-2", actor_id="u-1")
    incidents.set_assignee(incident.id, assignee_id="u-9", actor_id="u-1")
    incidents.append_event(incident.id, kind="comment", actor_id="u-1", message="looking")
    for state in ("acknowledged", "investigating", "mitigated"):
        incidents.transition_state(incident.id, to_state=state, actor_id="u-1")  # type: ignore[arg-type]
    resolved = incidents.transition_state(
        incident.id, to_state="resolved", actor_id="u-1", resolution=resolution_input()
    )
    assert resolved.resolution is not None
    incidents.transition_state(incident.id, to_state="closed", actor_id="u-1")
    reopened = incidents.transition_state(
        incident.id, to_state="open", actor_id="u-1", reason="regressed"
    )
    assert reopened.state == "open"
    assert [e.seq for e in incidents.list_timeline(incident.id)] == list(range(1, 11))
    assert [i.id for i in incidents.list_incidents(state="open")] == [incident.id]

    rule = rules.create_rule(rule_definition(), actor_id="u-1")
    edited = rules.update_rule(
        rule.id, rule_definition(name="renamed"), expected_version=1, actor_id="u-1"
    )
    active = rules.approve_rule(edited.id, approver_id="u-2", expected_version=edited.version)
    disabled = rules.disable_rule(active.id, actor_id="u-1")
    assert (disabled.status, disabled.version) == ("disabled", 4)
    assert [r.id for r in rules.list_rules(status="disabled")] == [rule.id]

    window = rules.create_window(window_definition(), actor_id="u-1")
    assert rules.cancel_window(window.id, actor_id="u-1").status == "cancelled"
    assert rules.list_windows(include_cancelled=True)[0].id == window.id
