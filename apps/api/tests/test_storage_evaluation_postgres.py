"""Migration 0003 (alert -> incident links, durable delivery attempts): static checks on the SQL
text plus live least-privilege, append-only and guarded-down tests (skipped without
``NETSIGHT_TEST_PG_DSN``)."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime

import psycopg
import pytest
from pg_support import PG_DSN, app_role, isolated_schema, requires_pg

from netsight_api.notifications.dispatcher import DeliveryAttempt
from netsight_api.notifications.store_postgres import PostgresDeliveryAttemptRepository
from netsight_api.storage import migrate
from netsight_api.storage.postgres import PostgresIncidentRepository, PostgresSettings
from netsight_api.storage.postgres_links import PostgresAlertIncidentLinkRepository

UP = migrate.MIGRATIONS_DIR / "0003_evaluation_links_and_delivery.up.sql"
DOWN = migrate.MIGRATIONS_DIR / "0003_evaluation_links_and_delivery.down.sql"
KEY = "c" * 32
NEW_TABLES = {"alert_incident_links", "notification_delivery_attempts"}


# --- static text -----------------------------------------------------------------------------------


def test_up_creates_both_tables_with_restricted_privileges_and_append_only_triggers() -> None:
    up = UP.read_text("utf-8")
    for table in NEW_TABLES:
        assert re.search(rf"CREATE TABLE {table}\b", up)
    assert re.search(r"REVOKE ALL ON TABLE alert_incident_links, notification_delivery", up)
    assert "REFERENCES incidents (id) ON DELETE RESTRICT" in up
    assert "CASCADE" not in up
    assert re.search(r"BEFORE UPDATE OR DELETE ON notification_delivery_attempts", up)
    assert re.search(r"BEFORE TRUNCATE ON notification_delivery_attempts", up)
    assert up.count("ENABLE ALWAYS TRIGGER") == 2


def test_the_notification_lookup_index_ends_with_id_to_match_its_ordering() -> None:
    up = UP.read_text("utf-8")
    assert re.search(
        r"notification_delivery_notification_idx\s+ON notification_delivery_attempts "
        r"\(notification_id, attempt, id\)",
        up,
    )


def test_grants_allow_the_evaluator_to_record_recovery_on_links_only() -> None:
    grants = migrate.GRANTS_PATH.read_text("utf-8")
    assert "UPDATE (incident_id, linked_at, recovered_at) ON TABLE %I.alert_incident_links" in grants


def test_down_drops_exactly_the_new_objects_and_is_visible_to_the_data_guard() -> None:
    down = DOWN.read_text("utf-8")
    guarded = {name for name in migrate._DROP_TABLE.findall(down)}
    assert guarded == NEW_TABLES  # the guard refuses to run while either table holds rows
    assert "DROP FUNCTION IF EXISTS netsight_reject_append_only_mutation()" in down
    assert "incidents" not in guarded


def test_grants_script_covers_the_new_tables_without_delete() -> None:
    grants = migrate.GRANTS_PATH.read_text("utf-8")
    assert "alert_incident_links" in grants and "notification_delivery_attempts" in grants
    assert "GRANT SELECT, INSERT ON TABLE %I.notification_delivery_attempts" in grants
    assert not re.search(r"GRANT[^;]*\b(DELETE|TRUNCATE|ALL)\b[^;]*alert_incident_links", grants)
    assert not re.search(r"GRANT[^;]*\b(UPDATE|DELETE|TRUNCATE)\b[^;]*delivery_attempts", grants)


# --- live ------------------------------------------------------------------------------------------


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


def _seed(env: Env) -> str:
    incident = PostgresIncidentRepository(env.app).create_incident(
        title="t", severity="high", actor_id="u-1"
    )
    assert PostgresAlertIncidentLinkRepository(env.app).claim(
        "alert", KEY, incident_id=incident.id, replacing=None
    )
    PostgresDeliveryAttemptRepository(env.app).record(
        DeliveryAttempt("n-1", KEY, "email", "email:abc", 1, "sent", "OK", datetime.now(UTC))
    )
    return incident.id


@requires_pg
@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE notification_delivery_attempts SET code = 'X'",
        "DELETE FROM notification_delivery_attempts",
        "TRUNCATE notification_delivery_attempts",
        "DELETE FROM alert_incident_links",
        "TRUNCATE alert_incident_links",
        "UPDATE alert_incident_links SET kind = 'group'",
        "UPDATE alert_incident_links SET dedup_key = repeat('d', 32)",
        "DROP TABLE alert_incident_links",
        "ALTER TABLE notification_delivery_attempts DISABLE TRIGGER ALL",
        "DROP FUNCTION netsight_reject_append_only_mutation()",
    ],
)
def test_app_role_cannot_rewrite_or_remove_links_and_attempts(env: Env, statement: str) -> None:
    _seed(env)
    with env.app.connect() as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute(statement)  # type: ignore[arg-type]


@requires_pg
def test_app_role_may_repoint_a_link_and_nothing_else(env: Env) -> None:
    incident_id = _seed(env)
    other = PostgresIncidentRepository(env.app).create_incident(
        title="t2", severity="low", actor_id="u-1"
    )
    links = PostgresAlertIncidentLinkRepository(env.app)
    assert links.claim("alert", KEY, incident_id=other.id, replacing=incident_id) is True
    assert links.get("alert", KEY) == other.id


@requires_pg
@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE notification_delivery_attempts SET code = 'X'",
        "DELETE FROM notification_delivery_attempts",
        "TRUNCATE notification_delivery_attempts",
    ],
)
def test_even_the_owner_is_stopped_by_the_append_only_trigger(env: Env, statement: str) -> None:
    _seed(env)
    with env.owner.connect() as conn, pytest.raises(psycopg.errors.IntegrityConstraintViolation):
        conn.execute(statement)  # type: ignore[arg-type]


@requires_pg
def test_the_trigger_also_fires_under_replica_replication_role(env: Env) -> None:
    _seed(env)
    with env.owner.connect() as conn:
        try:
            conn.execute("SET session_replication_role = replica")
        except psycopg.errors.InsufficientPrivilege:
            pytest.skip("the test role may not change session_replication_role")
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            conn.execute("DELETE FROM notification_delivery_attempts")


@requires_pg
def test_check_constraints_back_up_the_application_validation(env: Env) -> None:
    bad_rows = [
        "('n 1', 'a', 'email', 'd', 1, 'sent', 'OK')",
        "('n-1', 'a', 'sms', 'd', 1, 'sent', 'OK')",
        "('n-1', 'a', 'email', 'd', 9, 'sent', 'OK')",
        "('n-1', 'a', 'email', 'd', 1, 'queued', 'OK')",
        "('n-1', 'a', 'email', 'line' || chr(10) || 'break', 1, 'sent', 'OK')",
        "('n-1', 'a', 'email', 'd', 1, 'sent', 'not a code')",
    ]
    for values in bad_rows:
        with env.app.connect() as conn, pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO notification_delivery_attempts (notification_id, alert_ref, "  # type: ignore[arg-type]
                "channel, destination, attempt, status, code, attempted_at) "
                f"VALUES {values.rstrip(')')}, now())"
            )
    with env.app.connect() as conn, pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "INSERT INTO alert_incident_links (kind, dedup_key, incident_id, linked_at) "
            "VALUES ('alert', 'NOT-HEX', gen_random_uuid(), now())"
        )


@requires_pg
def test_a_link_cannot_outlive_a_missing_incident(env: Env) -> None:
    with env.app.connect() as conn, pytest.raises(psycopg.errors.ForeignKeyViolation):
        conn.execute(
            "INSERT INTO alert_incident_links (kind, dedup_key, incident_id, linked_at) "
            f"VALUES ('alert', '{KEY}', gen_random_uuid(), now())"
        )


@requires_pg
def test_down_refuses_while_the_new_tables_hold_rows_and_succeeds_with_consent(env: Env) -> None:
    _seed(env)
    with env.owner.connect() as conn, pytest.raises(migrate.DestructiveMigrationError) as raised:
        migrate.apply_down(conn, allow_destructive=True, env={})
    message = str(raised.value)
    assert "alert_incident_links" in message and "notification_delivery_attempts" in message
    with env.owner.connect() as conn:
        assert migrate.apply_down(
            conn, allow_destructive=True, env={migrate.DESTRUCTIVE_ENV: "1"}
        ) == ["0003"]
        row = conn.execute(
            "SELECT to_regclass('alert_incident_links') AS l, "
            "to_regclass('notification_delivery_attempts') AS a"
        ).fetchone()
    assert row == {"l": None, "a": None}
    with env.owner.connect() as conn:  # incidents survive the rollback
        assert conn.execute("SELECT count(*) AS n FROM incidents").fetchone() == {"n": 1}


@requires_pg
def test_down_on_empty_tables_needs_no_environment_override(env: Env) -> None:
    with env.owner.connect() as conn:
        assert migrate.apply_down(conn, allow_destructive=True, env={}) == ["0003"]
