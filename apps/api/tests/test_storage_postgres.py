"""PostgreSQL storage tests.

Static/offline tests (settings, migration pairing, SQL hygiene) always run.
Live tests need ``NETSIGHT_TEST_PG_DSN`` and are skipped otherwise.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import psycopg
import pytest
from pg_support import PG_DSN, isolated_schema, requires_pg
from test_storage_conformance import FakeClock, new_incident

from netsight_api.storage import (
    InvalidOperationError,
    StorageConfigurationError,
    StorageConflictError,
    StorageError,
    StorageUnavailableError,
    migrate,
)
from netsight_api.storage.connection import (
    APP_TIMEOUTS,
    MIGRATOR_TIMEOUTS,
    PostgresSettings,
    SessionTimeouts,
    translate_database_error,
)
from netsight_api.storage.postgres import PostgresIncidentRepository

STORAGE_DIR = Path(migrate.__file__).parent
APP_TABLES = {"incidents", "incident_timeline_events", "alert_rules", "maintenance_windows"}
EVALUATION_TABLES = {
    "alert_incident_links",
    "notification_delivery_attempts",
    "diagnostic_sessions",
}


# --- offline -----------------------------------------------------------------


def test_settings_never_reveal_the_dsn() -> None:
    secret = "postgresql://netsight:hunter2-very-secret@db.internal:5432/netsight"
    settings = PostgresSettings(dsn=secret)
    for rendered in (repr(settings), str(settings), f"{settings}", f"{settings!r}"):
        assert "hunter2" not in rendered
        assert "db.internal" not in rendered


def test_settings_from_env_reads_dsn_and_normalises_sqlalchemy_scheme() -> None:
    settings = PostgresSettings.from_env(
        {"DATABASE_URL": "postgresql+psycopg://u:p@localhost:5432/netsight"}
    )
    assert settings.dsn == "postgresql://u:p@localhost:5432/netsight"


@pytest.mark.parametrize("env", [{}, {"DATABASE_URL": ""}, {"DATABASE_URL": "   "}])
def test_settings_from_env_fails_closed_without_leaking(env: dict[str, str]) -> None:
    with pytest.raises(StorageConfigurationError) as raised:
        PostgresSettings.from_env(env)
    assert "DATABASE_URL" in str(raised.value)


def test_settings_reject_non_postgres_dsn_without_echoing_it() -> None:
    with pytest.raises(StorageConfigurationError) as raised:
        PostgresSettings.from_env({"DATABASE_URL": "mysql://root:topsecret@h/db"})
    assert "topsecret" not in str(raised.value)


@pytest.mark.parametrize("schema", ["a b", "x;drop", "1abc", "", "A" * 64, 'q"uote'])
def test_settings_reject_unsafe_schema_names(schema: str) -> None:
    with pytest.raises(StorageConfigurationError):
        PostgresSettings(dsn="postgresql://h/db", schema=schema)


def test_migrations_are_paired_ordered_and_contiguous() -> None:
    migrations = migrate.available_migrations()
    assert migrations, "no migrations found"
    assert [m.version for m in migrations] == sorted(m.version for m in migrations)
    assert [m.version for m in migrations] == [
        f"{index:04d}" for index in range(1, len(migrations) + 1)
    ]
    for migration in migrations:
        assert migration.up_path.is_file()
        # The source tree carries the rollback; the production wheel does not.
        assert migration.down_path is not None and migration.down_path.is_file()
        assert migration.down_path.read_text("utf-8").strip()


def test_up_migration_enforces_append_only_and_down_reverses_every_object() -> None:
    up = (migrate.MIGRATIONS_DIR / "0001_incident_alert_storage.up.sql").read_text("utf-8")
    down = (migrate.MIGRATIONS_DIR / "0001_incident_alert_storage.down.sql").read_text("utf-8")
    assert re.search(r"BEFORE UPDATE OR DELETE ON incident_timeline_events", up)
    assert re.search(r"BEFORE TRUNCATE ON incident_timeline_events", up)
    assert re.search(r"ON DELETE RESTRICT", up)
    assert "ON DELETE CASCADE" not in up
    assert "not even by the table owner" not in up  # an owner can always disable triggers
    for table in APP_TABLES:
        assert re.search(rf"CREATE TABLE {table}\b", up)
        assert re.search(rf"DROP TABLE (IF EXISTS )?{table}\b", down)


def test_list_statements_are_split_instead_of_using_optional_filters() -> None:
    source = (STORAGE_DIR / "postgres.py").read_text("utf-8")
    assert "IS NULL OR" not in source, "optional-filter predicates defeat index use"


SQL_VERBS = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b")


def test_runtime_sql_is_never_built_with_string_formatting() -> None:
    source = (STORAGE_DIR / "postgres.py").read_text("utf-8")
    for number, line in enumerate(source.splitlines(), start=1):
        if not SQL_VERBS.search(line):
            continue
        stripped = line.strip()
        assert not re.search(r"""\bf["']""", stripped), f"f-string SQL at line {number}"
        assert ".format(" not in stripped, f"format() SQL at line {number}"
        assert "% (" not in stripped and '%s" %' not in stripped, f"%-formatted SQL line {number}"
        assert not re.search(r"""["']\s*\+""", stripped), f"concatenated SQL at line {number}"


def test_storage_package_has_no_embedded_credentials() -> None:
    for path in STORAGE_DIR.rglob("*"):
        if path.suffix in {".py", ".sql"}:
            text = path.read_text("utf-8")
            assert not re.search(r"postgres(ql)?(\+\w+)?://[^\s\"']*:[^\s\"'@]+@", text), path


# --- live PostgreSQL ------------------------------------------------------------


@pytest.fixture
def pg() -> Iterator[PostgresSettings]:
    assert PG_DSN
    with isolated_schema() as schema:
        yield PostgresSettings(dsn=PG_DSN, schema=schema)


def tables_in_schema(settings: PostgresSettings) -> set[str]:
    with settings.connect() as conn:
        rows = conn.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = %s",
            (settings.schema,),
        ).fetchall()
    return {row["table_name"] for row in rows}


def functions_in_schema(settings: PostgresSettings) -> set[str]:
    with settings.connect() as conn:
        rows = conn.execute(
            "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = %s",
            (settings.schema,),
        ).fetchall()
    return {row["proname"] for row in rows}


@requires_pg
def test_migrations_apply_idempotently_and_reverse_cleanly(pg: PostgresSettings) -> None:
    with pg.connect() as conn:
        applied = migrate.apply_up(conn)
        assert applied == ["0001", "0002", "0003", "0004"]
        assert migrate.apply_up(conn) == []
    assert (APP_TABLES | EVALUATION_TABLES) <= tables_in_schema(pg)

    with pg.connect() as conn:
        assert migrate.apply_down(conn, steps=4, allow_destructive=True) == [
            "0004",
            "0003",
            "0002",
            "0001",
        ]
        assert migrate.apply_down(conn, allow_destructive=True) == []
    assert not ((APP_TABLES | EVALUATION_TABLES) & tables_in_schema(pg))
    assert not any(name.startswith("netsight_") for name in functions_in_schema(pg))

    with pg.connect() as conn:
        assert migrate.apply_up(conn) == ["0001", "0002", "0003", "0004"]
    assert APP_TABLES <= tables_in_schema(pg)


@pytest.fixture
def migrated(pg: PostgresSettings) -> PostgresSettings:
    with pg.connect() as conn:
        migrate.apply_up(conn)
    return pg


def _seed_incident_with_event(settings: PostgresSettings) -> str:
    repo = PostgresIncidentRepository(settings, clock=FakeClock())
    incident = new_incident(repo)
    repo.append_event(incident.id, kind="comment", actor_id="u", message="original")
    return incident.id


def _uuid_of(incident_id: str) -> uuid.UUID:
    return uuid.UUID(incident_id.removeprefix("incident-"))


@requires_pg
@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE incident_timeline_events SET message = 'edited'",
        "DELETE FROM incident_timeline_events",
        "TRUNCATE incident_timeline_events",
    ],
)
def test_database_itself_rejects_timeline_mutation(
    migrated: PostgresSettings, statement: str
) -> None:
    incident_id = _seed_incident_with_event(migrated)
    with migrated.connect() as conn, pytest.raises(psycopg.errors.IntegrityConstraintViolation):
        conn.execute(statement)
    with migrated.connect() as conn:
        row = conn.execute(
            "SELECT message FROM incident_timeline_events WHERE incident_id = %s",
            (_uuid_of(incident_id),),
        ).fetchone()
    assert row == {"message": "original"}


@requires_pg
def test_incident_with_history_cannot_be_deleted(migrated: PostgresSettings) -> None:
    incident_id = _seed_incident_with_event(migrated)
    with migrated.connect() as conn, pytest.raises(psycopg.errors.ForeignKeyViolation):
        conn.execute("DELETE FROM incidents WHERE id = %s", (_uuid_of(incident_id),))


@requires_pg
def test_check_constraints_back_up_the_contract_invariants(migrated: PostgresSettings) -> None:
    now = datetime(2026, 10, 8, 8, 0, tzinfo=UTC)
    bad_statements: list[tuple[str, tuple[object, ...]]] = [
        (
            (
                "INSERT INTO incidents (id, title, severity, state, created_at, updated_at) "
                "VALUES (%s, 't', 'high', 'resolved', %s, %s)"
            ),
            (uuid.uuid4(), now, now),
        ),
        (
            (
                "INSERT INTO incidents (id, title, severity, state, created_at, updated_at) "
                "VALUES (%s, 't', 'info', 'open', %s, %s)"
            ),
            (uuid.uuid4(), now, now),
        ),
        (
            (
                "INSERT INTO maintenance_windows (id, name, scope, starts_at, ends_at, "
                "evaluation, status, reason, created_by, created_at) "
                "VALUES (%s, 'n', '{}', %s, %s, 'retain', 'scheduled', 'r', 'u', %s)"
            ),
            (uuid.uuid4(), now, now, now),
        ),
    ]
    for statement, params in bad_statements:
        with migrated.connect() as conn, pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(statement, params)


@requires_pg
def test_event_checks_reject_payloads_the_contract_forbids(migrated: PostgresSettings) -> None:
    incident_id = _uuid_of(_seed_incident_with_event(migrated))
    now = datetime(2026, 10, 8, 9, 0, tzinfo=UTC)
    cases = [
        ("comment", None, None, None, None, None),  # comment without message
        ("state-changed", "open", None, None, None, None),  # missing state_to
        ("comment", "open", None, None, "m", None),  # state_from on a non-state event
        ("state-changed", "closed", "open", None, None, None),  # reopen without reason
        ("alert-linked", None, None, None, None, None),  # missing subject
    ]
    for seq, (kind, s_from, s_to, reason, message, subject) in enumerate(cases, start=10):
        with migrated.connect() as conn, pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO incident_timeline_events (id, incident_id, seq, occurred_at, "
                "actor_id, kind, state_from, state_to, reason, message, subject_id) "
                "VALUES (%s, %s, %s, %s, 'u', %s, %s, %s, %s, %s, %s)",
                (uuid.uuid4(), incident_id, seq, now, kind, s_from, s_to, reason, message, subject),
            )


@requires_pg
def test_concurrent_appends_get_unique_contiguous_sequence_numbers(
    migrated: PostgresSettings,
) -> None:
    repo = PostgresIncidentRepository(migrated, clock=FakeClock())
    incident = new_incident(repo)

    def append(index: int) -> int:
        return repo.append_event(
            incident.id, kind="comment", actor_id="u", message=f"note {index}"
        ).seq

    with ThreadPoolExecutor(max_workers=8) as pool:
        sequences = list(pool.map(append, range(40)))
    assert sorted(sequences) == list(range(1, 41))
    assert [e.seq for e in repo.list_timeline(incident.id, limit=500)] == list(range(1, 41))


@requires_pg
def test_concurrent_conflicting_transitions_only_one_wins(migrated: PostgresSettings) -> None:
    repo = PostgresIncidentRepository(migrated, clock=FakeClock())
    incident = new_incident(repo)

    def acknowledge(_: int) -> str:
        try:
            repo.transition_state(incident.id, to_state="acknowledged", actor_id="u")
        except Exception as error:  # noqa: BLE001 - outcome classification only
            return type(error).__name__
        return "ok"

    with ThreadPoolExecutor(max_workers=6) as pool:
        outcomes = list(pool.map(acknowledge, range(6)))
    assert outcomes.count("ok") == 1
    assert outcomes.count("IllegalTransitionError") == 5
    assert [e.kind for e in repo.list_timeline(incident.id)] == ["state-changed"]


@requires_pg
def test_repository_works_after_a_failed_write_rolls_back(migrated: PostgresSettings) -> None:
    repo = PostgresIncidentRepository(migrated, clock=FakeClock())
    incident = new_incident(repo)
    with pytest.raises(ValueError):
        repo.append_event(incident.id, kind="comment", actor_id="u")
    repo.append_event(incident.id, kind="comment", actor_id="u", message="fine")
    assert [e.seq for e in repo.list_timeline(incident.id)] == [1]


# --- session timeouts (M4) ----------------------------------------------------------


def test_default_timeouts_are_bounded_and_the_migrator_gets_longer_ones() -> None:
    assert (APP_TIMEOUTS.lock_ms, APP_TIMEOUTS.statement_ms) == (5_000, 15_000)
    assert APP_TIMEOUTS.idle_in_transaction_ms == 30_000
    assert MIGRATOR_TIMEOUTS.statement_ms > APP_TIMEOUTS.statement_ms
    assert MIGRATOR_TIMEOUTS.lock_ms > APP_TIMEOUTS.lock_ms


def test_migration_settings_read_the_separate_migrator_variable() -> None:
    env = {"DATABASE_URL": "postgresql://app@h/db", "DATABASE_MIGRATION_URL": "postgresql://m@h/db"}
    settings = PostgresSettings.for_migrator(env)
    assert settings.dsn == "postgresql://m@h/db"
    assert settings.timeouts == MIGRATOR_TIMEOUTS
    with pytest.raises(StorageConfigurationError) as raised:
        PostgresSettings.for_migrator({"DATABASE_URL": "postgresql://app@h/db"})
    assert "DATABASE_MIGRATION_URL" in str(raised.value)


@requires_pg
def test_app_sessions_apply_the_bounded_timeouts(pg: PostgresSettings) -> None:
    def show(settings: PostgresSettings) -> list[str]:
        names = ("lock_timeout", "statement_timeout", "idle_in_transaction_session_timeout")
        with settings.session() as conn:
            values = []
            for name in names:
                row = conn.execute(f"SHOW {name}").fetchone()
                assert row is not None
                values.append(row[name])
            return values

    assert show(pg) == ["5s", "15s", "30s"]
    migrator = PostgresSettings(dsn=pg.dsn, schema=pg.schema, timeouts=MIGRATOR_TIMEOUTS)
    assert show(migrator) == ["30s", "10min", "10min"]


# --- error translation (M5) ---------------------------------------------------------


@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        (psycopg.errors.UniqueViolation(), StorageConflictError),
        (psycopg.errors.SerializationFailure(), StorageConflictError),
        (psycopg.errors.DeadlockDetected(), StorageConflictError),
        (psycopg.errors.CheckViolation(), InvalidOperationError),
        (psycopg.errors.NumericValueOutOfRange(), InvalidOperationError),
        (psycopg.DataError(), InvalidOperationError),
        (psycopg.errors.LockNotAvailable(), StorageUnavailableError),
        (psycopg.errors.QueryCanceled(), StorageUnavailableError),
        (psycopg.errors.IdleInTransactionSessionTimeout(), StorageUnavailableError),
        (psycopg.OperationalError("connection refused"), StorageUnavailableError),
        (psycopg.InterfaceError("closed"), StorageUnavailableError),
        (psycopg.errors.InsufficientPrivilege(), StorageError),
        (psycopg.ProgrammingError("bad sql with secret-token"), StorageError),
    ],
)
def test_database_errors_translate_to_storage_errors_without_leaking(
    raised: psycopg.Error, expected: type[StorageError]
) -> None:
    translated = translate_database_error(raised)
    assert type(translated) is expected
    assert "secret-token" not in str(translated)
    assert "postgres" not in str(translated).lower()


def test_session_translates_connection_failures_without_echoing_the_dsn() -> None:
    settings = PostgresSettings(dsn="postgresql://user:hunter2@127.0.0.1:1/nodb")
    with pytest.raises(StorageUnavailableError) as raised, settings.session():
        pass
    assert "hunter2" not in str(raised.value)


@requires_pg
def test_duplicate_primary_key_is_a_conflict(migrated: PostgresSettings) -> None:
    fixed = uuid.uuid4()
    repo = PostgresIncidentRepository(migrated, clock=FakeClock(), new_uuid=lambda: fixed)
    new_incident(repo)
    with pytest.raises(StorageConflictError):
        new_incident(repo)


@requires_pg
def test_lock_wait_beyond_the_timeout_is_unavailable_not_a_hang(
    migrated: PostgresSettings,
) -> None:
    impatient = PostgresSettings(
        dsn=migrated.dsn,
        schema=migrated.schema,
        timeouts=SessionTimeouts(lock_ms=300, statement_ms=15_000, idle_in_transaction_ms=30_000),
    )
    repo = PostgresIncidentRepository(impatient, clock=FakeClock())
    incident = new_incident(repo)
    with migrated.connect() as holder:
        holder.execute("SELECT 1 FROM incidents WHERE id = %s FOR UPDATE", (_uuid_of(incident.id),))
        with pytest.raises(StorageUnavailableError):
            repo.transition_state(incident.id, to_state="acknowledged", actor_id="u")
    acknowledged = repo.transition_state(incident.id, to_state="acknowledged", actor_id="u")
    assert acknowledged.state == "acknowledged"


@requires_pg
def test_statement_beyond_the_timeout_is_cancelled_as_unavailable(pg: PostgresSettings) -> None:
    quick = PostgresSettings(
        dsn=pg.dsn,
        schema=pg.schema,
        timeouts=SessionTimeouts(lock_ms=1_000, statement_ms=100, idle_in_transaction_ms=30_000),
    )
    with pytest.raises(StorageUnavailableError), quick.session() as conn:
        conn.execute("SELECT pg_sleep(3)")


@requires_pg
def test_nul_characters_are_rejected_as_invalid_not_as_a_server_error(
    migrated: PostgresSettings,
) -> None:
    repo = PostgresIncidentRepository(migrated, clock=FakeClock())
    incident = new_incident(repo)
    with pytest.raises(InvalidOperationError):
        repo.append_event(incident.id, kind="comment", actor_id="u", message="a\x00b")


# --- trigger hardening (H1) -------------------------------------------------------


@requires_pg
def test_timeline_triggers_fire_even_under_replica_replication_role(
    migrated: PostgresSettings,
) -> None:
    with migrated.connect() as conn:
        rows = conn.execute(
            "SELECT tgname, tgenabled FROM pg_trigger WHERE tgrelid = "
            "'incident_timeline_events'::regclass AND NOT tgisinternal"
        ).fetchall()
    assert {row["tgname"]: row["tgenabled"] for row in rows} == {
        "incident_timeline_events_no_update_delete": "A",
        "incident_timeline_events_no_truncate": "A",
    }
    incident_id = _seed_incident_with_event(migrated)
    with migrated.connect() as conn:
        try:
            conn.execute("SET session_replication_role = replica")
        except psycopg.errors.InsufficientPrivilege:
            pytest.skip("test role cannot set session_replication_role")
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            conn.execute(
                "UPDATE incident_timeline_events SET message = 'x' WHERE incident_id = %s",
                (_uuid_of(incident_id),),
            )
