"""Conformance for the diagnostic session store (S7 Step 4a).

The same tests run against the in-memory implementation and (with ``NETSIGHT_TEST_PG_DSN``)
PostgreSQL as the migrator/owner and as the least-privilege application role. Sessions are
immutable once saved: there is no update or delete path and the database rejects both, even for
the table owner. Migration 0004 text checks run without a database.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta

import pytest
from diagnostic_support import make_session, session_id
from pg_support import app_role, isolated_schema, requires_pg

from netsight_api.storage import StorageConflictError, StorageError, migrate
from netsight_api.storage.diagnostics import (
    DiagnosticSessionRepository,
    InMemoryDiagnosticSessionRepository,
)

T0 = datetime(2026, 10, 10, 8, 0, tzinfo=UTC)
UP = migrate.MIGRATIONS_DIR / "0004_diagnostic_sessions.up.sql"
DOWN = migrate.MIGRATIONS_DIR / "0004_diagnostic_sessions.down.sql"


@pytest.fixture(
    params=[
        "memory",
        pytest.param("postgres", marks=requires_pg),
        pytest.param("postgres-app-role", marks=requires_pg),
    ]
)
def store(request: pytest.FixtureRequest) -> Iterator[DiagnosticSessionRepository]:
    if request.param == "memory":
        yield InMemoryDiagnosticSessionRepository()
        return
    from pg_support import PG_DSN

    from netsight_api.storage.connection import PostgresSettings
    from netsight_api.storage.postgres_diagnostics import PostgresDiagnosticSessionRepository

    assert PG_DSN
    with ExitStack() as stack:
        schema = stack.enter_context(isolated_schema())
        owner = PostgresSettings(dsn=PG_DSN, schema=schema)
        runtime = owner
        role_name = ""
        if request.param == "postgres-app-role":
            role_name, role_dsn = stack.enter_context(app_role())
            runtime = PostgresSettings(dsn=role_dsn, schema=schema)
        with owner.connect() as conn:
            migrate.apply_up(conn)
            if role_name:
                migrate.apply_grants(conn, role_name)
        yield PostgresDiagnosticSessionRepository(runtime)


# --- behaviour ---------------------------------------------------------------------------------


def test_a_saved_session_is_read_back_identically(store: DiagnosticSessionRepository) -> None:
    session = make_session(1)
    store.save_session(session, actor_id="user-1")
    assert store.get_session(session.run.id) == session


def test_an_unknown_or_malformed_id_reads_as_none(store: DiagnosticSessionRepository) -> None:
    assert store.get_session(session_id(404)) is None
    assert store.get_session("diagnostic-nope") is None
    assert store.get_session("incident-" + session_id(1)[len("diagnostic-") :]) is None


def test_a_finished_session_can_never_be_overwritten(store: DiagnosticSessionRepository) -> None:
    original = make_session(1, target="SERVER01")
    store.save_session(original, actor_id="user-1")
    with pytest.raises(StorageConflictError):
        store.save_session(make_session(1, target="TAMPERED"), actor_id="user-2")
    assert store.get_session(original.run.id) == original


def test_concurrent_saves_of_one_id_keep_exactly_one(store: DiagnosticSessionRepository) -> None:
    def attempt(n: int) -> bool:
        try:
            store.save_session(make_session(7, target=f"host-{n}"), actor_id="user-1")
        except StorageConflictError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt, range(8)))
    assert outcomes.count(True) == 1
    assert store.get_session(session_id(7)) is not None


def test_the_list_is_newest_first_with_a_stable_tiebreak(
    store: DiagnosticSessionRepository,
) -> None:
    store.save_session(make_session(1, completed_at=T0), actor_id="u")
    store.save_session(make_session(2, completed_at=T0 + timedelta(minutes=5)), actor_id="u")
    store.save_session(make_session(3, completed_at=T0 + timedelta(minutes=5)), actor_id="u")
    ids = [row.id for row in store.list_sessions()]
    assert ids == [session_id(3), session_id(2), session_id(1)]


def test_the_list_is_paged_and_projects_summaries(store: DiagnosticSessionRepository) -> None:
    for number in range(1, 6):
        store.save_session(
            make_session(
                number, target=f"host-{number}", completed_at=T0 + timedelta(minutes=number)
            ),
            actor_id="u",
        )
    first = store.list_sessions(limit=2, offset=0)
    second = store.list_sessions(limit=2, offset=2)
    assert [row.target for row in first] == ["host-5", "host-4"]
    assert [row.target for row in second] == ["host-3", "host-2"]
    assert first[0].probable_fault_domain == "firewall" and first[0].confidence == "medium"
    assert store.list_sessions(limit=2, offset=10) == []


def test_the_store_counts_sessions_completed_since_a_time(
    store: DiagnosticSessionRepository,
) -> None:
    assert store.count_sessions_since(T0) == 0
    for number, minutes in enumerate((0, 30, 90), start=1):
        store.save_session(
            make_session(number, completed_at=T0 + timedelta(minutes=minutes)), actor_id="u"
        )
    assert store.count_sessions_since(T0) == 3
    assert store.count_sessions_since(T0 + timedelta(minutes=30)) == 2
    assert store.count_sessions_since(T0 + timedelta(hours=3)) == 0


def test_an_empty_store_lists_nothing(store: DiagnosticSessionRepository) -> None:
    assert store.list_sessions() == []


@pytest.mark.parametrize(("limit", "offset"), [(0, 0), (101, 0), (-1, 0), (10, -1), (10, 10_001)])
def test_paging_bounds_are_enforced(
    store: DiagnosticSessionRepository, limit: int, offset: int
) -> None:
    with pytest.raises(ValueError, match="limit|offset"):
        store.list_sessions(limit=limit, offset=offset)


def test_the_store_offers_no_update_or_delete(store: DiagnosticSessionRepository) -> None:
    names = {name for name in dir(store) if not name.startswith("_")}
    assert not {n for n in names if n.startswith(("update", "delete", "remove", "set_", "edit"))}


def test_the_actor_is_validated_and_never_part_of_the_session(
    store: DiagnosticSessionRepository,
) -> None:
    with pytest.raises(ValueError, match="actor"):
        store.save_session(make_session(1), actor_id="")
    store.save_session(make_session(1), actor_id="user-1")
    assert "user-1" not in store.get_session(session_id(1)).model_dump_json()  # type: ignore[union-attr]


# --- migration 0004 (static) --------------------------------------------------------------------


def test_up_creates_an_immutable_table_with_restricted_privileges() -> None:
    up = UP.read_text("utf-8")
    assert re.search(r"CREATE TABLE diagnostic_sessions\b", up)
    assert re.search(r"REVOKE ALL ON TABLE diagnostic_sessions FROM PUBLIC", up)
    assert re.search(r"BEFORE UPDATE OR DELETE ON diagnostic_sessions", up)
    assert re.search(r"BEFORE TRUNCATE ON diagnostic_sessions", up)
    assert up.count("ENABLE ALWAYS TRIGGER") == 2
    assert "CASCADE" not in up
    assert "netsight_reject_append_only_mutation" in up
    assert not re.search(r"CREATE (OR REPLACE )?FUNCTION", up)  # reuses the 0003 function


def test_the_size_bound_counts_bytes_of_the_text_form() -> None:
    up = UP.read_text("utf-8")
    assert "octet_length(document::text) <= 1048576" in up
    assert "pg_column_size" not in up  # that is the compressed size and does not bound the text


def test_the_listing_index_matches_the_ordering() -> None:
    up = UP.read_text("utf-8")
    assert re.search(r"ON diagnostic_sessions \(completed_at DESC, id DESC\)", up)


def test_down_drops_exactly_the_new_table_and_is_visible_to_the_data_guard() -> None:
    down = DOWN.read_text("utf-8")
    assert set(migrate._DROP_TABLE.findall(down)) == {"diagnostic_sessions"}
    assert "DROP FUNCTION" not in down  # the shared trigger function belongs to 0003


def test_grants_give_the_app_role_select_and_insert_only() -> None:
    grants = migrate.GRANTS_PATH.read_text("utf-8")
    assert "GRANT SELECT, INSERT ON TABLE %I.diagnostic_sessions TO %I" in grants
    assert not re.search(r"GRANT UPDATE[^;]*diagnostic_sessions", grants)
    assert "%1$I.diagnostic_sessions" in grants  # revoked first, like every table


# --- live PostgreSQL ----------------------------------------------------------------------------


@pytest.fixture
def owner_conn() -> Iterator[object]:
    from pg_support import PG_DSN

    from netsight_api.storage.connection import PostgresSettings

    assert PG_DSN
    with ExitStack() as stack:
        schema = stack.enter_context(isolated_schema())
        settings = PostgresSettings(dsn=PG_DSN, schema=schema)
        with settings.connect() as conn:
            migrate.apply_up(conn)
        yield settings


@requires_pg
def test_even_the_owner_cannot_update_delete_or_truncate(owner_conn) -> None:  # type: ignore[no-untyped-def]
    import psycopg

    from netsight_api.storage.postgres_diagnostics import PostgresDiagnosticSessionRepository

    PostgresDiagnosticSessionRepository(owner_conn).save_session(make_session(1), actor_id="u")
    for statement in (
        "UPDATE diagnostic_sessions SET target = 'x'",
        "DELETE FROM diagnostic_sessions",
        "TRUNCATE diagnostic_sessions",
    ):
        with (
            owner_conn.connect() as conn,
            pytest.raises(psycopg.errors.IntegrityConstraintViolation),
        ):
            conn.execute(statement)  # type: ignore[arg-type]
    assert PostgresDiagnosticSessionRepository(owner_conn).get_session(session_id(1)) is not None


@requires_pg
def test_the_app_role_has_no_update_delete_or_ddl_rights() -> None:
    import psycopg
    from pg_support import PG_DSN

    from netsight_api.storage.connection import PostgresSettings
    from netsight_api.storage.postgres_diagnostics import PostgresDiagnosticSessionRepository

    assert PG_DSN
    with isolated_schema() as schema, app_role() as (role, role_dsn):
        owner = PostgresSettings(dsn=PG_DSN, schema=schema)
        with owner.connect() as conn:
            migrate.apply_up(conn)
            migrate.apply_grants(conn, role)
        runtime = PostgresSettings(dsn=role_dsn, schema=schema)
        PostgresDiagnosticSessionRepository(runtime).save_session(make_session(1), actor_id="u")
        for statement in (
            "UPDATE diagnostic_sessions SET target = 'x'",
            "DELETE FROM diagnostic_sessions",
            "TRUNCATE diagnostic_sessions",
            "ALTER TABLE diagnostic_sessions ADD COLUMN x int",
            "DROP TABLE diagnostic_sessions",
        ):
            with runtime.connect() as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(statement)  # type: ignore[arg-type]


_RAW_INSERT = (
    "INSERT INTO diagnostic_sessions (id, target, started_at, completed_at, "
    "probable_fault_domain, confidence, created_by, created_at, document) "
    "VALUES (%s, %s, %s, %s, %s, %s, 'u', now(), %s)"
)


def raw_insert(settings, session, *, document=None, **column_overrides):  # type: ignore[no-untyped-def]
    """INSERT a row bypassing the repository, so a CHECK constraint is what is under test."""
    from psycopg.types.json import Jsonb

    run = session.run
    columns = {
        "id": uuid.UUID(run.id.removeprefix("diagnostic-")),
        "target": run.target,
        "started_at": run.started_at,
        "completed_at": run.completed_at,
        "probable_fault_domain": run.probable_fault_domain,
        "confidence": run.confidence,
        **column_overrides,
    }
    doc = session.model_dump(mode="json", by_alias=True) if document is None else document
    with settings.connect() as conn:
        conn.execute(_RAW_INSERT, (*columns.values(), Jsonb(doc)))  # type: ignore[arg-type]


@requires_pg
def test_a_corrupt_stored_document_is_a_storage_error_not_a_session(owner_conn) -> None:  # type: ignore[no-untyped-def]
    from netsight_api.storage.postgres_diagnostics import PostgresDiagnosticSessionRepository

    # The mirrored columns agree with the document, so only the contract (not the database) can
    # tell this document is broken: it lacks a required section.
    session = make_session(9)
    broken = session.model_dump(mode="json", by_alias=True)
    del broken["path"]
    raw_insert(owner_conn, session, document=broken)
    with pytest.raises(StorageError):
        PostgresDiagnosticSessionRepository(owner_conn).get_session(session_id(9))


@requires_pg
@pytest.mark.parametrize(
    ("override", "constraint"),
    [
        ({"id": uuid.UUID(int=999)}, "diagnostic_sessions_id_matches_document"),
        ({"target": "another"}, "diagnostic_sessions_target_matches_document"),
        (
            {"completed_at": T0 + timedelta(days=1), "started_at": T0},
            "diagnostic_sessions_completed_at_matches_document",
        ),
        ({"probable_fault_domain": "core"}, "diagnostic_sessions_domain_matches_document"),
        ({"confidence": "high"}, "diagnostic_sessions_confidence_matches_document"),
    ],
)
def test_a_column_that_disagrees_with_the_document_is_refused(  # type: ignore[no-untyped-def]
    owner_conn, override, constraint
) -> None:
    import psycopg

    with pytest.raises(psycopg.errors.CheckViolation) as raised:
        raw_insert(owner_conn, make_session(1), **override)
    assert raised.value.diag.constraint_name == constraint


@requires_pg
def test_a_blank_target_is_refused_like_the_contract_refuses_it(owner_conn) -> None:  # type: ignore[no-untyped-def]
    import psycopg

    blank = make_session(1).model_dump(mode="json", by_alias=True)
    blank["run"]["target"] = "   "
    with pytest.raises(psycopg.errors.CheckViolation) as raised:
        raw_insert(owner_conn, make_session(1), document=blank, target="   ")
    assert raised.value.diag.constraint_name == "diagnostic_sessions_target_valid"


@requires_pg
def test_a_document_over_one_mebibyte_of_text_is_refused_even_if_it_compresses(owner_conn) -> None:  # type: ignore[no-untyped-def]
    import psycopg

    # pg_column_size sees the compressed (TOAST) size, where this padding shrinks to a few KB;
    # octet_length of the text form does not, so the byte bound is real.
    big = make_session(1).model_dump(mode="json", by_alias=True)
    big["padding"] = "a" * (1024 * 1024 + 1)
    with pytest.raises(psycopg.errors.CheckViolation) as raised:
        raw_insert(owner_conn, make_session(1), document=big)
    assert raised.value.diag.constraint_name == "diagnostic_sessions_document_bounded"


@requires_pg
def test_an_incident_title_in_the_stored_document_is_refused(owner_conn) -> None:  # type: ignore[no-untyped-def]
    import psycopg

    leaky = make_session(1).model_dump(mode="json", by_alias=True)
    items = leaky["recent_changes"]["items"]
    assert any(item["kind"] == "incident" for item in items)  # the base vector has one
    for item in items:
        if item["kind"] == "incident":
            item["title"] = "Payroll breach"
            item["title_redacted"] = False
    with pytest.raises(psycopg.errors.CheckViolation) as raised:
        raw_insert(owner_conn, make_session(1), document=leaky)
    assert raised.value.diag.constraint_name == "diagnostic_sessions_no_incident_titles"


@requires_pg
def test_a_redacted_incident_reference_is_accepted(owner_conn) -> None:  # type: ignore[no-untyped-def]
    raw_insert(owner_conn, make_session(1))


@requires_pg
def test_the_triggers_still_fire_when_replication_role_is_replica(owner_conn) -> None:  # type: ignore[no-untyped-def]
    import psycopg

    from netsight_api.storage.postgres_diagnostics import PostgresDiagnosticSessionRepository

    PostgresDiagnosticSessionRepository(owner_conn).save_session(make_session(1), actor_id="u")
    for statement in (
        "UPDATE diagnostic_sessions SET target = 'x'",
        "DELETE FROM diagnostic_sessions",
        "TRUNCATE diagnostic_sessions",
    ):
        with owner_conn.connect() as conn:
            try:
                conn.execute("SET session_replication_role = replica")
            except psycopg.errors.InsufficientPrivilege:
                pytest.skip("this role may not set session_replication_role")
            with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
                conn.execute(statement)  # type: ignore[arg-type]
    assert PostgresDiagnosticSessionRepository(owner_conn).get_session(session_id(1)) is not None


@requires_pg
def test_down_refuses_while_sessions_exist_and_succeeds_with_consent(owner_conn) -> None:  # type: ignore[no-untyped-def]
    from netsight_api.storage.postgres_diagnostics import PostgresDiagnosticSessionRepository

    PostgresDiagnosticSessionRepository(owner_conn).save_session(make_session(1), actor_id="u")
    with owner_conn.connect() as conn, pytest.raises(migrate.DestructiveMigrationError) as raised:
        migrate.apply_down(conn, steps=3, allow_destructive=True, env={})
    assert "diagnostic_sessions" in str(raised.value)
    with owner_conn.connect() as conn:
        assert migrate.apply_down(
            conn, steps=3, allow_destructive=True, env={migrate.DESTRUCTIVE_ENV: "1"}
        ) == ["0006", "0005", "0004"]
        assert conn.execute("SELECT to_regclass('diagnostic_sessions') AS t").fetchone() == {
            "t": None
        }
        # 0003's shared trigger function and tables are untouched
        assert conn.execute("SELECT to_regclass('alert_incident_links') AS t").fetchone() != {
            "t": None
        }


@requires_pg
def test_down_on_an_empty_table_needs_no_environment_override(owner_conn) -> None:  # type: ignore[no-untyped-def]
    with owner_conn.connect() as conn:
        assert migrate.apply_down(conn, steps=3, allow_destructive=True, env={}) == [
            "0006",
            "0005",
            "0004",
        ]
