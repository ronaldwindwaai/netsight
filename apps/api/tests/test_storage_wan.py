"""Conformance for the WAN probe-sample store (Step 5b, migration 0005).

The same tests run against the in-memory implementation and (with ``NETSIGHT_TEST_PG_DSN``)
PostgreSQL as the migrator/owner and with the production role split: the collector role INSERTs,
the API role SELECTs. Cycles and samples are append-only: no update or delete path exists, the
database rejects both even for the table owner, and a repeated cycle time is a conflict, never an
overwrite. Both tables are range-partitioned by month; a month without its partition is refused
(fail closed). Migration 0005 text checks run without a database.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from pg_support import requires_pg
from wan_support import WAN_MONTHS, SplitRoleStore, WanDatabase, provision_wan

from netsight_api.storage import StorageConflictError, StorageError, migrate
from netsight_api.storage import wan as wan_store
from netsight_api.storage.wan import (
    InMemoryWanSampleRepository,
    WanPartitionMissingError,
    WanSampleRepository,
)
from netsight_api.wan import sla
from netsight_api.wan.sla import Sample

T0 = datetime(2026, 10, 10, 8, 0, tzinfo=UTC)
UP = migrate.MIGRATIONS_DIR / "0005_wan_probe_samples.up.sql"
DOWN = migrate.MIGRATIONS_DIR / "0005_wan_probe_samples.down.sql"
PARTITIONED_MONTHS = frozenset((d.year, d.month) for d in WAN_MONTHS)


@pytest.fixture(
    params=[
        "memory",
        pytest.param("postgres", marks=requires_pg),
        pytest.param("postgres-split-roles", marks=requires_pg),
    ]
)
def store(request: pytest.FixtureRequest) -> Iterator[WanSampleRepository]:
    if request.param == "memory":
        yield InMemoryWanSampleRepository(partitioned_months=PARTITIONED_MONTHS)
        return
    from netsight_api.storage.postgres_wan import PostgresWanSampleRepository

    with provision_wan() as database:
        if request.param == "postgres":
            yield PostgresWanSampleRepository(database.owner)
        else:
            yield SplitRoleStore(database)


@pytest.fixture
def database() -> Iterator[WanDatabase]:
    with provision_wan() as provisioned:
        yield provisioned


def samples(*outcomes: str, latency: float | None = 12.5) -> list[Sample]:
    return [
        Sample(
            probe="icmp",
            target=f"t{index}.example",
            outcome=outcome,  # type: ignore[arg-type]
            latency_ms=latency if outcome == "pass" else None,
            location="branch",
        )
        for index, outcome in enumerate(outcomes)
    ]


def record(
    store: WanSampleRepository,
    minute: float,
    *outcomes: str,
    link: str = "wan-a",
    extra: list[Sample] | None = None,
    start: datetime = T0,
) -> sla.Cycle:
    rows = samples(*outcomes) + (extra or [])
    when = start + timedelta(seconds=round(minute * 60))
    cycle = sla.build_cycle(link, when, 60, rows)
    store.record_cycle(cycle, rows)
    return cycle


# --- behaviour ----------------------------------------------------------------------------------


def test_a_recorded_cycle_and_its_samples_are_read_back_identically(
    store: WanSampleRepository,
) -> None:
    dns = [Sample(probe="dns", target="dns-check.example", outcome="fail", latency_ms=None)]
    cycle = record(store, 0, "pass", "fail", extra=dns)
    assert store.cycles_between("wan-a", T0, T0 + timedelta(hours=1)) == [cycle]
    rows = store.samples_between("wan-a", T0, T0 + timedelta(hours=1))
    assert [when for when, _ in rows] == [T0] * 3
    assert [sample for _, sample in rows] == [*samples("pass", "fail"), *dns]


def test_a_repeated_cycle_time_is_a_conflict_and_never_an_overwrite(
    store: WanSampleRepository,
) -> None:
    original = record(store, 0, "pass")
    with pytest.raises(StorageConflictError):
        record(store, 0, "fail")
    assert store.cycles_between("wan-a", T0, T0 + timedelta(minutes=1)) == [original]
    assert len(store.samples_between("wan-a", T0, T0 + timedelta(minutes=1))) == 1


def test_a_conflicting_cycle_leaves_no_orphan_samples(store: WanSampleRepository) -> None:
    record(store, 0, "pass")
    with pytest.raises(StorageConflictError):
        record(store, 0, "fail", "fail")
    assert len(store.samples_between("wan-a", T0, T0 + timedelta(minutes=1))) == 1


def test_concurrent_records_of_one_cycle_keep_exactly_one(store: WanSampleRepository) -> None:
    def attempt(n: int) -> bool:
        try:
            record(store, 3, *(["pass"] * (n % 3 + 1)))
        except StorageConflictError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt, range(8)))
    assert outcomes.count(True) == 1
    assert len(store.cycles_between("wan-a", T0, T0 + timedelta(hours=1))) == 1


def test_a_cycle_that_disagrees_with_its_samples_is_refused(store: WanSampleRepository) -> None:
    rows = samples("pass", "pass")
    lying = sla.Cycle("wan-a", T0, 60, 0, 2, 0, "down")
    with pytest.raises(ValueError, match="samples"):
        store.record_cycle(lying, rows)
    assert store.cycles_between("wan-a", T0, T0 + timedelta(hours=1)) == []


def test_reads_include_a_cycle_that_still_covers_the_window_start_and_nothing_older(
    store: WanSampleRepository,
) -> None:
    older = record(store, -10, "pass")  # 10 min before: its coverage has long lapsed
    covering = record(store, -5, "pass")  # 5 min = 300 s before: inside the look-back
    inside = record(store, 1, "pass")
    at_end = record(store, 10, "pass")
    result = store.cycles_between("wan-a", T0, T0 + timedelta(minutes=10))
    assert result == [covering, inside]
    assert older not in result and at_end not in result


def test_cycles_are_ascending_and_isolated_per_link(store: WanSampleRepository) -> None:
    b = record(store, 1, "pass", link="wan-b")
    second = record(store, 2, "pass")
    first = record(store, 1, "pass")
    assert store.cycles_between("wan-a", T0, T0 + timedelta(hours=1)) == [first, second]
    assert store.cycles_between("wan-b", T0, T0 + timedelta(hours=1)) == [b]
    assert store.cycles_between("wan-none", T0, T0 + timedelta(hours=1)) == []


def test_a_read_spanning_two_months_returns_both_in_order(store: WanSampleRepository) -> None:
    end_of_sep = datetime(2026, 9, 30, 23, 58, tzinfo=UTC)
    late = record(store, 0, "pass", start=end_of_sep)
    early = record(store, 3, "pass", start=end_of_sep)  # 00:01 on 1 October
    window = (end_of_sep - timedelta(minutes=1), end_of_sep + timedelta(minutes=10))
    assert store.cycles_between("wan-a", *window) == [late, early]
    assert len(store.samples_between("wan-a", *window)) == 2


def test_samples_are_bounded_and_say_so_instead_of_truncating(
    store: WanSampleRepository,
) -> None:
    for minute in range(5):
        record(store, minute, "pass")
    assert len(store.samples_between("wan-a", T0, T0 + timedelta(hours=1), limit=5)) == 5
    with pytest.raises(StorageError, match="too many"):
        store.samples_between("wan-a", T0, T0 + timedelta(hours=1), limit=4)


def test_a_month_of_cycles_beyond_the_read_cap_is_an_error_not_a_silent_cut(
    store: WanSampleRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    for minute in range(4):
        record(store, minute, "pass")
    monkeypatch.setattr(wan_store, "MAX_CYCLES_READ", 3)
    with pytest.raises(StorageError, match="too many"):
        store.cycles_between("wan-a", T0, T0 + timedelta(hours=1))


def test_probe_sources_are_the_distinct_probes_targets_and_locations(
    store: WanSampleRepository,
) -> None:
    dns = [Sample(probe="dns", target="dns-check.example", outcome="pass", latency_ms=3.0)]
    record(store, 0, "pass", "fail", extra=dns)
    record(store, 1, "pass", "fail", extra=dns)
    found = store.probe_sources("wan-a", T0, T0 + timedelta(hours=1))
    assert [(item.probe, item.target, item.location) for item in found] == [
        ("dns", "dns-check.example", None),
        ("icmp", "t0.example", "branch"),
        ("icmp", "t1.example", "branch"),
    ]
    assert store.probe_sources("wan-a", T0 + timedelta(hours=2), T0 + timedelta(hours=3)) == []


@pytest.mark.parametrize("link", ["", "Wan-A", "wan a", "-x", "x" * 49, "wan/a", "wan\n"])
def test_a_malformed_link_id_is_refused(store: WanSampleRepository, link: str) -> None:
    rows = samples("pass")
    with pytest.raises(ValueError, match="link"):
        store.record_cycle(sla.build_cycle(link, T0, 60, rows), rows)
    with pytest.raises(ValueError, match="link"):
        store.cycles_between(link, T0, T0 + timedelta(hours=1))


def test_too_many_samples_in_one_cycle_are_refused(store: WanSampleRepository) -> None:
    rows = samples(*(["pass"] * (wan_store.MAX_SAMPLES_PER_CYCLE + 1)))
    with pytest.raises(ValueError, match="samples"):
        store.record_cycle(sla.build_cycle("wan-a", T0, 60, rows), rows)


def test_reads_need_aware_times_and_a_forward_window(store: WanSampleRepository) -> None:
    with pytest.raises(ValueError, match="timezone"):
        store.cycles_between("wan-a", T0.replace(tzinfo=None), T0 + timedelta(hours=1))
    with pytest.raises(ValueError, match="before"):
        store.cycles_between("wan-a", T0, T0)


def test_the_store_offers_no_update_or_delete(store: WanSampleRepository) -> None:
    names = {name for name in dir(store) if not name.startswith("_")}
    assert not {n for n in names if n.startswith(("update", "delete", "remove", "set_", "edit"))}


def test_a_target_with_hostile_text_round_trips_as_data(store: WanSampleRepository) -> None:
    rows = [Sample(probe="icmp", target="a.example", outcome="pass", latency_ms=1.0)]
    store.record_cycle(sla.build_cycle("wan-a", T0, 60, rows), rows)
    assert store.samples_between("wan-a", T0, T0 + timedelta(minutes=1))[0][1].target == "a.example"


# --- partitions: no partition for the month means the write is refused (database review H1) ----------


def test_a_cycle_in_a_month_without_a_partition_is_refused_and_stores_nothing(
    store: WanSampleRepository,
) -> None:
    december = datetime(2026, 12, 3, 8, 0, tzinfo=UTC)
    with pytest.raises(WanPartitionMissingError) as raised:
        record(store, 0, "pass", start=december)
    assert "partition" in str(raised.value)
    assert isinstance(raised.value, StorageError)
    assert store.cycles_between("wan-a", december, december + timedelta(hours=1)) == []
    record(store, 0, "pass")  # the months that do have a partition keep working


def test_a_missing_partition_is_not_a_conflict(store: WanSampleRepository) -> None:
    with pytest.raises(WanPartitionMissingError) as raised:
        record(store, 0, "pass", start=datetime(2030, 1, 1, tzinfo=UTC))
    assert not isinstance(raised.value, StorageConflictError)


# --- the cycle read cap follows the sampling interval (database review M1) ----------------------------


def test_the_cycle_read_cap_covers_a_month_at_the_interval_with_headroom() -> None:
    month_seconds = 31 * 86_400
    for interval in (30, 60, 120, 300):
        cap = wan_store.cycle_read_cap(interval)
        assert cap >= month_seconds // interval  # one writer, every round of a 31-day month
        assert cap >= 2 * (month_seconds // interval)  # two writers (a second node) still fit
        assert cap <= 3 * (month_seconds // interval) + 100  # but it stays a real bound
    assert (
        wan_store.cycle_read_cap(30) > wan_store.cycle_read_cap(60) > wan_store.cycle_read_cap(300)
    )


@pytest.mark.parametrize("interval", [0, -1, 29, 301])
def test_the_cycle_read_cap_refuses_an_interval_outside_the_supported_range(interval: int) -> None:
    with pytest.raises(ValueError, match="interval"):
        wan_store.cycle_read_cap(interval)


def test_the_default_cap_is_the_worst_case_at_the_shortest_interval() -> None:
    assert wan_store.MAX_CYCLES_READ == wan_store.cycle_read_cap(30)


def test_a_store_built_with_its_own_cap_enforces_it() -> None:
    small = InMemoryWanSampleRepository(max_cycles=2)
    for minute in range(3):
        record(small, minute, "pass")
    with pytest.raises(StorageError, match="too many"):
        small.cycles_between("wan-a", T0, T0 + timedelta(hours=1))


# --- migration 0005 (static) ----------------------------------------------------------------------


def test_up_creates_two_range_partitioned_append_only_tables() -> None:
    up = UP.read_text("utf-8")
    for table in ("wan_link_cycles", "wan_probe_samples"):
        body = up[up.index(f"CREATE TABLE {table} (") :].split("\nCREATE ", 1)[0]
        assert ") PARTITION BY RANGE (sampled_at);" in body
        assert re.search(rf"REVOKE ALL ON TABLE {table} FROM PUBLIC", up)
        assert re.search(rf"BEFORE UPDATE OR DELETE ON {table}", up)
        assert re.search(rf"BEFORE TRUNCATE ON {table}", up)
    assert "CASCADE" not in up
    assert "netsight_reject_append_only_mutation" in up
    assert not re.search(r"CREATE (OR REPLACE )?FUNCTION netsight_reject", up)  # the 0003 function


def test_the_parent_triggers_and_every_partition_trigger_are_enabled_always() -> None:
    up = UP.read_text("utf-8")
    for trigger in (
        "wan_link_cycles_no_update_delete",
        "wan_link_cycles_no_truncate",
        "wan_probe_samples_no_update_delete",
        "wan_probe_samples_no_truncate",
    ):
        assert f"ENABLE ALWAYS TRIGGER {trigger}" in up
    # the helper repeats it for each partition it creates
    helper = up[up.index("CREATE FUNCTION netsight_ensure_wan_partition") :]
    assert "ENABLE ALWAYS TRIGGER" in helper and "BEFORE TRUNCATE" in helper


def test_the_partition_helper_is_not_executable_by_public() -> None:
    up = UP.read_text("utf-8")
    assert re.search(
        r"REVOKE ALL ON FUNCTION netsight_ensure_wan_partition\(date\) FROM PUBLIC", up
    )
    helper = up[up.index("CREATE FUNCTION netsight_ensure_wan_partition") :]
    assert "SECURITY DEFINER" not in helper.split("$$;", 1)[0]


def test_the_cycle_state_is_pinned_to_its_counts_by_a_check() -> None:
    up = UP.read_text("utf-8")
    assert "wan_link_cycles_state_matches_counts" in up
    assert "passes > 0 AND fails = 0" in up


def test_a_failed_or_unknown_sample_carries_no_latency_by_a_check() -> None:
    up = UP.read_text("utf-8")
    assert "wan_probe_samples_latency_matches_outcome" in up
    assert "outcome = 'pass' OR latency_ms IS NULL" in up


def test_the_foreign_key_has_no_redundant_restrict_clause() -> None:
    assert "ON DELETE RESTRICT" not in UP.read_text("utf-8")


def test_a_covering_index_serves_the_probe_sources_export_query() -> None:
    up = UP.read_text("utf-8")
    assert re.search(
        r"CREATE INDEX wan_probe_samples_sources_idx ON wan_probe_samples\s+"
        r"\(link_id, sampled_at\)\s+INCLUDE \(probe, target, location\)",
        up,
    )


def test_deferred_constraint_triggers_tie_cycle_counts_to_their_samples() -> None:
    up = UP.read_text("utf-8")
    for table in ("wan_link_cycles", "wan_probe_samples"):
        assert re.search(
            rf"CREATE CONSTRAINT TRIGGER {table}_counts_match_samples\s+AFTER INSERT ON {table}\s+"
            r"DEFERRABLE INITIALLY DEFERRED",
            up,
        )
    assert "wan_cycle_counts_match_samples" in up


def test_down_drops_exactly_the_new_tables_and_their_helpers() -> None:
    down = DOWN.read_text("utf-8")
    assert set(migrate._DROP_TABLE.findall(down)) == {"wan_probe_samples", "wan_link_cycles"}
    assert "netsight_ensure_wan_partition" in down
    assert "netsight_wan_cycle_matches_samples" in down
    code = "\n".join(line for line in down.splitlines() if not line.startswith("--"))
    assert "netsight_reject_append_only_mutation" not in code  # that function is 0003's


def test_grants_give_the_api_role_select_only_and_the_collector_insert_only() -> None:
    api = migrate.GRANTS_PATH.read_text("utf-8")
    collector = migrate.COLLECTOR_GRANTS_PATH.read_text("utf-8")
    for table in ("wan_link_cycles", "wan_probe_samples"):
        assert f"GRANT SELECT ON TABLE %I.{table} TO %I" in api
        assert not re.search(rf"GRANT[^;]*INSERT[^;]*{table}", api)
        assert not re.search(rf"GRANT UPDATE[^;]*{table}", api)
        assert f"GRANT INSERT ON TABLE %I.{table} TO %I" in collector
        assert not re.search(rf"GRANT[^;]*(SELECT|UPDATE|DELETE|TRUNCATE)[^;]*{table}", collector)


# --- live PostgreSQL ------------------------------------------------------------------------------


def _owner_repo(database: WanDatabase) -> Any:
    from netsight_api.storage.postgres_wan import PostgresWanSampleRepository

    return PostgresWanSampleRepository(database.owner)


@requires_pg
def test_even_the_owner_cannot_update_delete_or_truncate(database: WanDatabase) -> None:
    import psycopg

    repo = _owner_repo(database)
    record(repo, 0, "pass")
    for statement in (
        "UPDATE wan_link_cycles SET interval_seconds = 30",
        "DELETE FROM wan_link_cycles",
        "TRUNCATE wan_link_cycles CASCADE",
        "UPDATE wan_probe_samples SET outcome = 'fail'",
        "DELETE FROM wan_probe_samples",
        "TRUNCATE wan_probe_samples",
    ):
        with (
            database.owner.connect() as conn,
            pytest.raises(psycopg.errors.IntegrityConstraintViolation),
        ):
            conn.execute(statement)  # type: ignore[arg-type]
    assert len(repo.cycles_between("wan-a", T0, T0 + timedelta(hours=1))) == 1


@requires_pg
def test_even_the_owner_cannot_touch_a_single_partition_directly(database: WanDatabase) -> None:
    import psycopg

    record(_owner_repo(database), 0, "pass")
    for statement in (
        "UPDATE wan_link_cycles_p202610 SET interval_seconds = 30",
        "DELETE FROM wan_link_cycles_p202610",
        "TRUNCATE wan_link_cycles_p202610",
        "UPDATE wan_probe_samples_p202610 SET outcome = 'fail'",
        "DELETE FROM wan_probe_samples_p202610",
        "TRUNCATE wan_probe_samples_p202610",
    ):
        # PostgreSQL itself refuses to truncate a table a foreign key references (the cycles
        # partition) before the trigger gets a say; either way the rows survive.
        refusals = (psycopg.errors.IntegrityConstraintViolation, psycopg.errors.FeatureNotSupported)
        with database.owner.connect() as conn, pytest.raises(refusals):
            conn.execute(statement)  # type: ignore[arg-type]
    assert len(_owner_repo(database).cycles_between("wan-a", T0, T0 + timedelta(hours=1))) == 1


@requires_pg
def test_every_wan_table_and_partition_keeps_enabled_always_append_only_triggers(
    database: WanDatabase,
) -> None:
    with database.owner.connect() as conn:
        rows = conn.execute(
            "SELECT c.relname AS rel, t.tgname AS name, t.tgenabled AS enabled "
            "FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
            "WHERE c.relnamespace = current_schema()::regnamespace AND NOT t.tgisinternal "
            "AND c.relname LIKE 'wan\\_%'"
        ).fetchall()
    by_relation: dict[str, list[tuple[str, str]]] = {}
    for row in rows:
        by_relation.setdefault(row["rel"], []).append((row["name"], row["enabled"]))
    expected = {"wan_link_cycles", "wan_probe_samples"} | {
        f"{table}_p{month:%Y%m}"
        for table in ("wan_link_cycles", "wan_probe_samples")
        for month in WAN_MONTHS
    }
    assert set(by_relation) == expected
    for relation, triggers in by_relation.items():
        assert {enabled for _, enabled in triggers} == {"A"}, relation  # ENABLE ALWAYS
        names = " ".join(name for name, _ in triggers)
        assert "no_update_delete" in names and "no_truncate" in names, relation
        assert "counts_match_samples" in names, relation


@requires_pg
def test_partition_creation_is_idempotent_and_takes_any_day_of_the_month(
    database: WanDatabase,
) -> None:
    with database.owner.connect() as conn:
        migrate.ensure_wan_partitions(conn, [date(2026, 12, 17)])
        migrate.ensure_wan_partitions(conn, [date(2026, 12, 1), date(2026, 12, 31)])
        names = {
            row["relname"]
            for row in conn.execute(
                "SELECT relname FROM pg_class WHERE relname LIKE 'wan\\_%\\_p2026%'"
                " AND relnamespace = current_schema()::regnamespace"
            ).fetchall()
        }
    assert {"wan_link_cycles_p202612", "wan_probe_samples_p202612"} <= names
    record(_owner_repo(database), 0, "pass", start=datetime(2026, 12, 3, 8, 0, tzinfo=UTC))


@requires_pg
def test_a_new_partition_is_append_only_too(database: WanDatabase) -> None:
    import psycopg

    with database.owner.connect() as conn:
        migrate.ensure_wan_partitions(conn, [date(2027, 1, 5)])
    january = datetime(2027, 1, 5, 8, 0, tzinfo=UTC)
    record(_owner_repo(database), 0, "pass", start=january)
    for statement in (
        "DELETE FROM wan_probe_samples_p202701",
        "TRUNCATE wan_probe_samples_p202701",
        "UPDATE wan_link_cycles_p202701 SET interval_seconds = 30",
    ):
        with (
            database.owner.connect() as conn,
            pytest.raises(psycopg.errors.IntegrityConstraintViolation),
        ):
            conn.execute(statement)  # type: ignore[arg-type]
    with database.owner.connect() as conn:
        states = conn.execute(
            "SELECT DISTINCT t.tgenabled AS e FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid"
            " WHERE c.relname = 'wan_probe_samples_p202701' AND NOT t.tgisinternal"
        ).fetchall()
    assert states == [{"e": "A"}]


@requires_pg
def test_the_partition_helper_refuses_a_null_month(database: WanDatabase) -> None:
    import psycopg

    with database.owner.connect() as conn, pytest.raises(psycopg.errors.RaiseException):
        conn.execute("SELECT netsight_ensure_wan_partition(NULL)")


@requires_pg
def test_retention_is_the_migrator_dropping_a_month_samples_first_then_detaching_the_cycles(
    database: WanDatabase,
) -> None:
    """The documented (human-decided, not scheduled) procedure works and needs the owner."""
    import psycopg

    repo = _owner_repo(database)
    september = datetime(2026, 9, 5, 8, 0, tzinfo=UTC)
    record(repo, 0, "pass", start=september)
    record(repo, 0, "pass")
    with database.owner.connect() as conn, pytest.raises(psycopg.errors.DependentObjectsStillExist):
        # the foreign key on the samples parent references each cycles partition
        conn.execute("DROP TABLE wan_link_cycles_p202609")
    with database.owner.connect() as conn:
        conn.execute("DROP TABLE wan_probe_samples_p202609")
        conn.execute("ALTER TABLE wan_link_cycles DETACH PARTITION wan_link_cycles_p202609")
        conn.execute("DROP TABLE wan_link_cycles_p202609")
    window = (september - timedelta(days=1), T0 + timedelta(days=1))
    assert [c.sampled_at for c in repo.cycles_between("wan-a", *window)] == [T0]
    record(repo, 1, "pass")  # the other months are untouched and still writable


@requires_pg
def test_the_api_role_reads_but_cannot_write_change_or_create_anything(
    database: WanDatabase,
) -> None:
    import psycopg

    record(_owner_repo(database), 0, "pass")
    reader = SplitRoleStore(database)
    assert len(reader.cycles_between("wan-a", T0, T0 + timedelta(hours=1))) == 1
    for statement in (
        "INSERT INTO wan_link_cycles VALUES ('wan-a', now(), 60, 0, 0, 0, 'unknown')",
        "UPDATE wan_link_cycles SET interval_seconds = 30",
        "DELETE FROM wan_probe_samples",
        "TRUNCATE wan_probe_samples",
        "SELECT 1 FROM wan_link_cycles_p202610",  # partitions carry no grant of their own
        "ALTER TABLE wan_link_cycles ADD COLUMN x int",
        "DROP TABLE wan_probe_samples_p202610",
        "CREATE TABLE intruder (x int)",
        "SELECT netsight_ensure_wan_partition(DATE '2028-01-01')",
    ):
        with database.reader.connect() as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(statement)  # type: ignore[arg-type]


@requires_pg
def test_the_collector_role_can_only_insert(database: WanDatabase) -> None:
    import psycopg

    from netsight_api.storage.postgres_wan import PostgresWanSampleRepository

    collector = PostgresWanSampleRepository(database.writer)
    record(collector, 0, "pass", "fail")
    for statement in (
        "SELECT 1 FROM wan_link_cycles",
        "SELECT 1 FROM wan_probe_samples",
        "UPDATE wan_link_cycles SET interval_seconds = 30",
        "DELETE FROM wan_probe_samples",
        "TRUNCATE wan_link_cycles",
        "ALTER TABLE wan_link_cycles ADD COLUMN x int",
        (
            "CREATE TABLE wan_link_cycles_p202712 PARTITION OF wan_link_cycles "
            "FOR VALUES FROM ('2027-12-01') TO ('2028-01-01')"
        ),
        "SELECT netsight_ensure_wan_partition(DATE '2028-01-01')",
        "SELECT 1 FROM incidents",
    ):
        with database.writer.connect() as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(statement)  # type: ignore[arg-type]
    assert len(SplitRoleStore(database).cycles_between("wan-a", T0, T0 + timedelta(hours=1))) == 1


_CYCLE_INSERT = (
    "INSERT INTO wan_link_cycles (link_id, sampled_at, interval_seconds, passes, fails, "
    "unknowns, state) VALUES (%s, %s, %s, %s, %s, %s, %s)"
)
_SAMPLE_INSERT = (
    "INSERT INTO wan_probe_samples (link_id, sampled_at, seq, probe, target, location, "
    "outcome, latency_ms) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
)
_EMPTY_CYCLE = ("wan-a", T0, 60, 0, 0, 0, "unknown")


def _violation(settings: Any, statement: str, params: tuple[Any, ...]) -> str | None:
    import psycopg

    with settings.connect() as conn, pytest.raises(psycopg.errors.CheckViolation) as raised:
        conn.execute(statement, params)
    return raised.value.diag.constraint_name  # type: ignore[no-any-return]


@requires_pg
@pytest.mark.parametrize(
    ("params", "constraint"),
    [
        (("wan-a", T0, 60, 0, 2, 0, "up"), "wan_link_cycles_state_matches_counts"),
        (("wan-a", T0, 60, 1, 1, 0, "down"), "wan_link_cycles_state_matches_counts"),
        (("wan-a", T0, 60, 0, 1, 1, "down"), "wan_link_cycles_state_matches_counts"),
        (("wan-a", T0, 60, 0, 0, 0, "up"), "wan_link_cycles_state_matches_counts"),
        (("wan-a", T0.replace(microsecond=5), 60, 1, 0, 0, "up"), "wan_link_cycles_whole_second"),
        (("wan-a", T0, 29, 1, 0, 0, "up"), "wan_link_cycles_interval_valid"),
        (("wan-a", T0, 301, 1, 0, 0, "up"), "wan_link_cycles_interval_valid"),
        (("Wan A", T0, 60, 1, 0, 0, "up"), "wan_link_cycles_link_valid"),
        (("wan-a", T0, 60, -1, 0, 0, "unknown"), "wan_link_cycles_counts_valid"),
        (("wan-a", T0, 60, 65, 0, 0, "up"), "wan_link_cycles_counts_valid"),
    ],
)
def test_the_cycle_table_refuses_inconsistent_rows(
    database: WanDatabase, params: tuple[Any, ...], constraint: str
) -> None:
    assert _violation(database.owner, _CYCLE_INSERT, params) == constraint


@requires_pg
@pytest.mark.parametrize(
    ("params", "constraint"),
    [
        (("wan-a", T0, 1, "http", "x.example", None, "pass", 1.0), "wan_probe_samples_probe_valid"),
        (
            ("wan-a", T0, 1, "icmp", "x.example", None, "ok", None),
            "wan_probe_samples_outcome_valid",
        ),
        (
            ("wan-a", T0, 1, "icmp", "x.example", "mars", "pass", 1.0),
            "wan_probe_samples_location_valid",
        ),
        (("wan-a", T0, 1, "icmp", "bad host", None, "pass", 1.0), "wan_probe_samples_target_valid"),
        (
            ("wan-a", T0, 1, "icmp", "x.example", None, "pass", -1.0),
            "wan_probe_samples_latency_valid",
        ),
        (
            ("wan-a", T0, 1, "icmp", "x.example", None, "pass", 4e9),
            "wan_probe_samples_latency_valid",
        ),
        (
            ("wan-a", T0, 1, "icmp", "x.example", None, "pass", float("nan")),
            "wan_probe_samples_latency_valid",
        ),
        (
            ("wan-a", T0, 1, "icmp", "x.example", None, "fail", 1.0),
            "wan_probe_samples_latency_matches_outcome",
        ),
        (
            ("wan-a", T0, 1, "icmp", "x.example", None, "unknown", 0.0),
            "wan_probe_samples_latency_matches_outcome",
        ),
    ],
)
def test_the_sample_table_refuses_malformed_rows(
    database: WanDatabase, params: tuple[Any, ...], constraint: str
) -> None:
    with database.owner.connect() as conn:
        conn.execute(_CYCLE_INSERT, _EMPTY_CYCLE)
    assert _violation(database.owner, _SAMPLE_INSERT, params) == constraint


@requires_pg
def test_a_pass_may_carry_no_latency_and_a_failure_must_not(database: WanDatabase) -> None:
    rows = [
        Sample("icmp", "a.example", "pass", None),
        Sample("icmp", "b.example", "fail", None),
        Sample("dns", "c.example", "unknown", None),
    ]
    _owner_repo(database).record_cycle(sla.build_cycle("wan-a", T0, 60, rows), rows)


@requires_pg
def test_a_sample_cannot_exist_without_its_cycle(database: WanDatabase) -> None:
    import psycopg

    with database.owner.connect() as conn, pytest.raises(psycopg.errors.ForeignKeyViolation):
        conn.execute(_SAMPLE_INSERT, ("wan-a", T0, 1, "icmp", "x.example", None, "pass", 1.0))


@requires_pg
def test_a_cycle_whose_counts_disagree_with_its_samples_cannot_commit(
    database: WanDatabase,
) -> None:
    import psycopg

    # the check is deferred to COMMIT, so the raises block must enclose the connection's exit
    with pytest.raises(psycopg.errors.CheckViolation) as raised, database.owner.connect() as conn:
        conn.execute(_CYCLE_INSERT, ("wan-a", T0, 60, 1, 0, 0, "up"))  # a pass, but no sample
    assert raised.value.diag.constraint_name == "wan_cycle_counts_match_samples"

    with pytest.raises(psycopg.errors.CheckViolation), database.owner.connect() as conn:
        conn.execute(_CYCLE_INSERT, ("wan-a", T0, 60, 1, 0, 0, "up"))
        conn.execute(_SAMPLE_INSERT, ("wan-a", T0, 1, "icmp", "x.example", None, "fail", None))
    assert not _owner_repo(database).cycles_between("wan-a", T0, T0 + timedelta(hours=1))


@requires_pg
def test_matching_counts_commit_and_a_dns_sample_does_not_count(database: WanDatabase) -> None:
    with database.owner.connect() as conn:
        conn.execute(_CYCLE_INSERT, ("wan-a", T0, 60, 1, 0, 0, "up"))
        conn.execute(_SAMPLE_INSERT, ("wan-a", T0, 1, "icmp", "x.example", None, "pass", 3.0))
        conn.execute(_SAMPLE_INSERT, ("wan-a", T0, 2, "dns", "y.example", None, "fail", None))
    assert len(_owner_repo(database).cycles_between("wan-a", T0, T0 + timedelta(hours=1))) == 1


@requires_pg
def test_a_sample_added_later_to_a_stored_cycle_cannot_commit(database: WanDatabase) -> None:
    import psycopg

    record(_owner_repo(database), 0, "pass")
    with pytest.raises(psycopg.errors.CheckViolation), database.owner.connect() as conn:
        conn.execute(_SAMPLE_INSERT, ("wan-a", T0, 9, "icmp", "z.example", None, "pass", 1.0))
    assert len(_owner_repo(database).samples_between("wan-a", T0, T0 + timedelta(hours=1))) == 1


@requires_pg
def test_the_triggers_still_fire_when_replication_role_is_replica(database: WanDatabase) -> None:
    import psycopg

    record(_owner_repo(database), 0, "pass")
    for statement in (
        "UPDATE wan_link_cycles SET interval_seconds = 30",
        "DELETE FROM wan_probe_samples",
        "TRUNCATE wan_probe_samples",
        "DELETE FROM wan_probe_samples_p202610",
    ):
        with database.owner.connect() as conn:
            try:
                conn.execute("SET session_replication_role = replica")
            except psycopg.errors.InsufficientPrivilege:
                pytest.skip("this role may not set session_replication_role")
            with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
                conn.execute(statement)  # type: ignore[arg-type]


@requires_pg
def test_down_refuses_while_rows_exist_and_succeeds_with_consent(database: WanDatabase) -> None:
    record(_owner_repo(database), 0, "pass")
    with (
        database.owner.connect() as conn,
        pytest.raises(migrate.DestructiveMigrationError) as raised,
    ):
        migrate.apply_down(conn, steps=3, allow_destructive=True, env={})
    assert "wan_link_cycles" in str(raised.value)
    with database.owner.connect() as conn:
        assert migrate.apply_down(
            conn, steps=3, allow_destructive=True, env={migrate.DESTRUCTIVE_ENV: "1"}
        ) == ["0007", "0006", "0005"]
        assert conn.execute("SELECT to_regclass('wan_link_cycles') AS t").fetchone() == {"t": None}
        assert conn.execute("SELECT to_regclass('wan_link_cycles_p202610') AS t").fetchone() == {
            "t": None
        }
        assert conn.execute("SELECT to_regclass('diagnostic_sessions') AS t").fetchone() != {
            "t": None
        }
        gone = conn.execute(
            "SELECT count(*) AS n FROM pg_proc WHERE proname LIKE 'netsight_%wan%'"
            " AND pronamespace = current_schema()::regnamespace"
        ).fetchone()
        assert gone == {"n": 0}


@requires_pg
def test_down_on_empty_tables_needs_no_environment_override(database: WanDatabase) -> None:
    with database.owner.connect() as conn:
        assert migrate.apply_down(conn, steps=3, allow_destructive=True, env={}) == [
            "0007",
            "0006",
            "0005",
        ]


@requires_pg
def test_up_again_after_down_restores_the_tables_without_partitions(
    database: WanDatabase,
) -> None:
    with database.owner.connect() as conn:
        migrate.apply_down(conn, steps=3, allow_destructive=True, env={})
        assert migrate.apply_up(conn) == ["0005", "0006", "0007"]
        # a fresh table has no partition until the migrator step creates one: writes fail closed
    with pytest.raises(WanPartitionMissingError):
        record(_owner_repo(database), 0, "pass")
