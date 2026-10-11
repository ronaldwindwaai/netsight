"""The PostgreSQL WAN store's error mapping and statement shape, without a database.

A fake connection stands in for the driver so each failure mode can be produced on demand:
only a unique violation means "this cycle already exists" (a deadlock or serialization failure
is a failed write), a row with no partition is a refusal to write, samples go in with one
``executemany``, and the collector's database role is checked before it may start.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, Self

import psycopg
import pytest

from netsight_api.storage import wan
from netsight_api.storage.connection import PostgresSettings
from netsight_api.storage.errors import (
    InvalidOperationError,
    StorageConflictError,
    StorageError,
    StorageUnavailableError,
)
from netsight_api.storage.postgres_wan import (
    CollectorRoleError,
    PostgresWanSampleRepository,
    check_collector_role,
)
from netsight_api.wan import sla
from netsight_api.wan.sla import Sample

T0 = datetime(2026, 10, 10, 8, 0, tzinfo=UTC)
ROWS = [
    Sample("icmp", "a.example", "pass", 5.0, "branch"),
    Sample("icmp", "b.example", "fail", None, "branch"),
    Sample("dns", "c.example", "unknown", None),
]


class NamedCheckViolation(psycopg.errors.CheckViolation):
    """A check violation that names its constraint (what a real column CHECK reports)."""

    @property
    def diag(self) -> Any:  # type: ignore[override]
        return SimpleNamespace(constraint_name="wan_probe_samples_latency_valid")


class FakeCursor:
    def __init__(self, conn: FakeConnection) -> None:
        self.conn = conn

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def execute(self, query: str, params: Any = None) -> FakeCursor:
        self.conn.calls.append(("execute", query, params))
        self.conn.raise_for("execute")
        return self

    def executemany(self, query: str, params: Any) -> None:
        self.conn.calls.append(("executemany", query, list(params)))
        self.conn.raise_for("executemany")

    def fetchone(self) -> Any:
        return self.conn.row

    def fetchall(self) -> list[Any]:
        return self.conn.rows


class FakeConnection:
    def __init__(
        self,
        *,
        fail_on: str | None = None,
        error: Exception | None = None,
        row: Any = None,
        rows: list[Any] | None = None,
    ) -> None:
        self.calls: list[tuple[str, str, Any]] = []
        self.fail_on, self.error, self.row, self.rows = fail_on, error, row, rows or []

    def raise_for(self, kind: str) -> None:
        if self.error is not None and self.fail_on == kind:
            raise self.error

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def execute(self, query: str, params: Any = None) -> FakeCursor:
        return self.cursor().execute(query, params)


@dataclass(frozen=True)
class FakeSettings(PostgresSettings):
    """Real ``session()`` translation, a scripted connection."""

    scripted: Any = None

    def connect(self, *, autocommit: bool = False, **extra: Any) -> Any:  # type: ignore[override]
        return self.scripted


def repository(connection: FakeConnection, **kwargs: Any) -> PostgresWanSampleRepository:
    settings = FakeSettings(dsn="postgresql://u:p@h/db", scripted=connection)
    return PostgresWanSampleRepository(settings, **kwargs)


def cycle_and_rows() -> tuple[sla.Cycle, list[Sample]]:
    return sla.build_cycle("wan-a", T0, 60, ROWS), list(ROWS)


# --- statement shape ---------------------------------------------------------------------------


def test_a_cycle_is_one_insert_and_its_samples_are_one_executemany() -> None:
    connection = FakeConnection()
    cycle, rows = cycle_and_rows()
    repository(connection).record_cycle(cycle, rows)
    kinds = [kind for kind, _, _ in connection.calls]
    assert kinds == ["execute", "executemany"]
    params = connection.calls[1][2]
    assert [row[2] for row in params] == [1, 2, 3]  # seq
    assert [row[3] for row in params] == ["icmp", "icmp", "dns"]
    assert all(row[0] == "wan-a" and row[1] == T0 for row in params)
    assert params[0][7] == 5.0 and params[1][7] is None


def test_a_cycle_without_samples_makes_no_executemany() -> None:
    connection = FakeConnection()
    empty = sla.build_cycle("wan-a", T0, 60, [])
    repository(connection).record_cycle(empty, [])
    assert [kind for kind, _, _ in connection.calls] == ["execute"]


# --- which failures mean "this cycle already exists" -----------------------------------------------


def test_only_a_unique_violation_is_a_conflict() -> None:
    connection = FakeConnection(fail_on="execute", error=psycopg.errors.UniqueViolation("dup"))
    cycle, rows = cycle_and_rows()
    with pytest.raises(StorageConflictError):
        repository(connection).record_cycle(cycle, rows)


@pytest.mark.parametrize(
    "error",
    [psycopg.errors.DeadlockDetected("x"), psycopg.errors.SerializationFailure("x")],
)
@pytest.mark.parametrize("stage", ["execute", "executemany"])
def test_a_deadlock_or_serialization_failure_is_a_failed_write_not_a_skip(
    error: Exception, stage: str
) -> None:
    connection = FakeConnection(fail_on=stage, error=error)
    cycle, rows = cycle_and_rows()
    with pytest.raises(StorageUnavailableError) as raised:
        repository(connection).record_cycle(cycle, rows)
    assert not isinstance(raised.value, StorageConflictError)


# --- a month with no partition ---------------------------------------------------------------------


def test_a_row_with_no_partition_is_a_refusal_to_write() -> None:
    error = psycopg.errors.CheckViolation(
        'no partition of relation "wan_link_cycles" found for row'
    )
    connection = FakeConnection(fail_on="execute", error=error)
    cycle, rows = cycle_and_rows()
    with pytest.raises(wan.WanPartitionMissingError) as raised:
        repository(connection).record_cycle(cycle, rows)
    assert "partition" in str(raised.value) and "wan_link_cycles" not in str(raised.value)


def test_a_named_check_violation_is_not_mistaken_for_a_missing_partition() -> None:
    connection = FakeConnection(fail_on="executemany", error=NamedCheckViolation("bad latency"))
    cycle, rows = cycle_and_rows()
    with pytest.raises(InvalidOperationError) as raised:
        repository(connection).record_cycle(cycle, rows)
    assert not isinstance(raised.value, wan.WanPartitionMissingError)


# --- the read cap ------------------------------------------------------------------------------------


def test_the_cycle_cap_given_at_construction_is_enforced_by_asking_for_one_more() -> None:
    row = {
        "link_id": "wan-a",
        "sampled_at": T0,
        "interval_seconds": 60,
        "passes": 1,
        "fails": 0,
        "unknowns": 0,
        "state": "up",
    }
    rows = [dict(row, sampled_at=T0 + timedelta(minutes=n)) for n in range(3)]
    connection = FakeConnection(rows=rows)
    repo = repository(connection, max_cycles=2)
    with pytest.raises(StorageError, match="too many"):
        repo.cycles_between("wan-a", T0, T0 + timedelta(hours=1))
    assert connection.calls[0][2][3] == 3  # LIMIT cap + 1
    assert (
        len(
            repository(FakeConnection(rows=rows), max_cycles=3).cycles_between(
                "wan-a", T0, T0 + timedelta(hours=1)
            )
        )
        == 3
    )


# --- the collector's database role ---------------------------------------------------------------------


def settings_with(row: Any) -> PostgresSettings:
    return FakeSettings(dsn="postgresql://c:pw@h/db", scripted=FakeConnection(row=row))


def test_a_plain_insert_only_role_is_accepted() -> None:
    check_collector_role(
        settings_with({"is_superuser": False, "bypasses_rls": False, "owns_tables": False})
    )


@pytest.mark.parametrize(
    ("row", "word"),
    [
        ({"is_superuser": True, "bypasses_rls": False, "owns_tables": False}, "superuser"),
        ({"is_superuser": False, "bypasses_rls": True, "owns_tables": False}, "row security"),
        ({"is_superuser": False, "bypasses_rls": False, "owns_tables": True}, "own"),
        (None, "verified"),
    ],
)
def test_a_superuser_bypassing_or_owning_role_is_refused(row: Any, word: str) -> None:
    with pytest.raises(CollectorRoleError, match=word):
        check_collector_role(settings_with(row))


def test_a_role_that_cannot_be_checked_is_refused_without_leaking_the_dsn() -> None:
    broken = FakeSettings(
        dsn="postgresql://c:s3cret@h/db",
        scripted=FakeConnection(fail_on="execute", error=psycopg.OperationalError("s3cret host")),
    )
    with pytest.raises(CollectorRoleError) as raised:
        check_collector_role(broken)
    assert "s3cret" not in str(raised.value) and "postgresql" not in str(raised.value)
