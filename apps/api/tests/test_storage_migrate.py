"""Migration runner safety, the ``python -m`` entrypoint and production packaging.

Offline tests always run; tests marked ``requires_pg`` need ``NETSIGHT_TEST_PG_DSN``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from pg_support import PG_DSN, app_role, isolated_schema, requires_pg
from test_storage_conformance import FakeClock, new_incident

from netsight_api.storage import migrate
from netsight_api.storage.postgres import PostgresIncidentRepository, PostgresSettings

PROJECT_DIR = Path(__file__).resolve().parents[1]
UP_FILES = {
    "0001_incident_alert_storage.up.sql",
    "0002_harden_privileges.up.sql",
    "0003_evaluation_links_and_delivery.up.sql",
    "0004_diagnostic_sessions.up.sql",
}


# --- apply_down safety (H2) ----------------------------------------------------------


class _ExplodingConnection:
    """Any use means a guard failed to run before touching the database."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"connection used before the destructive guard: {name}")


def test_apply_down_refuses_without_explicit_allow_destructive() -> None:
    with pytest.raises(migrate.DestructiveMigrationError):
        migrate.apply_down(_ExplodingConnection())  # type: ignore[arg-type]
    with pytest.raises(migrate.DestructiveMigrationError):
        migrate.apply_down(
            _ExplodingConnection(),  # type: ignore[arg-type]
            allow_destructive=False,
            env={migrate.DESTRUCTIVE_ENV: "1"},
        )


def test_apply_down_rejects_a_non_positive_step_count() -> None:
    with pytest.raises(ValueError):
        migrate.apply_down(_ExplodingConnection(), steps=0, allow_destructive=True)  # type: ignore[arg-type]


@pytest.fixture
def migrated_pg() -> Iterator[PostgresSettings]:
    assert PG_DSN
    with isolated_schema() as schema:
        settings = PostgresSettings(dsn=PG_DSN, schema=schema)
        with settings.connect() as conn:
            migrate.apply_up(conn)
        yield settings


def _version_rows(settings: PostgresSettings) -> list[str]:
    with settings.connect() as conn:
        rows = conn.execute("SELECT version FROM netsight_schema_migrations ORDER BY 1").fetchall()
    return [row["version"] for row in rows]


@requires_pg
def test_apply_down_refuses_to_drop_populated_tables_without_the_environment_override(
    migrated_pg: PostgresSettings,
) -> None:
    new_incident(PostgresIncidentRepository(migrated_pg, clock=FakeClock()))
    with migrated_pg.connect() as conn, pytest.raises(migrate.DestructiveMigrationError) as raised:
        migrate.apply_down(conn, steps=4, allow_destructive=True, env={})
    assert "incidents" in str(raised.value)
    for wrong in ("0", "true", "yes", ""):
        with migrated_pg.connect() as conn, pytest.raises(migrate.DestructiveMigrationError):
            migrate.apply_down(
                conn, steps=4, allow_destructive=True, env={migrate.DESTRUCTIVE_ENV: wrong}
            )
    assert _version_rows(migrated_pg) == ["0001", "0002", "0003", "0004"]  # nothing was reversed


@requires_pg
def test_apply_down_on_populated_tables_needs_both_flag_and_environment(
    migrated_pg: PostgresSettings,
) -> None:
    new_incident(PostgresIncidentRepository(migrated_pg, clock=FakeClock()))
    with migrated_pg.connect() as conn:
        reversed_versions = migrate.apply_down(
            conn, steps=4, allow_destructive=True, env={migrate.DESTRUCTIVE_ENV: "1"}
        )
    assert reversed_versions == ["0004", "0003", "0002", "0001"]


@requires_pg
def test_apply_down_of_the_privilege_migration_never_touches_data(
    migrated_pg: PostgresSettings,
) -> None:
    new_incident(PostgresIncidentRepository(migrated_pg, clock=FakeClock()))
    with migrated_pg.connect() as conn:
        assert migrate.apply_down(conn, steps=3, allow_destructive=True, env={}) == [
            "0004",
            "0003",
            "0002",
        ]
    assert _version_rows(migrated_pg) == ["0001"]


# --- role name and grants validation (H1) --------------------------------------------


@pytest.mark.parametrize("role", ["", "Role", "x;drop", "a b", "1abc", "a" * 64, 'q"uote', "-x"])
def test_invalid_role_names_are_rejected_before_any_sql(role: str) -> None:
    with pytest.raises(ValueError):
        migrate.apply_grants(_ExplodingConnection(), role)  # type: ignore[arg-type]


@requires_pg
def test_grants_refuse_unsafe_or_missing_roles(migrated_pg: PostgresSettings) -> None:
    with migrated_pg.connect() as conn, pytest.raises(migrate.MigrationError):
        migrate.apply_grants(conn, "nsapp_does_not_exist")
    with migrated_pg.connect() as conn:
        row = conn.execute(
            "SELECT current_user AS name, rolsuper FROM pg_roles WHERE rolname = current_user"
        ).fetchone()
    assert row is not None
    if row["rolsuper"]:
        with migrated_pg.connect() as conn, pytest.raises(migrate.MigrationError):
            migrate.apply_grants(conn, row["name"])


@requires_pg
def test_grants_refuse_a_role_that_owns_the_tables(migrated_pg: PostgresSettings) -> None:
    with app_role() as (role, _dsn), migrated_pg.connect() as conn:
        conn.execute(f'ALTER TABLE incidents OWNER TO "{role}"')
        with pytest.raises(migrate.MigrationError) as raised:
            migrate.apply_grants(conn, role)
        assert "owns" in str(raised.value)
        conn.rollback()


# --- CLI (H3) --------------------------------------------------------------------------


def run_cli(*args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    clean = {k: v for k, v in os.environ.items() if not k.startswith(("DATABASE_", "NETSIGHT_"))}
    return subprocess.run(
        [sys.executable, "-m", "netsight_api.storage.migrate", *args],
        env={**clean, **env},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_cli_without_a_migration_dsn_fails_with_a_usage_exit_code() -> None:
    result = run_cli("up", "--no-grants", env={"DATABASE_URL": "postgresql://app@h/db"})
    assert result.returncode == 2
    assert "DATABASE_MIGRATION_URL" in result.stderr


def test_cli_requires_an_app_role_unless_grants_are_explicitly_skipped() -> None:
    result = run_cli("up", env={"DATABASE_MIGRATION_URL": "postgresql://m@127.0.0.1:1/db"})
    assert result.returncode == 2
    assert "DATABASE_APP_ROLE" in result.stderr


def test_cli_rejects_unknown_commands() -> None:
    assert run_cli("down", env={}).returncode == 2
    assert run_cli(env={}).returncode == 2


@pytest.mark.parametrize("command", [["up", "--no-grants"], ["status"]])
def test_cli_failure_exits_non_zero_and_never_prints_the_dsn(command: list[str]) -> None:
    secret = "s3cr3t-pw-marker"
    result = run_cli(
        *command,
        env={"DATABASE_MIGRATION_URL": f"postgresql://migrator:{secret}@127.0.0.1:1/nodb"},
    )
    assert result.returncode == 1
    combined = result.stdout + result.stderr
    assert secret not in combined
    assert "127.0.0.1" not in combined
    assert "migrator" not in combined


def _schema_dsn(schema: str) -> dict[str, str]:
    assert PG_DSN
    return {"DATABASE_MIGRATION_URL": PG_DSN}


@requires_pg
def test_cli_up_and_status_round_trip_with_grants() -> None:
    with isolated_schema() as schema, app_role() as (role, role_dsn):
        base = _schema_dsn(schema)
        schema_args = ["--schema", schema]

        before = run_cli("status", *schema_args, env=base)
        assert before.returncode == 0, before.stderr
        assert all(f"pending: {v}" in before.stdout for v in ("0001", "0002", "0003", "0004"))

        first = run_cli("up", "--app-role", role, *schema_args, env=base)
        assert first.returncode == 0, first.stderr
        assert all(f"applied: {v}" in first.stdout for v in ("0001", "0002", "0003", "0004"))
        assert "grants applied" in first.stdout

        again = run_cli("up", *schema_args, env={**base, "DATABASE_APP_ROLE": role})
        assert again.returncode == 0, again.stderr
        assert "applied:" not in again.stdout  # nothing new, grants are idempotent

        after = run_cli("status", *schema_args, env=base)
        assert "applied: 0001" in after.stdout and "pending:" not in after.stdout

        runtime = PostgresSettings(dsn=role_dsn, schema=schema)
        incident = new_incident(PostgresIncidentRepository(runtime, clock=FakeClock()))
        assert incident.state == "open"
        for output in (first.stdout, first.stderr, again.stdout, after.stdout):
            assert role_dsn not in output


@requires_pg
def test_cli_up_without_grants_leaves_the_app_role_without_access() -> None:
    with isolated_schema() as schema, app_role() as (_role, role_dsn):
        result = run_cli(
            "up", "--no-grants", "--schema", schema, env={"DATABASE_MIGRATION_URL": PG_DSN or ""}
        )
        assert result.returncode == 0, result.stderr
        runtime = PostgresSettings(dsn=role_dsn, schema=schema)
        # Without USAGE on the schema the table is not even visible to the role.
        denied = (psycopg.errors.InsufficientPrivilege, psycopg.errors.UndefinedTable)
        with pytest.raises(denied), runtime.connect() as conn:
            conn.execute("SELECT 1 FROM incidents")


# --- packaging (H2 / H3) -----------------------------------------------------------------


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("wheel-out")
    script = "import sys, hatchling.build as b; print(b.build_wheel(sys.argv[1]))"
    subprocess.run(
        [sys.executable, "-I", "-c", script, str(out)],
        cwd=PROJECT_DIR,
        check=True,
        capture_output=True,
        text=True,
        timeout=300,
    )
    wheels = list(out.glob("netsight_api-*.whl"))
    assert len(wheels) == 1
    return wheels[0]


def test_wheel_ships_up_migrations_and_grants_but_never_rollback_sql(built_wheel: Path) -> None:
    with zipfile.ZipFile(built_wheel) as archive:
        names = archive.namelist()
    shipped = {Path(n).name for n in names if "/storage/migrations/" in n}
    assert shipped == UP_FILES
    assert not [n for n in names if n.endswith(".down.sql")]
    assert any(n.endswith("storage/grants/app_role.sql") for n in names)


_INSTALLED_PROBE = r"""
import json, pathlib, sys
site = sys.argv[1]
sys.path.insert(0, site)
from netsight_api.storage import migrate

assert pathlib.Path(migrate.__file__).is_relative_to(site), migrate.__file__

class Cursor:
    def __init__(self, rows): self._rows = rows
    def fetchall(self): return self._rows

class Transaction:
    def __enter__(self): return self
    def __exit__(self, *exc): return False

class Conn:
    def __init__(self, applied): self.applied, self.statements = applied, []
    def transaction(self): return Transaction()
    def execute(self, statement, params=None):
        self.statements.append(str(statement))
        if "SELECT version" in str(statement):
            return Cursor([{"version": v} for v in self.applied])
        return Cursor([])

fresh = Conn([])
applied = migrate.apply_up(fresh)
down_error = None
try:
    migrate.apply_down(Conn(["0001"]), allow_destructive=True, env={migrate.DESTRUCTIVE_ENV: "1"})
except Exception as error:
    down_error = type(error).__name__
print(json.dumps({
    "versions": [m.version for m in migrate.available_migrations()],
    "applied": applied,
    "ran_ddl": any("CREATE TABLE incidents" in s for s in fresh.statements),
    "down_error": down_error,
}))
"""


def test_installed_wheel_finds_its_up_migrations_and_cannot_roll_back(
    built_wheel: Path, tmp_path: Path
) -> None:
    site = tmp_path / "site"
    with zipfile.ZipFile(built_wheel) as archive:
        archive.extractall(site)
    result = subprocess.run(
        [sys.executable, "-I", "-c", _INSTALLED_PROBE, str(site)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["versions"] == ["0001", "0002", "0003", "0004"]
    assert report["applied"] == ["0001", "0002", "0003", "0004"]
    assert report["ran_ddl"] is True
    assert report["down_error"] == "MigrationError"


def test_source_tree_wheel_exclusion_is_configured() -> None:
    text = (PROJECT_DIR / "pyproject.toml").read_text("utf-8")
    assert "**/*.down.sql" in text
