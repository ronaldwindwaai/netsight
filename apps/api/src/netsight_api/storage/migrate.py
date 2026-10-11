"""Minimal forward/backward SQL migration runner and its ``python -m`` entrypoint.

Migrations are ``NNNN_name.up.sql`` files in ``migrations/`` with an optional
``NNNN_name.down.sql`` rollback. They are static DDL reviewed in the repository (no
values are interpolated); applied versions are tracked in ``netsight_schema_migrations``
inside the connection's current schema. Alembic is installed but is not wired into the
repo yet; this runner can be replaced by an Alembic environment that executes the same
files without changing them.

* The production wheel ships the ``up`` files only (rollbacks are destructive and are
  excluded in ``pyproject.toml``); a source checkout carries both.
* Each ``up`` runs in its own transaction with its tracking row; an advisory lock
  serialises concurrent runners.
* ``apply_down`` is destructive and fails closed: it needs ``allow_destructive=True`` and
  either empty target tables or ``NETSIGHT_ALLOW_DESTRUCTIVE_DOWN=1`` in the environment.
* Runtime grants for the application role are applied by ``apply_grants`` from
  ``grants/app_role.sql``; the role name is configuration, never hardcoded. The WAN collector
  role (INSERT only on the WAN tables) has its own script, ``grants/wan_collector_role.sql``.
* The WAN evidence tables are partitioned by month. Creating a partition is DDL, which the runtime
  roles do not hold, so it is a migrator step: ``up`` creates the current and next month and
  ``partitions`` (a scheduled monthly run) keeps the next one ready; both are idempotent.

Command line (uses the migrator/owner credential, never the application one)::

    DATABASE_MIGRATION_URL=... DATABASE_APP_ROLE=... [DATABASE_WAN_COLLECTOR_ROLE=...]
        python -m netsight_api.storage.migrate up
    DATABASE_MIGRATION_URL=... python -m netsight_api.storage.migrate status
    DATABASE_MIGRATION_URL=... python -m netsight_api.storage.migrate partitions   # monthly

Exit codes: 0 success, 1 migration/database failure, 2 usage or configuration error. The
DSN and database error text are never printed.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import psycopg
from psycopg import sql

from netsight_api.storage.errors import StorageConfigurationError, StorageError

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
GRANTS_PATH = Path(__file__).parent / "grants" / "app_role.sql"
COLLECTOR_GRANTS_PATH = Path(__file__).parent / "grants" / "wan_collector_role.sql"
DESTRUCTIVE_ENV = "NETSIGHT_ALLOW_DESTRUCTIVE_DOWN"
APP_ROLE_ENV = "DATABASE_APP_ROLE"
WAN_COLLECTOR_ROLE_ENV = "DATABASE_WAN_COLLECTOR_ROLE"
MAX_PARTITION_MONTHS_AHEAD = 12
_ADVISORY_LOCK_KEY = 7_274_001
_FILE = re.compile(r"^(\d{4})_([a-z0-9_]+)\.(up|down)\.sql$")
_ROLE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_DROP_TABLE = re.compile(
    r"^\s*DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([a-z_][a-z0-9_]*)\s*;", re.IGNORECASE | re.MULTILINE
)

Connection = psycopg.Connection[Any]


class MigrationError(StorageError):
    """A migration step was refused or could not be performed."""


class DestructiveMigrationError(MigrationError):
    """A rollback was refused because it would destroy data without explicit consent."""


@dataclass(frozen=True)
class Migration:
    version: str
    name: str
    up_path: Path
    down_path: Path | None


@dataclass(frozen=True)
class MigrationStatus:
    applied: tuple[str, ...]
    pending: tuple[str, ...]


def available_migrations(directory: Path = MIGRATIONS_DIR) -> list[Migration]:
    """Return migrations ordered by version; fail on a rollback with no forward file."""
    found: dict[tuple[str, str], dict[str, Path]] = {}
    for path in sorted(directory.glob("*.sql")):
        match = _FILE.match(path.name)
        if match is None:
            raise ValueError(f"unrecognised migration file name: {path.name}")
        version, name, direction = match.groups()
        found.setdefault((version, name), {})[direction] = path
    migrations: list[Migration] = []
    for (version, name), paths in sorted(found.items()):
        if "up" not in paths:
            raise ValueError(f"migration {version}_{name} has a down file but no up file")
        migrations.append(Migration(version, name, paths["up"], paths.get("down")))
    return migrations


def _ensure_tracking_table(conn: Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS netsight_schema_migrations ("
        "version text PRIMARY KEY, name text NOT NULL, "
        "applied_at timestamptz NOT NULL DEFAULT now())"
    )


def _first_value(row: Any) -> Any:
    return next(iter(row.values())) if isinstance(row, dict) else row[0]


def _applied_versions(conn: Connection) -> list[str]:
    rows = conn.execute(
        "SELECT version FROM netsight_schema_migrations ORDER BY version"
    ).fetchall()
    return [_first_value(row) for row in rows]


def migration_status(conn: Connection) -> MigrationStatus:
    """Read-only: report applied and pending versions without creating anything."""
    row = conn.execute("SELECT to_regclass('netsight_schema_migrations') IS NOT NULL").fetchone()
    done = _applied_versions(conn) if row is not None and _first_value(row) else []
    known = [m.version for m in available_migrations()]
    return MigrationStatus(
        applied=tuple(done), pending=tuple(v for v in known if v not in set(done))
    )


def apply_up(conn: Connection) -> list[str]:
    """Apply every pending migration; return the versions applied (idempotent)."""
    applied_now: list[str] = []
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (_ADVISORY_LOCK_KEY,))
        _ensure_tracking_table(conn)
        done = set(_applied_versions(conn))
        for migration in available_migrations():
            if migration.version in done:
                continue
            conn.execute(migration.up_path.read_text("utf-8"))
            conn.execute(
                "INSERT INTO netsight_schema_migrations (version, name) VALUES (%s, %s)",
                (migration.version, migration.name),
            )
            applied_now.append(migration.version)
    return applied_now


def _non_empty_tables(conn: Connection, down_sql: str) -> list[str]:
    """Tables a rollback drops that currently exist and hold rows (names come from our SQL)."""
    populated: list[str] = []
    for table in _DROP_TABLE.findall(down_sql):
        present = conn.execute("SELECT to_regclass(%s) IS NOT NULL", (table,)).fetchone()
        if present is None or not _first_value(present):
            continue
        has_rows = conn.execute(
            sql.SQL("SELECT EXISTS (SELECT 1 FROM {})").format(sql.Identifier(table))
        ).fetchone()
        if has_rows is not None and _first_value(has_rows):
            populated.append(table)
    return populated


def apply_down(
    conn: Connection,
    steps: int = 1,
    *,
    allow_destructive: bool = False,
    env: Mapping[str, str] | None = None,
) -> list[str]:
    """Reverse the most recent ``steps`` applied migrations; return the versions reversed.

    Fails closed: ``allow_destructive`` must be True, and a rollback that would drop a
    table holding rows additionally needs ``NETSIGHT_ALLOW_DESTRUCTIVE_DOWN=1`` in ``env``
    (default: the process environment). Rollback files exist only in a source checkout.
    """
    if steps < 1:
        raise ValueError("steps must be at least 1")
    if not allow_destructive:
        raise DestructiveMigrationError(
            "rolling back is destructive; allow_destructive=True required"
        )
    override = (os.environ if env is None else env).get(DESTRUCTIVE_ENV) == "1"
    reversed_now: list[str] = []
    by_version = {m.version: m for m in available_migrations()}
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (_ADVISORY_LOCK_KEY,))
        _ensure_tracking_table(conn)
        for version in reversed(_applied_versions(conn)):
            if len(reversed_now) == steps:
                break
            migration = by_version.get(version)
            if migration is None:
                raise ValueError(f"applied migration {version} has no file; refusing to continue")
            if migration.down_path is None:
                raise MigrationError(f"rollback SQL for {version} is not available in this install")
            down_sql = migration.down_path.read_text("utf-8")
            populated = _non_empty_tables(conn, down_sql)
            if populated and not override:
                raise DestructiveMigrationError(
                    f"rollback of {version} would destroy data in: {', '.join(populated)}; "
                    f"set {DESTRUCTIVE_ENV}=1 to confirm"
                )
            conn.execute(down_sql)
            conn.execute("DELETE FROM netsight_schema_migrations WHERE version = %s", (version,))
            reversed_now.append(version)
    return reversed_now


def apply_grants(conn: Connection, app_role: str, wan_collector_role: str | None = None) -> None:
    """(Re)apply the least-privilege grants for ``app_role`` (and the collector); idempotent.

    Run as the migrator/owner after ``apply_up``. Refuses a missing role, a superuser or
    BYPASSRLS role, and a role that owns (or inherits ownership of) the tables. The API role gets
    SELECT only on the WAN tables; the optional ``wan_collector_role`` gets INSERT only on them
    and must differ from the application role.
    """
    if not _ROLE_NAME.fullmatch(app_role):
        raise ValueError("the application role name must match [a-z_][a-z0-9_]{0,62}")
    if wan_collector_role is not None and not _ROLE_NAME.fullmatch(wan_collector_role):
        raise ValueError("the WAN collector role name must match [a-z_][a-z0-9_]{0,62}")
    if wan_collector_role == app_role:
        raise ValueError("the WAN collector role must differ from the application role")
    try:
        with conn.transaction():
            conn.execute("SELECT set_config('netsight.app_role', %s, true)", (app_role,))
            conn.execute(GRANTS_PATH.read_text("utf-8"))
            if wan_collector_role is not None:
                conn.execute(
                    "SELECT set_config('netsight.wan_collector_role', %s, true)",
                    (wan_collector_role,),
                )
                conn.execute(COLLECTOR_GRANTS_PATH.read_text("utf-8"))
    except psycopg.errors.RaiseException as error:
        raise MigrationError(error.diag.message_primary or "grants were refused") from None


def wan_partition_months(now: datetime, ahead: int = 1) -> list[date]:
    """The first day of the UTC month of ``now`` and of each of the next ``ahead`` months."""
    if not 0 <= ahead <= MAX_PARTITION_MONTHS_AHEAD:
        raise ValueError(f"months ahead must be between 0 and {MAX_PARTITION_MONTHS_AHEAD}")
    current = now.astimezone(UTC)
    index = current.year * 12 + current.month - 1
    return [date((index + n) // 12, (index + n) % 12 + 1, 1) for n in range(ahead + 1)]


def ensure_wan_partitions(conn: Connection, months: Sequence[date]) -> None:
    """Create (idempotently) the WAN cycle and sample partitions for each month in ``months``.

    DDL: run as the migrator/owner only. A month already partitioned is left untouched.
    """
    with conn.transaction():
        for month in months:
            conn.execute("SELECT netsight_ensure_wan_partition(%s)", (month,))


# --- command line ---------------------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m netsight_api.storage.migrate",
        description="Apply or inspect NetSight database migrations (uses DATABASE_MIGRATION_URL).",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    up = commands.add_parser("up", help="apply pending migrations, then the application grants")
    up.add_argument("--app-role", help=f"application role to grant (default: ${APP_ROLE_ENV})")
    up.add_argument(
        "--wan-collector-role",
        help=f"WAN collector role granted INSERT on the WAN tables (default: ${WAN_COLLECTOR_ROLE_ENV})",
    )
    up.add_argument("--no-grants", action="store_true", help="skip the application-role grants")
    status = commands.add_parser("status", help="list applied and pending migrations")
    partitions = commands.add_parser(
        "partitions",
        help="create the WAN month partitions for the current and next month (run monthly)",
    )
    partitions.add_argument(
        "--months-ahead",
        type=int,
        default=1,
        help=f"further months to prepare, 0 to {MAX_PARTITION_MONTHS_AHEAD} (default 1)",
    )
    for command in (up, status, partitions):
        command.add_argument("--schema", help="schema to operate in (default: search_path)")
    return parser


def _run_up(conn: Connection, role: str | None, collector_role: str | None = None) -> None:
    applied = apply_up(conn)
    for version in applied:
        print(f"applied: {version}")
    if not applied:
        print("schema is up to date")
    _run_partitions(conn, 1)
    if role is not None:
        apply_grants(conn, role, collector_role)
        print(f"grants applied for role {role}")
        if collector_role is not None:
            print(f"WAN collector grants applied for role {collector_role}")


def _run_partitions(conn: Connection, ahead: int) -> None:
    months = wan_partition_months(datetime.now(UTC), ahead)
    ensure_wan_partitions(conn, months)
    print("WAN partitions ready: " + ", ".join(f"{month:%Y-%m}" for month in months))


def _run_status(conn: Connection) -> None:
    report = migration_status(conn)
    for version in report.applied:
        print(f"applied: {version}")
    for version in report.pending:
        print(f"pending: {version}")


def main(argv: Sequence[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    # Imported here so importing this module for apply_up/apply_down stays light.
    from netsight_api.storage.connection import PostgresSettings

    args = _parser().parse_args(argv)
    source = os.environ if env is None else env
    role: str | None = None
    collector_role: str | None = None
    if args.command == "up" and not args.no_grants:
        role = args.app_role or source.get(APP_ROLE_ENV) or None
        if role is None or not _ROLE_NAME.fullmatch(role):
            print(
                f"error: a valid application role is required ({APP_ROLE_ENV} or --app-role), "
                "or pass --no-grants",
                file=sys.stderr,
            )
            return 2
        collector_role = args.wan_collector_role or source.get(WAN_COLLECTOR_ROLE_ENV) or None
        if collector_role is not None and (
            not _ROLE_NAME.fullmatch(collector_role) or collector_role == role
        ):
            print(
                "error: the WAN collector role must be a valid role name that differs from the "
                "application role",
                file=sys.stderr,
            )
            return 2
    if args.command == "partitions" and not 0 <= args.months_ahead <= MAX_PARTITION_MONTHS_AHEAD:
        print(
            f"error: --months-ahead must be between 0 and {MAX_PARTITION_MONTHS_AHEAD}",
            file=sys.stderr,
        )
        return 2
    try:
        settings = PostgresSettings.for_migrator(source, schema=args.schema)
    except StorageConfigurationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    try:
        with settings.connect() as conn:
            if args.command == "up":
                _run_up(conn, role, collector_role)
            elif args.command == "partitions":
                _run_partitions(conn, args.months_ahead)
            else:
                _run_status(conn)
    except MigrationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except psycopg.Error as error:
        state = error.sqlstate or "-"
        print(
            f"error: database operation failed ({type(error).__name__}, sqlstate {state})",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
