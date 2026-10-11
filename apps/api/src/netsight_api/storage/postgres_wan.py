"""PostgreSQL implementation of the WAN probe-sample store (see ``wan``).

One short transaction per call, static SQL, bound parameters. ``record_cycle`` writes the cycle
and its samples in a single transaction so a conflicting cycle leaves no orphan sample. There is
no UPDATE or DELETE statement here and the tables' triggers and the roles' grants forbid both.
Result caps are enforced by asking the database for one row more than the cap, so an over-large
window is an error, never a silent cut.

The tables are partitioned by month and the runtime roles hold no DDL, so a write into a month
without a partition is refused (``WanPartitionMissingError``): the migrator creates partitions.
Only a unique violation means "this cycle already exists"; a deadlock or serialization failure is
a failed write, never a skipped one.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import datetime
from typing import Any, Final

import psycopg

from netsight_api.storage import wan
from netsight_api.storage.connection import PostgresSettings
from netsight_api.storage.errors import (
    InvalidOperationError,
    StorageConflictError,
    StorageError,
    StorageUnavailableError,
)
from netsight_api.wan.sla import Cycle, Sample

_LOGGER = logging.getLogger("netsight_api")

_INSERT_CYCLE = (
    "INSERT INTO wan_link_cycles (link_id, sampled_at, interval_seconds, passes, fails, "
    "unknowns, state) VALUES (%s, %s, %s, %s, %s, %s, %s)"
)
_INSERT_SAMPLE = (
    "INSERT INTO wan_probe_samples (link_id, sampled_at, seq, probe, target, location, "
    "outcome, latency_ms) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
)
_SELECT_CYCLES = (
    "SELECT link_id, sampled_at, interval_seconds, passes, fails, unknowns, state "
    "FROM wan_link_cycles WHERE link_id = %s AND sampled_at >= %s AND sampled_at < %s "
    "ORDER BY sampled_at LIMIT %s"
)
_SELECT_SAMPLES = (
    "SELECT sampled_at, probe, target, location, outcome, latency_ms FROM wan_probe_samples "
    "WHERE link_id = %s AND sampled_at >= %s AND sampled_at < %s "
    "ORDER BY sampled_at, seq LIMIT %s"
)
_SELECT_SOURCES = (
    "SELECT DISTINCT probe, target, location FROM wan_probe_samples "
    "WHERE link_id = %s AND sampled_at >= %s AND sampled_at < %s "
    "ORDER BY probe, target, location NULLS FIRST LIMIT %s"
)


class CollectorRoleError(ValueError):
    """The collector's database role is unsafe (or could not be checked): do not start."""


_ROLE_PROBE: Final = (
    "SELECT r.rolsuper AS is_superuser, r.rolbypassrls AS bypasses_rls, "
    "COALESCE(bool_or(pg_has_role(current_user, c.relowner, 'USAGE')), false) AS owns_tables "
    "FROM pg_roles r LEFT JOIN pg_class c "
    "ON c.oid IN (to_regclass('wan_link_cycles'), to_regclass('wan_probe_samples')) "
    "WHERE r.rolname = current_user GROUP BY r.rolsuper, r.rolbypassrls"
)


def check_collector_role(settings: PostgresSettings) -> None:
    """Refuse a collector role that is a superuser, bypasses row security or owns the WAN tables.

    The collector must hold INSERT on the evidence tables and nothing more: an owner or superuser
    could also disable the append-only triggers. Raises ``CollectorRoleError`` (no DSN, no driver
    text) for an unsafe role and when the role cannot be checked at all.
    """
    try:
        with settings.session() as conn:
            row = conn.execute(_ROLE_PROBE).fetchone()
    except StorageError:
        _LOGGER.warning("the WAN collector database role could not be checked")
        raise CollectorRoleError("the WAN collector database role could not be verified") from None
    if row is None:
        raise CollectorRoleError("the WAN collector database role could not be verified")
    if row["is_superuser"]:
        raise CollectorRoleError("the WAN collector database role must not be a superuser")
    if row["bypasses_rls"]:
        raise CollectorRoleError("the WAN collector database role must not bypass row security")
    if row["owns_tables"]:
        raise CollectorRoleError("the WAN collector database role must not own the WAN tables")


class PostgresWanSampleRepository:
    def __init__(self, settings: PostgresSettings, *, max_cycles: int | None = None) -> None:
        self._settings = settings
        self._max_cycles = max_cycles

    @property
    def max_cycles(self) -> int:
        """The most cycles a read may return (the explicit cap, else the worst-case default)."""
        return self._max_cycles or wan.MAX_CYCLES_READ

    def record_cycle(self, cycle: Cycle, samples: Sequence[Sample]) -> None:
        wan.check_record(cycle, samples)
        try:
            with self._settings.session() as conn, conn.cursor() as cursor:
                cursor.execute(
                    _INSERT_CYCLE,
                    (
                        cycle.link_id,
                        cycle.sampled_at,
                        cycle.interval_seconds,
                        cycle.passes,
                        cycle.fails,
                        cycle.unknowns,
                        cycle.state,
                    ),
                )
                if samples:
                    cursor.executemany(
                        _INSERT_SAMPLE,
                        [
                            (
                                cycle.link_id,
                                cycle.sampled_at,
                                seq,
                                sample.probe,
                                sample.target,
                                sample.location,
                                sample.outcome,
                                sample.latency_ms,
                            )
                            for seq, sample in enumerate(samples, start=1)
                        ],
                    )
        except StorageConflictError as error:
            if isinstance(error.__cause__, psycopg.errors.UniqueViolation):
                raise  # the cycle already exists: the only conflict that means "skipped"
            # A deadlock or serialization failure wrote nothing: that is a failed write.
            raise StorageUnavailableError("the WAN write could not be completed") from error
        except InvalidOperationError as error:
            cause = error.__cause__
            if (
                isinstance(cause, psycopg.errors.CheckViolation)
                and cause.diag.constraint_name is None
            ):
                # Routing a row to a partition that does not exist is the only check violation
                # that names no constraint.
                raise wan.WanPartitionMissingError(
                    "no database partition exists for the cycle's month"
                ) from error
            raise

    def cycles_between(self, link_id: str, start: datetime, end: datetime) -> list[Cycle]:
        wan.check_window(link_id, start, end)
        cap = self.max_cycles
        with self._settings.session() as conn:
            rows = conn.execute(
                _SELECT_CYCLES, (link_id, wan.lookback_start(start), end, cap + 1)
            ).fetchall()
        if len(rows) > cap:
            raise StorageError("too many cycles in the requested window")
        try:
            return [_cycle(row) for row in rows]
        except ValueError as error:
            _LOGGER.warning("a stored WAN cycle failed validation")
            raise StorageError("a stored cycle could not be read") from error

    def samples_between(
        self,
        link_id: str,
        start: datetime,
        end: datetime,
        *,
        limit: int = wan.MAX_SAMPLES_READ,
    ) -> list[tuple[datetime, Sample]]:
        wan.check_window(link_id, start, end)
        with self._settings.session() as conn:
            rows = conn.execute(_SELECT_SAMPLES, (link_id, start, end, limit + 1)).fetchall()
        if len(rows) > limit:
            raise StorageError("too many samples in the requested window")
        return [
            (
                row["sampled_at"],
                Sample(
                    probe=row["probe"],
                    target=row["target"],
                    outcome=row["outcome"],
                    latency_ms=row["latency_ms"],
                    location=row["location"],
                ),
            )
            for row in rows
        ]

    def probe_sources(self, link_id: str, start: datetime, end: datetime) -> list[wan.ProbeSource]:
        wan.check_window(link_id, start, end)
        with self._settings.session() as conn:
            rows = conn.execute(_SELECT_SOURCES, (link_id, start, end, wan.MAX_SOURCES)).fetchall()
        return [wan.ProbeSource(row["probe"], row["target"], row["location"]) for row in rows]


def _cycle(row: dict[str, Any]) -> Cycle:
    return Cycle(
        link_id=row["link_id"],
        sampled_at=row["sampled_at"],
        interval_seconds=row["interval_seconds"],
        passes=row["passes"],
        fails=row["fails"],
        unknowns=row["unknowns"],
        state=row["state"],
    )
