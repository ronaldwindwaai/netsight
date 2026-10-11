"""Live-PostgreSQL helpers for the WAN tests: partitions, split roles and a split-role store.

The WAN tables are range-partitioned by month and the API (read-only) and the collector
(insert-only) use different database roles, so a live test needs the month partitions it writes
into and one connection per role. ``provision_wan`` builds that in a throwaway schema.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import date, datetime

from pg_support import PG_DSN, app_role, isolated_schema

from netsight_api.storage import migrate
from netsight_api.storage.connection import PostgresSettings
from netsight_api.storage.postgres_wan import PostgresWanSampleRepository
from netsight_api.storage.wan import ProbeSource
from netsight_api.wan.sla import Cycle, Sample

# The months the shared WAN fixtures write into (September for the report data, October for "now").
WAN_MONTHS: tuple[date, ...] = (date(2026, 9, 1), date(2026, 10, 1), date(2026, 11, 1))


@dataclass(frozen=True)
class WanDatabase:
    schema: str
    owner: PostgresSettings
    reader: PostgresSettings  # the API's SELECT-only role
    writer: PostgresSettings  # the collector's INSERT-only role
    reader_role: str
    writer_role: str


@contextmanager
def provision_wan(months: Sequence[date] = WAN_MONTHS) -> Iterator[WanDatabase]:
    """A migrated throwaway schema with ``months`` partitions and both runtime roles granted."""
    assert PG_DSN
    with ExitStack() as stack:
        schema = stack.enter_context(isolated_schema())
        reader_role, reader_dsn = stack.enter_context(app_role())
        writer_role, writer_dsn = stack.enter_context(app_role())
        owner = PostgresSettings(dsn=PG_DSN, schema=schema)
        with owner.connect() as conn:
            migrate.apply_up(conn)
            migrate.ensure_wan_partitions(conn, months)
            migrate.apply_grants(conn, reader_role, writer_role)
        yield WanDatabase(
            schema=schema,
            owner=owner,
            reader=PostgresSettings(dsn=reader_dsn, schema=schema),
            writer=PostgresSettings(dsn=writer_dsn, schema=schema),
            reader_role=reader_role,
            writer_role=writer_role,
        )


class SplitRoleStore:
    """The production shape: the collector role writes, the API role reads."""

    def __init__(self, database: WanDatabase) -> None:
        self._writer = PostgresWanSampleRepository(database.writer)
        self._reader = PostgresWanSampleRepository(database.reader)

    def record_cycle(self, cycle: Cycle, samples: Sequence[Sample]) -> None:
        self._writer.record_cycle(cycle, samples)

    def cycles_between(self, link_id: str, start: datetime, end: datetime) -> list[Cycle]:
        return self._reader.cycles_between(link_id, start, end)

    def samples_between(
        self, link_id: str, start: datetime, end: datetime, *, limit: int = 5_000
    ) -> list[tuple[datetime, Sample]]:
        return self._reader.samples_between(link_id, start, end, limit=limit)

    def probe_sources(self, link_id: str, start: datetime, end: datetime) -> list[ProbeSource]:
        return self._reader.probe_sources(link_id, start, end)
