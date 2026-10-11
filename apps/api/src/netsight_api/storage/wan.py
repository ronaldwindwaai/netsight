"""WAN probe-sample store (Step 5b): the Protocol and the in-memory implementation.

PostgreSQL owns this application state (DATABASE-OWNERSHIP). Two append-only record kinds:

* **samples** - one row per probe outcome (``icmp``/``tcp`` reachability, ``dns``), the raw
  evidence;
* **cycles** - one rollup row per link per sampling round, holding the counts of that round's
  reachability samples and the state they imply. The database pins the state to the counts, and
  ``record_cycle`` refuses a cycle that disagrees with the samples it is stored with, so the SLA
  maths in ``netsight_api.wan.sla`` can be re-derived from the samples at any time.

A cycle and its samples are written in one transaction. Nothing is ever updated or deleted by the
application (there is no such method; the database rejects both for every role including the
owner) and a repeated ``(link, time)`` is a conflict, never an overwrite. Reads are bounded: a
result larger than its cap is an error, never a silent cut, so a figure is never computed from a
truncated month. Retention and a prune step are a pending human decision (DATA-RETENTION-MATRIX).

The PostgreSQL tables are range-partitioned by month. A write into a month that has no partition
is refused with ``WanPartitionMissingError`` (the collector fails closed and logs it); creating
partitions is DDL and belongs to the migrator (``netsight_api.storage.migrate partitions``), never
to the runtime roles.
"""

from __future__ import annotations

import math
import re
import threading
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final, Protocol

from netsight_api.storage.errors import StorageConflictError, StorageError
from netsight_api.wan import sla
from netsight_api.wan.sla import Cycle, Sample

MAX_SAMPLES_PER_CYCLE: Final = 64
# The longest a cycle can cover: the maximum sampling interval (300 s) plus the half-interval grace.
LOOKBACK_SECONDS: Final = 450
# The sampling interval bounds (apps/api wan/config.py); repeated here because the store sits below
# the configuration module.
MIN_INTERVAL_SECONDS: Final = 30
MAX_INTERVAL_SECONDS: Final = 300
_LONGEST_MONTH_SECONDS: Final = 31 * 86_400
# Rounds of one month are doubled so a second writer (a standby that briefly overlaps the leader)
# cannot push a normal month over the cap.
_WRITER_HEADROOM: Final = 2
MAX_SAMPLES_READ: Final = 5_000
MAX_SOURCES: Final = 64


def cycle_read_cap(interval_seconds: int) -> int:
    """The most cycles one month read may return at ``interval_seconds``, with headroom.

    One link stores at most ``31 days / interval`` cycles a month; the cap is twice that plus the
    cycles of the look-back, so a normal month never hits it and a runaway writer still does (an
    over-large read is an error, never a silent cut).
    """
    if not MIN_INTERVAL_SECONDS <= interval_seconds <= MAX_INTERVAL_SECONDS:
        raise ValueError("the sampling interval is outside the supported range")
    rounds = math.ceil(_LONGEST_MONTH_SECONDS / interval_seconds)
    return _WRITER_HEADROOM * rounds + math.ceil(LOOKBACK_SECONDS / interval_seconds)


# The default is the worst case: the shortest interval.
MAX_CYCLES_READ: Final = cycle_read_cap(MIN_INTERVAL_SECONDS)

_LINK_ID: Final = re.compile(r"[a-z0-9][a-z0-9-]{0,47}", re.ASCII)


class WanPartitionMissingError(StorageError):
    """No month partition exists for the cycle's time: the write was refused (fail closed)."""


@dataclass(frozen=True)
class ProbeSource:
    probe: str
    target: str
    location: str | None


class WanSampleRepository(Protocol):
    def record_cycle(self, cycle: Cycle, samples: Sequence[Sample]) -> None:
        """Store a cycle with its samples atomically. ``StorageConflictError`` if the link already
        has a cycle at that time (never overwrites); ``ValueError`` if the cycle's counts do not
        match its samples."""
        ...

    def cycles_between(self, link_id: str, start: datetime, end: datetime) -> list[Cycle]:
        """Cycles in ``[start - look-back, end)``, oldest first (the look-back keeps a cycle that
        still covers ``start``). More than ``MAX_CYCLES_READ`` is a ``StorageError``."""
        ...

    def samples_between(
        self, link_id: str, start: datetime, end: datetime, *, limit: int = MAX_SAMPLES_READ
    ) -> list[tuple[datetime, Sample]]:
        """Samples in ``[start, end)``, oldest first; more than ``limit`` is a ``StorageError``."""
        ...

    def probe_sources(self, link_id: str, start: datetime, end: datetime) -> list[ProbeSource]:
        """The distinct probe, target and location behind the samples in ``[start, end)``."""
        ...


def check_link_id(link_id: str) -> None:
    if not isinstance(link_id, str) or _LINK_ID.fullmatch(link_id) is None:
        raise ValueError("link id is not a valid WAN link identifier")


def check_window(link_id: str, start: datetime, end: datetime) -> None:
    check_link_id(link_id)
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("a window must carry a timezone")
    if not start < end:
        raise ValueError("the window start must be before its end")


def check_record(cycle: Cycle, samples: Sequence[Sample]) -> None:
    check_link_id(cycle.link_id)
    if len(samples) > MAX_SAMPLES_PER_CYCLE:
        raise ValueError(f"a cycle holds at most {MAX_SAMPLES_PER_CYCLE} samples")
    if sla.build_cycle(cycle.link_id, cycle.sampled_at, cycle.interval_seconds, samples) != cycle:
        raise ValueError("the cycle does not match its samples")


def lookback_start(start: datetime) -> datetime:
    return start - timedelta(seconds=LOOKBACK_SECONDS)


class InMemoryWanSampleRepository:
    """Unit-test implementation with the same rules as the PostgreSQL store."""

    def __init__(
        self,
        *,
        partitioned_months: Collection[tuple[int, int]] | None = None,
        max_cycles: int | None = None,
    ) -> None:
        """``partitioned_months`` ``(year, month)`` mimics the database: a cycle in any other month
        is refused. ``None`` (the default) accepts every month."""
        self._lock = threading.Lock()
        self._months = None if partitioned_months is None else frozenset(partitioned_months)
        self._max_cycles = max_cycles
        self._cycles: dict[tuple[str, datetime], Cycle] = {}
        self._samples: dict[tuple[str, datetime], tuple[Sample, ...]] = {}

    def record_cycle(self, cycle: Cycle, samples: Sequence[Sample]) -> None:
        check_record(cycle, samples)
        moment = cycle.sampled_at.astimezone(UTC)
        if self._months is not None and (moment.year, moment.month) not in self._months:
            raise WanPartitionMissingError("no database partition exists for the cycle's month")
        key = (cycle.link_id, cycle.sampled_at)
        with self._lock:
            if key in self._cycles:
                raise StorageConflictError("the cycle already exists and is immutable")
            self._cycles[key] = cycle
            self._samples[key] = tuple(samples)

    def cycles_between(self, link_id: str, start: datetime, end: datetime) -> list[Cycle]:
        check_window(link_id, start, end)
        floor = lookback_start(start)
        with self._lock:
            found = [
                cycle
                for (link, when), cycle in self._cycles.items()
                if link == link_id and floor <= when < end
            ]
        if len(found) > (self._max_cycles or MAX_CYCLES_READ):
            raise StorageError("too many cycles in the requested window")
        return sorted(found, key=lambda cycle: cycle.sampled_at)

    def samples_between(
        self, link_id: str, start: datetime, end: datetime, *, limit: int = MAX_SAMPLES_READ
    ) -> list[tuple[datetime, Sample]]:
        check_window(link_id, start, end)
        with self._lock:
            found = [
                (when, sample)
                for (link, when), rows in sorted(self._samples.items(), key=lambda kv: kv[0][1])
                if link == link_id and start <= when < end
                for sample in rows
            ]
        if len(found) > limit:
            raise StorageError("too many samples in the requested window")
        return found

    def probe_sources(self, link_id: str, start: datetime, end: datetime) -> list[ProbeSource]:
        check_window(link_id, start, end)
        with self._lock:
            distinct = {
                ProbeSource(sample.probe, sample.target, sample.location)
                for (link, when), rows in self._samples.items()
                if link == link_id and start <= when < end
                for sample in rows
            }
        ordered = sorted(distinct, key=lambda s: (s.probe, s.target, s.location or ""))
        return ordered[:MAX_SOURCES]
