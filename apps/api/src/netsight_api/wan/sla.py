"""Deterministic WAN availability, outage and quality maths over stored probe samples.

Pure functions of stored data and a window: no clock, no I/O, no inference beyond what a sample
says. The rules, in one place so the SLA export and the page cannot disagree:

* A **cycle** is one sampling round for one link. Its state comes only from its *reachability*
  samples (probe kinds ``icmp`` and ``tcp``): all passed or some unknown -> ``up``; some passed and
  some failed -> ``degraded``; all failed (none unknown) -> ``down``; anything else -> ``unknown``.
  An unknown sample is never a pass and never a failure. DNS samples are reported separately.
* A cycle **covers** the time from its sample until the next cycle, but never longer than its
  sampling interval plus half of it (the grace absorbs scheduling jitter and is documented, not
  tuned). Time no cycle covers is **unknown**: a gap in sampling is never counted as up or down.
* Uptime is ``(up + degraded) / (up + degraded + down)`` over *known* time (a degraded link was
  reachable); it is ``None`` when nothing was known, never 0 or 100. Coverage is known time over
  the whole window. An outage is a contiguous run of ``down`` coverage, ended by any other state or
  by a gap.
* Cycle times are whole seconds, so every duration here is an integer number of seconds.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from typing import Final, Literal

SampleOutcome = Literal["pass", "fail", "unknown"]
CycleState = Literal["up", "degraded", "down", "unknown"]
WindowKind = Literal["down", "degraded", "unknown"]

REACHABILITY_PROBES: Final = frozenset({"icmp", "tcp"})
DNS_PROBE: Final = "dns"
MAX_MONTHS_BACK: Final = 24
MAX_WINDOWS: Final = 2000
_MONTH: Final = re.compile(r"(\d{4})-(\d{2})", re.ASCII)


@dataclass(frozen=True)
class Sample:
    probe: str
    target: str
    outcome: SampleOutcome
    latency_ms: float | None = None
    # Where the probe ran (a configured probe location), when the probe source declares one.
    location: str | None = None


def cycle_state(passes: int, fails: int, unknowns: int) -> CycleState:
    if passes > 0 and fails == 0:
        return "up"
    if passes > 0:
        return "degraded"
    if fails > 0 and unknowns == 0:
        return "down"
    return "unknown"


@dataclass(frozen=True)
class Cycle:
    """One stored sampling round: counts of its reachability samples and the state they imply."""

    link_id: str
    sampled_at: datetime
    interval_seconds: int
    passes: int
    fails: int
    unknowns: int
    state: CycleState

    def __post_init__(self) -> None:
        _check_time(self.sampled_at)
        if self.interval_seconds < 1 or min(self.passes, self.fails, self.unknowns) < 0:
            raise ValueError("cycle counts and interval must be positive")
        if self.state != cycle_state(self.passes, self.fails, self.unknowns):
            raise ValueError("cycle state is inconsistent with its sample counts")

    @property
    def coverage_seconds(self) -> int:
        return self.interval_seconds + self.interval_seconds // 2


def _check_time(moment: datetime) -> None:
    if moment.tzinfo is None:
        raise ValueError("a time must carry a timezone")
    if moment.microsecond:
        raise ValueError("a cycle time must be whole seconds")


def build_cycle(
    link_id: str, sampled_at: datetime, interval_seconds: int, samples: Iterable[Sample]
) -> Cycle:
    """The cycle record for ``samples``; only reachability probes count towards its state."""
    _check_time(sampled_at)
    reach = [sample for sample in samples if sample.probe in REACHABILITY_PROBES]
    passes = sum(1 for sample in reach if sample.outcome == "pass")
    fails = sum(1 for sample in reach if sample.outcome == "fail")
    unknowns = len(reach) - passes - fails
    return Cycle(
        link_id=link_id,
        sampled_at=sampled_at.astimezone(UTC),
        interval_seconds=interval_seconds,
        passes=passes,
        fails=fails,
        unknowns=unknowns,
        state=cycle_state(passes, fails, unknowns),
    )


# --- coverage -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Segment:
    start: datetime
    end: datetime
    state: CycleState
    sample_count: int

    @property
    def seconds(self) -> int:
        return int((self.end - self.start).total_seconds())


def _reconcile(first: Cycle, second: Cycle) -> Cycle:
    """Two cycles stored for one instant (two writers): agreement keeps one, conflict is unknown.

    Evidence that contradicts itself proves neither state, so the instant becomes an ``unknown``
    cycle (never a pass, never a failure). The shorter interval is kept, so coverage is never
    stretched. The result does not depend on the order of the two.
    """
    if first == second:
        return first
    return Cycle(
        link_id=first.link_id,
        sampled_at=first.sampled_at,
        interval_seconds=min(first.interval_seconds, second.interval_seconds),
        passes=0,
        fails=0,
        unknowns=max(
            1,
            first.passes
            + first.fails
            + first.unknowns
            + second.passes
            + second.fails
            + second.unknowns,
        ),
        state="unknown",
    )


def _ordered(cycles: Iterable[Cycle]) -> list[Cycle]:
    """Oldest first, one cycle per instant; overlapping coverage is cut at the next cycle."""
    ordered: list[Cycle] = []
    for cycle in sorted(cycles, key=lambda c: (c.sampled_at, c.state, c.interval_seconds)):
        if ordered and ordered[-1].sampled_at == cycle.sampled_at:
            ordered[-1] = _reconcile(ordered[-1], cycle)
        else:
            ordered.append(cycle)
    return ordered


def _merge(segments: list[Segment]) -> list[Segment]:
    merged: list[Segment] = []
    for segment in segments:
        if merged and merged[-1].state == segment.state and merged[-1].end == segment.start:
            last = merged.pop()
            segment = Segment(
                last.start, segment.end, last.state, last.sample_count + segment.sample_count
            )
        merged.append(segment)
    return merged


def segments(cycles: Iterable[Cycle], start: datetime, end: datetime) -> list[Segment]:
    """Tile ``[start, end)`` with the state each cycle covers; uncovered time is ``unknown``."""
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("a window must carry a timezone")
    if not start < end:
        raise ValueError("the window start must be before its end")
    ordered = _ordered(cycles)
    tiles: list[Segment] = []
    cursor = start
    for index, cycle in enumerate(ordered):
        until = cycle.sampled_at + timedelta(seconds=cycle.coverage_seconds)
        if index + 1 < len(ordered):
            until = min(until, ordered[index + 1].sampled_at)
        covered_from, covered_to = max(cycle.sampled_at, start), min(until, end)
        if covered_from >= covered_to:
            continue
        if covered_from > cursor:
            tiles.append(Segment(cursor, covered_from, "unknown", 0))
        tiles.append(Segment(covered_from, covered_to, cycle.state, 1))
        cursor = covered_to
    if cursor < end:
        tiles.append(Segment(cursor, end, "unknown", 0))
    return _merge(tiles)


# --- summary ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Window:
    kind: WindowKind
    started_at: datetime
    ended_at: datetime
    duration_seconds: int
    sample_count: int


@dataclass(frozen=True)
class Violation:
    kind: Literal["uptime-below-target"]
    target_pct: float
    actual_pct: float


@dataclass(frozen=True)
class Summary:
    total_seconds: int
    up_seconds: int
    degraded_seconds: int
    down_seconds: int
    unknown_seconds: int
    uptime_pct: float | None
    coverage_pct: float
    outage_count: int
    longest_outage_seconds: int
    cycle_count: int
    windows: tuple[Window, ...]
    windows_truncated: bool
    violations: tuple[Violation, ...]


def _empty_summary() -> Summary:
    """The summary of a zero-length period (the instant a month starts): nothing known, no claim."""
    return Summary(
        total_seconds=0,
        up_seconds=0,
        degraded_seconds=0,
        down_seconds=0,
        unknown_seconds=0,
        uptime_pct=None,
        coverage_pct=0.0,
        outage_count=0,
        longest_outage_seconds=0,
        cycle_count=0,
        windows=(),
        windows_truncated=False,
        violations=(),
    )


def _pct(part: int, whole: int) -> float | None:
    return None if whole == 0 else round(part / whole * 100, 3)


def summarise(
    cycles: Sequence[Cycle],
    start: datetime,
    end: datetime,
    *,
    uptime_target_pct: float | None = None,
    max_windows: int = MAX_WINDOWS,
) -> Summary:
    if start.tzinfo is not None and end.tzinfo is not None and start == end:
        return _empty_summary()
    ordered = _ordered(cycles)
    tiles = segments(ordered, start, end)
    seconds: dict[str, int] = {"up": 0, "degraded": 0, "down": 0, "unknown": 0}
    for tile in tiles:
        seconds[tile.state] += tile.seconds
    total = int((end - start).total_seconds())
    # Whole-second tiles of a window with fractional edges can fall short of the whole-second
    # total: the remainder is time nothing covered, so it is unknown and the parts add up exactly.
    seconds["unknown"] += max(0, total - sum(seconds.values()))
    known = seconds["up"] + seconds["degraded"] + seconds["down"]
    uptime = _pct(seconds["up"] + seconds["degraded"], known)
    windows = tuple(
        Window(tile.state, tile.start, tile.end, tile.seconds, tile.sample_count)
        for tile in tiles
        if tile.state != "up"
    )
    outages = [window for window in windows if window.kind == "down"]
    violations: tuple[Violation, ...] = ()
    if uptime_target_pct is not None and uptime is not None and uptime < uptime_target_pct:
        violations = (Violation("uptime-below-target", uptime_target_pct, uptime),)
    return Summary(
        total_seconds=total,
        up_seconds=seconds["up"],
        degraded_seconds=seconds["degraded"],
        down_seconds=seconds["down"],
        unknown_seconds=seconds["unknown"],
        uptime_pct=uptime,
        coverage_pct=_pct(known, total) or 0.0,
        outage_count=len(outages),
        longest_outage_seconds=max((window.duration_seconds for window in outages), default=0),
        cycle_count=sum(tile.sample_count for tile in tiles),
        windows=windows[:max_windows],
        windows_truncated=len(windows) > max_windows,
        violations=violations,
    )


@dataclass(frozen=True)
class Outage:
    started_at: datetime
    duration_seconds: int


def current_outage(cycles: Sequence[Cycle], now: datetime) -> Outage | None:
    """The outage in progress at ``now``: only while the newest cycle is down *and* still current.

    A collector that has gone quiet leaves the outage unknown: once the newest cycle's coverage
    has lapsed nothing is claimed about the present.
    """
    ordered = [cycle for cycle in _ordered(cycles) if cycle.sampled_at <= now]
    if not ordered or ordered[-1].state != "down":
        return None
    newest = ordered[-1]
    if now >= newest.sampled_at + timedelta(seconds=newest.coverage_seconds):
        return None
    started = newest.sampled_at
    for earlier, later in zip(reversed(ordered[:-1]), reversed(ordered[1:]), strict=True):
        contiguous = later.sampled_at - earlier.sampled_at <= timedelta(
            seconds=earlier.coverage_seconds
        )
        if earlier.state != "down" or not contiguous:
            break
        started = earlier.sampled_at
    return Outage(started, int((now - started).total_seconds()))


# --- quality ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Quality:
    sample_count: int
    latency_ms: float | None
    jitter_ms: float | None
    loss_pct: float | None
    dns_status: SampleOutcome | None
    dns_latency_ms: float | None


def quality(rows: Iterable[tuple[datetime, Sample]]) -> Quality:
    """Latency, jitter and loss from reachability samples; the newest DNS sample separately.

    Latency is the mean over passing samples that carry one; jitter is the mean absolute
    difference between consecutive latencies of the same target (``None`` without a pair); loss is
    failed over passed-plus-failed (unknown samples are neither). Nothing is ever a zero by default.
    """
    ordered = sorted(rows, key=lambda row: row[0])
    reach = [(when, sample) for when, sample in ordered if sample.probe in REACHABILITY_PROBES]
    passes = sum(1 for _, sample in reach if sample.outcome == "pass")
    fails = sum(1 for _, sample in reach if sample.outcome == "fail")
    latencies = [
        sample.latency_ms
        for _, sample in reach
        if sample.outcome == "pass" and sample.latency_ms is not None
    ]
    series: dict[tuple[str, str], list[float]] = {}
    for _, sample in reach:
        if sample.outcome == "pass" and sample.latency_ms is not None:
            series.setdefault((sample.probe, sample.target), []).append(sample.latency_ms)
    steps = [abs(b - a) for values in series.values() for a, b in pairwise(values)]
    dns = [sample for _, sample in ordered if sample.probe == DNS_PROBE]
    newest_dns = dns[-1] if dns else None
    return Quality(
        sample_count=len(reach),
        latency_ms=round(sum(latencies) / len(latencies), 3) if latencies else None,
        jitter_ms=round(sum(steps) / len(steps), 3) if steps else None,
        loss_pct=_pct(fails, passes + fails),
        dns_status=None if newest_dns is None else newest_dns.outcome,
        dns_latency_ms=None if newest_dns is None else newest_dns.latency_ms,
    )


# --- months -------------------------------------------------------------------------------------


def month_window(month: str, now: datetime) -> tuple[datetime, datetime]:
    """UTC calendar month ``YYYY-MM`` as ``[start, end)``, clipped to ``now`` for the current month.

    Server-bounded: the current month back to ``MAX_MONTHS_BACK`` months ago; anything else is a
    ``ValueError`` (HTTP 422), never a silent substitute.
    """
    match = _MONTH.fullmatch(month)
    if match is None:
        raise ValueError("month must be YYYY-MM")
    year, number = int(match.group(1)), int(match.group(2))
    if not 1 <= number <= 12:
        raise ValueError("month must be YYYY-MM")
    current = now.astimezone(UTC)
    index = year * 12 + number - 1
    now_index = current.year * 12 + current.month - 1
    if index > now_index or index < now_index - MAX_MONTHS_BACK:
        raise ValueError("month is outside the supported range")
    start = datetime(year, number, 1, tzinfo=UTC)
    return start, min(month_calendar_end(month), current)


def month_calendar_end(month: str) -> datetime:
    """The first instant after UTC calendar month ``YYYY-MM`` (not clipped to any clock)."""
    match = _MONTH.fullmatch(month)
    if match is None:
        raise ValueError("month must be YYYY-MM")
    year, number = int(match.group(1)), int(match.group(2))
    return datetime(year + (number == 12), number % 12 + 1, 1, tzinfo=UTC)
