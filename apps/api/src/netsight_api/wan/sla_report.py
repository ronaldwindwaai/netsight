"""Monthly SLA figures and the ISP-dispute evidence export, assembled from stored cycles.

All arithmetic lives in ``wan.sla`` (pure, deterministic); this module only fetches the stored
cycles for a server-bounded UTC month, applies the operator's uptime target, and shapes the
contracts. Honesty rules:

* no sample store: ``not-connected``; every link unreadable: ``unknown``; one unreadable link is
  that link's ``unknown`` and never hides the others;
* a month with no samples is all-unknown (never up), and a gap in sampling is an ``unknown``
  window with zero probe rounds, never up and never down;
* the instant a month starts is an empty period (zero seconds, nothing known), not an error;
* a closed month (over for ``CLOSED_MONTH_SETTLE_SECONDS``) can no longer change, so its figures
  are computed once and kept in a small in-memory cache; recomputing gives the same result, so the
  cache only saves work. The open month and the settling hour are always recomputed;
* the export carries only what is stored: windows (down, degraded, unknown), the probe, target and
  location behind the samples, and round counts. The ISP name is the operator's declaration.

``export_csv`` writes one row per window with a fixed header, CRLF lines, quoting by the csv
module and a leading apostrophe on any cell a spreadsheet could read as a formula. A link whose
window list was cut gets a trailing ``truncated`` sentinel row, so a truncated file cannot be
mistaken for a complete one.
"""

from __future__ import annotations

import csv
import io
import logging
import threading
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from netsight_api.schemas_internet import (
    ExportLink,
    ExportSource,
    ExportWindow,
    SlaExport,
    SlaLink,
    SlaResponse,
    SlaViolation,
)
from netsight_api.storage.errors import StorageError
from netsight_api.storage.wan import WanSampleRepository
from netsight_api.wan import sla
from netsight_api.wan.config import WanConfig, WanLinkConfig

_LOGGER: Final = logging.getLogger("netsight_api")

MAX_EXPORT_WINDOWS: Final = 2000
# A round that started in the last seconds of a month may be stored a little after it ends.
CLOSED_MONTH_SETTLE_SECONDS: Final = 3600
CACHE_MAX_ENTRIES: Final = 256
TRUNCATED_KIND: Final = "truncated"
BASIS: Final = (
    "Computed only from stored probe samples taken by Netsight (ICMP or TCP reachability rounds). "
    "Each round covers its sampling interval plus half of it; time with no round is unknown and is "
    "never counted as up or down. Uptime counts degraded time as reachable and is taken over known "
    "time only. DNS samples are listed as sources but do not decide reachability. The ISP name is "
    "an operator declaration, not a measurement. This evidence is only as trustworthy as the host "
    "that recorded it: the samples are taken and stored by this Netsight host and are not signed "
    "or independently attested."
)
CSV_COLUMNS: Final = (
    "month",
    "link_id",
    "link_name",
    "isp",
    "kind",
    "started_at",
    "ended_at",
    "duration_seconds",
    "sample_count",
    "sources",
)
_FORMULA_STARTS: Final = ("=", "+", "-", "@", "\t", "\r", "\n")


@dataclass(frozen=True)
class _LinkEvidence:
    summary: sla.Summary
    windows: tuple[sla.Window, ...]
    sources: tuple[ExportSource, ...]


class ClosedMonthCache:
    """Bounded, thread-safe memo of per-link evidence for months that can no longer change.

    Entries are pure functions of immutable stored cycles, so a hit equals a recomputation. The
    oldest entry is evicted first. Nothing failed or partial is ever stored.
    """

    def __init__(self, max_entries: int = CACHE_MAX_ENTRIES) -> None:
        self._max = max_entries
        self._lock = threading.Lock()
        self._items: OrderedDict[tuple[object, ...], _LinkEvidence] = OrderedDict()

    def get(self, key: tuple[object, ...]) -> _LinkEvidence | None:
        with self._lock:
            return self._items.get(key)

    def put(self, key: tuple[object, ...], value: _LinkEvidence) -> None:
        with self._lock:
            self._items[key] = value
            self._items.move_to_end(key)
            while len(self._items) > self._max:
                self._items.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


def _period(month: str, now: datetime) -> tuple[datetime, datetime]:
    """``[start, end)`` of the month, clipped to ``now``; empty at the instant the month starts."""
    return sla.month_window(month, now)


def _is_closed(month: str, now: datetime) -> bool:
    """True once the whole calendar month plus the settling time is in the past."""
    return now >= sla.month_calendar_end(month) + timedelta(seconds=CLOSED_MONTH_SETTLE_SECONDS)


def _read_link(
    link: WanLinkConfig,
    store: WanSampleRepository,
    start: datetime,
    end: datetime,
    *,
    sources: bool,
) -> _LinkEvidence | None:
    if start == end:  # the instant a month starts: nothing to read, nothing known
        summary = sla.summarise([], start, end, uptime_target_pct=link.uptime_target_pct)
        return _LinkEvidence(summary=summary, windows=(), sources=())
    try:
        cycles = store.cycles_between(link.id, start, end)
        summary = sla.summarise(
            cycles,
            start,
            end,
            uptime_target_pct=link.uptime_target_pct,
            max_windows=MAX_EXPORT_WINDOWS,
        )
        found = store.probe_sources(link.id, start, end) if sources else []
    except (StorageError, ValueError, OSError) as error:
        _LOGGER.warning(
            "WAN SLA read failed",
            extra={"link_id": link.id, "error_type": type(error).__name__},
        )
        return None
    return _LinkEvidence(
        summary=summary,
        windows=summary.windows,
        sources=tuple(
            ExportSource(probe=s.probe, target=s.target, location=s.location)  # type: ignore[arg-type]
            for s in found
        ),
    )


def _sla_link(link: WanLinkConfig, evidence: _LinkEvidence | None) -> SlaLink:
    if evidence is None:
        return SlaLink(
            link_id=link.id,
            name=link.name,
            state="unknown",
            uptime_target_pct=link.uptime_target_pct,
            total_seconds=None,
            up_seconds=None,
            degraded_seconds=None,
            down_seconds=None,
            unknown_seconds=None,
            uptime_pct=None,
            coverage_pct=None,
            outage_count=None,
            longest_outage_seconds=None,
            cycle_count=None,
            windows_truncated=None,
            violations=[],
        )
    s = evidence.summary
    return SlaLink(
        link_id=link.id,
        name=link.name,
        state="ok",
        uptime_target_pct=link.uptime_target_pct,
        total_seconds=s.total_seconds,
        up_seconds=s.up_seconds,
        degraded_seconds=s.degraded_seconds,
        down_seconds=s.down_seconds,
        unknown_seconds=s.unknown_seconds,
        uptime_pct=s.uptime_pct,
        coverage_pct=s.coverage_pct,
        outage_count=s.outage_count,
        longest_outage_seconds=s.longest_outage_seconds,
        cycle_count=s.cycle_count,
        windows_truncated=s.windows_truncated,
        violations=[
            SlaViolation(kind=v.kind, target_pct=v.target_pct, actual_pct=v.actual_pct)
            for v in s.violations
        ],
    )


def _link_evidence(
    link: WanLinkConfig,
    store: WanSampleRepository,
    period: tuple[datetime, datetime],
    month: str,
    now: datetime,
    *,
    sources: bool,
    cache: ClosedMonthCache | None,
) -> _LinkEvidence | None:
    if cache is None or not _is_closed(month, now):
        return _read_link(link, store, *period, sources=sources)
    key = (link.id, month, link.uptime_target_pct, sources, MAX_EXPORT_WINDOWS)
    hit = cache.get(key)
    if hit is not None:
        return hit
    evidence = _read_link(link, store, *period, sources=sources)
    if evidence is not None:
        cache.put(key, evidence)
    return evidence


def _evidence(
    config: WanConfig,
    store: WanSampleRepository | None,
    month: str,
    now: datetime,
    *,
    sources: bool,
    cache: ClosedMonthCache | None,
) -> tuple[str, tuple[datetime, datetime] | None, list[tuple[WanLinkConfig, _LinkEvidence | None]]]:
    """``(state, period, per-link evidence)``; the validated month is checked even when empty."""
    period = _period(month, now)
    if config.state != "ok":
        return config.state, None, []
    if store is None:
        return "not-connected", None, []
    read = [
        (link, _link_evidence(link, store, period, month, now, sources=sources, cache=cache))
        for link in config.links
    ]
    if all(evidence is None for _, evidence in read):
        return "unknown", None, []
    return "ok", period, read


def build_sla(
    config: WanConfig,
    store: WanSampleRepository | None,
    month: str,
    now: datetime,
    *,
    cache: ClosedMonthCache | None = None,
) -> SlaResponse:
    state, period, read = _evidence(config, store, month, now, sources=False, cache=cache)
    return SlaResponse(
        state=state,  # type: ignore[arg-type]
        month=month,
        period_start=None if period is None else period[0],
        period_end=None if period is None else period[1],
        generated_at=now,
        links=[_sla_link(link, evidence) for link, evidence in read],
    )


def _export_link(
    link: WanLinkConfig, evidence: _LinkEvidence | None, *, detail: bool
) -> ExportLink:
    summary_link = _sla_link(link, evidence)
    isp = link.isp if detail else None
    if evidence is None:
        return ExportLink(
            link=summary_link, isp=isp, sources=[], windows=[], windows_truncated=False
        )
    return ExportLink(
        link=summary_link,
        isp=isp,
        sources=list(evidence.sources),
        windows=[
            ExportWindow(
                kind=w.kind,
                started_at=w.started_at,
                ended_at=w.ended_at,
                duration_seconds=w.duration_seconds,
                sample_count=w.sample_count,
            )
            for w in evidence.windows
        ],
        windows_truncated=evidence.summary.windows_truncated,
    )


def build_export(
    config: WanConfig,
    store: WanSampleRepository | None,
    month: str,
    now: datetime,
    *,
    detail: bool = False,
    cache: ClosedMonthCache | None = None,
) -> SlaExport:
    """The evidence export. ``detail`` is the caller's ``internet:read_detail``: without it (the
    fail-closed default) the operator-declared ISP name is withheld."""
    state, period, read = _evidence(config, store, month, now, sources=True, cache=cache)
    return SlaExport(
        state=state,  # type: ignore[arg-type]
        month=month,
        period_start=None if period is None else period[0],
        period_end=None if period is None else period[1],
        generated_at=now,
        basis=BASIS,
        detail_redacted=not detail,
        links=[_export_link(link, evidence, detail=detail) for link, evidence in read],
    )


# --- CSV ----------------------------------------------------------------------------------------


def _stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_cell(value: str) -> str:
    """Neutralise a cell a spreadsheet would execute as a formula (OWASP CSV injection)."""
    return "'" + value if value.startswith(_FORMULA_STARTS) else value


def _sources_cell(sources: Sequence[ExportSource]) -> str:
    return ";".join(
        f"{s.probe}:{s.target}" + ("" if s.location is None else f"@{s.location}") for s in sources
    )


def export_csv(export: SlaExport) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for item in export.links:
        if item.link.state != "ok":
            continue
        cells = (
            export.month,
            item.link.link_id,
            _safe_cell(item.link.name),
            _safe_cell(item.isp or ""),
        )
        sources = _sources_cell(item.sources)
        for window in item.windows:
            writer.writerow(
                (
                    *cells,
                    window.kind,
                    _stamp(window.started_at),
                    _stamp(window.ended_at),
                    window.duration_seconds,
                    window.sample_count,
                    _safe_cell(sources),
                )
            )
    _write_truncation_sentinels(writer, export)
    return out.getvalue()


def _write_truncation_sentinels(writer: Any, export: SlaExport) -> None:
    """One trailing row per link whose window list was cut, so the file cannot pass as complete."""
    note = (
        f"EXPORT INCOMPLETE: this link has more than {MAX_EXPORT_WINDOWS} windows and the rest "
        "are omitted; the monthly SLA figures are complete"
    )
    for item in export.links:
        if item.link.state == "ok" and item.windows_truncated:
            writer.writerow(
                (
                    export.month,
                    item.link.link_id,
                    _safe_cell(item.link.name),
                    _safe_cell(item.isp or ""),
                    TRUNCATED_KIND,
                    "",
                    "",
                    "",
                    "",
                    note,
                )
            )
