"""Identity correlation as a read service: bounded evidence in, honest views out (Step 6c).

**Compute on read, not stored.** Correlations are derived from evidence the sources already hold
(DATABASE-OWNERSHIP: no second telemetry lake), so nothing here writes to PostgreSQL. A request
gathers a bounded snapshot (at most ``MAX_RECORDS`` records, each source asked for at most
``PER_SOURCE_LIMIT`` for a window of ``EVIDENCE_LOOKBACK``), runs the pure engine and maps the
result. A snapshot for "now" is cached for ``CACHE_TTL_SECONDS`` so a search box cannot hammer the
upstream systems; a question about a past time is never cached. See IDENTITY-CORRELATION.md for
what this does not give (history beyond the sources' own retention) and the decision it needs.

Failure is explicit: an unconfigured source is ``not-connected``, a source that errors, stalls,
returns too much, impersonates another source or emits a kind it is not declared for is
``unknown`` and contributes nothing. Silence from a failed source is reported as
``source-unavailable``, never as "no evidence".
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal, Protocol

from netsight_api import schemas_identity as api
from netsight_api.identity import api_models
from netsight_api.identity.engine import MAX_RECORDS, CorrelationIndex
from netsight_api.identity.model import (
    CorrelationPolicy,
    EntityRef,
    EvidenceKind,
    EvidenceRecord,
    PersonSummary,
    PersonView,
    Reason,
    Resolution,
    hostname_ref,
    ip_ref,
    mac_ref,
)
from netsight_api.identity.sources import EvidenceBatch, SourceSlot
from netsight_api.schemas import Freshness, SecurityEvent, TrafficItem

_LOGGER = logging.getLogger("netsight_api")

EVIDENCE_LOOKBACK = timedelta(hours=24)
SOURCE_TIMEOUT_SECONDS = 15.0
PER_SOURCE_LIMIT = 2500
CACHE_TTL_SECONDS = 30.0
TRAFFIC_WINDOW = timedelta(hours=1)
TRAFFIC_TOP_N = 100
MAX_TRAFFIC_ADDRESSES = 16
SECURITY_READ_LIMIT = 500
MAX_SECURITY_ITEMS = 20
FRESH_THRESHOLD = timedelta(hours=1)
MAX_PROFILE_LINKS = 50

SourceState = Literal["not-connected", "unknown", "ok"]


class TrafficReader(Protocol):
    async def top(
        self, *, dimension: Any, start: datetime, end: datetime, limit: int
    ) -> tuple[list[TrafficItem], datetime | None]: ...


class SecurityReader(Protocol):
    async def events(
        self, *, start: datetime, end: datetime, limit: int
    ) -> tuple[list[SecurityEvent], datetime | None]: ...


MAX_RESOLUTIONS = 500


@dataclass(frozen=True)
class ManyResolutions:
    """Answers for a batch of (address, time) questions against one snapshot.

    ``as_of`` is the snapshot's end, ``None`` unless ``state`` is ``ok``. A question whose time
    precedes the evidence window maps to ``None``: the sources were not asked about that time, so
    "no evidence" would be a false statement.
    """

    state: SourceState
    as_of: datetime | None
    resolutions: dict[tuple[str, datetime], Resolution | None]


@dataclass(frozen=True)
class SourceReport:
    name: str
    state: SourceState
    record_count: int
    newest_observed_at: datetime | None
    # Rows the adapter could not use and skipped (logged with this count; the source stays `ok`).
    skipped: int = 0


@dataclass(frozen=True)
class Snapshot:
    index: CorrelationIndex
    reports: tuple[SourceReport, ...]
    start: datetime
    end: datetime
    # The people computation, started once per snapshot and shared by every request that reads it.
    # A mutable holder inside a frozen value: it is a memo, not state anyone may depend on.
    memo: dict[str, asyncio.Task[list[PersonSummary]]] = field(
        default_factory=dict, compare=False, repr=False
    )

    @property
    def state(self) -> SourceState:
        states = {report.state for report in self.reports}
        if "ok" in states:
            return "ok"
        return "unknown" if "unknown" in states else "not-connected"

    @property
    def degraded(self) -> bool:
        return any(report.state == "unknown" for report in self.reports)


def _fail(name: str, error: BaseException) -> SourceReport:
    _LOGGER.warning(
        "identity source read failed",
        extra={"source": name, "error_type": type(error).__name__},
    )
    return SourceReport(name, "unknown", 0, None)


def _checked(slot: SourceSlot, batch: EvidenceBatch, limit: int) -> tuple[EvidenceRecord, ...]:
    """Refuse a batch that is partial, oversized or not the source's own."""
    source = slot.source
    assert source is not None
    if batch.truncated or len(batch.records) > limit:
        raise ValueError("the source returned more than it was asked for")
    for record in batch.records:
        if (
            not isinstance(record, EvidenceRecord)
            or record.source != slot.name
            or record.kind not in source.kinds
        ):
            raise ValueError("the source emitted a record that is not its own")
    return batch.records


async def _read(
    slot: SourceSlot, start: datetime, end: datetime, limit: int, timeout: float
) -> tuple[SourceReport, tuple[EvidenceRecord, ...]]:
    if slot.source is None:
        return SourceReport(slot.name, "not-connected", 0, None), ()
    try:
        batch = await asyncio.wait_for(
            slot.source.fetch(start=start, end=end, limit=limit), timeout=timeout
        )
        records = _checked(slot, batch, limit)
    except Exception as error:  # noqa: BLE001 - the source boundary: any failure is `unknown`
        return _fail(slot.name, error), ()
    newest = max((record.observed_at for record in records), default=None)
    if batch.skipped:
        _LOGGER.warning(
            "identity source rows skipped",
            extra={"source": slot.name, "skipped_rows": batch.skipped},
        )
    return SourceReport(slot.name, "ok", len(records), newest, batch.skipped), records


async def gather(
    slots: Sequence[SourceSlot],
    policy: CorrelationPolicy,
    *,
    start: datetime,
    end: datetime,
    per_source_limit: int = PER_SOURCE_LIMIT,
    timeout: float = SOURCE_TIMEOUT_SECONDS,
) -> Snapshot:
    results = await asyncio.gather(
        *(_read(slot, start, end, per_source_limit, timeout) for slot in slots)
    )
    reports: list[SourceReport] = []
    records: list[EvidenceRecord] = []
    for report, batch in results:
        if report.state == "ok" and len(records) + len(batch) > MAX_RECORDS:
            # Over the bound: refuse the source rather than keep a partial list of its evidence.
            _LOGGER.warning("identity evidence bound exceeded", extra={"source": report.name})
            report = SourceReport(report.name, "unknown", 0, None)
            batch = ()
        reports.append(report)
        records.extend(batch)
    # Building the index sorts and indexes up to MAX_RECORDS records: not on the event loop.
    index = await asyncio.to_thread(CorrelationIndex, records, policy)
    return Snapshot(index, tuple(reports), start, end)


class SnapshotCache:
    """One short-lived snapshot for "now", shared by concurrent requests."""

    def __init__(
        self, ttl_seconds: float = CACHE_TTL_SECONDS, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._ttl = ttl_seconds
        self._clock = clock
        self._entry: tuple[str, float, Snapshot] | None = None
        self._lock: asyncio.Lock | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    def _lock_here(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._lock is None or self._loop is not loop:
            self._lock, self._loop = asyncio.Lock(), loop
        return self._lock

    async def get(self, key: str, load: Callable[[], Awaitable[Snapshot]]) -> Snapshot:
        async with self._lock_here():
            now = self._clock()
            if self._entry is not None:
                cached_key, taken, snapshot = self._entry
                if cached_key == key and 0 <= now - taken < self._ttl:
                    return snapshot
            snapshot = await load()
            self._entry = (key, self._clock(), snapshot)
            return snapshot


def canonical_subject(kind: str, value: str) -> EntityRef:
    """The subject of a resolve question as an entity; ``ValueError`` when it is not one."""
    if kind == "ip":
        return ip_ref(value)
    if kind == "mac":
        return mac_ref(value)
    if kind == "hostname":
        return hostname_ref(value)
    raise ValueError("the subject is an ip, a mac or a hostname")


def _freshness(report: SourceReport, now: datetime) -> Freshness:
    if report.state != "ok":
        return Freshness(state="unknown", observed_at=None, source=None)
    if report.newest_observed_at is None:
        return Freshness(state="unknown", observed_at=None, source=report.name)
    fresh = report.newest_observed_at >= now - FRESH_THRESHOLD
    return Freshness(
        state="fresh" if fresh else "stale",
        observed_at=report.newest_observed_at,
        source=report.name,
    )


class IdentityService:
    def __init__(
        self,
        slots: Sequence[SourceSlot],
        policy: CorrelationPolicy,
        *,
        cache: SnapshotCache | None = None,
        per_source_limit: int = PER_SOURCE_LIMIT,
        source_timeout_seconds: float = SOURCE_TIMEOUT_SECONDS,
    ) -> None:
        self._slots = tuple(slots)
        self._policy = policy
        self._cache = cache
        self._per_source_limit = per_source_limit
        self._timeout = source_timeout_seconds

    async def _snapshot(self, now: datetime, at: datetime | None) -> Snapshot:
        end = now if at is None else at
        start = end - EVIDENCE_LOOKBACK

        async def load() -> Snapshot:
            return await gather(
                self._slots,
                self._policy,
                start=start,
                end=end,
                per_source_limit=self._per_source_limit,
                timeout=self._timeout,
            )

        if at is None and self._cache is not None:
            key = "|".join(f"{slot.name}:{slot.source is not None}" for slot in self._slots)
            return await self._cache.get(key, load)
        return await load()

    # --- shared pieces -------------------------------------------------------------------------

    @staticmethod
    async def _people(snapshot: Snapshot) -> list[PersonSummary]:
        """Everyone known as of the snapshot, computed once and off the event loop.

        Walking every person is the heaviest thing this service does; concurrent and repeated
        list/summary requests for one snapshot share a single run in a worker thread. A failed run
        is forgotten so the next request retries instead of replaying the failure.
        """
        loop = asyncio.get_running_loop()
        task = snapshot.memo.get("people")
        if task is None or task.get_loop() is not loop:
            task = loop.create_task(asyncio.to_thread(snapshot.index.people, snapshot.end))
            snapshot.memo["people"] = task
        try:
            return await asyncio.shield(task)
        except BaseException:
            if task.done() and snapshot.memo.get("people") is task:
                snapshot.memo.pop("people", None)
            raise

    @staticmethod
    def _window(snapshot: Snapshot) -> api.TimeWindow:
        return api.TimeWindow(**{"from": snapshot.start, "to": snapshot.end})

    @staticmethod
    def _sources(snapshot: Snapshot) -> list[api.SourceStatus]:
        return [
            api.SourceStatus(
                source=report.name,
                state=report.state,
                record_count=report.record_count,
                truncated=False,
                freshness=_freshness(report, snapshot.end),
            )
            for report in snapshot.reports
        ]

    # --- GET /users --------------------------------------------------------------------------------

    async def list_users(self, now: datetime, *, page: int, page_size: int) -> api.UserListResponse:
        snapshot = await self._snapshot(now, None)
        items: list[api.UserSummary] = []
        total = 0
        if snapshot.state == "ok":
            people = sorted(
                await self._people(snapshot),
                key=lambda p: ((p.person.label or "").lower(), p.person.id),
            )
            total = len(people)
            first = (page - 1) * page_size
            items = [
                api.UserSummary(
                    id=p.person.id,
                    display_name=p.person.label,
                    account_count=min(p.account_count, 1000),
                    assigned_device_count=min(p.assigned_device_count, 1000),
                    session_count=min(p.session_count, 1000),
                    presence=p.presence.value,
                    last_evidence_at=p.last_evidence_at,
                )
                for p in people[first : first + page_size]
            ]
        return api.UserListResponse(
            state=snapshot.state,
            as_of=snapshot.end,
            window=self._window(snapshot),
            sources=self._sources(snapshot),
            items=items,
            page=page,
            page_size=page_size,
            total=total,
        )

    # --- GET /users/summary ---------------------------------------------------------------------------

    async def summary(self, now: datetime) -> api.UsersAggregateResponse:
        snapshot = await self._snapshot(now, None)
        counts: dict[str, int | None] = dict.fromkeys(
            (
                "people_total",
                "with_observed_session",
                "with_inferred_session",
                "without_session_evidence",
                "vpn_sessions",
            )
        )
        if snapshot.state == "ok":
            people = await self._people(snapshot)
            observed = sum(1 for p in people if p.presence.value == "observed")
            inferred = sum(1 for p in people if p.presence.value == "inferred")
            counts = {
                "people_total": len(people),
                "with_observed_session": observed,
                "with_inferred_session": inferred,
                "without_session_evidence": len(people) - observed - inferred,
                "vpn_sessions": sum(p.vpn_session_count for p in people),
            }
        return api.UsersAggregateResponse(
            state=snapshot.state,
            as_of=snapshot.end,
            window=self._window(snapshot),
            sources=self._sources(snapshot),
            **counts,
        )

    # --- GET /identity/resolve --------------------------------------------------------------------------

    async def resolve(
        self,
        now: datetime,
        at: datetime | None,
        kind: str,
        value: str,
        *,
        redact_person: bool,
    ) -> api.ResolveResponse:
        subject = canonical_subject(kind, value)
        as_of = now if at is None else at
        snapshot = await self._snapshot(now, at)
        attribution = api_models.unattributed(Reason.SOURCE_UNAVAILABLE)
        endpoint: list[api.IdentityLink] = []
        if snapshot.state == "ok":
            result = snapshot.index.resolve(subject, as_of, degraded=snapshot.degraded)
            attribution = (
                api_models.restricted_attribution()
                if redact_person
                else api_models.attribution(result.attribution)
            )
            endpoint = [api_models.link(item, opaque=redact_person) for item in result.endpoint]
        return api.ResolveResponse(
            state=snapshot.state,
            subject=api.ResolveSubject(kind=kind, value=subject.id),  # type: ignore[arg-type]
            as_of=as_of,
            window=self._window(snapshot),
            sources=self._sources(snapshot),
            attribution=attribution,
            endpoint=endpoint,
            notes=self._notes(snapshot, at),
        )

    async def resolve_many(
        self, now: datetime, questions: Sequence[tuple[str, datetime]]
    ) -> ManyResolutions:
        """Who is behind each address at each time, from one shared snapshot of "now".

        Unparseable addresses are left out of the answer. Bounded to ``MAX_RESOLUTIONS`` distinct
        questions; the work runs in a worker thread so a large batch never blocks the event loop.
        """
        distinct = list(dict.fromkeys(questions))
        if len(distinct) > MAX_RESOLUTIONS:
            raise ValueError("too many questions in one batch")
        snapshot = await self._snapshot(now, None)
        if snapshot.state != "ok":
            return ManyResolutions(snapshot.state, None, {})

        def work() -> dict[tuple[str, datetime], Resolution | None]:
            answers: dict[tuple[str, datetime], Resolution | None] = {}
            for text, moment in distinct:
                try:
                    subject = ip_ref(text)
                except ValueError:
                    continue
                if moment < snapshot.start:
                    answers[(text, moment)] = None
                    continue
                at = min(moment, snapshot.end)
                answers[(text, moment)] = snapshot.index.resolve(
                    subject, at, degraded=snapshot.degraded
                )
            return answers

        return ManyResolutions(snapshot.state, snapshot.end, await asyncio.to_thread(work))

    @staticmethod
    def _notes(snapshot: Snapshot, at: datetime | None) -> list[api.ResolveNote]:
        """A past-time answer that leans on the register must say the register is current state.

        NetBox answers with what is assigned now and does not say when an assignment was deleted,
        so for an earlier instant it can show an owner who was not yet (or no longer) the owner.
        """
        if at is not None and snapshot.index.has_kind(EvidenceKind.ASSET_ASSIGNMENT):
            return ["register-is-current-state"]
        return []

    # --- GET /users/{id} ------------------------------------------------------------------------------------

    async def user_detail(
        self,
        now: datetime,
        person_id: str,
        *,
        traffic: TrafficReader | None,
        security: SecurityReader | None,
    ) -> api.UserDetailResponse | None:
        snapshot = await self._snapshot(now, None)
        window, sources = self._window(snapshot), self._sources(snapshot)
        if snapshot.state != "ok":
            return api.UserDetailResponse(
                state=snapshot.state,
                as_of=now,
                window=window,
                sources=sources,
                user=None,
                traffic=None,
                security=None,
            )
        view = snapshot.index.person_view(person_id, now)
        if view is None:
            return None
        profile = api.UserProfile(
            id=view.person.id,
            display_name=view.person.label,
            accounts=[api_models.link(x) for x in view.accounts[:MAX_PROFILE_LINKS]],
            assigned_devices=[
                api_models.link(x) for x in view.assigned_devices[:MAX_PROFILE_LINKS]
            ],
            sessions=[api_models.session(x) for x in view.sessions[:MAX_PROFILE_LINKS]],
        )
        return api.UserDetailResponse(
            state="ok",
            as_of=now,
            window=window,
            sources=sources,
            user=profile,
            traffic=await self._traffic(snapshot, view, now, traffic),
            security=await self._security(snapshot, view, security),
        )

    @staticmethod
    def _addresses(view: PersonView) -> list[str]:
        found = {
            entity.id
            for session in view.sessions
            for item in session.links
            for entity in (item.source, item.target)
            if entity is not None and entity.type.value == "ip"
        }
        return sorted(found)[:MAX_TRAFFIC_ADDRESSES]

    async def _traffic(
        self, snapshot: Snapshot, view: PersonView, now: datetime, source: TrafficReader | None
    ) -> api.UserTraffic:
        if source is None:
            return api.UserTraffic(
                state="not-connected", basis="unknown", window=None, top_n=0, items=[]
            )
        window = api.TimeWindow(**{"from": now - TRAFFIC_WINDOW, "to": now})
        # Only addresses the person is still attributed to; and the whole window is covered only if
        # the chain held since before it started (a link's window is contiguous around "now").
        covered: dict[str, bool] = {}
        for address in self._addresses(view):
            result = snapshot.index.resolve(ip_ref(address), now)
            mine = [
                link
                for link in result.attribution.links
                if link.target is not None and link.target.id == view.person.id
            ]
            if mine and mine[0].valid_from is not None:
                covered[address] = mine[0].valid_from <= window.from_
        if not covered:
            return api.UserTraffic(state="ok", basis="inferred", window=window, top_n=0, items=[])
        try:
            rows, _ = await source.top(
                dimension="talkers", start=window.from_, end=window.to, limit=TRAFFIC_TOP_N
            )
        except Exception as error:  # noqa: BLE001 - the traffic source boundary
            _fail("traffic", error)
            return api.UserTraffic(state="unknown", basis="unknown", window=None, top_n=0, items=[])
        listed: dict[str, int] = {}
        for row in rows:
            if row.subject_kind == "ip":
                try:
                    listed[ip_ref(row.label).id] = listed.get(ip_ref(row.label).id, 0) + row.bytes
                except ValueError:
                    continue
        items = [
            api.UserTrafficItem(
                address=address,
                bytes=listed.get(address) if holds else None,
                covers_window=holds,
            )
            for address, holds in sorted(covered.items())
        ]
        return api.UserTraffic(
            state="ok", basis="inferred", window=window, top_n=TRAFFIC_TOP_N, items=items
        )

    async def _security(
        self, snapshot: Snapshot, view: PersonView, source: SecurityReader | None
    ) -> api.UserSecurity:
        if source is None:
            return api.UserSecurity(state="not-connected", window=None, items=[], truncated=False)
        try:
            events, _ = await source.events(
                start=snapshot.start, end=snapshot.end, limit=SECURITY_READ_LIMIT
            )
        except Exception as error:  # noqa: BLE001 - the security source boundary
            _fail("security", error)
            return api.UserSecurity(state="unknown", window=None, items=[], truncated=False)
        items: list[api.UserSecurityItem] = []
        truncated = False
        ordered = sorted(events, key=lambda e: (-e.observed_at.timestamp(), e.id))
        for item in ordered:
            matched = self._attribute_event(snapshot, view.person, item)
            if matched is None:
                continue
            if len(items) == MAX_SECURITY_ITEMS:
                truncated = True
                break
            items.append(matched)
        return api.UserSecurity(
            state="ok", window=self._window(snapshot), items=items, truncated=truncated
        )

    @staticmethod
    def _attribute_event(
        snapshot: Snapshot, person: EntityRef, event: SecurityEvent
    ) -> api.UserSecurityItem | None:
        """The event, if an address in it belonged to ``person`` when the event happened."""
        if not snapshot.start <= event.observed_at < snapshot.end:
            return None
        for text in (event.source_ip, event.destination_ip):
            if text is None:
                continue
            try:
                address = ip_ref(text)
            except ValueError:
                continue
            if not snapshot.index.knows(address):
                continue
            attribution = snapshot.index.resolve(address, event.observed_at).attribution
            for link in attribution.links:
                if link.target is not None and link.target.id == person.id:
                    return api.UserSecurityItem(
                        event_id=event.id,
                        observed_at=event.observed_at,
                        severity=event.severity,
                        signature=event.signature,
                        address=address.id,
                        link=api_models.link(link),
                    )
        return None
