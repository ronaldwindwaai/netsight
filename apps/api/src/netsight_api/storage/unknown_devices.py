"""Unknown-device finding store (Step 8c): the Protocol, the shared rules and the in-memory store.

Findings are Netsight application state (DATABASE-OWNERSHIP): what telemetry saw that NetBox does
not know, with the evidence chain captured at detection, and the lifecycle people move it through
(new, acknowledged, investigating, resolved, false-positive). NetBox is never written to.

* ``observe`` is the scanner's write: it creates a finding, refreshes an open one, or is suppressed
  by an earlier false-positive. A quiet endpoint seen again costs a counter and a time; a change in
  what is known about it (a hop observed, the severity moved) is an ``evidence-updated`` event, at
  most one an hour unless the severity, the proposal or NetBox's verdict changed. After a resolution
  (or an expired dismissal) a new sighting is a *new* finding that points at the old one.
* **Identity.** The MAC is authoritative; a finding is stored under one key but a sighting is matched
  against every key of its endpoint (``model.lookup_keys``), so a dismissal on a MAC also suppresses
  the address and the other way round. Two MACs are two endpoints even at one address.
* A dismissal (false-positive) expires after ``fp_ttl`` (``NETSIGHT_UNKNOWN_DEVICE_FP_TTL_DAYS``,
  default 90): the next sighting is a new finding, so the decision is reviewed. While it holds, a
  sighting with different evidence leaves a ``suppressed-sighting`` event, at most one a day.
* The lifecycle is the fixed table in ``schemas_unknown_devices.ALLOWED_TRANSITIONS``. A write that
  decides on what the person saw quotes the finding's ``evidence_version`` (it moves only when the
  evidence does, not on every sighting) and loses with ``StaleEvidenceError`` (HTTP 409) otherwise.
  The state machine is the second optimistic check: a transition is applied under a row lock only
  from a state it is legal from, so the loser of a race gets ``IllegalTransitionError`` (HTTP 409).
* The timeline is append-only. Free text (reasons, comments) is stored and returned verbatim as data.
* Reads are bounded: a page is capped, an offset is capped and so is a timeline page.

The shared pure rules live here so the in-memory fake and the PostgreSQL store cannot disagree.
"""

from __future__ import annotations

import threading
import uuid
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Literal, Protocol

from netsight_api.schemas_unknown_devices import (
    ALLOWED_TRANSITIONS,
    FINAL_STATES,
    MAX_COMMENT,
    MAX_COUNT,
    MAX_PAGE_SIZE,
    MAX_REASON,
    MAX_TIMELINE_PAGE,
    OPEN_STATES,
    SYSTEM_ACTOR,
    FindingState,
    Severity,
    UnknownDeviceCounts,
    UnknownDeviceEvent,
    UnknownDeviceFinding,
    UnknownDeviceSeverityCount,
    UnknownDeviceStateCount,
)
from netsight_api.storage import lifecycle
from netsight_api.storage.errors import (
    IllegalTransitionError,
    InvalidOperationError,
    NotFoundError,
    StaleEvidenceError,
)
from netsight_api.unknown_devices.model import (
    Detection,
    finding_fingerprint,
    finding_significance,
    same_endpoint,
)

FINDING_PREFIX: Final = "unknown-device"
EVENT_PREFIX: Final = "unknown-device-event"
MAX_ASSIGNEE: Final = 255
# A page of findings is reached by an offset, which PostgreSQL pays for by reading and discarding
# every earlier row; past this the caller narrows the filter instead (a keyset cursor would need a
# different contract: the pages and the total are part of it).
MAX_OFFSET: Final = 10_000
SNAPSHOT_MIN_INTERVAL: Final = timedelta(hours=1)
SIGHTING_MIN_INTERVAL: Final = timedelta(days=1)
FP_TTL_ENV: Final = "NETSIGHT_UNKNOWN_DEVICE_FP_TTL_DAYS"
DEFAULT_FP_TTL: Final = timedelta(days=90)
MIN_FP_TTL_DAYS: Final = 1
MAX_FP_TTL_DAYS: Final = 3650
_STATE_ORDER: Final[tuple[FindingState, ...]] = (
    "new",
    "acknowledged",
    "investigating",
    "resolved",
    "false-positive",
)
_SEVERITY_ORDER: Final[tuple[Severity, ...]] = ("low", "medium", "high", "critical", "unknown")


@dataclass(frozen=True)
class Observation:
    """What an observation did: made a finding, refreshed an open one, or was suppressed."""

    outcome: Literal["created", "refreshed", "suppressed"]
    finding_id: str


class UnknownDeviceRepository(Protocol):
    def observe(self, detection: Detection) -> Observation: ...

    def known_subject_keys(self, keys: Sequence[str]) -> set[str]:
        """Which of ``keys`` (``mac:...``, ``ip:...``) already have a finding, whatever its state."""
        ...

    def get_finding(self, finding_id: str) -> UnknownDeviceFinding | None: ...

    def list_findings(
        self,
        *,
        states: Sequence[FindingState] | None = None,
        severity: Severity | None = None,
        assigned: bool | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> tuple[list[UnknownDeviceFinding], int]:
        """Newest sighting first; the total is the number of matches, not of this page."""
        ...

    def counts(self) -> UnknownDeviceCounts: ...

    def list_timeline(
        self, finding_id: str, *, after_seq: int = 0, limit: int = 200
    ) -> list[UnknownDeviceEvent]: ...

    def transition_state(
        self,
        finding_id: str,
        *,
        to_state: FindingState,
        actor_id: str,
        expected_evidence_version: int,
        reason: str | None = None,
    ) -> UnknownDeviceFinding: ...

    def set_assignee(
        self,
        finding_id: str,
        *,
        assignee_id: str | None,
        actor_id: str,
        expected_evidence_version: int,
    ) -> UnknownDeviceFinding: ...

    def add_comment(
        self, finding_id: str, *, actor_id: str, message: str
    ) -> UnknownDeviceEvent: ...


# --- shared rules ------------------------------------------------------------------------------------


def fp_ttl_from_env(env: Mapping[str, str]) -> timedelta:
    """The dismissal lifetime: 1 to 3650 whole days (default 90); anything else is refused."""
    raw = env.get(FP_TTL_ENV, "").strip()
    if not raw:
        return DEFAULT_FP_TTL
    if not raw.isascii() or not raw.isdigit() or not MIN_FP_TTL_DAYS <= int(raw) <= MAX_FP_TTL_DAYS:
        raise ValueError(f"{FP_TTL_ENV} must be {MIN_FP_TTL_DAYS} to {MAX_FP_TTL_DAYS} days")
    return timedelta(days=int(raw))


def check_list_args(limit: int, offset: int) -> None:
    lifecycle.check_page(limit, offset, maximum=MAX_PAGE_SIZE)
    if offset > MAX_OFFSET:
        raise ValueError(f"offset must not exceed {MAX_OFFSET}; narrow the filter instead")


def check_states(states: Sequence[FindingState] | None) -> tuple[FindingState, ...] | None:
    """The state filter, proven to be members of the closed set (it is spelled into SQL)."""
    if states is None:
        return None
    for state in states:
        if state not in _STATE_ORDER:
            raise ValueError("unknown state in the filter")
    return tuple(states)


def check_timeline_args(after_seq: int, limit: int) -> None:
    if after_seq < 0:
        raise ValueError("after_seq must not be negative")
    lifecycle.check_page(limit, 0, maximum=MAX_TIMELINE_PAGE)


def check_actor(actor_id: str) -> str:
    if (
        not isinstance(actor_id, str)
        or not 1 <= len(actor_id) <= MAX_ASSIGNEE
        or not actor_id.strip()
    ):
        raise InvalidOperationError(f"an actor is 1 to {MAX_ASSIGNEE} characters")
    return actor_id


def clean_assignee(assignee_id: str | None) -> str | None:
    if assignee_id is None:
        return None
    if (
        not isinstance(assignee_id, str)
        or not assignee_id.strip()
        or len(assignee_id) > MAX_ASSIGNEE
    ):
        raise InvalidOperationError(f"an assignee is 1 to {MAX_ASSIGNEE} non-blank characters")
    return assignee_id


def clean_comment(message: str) -> str:
    if not isinstance(message, str) or not message.strip() or len(message) > MAX_COMMENT:
        raise InvalidOperationError(f"a comment is 1 to {MAX_COMMENT} non-blank characters")
    return message


def check_evidence_version(current: UnknownDeviceFinding, expected: int) -> None:
    """The decision was taken on the evidence the finding still has."""
    if current.evidence_version != expected:
        raise StaleEvidenceError("the evidence changed since it was shown; reload and decide again")


def plan_transition(
    current: FindingState, to_state: FindingState, reason: str | None
) -> str | None:
    """Validate one state change; returns the cleaned reason (``None`` when none was needed)."""
    if to_state not in ALLOWED_TRANSITIONS[current]:
        raise IllegalTransitionError(f"cannot move a finding from {current} to {to_state}")
    needs_reason = to_state in FINAL_STATES
    if reason is None:
        if needs_reason:
            raise InvalidOperationError("resolving or dismissing a finding requires a reason")
        return None
    if not isinstance(reason, str) or not reason.strip() or len(reason) > MAX_REASON:
        raise InvalidOperationError(f"a reason is 1 to {MAX_REASON} non-blank characters")
    return reason


def is_open(state: FindingState) -> bool:
    return state in OPEN_STATES


def counts_from_groups(groups: Iterable[tuple[FindingState, Severity, int]]) -> UnknownDeviceCounts:
    """Counts from ``GROUP BY state, severity`` rows (a few rows, however many findings)."""
    by_state: Counter[FindingState] = Counter()
    by_severity: Counter[Severity] = Counter()
    for state, severity, count in groups:
        by_state[state] += count
        by_severity[severity] += count
    return UnknownDeviceCounts(
        open=sum(n for s, n in by_state.items() if is_open(s)),
        by_state=[
            UnknownDeviceStateCount(state=s, count=by_state[s])
            for s in _STATE_ORDER
            if by_state[s]
        ],
        by_severity=[
            UnknownDeviceSeverityCount(severity=s, count=by_severity[s])
            for s in _SEVERITY_ORDER
            if by_severity[s]
        ],
    )


@dataclass(frozen=True)
class Known:
    """A stored finding as the observation rules need it."""

    finding: UnknownDeviceFinding
    updated_at: datetime  # for a dismissal: when it was made


@dataclass(frozen=True)
class Decision:
    """What a sighting does: refresh an open finding, be suppressed by a dismissal, or create."""

    action: Literal["refresh", "suppress", "create"]
    known: Known | None = None  # the finding refreshed or suppressing, or the one to point back to


def decide(
    history: Sequence[Known], detection: Detection, now: datetime, fp_ttl: timedelta
) -> Decision:
    """The outcome of one sighting; ``history`` is every finding of the endpoint, newest first."""
    matches = [k for k in history if same_endpoint(k.finding.endpoint, detection.endpoint)]
    for known in matches:
        if is_open(known.finding.state):
            return Decision("refresh", known)
    if not matches:
        return Decision("create")
    latest = matches[0]
    if latest.finding.state == "false-positive" and now - latest.updated_at < fp_ttl:
        return Decision("suppress", latest)
    return Decision("create", latest)  # resolved, or a dismissal that has run out


def refresh_applies(
    current: UnknownDeviceFinding,
    detection: Detection,
    now: datetime,
    last_evidence_event: datetime | None,
) -> bool:
    """Whether a sighting's evidence is recorded (True) or only counted (False).

    Nothing changed: counted. Something an analyst decides on changed (severity, proposal, NetBox's
    verdict): recorded at once. Only where it was seen changed (a port, an address): recorded at
    most once an hour, so a flapping hop can not fill the timeline.
    """
    if finding_fingerprint(current) == detection.fingerprint():
        return False
    if finding_significance(current) != detection.significance():
        return True
    return last_evidence_event is None or now - last_evidence_event >= SNAPSHOT_MIN_INTERVAL


def sighting_due(
    current: UnknownDeviceFinding, detection: Detection, now: datetime, last: datetime | None
) -> bool:
    """Whether a dismissed endpoint seen with different evidence leaves a sighting event."""
    if finding_fingerprint(current) == detection.fingerprint():
        return False
    return last is None or now - last >= SIGHTING_MIN_INTERVAL


def saturate(value: int) -> int:
    """Counters stop at the contract's cap instead of overflowing it."""
    return min(value, MAX_COUNT)


# --- in-memory store ---------------------------------------------------------------------------------


class InMemoryUnknownDeviceRepository:
    """Unit-test implementation applying the same rules as the PostgreSQL store."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] = lifecycle.utc_now,
        new_uuid: Callable[[], uuid.UUID] = uuid.uuid4,
        fp_ttl: timedelta = DEFAULT_FP_TTL,
    ) -> None:
        self._clock = clock
        self._new_uuid = new_uuid
        self._fp_ttl = fp_ttl
        self._lock = threading.RLock()
        self._findings: dict[str, UnknownDeviceFinding] = {}
        self._subject: dict[str, str] = {}  # finding id -> subject key
        self._updated: dict[str, datetime] = {}  # finding id -> updated_at
        self._order: list[str] = []  # creation order
        self._events: dict[str, list[UnknownDeviceEvent]] = {}

    # -- internals --

    def _event(
        self, finding_id: str, kind: str, actor_id: str, now: datetime, **fields: object
    ) -> UnknownDeviceEvent:
        events = self._events[finding_id]
        event = UnknownDeviceEvent.model_validate(
            {
                "id": lifecycle.format_id(EVENT_PREFIX, self._new_uuid()),
                "finding_id": finding_id,
                "seq": min(len(events) + 1, MAX_COUNT),
                "occurred_at": now,
                "actor_id": actor_id,
                "kind": kind,
                "state_from": None,
                "state_to": None,
                "reason": None,
                "message": None,
                "subject_id": None,
                **fields,
            }
        )
        events.append(event)
        return event

    def _last_event_at(self, finding_id: str, kind: str) -> datetime | None:
        times = [e.occurred_at for e in self._events[finding_id] if e.kind == kind]
        return max(times) if times else None

    def _locked(self, finding_id: str) -> UnknownDeviceFinding:
        found = (
            self._findings.get(finding_id)
            if lifecycle.parse_id(FINDING_PREFIX, finding_id)
            else None
        )
        if found is None:
            raise NotFoundError("finding not found")
        return found

    def _history(self) -> list[Known]:
        return [Known(self._findings[i], self._updated[i]) for i in reversed(self._order)]

    def _store(self, finding: UnknownDeviceFinding, now: datetime) -> None:
        self._findings[finding.id] = finding
        self._updated[finding.id] = max(self._updated.get(finding.id, now), now)

    # -- scanner write --

    def known_subject_keys(self, keys: Sequence[str]) -> set[str]:
        with self._lock:
            stored = set(self._subject.values())
        return {key for key in keys if key in stored}

    def observe(self, detection: Detection) -> Observation:
        with self._lock:
            now = self._clock()
            decision = decide(self._history(), detection, now, self._fp_ttl)
            if decision.action == "refresh":
                assert decision.known is not None
                return self._refresh(decision.known.finding, detection, now)
            if decision.action == "suppress":
                assert decision.known is not None
                return self._suppress(decision.known.finding, detection, now)
            recurrence = decision.known.finding.id if decision.known is not None else None
            return self._create(detection, now, recurrence)

    def _create(
        self, detection: Detection, now: datetime, recurrence: str | None
    ) -> Observation:
        finding_id = lifecycle.format_id(FINDING_PREFIX, self._new_uuid())
        finding = detection.as_finding(finding_id, now, recurrence_of=recurrence)
        self._store(finding, now)
        self._subject[finding_id] = detection.subject_key
        self._order.append(finding_id)
        self._events[finding_id] = []
        self._event(finding_id, "detected", SYSTEM_ACTOR, now)
        if finding.proposed_action is not None:
            self._event(finding_id, "action-proposed", SYSTEM_ACTOR, now)
        return Observation("created", finding_id)

    def _refresh(
        self, current: UnknownDeviceFinding, detection: Detection, now: datetime
    ) -> Observation:
        recorded = refresh_applies(
            current, detection, now, self._last_event_at(current.id, "evidence-updated")
        )
        values: dict[str, object] = {
            "last_seen_at": max(current.last_seen_at, now),
            "seen_count": saturate(current.seen_count + 1),
            "comparison": detection.comparison,
        }
        if recorded:
            values.update(
                severity=detection.severity,
                severity_basis=detection.severity_basis,
                endpoint=detection.endpoint,
                chain=list(detection.chain),
                proposed_action=detection.proposed_action,
                evidence_version=saturate(current.evidence_version + 1),
            )
        self._store(UnknownDeviceFinding.model_validate({**current.model_dump(), **values}), now)
        if recorded:
            self._event(current.id, "evidence-updated", SYSTEM_ACTOR, now)
            if current.proposed_action is None and detection.proposed_action is not None:
                self._event(current.id, "action-proposed", SYSTEM_ACTOR, now)
        return Observation("refreshed", current.id)

    def _suppress(
        self, dismissed: UnknownDeviceFinding, detection: Detection, now: datetime
    ) -> Observation:
        last = self._last_event_at(dismissed.id, "suppressed-sighting")
        if sighting_due(dismissed, detection, now, last):
            self._event(dismissed.id, "suppressed-sighting", SYSTEM_ACTOR, now)
        return Observation("suppressed", dismissed.id)

    # -- reads --

    def get_finding(self, finding_id: str) -> UnknownDeviceFinding | None:
        with self._lock:
            found = self._findings.get(finding_id)
            return found.model_copy(deep=True) if found is not None else None

    def list_findings(
        self,
        *,
        states: Sequence[FindingState] | None = None,
        severity: Severity | None = None,
        assigned: bool | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> tuple[list[UnknownDeviceFinding], int]:
        check_list_args(limit, offset)
        wanted = check_states(states)
        with self._lock:
            rows = [
                f
                for f in self._findings.values()
                if (wanted is None or f.state in wanted)
                and (severity is None or f.severity == severity)
                and (assigned is None or (f.assignee_id is not None) == assigned)
            ]
        rows.sort(key=lambda f: (f.last_seen_at, f.id), reverse=True)
        return [f.model_copy(deep=True) for f in rows[offset : offset + limit]], len(rows)

    def counts(self) -> UnknownDeviceCounts:
        with self._lock:
            groups = Counter((f.state, f.severity) for f in self._findings.values())
        return counts_from_groups((s, v, n) for (s, v), n in groups.items())

    def list_timeline(
        self, finding_id: str, *, after_seq: int = 0, limit: int = 200
    ) -> list[UnknownDeviceEvent]:
        check_timeline_args(after_seq, limit)
        with self._lock:
            self._locked(finding_id)
            events = [e for e in self._events[finding_id] if e.seq > after_seq]
            return [e.model_copy(deep=True) for e in events[:limit]]

    # -- people's writes --

    def transition_state(
        self,
        finding_id: str,
        *,
        to_state: FindingState,
        actor_id: str,
        expected_evidence_version: int,
        reason: str | None = None,
    ) -> UnknownDeviceFinding:
        check_actor(actor_id)
        with self._lock:
            current = self._locked(finding_id)
            check_evidence_version(current, expected_evidence_version)
            cleaned = plan_transition(current.state, to_state, reason)
            now = self._clock()
            updated = current.model_copy(update={"state": to_state})
            self._store(updated, now)
            self._event(
                finding_id,
                "state-changed",
                actor_id,
                now,
                state_from=current.state,
                state_to=to_state,
                reason=cleaned,
            )
            return updated.model_copy(deep=True)

    def set_assignee(
        self,
        finding_id: str,
        *,
        assignee_id: str | None,
        actor_id: str,
        expected_evidence_version: int,
    ) -> UnknownDeviceFinding:
        check_actor(actor_id)
        assignee = clean_assignee(assignee_id)
        with self._lock:
            current = self._locked(finding_id)
            check_evidence_version(current, expected_evidence_version)
            if current.state in FINAL_STATES:
                raise IllegalTransitionError("a finished finding cannot be reassigned")
            if current.assignee_id == assignee:
                return current.model_copy(deep=True)
            now = self._clock()
            updated = current.model_copy(update={"assignee_id": assignee})
            self._store(updated, now)
            self._event(finding_id, "assignee-changed", actor_id, now, subject_id=assignee)
            return updated.model_copy(deep=True)

    def add_comment(self, finding_id: str, *, actor_id: str, message: str) -> UnknownDeviceEvent:
        check_actor(actor_id)
        text = clean_comment(message)
        with self._lock:
            self._locked(finding_id)
            event = self._event(finding_id, "comment", actor_id, self._clock(), message=text)
            return event.model_copy(deep=True)

